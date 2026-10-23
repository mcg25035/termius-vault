// Normalized Termius host model reconstruction.
//
// The denormalized session-log records (used by termius-lib's legacy path) only
// cover hosts you have actually connected to, and they record resolved IPs. The
// authoritative host list the Termius UI shows lives in a normalized model
// spread across several IndexedDB "databases" (each keyed by a per-store
// local_id), joined by foreign keys:
//
//   db 15  Host         local_id -> { address, label }        (encrypted value)
//   db 3   SshConfig    local_id -> { port }                  (encrypted value)
//   db 11  Identity     local_id -> { username, password }    (encrypted value)
//   db 10  SshKey       local_id -> { private_key, passphrase, label }
//   relation entity (plaintext v8): host.local_id -> { id(big), ssh_config.local_id, identity.local_id }
//   session entity    (plaintext v8): host.local_id -> ssh_key.local_id
//
// We decode each record's (databaseId, local_id) straight from its LevelDB key
// (reliable, unlike heuristic id-sniffing), join the stores, and produce the
// full host list — including hosts never connected to, which the session path
// cannot see.

const fs = require('fs');
const path = require('path');
const v8 = require('v8');
const { readCurrentRecords } = require('@c0dingbear/chromium-idb-reader');

// Chromium IndexedDB object-store data key: KeyPrefix (databaseId, objectStoreId,
// indexId) then the encoded primary key. For these integer-keyed stores the
// primary key is a Number (type 3) = 8-byte little-endian double = local_id.
function decodeKey(uk) {
  if (!uk || uk.length < 4) return null;
  const b0 = uk[0];
  const dbBytes = ((b0 >> 5) & 7) + 1;
  const osBytes = ((b0 >> 2) & 7) + 1;
  const ixBytes = (b0 & 3) + 1;
  let p = 1;
  const readBE = (n) => { let v = 0; for (let i = 0; i < n; i++) v = v * 256 + uk[p++]; return v; };
  if (1 + dbBytes + osBytes + ixBytes > uk.length) return null;
  const databaseId = readBE(dbBytes);
  const objectStoreId = readBE(osBytes);
  const indexId = readBE(ixBytes);
  let primaryKey = null;
  if (p < uk.length) {
    const t = uk[p++];
    if (t === 3 && p + 8 <= uk.length) primaryKey = uk.slice(p, p + 8).readDoubleLE(0);
  }
  return { databaseId, objectStoreId, indexId, primaryKey };
}

// Known database ids (stable within a Termius install). We confirm the role of
// each by content too, so a differing layout degrades gracefully.
const DB_HOST = 15;
const DB_SSHCONFIG = 3;
const DB_IDENTITY = 11;
const DB_SSHKEY = 10;

function scanV8Entities(dbPath, marker, predicate) {
  const out = [];
  const needle = Buffer.from(marker);
  for (const file of fs.readdirSync(dbPath).filter(n => n.endsWith('.ldb') || n.endsWith('.log'))) {
    const buf = fs.readFileSync(path.join(dbPath, file));
    let off = 0;
    while ((off = buf.indexOf(needle, off)) !== -1) {
      for (let start = Math.max(0, off - 1500); start <= off; start++) {
        try {
          const e = v8.deserialize(buf.subarray(start));
          if (e && typeof e === 'object' && predicate(e)) { out.push(e); break; }
        } catch {}
      }
      off += marker.length;
    }
  }
  return out;
}

// Build the full host list from the normalized model, merging accurate
// credentials/port from the session-derived connections (keyed by host id and
// by address+user) for hosts that have been connected to.
//
// `decryptFirstJson(valueBuffer)` must return the first decrypted JSON object in
// a record value (or null) — supplied by the caller which holds the vault key.
function buildHostList({ dbPath, decryptFirstJson, sessionConns }) {
  const records = readCurrentRecords(dbPath);

  const hostsByLocal = new Map();   // local_id -> { address, label }
  const sshcfgByLocal = new Map();  // local_id -> { port }
  const identByLocal = new Map();   // local_id -> { username, password }
  const keyByLocal = new Map();     // local_id -> { private_key, passphrase, label }

  for (const r of records) {
    const dk = decodeKey(r.key);
    if (!dk || dk.indexId !== 1 || dk.primaryKey == null) continue;
    const d = decryptFirstJson(r.value);
    if (!d) continue;
    if (dk.databaseId === DB_HOST && d.address && d.label !== undefined) hostsByLocal.set(dk.primaryKey, d);
    else if (dk.databaseId === DB_SSHCONFIG && d.port !== undefined && d.host === undefined) sshcfgByLocal.set(dk.primaryKey, d);
    else if (dk.databaseId === DB_IDENTITY && d.username !== undefined && d.password !== undefined) identByLocal.set(dk.primaryKey, d);
    else if (dk.databaseId === DB_SSHKEY && d.private_key) keyByLocal.set(dk.primaryKey, d);
  }

  if (hostsByLocal.size === 0) return null; // normalized model not present; caller falls back

  // The 'ssh_config' marker matches two entity kinds that share local_id:
  //  - a host entity: { id: <host id>, address|hosts_chain, ssh_config:{local_id}, ... }
  //  - an ssh_config link: { id: <ssh_config id>, ssh_config:{local_id}, identity:{local_id} }
  // We take the host's big id from the host entity (it carries address/hosts_chain)
  // and the ssh_config/identity local ids from whichever entity has them.
  const relByHost = new Map();     // host.local_id -> { sshConfigLocal, identityLocal }
  const hostBigByLocal = new Map(); // host.local_id -> host big id
  for (const e of scanV8Entities(dbPath, 'ssh_config', e => e.ssh_config && e.ssh_config.local_id != null && e.local_id != null)) {
    const cur = relByHost.get(e.local_id) || {};
    if (cur.sshConfigLocal == null) cur.sshConfigLocal = e.ssh_config.local_id;
    if (cur.identityLocal == null && e.identity && e.identity.local_id != null) cur.identityLocal = e.identity.local_id;
    relByHost.set(e.local_id, cur);
    // Host entity (has address/hosts_chain) → its id is the host id.
    if ((e.address !== undefined || e.hosts_chain !== undefined) && e.id != null) {
      hostBigByLocal.set(e.local_id, e.id);
    }
  }
  // From connection/session entities: host.local_id -> ssh_key.local_id, and
  // host.local_id -> host's big id. The relation entity's top-level id is the
  // ssh_config id, not the host id, so we take the authoritative host id from
  // here (needed to match the connect-chain / jump-host relations downstream).
  const sessKeyByHost = new Map();
  for (const e of scanV8Entities(dbPath, 'session_log_data', e => e.host && e.host.local_id != null)) {
    if (e.ssh_key && e.ssh_key.local_id != null && !sessKeyByHost.has(e.host.local_id)) {
      sessKeyByHost.set(e.host.local_id, e.ssh_key.local_id);
    }
    // Secondary source for the host's big id.
    if (e.host.id != null && !hostBigByLocal.has(e.host.local_id)) {
      hostBigByLocal.set(e.host.local_id, e.host.id);
    }
  }

  // Credential pool from the session-derived connections (accurate for
  // connected hosts). Index by big host id and by address+username, keeping the
  // richest credential (prefer a key over a password over none) per key so a
  // partial/older session record doesn't mask the real credential.
  const authRank = (c) => (c && c.privateKey ? 2 : (c && c.password ? 1 : 0));
  const keepBest = (map, k, c) => {
    const prev = map.get(k);
    if (!prev || authRank(c) > authRank(prev)) map.set(k, c);
  };
  const sessByBig = new Map();
  const sessByHostUser = new Map();
  for (const c of (sessionConns || [])) {
    if (c.id != null) keepBest(sessByBig, String(c.id), c);
    keepBest(sessByHostUser, `${c.host}|${c.username}`, c);
  }
  const soleKey = keyByLocal.size === 1 ? [...keyByLocal.values()][0] : null;

  const out = [];
  for (const [local, addrRec] of [...hostsByLocal.entries()].sort((a, b) => a[0] - b[0])) {
    const rel = relByHost.get(local) || {};
    const address = String(addrRec.address || '').trim();
    const label = addrRec.label || address;

    const idn = rel.identityLocal != null ? identByLocal.get(rel.identityLocal) : null;
    const normUser = (idn && idn.username) || null;
    let username = normUser;
    let port = (rel.sshConfigLocal != null && sshcfgByLocal.get(rel.sshConfigLocal) && sshcfgByLocal.get(rel.sshConfigLocal).port) || null;
    let password = null, privateKey = null, passphrase = null, keyLabel = null;

    // The host's authoritative big id (for credential/chain matching) comes from
    // the session entity; the relation's own id is the ssh_config id.
    const hostBig = hostBigByLocal.get(local) ?? rel.big;

    // Match the session-derived connection ONLY by stable identity: big host id,
    // or address+username. Never by address alone — a single address can host
    // several Termius hosts (e.g. tw1 has both a codingbear and a root host), so
    // an address-only match would attach the wrong credential.
    let sess = hostBig != null ? sessByBig.get(String(hostBig)) : null;
    if (!sess && normUser) sess = sessByHostUser.get(`${address}|${normUser}`);

    if (sess) {
      // Connected host: the session recorded what actually works. Keep the
      // normalized ssh_config port as authoritative (it is the host's own
      // configured port); only fall back to the session's port when the host
      // has no ssh_config record — several hosts can share an address+user with
      // different ports, so the session port can belong to a sibling host.
      username = sess.username || username;
      port = port || sess.port;
      password = sess.password || null;
      privateKey = sess.privateKey || null;
      passphrase = sess.passphrase || null;
      keyLabel = sess.keyLabel || null;
    } else {
      // Never connected: derive from the normalized identity. An empty password
      // means key auth; attach the key from a session link if any, else the
      // vault's sole key.
      if (idn && idn.password) {
        password = idn.password;
      } else {
        const keyLocal = sessKeyByHost.get(local);
        const keyObj = (keyLocal != null && keyByLocal.get(keyLocal)) || soleKey;
        if (keyObj) { privateKey = keyObj.private_key; passphrase = keyObj.passphrase || null; keyLabel = keyObj.label || null; }
      }
    }

    if (!port) port = 22;
    const authType = privateKey ? 'key' : (password ? 'password' : 'none');
    const os = (sess && sess.os && sess.os !== 'unknown') ? sess.os : (addrRec.os_name || 'unknown');

    out.push({
      id: hostBig != null ? hostBig : null,
      localId: local,
      label,
      host: address,
      port,
      username: username || (sess && sess.username) || 'root',
      authType,
      password,
      privateKey,
      passphrase,
      keyLabel,
      os
    });
  }
  return out;
}

module.exports = { buildHostList, decodeKey };
