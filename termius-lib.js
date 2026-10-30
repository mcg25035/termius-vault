const sodium = require('libsodium-wrappers');
const keytar = require('keytar');
const fs = require('fs');
const path = require('path');
const os = require('os');
const v8 = require('v8');
const { readCurrentRecords } = require('@c0dingbear/chromium-idb-reader');
const { buildHostList } = require('./termius-model');

function getDbPath() {
  if (process.platform === 'darwin') {
    return path.join(os.homedir(), 'Library/Application Support/Termius/IndexedDB/file__0.indexeddb.leveldb');
  }
  if (process.platform === 'win32') {
    if (!process.env.APPDATA) throw new Error('APPDATA environment variable is not set');
    return path.join(process.env.APPDATA, 'Termius/IndexedDB/file__0.indexeddb.leveldb');
  }
  return path.join(process.env.XDG_CONFIG_HOME || path.join(os.homedir(), '.config'), 'Termius/IndexedDB/file__0.indexeddb.leveldb');
}

async function getEncryptionKey() {
  // Try 'termius-app' first (common on Linux), then 'Termius' (macOS/Windows)
  let key = await keytar.getPassword('termius-app', 'localKey');
  if (!key) {
    key = await keytar.getPassword('Termius', 'localKey');
  }
  if (!key) {
    throw new Error('Termius encryption key not found. Please ensure you are logged into Termius.');
  }
  return Buffer.from(key, 'base64');
}

function readVarint(buffer, offset) {
  let value = 0;
  let shift = 0;
  let bytesRead = 0;
  while (true) {
    const byte = buffer[offset + bytesRead];
    bytesRead++;
    value |= (byte & 0x7f) << shift;
    shift += 7;
    if (!(byte & 0x80)) break;
    if (bytesRead > 5) throw new Error('Varint too long');
  }
  return { value, bytesRead };
}

/**
 * Searches backwards from blockIndex in the buffer for V8 serialization Smi ID ("idI" pattern)
 */
function findAssociatedId(buffer, blockIndex) {
  const startSearch = Math.max(0, blockIndex - 200);
  const pattern = Buffer.from([0x22, 0x02, 0x69, 0x64, 0x49]); // ASCII: "idI" with string length 2 header
  
  let matchIdx = -1;
  for (let i = blockIndex - pattern.length; i >= startSearch; i--) {
    let match = true;
    for (let j = 0; j < pattern.length; j++) {
      if (buffer[i + j] !== pattern[j]) {
        match = false;
        break;
      }
    }
    if (match) {
      matchIdx = i;
      break;
    }
  }

  if (matchIdx !== -1) {
    try {
      const varintOffset = matchIdx + pattern.length;
      const { value } = readVarint(buffer, varintOffset);
      return value >> 1; // Smi value is encoded as value << 1
    } catch (e) {
      return null;
    }
  }
  return null;
}

async function decrypt(base64Data, key) {
  const data = Buffer.from(base64Data, 'base64');
  if (data[0] !== 4) return null;

  const nonce = data.slice(2, 26);
  const ciphertext = data.slice(26);

  try {
    const decrypted = sodium.crypto_secretbox_open_easy(
      new Uint8Array(ciphertext),
      new Uint8Array(nonce),
      new Uint8Array(key)
    );
    return Buffer.from(decrypted).toString('utf8');
  } catch {
    return null;
  }
}

async function extractAndDecrypt(key) {
  const dbPath = getDbPath();
  if (!fs.existsSync(dbPath)) {
    throw new Error(`Termius database not found at: ${dbPath}`);
  }

  // Read the CURRENT value of every IndexedDB record (highest LevelDB sequence
  // per key), instead of regex-scanning the raw files for every ciphertext ever
  // written. The old approach resurrected superseded record versions, which is
  // why edited hosts reappeared under their old addresses. We also keep each
  // record's sequence number: among a host's sibling session records, the one
  // with the greatest sequence was written most recently and therefore carries
  // the host's current resolved address.
  const records = readCurrentRecords(dbPath);
  const results = [];

  for (const { value, seq } of records) {
    const valueStr = value.toString('binary');
    const matches = valueStr.match(/BA[A-Za-z0-9+/=]{30,}/g) || [];
    for (const m of matches) {
      const dec = await decrypt(m, key);
      if (dec) {
        const id = findAssociatedId(value, valueStr.indexOf(m));
        results.push({ decryptedStr: dec, id, seq });
      }
    }
  }

  return results;
}

// The host/ssh_config/hosts_chain relation entities are stored as PLAINTEXT V8
// values (not inside the encrypted BA blobs). Reading them by scanning raw file
// bytes for a marker only works while those records sit in the uncompressed
// .log; once Termius compacts the database they move into Snappy-compressed
// .ldb SSTable blocks and the byte scan finds nothing (this is what silently
// broke the proxy connect-chain). So we decompress every current record via the
// LevelDB reader and V8-deserialize the value instead — compaction-proof.
function readV8RelationEntities() {
  const dbPath = getDbPath();
  if (!fs.existsSync(dbPath)) return [];
  let records;
  try { records = readCurrentRecords(dbPath); } catch { return []; }
  const out = [];
  for (const r of records) {
    for (let start = 0; start < 8; start++) {
      try {
        const e = v8.deserialize(r.value.subarray(start));
        if (e && typeof e === 'object') { out.push(e); break; }
      } catch {}
    }
  }
  return out;
}

function extractIndexedDbEntities() {
  const results = [];
  for (const entity of readV8RelationEntities()) {
    if (Array.isArray(entity.hosts_chain) && entity.ssh_config != null) {
      results.push({ decryptedStr: JSON.stringify(entity), id: entity.id });
    }
  }
  return results;
}

function extractIndexedDbHostConfigRelations() {
  const relations = new Map();
  for (const entity of readV8RelationEntities()) {
    const config = entity && entity.ssh_config;
    if (entity && entity.id != null && config && typeof config === 'object' && config.id != null) {
      relations.set(String(config.id), Number(entity.id));
    }
  }
  return relations;
}

function extractCachedHostConfigRelations() {
  const cachePath = path.join(os.homedir(), '.config', 'Termius', 'Cache', 'Cache_Data');
  const relations = new Map();
  if (!fs.existsSync(cachePath)) return relations;
  for (const file of fs.readdirSync(cachePath)) {
    let text;
    try { text = fs.readFileSync(path.join(cachePath, file), 'utf8'); } catch { continue; }
    const pattern = /"id":(\d+),"updated_at":"[^"]+","ssh_config":\{"id":(\d+)\}/g;
    let match;
    while ((match = pattern.exec(text))) {
      relations.set(String(match[2]), Number(match[1]));
    }
  }
  return relations;
}

function parseDecryptedData(results) {
  const identitiesByUser = new Map();
  const keysById = new Map();
  const connections = [];
  const hostChains = [];
  const snippets = [];
  const addressLabels = []; // {address, label, date} from Termius' address cache

  results.forEach(({ decryptedStr, id, seq }) => {
    if (!decryptedStr.startsWith('{')) return;
    try {
      const obj = JSON.parse(decryptedStr);
      if (id) {
        obj.id = id;
      }
      if (seq !== undefined) {
        obj.__seq = seq; // LevelDB sequence: higher = written more recently
      }

      // Extract identities (username & password)
      if (obj.username !== undefined && obj.password !== undefined) {
        const mapKey = obj.label || obj.username;
        if (!identitiesByUser.has(mapKey) || obj.password) {
          identitiesByUser.set(mapKey, obj);
        }
      }

      // Extract keys
      if (obj.private_key && obj.id) {
        keysById.set(obj.id, obj);
      }

      // Extract connections
      if (obj.host && obj.user_name && obj.connection_type) {
        connections.push(obj);
      }

      // Termius stores Connect Chain as a separate hostchain entity in some
      // versions. Keep the raw relation until all host records are indexed.
      if (obj.hosts_chain || obj.ssh_config || Object.keys(obj).some(key => /host.?chain|jump.?host|parent.?host|chain/i.test(key))) {
        hostChains.push(obj);
      }

      // Extract snippets
      if (obj.script && obj.label) {
        snippets.push({
          label: obj.label,
          script: obj.script
        });
      }

      // Termius' address cache: maps a resolved address to the host's
      // user-facing label (the saved name shown in the UI). Session records
      // only carry the address as their title, so this is where the real name
      // like "[DO NOT USE SSH] MCLOUD SFTP" or "samlee" lives.
      if (obj.address && obj.label && obj.host === undefined && obj.user_name === undefined) {
        addressLabels.push({
          address: String(obj.address).trim(),
          label: obj.label,
          date: obj.interaction_date || ''
        });
      }
    } catch {}
  });

  return { identitiesByUser, keysById, connections, hostChains, snippets, addressLabels };
}

class TermiusClient {
  constructor() {
    this.initialized = false;
    this.connections = [];
    this.hostChains = [];
    this.snippets = [];
  }

  /**
   * Initialize and decrypt the Termius local vault
   */
  async init() {
    await sodium.ready;
    const key = await getEncryptionKey();
    const decryptedRaw = [
      ...(await extractAndDecrypt(key)),
      ...extractIndexedDbEntities()
    ];
    const hostConfigRelations = new Map([
      ...extractCachedHostConfigRelations(),
      ...extractIndexedDbHostConfigRelations()
    ]);
    const parsed = parseDecryptedData(decryptedRaw);

    const { identitiesByUser, keysById, connections, hostChains, snippets, addressLabels } = parsed;
    
    this.snippets = snippets;
    this.hostChains = hostChains;
    this.connections = [];

    // Enrich each raw host record with its credential, carrying the real
    // `host_id` from the decrypted JSON. Note: `connections` here contains not
    // only the saved hosts but also every per-connection "session" record
    // Termius logs. Those session records are what made the list explode: a
    // dynamic-DNS host gets logged under each resolved IP it ever used, so the
    // same machine showed up as dozens of stale ghost IPs. The real fix is to
    // group by Termius's own stable host identity (`host_id`) below.
    const built = connections.map(conn => {
      let password = null;
      identitiesByUser.forEach(id => {
        if (id.username === conn.user_name && id.password) password = id.password;
      });

      let privateKey = null;
      let passphrase = null;
      let keyLabel = null;
      if (conn.key_id) {
        const keyObj = keysById.get(conn.key_id);
        if (keyObj) {
          privateKey = keyObj.private_key || null;
          passphrase = keyObj.passphrase || null;
          keyLabel = keyObj.label || null;
        }
      }

      return {
        hostId: conn.host_id != null ? conn.host_id : null,
        id: conn.host_id || conn.id || null,
        title: typeof conn.title === 'string' ? conn.title : '',
        // Trim: some records store the address with a stray leading space,
        // which otherwise becomes `getaddrinfo ENOTFOUND " 1.2.3.4"`.
        host: (conn.host || '').trim(),
        port: conn.port || 22,
        username: conn.user_name,
        privateKey,
        passphrase,
        keyLabel,
        password,
        os: conn.host_os_name || 'unknown',
        seq: conn.__seq !== undefined ? conn.__seq : 0n
      };
    }).filter(c => c.host);

    // Primary path: reconstruct the full host list from Termius' normalized
    // model (Host/SshConfig/Identity/SshKey joined by local_id). This yields the
    // complete list the UI shows — including hosts never connected to — and the
    // current saved address/label for each, using `built` as the accurate
    // credential/port source for hosts that have been connected to.
    const decryptFirstJson = (valueBuf) => {
      const s = valueBuf.toString('latin1');
      for (const m of (s.match(/BA[A-Za-z0-9+/=]{30,}/g) || [])) {
        const data = Buffer.from(m, 'base64');
        if (data[0] !== 4) continue;
        const nonce = data.slice(2, 26);
        const ciphertext = data.slice(26);
        try {
          const dec = Buffer.from(sodium.crypto_secretbox_open_easy(
            new Uint8Array(ciphertext), new Uint8Array(nonce), new Uint8Array(key)
          )).toString('utf8');
          if (dec.startsWith('{')) return JSON.parse(dec);
        } catch {}
      }
      return null;
    };
    let normalized = null;
    try {
      normalized = buildHostList({ dbPath: getDbPath(), decryptFirstJson, sessionConns: built });
    } catch { normalized = null; }

    if (normalized && normalized.length) {
      this.connections = normalized;
    } else {
    // Fallback: session-grouped reconstruction (used only if the normalized
    // model cannot be read, e.g. a future Termius storage change).
    // Group by Termius host identity. Session/connection records carry the
    // stable `host_id` of their parent host; records without one ARE the host
    // entity. We also link a host_id-less record into an existing host_id group
    // when its address or title matches that group, so a host whose saved
    // address was edited (old snapshot kept on disk by append-only LevelDB)
    // doesn't resurface as a separate stale entry.
    const built_hid = built.filter(c => c.hostId != null);
    const hostToHid = new Map();
    const titleToHid = new Map();
    for (const c of built_hid) {
      if (!hostToHid.has(c.host)) hostToHid.set(c.host, c.hostId);
      if (c.title && !titleToHid.has(c.title)) titleToHid.set(c.title, c.hostId);
    }
    const groupKey = (c) => {
      if (c.hostId != null) return `hid:${c.hostId}`;
      const linked = hostToHid.get(c.host) ?? (c.title ? titleToHid.get(c.title) : undefined);
      if (linked != null) return `hid:${linked}`;
      return `own:${c.host}:${c.port}:${c.username}`;
    };
    const groups = new Map();
    for (const c of built) {
      const gkey = groupKey(c);
      if (!groups.has(gkey)) groups.set(gkey, []);
      groups.get(gkey).push(c);
    }

    // A real DNS hostname (ends in a dotted alpha label); not an IPv4/IPv6 literal.
    const isFqdn = (h) => /[a-zA-Z]/.test(h) && /\.[a-zA-Z]{2,}$/.test(h);
    const hostScore = (h) => {
      if (isFqdn(h)) return 100;          // prefer the stable DNS name
      if (h.startsWith('127.') || h === '::1') return -50; // local forward artifact
      return 0;                            // bare IP
    };
    const authRank = (c) => (c.privateKey ? 2 : (c.password ? 1 : 0));

    // Termius' address cache: label -> { address, date }. This is the saved
    // name + current resolved address the UI shows. We link a host group to its
    // cache entry by an exact title match (a session record whose title equals
    // the cache label), NOT by address — a single address can host several
    // Termius hosts (e.g. tw1.mcloudtw.com has both a codingbear host and the
    // root "詛咒走路者" host), so address matching would mislabel them.
    const cacheByLabel = new Map();
    for (const a of addressLabels) {
      if (!a.label) continue;
      const prev = cacheByLabel.get(a.label);
      if (!prev || (a.date || '') >= (prev.date || '')) {
        cacheByLabel.set(a.label, { address: (a.address || '').trim(), date: a.date || '' });
      }
    }

    this.connections = [];
    for (const members of groups.values()) {
      // Representative address: prefer a stable DNS name; among bare IPs, take
      // the one from the most recently written record (highest LevelDB
      // sequence), i.e. the host's current resolved address.
      const bySeq = new Map(); // host -> max seq seen for it
      for (const m of members) {
        const prev = bySeq.get(m.host);
        if (prev === undefined || m.seq > prev) bySeq.set(m.host, m.seq);
      }
      const repHost = [...bySeq.keys()].sort((a, b) => {
        const s = hostScore(b) - hostScore(a);
        if (s) return s;
        return bySeq.get(b) > bySeq.get(a) ? 1 : (bySeq.get(b) < bySeq.get(a) ? -1 : 0);
      })[0];

      // Best credential found anywhere in the group (a session record may hold
      // the key while the plain host record does not), newest first on ties.
      const credSrc = members.slice().sort((a, b) =>
        (authRank(b) - authRank(a)) || (b.seq > a.seq ? 1 : b.seq < a.seq ? -1 : 0)
      )[0];

      // Label: prefer a real human name. Session records set `title` to the bare
      // address, and old records may carry a malformed "host:port" title, so a
      // title that looks like an address (an IP, an FQDN, a host:port, or any
      // address seen in this group) is not a name. Fall back to the clean
      // representative host; the address-cache pass below then upgrades it to
      // the saved label when one exists.
      const titles = members.map(m => m.title).filter(Boolean);
      const isAddressLike = (t) =>
        t === repHost ||
        bySeq.has(t) ||
        isFqdn(t) ||
        /^\d{1,3}(\.\d{1,3}){3}$/.test(t) ||
        /:\d+$/.test(t) ||
        t.includes(':');
      let repAddr = repHost;
      let label =
        titles.find(t => !t.includes('[via') && !isAddressLike(t)) ||
        repHost;

      // If any session title in this group exactly matches an address-cache
      // label, that cache entry is authoritative for both the saved name and
      // the current resolved address. This is what turns the codingbear group
      // into "codingbear.mcloudtw.com [via IP]" at its current IP, instead of a
      // stale bare hostname, and keeps labels attached to the right host.
      let bestDate = '';
      for (const t of titles) {
        const hit = cacheByLabel.get(t);
        if (hit && (hit.date || '') >= bestDate) {
          label = t;
          if (hit.address) repAddr = hit.address;
          bestDate = hit.date || '';
        }
      }

      const port = members.find(m => m.host === repAddr)?.port || members.find(m => m.host === repHost)?.port || members[0].port;
      const os = members.map(m => m.os).find(o => o && o !== 'unknown' && o !== 'none') || 'unknown';

      this.connections.push({
        id: members.find(m => m.hostId != null)?.hostId ?? members[0].id,
        label,
        host: repAddr,
        port,
        username: credSrc.username,
        authType: credSrc.privateKey ? 'key' : (credSrc.password ? 'password' : 'none'),
        password: credSrc.password,
        privateKey: credSrc.privateKey,
        passphrase: credSrc.passphrase,
        keyLabel: credSrc.keyLabel,
        os
      });
    }

    // Final collapse: a host may appear both as its own (host_id-less) record
    // and as a host_id group; both resolve to the same address, so dedupe by
    // the resolved host:port:username, keeping the richer credential.
    {
      const dedup = new Map();
      for (const c of this.connections) {
        const k = `${c.host}:${c.port}:${c.username}`;
        const prev = dedup.get(k);
        if (!prev || authRank(c) >= authRank(prev)) dedup.set(k, c);
      }
      this.connections = [...dedup.values()];
    }
    } // end fallback

    const byId = new Map(this.connections.filter(c => c.id != null).map(c => [String(c.id), c]));
    const byHostConfig = new Map();
    for (const [sshConfigId, hostId] of hostConfigRelations) {
      const host = byId.get(String(hostId));
      if (host) byHostConfig.set(String(sshConfigId), host);
    }
    const relationValue = (relation, names) => {
      for (const name of names) {
        if (relation[name] != null) return relation[name];
      }
      return null;
    };
    for (const relation of this.hostChains) {
      if (Array.isArray(relation.hosts_chain)) {
        const sshConfigId = relation.ssh_config?.id || relation.ssh_config_id || relation.ssh_config;
        const target = byHostConfig.get(String(sshConfigId));
        const jumps = relation.hosts_chain.map(item => {
          const id = typeof item === 'object' ? (item.id || item.local_id || item.host_id) : item;
          return byId.get(String(id));
        }).filter(Boolean);
        if (target && jumps.length) {
          for (const connection of this.connections) {
            if (connection.id === target.id) connection.connectChain = jumps;
          }
        }
        continue;
      }
      const hostId = relationValue(relation, ['host_id', 'hostId', 'target_host_id', 'targetHostId', 'destination_host_id', 'destinationHostId']);
      let jumpIds = relationValue(relation, ['jump_host_id', 'jumpHostId', 'parent_host_id', 'parentHostId', 'proxy_host_id', 'proxyHostId', 'chain_host_ids', 'chainHostIds', 'host_ids', 'hostIds']);
      if (jumpIds == null) {
        const nested = relationValue(relation, ['chain', 'connect_chain', 'connectChain', 'hosts', 'jump_hosts', 'jumpHosts']);
        if (Array.isArray(nested)) {
          jumpIds = nested.map(item => typeof item === 'object'
            ? relationValue(item, ['host_id', 'hostId', 'id'])
            : item);
        }
      }
      const target = byId.get(String(hostId));
      const ids = Array.isArray(jumpIds) ? jumpIds : [jumpIds];
      const jumps = ids.map(id => byId.get(String(id))).filter(Boolean);
      if (target && jumps.length) {
        const chain = jumps.filter((jump, index, all) =>
          all.findIndex(candidate => candidate.id === jump.id) === index
        );
        for (const connection of this.connections) {
          if (connection.id === target.id) connection.connectChain = chain;
        }
      }
    }

    this.initialized = true;
  }

  /**
   * Get all connections
   */
  getConnections() {
    if (!this.initialized) throw new Error('TermiusClient is not initialized. Call init() first.');
    return this.connections;
  }

  /**
   * Get a single connection by exact label, exact host, or closest match.
   * @param {string} query Label or host IP/domain
   * @returns {object|null}
   */
  getConnection(query) {
    if (!this.initialized) throw new Error('TermiusClient is not initialized. Call init() first.');
    if (!query) return null;
    const q = query.toLowerCase().trim();
    
    // 1. Try exact label match
    let found = this.connections.find(c => c.label.toLowerCase() === q);
    if (found) return found;
    
    // 2. Try exact host match
    found = this.connections.find(c => c.host.toLowerCase() === q);
    if (found) return found;

    // 3. Try partial label match
    found = this.connections.find(c => c.label.toLowerCase().includes(q));
    if (found) return found;

    // 4. Try partial host match
    found = this.connections.find(c => c.host.toLowerCase().includes(q));
    if (found) return found;

    return null;
  }

  /**
   * Find a connection by label or host
   * @param {string} searchStr Label or host IP/domain to search for
   */
  findConnection(searchStr) {
    if (!this.initialized) throw new Error('TermiusClient is not initialized. Call init() first.');
    const query = searchStr.toLowerCase();
    return this.connections.filter(c => 
      c.label.toLowerCase().includes(query) || 
      c.host.toLowerCase().includes(query)
    );
  }

  /**
   * Get all snippets
   */
  getSnippets() {
    if (!this.initialized) throw new Error('TermiusClient is not initialized. Call init() first.');
    return this.snippets;
  }
}

module.exports = {
  TermiusClient
};
