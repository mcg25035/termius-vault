# @c0dingbear/termius-vault

Read your local **Termius** vault from Node.js: decrypt the IndexedDB store and
reconstruct the **complete saved-host list** the Termius UI shows — including
hosts you have never connected to.

It joins Termius' normalized model (Host / SshConfig / Identity / SshKey,
keyed by `local_id`) on top of [`@c0dingbear/chromium-idb-reader`](https://www.npmjs.com/package/@c0dingbear/chromium-idb-reader),
so each host comes back with its current address, port, username, credential
(key or password), label, OS and connect-chain (jump hosts).

## Usage

```js
const { TermiusClient } = require("@c0dingbear/termius-vault");

const t = new TermiusClient();
await t.init();                 // reads + decrypts the local vault
for (const c of t.getConnections()) {
  console.log(c.label, c.host + ":" + c.port, c.username, c.authType);
}
t.getConnection("prod-db");     // best match by label/host
t.getSnippets();                // saved snippets
```

Requires the Termius desktop app installed and logged in on the same machine
(the vault key is read from the OS keychain via `keytar`).

## License

MIT
