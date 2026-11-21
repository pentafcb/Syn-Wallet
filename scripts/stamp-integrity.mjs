// Release integrity stamp — runs at the end of `npm run build:client`.
//
// Produces the release manifest and pins the release into the places
// that verify it later:
//   1. release-manifest.json at the repo root (NOT served — it is the
//      release record and the on-box checker's reference). SHA-256 of
//      every served client asset, the bundle pin, the connect-src
//      endpoint inventory, and every external host string present in
//      the shipped JS (the drift baseline for the checker).
//   2. public/boot-watchdog.js is generated from client/boot-watchdog.js
//      with the main bundle's path + SHA-256 stamped in; the watchdog
//      verifies the bundle's hash at boot BEFORE loading it, so a
//      tampered bundle never executes.
//   3. src/csp-hosts.ts — the connect-src allowlist, generated from
//      the chain registries + the curated direct-API list below, so
//      the CSP and the endpoint inventory can never drift apart.
//   4. The built index.html's direct module <script> tag is stripped:
//      from this build on, the watchdog is the bundle's only loader.
//
// Also prunes stale hashed bundles from public/assets: only files the
// current release references (transitively) survive, so "every served
// client asset" in the manifest is the release's real, tight set.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const pub = path.join(root, 'public');
const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest('hex');
const read = (p) => fs.readFileSync(p);
const rel = (p) => path.relative(pub, p).split(path.sep).join('/');
const walkFiles = (dir, out = []) => { for (const e of fs.readdirSync(dir, { withFileTypes: true })) { const p = path.join(dir, e.name); if (e.isDirectory()) walkFiles(p, out); else out.push(p); } return out; };

// ---------- 1. prune stale hashed assets ----------
const indexHtmlPath = path.join(pub, 'index.html');
let indexHtml = read(indexHtmlPath).toString('utf8');
const moduleMatch = indexHtml.match(/<script[^>]*type="module"[^>]*src="([^"]+)"/) || indexHtml.match(/<script[^>]*src="([^"]+)"[^>]*type="module"/);
if (!moduleMatch) { console.error('[integrity] no module script found in built index.html'); process.exit(1); }
const bundlePath = moduleMatch[1]; // e.g. /assets/index-XXXX.js
const referenced = new Set();
const scanRefs = (text) => { for (const m of text.matchAll(/assets\/[A-Za-z0-9_.-]+\.(?:js|css)/g)) referenced.add(m[0]); };
scanRefs(indexHtml);
{
  const queue = [...referenced]; const seen = new Set();
  while (queue.length) {
    const r = queue.pop(); if (seen.has(r)) continue; seen.add(r);
    const f = path.join(pub, r); if (!fs.existsSync(f)) continue;
    scanRefs(read(f).toString('utf8'));
    for (const x of referenced) if (!seen.has(x)) queue.push(x);
  }
}
let pruned = 0;
for (const name of fs.readdirSync(path.join(pub, 'assets'))) {
  if (/^(index|dist)-[A-Za-z0-9_-]+\.(js|css)$/.test(name) && !referenced.has('assets/' + name)) {
    fs.unlinkSync(path.join(pub, 'assets', name)); pruned++;
  }
}
console.log(`[integrity] pruned ${pruned} stale hashed assets; kept ${referenced.size} referenced`);

// ---------- 2. generate the stamped watchdog ----------
const bundleRel = bundlePath.replace(/^\//, '');
const bundleHash = sha256(read(path.join(pub, bundleRel)));
const wdSrc = read(path.join(root, 'client/boot-watchdog.js')).toString('utf8');
if (!/__SYN_BUNDLE_PATH__|__SYN_BUNDLE_SHA256__/.test(wdSrc)) { console.error('[integrity] watchdog pin placeholders missing in client/boot-watchdog.js'); process.exit(1); }
const wdOut = wdSrc.replace('__SYN_BUNDLE_PATH__', bundlePath).replace('__SYN_BUNDLE_SHA256__', bundleHash);
fs.writeFileSync(path.join(pub, 'boot-watchdog.js'), wdOut);
console.log(`[integrity] watchdog pinned to ${bundlePath} sha256 ${bundleHash.slice(0, 16)}…`);

// ---------- 3. strip the direct module tag from built index.html ----------
// From here on the watchdog is the bundle's only loader: it verifies
// the hash first, so unverified code can never execute.
indexHtml = indexHtml.replace(/<script[^>]*type="module"[^>]*><\/script>\s*/g, '').replace(/<script[^>]*type="module"[^>]*\/>\s*/g, '');
if (indexHtml.includes('type="module"')) { console.error('[integrity] failed to strip module tag from index.html'); process.exit(1); }
// Version the watchdog URL with the bundle hash. The watchdog has a
// fixed filename, so a client that once cached it (an immutable
// response shipped by a server bug in Nov 2026 did exactly that)
// would never fetch the new pin and would boot the old release
// forever. A per-build query makes every release a URL no cache has
// seen; index.html itself is no-cache, so the fresh tag is picked up
// on the next load and the stale cached watchdog is simply orphaned.
indexHtml = indexHtml.replace('/boot-watchdog.js"', '/boot-watchdog.js?v=' + bundleHash.slice(0, 16) + '"');
if (!indexHtml.includes('/boot-watchdog.js?v=')) { console.error('[integrity] failed to version the watchdog URL in index.html'); process.exit(1); }
fs.writeFileSync(indexHtmlPath, indexHtml);

// ---------- 4. endpoint inventory ----------
// Connection hosts extracted from the chain registries (rpc / lcd /
// rest / blockscout fields — the hosts the client actually dials for
// balances, history and broadcasts) …
const hostOf = (u) => { try { return new URL(u).host; } catch { return null; } };
const endpoints = new Set();
for (const f of ['client/lib/chains-data.ts', 'client/lib/wallet.ts', 'client/main.ts']) {
  const src = read(path.join(root, f)).toString('utf8');
  for (const m of src.matchAll(/(?:rpc|lcd|rest|blockscout|wss|wsRpc)\s*:\s*'(https?|wss?):\/\/([a-zA-Z0-9.-]+)/g)) endpoints.add(m[2]);
  for (const m of src.matchAll(/rpcPool\s*:\s*'([^']+)'/g)) for (const u of m[1].split(',')) { const h = hostOf(u.trim()); if (h) endpoints.add(h); }
}
// … plus the direct-API hosts the client code dials outside the
// registries (verified by the call-site audit in tests/test-integrity.ts).
const DIRECT = [
  'api.trongrid.io', 'graphql.mainnet.sui.io', 'xrplcluster.com', 'api.mainnet.aptoslabs.com',
  'api.gopluslabs.io', 'clob.polymarket.com', 'gamma-api.polymarket.com', 'data-api.polymarket.com',
  'relayer-v2.polymarket.com', 'rest.cosmos.directory', 'cosmos-rest.publicnode.com',
  'ipfs.io', 'cloudflare-ipfs.com', 'dweb.link', 'arweave.net',
  'relay.walletconnect.org', 'verify.walletconnect.com', 'verify.walletconnect.org',
  'echo.walletconnect.com', 'rpc.walletconnect.org',
  // Deliberately ABSENT: pulse.walletconnect.org — the WC SDK's
  // telemetry endpoint. Telemetry is disabled in the client init, and
  // CSP must block it even if a future SDK update re-enabled it.
];
for (const h of DIRECT) endpoints.add(h);
const endpointList = [...endpoints].sort();

// Every external host string present in the shipped JS (links and
// connections alike) — the checker's drift baseline: a NEW host string
// appearing in a later build is a release-note-level event.
const bundleHosts = new Set();
for (const f of walkFiles(pub).filter((f) => f.endsWith('.js'))) {
  const text = read(f).toString('utf8');
  for (const m of text.matchAll(/(?:https?|wss?):\/\/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/g)) bundleHosts.add(m[1]);
}

// ---------- 5. hash the served tree → manifest ----------
const files = {};
for (const f of walkFiles(pub)) files[rel(f)] = sha256(read(f));
const manifest = {
  build: (() => { try { return read(path.join(root, 'src/build-id.ts')).toString('utf8').match(/BUILD_ID = '([^']+)'/)[1]; } catch { return 'unknown'; } })(),
  generatedAt: new Date().toISOString(),
  bundle: { path: bundlePath, sha256: bundleHash },
  endpoints: endpointList,
  bundleHosts: [...bundleHosts].sort(),
  files,
};
fs.writeFileSync(path.join(root, 'release-manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
console.log(`[integrity] manifest: ${Object.keys(files).length} files; endpoints: ${endpointList.length} connect hosts; bundle hosts: ${bundleHosts.size}`);

// ---------- 6. CSP hosts module for the server ----------
const cspTs = `// GENERATED by scripts/stamp-integrity.mjs during \`npm run build\` — do not edit by hand.
// The connect-src allowlist: every host the client may dial, extracted
// from the chain registries plus the curated direct-API list in the
// stamp script. Regenerated every build so CSP and inventory agree.
export const CONNECT_HOSTS: string[] = ${JSON.stringify(endpointList, null, 2)};
`;
fs.writeFileSync(path.join(root, 'src/csp-hosts.ts'), cspTs);
console.log('[integrity] src/csp-hosts.ts regenerated');
