// Release-integrity + secrets-egress static gates (security checklist
// pass, 2026-11-19). Runs against the BUILT tree (npm test follows
// npm run build in the release flow):
//  1. The release manifest agrees with the served bytes: bundle hash,
//     watchdog pin, every listed file.
//  2. The built index.html carries no direct module script — the
//     watchdog is the bundle's only loader.
//  3. Endpoint scan: every connection host the client code can dial
//     (registry fields + the stamp script's curated direct list) is
//     inside the manifest's CSP endpoint inventory — a new connection
//     surface added to the code fails the suite until the release
//     manifest (and therefore the CSP) is regenerated with it.
//  4. Egress hygiene: no sendBeacon anywhere (client source or shipped
//     JS), no analytics/telemetry/error-reporting domains in the
//     shipped JS, the WC telemetry endpoint is NOT in the CSP
//     allowlist, and the WC client init pins telemetryEnabled: false.
// The runtime half of the egress proof (instrumented fetch/XHR/WS
// during create + unlock + sign) is proof-rig/proof-secrets-egress.mjs.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

let failures = 0;
const ok = (cond: boolean, label: string) => { console.log(`${cond ? 'PASS' : 'FAIL'}  ${label}`); if (!cond) failures++; };

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const pub = path.join(root, 'public');
const sha256 = (buf: Buffer) => crypto.createHash('sha256').update(buf).digest('hex');
const walk = (dir: string, out: string[] = []): string[] => { for (const e of fs.readdirSync(dir, { withFileTypes: true })) { const p = path.join(dir, e.name); if (e.isDirectory()) walk(p, out); else out.push(p); } return out; };

// ---- 1+2. manifest ↔ served bytes ↔ watchdog pin ----
const manifest = JSON.parse(fs.readFileSync(path.join(root, 'release-manifest.json'), 'utf8'));
const bundleFile = path.join(pub, manifest.bundle.path.replace(/^\//, ''));
ok(fs.existsSync(bundleFile) && sha256(fs.readFileSync(bundleFile)) === manifest.bundle.sha256, 'manifest bundle sha256 matches the served bundle');
const watchdog = fs.readFileSync(path.join(pub, 'boot-watchdog.js'), 'utf8');
ok(watchdog.includes(manifest.bundle.sha256) && watchdog.includes(manifest.bundle.path), 'boot watchdog pin matches the manifest (path + sha256)');
let fileMismatch = 0;
for (const [rel, want] of Object.entries(manifest.files)) {
  const f = path.join(pub, rel);
  if (!fs.existsSync(f) || sha256(fs.readFileSync(f)) !== want) fileMismatch++;
}
ok(fileMismatch === 0, `all ${Object.keys(manifest.files).length} manifest files match the served tree`);
const indexHtml = fs.readFileSync(path.join(pub, 'index.html'), 'utf8');
ok(!indexHtml.includes('type="module"'), 'built index.html has no direct module script (watchdog is the only loader)');
ok(indexHtml.includes('/boot-watchdog.js'), 'built index.html loads the boot watchdog');
ok(/\/boot-watchdog\.js\?v=[0-9a-f]{16}/.test(indexHtml), 'watchdog URL is versioned per build (a stale cached watchdog can never be reused)');

// ---- 3. endpoint scan ----
const endpoints = new Set<string>(manifest.endpoints);
const hostOf = (u: string) => { try { return new URL(u).host; } catch { return null; } };
const missing: string[] = [];
for (const f of ['client/lib/chains-data.ts', 'client/lib/wallet.ts', 'client/main.ts']) {
  const src = fs.readFileSync(path.join(root, f), 'utf8');
  for (const m of src.matchAll(/(?:rpc|lcd|rest|blockscout|wss|wsRpc)\s*:\s*'(https?|wss?):\/\/([a-zA-Z0-9.-]+)/g)) if (!endpoints.has(m[2])) missing.push(`${m[2]} (${f})`);
  for (const m of src.matchAll(/rpcPool\s*:\s*'([^']+)'/g)) for (const u of m[1].split(',')) { const h = hostOf(u.trim()); if (h && !endpoints.has(h)) missing.push(`${h} (${f} rpcPool)`); }
}
const stampSrc = fs.readFileSync(path.join(root, 'scripts/stamp-integrity.mjs'), 'utf8');
const directBlock = stampSrc.match(/const DIRECT = \[([\s\S]*?)\];/);
ok(!!directBlock, 'stamp script carries the curated DIRECT host list');
if (directBlock) for (const m of directBlock[1].matchAll(/'([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})'/g)) if (!endpoints.has(m[1])) missing.push(`${m[1]} (DIRECT)`);
ok(missing.length === 0, `every code connection host is inside the CSP endpoint inventory${missing.length ? ' — missing: ' + missing.slice(0, 6).join(', ') : ''} (${endpoints.size} hosts)`);

// ---- 4. egress hygiene ----
const clientSrc = walk(path.join(root, 'client')).filter((f) => f.endsWith('.ts') || f.endsWith('.js')).map((f) => fs.readFileSync(f, 'utf8')).join('\n');
ok(!clientSrc.includes('sendBeacon'), 'no sendBeacon in the client source');
const shippedJs = walk(pub).filter((f) => f.endsWith('.js')).map((f) => fs.readFileSync(f, 'utf8')).join('\n');
ok(!shippedJs.includes('sendBeacon'), 'no sendBeacon in the shipped JS');
const ANALYTICS = ['google-analytics.com', 'googletagmanager.com', 'api.mixpanel.com', 'cdn.segment.com', 'api.segment.io', 'sentry.io', 'app.launchdarkly.com', 'api.amplitude.com', 'static.hotjar.com', 'fullstory.com', 'app.posthog.com', 'heapanalytics.com'];
const foundAnalytics = ANALYTICS.filter((h) => shippedJs.includes(h));
ok(foundAnalytics.length === 0, `no analytics/telemetry/error-reporting domains in the shipped JS${foundAnalytics.length ? ' — found: ' + foundAnalytics.join(', ') : ''}`);
ok(!endpoints.has('pulse.walletconnect.org'), 'WC telemetry endpoint (pulse.walletconnect.org) is NOT in the CSP connect-src allowlist');
const wcSrc = fs.readFileSync(path.join(root, 'client/lib/walletconnect.ts'), 'utf8');
ok(/telemetryEnabled:\s*false/.test(wcSrc), 'WalletConnect client init pins telemetryEnabled: false');
ok(shippedJs.includes('telemetryEnabled'), 'shipped WC chunk carries the telemetry flag (init option reaches the SDK)');

console.log(failures ? `\n${failures} FAILURES` : '\nALL PASS');
process.exit(failures ? 1 : 0);
