// Release integrity checker — re-hashes the SERVED client assets and
// compares them against the release manifest (release-manifest.json
// at the app root, written by scripts/stamp-integrity.mjs at build
// time). Run hourly by syn-wallet-integrity.timer and after deploys
// (`systemctl start syn-wallet-integrity.service`).
//
// Checks:
//   - every manifest file exists with a matching SHA-256;
//   - no file exists in public/ that the manifest does not list
//     (an unexpected script or asset is drift, never silent);
//   - the shipped bundle contains no external host string that the
//     manifest's bundleHosts baseline does not know (a new endpoint
//     appearing in a build is a release-note-level event).
// Result is printed loudly (journal via the systemd unit) and written
// to data/integrity-status.json, which /api/health surfaces as its
// "integrity" field. Exit code 1 on any drift.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const args = process.argv.slice(2);
const rootIdx = args.indexOf('--root');
const root = rootIdx >= 0 ? args[rootIdx + 1] : path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const pub = path.join(root, 'public');
const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest('hex');
const walkFiles = (dir, out = []) => { for (const e of fs.readdirSync(dir, { withFileTypes: true })) { const p = path.join(dir, e.name); if (e.isDirectory()) walkFiles(p, out); else out.push(p); } return out; };

const findings = [];
let manifest;
try {
  manifest = JSON.parse(fs.readFileSync(path.join(root, 'release-manifest.json'), 'utf8'));
} catch (e) {
  console.error(`INTEGRITY FAILED: release manifest unreadable at ${root}: ${e.message}`);
  process.exit(1);
}

// 1. manifest files present + unchanged
let verified = 0;
for (const [rel, want] of Object.entries(manifest.files)) {
  const f = path.join(pub, rel);
  if (!fs.existsSync(f)) { findings.push(`MISSING served file: ${rel}`); continue; }
  const got = sha256(fs.readFileSync(f));
  if (got !== want) findings.push(`CHANGED served file: ${rel} (sha256 ${got.slice(0, 16)}… != manifest ${String(want).slice(0, 16)}…)`);
  else verified++;
}
// 2. no unlisted files in the served tree
const listed = new Set(Object.keys(manifest.files));
for (const f of walkFiles(pub)) {
  const rel = path.relative(pub, f).split(path.sep).join('/');
  if (!listed.has(rel)) findings.push(`UNEXPECTED file in served tree: ${rel}`);
}
// 3. bundle host-string drift
try {
  const bundleText = fs.readFileSync(path.join(pub, manifest.bundle.path.replace(/^\//, '')), 'utf8');
  const known = new Set(manifest.bundleHosts);
  for (const m of bundleText.matchAll(/(?:https?|wss?):\/\/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/g)) {
    if (!known.has(m[1])) findings.push(`NEW endpoint host in bundle: ${m[1]}`);
  }
} catch (e) {
  findings.push(`bundle unreadable: ${e.message}`);
}

const status = findings.length ? 'failed' : 'ok';
const detail = findings.length ? findings.slice(0, 8).join('; ') : `${verified} files verified against release manifest (build ${manifest.build})`;
try {
  fs.mkdirSync(path.join(root, 'data'), { recursive: true });
  fs.writeFileSync(path.join(root, 'data', 'integrity-status.json'), JSON.stringify({ status, detail, checkedAt: new Date().toISOString(), build: manifest.build }, null, 2) + '\n');
} catch (e) {
  console.error(`INTEGRITY WARNING: could not write status file: ${e.message}`);
}
if (findings.length) {
  for (const f of findings) console.error(`INTEGRITY FAILED: ${f}`);
  console.error(`INTEGRITY FAILED: ${findings.length} finding(s) — served assets differ from release build ${manifest.build}`);
  process.exit(1);
}
console.log(`integrity ok: ${detail}`);
