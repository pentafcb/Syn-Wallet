// Token catalog generator v4 (stage 1) — discovery from Trust
// Wallet's curated token lists (jsDelivr mirror of trustwallet/
// assets); ordering by CoinGecko market-cap rank matched on
// name+symbol (ORDER ONLY — cg ids are assigned by contract in the
// stage-2 enrichment, scripts/gen-token-catalog.mjs); decimals
// verified ON-CHAIN through the app's own RPC proxies. Cap 500.
// Also writes candidates.json (every verified entry) for stage 2.
import { writeFileSync, readFileSync } from 'node:fs';

const CAP = 500;
const RPC = 'https://127.0.0.1:8801/api/rpc/';
const builtins = JSON.parse(readFileSync('/tmp/catgen/builtins.json', 'utf8'));
const builtinKeys = new Set(builtins.map(b => b.chainId + ':' + b.contract.toLowerCase()));

const NAME_OK = /^[\p{L}\p{N}][\p{L}\p{N} .&'()+-]*$/u;
const SYMBOL_OK = /^[A-Za-z0-9][A-Za-z0-9 ._-]*$/;
const SCAMMY = /(airdrop|claim|bonus|visit|www\.|\.com\b|\.io\b|\.org\b)/i;
const okName = n => typeof n === 'string' && n.length >= 2 && n.length <= 64 && NAME_OK.test(n.trim()) && !SCAMMY.test(n);
const okSym = s => typeof s === 'string' && s.length >= 1 && s.length <= 12 && SYMBOL_OK.test(s.trim()) && !SCAMMY.test(s);
const sleep = ms => new Promise(s => setTimeout(s, ms));
const fetchJson = async (url, tries = 3) => {
  let last;
  for (let i = 0; i < tries; i++) {
    try {
      const r = await fetch(url, { headers: { 'user-agent': 'syn-wallet-catalog-gen', accept: 'application/json' }, signal: AbortSignal.timeout(45000) });
      if (r.status === 429) { last = new Error('429 ' + url); await sleep(6000 * (i + 1)); continue; }
      if (!r.ok) throw new Error('HTTP ' + r.status + ' ' + url);
      return await r.json();
    } catch (e) { last = e; await sleep(2500 * (i + 1)); }
  }
  throw last;
};

// ---------- discovery: Trust Wallet lists ----------
const TW = { ethereum: 'ethereum', smartchain: 'bnb', polygon: 'polygon', arbitrum: 'arbitrum', optimism: 'optimism', base: 'base', fantom: 'fantom', solana: 'solana', zksync: 'zksync' };
const cand = new Map();
for (const [dir, chainId] of Object.entries(TW)) {
  try {
    const j = await fetchJson(`https://cdn.jsdelivr.net/gh/trustwallet/assets@master/blockchains/${dir}/tokenlist.json`);
    for (const t of j.tokens || []) {
      if (!t.address) continue;
      const key = chainId + ':' + String(t.address).toLowerCase();
      if (cand.has(key) || builtinKeys.has(key)) continue;
      cand.set(key, { chainId, contract: t.address, name: t.name, symbol: t.symbol, decimals: t.decimals });
    }
    console.log('TW', dir, '-> candidates', cand.size);
  } catch (e) { console.log('TW', dir, 'failed:', String(e).slice(0, 60)); }
}

// ---------- rank (order only) from CoinGecko markets ----------
const rankOf = new Map();
try {
  for (const page of [1, 2, 3]) {
    const m = await fetchJson(`https://api.coingecko.com/api/v3/coins/markets?vs_currency=usd&order=market_cap_desc&per_page=250&page=${page}&sparkline=false`);
    for (const c of m) { const k = String(c.symbol).toUpperCase() + '|' + String(c.name).toLowerCase(); if (!rankOf.has(k)) rankOf.set(k, rankOf.size); }
  }
} catch (e) { console.log('cg markets failed:', String(e).slice(0, 60)); }
console.log('rank entries:', rankOf.size);

// ---------- on-chain decimals verification ----------
import { request as httpsRequest } from 'node:https';
const rpcCall = (chainId, method, params) => new Promise((resolve, reject) => {
  const body = JSON.stringify({ jsonrpc: '2.0', id: 1, method, params });
  const req = httpsRequest(RPC + chainId, { method: 'POST', headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) }, rejectUnauthorized: false, timeout: 15000 }, (res) => {
    let data = '';
    res.on('data', d => { data += d; });
    res.on('end', () => { try { const j = JSON.parse(data); if (j.error) reject(new Error(j.error.message || 'rpc error')); else resolve(j.result); } catch (e) { reject(e); } });
  });
  req.on('timeout', () => req.destroy(new Error('rpc timeout')));
  req.on('error', reject);
  req.write(body); req.end();
});
async function chainDecimals(c) {
  if (c.chainId === 'solana') {
    const v = await rpcCall('solana', 'getTokenSupply', [c.contract]);
    return v?.value?.decimals;
  }
  const hex = await rpcCall(c.chainId, 'eth_call', [{ to: c.contract, data: '0x313ce567' }, 'latest']);
  return Number(BigInt(hex));
}

const ordered = [...cand.values()].map((c, i) => ({ c, i, rank: rankOf.get(String(c.symbol || '').toUpperCase() + '|' + String(c.name || '').toLowerCase()) ?? 1e9 }))
  .sort((a, b) => a.rank - b.rank || a.i - b.i).map(x => x.c);
const out = [];
const perChainSym = new Map();
const CHUNK = 40;
for (let i = 0; i < ordered.length && out.length < CAP; i += CHUNK) {
  const batch = ordered.slice(i, i + CHUNK);
  const results = await Promise.all(batch.map(async c => {
    if (!okName(c.name) || !okSym(c.symbol)) return null;
    if (c.chainId === 'solana') { if (!/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(c.contract)) return null; }
    else if (!/^0x[0-9a-fA-F]{40}$/.test(c.contract) || /^0x0{40}$/.test(c.contract)) return null;
    let dec;
    try { dec = await chainDecimals(c); } catch { return null; }
    if (!Number.isInteger(dec) || dec < 0 || dec > 36) return null;
    return { ...c, decimals: dec };
  }));
  for (const r of results) {
    if (!r || out.length >= CAP) continue;
    const symKey = r.chainId + ':' + r.symbol.toUpperCase();
    if ((perChainSym.get(symKey) || 0) >= 2) continue;
    perChainSym.set(symKey, (perChainSym.get(symKey) || 0) + 1);
    const slug = r.chainId === 'solana' ? r.contract.slice(0, 10) : r.contract.slice(2, 12).toLowerCase();
    out.push({ id: `cat-${r.chainId}-${slug}`, chainId: r.chainId, contract: r.contract, name: r.name.trim(), symbol: r.symbol.trim(), decimals: r.decimals });
  }
  console.log('verified batch -> kept', out.length);
}
const idSeen = new Map();
for (const t of out) { if (idSeen.has(t.id)) { const n = idSeen.get(t.id) + 1; idSeen.set(t.id, n); t.id = t.id + '-' + n; } else idSeen.set(t.id, 1); }
const byChainOut = {};
for (const t of out) byChainOut[t.chainId] = (byChainOut[t.chainId] || 0) + 1;
console.log('FINAL:', out.length, JSON.stringify(byChainOut));
writeFileSync('/tmp/catgen/catalog-entries.json', JSON.stringify(out, null, 1));

export const renderCatalog = (entries) => {
  const body = entries.map(t => `  { id: '${t.id}', chainId: '${t.chainId}', contract: '${t.contract}', name: ${JSON.stringify(t.name)}, symbol: ${JSON.stringify(t.symbol)}, decimals: ${t.decimals}${t.cg ? `, cg: '${t.cg}'` : ''} },`).join('\n');
  return `// Token catalog for the Add token browser — GENERATED by
// scripts/gen-token-catalog.mjs (2026-11-20) from Trust Wallet's
// curated token lists and GeckoTerminal's top pools, CoinGecko ids
// resolved by contract via GeckoTerminal, market-cap ranked, and
// every entry's decimals verified ON-CHAIN through Syn's own RPC
// proxies before inclusion. Entries already in BUILTIN_TOKENS are
// excluded. A catalog entry is NOT a wallet token: it becomes one
// only when the user adds it, which copies the def into
// config.tokens — so the catalog costs zero balance fetches and
// zero Home rows by itself.
export interface CatalogToken { id: string; chainId: string; contract: string; name: string; symbol: string; decimals: number; cg?: string }
export const TOKEN_CATALOG: CatalogToken[] = [
${body}
];
`;
};
writeFileSync('/tmp/catgen/token-catalog.ts', renderCatalog(out));
console.log('written token-catalog.ts');
