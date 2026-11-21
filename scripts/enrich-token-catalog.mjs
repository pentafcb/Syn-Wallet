// Stage 2 enrichment — slow-paced GeckoTerminal pass over the
// stage-1 catalog: (1) top up thin chains from GT top pools
// (real-liquidity tokens), (2) resolve CoinGecko ids BY CONTRACT via
// GT multi-token for every entry missing one, (3) verify new entries'
// decimals on-chain, (4) re-sort by true CG market-cap rank and
// rewrite token-catalog.ts. GT free tier 429s aggressively from this
// IP, so calls are paced 7s apart with long backoff.
import { writeFileSync, readFileSync } from 'node:fs';
import { request as httpsRequest } from 'node:https';

const CAP = 500;
const RPC = 'https://127.0.0.1:8801/api/rpc/';
const builtins = JSON.parse(readFileSync('/tmp/catgen/builtins.json', 'utf8'));
const builtinKeys = new Set(builtins.map(b => b.chainId + ':' + b.contract.toLowerCase()));
const entries = JSON.parse(readFileSync('/tmp/catgen/catalog-entries.json', 'utf8'));
const have = new Set(entries.map(t => t.chainId + ':' + t.contract.toLowerCase()));

const NAME_OK = /^[\p{L}\p{N}][\p{L}\p{N} .&'()+-]*$/u;
const SYMBOL_OK = /^[A-Za-z0-9][A-Za-z0-9 ._-]*$/;
const SCAMMY = /(airdrop|claim|bonus|visit|www\.|\.com\b|\.io\b|\.org\b)/i;
const okName = n => typeof n === 'string' && n.length >= 2 && n.length <= 64 && NAME_OK.test(n.trim()) && !SCAMMY.test(n);
const okSym = s => typeof s === 'string' && s.length >= 1 && s.length <= 12 && SYMBOL_OK.test(s.trim()) && !SCAMMY.test(s);
const sleep = ms => new Promise(s => setTimeout(s, ms));

const gtJson = async (url) => {
  let last;
  for (let i = 0; i < 6; i++) {
    try {
      const r = await fetch(url, { headers: { 'user-agent': 'syn-wallet-catalog-gen', accept: 'application/json' }, signal: AbortSignal.timeout(45000) });
      if (r.status === 429) { console.log('GT 429, backing off 45s'); await sleep(45000); continue; }
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return await r.json();
    } catch (e) { last = e; await sleep(8000); }
  }
  throw last;
};
const GT = { ethereum: 'eth', polygon: 'polygon_pos', bnb: 'bsc', arbitrum: 'arbitrum', base: 'base', optimism: 'optimism', avalanche: 'avax', fantom: 'fantom', zksync: 'zksync', solana: 'solana' };

// (1) top-up discovery from GT top pools on thin chains
const fresh = [];
for (const chainId of ['polygon', 'arbitrum', 'base', 'optimism', 'avalanche']) {
  const net = GT[chainId];
  try {
    for (const page of [1, 2]) {
      const j = await gtJson(`https://api.geckoterminal.com/api/v2/networks/${net}/pools?page=${page}`);
      await sleep(7000);
      const inc = new Map((j.included || []).filter(x => x.type === 'token').map(x => [x.id, x.attributes]));
      for (const p of j.data || []) {
        if (Number(p.attributes?.reserve_in_usd || 0) < 50000) continue;
        for (const rel of ['base_token', 'quote_token']) {
          const at = inc.get(p.relationships?.[rel]?.data?.id);
          if (!at?.address) continue;
          const key = chainId + ':' + at.address.toLowerCase();
          if (have.has(key) || builtinKeys.has(key)) continue;
          have.add(key);
          fresh.push({ chainId, contract: at.address, name: at.name, symbol: at.symbol, decimals: at.decimals });
        }
      }
    }
    console.log('topup', chainId, '-> fresh candidates', fresh.length);
  } catch (e) { console.log('topup', chainId, 'failed:', String(e).slice(0, 60)); }
}

// (2) cg by contract for everything missing one (existing + fresh)
const cgByKey = new Map();
const needCg = [...entries.filter(t => !t.cg), ...fresh];
const byChain = new Map();
for (const t of needCg) { if (!byChain.has(t.chainId)) byChain.set(t.chainId, []); byChain.get(t.chainId).push(t); }
for (const [chainId, arr] of byChain) {
  const net = GT[chainId]; if (!net) continue;
  for (let i = 0; i < arr.length; i += 30) {
    const batch = arr.slice(i, i + 30);
    try {
      const j = await gtJson(`https://api.geckoterminal.com/api/v2/networks/${net}/tokens/multi/${batch.map(c => c.contract).join(',')}`);
      await sleep(7000);
      for (const d of j.data || []) {
        const a = d.attributes || {};
        if (a.coingecko_coin_id) cgByKey.set(chainId + ':' + String(a.address).toLowerCase(), a.coingecko_coin_id);
      }
      console.log('cg batch', chainId, i, '-> resolved total', cgByKey.size);
    } catch (e) { console.log('cg batch', chainId, i, 'failed:', String(e).slice(0, 60)); }
  }
}
for (const t of entries) if (!t.cg) t.cg = cgByKey.get(t.chainId + ':' + t.contract.toLowerCase());
for (const t of fresh) t.cg = cgByKey.get(t.chainId + ':' + t.contract.toLowerCase());

// (3) verify fresh on-chain
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
const perChainSym = new Map();
for (const t of entries) perChainSym.set(t.chainId + ':' + t.symbol.toUpperCase(), (perChainSym.get(t.chainId + ':' + t.symbol.toUpperCase()) || 0) + 1);
const verifiedFresh = [];
for (let i = 0; i < fresh.length; i += 40) {
  const batch = fresh.slice(i, i + 40);
  const results = await Promise.all(batch.map(async c => {
    if (!okName(c.name) || !okSym(c.symbol)) return null;
    if (c.chainId === 'solana') { if (!/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(c.contract)) return null; }
    else if (!/^0x[0-9a-fA-F]{40}$/.test(c.contract) || /^0x0{40}$/.test(c.contract)) return null;
    try {
      let dec;
      if (c.chainId === 'solana') { const v = await rpcCall('solana', 'getTokenSupply', [c.contract]); dec = v?.value?.decimals; }
      else { const hex = await rpcCall(c.chainId, 'eth_call', [{ to: c.contract, data: '0x313ce567' }, 'latest']); dec = Number(BigInt(hex)); }
      if (!Number.isInteger(dec) || dec < 0 || dec > 36) return null;
      return { ...c, decimals: dec };
    } catch { return null; }
  }));
  for (const r of results) {
    if (!r) continue;
    const symKey = r.chainId + ':' + r.symbol.toUpperCase();
    if ((perChainSym.get(symKey) || 0) >= 2) continue;
    perChainSym.set(symKey, (perChainSym.get(symKey) || 0) + 1);
    const slug = r.chainId === 'solana' ? r.contract.slice(0, 10) : r.contract.slice(2, 12).toLowerCase();
    verifiedFresh.push({ id: `cat-${r.chainId}-${slug}`, chainId: r.chainId, contract: r.contract, name: r.name.trim(), symbol: r.symbol.trim(), decimals: r.decimals, ...(r.cg ? { cg: r.cg } : {}) });
  }
}
console.log('fresh verified:', verifiedFresh.length);

// (4) merge, rank-sort, cap, write
const rankOf = new Map();
try {
  for (const page of [1, 2, 3]) {
    const r = await fetch(`https://api.coingecko.com/api/v3/coins/markets?vs_currency=usd&order=market_cap_desc&per_page=250&page=${page}&sparkline=false`, { headers: { 'user-agent': 'syn-wallet-catalog-gen' }, signal: AbortSignal.timeout(45000) });
    const m = await r.json();
    for (const c of m) if (!rankOf.has(c.id)) rankOf.set(c.id, rankOf.size);
    await sleep(3000);
  }
} catch (e) { console.log('rank failed:', String(e).slice(0, 60)); }
const all = [...entries, ...verifiedFresh];
const idSeen = new Map();
for (const t of all) { if (idSeen.has(t.id)) { const n = idSeen.get(t.id) + 1; idSeen.set(t.id, n); t.id = t.id + '-' + n; } else idSeen.set(t.id, 1); }
const merged = all.map((t, i) => ({ t, i, rank: t.cg ? (rankOf.get(t.cg) ?? 1e9) : 1e9 })).sort((a, b) => a.rank - b.rank || a.i - b.i).map(x => x.t).slice(0, CAP);
const byChainOut = {};
for (const t of merged) byChainOut[t.chainId] = (byChainOut[t.chainId] || 0) + 1;
console.log('FINAL:', merged.length, JSON.stringify(byChainOut), '| with cg:', merged.filter(t => t.cg).length);
writeFileSync('/tmp/catgen/catalog-entries.json', JSON.stringify(merged, null, 1));
const body = merged.map(t => `  { id: '${t.id}', chainId: '${t.chainId}', contract: '${t.contract}', name: ${JSON.stringify(t.name)}, symbol: ${JSON.stringify(t.symbol)}, decimals: ${t.decimals}${t.cg ? `, cg: '${t.cg}'` : ''} },`).join('\n');
const ts = `// Token catalog for the Add token browser — GENERATED by
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
writeFileSync('/tmp/catgen/token-catalog.ts', ts);
console.log('written token-catalog.ts', ts.length, 'bytes');
