// Syn Wallet server — dumb static host + price/RPC proxy ONLY.
// It NEVER receives, logs or stores any seed, private key or password.
// All key material lives exclusively in the user's browser.
import fs from 'fs';
import http from 'http';
import https from 'https';
import path from 'path';
import { createHmac } from 'node:crypto';
import { WebSocketServer, WebSocket as WsSocket } from 'ws';
import { fileURLToPath } from 'url';
import express, { Request, Response, NextFunction } from 'express';
import compression from 'compression';
import { execSync } from 'child_process';
import { PublicKey } from '@solana/web3.js';
import { getAssociatedTokenAddressSync } from '@solana/spl-token';
import { keccak_256 } from '@noble/hashes/sha3';
import { BUILD_ID as STAMPED_BUILD_ID } from './build-id.js';
import { CONNECT_HOSTS } from './csp-hosts.js';
import { twConfigured, twCoinStatus, twValidate, twTickers } from './tw.js';

// The build this server was compiled from (stamped at `npm run build`,
// see scripts/stamp-build.mjs). Reported on /api/health so clients can
// tell when they are running a stale copy. SYN_BUILD_ID overrides it —
// an ops/testing knob, not part of normal operation.
const BUILD_ID = process.env.SYN_BUILD_ID || STAMPED_BUILD_ID;

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(__dirname, '..');
const PORT = Number(process.env.PORT || 8801);
const REDIRECT_PORT = Number(process.env.SYN_REDIRECT_PORT || 8800);
const DATA_DIR = path.join(ROOT, 'data');
const tlsKey = path.join(DATA_DIR, 'tls', 'key.pem');
const tlsCert = path.join(DATA_DIR, 'tls', 'cert.pem');

function ensureTls(): boolean {
  if (fs.existsSync(tlsKey) && fs.existsSync(tlsCert)) return true;
  try {
    fs.mkdirSync(path.dirname(tlsKey), { recursive: true });
    execSync(`openssl req -x509 -newkey rsa:2048 -keyout "${tlsKey}" -out "${tlsCert}" -days 825 -nodes -subj "/CN=79.108.164.56" -addext "subjectAltName=IP:79.108.164.56,DNS:localhost"`, { stdio: 'ignore' });
    return fs.existsSync(tlsKey);
  } catch { return false; }
}
const TLS = ensureTls();

const app = express();
app.disable('x-powered-by');
// Deep audit 2026-11-22: responses were served completely
// uncompressed — the ~1.4 MB main bundle cost ~1.4 MB on the wire on
// every cold load (the long-standing slow phone boot). gzip/brotli
// cuts the JS/CSS/HTML payload by roughly two-thirds. Transport
// encoding only: the bytes a browser decodes are identical, so the
// boot watchdog's hash pins and the integrity manifest are unaffected.
app.use(compression());
app.use(express.json({ limit: '256kb' }));
app.use((req: Request, res: Response, next: NextFunction) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()');
  // Strict CSP (security checklist pass, 2026-11-19). The endpoint set
  // IS enumerated now: connect-src is built from CONNECT_HOSTS
  // (src/csp-hosts.ts, generated at build time from the chain
  // registries + the audited direct-API list — see
  // scripts/stamp-integrity.mjs and the release manifest). Every
  // built-in network, API and relay the client dials is in the list;
  // anything else — including a hypothetical injected exfiltration
  // call, or the WalletConnect SDK's pulse.walletconnect.org
  // telemetry endpoint (deliberately excluded; telemetry is also
  // disabled in the client init) — is blocked by the browser.
  // Known trade-off, accepted by the checklist: user-typed custom RPC
  // URLs and NFT metadata hosted on arbitrary one-off domains fall
  // outside the allowlist and are blocked; IPFS/Arweave metadata via
  // the standard gateways (in the list) keeps working.
  // script-src 'self' with no unsafe-inline/unsafe-eval: no remote or
  // injected code can ever execute — the boundary that protects key
  // material. style-src keeps 'unsafe-inline' because the app renders
  // pervasive inline style attributes (styles cannot execute code).
  // img-src keeps https: because NFT artwork and token icons live on
  // arbitrary hosts (images cannot execute code; connect-src is what
  // guards data egress). media-src 'none': the app renders no media
  // elements. worker-src 'self' covers the kill-switch service worker.
  const connectSrc = "'self' " + CONNECT_HOSTS.map((h) => `https://${h} wss://${h}`).join(' ');
  res.setHeader('Content-Security-Policy', `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob: https:; font-src 'self'; media-src 'none'; connect-src ${connectSrc}; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; worker-src 'self'`);
  if (TLS) res.setHeader('Strict-Transport-Security', 'max-age=31536000');
  next();
});

// ---- Audit H-8 (2026-11-19): per-IP rate limiting on /api ----
// No auth exists by design (the server is a public proxy), so a single
// abusive client could burn the shared upstream quotas (CoinGecko,
// RPC pools, LI.FI/Jupiter pass-throughs) for everyone. A simple
// fixed-window limiter: 600 requests/minute per IP across /api (far
// above any real wallet session — the app polls a handful of endpoints
// per minute), with a stricter 60/minute bucket for the expensive
// uncached paths. Exceeding it is a plain 429 JSON.
const rlBuckets = new Map<string, { at: number; n: number }>();
function rateLimit(maxPerMin: number, label?: string) {
  return (req: Request, res: Response, next: NextFunction) => {
    const ip = (req.socket.remoteAddress || 'unknown').replace(/^::ffff:/, '');
    // Buckets are PER ROUTE (label), as every call site intends:
    // keying by the limit number alone made every 120/min route share
    // ONE bucket, so ordinary app traffic (balances, token logos,
    // history) plus the per-card Hyperliquid feeds starved skew and
    // candles into 429s while the unlimited markets route sailed on
    // (owner's bug 2026-11-24: prices load, Long/Short % never does).
    const key = `${label || maxPerMin}:${ip}`;
    const now = Date.now();
    let b = rlBuckets.get(key);
    if (!b || now - b.at >= 60000) { b = { at: now, n: 0 }; rlBuckets.set(key, b); }
    if (rlBuckets.size > 5000) { for (const [k, v] of rlBuckets) if (now - v.at >= 60000) rlBuckets.delete(k); }
    b.n++;
    if (b.n > maxPerMin) { res.status(429).json({ error: 'rate limited' }); return; }
    next();
  };
}
app.use('/api', rateLimit(600));

// ---- CoinGecko proxy + resilient cache ----
// One resilience model for every CoinGecko-backed endpoint:
//  - fresh window: serve from memory, zero upstream calls;
//  - stale-while-revalidate: past the fresh window the cached copy is
//    served instantly and refreshed in the background — a screen never
//    waits on CoinGecko, and concurrent requests share ONE in-flight
//    upstream fetch per key (no stampede);
//  - serve-stale on failure: if the upstream errors (incl. 429), the last
//    good copy is served, flagged `stale` — once a series has loaded it
//    effectively never goes unavailable again;
//  - 429 backoff: a 429 puts that key on cooldown (Retry-After honoured,
//    else 90s) plus a short global cooldown, because CoinGecko limits per
//    IP — a rate-limit window stops burning budget instead of retrying;
//  - persistence: the caches are written to data/cg-cache.json (PUBLIC
//    market data only — never anything user-specific) so a deploy or
//    restart does not cold-start them back into an upstream rate limit.
class CgError extends Error {
  status: number; retryAfterMs: number;
  constructor(status: number, retryAfterMs = 0) { super(`coingecko ${status}`); this.status = status; this.retryAfterMs = retryAfterMs; }
}
let cgGlobalCooldownUntil = 0;
async function cgFetch(url: string): Promise<any> {
  // A 429 is failed FAST and reported with its Retry-After — the cache
  // layer turns it into a cooldown; retrying inside the window only burns
  // more of the per-IP budget. Transient 5xx errors get one retry after a
  // short pause.
  let lastErr: Error | null = null;
  for (let attempt = 0; attempt < 2; attempt++) {
    if (attempt > 0) await new Promise(r => setTimeout(r, 900));
    const r = await fetch(url, { headers: { accept: 'application/json' }, signal: AbortSignal.timeout(10000) });
    if (r.ok) return r.json();
    if (r.status === 429) {
      const ra = Number(r.headers.get('retry-after'));
      const ms = Number.isFinite(ra) && ra > 0 ? Math.min(Math.max(ra * 1000, 15000), 300000) : 90000;
      throw new CgError(429, ms);
    }
    lastErr = new CgError(r.status);
    if (r.status < 500) break;
  }
  throw lastErr ?? new Error('coingecko error');
}

type SwrEntry = { at: number; data: any };
class SwrCache {
  entries = new Map<string, SwrEntry>();
  private inflight = new Map<string, Promise<any>>();
  private cooldownUntil = new Map<string, number>();
  constructor(private freshMs: number, private onStore: () => void) {}
  // Resolves with the freshest copy available. Throws ONLY when the key
  // has never loaded and the fetch fails (a truly cold start).
  async get(key: string, fetcher: () => Promise<any>): Promise<{ data: any; stale: boolean }> {
    const hit = this.entries.get(key);
    if (hit && Date.now() - hit.at < this.freshMs) return { data: hit.data, stale: false };
    if (hit) {
      // Serve stale instantly; ONE background refresh revalidates.
      void this.refresh(key, fetcher).catch(() => { /* stale already served */ });
      return { data: hit.data, stale: true };
    }
    return { data: await this.refresh(key, fetcher), stale: false };
  }
  private refresh(key: string, fetcher: () => Promise<any>): Promise<any> {
    const existing = this.inflight.get(key);
    if (existing) return existing;
    const cd = Math.max(this.cooldownUntil.get(key) || 0, cgGlobalCooldownUntil);
    if (Date.now() < cd) return Promise.reject(new Error('coingecko cooldown'));
    const p = (async () => {
      try {
        const data = await fetcher();
        this.entries.set(key, { at: Date.now(), data });
        // Deep audit 2026-11-22: entries/cooldowns were never evicted
        // in memory (only the disk dump was sliced) and keys are
        // attacker-influenced (arbitrary market/chart IDs) — bound
        // both maps, oldest first.
        if (this.entries.size > 400) { const sorted = [...this.entries.entries()].sort((a, b) => a[1].at - b[1].at); for (const [k] of sorted.slice(0, this.entries.size - 400)) this.entries.delete(k); }
        if (this.cooldownUntil.size > 400) { const now = Date.now(); for (const [k, v] of this.cooldownUntil) if (v <= now) this.cooldownUntil.delete(k); if (this.cooldownUntil.size > 400) { const sorted = [...this.cooldownUntil.entries()].sort((a, b) => a[1] - b[1]); for (const [k] of sorted.slice(0, this.cooldownUntil.size - 400)) this.cooldownUntil.delete(k); } }
        this.onStore();
        return data;
      } catch (e) {
        if (e instanceof CgError && e.status === 429) {
          this.cooldownUntil.set(key, Date.now() + e.retryAfterMs);
          cgGlobalCooldownUntil = Math.max(cgGlobalCooldownUntil, Date.now() + Math.min(Math.max(e.retryAfterMs, 15000), 90000));
        } else if (!this.entries.has(key)) {
          // Audit H-8: a cold miss that fails must not be re-attempted
          // on every request — negative-cache the failure briefly so a
          // down upstream (or a flood of distinct keys) can't amplify.
          this.cooldownUntil.set(key, Date.now() + 15000);
        }
        throw e;
      } finally { this.inflight.delete(key); }
    })();
    this.inflight.set(key, p);
    return p;
  }
  dump(): [string, SwrEntry][] { return [...this.entries.entries()].sort((a, b) => b[1].at - a[1].at).slice(0, 300); }
  restore(rows: [string, SwrEntry][]) {
    // Audit H-7: a disk-restored entry is the weakest-validated data in
    // the system — validate it like fresh data: numeric timestamp, not
    // from the future, not ancient, and a real payload object.
    const now = Date.now();
    for (const [k, v] of rows || []) {
      if (!k || !v || typeof v.at !== 'number' || !Number.isFinite(v.at)) continue;
      if (v.at > now + 60000 || now - v.at > 48 * 3600_000) continue;
      if (!('data' in v) || v.data == null || typeof v.data !== 'object') continue;
      this.entries.set(k, v);
    }
  }
}

const CG_IDS: Record<string, string> = { solana: 'solana', ethereum: 'ethereum', bitcoin: 'bitcoin', bnb: 'binancecoin', matic: 'polygon-ecosystem-token', polygon: 'polygon-ecosystem-token' };
// Fresh windows: prices/markets stay at 60s (they are the live numbers and
// SWR means requests never block on the upstream anyway); chart/ohlc get
// 5 minutes — candle/line series do not need 60s freshness, and the longer
// window cuts their upstream burn 5x.
const pricesCache = new SwrCache(60000, () => persistCgCaches());
const marketsCache = new SwrCache(60000, () => persistCgCaches());
const chartCache = new SwrCache(300000, () => persistCgCaches());
const ohlcCache = new SwrCache(300000, () => persistCgCaches());

// ---- Price service: one multi-source store behind /api/prices + /api/markets ----
// A server-side poller (see pollPrices below) keeps a price entry for every
// asset the app shows, refreshing from CoinGecko first and failing over
// WHOLESALE per asset to Binance, then Coinbase, then Kraken — all keyless
// public APIs, all verified reachable from this server. One refresh cycle
// serves every connected client, so a single source's 429 or outage never
// surfaces in the app while another source (or the last-known entry) has
// data. Every figure comes from a real source: failover sources that can't
// provide a field (Kraken has no market cap; its ticker has no true 24h
// open) leave the last real value in place instead of inventing one.
// Per-source attribution stays server-side; clients just get prices.
interface PriceEntry { usd: number | null; change24h: number | null; high24h: number | null; low24h: number | null; marketCap: number | null; marketCapChange24h: number | null; at: number; src: string }
const priceStore = new Map<string, PriceEntry>();
const bandPending = new Map<string, { usd: number; at: number }>();
interface PriceAsset { cg: string; binance?: string; coinbase?: string; kraken?: string; krakenCode?: string }
const PRICE_ASSETS: PriceAsset[] = [
  { cg: 'bitcoin', binance: 'BTCUSDT', coinbase: 'BTC-USD', kraken: 'BTCUSD', krakenCode: 'XBT' },
  { cg: 'ethereum', binance: 'ETHUSDT', coinbase: 'ETH-USD', kraken: 'ETHUSD', krakenCode: 'ETH' },
  { cg: 'solana', binance: 'SOLUSDT', coinbase: 'SOL-USD', kraken: 'SOLUSD', krakenCode: 'SOL' },
  { cg: 'binancecoin', binance: 'BNBUSDT', coinbase: 'BNB-USD', kraken: 'BNBUSD', krakenCode: 'BNB' },
  // CoinGecko's polygon-ecosystem-token IS the migrated POL asset (1:1);
  // exchanges list it under POL.
  { cg: 'polygon-ecosystem-token', binance: 'POLUSDT', coinbase: 'POL-USD', kraken: 'POLUSD', krakenCode: 'POL' },
  { cg: 'tron', binance: 'TRXUSDT', coinbase: 'TRX-USD', kraken: 'TRXUSD', krakenCode: 'TRX' },
  { cg: 'ripple', binance: 'XRPUSDT', coinbase: 'XRP-USD', kraken: 'XRPUSD', krakenCode: 'XRP' },
  { cg: 'cosmos', binance: 'ATOMUSDT', coinbase: 'ATOM-USD', kraken: 'ATOMUSD', krakenCode: 'ATOM' },
  { cg: 'sui', binance: 'SUIUSDT', coinbase: 'SUI-USD', kraken: 'SUIUSD', krakenCode: 'SUI' },
  { cg: 'aptos', binance: 'APTUSDT', coinbase: 'APT-USD', kraken: 'APTUSD', krakenCode: 'APT' },
  { cg: 'avalanche-2', binance: 'AVAXUSDT', coinbase: 'AVAX-USD', kraken: 'AVAXUSD', krakenCode: 'AVAX' },
  { cg: 'tether', coinbase: 'USDT-USD', kraken: 'USDTUSD', krakenCode: 'USDT' },
  { cg: 'usd-coin', coinbase: 'USDC-USD', kraken: 'USDCUSD', krakenCode: 'USDC' },
  // No reliable keyless exchange listing — CoinGecko + cache only.
  { cg: 'fantom' },
  { cg: 'staked-ether' },
];
const BINANCE_BY_CG: Record<string, string> = Object.fromEntries(PRICE_ASSETS.filter(a => a.binance).map(a => [a.cg, a.binance!]));
function setPrice(cg: string, p: { usd: number; change24h?: number | null; high24h?: number | null; low24h?: number | null; marketCap?: number | null; marketCapChange24h?: number | null }, src: string) {
  if (!(typeof p.usd === 'number' && Number.isFinite(p.usd) && p.usd > 0)) return;
  const prev = priceStore.get(cg);
  // Audit H-7: sanity band vs the previous value. A single bad upstream
  // payload must not replace a good price with BTC at $0.01 or $10^9:
  // moves beyond the band are rejected and the previous value kept.
  // Stablecoins get a tight 5% band; everything else 50% (a real 50%
  // move between 60s polls is a market event the NEXT poll confirms —
  // by then the band has re-anchored only if the move persists via
  // successive in-band steps... a genuine cliff still lands within two
  // polls because each source cycle re-reads all sources wholesale).
  if (prev?.usd) {
    const band = cg === 'tether' || cg === 'usd-coin' ? 0.05 : 0.5;
    if (Math.abs(p.usd / prev.usd - 1) > band) {
      // Out of band: accept only when a SECOND consecutive poll agrees
      // with the first out-of-band value (a real market cliff persists;
      // a single poisoned payload does not).
      const pend = bandPending.get(cg);
      if (pend && Math.abs(p.usd / pend.usd - 1) < 0.05 && Date.now() - pend.at < 180000) {
        bandPending.delete(cg);
      } else {
        bandPending.set(cg, { usd: p.usd, at: Date.now() });
        return;
      }
    } else bandPending.delete(cg);
  }
  priceStore.set(cg, {
    usd: p.usd,
    change24h: p.change24h ?? prev?.change24h ?? null,
    high24h: p.high24h ?? prev?.high24h ?? null,
    low24h: p.low24h ?? prev?.low24h ?? null,
    marketCap: p.marketCap ?? prev?.marketCap ?? null,
    // Only CoinGecko publishes a 24h market-cap change; failover sources
    // leave the last real value in place, like every other field here.
    marketCapChange24h: p.marketCapChange24h ?? prev?.marketCapChange24h ?? null,
    at: Date.now(), src,
  });
}
const priceShape = (e: PriceEntry) => ({ usd: e.usd, change24h: e.change24h, high24h: e.high24h, low24h: e.low24h, marketCap: e.marketCap, marketCapChange24h: e.marketCapChange24h ?? null });
const NULL_PRICE = { usd: null, change24h: null, high24h: null, low24h: null, marketCap: null, marketCapChange24h: null };

const CG_CACHE_FILE = path.join(DATA_DIR, 'cg-cache.json');
let cgPersistTimer: ReturnType<typeof setTimeout> | null = null;
function persistCgCaches() {
  if (cgPersistTimer) return;
  cgPersistTimer = setTimeout(() => {
    cgPersistTimer = null;
    try {
      fs.mkdirSync(DATA_DIR, { recursive: true });
      const tmp = CG_CACHE_FILE + '.tmp';
      fs.writeFileSync(tmp, JSON.stringify({ prices: pricesCache.dump(), markets: marketsCache.dump(), chart: chartCache.dump(), ohlc: ohlcCache.dump(), store: [...priceStore.entries()] }));
      fs.renameSync(tmp, CG_CACHE_FILE);
    } catch { /* best-effort: the in-memory cache still works */ }
  }, 1500);
}
try {
  const saved = JSON.parse(fs.readFileSync(CG_CACHE_FILE, 'utf8'));
  pricesCache.restore(saved.prices); marketsCache.restore(saved.markets); chartCache.restore(saved.chart); ohlcCache.restore(saved.ohlc);
  for (const [k, v] of (saved.store || [])) {
    // Audit H-7: validate restored price entries like fresh ones —
    // finite positive usd, sane timestamp, and an age cap so a poisoned
    // or ancient disk entry is never served as a live price.
    if (!k || !v || typeof v.at !== 'number' || !Number.isFinite(v.at)) continue;
    if (v.at > Date.now() + 60000 || Date.now() - v.at > 24 * 3600_000) continue;
    if (!(typeof v.usd === 'number' && Number.isFinite(v.usd) && v.usd > 0)) continue;
    priceStore.set(k, v);
  }
} catch { /* first run: caches start cold */ }

app.get('/api/prices', async (_req, res) => {
  // Store-first: the poller keeps these five fresh from multiple sources.
  // Audit H-7: entries older than 24h are never served as prices, and a
  // response built from entries older than 10 minutes says so (stale).
  const fromStore = (id: string) => { const e = priceStore.get(id); return e && e.usd != null && Date.now() - e.at < 24 * 3600_000 ? priceShape(e) : null; };
  const storeStale = ['solana', 'ethereum', 'bitcoin', 'binancecoin', 'polygon-ecosystem-token'].some(id => { const e = priceStore.get(id); return e && Date.now() - e.at >= 600000; });
  const SOL = fromStore('solana'), ETH = fromStore('ethereum'), BTC = fromStore('bitcoin'), BNB = fromStore('binancecoin'), MATIC = fromStore('polygon-ecosystem-token');
  if (SOL || ETH || BTC || BNB || MATIC) {
    res.json({ SOL: SOL ?? NULL_PRICE, ETH: ETH ?? NULL_PRICE, BTC: BTC ?? NULL_PRICE, BNB: BNB ?? NULL_PRICE, MATIC: MATIC ?? NULL_PRICE, at: Date.now(), ...(storeStale ? { stale: true } : {}) });
    return;
  }
  // Cold boot (poller hasn't landed a cycle yet): the SWR CoinGecko path.
  try {
    const { data, stale } = await pricesCache.get('all', async () => {
      const ids = 'solana,ethereum,bitcoin,binancecoin,polygon-ecosystem-token';
      const arr = await cgFetch(`https://api.coingecko.com/api/v3/coins/markets?vs_currency=usd&ids=${ids}&price_change_percentage=24h`);
      const byId: Record<string, any> = {}; for (const m of (Array.isArray(arr) ? arr : [])) byId[m.id] = m;
      // Audit H-7: type-check every picked field — a string/null/garbage
      // payload from upstream becomes null (unavailable), never a price.
      const num = (v: any) => (typeof v === 'number' && Number.isFinite(v) ? v : null);
      const pick = (id: string) => { const m = byId[id]; const usd = num(m?.current_price); return { usd: usd != null && usd > 0 ? usd : null, change24h: num(m?.price_change_percentage_24h), high24h: num(m?.high_24h), low24h: num(m?.low_24h), marketCap: num(m?.market_cap), marketCapChange24h: num(m?.market_cap_change_percentage_24h) }; };
      return {
        SOL: pick('solana'),
        ETH: pick('ethereum'),
        BTC: pick('bitcoin'),
        BNB: pick('binancecoin'),
        MATIC: pick('polygon-ecosystem-token'),
        at: Date.now(),
      };
    });
    res.json(stale ? { ...data, stale: true } : data);
  } catch (e) {
    res.status(502).json({ error: 'Prices unavailable' });
  }
});
// Generic CoinGecko markets proxy for arbitrary coin ids (Wave 1A registry
// chains + non-EVM families). Public market data only; 60s fresh per
// id-set with SWR + stale fallback (see the cache model above).
app.get('/api/markets', async (req, res) => {
  const ids = String(req.query.ids || '').split(',').map(s => s.trim().toLowerCase()).filter(s => /^[a-z0-9-]{2,60}$/.test(s)).slice(0, 100);
  if (!ids.length) { res.status(400).json({ error: 'no valid ids' }); return; }
  // Curated ids come from the multi-source price store; anything else
  // (long-tail registry coins, custom tokens) falls back to the on-demand
  // SWR CoinGecko path below.
  const out: Record<string, any> = {};
  const need: string[] = [];
  for (const id of ids) {
    const e = priceStore.get(id);
    if (e && e.usd != null) out[id] = priceShape(e); else need.push(id);
  }
  if (need.length) {
    const key = [...need].sort().join(',');
    try {
      const { data } = await marketsCache.get(key, async () => {
        const arr = await cgFetch(`https://api.coingecko.com/api/v3/coins/markets?vs_currency=usd&ids=${encodeURIComponent(key)}&price_change_percentage=24h`);
        const o: Record<string, any> = {};
        for (const m of (Array.isArray(arr) ? arr : [])) o[m.id] = { usd: m?.current_price ?? null, change24h: m?.price_change_percentage_24h ?? null, high24h: m?.high_24h ?? null, low24h: m?.low_24h ?? null, marketCap: m?.market_cap ?? null, marketCapChange24h: m?.market_cap_change_percentage_24h ?? null };
        o.at = Date.now();
        return o;
      });
      for (const id of need) if (data[id]) out[id] = data[id];
    } catch { /* unserved ids stay absent — the client keeps its last price */ }
  }
  out.at = Date.now();
  res.json(out);
});
// Binance klines: real OHLCV from a keyless exchange API whose volume is
// already in coin units. For every asset Binance lists, charts stop
// depending on CoinGecko entirely; CoinGecko remains the fallback for the
// rest. Returns [t, open, high, low, close, volumeCoinUnits] rows.
async function binanceKlines(symbol: string, interval: string, limit: number): Promise<number[][] | null> {
  for (const host of ['https://data-api.binance.vision', 'https://api.binance.com']) {
    try {
      const r = await fetch(`${host}/api/v3/klines?symbol=${symbol}&interval=${interval}&limit=${limit}`, { headers: { accept: 'application/json' }, signal: AbortSignal.timeout(10000) });
      if (!r.ok) continue;
      const arr = await r.json();
      if (!Array.isArray(arr) || !arr.length) continue;
      const rows = arr.map((k: any) => [Number(k[0]), Number(k[1]), Number(k[2]), Number(k[3]), Number(k[4]), Number(k[5])]).filter(c => c[4] > 0);
      if (rows.length) return rows;
    } catch { /* next host */ }
  }
  return null;
}
// OHLC + volume proxy for the price chart (asset/token detail). Returns
// candles with volumes in coin units so the client only aggregates:
// Binance klines when the asset is listed there, else CoinGecko OHLC
// merged with market_chart volumes (USD volume / close). days=1 is the
// chart's 1D range: 24 hourly buckets (Binance 1h klines; CoinGecko's
// 1-day OHLC arrives as 30-minute candles and the client merges them
// into hours). Public market data only; 5-minute fresh cache per
// id+days with SWR + stale fallback.
// The candle loader behind /api/ohlc, shared with /api/dex/ohlc
// (which resolves a contract to its CoinGecko id when it has one).
async function cgOhlcData(id: string, days: string): Promise<{ data: any; stale: boolean }> {
  const key = `${id}:${days}`;
  return ohlcCache.get(key, async () => {
    const sym = BINANCE_BY_CG[id];
    if (sym) {
      const [interval, limit] = days === '1' ? ['1h', 24] : days === '7' ? ['4h', 42] : days === '30' ? ['4h', 180] : ['1d', 365];
      const kl = await binanceKlines(sym, interval as string, limit as number);
      if (kl && kl.length) return { id, days: Number(days), candles: kl, at: Date.now() };
    }
    const [ohlc, mc] = await Promise.all([
      cgFetch(`https://api.coingecko.com/api/v3/coins/${id}/ohlc?vs_currency=usd&days=${days}`),
      cgFetch(`https://api.coingecko.com/api/v3/coins/${id}/market_chart?vs_currency=usd&days=${days}`),
    ]);
    const raw: [number, number, number, number, number][] = (Array.isArray(ohlc) ? ohlc : []).filter((c: any) => Array.isArray(c) && c.length >= 5 && c[4] > 0);
    const vols: [number, number][] = (mc?.total_volumes || []).filter((p: any) => Array.isArray(p) && p[1] >= 0);
    // Sum USD volume into each candle's window [t, nextT), then convert to
    // coin units with the candle's close — an honest traded-volume estimate.
    const candles = raw.map((c, i) => {
      const end = i + 1 < raw.length ? raw[i + 1][0] : Number.POSITIVE_INFINITY;
      let usd = 0; for (const [vt, vv] of vols) if (vt >= c[0] && vt < end) usd += vv;
      return [c[0], c[1], c[2], c[3], c[4], c[4] > 0 ? usd / c[4] : 0];
    });
    return { id, days: Number(days), candles, at: Date.now() };
  });
}
app.get('/api/ohlc', async (req, res) => {
  const id = String(req.query.id || '').toLowerCase();
  if (!/^[a-z0-9-]{2,60}$/.test(id)) { res.status(400).json({ error: 'unknown coin' }); return; }
  const days = ['1', '7', '30', '365'].includes(String(req.query.days)) ? String(req.query.days) : '7';
  try {
    const { data, stale } = await cgOhlcData(id, days);
    res.json(stale ? { ...data, stale: true } : data);
  } catch (e) {
    res.status(502).json({ error: 'OHLC unavailable' });
  }
});
app.get('/api/chart/:coin', async (req, res) => {
  const coinKey = String(req.params.coin || '').toLowerCase();
  const cgId = CG_IDS[coinKey] || (/^[a-z0-9-]{2,60}$/.test(coinKey) ? coinKey : undefined);
  if (!cgId) { res.status(400).json({ error: 'unknown coin' }); return; }
  const range = String(req.query.range || '24h');
  const days = range === '7d' ? '7' : range === '30d' || range === '1m' ? '30' : '1';
  const key = `${cgId}:${days}`;
  try {
    const { data, stale } = await chartCache.get(key, async () => {
      const sym = BINANCE_BY_CG[cgId];
      if (sym) {
        const [interval, limit] = days === '1' ? ['5m', 288] : days === '7' ? ['1h', 168] : ['4h', 180];
        const kl = await binanceKlines(sym, interval as string, limit as number);
        if (kl && kl.length) return { coin: coinKey, cgId, range, prices: kl.map(c => [c[0], c[4]] as [number, number]), at: Date.now() };
      }
      const j = await cgFetch(`https://api.coingecko.com/api/v3/coins/${cgId}/market_chart?vs_currency=usd&days=${days}`);
      const prices: [number, number][] = (j.prices || []).filter((p: any) => Array.isArray(p) && p[1] > 0);
      return { coin: coinKey, cgId, range, prices, at: Date.now() };
    });
    res.json(stale ? { ...data, stale: true } : data);
  } catch (e) {
    res.status(502).json({ error: 'Chart unavailable' });
  }
});

// ---- Price poller: one cycle per minute serves every client ----
// SYN_DISABLE_CG=1 is an ops kill-switch that takes CoinGecko out of the
// rotation entirely; the failover sources then carry the store alone.
let pollRunning = false;
async function pollPrices() {
  if (pollRunning) return;
  pollRunning = true;
  try {
    const updated = new Set<string>();
    // 1) CoinGecko batch — primary, and the only source with market caps.
    if (!process.env.SYN_DISABLE_CG && Date.now() >= cgGlobalCooldownUntil) {
      try {
        const ids = PRICE_ASSETS.map(a => a.cg).join(',');
        const arr = await cgFetch(`https://api.coingecko.com/api/v3/coins/markets?vs_currency=usd&ids=${ids}&price_change_percentage=24h`);
        for (const m of (Array.isArray(arr) ? arr : [])) {
          if (m && m.id && typeof m.current_price === 'number') {
            setPrice(m.id, { usd: m.current_price, change24h: m.price_change_percentage_24h, high24h: m.high_24h, low24h: m.low_24h, marketCap: m.market_cap, marketCapChange24h: m.market_cap_change_percentage_24h }, 'coingecko');
            updated.add(m.id);
          }
        }
      } catch (e) {
        if (e instanceof CgError && e.status === 429) cgGlobalCooldownUntil = Math.max(cgGlobalCooldownUntil, Date.now() + e.retryAfterMs);
      }
    }
    const missing = () => PRICE_ASSETS.filter(a => !updated.has(a.cg));
    // 2) Binance batch — true 24h stats in a single call.
    if (missing().length) {
      try {
        const syms = missing().filter(a => a.binance).map(a => a.binance!);
        if (syms.length) {
          const q = encodeURIComponent(JSON.stringify(syms));
          let arr: any = null;
          for (const host of ['https://data-api.binance.vision', 'https://api.binance.com']) {
            try {
              const r = await fetch(`${host}/api/v3/ticker/24hr?symbols=${q}`, { headers: { accept: 'application/json' }, signal: AbortSignal.timeout(10000) });
              if (r.ok) { arr = await r.json(); break; }
            } catch { /* next host */ }
          }
          if (Array.isArray(arr)) for (const t of arr) {
            const a = PRICE_ASSETS.find(x => x.binance === t.symbol);
            if (!a) continue;
            setPrice(a.cg, { usd: Number(t.lastPrice), change24h: Number(t.priceChangePercent), high24h: Number(t.highPrice), low24h: Number(t.lowPrice) }, 'binance');
            updated.add(a.cg);
          }
        }
      } catch { /* next source */ }
    }
    // 3) Coinbase per-asset stats — its open is the price 24h ago, so the
    // change computed from it is a true 24h change.
    for (const a of missing()) {
      if (!a.coinbase) continue;
      try {
        const r = await fetch(`https://api.exchange.coinbase.com/products/${a.coinbase}/stats`, { headers: { accept: 'application/json' }, signal: AbortSignal.timeout(8000) });
        if (!r.ok) continue;
        const s: any = await r.json();
        const last = Number(s.last), open = Number(s.open);
        if (!(last > 0)) continue;
        setPrice(a.cg, { usd: last, change24h: open > 0 ? ((last - open) / open) * 100 : null, high24h: Number(s.high) || null, low24h: Number(s.low) || null }, 'coinbase');
        updated.add(a.cg);
      } catch { /* next asset */ }
    }
    // 4) Kraken batch — last price + true 24h high/low (its ticker arrays
    // carry [today, last24h]); it publishes no 24h open, so change24h
    // keeps its last real value via setPrice's preserve-on-null.
    if (missing().length) {
      try {
        const want = missing().filter(a => a.kraken);
        if (want.length) {
          const r = await fetch(`https://api.kraken.com/0/public/Ticker?pair=${want.map(a => a.kraken).join(',')}`, { headers: { accept: 'application/json' }, signal: AbortSignal.timeout(10000) });
          if (r.ok) {
            const j: any = await r.json();
            const result = j?.result || {};
            const keys = Object.keys(result);
            for (const a of want) {
              const key = keys.find(k => k === a.kraken) || keys.filter(k => k.endsWith('USD') && k.includes(a.krakenCode!) && k.length <= a.krakenCode!.length + 5).sort((x, y) => x.length - y.length)[0];
              const t = key ? result[key] : null;
              if (!t) continue;
              setPrice(a.cg, { usd: Number(t.c?.[0]), high24h: Number(t.h?.[1]) || null, low24h: Number(t.l?.[1]) || null }, 'kraken');
              updated.add(a.cg);
            }
          }
        }
      } catch { /* store keeps last-known values */ }
    }
    if (updated.size) persistCgCaches();
  } finally { pollRunning = false; }
}
void pollPrices();
setInterval(() => void pollPrices(), 60000);

// ---- RPC pools: several public endpoints per chain, health-tracked ----
// Every member below was live-probed from this server at build time
// (eth_getBalance / getBalance answered correctly). Members that fail at
// transport level (network error, timeout, HTTP 429/5xx) are marked down
// for 30s and skipped; a JSON-RPC error body is a legitimate answer and
// is returned verbatim, never failed over. An operator can replace any
// pool without a rebuild via SYN_RPC_POOL_<CHAIN>="url1,url2,...".
type PoolMember = { url: string; downUntil: number; fails: number };
class RpcPool {
  members: PoolMember[];
  constructor(urls: string[]) { this.members = urls.map(url => ({ url, downUntil: 0, fails: 0 })); }
  private order(): PoolMember[] {
    const now = Date.now();
    return [...this.members.filter(m => m.downUntil <= now), ...this.members.filter(m => m.downUntil > now)];
  }
  private bad(m: PoolMember) { m.fails++; m.downUntil = Date.now() + 30000; }
  private good(m: PoolMember) { m.fails = 0; m.downUntil = 0; }
  async post(body: any, timeoutMs = 12000): Promise<{ status: number; text: string; url: string }> {
    let lastErr: Error | null = null;
    const candidates = this.order();
    for (let i = 0; i < Math.min(candidates.length, 3); i++) {
      const m = candidates[i];
      try {
        const r = await fetch(m.url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body), signal: AbortSignal.timeout(timeoutMs) });
        const text = await r.text();
        // Audit 2026-11-21: responses were buffered whole with no
        // cap — a heavy upstream answer (wide log scans, vote-account
        // dumps) could park tens of MB per request in memory. 16MB is
        // far above any answer this wallet consumes.
        if (text.length > 16_000_000) { return { status: 413, text: JSON.stringify({ jsonrpc: '2.0', id: (body as any)?.id ?? null, error: { code: -32000, message: 'upstream response too large' } }), url: m.url }; }
        if (r.status === 429 || r.status >= 500) { this.bad(m); lastErr = new Error(`rpc http ${r.status}`); continue; }
        this.good(m);
        return { status: r.status, text, url: m.url };
      } catch (e) { this.bad(m); lastErr = e as Error; }
    }
    throw lastErr ?? new Error('all RPC pool members failed');
  }
  // Balance-service calls: these callers want a RESULT, not a specific
  // node's answer — so unlike the verbatim proxy below, a JSON-RPC error
  // from one member (method gated, rate limited, …) also fails over to
  // the next member before surfacing.
  async rpcEach(method: string, params: any[]): Promise<any> {
    let lastErr: Error | null = null;
    const candidates = this.order();
    for (let i = 0; i < Math.min(candidates.length, 3); i++) {
      const m = candidates[i];
      try {
        const r = await fetch(m.url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }), signal: AbortSignal.timeout(12000) });
        const text = await r.text();
        if (r.status === 429 || r.status >= 500) { this.bad(m); lastErr = new Error(`rpc http ${r.status}`); continue; }
        const j = JSON.parse(text);
        if (j.error) { this.bad(m); lastErr = new Error(j.error.message || 'RPC error'); continue; }
        this.good(m);
        return j.result;
      } catch (e) { this.bad(m); lastErr = e as Error; }
    }
    throw lastErr ?? new Error('all RPC pool members failed');
  }
}
function poolUrls(chain: string, defaults: string[]): string[] {
  const env = process.env[`SYN_RPC_POOL_${chain.toUpperCase()}`];
  if (env) { const urls = env.split(',').map(s => s.trim()).filter(Boolean); if (urls.length) return urls; }
  return defaults;
}
const RPC_POOL_DEFS: Record<string, string[]> = {
  solana: ['https://api.mainnet-beta.solana.com', 'https://solana-rpc.publicnode.com'],
  ethereum: ['https://ethereum-rpc.publicnode.com', 'https://eth.drpc.org', 'https://eth-mainnet.public.blastapi.io', 'https://1rpc.io/eth'],
  polygon: ['https://polygon-bor-rpc.publicnode.com', 'https://polygon.drpc.org', 'https://1rpc.io/matic'],
  bnb: ['https://bsc-dataseed.binance.org', 'https://bsc-rpc.publicnode.com', 'https://1rpc.io/bnb', 'https://bsc.drpc.org'],
  arbitrum: ['https://arb1.arbitrum.io/rpc', 'https://arbitrum-one-rpc.publicnode.com', 'https://arbitrum.drpc.org', 'https://1rpc.io/arb'],
  base: ['https://mainnet.base.org', 'https://base-rpc.publicnode.com', 'https://base.drpc.org', 'https://1rpc.io/base'],
  optimism: ['https://mainnet.optimism.io', 'https://optimism-rpc.publicnode.com', 'https://optimism.drpc.org'],
  avalanche: ['https://api.avax.network/ext/bc/C/rpc', 'https://avalanche-c-chain-rpc.publicnode.com', 'https://avalanche.drpc.org'],
  fantom: ['https://fantom.drpc.org'],
  zksync: ['https://mainnet.era.zksync.io'],
  xrp: ['https://s1.ripple.com:51234', 'https://s2.ripple.com:51234', 'https://xrplcluster.com'],
};
// Alchemy (operator key, server-side only — it is never shipped to
// a phone or written into this repo): prepended to the high-traffic
// pools ahead of the public endpoints, which stay as fallbacks. The
// evm-999 / evm-204 pools always exist so those chains can route
// through /api/rpc; evm-4663 (Robinhood Chain) exists only with the
// key, as no public endpoint for it is verified.
RPC_POOL_DEFS['evm-999'] = ['https://rpc.hyperliquid.xyz/evm'];
RPC_POOL_DEFS['evm-204'] = ['https://opbnb-mainnet-rpc.bnbchain.org'];
const ALCHEMY_API_KEY = process.env.ALCHEMY_API_KEY || '';
if (ALCHEMY_API_KEY) {
  const alchemy = (host: string) => `https://${host}.g.alchemy.com/v2/${ALCHEMY_API_KEY}`;
  const prepend = (chain: string, url: string) => { const defs = RPC_POOL_DEFS[chain]; if (defs && !defs.includes(url)) defs.unshift(url); };
  prepend('solana', alchemy('solana-mainnet'));
  prepend('ethereum', alchemy('eth-mainnet'));
  prepend('polygon', alchemy('polygon-mainnet'));
  prepend('base', alchemy('base-mainnet'));
  prepend('evm-999', alchemy('hyperliquid-mainnet'));
  prepend('evm-204', alchemy('opbnb-mainnet'));
  RPC_POOL_DEFS['evm-4663'] = [alchemy('robinhood-mainnet')];
}
const rpcPools = new Map<string, RpcPool>();
for (const [chain, urls] of Object.entries(RPC_POOL_DEFS)) rpcPools.set(chain, new RpcPool(poolUrls(chain, urls)));

// ---- RPC proxy (forwards JSON-RPC verbatim through the chain's pool; no
// key material ever) ----
// Audit 2026-11-21: this route fronts the operator's paid Alchemy
// key and accepted ANY JSON-RPC method at the global 600/min — an
// open quota tap for the heaviest scan methods. It now carries its
// own 300/min bucket (far above a real wallet session) and refuses
// the known account-scan methods outright; the app never issues
// them (balances go through the balance service / bounded calls).
const RPC_BLOCKED_METHODS = new Set(['getprogramaccounts', 'gettokenaccountsbyowner', 'gettokenaccountsbydelegate', 'getlargestaccounts', 'getclusternodes']);
app.post('/api/rpc/:chain', rateLimit(300), async (req, res) => {
  const pool = rpcPools.get(String(req.params.chain || ''));
  if (!pool) { res.status(400).json({ error: 'unknown chain' }); return; }
  const calls = Array.isArray(req.body) ? req.body : [req.body];
  for (const c of calls) {
    const m = typeof (c as any)?.method === 'string' ? ((c as any).method as string).toLowerCase() : '';
    // Deep audit 2026-11-22: debug_/trace_ namespaces are never used
    // by the app and are the heaviest calls a node offers — refuse
    // the whole namespaces alongside the named scan methods.
    if (!m || RPC_BLOCKED_METHODS.has(m) || m.startsWith('debug_') || m.startsWith('trace_')) { res.status(403).json({ jsonrpc: '2.0', id: (c as any)?.id ?? null, error: { code: -32601, message: 'method not allowed on this relay' } }); return; }
  }
  try {
    const { status, text } = await pool.post(req.body || {}, 15000);
    res.status(status).type('application/json').send(text);
  } catch (e) { res.status(502).json({ jsonrpc: '2.0', id: (req.body as any)?.id ?? null, error: { code: -32000, message: String((e as Error).message).replace(/https?:\/\/\S+/gi, '').slice(0, 120) } }); }
});
// ---- Solana validators, trimmed + cached ----
// getVoteAccounts returns EVERY vote account (thousands of entries,
// megabytes of JSON) and the Stake screen only ever shows the top
// 100 by stake — reading it through the phone was the screen's whole
// load time. This endpoint does the read server-side once, trims to
// the top 150 in the client's own ValidatorInfo shape, and caches
// for 5 minutes (validator stakes move slowly); stale beats a 502.
let stakeValCache: { at: number; body: string } | null = null;
app.get('/api/stake/validators', async (_req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.type('application/json');
  if (stakeValCache && Date.now() - stakeValCache.at < 300_000) { res.send(stakeValCache.body); return; }
  const pool = rpcPools.get('solana');
  if (!pool) { res.status(502).json({ error: 'no solana pool' }); return; }
  try {
    const { status, text } = await pool.post({ jsonrpc: '2.0', id: 1, method: 'getVoteAccounts', params: [] }, 25000);
    if (status !== 200) throw new Error('rpc ' + status);
    const result = JSON.parse(text)?.result;
    const rows: { votePubkey: string; nodePubkey: string; activatedStakeSol: number; commission: number; delinquent: boolean }[] = [];
    const push = (list: any, delinquent: boolean) => {
      for (const v of (Array.isArray(list) ? list : [])) {
        if (!v?.votePubkey) continue;
        rows.push({ votePubkey: String(v.votePubkey), nodePubkey: String(v.nodePubkey || ''), activatedStakeSol: Number(v.activatedStake || 0) / 1e9, commission: Number(v.commission || 0), delinquent });
      }
    };
    push(result?.current, false);
    push(result?.delinquent, true);
    rows.sort((a, b) => b.activatedStakeSol - a.activatedStakeSol);
    const body = JSON.stringify(rows.slice(0, 150));
    stakeValCache = { at: Date.now(), body };
    res.send(body);
  } catch {
    if (stakeValCache) { res.send(stakeValCache.body); return; }
    res.status(502).json({ error: 'validators unavailable' });
  }
});
// UTXO-family data (Bitcoin + Litecoin) via keyless esplora-shaped
// APIs with failover per chain. Litecoin's source is litecoinspace
// (the mempool.space fork for LTC — same esplora response shapes,
// verified live 2026-11-20: /api/address, /api/address/:a/utxo,
// /api/address/:a/txs, /api/v1/fees/recommended all answer).
const UTXO_APIS: Record<string, string[]> = {
  bitcoin: ['https://blockstream.info', 'https://mempool.space'],
  litecoin: ['https://litecoinspace.org'],
};
// Deep audit 2026-11-22: only the RPC pool capped upstream response
// size (16 MB); every other proxy buffered the entire upstream body
// unbounded — a huge or compromised upstream response was a memory
// DoS. All proxy body reads now go through this capped reader.
const MAX_UPSTREAM_BODY = 16 * 1024 * 1024;
async function readBodyCapped(r: globalThis.Response, cap = MAX_UPSTREAM_BODY): Promise<string> {
  const cl = Number(r.headers.get('content-length') || 0);
  if (cl > cap) throw new Error('upstream response too large');
  const reader = (r.body as any)?.getReader?.();
  if (!reader) { const t = await r.text(); if (t.length > cap) throw new Error('upstream response too large'); return t; }
  const chunks: Uint8Array[] = []; let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > cap) { try { await reader.cancel(); } catch { /* already closed */ } throw new Error('upstream response too large'); }
    chunks.push(value);
  }
  const all = new Uint8Array(total); let off = 0;
  for (const c of chunks) { all.set(c, off); off += c.byteLength; }
  return new TextDecoder().decode(all);
}
async function utxoGet(chain: string, p: string): Promise<{ status: number; text: string }> {
  const bases = UTXO_APIS[chain]; if (!bases) throw new Error('unknown utxo chain');
  let lastErr: Error | null = null;
  for (const base of bases) {
    try {
      const r = await fetch(`${base}${p}`, { signal: AbortSignal.timeout(10000) });
      const text = await readBodyCapped(r);
      if (r.status >= 500) { lastErr = new Error(`utxo api ${r.status}`); continue; }
      return { status: r.status, text };
    } catch (e) { lastErr = e as Error; }
  }
  throw lastErr ?? new Error('utxo api unreachable');
}
async function utxoPostTx(chain: string, hex: string): Promise<string> {
  const bases = UTXO_APIS[chain]; if (!bases) throw new Error('unknown utxo chain');
  let lastErr: Error | null = null;
  for (const base of bases) {
    try {
      const r = await fetch(`${base}/api/tx`, { method: 'POST', headers: { 'content-type': 'text/plain' }, body: hex, signal: AbortSignal.timeout(15000) });
      const text = (await r.text()).trim();
      if (r.ok && /^[0-9a-f]{64}$/i.test(text)) return text.toLowerCase();
      lastErr = new Error(text.slice(0, 160) || `broadcast ${r.status}`);
      if (r.status < 500) break; // a rejection (bad tx) is definitive — don't retry it elsewhere
    } catch (e) { lastErr = e as Error; }
  }
  throw lastErr ?? new Error('broadcast failed');
}
app.get('/api/utxo/:chain/address/:addr', rateLimit(120, 'utxo'), async (req, res) => {
  try {
    const { status, text } = await utxoGet(String(req.params.chain), `/api/address/${encodeURIComponent(req.params.addr)}`);
    res.status(status).type('application/json').send(text);
  } catch { res.status(502).json({ error: 'UTXO data unavailable' }); }
});
app.get('/api/utxo/:chain/txs/:addr', rateLimit(120, 'utxo'), async (req, res) => {
  try {
    const { status, text } = await utxoGet(String(req.params.chain), `/api/address/${encodeURIComponent(req.params.addr)}/txs`);
    res.status(status).type('application/json').send(text);
  } catch { res.status(502).json({ error: 'UTXO data unavailable' }); }
});
app.get('/api/utxo/:chain/utxo/:addr', rateLimit(120, 'utxo'), async (req, res) => {
  try {
    const { status, text } = await utxoGet(String(req.params.chain), `/api/address/${encodeURIComponent(req.params.addr)}/utxo`);
    res.status(status).type('application/json').send(text);
  } catch { res.status(502).json({ error: 'UTXO data unavailable' }); }
});
// Normalized fee estimate: { satVb } — esplora /fee-estimates where
// the source offers it (blockstream), else the mempool-style
// /api/v1/fees/recommended (mempool.space + litecoinspace). Target:
// roughly next-3-blocks / half-hour. Floored at 1 sat/vB.
app.get('/api/utxo/:chain/fees', rateLimit(120, 'utxo'), async (req, res) => {
  const chain = String(req.params.chain);
  try {
    try {
      const { status, text } = await utxoGet(chain, '/api/fee-estimates');
      if (status === 200) { const j = JSON.parse(text); const v = Number(j['3'] ?? j['6'] ?? j['1']); if (v > 0) { res.json({ satVb: Math.max(1, Math.ceil(v)) }); return; } }
    } catch { /* fall through to the mempool-style endpoint */ }
    const { status, text } = await utxoGet(chain, '/api/v1/fees/recommended');
    if (status !== 200) throw new Error('fees unavailable');
    const j = JSON.parse(text); const v = Number(j.halfHourFee ?? j.fastestFee);
    if (!(v > 0)) throw new Error('fees unavailable');
    res.json({ satVb: Math.max(1, Math.ceil(v)) });
  } catch { res.status(502).json({ error: 'Fee data unavailable' }); }
});
app.post('/api/utxo/:chain/tx', rateLimit(60), async (req, res) => {
  const hex = String((req.body as any)?.hex || '');
  if (!/^[0-9a-fA-F]{100,200000}$/.test(hex)) { res.status(400).json({ error: 'invalid tx hex' }); return; }
  try { const txid = await utxoPostTx(String(req.params.chain), hex.toLowerCase()); res.json({ txid }); }
  catch (e) { res.status(502).json({ error: 'Broadcast failed: ' + String((e as Error).message).slice(0, 160) }); }
});
// Legacy BTC paths (kept for any client built before the
// generalization; same handlers, chain pinned to bitcoin).
app.get('/api/btc/address/:addr', async (req, res) => {
  try {
    const { status, text } = await utxoGet('bitcoin', `/api/address/${encodeURIComponent(req.params.addr)}`);
    res.status(status).type('application/json').send(text);
  } catch { res.status(502).json({ error: 'Bitcoin data unavailable' }); }
});
app.get('/api/btc/txs/:addr', async (req, res) => {
  try {
    const { status, text } = await utxoGet('bitcoin', `/api/address/${encodeURIComponent(req.params.addr)}/txs`);
    res.status(status).type('application/json').send(text);
  } catch { res.status(502).json({ error: 'Bitcoin data unavailable' }); }
});

// ---- Balance service ----
// GET /api/balance/:chain?address=<addr>[&token=<contract|mint>][&decimals=<n>]
//   200 → { chain, address, token, balance, symbol, at, stale?, source }
//         balance is in whole coin units; 0 is a REAL answer (unfunded or
//         not-yet-activated account), never a failure placeholder.
//   502 → { error: 'Balance unavailable', chain } when every pool member
//         failed and no cached copy exists.
// The phone talks only to this endpoint for built-in chains; the server
// absorbs upstream rate limits through the pools above plus a 12-second
// per-(chain,address,token) SWR cache with request coalescing — N clients
// asking for the same balance inside the window cost ONE upstream call,
// and a failed refresh serves the last good value flagged `stale`.
// Balances are cached in memory only (an address is user data; nothing
// about it is ever written to disk or logged).
const balanceCache = new SwrCache(12000, () => { });
const CHAIN_SYMBOL: Record<string, string> = { solana: 'SOL', ethereum: 'ETH', polygon: 'MATIC', bnb: 'BNB', arbitrum: 'ETH', base: 'ETH', optimism: 'ETH', avalanche: 'AVAX', fantom: 'FTM', zksync: 'ETH', bitcoin: 'BTC', litecoin: 'LTC', tron: 'TRX', xrp: 'XRP', cosmos: 'ATOM', sui: 'SUI', aptos: 'APT' };
async function restFailover(urls: string[], init?: RequestInit): Promise<any> {
  let lastErr: Error | null = null;
  for (const url of urls) {
    try {
      const r = await fetch(url, { ...init, signal: AbortSignal.timeout(10000) });
      if (r.status === 404) return { __status: 404 };
      if (!r.ok) { lastErr = new Error(`http ${r.status}`); continue; }
      return await r.json();
    } catch (e) { lastErr = e as Error; }
  }
  throw lastErr ?? new Error('rest endpoints unreachable');
}
async function tronGetAccount(url: string, address: string): Promise<any> {
  const r = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ address, visible: true }), signal: AbortSignal.timeout(10000) });
  if (!r.ok) throw new Error(`tron node ${r.status}`);
  const j: any = await r.json();
  return j && j.address ? j : { balance: 0 };
}
async function tronBalance(address: string): Promise<number> {
  const adapters: (() => Promise<number>)[] = [
    async () => {
      const r = await fetch(`https://api.trongrid.io/v1/accounts/${encodeURIComponent(address)}`, { signal: AbortSignal.timeout(10000) });
      if (!r.ok) throw new Error(`trongrid ${r.status}`);
      const j: any = await r.json();
      const a = j?.data?.[0];
      return a ? (a.balance || 0) / 1e6 : 0;
    },
    async () => (await tronGetAccount('https://tron-rpc.publicnode.com/wallet/getaccount', address)).balance / 1e6 || 0,
    async () => (await tronGetAccount('https://api.tronstack.io/wallet/getaccount', address)).balance / 1e6 || 0,
  ];
  // Note: getaccount's balance is in sun; a missing balance field means 0.
  let lastErr: Error | null = null;
  for (const fn of adapters) { try { return await fn(); } catch (e) { lastErr = e as Error; } }
  throw lastErr ?? new Error('tron unreachable');
}
async function fetchBalanceUpstream(chain: string, address: string, token: string | null, decimals: number): Promise<number> {
  if (chain === 'bitcoin' || chain === 'litecoin') {
    try {
      const { status, text } = await utxoGet(chain, `/api/address/${encodeURIComponent(address)}`);
      if (status !== 200) throw new Error(`utxo api ${status}`);
      const j = JSON.parse(text);
      return ((j.chain_stats?.funded_txo_sum || 0) - (j.chain_stats?.spent_txo_sum || 0)) / 1e8;
    } catch (e) {
      if (chain === 'bitcoin') throw e;
      // Litecoin's only esplora source (litecoinspace.org) has no
      // same-shape failover partner and was found down (Cloudflare
      // 525 / timeouts, 2026-11-20) — with it went every LTC balance
      // and the Home total went permanently "partial". BlockCypher's
      // keyless balance endpoint is the independent second source
      // (final_balance, in satoshis).
      const r = await fetch(`https://api.blockcypher.com/v1/ltc/main/addrs/${encodeURIComponent(address)}/balance`, { signal: AbortSignal.timeout(10000) });
      if (!r.ok) throw new Error(`blockcypher ${r.status}`);
      const j: any = await r.json();
      if (typeof j?.final_balance !== 'number') throw new Error('blockcypher: no balance in response');
      return j.final_balance / 1e8;
    }
  }
  if (chain === 'tron') return tronBalance(address);
  if (chain === 'cosmos') {
    const j = await restFailover([
      `https://rest.cosmos.directory/cosmoshub/cosmos/bank/v1beta1/balances/${encodeURIComponent(address)}`,
      `https://cosmos-rest.publicnode.com/cosmos/bank/v1beta1/balances/${encodeURIComponent(address)}`,
    ]);
    const u = (j?.balances || []).find((b: any) => b.denom === 'uatom');
    return u ? Number(u.amount) / 1e6 : 0;
  }
  if (chain === 'sui') {
    // Sui's public JSON-RPC was deprecated by the foundation (the old
    // client-direct path now gets "Method not found" from every public
    // fullnode) — the official GraphQL endpoint is the keyless route.
    const j = await restFailover(['https://graphql.mainnet.sui.io/graphql'], {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ query: 'query($a: SuiAddress!) { address(address: $a) { balance(coinType: "0x2::sui::SUI") { totalBalance } } }', variables: { a: address } }),
    });
    const total = j?.data?.address?.balance?.totalBalance;
    if (total == null) { if (j?.data?.address == null && !j?.errors) return 0; throw new Error('sui: no balance in response'); }
    return Number(total) / 1e9;
  }
  if (chain === 'aptos') {
    const j = await restFailover([
      `https://api.mainnet.aptoslabs.com/v1/accounts/${encodeURIComponent(address)}/resources`,
      `https://fullnode.mainnet.aptoslabs.com/v1/accounts/${encodeURIComponent(address)}/resources`,
    ]);
    if (j?.__status === 404) return 0;
    const cs = (Array.isArray(j) ? j : []).find((r: any) => r.type === '0x1::coin::CoinStore<0x1::aptos_coin::AptosCoin>');
    return cs ? Number(cs.data?.coin?.value || 0) / 1e8 : 0;
  }
  if (chain === 'xrp') {
    const { text } = await rpcPools.get('xrp')!.post({ method: 'account_info', params: [{ account: address, ledger_index: 'validated' }] });
    const j = JSON.parse(text);
    if (j?.result?.error === 'actNotFound') return 0;
    const bal = j?.result?.account_data?.Balance;
    if (bal == null) throw new Error('xrp: no balance in response');
    return Number(bal) / 1e6;
  }
  const pool = rpcPools.get(chain);
  if (!pool) throw new Error('no pool for chain');
  if (chain === 'solana') {
    if (token) {
      try {
        const v = await pool.rpcEach('getTokenAccountsByOwner', [address, { mint: token }, { encoding: 'jsonParsed' }]);
        let sum = 0;
        for (const a of (v?.value || [])) sum += a?.account?.data?.parsed?.info?.tokenAmount?.uiAmount || 0;
        return sum;
      } catch { /* indexed query unavailable on every member — ATA read below */ }
      // Fallback for pools whose members gate the indexed by-owner query
      // (Allnodes' free public endpoint gates ALL token methods): read
      // the wallet's associated token account directly — a plain account
      // read every member serves. Counted only when the account's
      // authority is the wallet itself, matching by-owner semantics.
      const ata = getAssociatedTokenAddressSync(new PublicKey(token), new PublicKey(address)).toBase58();
      const info = await pool.rpcEach('getAccountInfo', [ata, { encoding: 'jsonParsed' }]);
      const parsed = info?.value?.data?.parsed?.info;
      if (!parsed || parsed.owner !== address) return 0;
      return parsed.tokenAmount?.uiAmount || 0;
    }
    const v = await pool.rpcEach('getBalance', [address]);
    return (v?.value ?? v) / 1e9;
  }
  if (token) {
    const data = '0x70a08231' + address.slice(2).toLowerCase().padStart(64, '0');
    const res = await pool.rpcEach('eth_call', [{ to: token, data }, 'latest']);
    if (res === '0x' || res == null) return 0;
    return Number(BigInt(res)) / 10 ** decimals;
  }
  const hex = await pool.rpcEach('eth_getBalance', [address, 'latest']);
  return Number(BigInt(hex)) / 1e18;
}
app.get('/api/balance/:chain', rateLimit(120, 'balance'), async (req, res) => {
  const chain = String(req.params.chain || '').toLowerCase();
  const address = String(req.query.address || '');
  const token = req.query.token ? String(req.query.token) : null;
  const decimals = Math.min(Math.max(Number(req.query.decimals ?? 18) || 0, 0), 36);
  if (!CHAIN_SYMBOL[chain] || !address || address.length > 128 || (token !== null && token.length > 128)) { res.status(400).json({ error: 'bad request' }); return; }
  // Audit NEW LOW 9: only hex (EVM-style) addresses are case-insensitive.
  // Lowercasing a base58 address (Solana/BTC) would merge two DISTINCT
  // addresses into one cache entry — key those exactly as given.
  const keyAddr = /^0x[0-9a-fA-F]+$/.test(address) ? address.toLowerCase() : address;
  // Decimals belong in the key: the upstream result is scaled by
  // them, so a corrected decimals value must not be served the
  // previous scaling from the SWR window.
  const key = `${chain}:${keyAddr}:${token || ''}:${decimals}`;
  try {
    const { data, stale } = await balanceCache.get(key, async () => ({ balance: await fetchBalanceUpstream(chain, address, token, decimals), at: Date.now() }));
    if (balanceCache.entries.size > 1000) {
      const oldest = [...balanceCache.entries.entries()].sort((a, b) => a[1].at - b[1].at).slice(0, 200);
      for (const [k] of oldest) balanceCache.entries.delete(k);
    }
    res.json({ chain, address, token, balance: data.balance, symbol: CHAIN_SYMBOL[chain], at: data.at, ...(stale ? { stale: true } : {}) });
  } catch (e) {
    res.status(502).json({ error: 'Balance unavailable', chain });
  }
});
// ---- Wave 2: public feature config (publishable values ONLY) ----
// WalletConnect needs a Reown project ID and the buy/sell ramps need a
// provider publishable key. Both are PUBLIC identifiers by design (they
// ship in every client that uses those services) — never secret keys.
// They come from the server environment so the operator can enable the
// features without a rebuild; empty means the feature stays honestly
// gated in the UI. Nothing user-specific is ever returned or stored.
app.get('/api/config', (_req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.json({
    walletConnectProjectId: process.env.WALLETCONNECT_PROJECT_ID || '',
    moonpayPublishableKey: process.env.MOONPAY_PUBLISHABLE_KEY || '',
    twApiConfigured: twConfigured(),
    polymarketBuilderConfigured: !!builderCreds(),
    // Public builder identity (operator config, not secrets): the
    // builder CODE is a public on-chain identifier that appears in
    // every attributed order — the client needs it to write it into
    // the signed order's builder field (CLOB V2 attribution).
    polymarketBuilderCode: builderCode(),
    polymarketBuilderAddress: builderAddress(),
  });
});

// ---- Trust Wallet API proxy (optional operator data source) ----
// Enabled only when TWAK_ACCESS_ID + TWAK_HMAC_SECRET are set in the
// server environment (see src/tw.ts). The client never sees the keys —
// only whether the source is configured. Asset ids are Trust Wallet's
// public c{coinId}[_t{contract}] identifiers; the validate route takes
// a public address the user is about to interact with, the same data
// the client's existing GoPlus address check already sends out.
const TW_ASSET_RE = /^c\d{1,12}(_t[0-9a-zA-Z.:_-]{1,90})?$/;
app.post('/api/tw/tickers', rateLimit(60), async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  if (!twConfigured()) return res.json({ configured: false, tickers: {} });
  const assets = Array.isArray(req.body?.assets)
    ? req.body.assets.filter((a: any) => typeof a === 'string' && TW_ASSET_RE.test(a)).slice(0, 50)
    : [];
  const tickers = await twTickers(assets);
  return res.json({ configured: true, tickers });
});
app.get('/api/tw/coinstatus', rateLimit(60), async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  if (!twConfigured()) return res.json({ configured: false, risk: null });
  const asset = String(req.query.asset || '');
  if (!TW_ASSET_RE.test(asset)) return res.status(400).json({ error: 'bad asset id' });
  const risk = await twCoinStatus(asset);
  return res.json({ configured: true, risk });
});
app.get('/api/tw/validate', rateLimit(60), async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  if (!twConfigured()) return res.json({ configured: false, validation: null });
  const asset = String(req.query.asset || '');
  const address = String(req.query.address || '');
  if (!TW_ASSET_RE.test(asset) || !address || address.length > 128) return res.status(400).json({ error: 'bad params' });
  const validation = await twValidate(asset, address);
  return res.json({ configured: true, validation });
});

// ---- Invest: Hyperliquid markets + account (Addition 6) ----
// Hyperliquid's public info API is keyless. The server proxies and
// normalises it (own-data-layer pattern): perpDexs enumerates the main
// dex plus every HIP-3 builder dex; metaAndAssetCtxs gives each asset's
// live mark price, previous-day price, volume and open interest. The
// account endpoint is a READ-ONLY view of a public address's
// clearinghouse state — Hyperliquid state is public by design; nothing
// about the requesting user is sent or stored.
const HL_API = 'https://api.hyperliquid.xyz/info';
async function hlPost(body: unknown): Promise<any> {
  // Audit M-15: every upstream fetch carries a timeout — a hung
  // Hyperliquid response must never pin a request (or the sequential
  // per-dex account loop) forever.
  const r = await fetch(HL_API, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body), signal: AbortSignal.timeout(15000) });
  if (!r.ok) throw new Error('hl ' + r.status);
  return JSON.parse(await readBodyCapped(r));
}
let hlMarketsCache: { at: number; data: unknown } = { at: 0, data: null };
let hlDexListCache: { at: number; dexes: any[] } = { at: 0, dexes: [] };
async function hlDexList(): Promise<any[]> {
  if (hlDexListCache.dexes.length && Date.now() - hlDexListCache.at < 5 * 60000) return hlDexListCache.dexes;
  const dexes = await hlPost({ type: 'perpDexs' });
  if (Array.isArray(dexes) && dexes.length) hlDexListCache = { at: Date.now(), dexes };
  return dexes;
}
let hlMarketsInflight: Promise<unknown> | null = null;
async function hlMarkets(): Promise<unknown> {
  if (hlMarketsCache.data && Date.now() - hlMarketsCache.at < 20000) return hlMarketsCache.data;
  // Stale-while-revalidate (2026-11-24): a cold sweep walks every
  // dex upstream and can take seconds; a phone must never block on
  // it when a previous snapshot exists. Serve the stale snapshot
  // and refresh behind it (deduped); only the first-ever request
  // pays the sweep.
  if (hlMarketsCache.data) {
    if (!hlMarketsInflight) {
      hlMarketsInflight = hlMarketsSweep().catch(() => hlMarketsCache.data).finally(() => { hlMarketsInflight = null; });
      void hlMarketsInflight;
    }
    return hlMarketsCache.data;
  }
  if (hlMarketsInflight) return hlMarketsInflight;
  hlMarketsInflight = hlMarketsSweep().finally(() => { hlMarketsInflight = null; });
  return hlMarketsInflight;
}
async function hlMarketsSweep(): Promise<unknown> {
  try {
    const dexes = await hlDexList();
    // Per-dex isolation with gentle concurrency (3 at a time — the
    // public API rate-limits bursts): a dex that fails degrades
    // ALONE (ok:false, no assets) and never takes the whole section
    // down. Delisted assets are excluded by the metadata's own
    // isDelisted flag; a dex whose markets are ALL delisted
    // (flx/hyna/vntl/km/abcd/cash at audit time) honestly
    // contributes zero rows.
    const fetchDex = async (d: any, i: number) => {
      const id = i === 0 ? '' : (d?.name || '');
      const label = i === 0 ? 'Hyperliquid' : (d?.fullName || d?.name || id);
      try {
        const [meta, ctxs] = await hlPost(id ? { type: 'metaAndAssetCtxs', dex: id } : { type: 'metaAndAssetCtxs' });
        const assets = (meta.universe as any[]).map((a: any, j: number) => {
          const c = (ctxs as any[])[j] || {};
          const mark = parseFloat(c.markPx || '0'); const prev = parseFloat(c.prevDayPx || '0');
          return { name: a.name, idx: j, szDecimals: Number(a.szDecimals ?? 0), markPx: mark, prevDayPx: prev, change24h: prev > 0 ? (mark - prev) / prev * 100 : null, dayNtlVlm: parseFloat(c.dayNtlVlm || '0'), openInterest: parseFloat(c.openInterest || '0'), funding: parseFloat(c.funding || '0'), oraclePx: parseFloat(c.oraclePx || '0'), maxLeverage: a.maxLeverage, delisted: !!a.isDelisted };
        }).filter((a: any) => !a.delisted && a.markPx > 0);
        return { id, name: label, ord: i, ok: true, assets };
      } catch { return { id, name: label, ord: i, ok: false, assets: [] as unknown[] }; }
    };
    const out: unknown[] = new Array(dexes.length);
    let next = 0;
    const workers = Array.from({ length: Math.min(3, dexes.length) }, async () => { while (next < dexes.length) { const i = next++; out[i] = await fetchDex(dexes[i], i); } });
    await Promise.all(workers);
    const data = { dexes: out, at: Date.now() };
    // A sweep in which EVERY dex failed (upstream throttling) must
    // not evict the last good snapshot: keep serving it (with a
    // fresh TTL so clients aren't hammering) until a sweep lands.
    const liveCount = (ds: any): number => (ds?.dexes || []).reduce((s: number, d: any) => s + (d?.assets?.length || 0), 0);
    if (liveCount(data) === 0 && liveCount(hlMarketsCache.data) > 0) { hlMarketsCache = { at: Date.now(), data: hlMarketsCache.data }; return hlMarketsCache.data; }
    hlMarketsCache = { at: Date.now(), data };
    return data;
  } catch (e) {
    // Upstream unreachable (rate limit / outage): serve the last
    // good snapshot rather than blanking the section — the client
    // keeps refreshing and the data self-heals on the next success.
    if (hlMarketsCache.data) return hlMarketsCache.data;
    throw e;
  }
}
// Perp candles for the market detail chart: a thin normalising proxy
// over candleSnapshot. Coin is the universe name verbatim (builder
// dex coins carry their 'dex:' prefix, which is how HL addresses
// them); interval is whitelisted; the window is bounded.
const HL_CANDLE_INTERVALS = new Set(['15m', '1h', '4h', '1d']);
const hlCandleCache = new Map<string, { at: number; data: any }>();
const hlCandleInflight = new Map<string, Promise<any>>();
// One upstream candle fetch per key, shared by the single route and
// the batch sparkline route below; fresh cache 30s, and a stale copy
// beats an error when the upstream throttles.
function hlCandlesFor(coin: string, interval: string, hours: number): Promise<any> {
  const key = `${coin}|${interval}|${hours}`;
  const hit = hlCandleCache.get(key);
  if (hit && Date.now() - hit.at < 30000) return Promise.resolve(hit.data);
  const flying = hlCandleInflight.get(key);
  if (flying) return hit ? Promise.resolve(hit.data) : flying;
  const p = (async () => {
    try {
      const end = Date.now(); const start = end - hours * 3600_000;
      const raw = await hlPost({ type: 'candleSnapshot', req: { type: 'candleSnapshot', coin, interval, startTime: start, endTime: end } });
      const candles = (Array.isArray(raw) ? raw : []).map((k: any) => ({ time: Number(k.t), open: parseFloat(k.o), high: parseFloat(k.h), low: parseFloat(k.l), close: parseFloat(k.c), volume: parseFloat(k.v || '0') })).filter((c: any) => c.time > 0 && c.close > 0);
      const data = { coin, interval, candles };
      cacheSet(hlCandleCache, key, { at: Date.now(), data }, 300);
      return data;
    } catch {
      // Throttled upstream: serve the last good candles (any age)
      // rather than blanking the chart — the next tick retries.
      if (hit) return hit.data;
      throw new Error('hyperliquid unavailable');
    }
  })();
  hlCandleInflight.set(key, p);
  void p.then(() => hlCandleInflight.delete(key), () => hlCandleInflight.delete(key));
  // Stale-while-revalidate (2026-11-24): an expired copy answers
  // instantly and the fetch above refreshes it in the background —
  // a batch of 40 coins must never wait on 40 upstream round trips.
  if (hit) return Promise.resolve(hit.data);
  return p;
}
app.get('/api/hl/candles', rateLimit(120, 'hl-candles'), async (req, res) => {
  const coin = String(req.query.coin || '');
  const interval = String(req.query.interval || '1h');
  const hours = Math.max(1, Math.min(24 * 31, Number(req.query.hours || 24) || 24));
  if (!/^[A-Za-z0-9:._-]{1,32}$/.test(coin) || !HL_CANDLE_INTERVALS.has(interval)) { res.status(400).json({ error: 'bad candle request' }); return; }
  try { res.json(await hlCandlesFor(coin, interval, hours)); } catch { res.status(502).json({ error: 'hyperliquid unavailable' }); }
});
// Long/short skew for one perp, from the market's LIVE order book:
// Hyperliquid publishes no long/short position split, so the split
// shown in the app is the book's own depth imbalance — bid notional
// vs ask notional within ±2% of mid, the real per-market pressure
// reading the public API supports. Cached 20s per coin; a stale
// entry beats an error.
const hlSkewCache = new Map<string, { at: number; data: any }>();
const hlSkewInflight = new Map<string, Promise<any>>();
// One upstream l2Book fetch per coin, shared by the single route and
// the batch route below; fresh cache 20s, a stale copy beats an
// error, and null means the coin has never produced a reading.
function hlSkewFor(coin: string): Promise<any> {
  const hit = hlSkewCache.get(coin);
  if (hit && Date.now() - hit.at < 20000) return Promise.resolve(hit.data);
  const flying = hlSkewInflight.get(coin);
  if (flying) return hit ? Promise.resolve(hit.data) : flying;
  const p = (async () => {
    try {
      const book = await hlPost({ type: 'l2Book', coin });
      const bids = (book?.levels?.[0] || []) as any[];
      const asks = (book?.levels?.[1] || []) as any[];
      const bestBid = parseFloat(bids[0]?.px || '0'); const bestAsk = parseFloat(asks[0]?.px || '0');
      if (!(bestBid > 0) || !(bestAsk > 0)) throw new Error('empty book');
      const mid = (bestBid + bestAsk) / 2;
      const ntl = (lvls: any[], keep: (px: number) => boolean): number => lvls.reduce((s, l) => { const px = parseFloat(l.px || '0'); const sz = parseFloat(l.sz || '0'); return keep(px) && px > 0 && sz > 0 ? s + px * sz : s; }, 0);
      const bidNtl = ntl(bids, px => px >= mid * 0.98);
      const askNtl = ntl(asks, px => px <= mid * 1.02);
      if (!(bidNtl + askNtl > 0)) throw new Error('no depth in band');
      const data = { coin, longPct: Math.round(100 * bidNtl / (bidNtl + askNtl)), mid };
      cacheSet(hlSkewCache, coin, { at: Date.now(), data }, 300);
      return data;
    } catch {
      if (hit) return hit.data;
      return null;
    }
  })();
  hlSkewInflight.set(coin, p);
  void p.then(() => hlSkewInflight.delete(coin), () => hlSkewInflight.delete(coin));
  // Stale-while-revalidate (2026-11-24): same contract as candles —
  // an expired reading answers instantly, the refresh lands behind it.
  if (hit) return Promise.resolve(hit.data);
  return p;
}
app.get('/api/hl/skew', rateLimit(120, 'hl-skew'), async (req, res) => {
  const coin = String(req.query.coin || '');
  if (!/^[A-Za-z0-9:._-]{1,32}$/.test(coin)) { res.status(400).json({ error: 'bad skew request' }); return; }
  const data = await hlSkewFor(coin);
  if (data) { res.json(data); return; }
  res.status(502).json({ error: 'hyperliquid unavailable' });
});
// ---- Batch list feeds (2026-11-24) ----
// The Invest perp list used to fire TWO requests per card (candles +
// skew); a phone scrolling the list blew the shared per-minute
// bucket and both feeds starved at "—" while prices (one cached
// call) loaded. The list now asks for every queued coin in ONE
// request per feed. Upstream fetches run at gentle concurrency (the
// public API throttles bursts) and share the per-coin caches with
// the single routes; a coin with no reading yet comes back null and
// the client retries it on the next 25s repaint.
const HL_BATCH_MAX = 40;
function hlBatchCoins(req: Request): string[] | null {
  const coins = String(req.query.coins || '').split(',').map(s => s.trim()).filter(Boolean);
  if (!coins.length || coins.length > HL_BATCH_MAX) return null;
  if (!coins.every(c => /^[A-Za-z0-9:._-]{1,32}$/.test(c))) return null;
  return [...new Set(coins)];
}
async function hlPool<T>(items: string[], n: number, fn: (c: string) => Promise<T>): Promise<Map<string, T>> {
  const out = new Map<string, T>();
  let next = 0;
  const workers = Array.from({ length: Math.min(n, items.length) }, async () => { while (next < items.length) { const c = items[next++]; out.set(c, await fn(c)); } });
  await Promise.all(workers);
  return out;
}
app.get('/api/hl/skews', rateLimit(240, 'hl-skews'), async (req, res) => {
  const coins = hlBatchCoins(req);
  if (!coins) { res.status(400).json({ error: 'bad skews request' }); return; }
  const got = await hlPool(coins, 4, c => hlSkewFor(c));
  const skews: Record<string, unknown> = {};
  for (const c of coins) skews[c] = got.get(c) ?? null;
  res.json({ skews });
});
app.get('/api/hl/sparklines', rateLimit(240, 'hl-sparklines'), async (req, res) => {
  const coins = hlBatchCoins(req);
  if (!coins) { res.status(400).json({ error: 'bad sparklines request' }); return; }
  const got = await hlPool(coins, 4, async c => { try { const d = await hlCandlesFor(c, '1h', 24); return (d?.candles || []).map((k: any) => k.close).filter((v: number) => v > 0) as number[]; } catch { return null; } });
  const sparks: Record<string, unknown> = {};
  for (const c of coins) { const v = got.get(c); sparks[c] = Array.isArray(v) && v.length > 1 ? v : null; }
  res.json({ sparks });
});
app.get('/api/hl/markets', async (_req, res) => {
  try { res.json(await hlMarkets()); } catch { res.status(502).json({ error: 'hyperliquid unavailable' }); }
});
// Audit H-8: the account view loops every Hyperliquid dex per request
// and was completely uncached — cache per address for 20s and put the
// route behind the strict bucket.
const hlAccountCache = new Map<string, { at: number; data: unknown }>();
app.get('/api/hl/account/:address', rateLimit(60), async (req, res) => {
  const address = String(req.params.address || '');
  if (!/^0x[0-9a-fA-F]{40}$/.test(address)) { res.status(400).json({ error: 'bad address' }); return; }
  const hlHit = hlAccountCache.get(address.toLowerCase());
  if (hlHit && Date.now() - hlHit.at < 20000) { res.json(hlHit.data); return; }
  try {
    const dexes = await hlDexList();
    const positions: unknown[] = [];
    let totalValue = 0; let totalUpnl = 0; let any = false;
    for (let i = 0; i < dexes.length; i++) {
      const d = dexes[i]; const dexName = d ? d.name : '';
      const st = await hlPost(dexName ? { type: 'clearinghouseState', user: address, dex: dexName } : { type: 'clearinghouseState', user: address });
      const av = parseFloat(st?.marginSummary?.accountValue || '0');
      const ps = (st?.assetPositions || []).map((p: any) => p.position).filter((p: any) => p && parseFloat(p.szi || '0') !== 0);
      if (av > 0 || ps.length) any = true;
      totalValue += av;
      for (const p of ps) {
        const szi = parseFloat(p.szi); const pv = parseFloat(p.positionValue || '0'); const upnl = parseFloat(p.unrealizedPnl || '0');
        totalUpnl += upnl;
        positions.push({ coin: p.coin, dex: dexName, szi, entryPx: parseFloat(p.entryPx || '0'), markPx: Math.abs(szi) > 0 ? pv / Math.abs(szi) : 0, positionValue: pv, unrealizedPnl: upnl, leverage: p.leverage?.value ?? null });
      }
    }
    let spotUsdc = 0;
    try { const spot = await hlPost({ type: 'spotClearinghouseState', user: address }); const b = (spot?.balances || []).find((x: any) => x.coin === 'USDC'); if (b) spotUsdc = parseFloat(b.total || '0'); } catch { /* spot is optional */ }
    const data = { any: any || spotUsdc > 0, accountValue: totalValue, unrealizedPnl: totalUpnl, spotUsdc, positions, at: Date.now() };
    cacheSet(hlAccountCache, address.toLowerCase(), { at: Date.now(), data }, 200);
    res.json(data);
  } catch { res.status(502).json({ error: 'hyperliquid unavailable' }); }
});

// ---- Hyperliquid trading relays (in-wallet perps) ----
// The wallet signs everything in the browser with its own keys; these
// two routes are dumb pipes. /api/hl/info forwards READ-ONLY info
// queries (allowlisted types only — no exchange actions can ride it).
// /api/hl/exchange forwards an already-signed exchange payload
// verbatim and returns the upstream response verbatim: the server
// holds no keys, signs nothing, and does not log payloads.
const HL_INFO_TYPES = new Set(['clearinghouseState', 'spotClearinghouseState', 'openOrders', 'frontendOpenOrders', 'allMids', 'metaAndAssetCtxs', 'spotMetaAndAssetCtxs', 'perpDexs', 'l2Book', 'candleSnapshot', 'userFills', 'userFillsByTime', 'userRole', 'portfolio', 'fundingHistory', 'userFunding', 'delegations', 'userFees']);
app.post('/api/hl/info', rateLimit(120, 'hl-info'), async (req, res) => {
  const body = req.body;
  if (!body || typeof body !== 'object' || typeof body.type !== 'string' || !HL_INFO_TYPES.has(body.type)) { res.status(400).json({ error: 'unsupported info query' }); return; }
  if (body.user !== undefined && (typeof body.user !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(body.user))) { res.status(400).json({ error: 'bad user address' }); return; }
  if (body.dex !== undefined && (typeof body.dex !== 'string' || body.dex.length > 24)) { res.status(400).json({ error: 'bad dex' }); return; }
  if (body.coin !== undefined && (typeof body.coin !== 'string' || body.coin.length > 40)) { res.status(400).json({ error: 'bad coin' }); return; }
  try { res.json(await hlPost(body)); } catch { res.status(502).json({ error: 'hyperliquid unavailable' }); }
});
app.post('/api/hl/exchange', rateLimit(60), async (req, res) => {
  const body = req.body;
  if (!body || typeof body !== 'object' || !body.action || typeof body.action !== 'object' || typeof body.action.type !== 'string' || typeof body.nonce !== 'number' || !body.signature || typeof body.signature !== 'object') { res.status(400).json({ error: 'malformed exchange payload' }); return; }
  try {
    const r = await fetch('https://api.hyperliquid.xyz/exchange', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body), signal: AbortSignal.timeout(15000) });
    const text = await readBodyCapped(r);
    res.status(r.status).type('application/json').send(text);
  } catch { res.status(502).json({ error: 'hyperliquid unavailable' }); }
});

// ---- Invest: GeckoTerminal trending pools per network (Addition 6) ----
// Keyless discovery of what's actually trading on a chain right now.
// Server-cached; a stale copy is served if the upstream rate-limits.
const GT_NETWORKS: Record<string, string> = { solana: 'solana', ethereum: 'eth', bnb: 'bsc', base: 'base', arbitrum: 'arbitrum', hyperevm: 'hyperevm' };
// Audit NEW LOW 2 (server half): pool/token addresses leave this server
// only in a plausible address shape (EVM hex or base58) — anything else
// in an upstream payload is dropped, never forwarded to a DOM attribute.
function isPlausibleAddress(s: unknown): boolean {
  return typeof s === 'string' && (/^0x[0-9a-fA-F]{40}$/.test(s) || /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(s));
}
const gtCache = new Map<string, { at: number; data: unknown }>();
app.get('/api/gt/trending/:chain', rateLimit(120, 'gt-trending'), async (req, res) => {
  const net = GT_NETWORKS[String(req.params.chain || '')];
  if (!net) { res.status(400).json({ error: 'unsupported network' }); return; }
  const hit = gtCache.get(net);
  if (hit && Date.now() - hit.at < 60000) { res.json(hit.data); return; }
  try {
    const r = await fetch(`https://api.geckoterminal.com/api/v2/networks/${net}/trending_pools?page=1&include=base_token`, { headers: { Accept: 'application/json;version=20230302' }, signal: AbortSignal.timeout(10000) });
    if (!r.ok) throw new Error('gt ' + r.status);
    const j: any = await r.json();
    const toks = new Map<string, any>();
    for (const inc of (j.included || [])) if (inc.type === 'token') toks.set(inc.id, inc.attributes);
    const pools = (j.data || []).map((p: any) => {
      const a = p.attributes; const bt = toks.get(p.relationships?.base_token?.data?.id) || {};
      return { name: bt.name || '', symbol: bt.symbol || '', address: bt.address || '', pool: a.address, img: typeof bt.image_url === 'string' ? bt.image_url : '', priceUsd: parseFloat(a.base_token_price_usd || '0'), change24h: a.price_change_percentage?.h24 != null ? parseFloat(a.price_change_percentage.h24) : null, volume24h: a.volume_usd?.h24 != null ? parseFloat(a.volume_usd.h24) : null, liquidityUsd: a.reserve_in_usd != null ? parseFloat(a.reserve_in_usd) : null, fdvUsd: a.fdv_usd != null ? parseFloat(a.fdv_usd) : null };
    }).filter((x: any) => x.address && x.priceUsd > 0 && isPlausibleAddress(x.pool) && isPlausibleAddress(x.address));
    const data = { pools, at: Date.now() };
    gtCache.set(net, { at: Date.now(), data });
    res.json(data);
  } catch { if (hit) { res.json(hit.data); return; } res.status(502).json({ error: 'geckoterminal unavailable' }); }
});

// ---- Invest: Binance bStocks (Addition 6, completed Wave 13) ----
// bStocks are BTECH Holdings' tokenized U.S. stocks/ETFs — plain BEP-20
// tokens on BNB Chain with public PancakeSwap liquidity (a live LI.FI
// USDT→SPCXB quote was verified from this server during the build).
//
// The catalog is a PINNED REGISTRY, not search: the old flow searched
// DexScreener per symbol, but its search returns at most 30 pairs and
// same-symbol copycats crowd it (a fake "NVIDIA Corp" token carries
// more wash liquidity than the real one) — even the original 20 names
// resolved only ~12 at a time. The registry below is the COMPLETE
// catalog as of 2026-11-19: the Glassnode tokenization registry's
// BTech Holdings issuer page lists 112 products; CoinGecko's
// "bStocks Ecosystem" category carries 111 of them with BSC contract
// addresses, and the 112th (BABAB) is CoinGecko-listed outside the
// category — its platform address matches its DexScreener pairs.
// Every address was cross-checked: the 12 the old flow already served
// match CoinGecko exactly, and 87 of the 112 had a live BSC pair at
// their pinned address at verification time (the other 25 trade on
// Binance only for now — no DEX pair exists to price; they are listed
// with null price fields rather than dropped).
// Prices come from DexScreener's per-token endpoint (one call per
// pinned address — the batch form caps at 30 pairs per response, so
// it silently drops tokens). A pair only counts when its base token
// IS the pinned address, so copycats can never enter the list.
const BSTOCKS: { symbol: string; name: string; address: string }[] = [
  { symbol: 'AAOIB', name: 'Applied Optoelectronics (bStocks Tokenized Stock)', address: '0x10343EF7da3301493D7Ecb647d68A288C6c1Db2F' },
  { symbol: 'AAPLB', name: 'Apple (bStocks Tokenized Stock)', address: '0x431a3BEE82E2ca41e49895CbECE5bB0F76A89b7A' },
  { symbol: 'ADBEB', name: 'Adobe (bStocks Tokenized Stock)', address: '0x65c0249d49E3231540Fd0db0a1ae9259e6eAaf57' },
  { symbol: 'AGPUB', name: 'Axe Compute (bStocks Tokenized Stock)', address: '0xa455ae0f04a2b86eee47adCA98985E61D14CbEfb' },
  { symbol: 'ALABB', name: 'Astera Labs (bStocks Tokenized Stock)', address: '0x1282493EdE6a22753D45Cb2C0fdBd8D35E97555a' },
  { symbol: 'AMATB', name: 'Applied Materials (bStocks Tokenized Stock)', address: '0xa304BD78e739C0F777202B3eB73Ac3736d1df801' },
  { symbol: 'AMCB', name: 'AMC Entertainment Holdings (bStocks Tokenized Stock)', address: '0x96e7d606e229448eF817A7f35fd7394C3E15d00C' },
  { symbol: 'AMDB', name: 'Advanced Micro Devices (bStocks Tokenized Stock)', address: '0x75Fd4cF6f8392E41E70391D60c90C0D5211603a1' },
  { symbol: 'AMZNB', name: 'Amazon (bStocks Tokenized Stock)', address: '0x1a4b499833A79A09ad7Cf1D42D7DacF71e92eb00' },
  { symbol: 'APPB', name: 'Applovin (bStocks Tokenized Stock)', address: '0x15ec59551096d5aE2Df8CdE08618035145828548' },
  { symbol: 'ARMB', name: 'Arm (bStocks Tokenized Stock)', address: '0xD42A79ebb7F527F40fAecD196FFB47aD5e8D6f8C' },
  { symbol: 'ASMLB', name: 'ASML (bStocks Tokenized Stock)', address: '0xFbfB4f79cFB4C34DCd7C82Bdee5A0Fa199B2e7f9' },
  { symbol: 'ASTSB', name: 'AST SpaceMobile (bStocks Tokenized Stock)', address: '0x58b6F5fEeb8436489F5bf4a56619092B1FA8E777' },
  { symbol: 'AVGOB', name: 'Broadcom (bStocks Tokenized Stock)', address: '0x76682c454467b3A1150Ad8b6a92FC5eE2C21d7eD' },
  { symbol: 'AXTIB', name: 'AXT (bStocks Tokenized Stock)', address: '0x9BDC8B470dbf89DbCb123587C6f5E49cCA3463BE' },
  { symbol: 'BABAB', name: 'Alibaba (bStocks Tokenized Stock)', address: '0x4eF9d3062c7F6ebA4AAE4990c5036598C6eff4ec' },
  { symbol: 'BBB', name: 'Blackberry (bStocks Tokenized Stock)', address: '0xCBB733B3DCcBB983e49bAac52AbE7BC3a8E85a4f' },
  { symbol: 'BEB', name: 'Bloom Energy (bStocks Tokenized Stock)', address: '0x5519de00F5388c17d886b97Cb5D2D43a812a82bC' },
  { symbol: 'BMNRB', name: 'BitMine Immersion Technologies (bStocks Tokenized Stock)', address: '0x3548Da95a9eFFE481e8604664d75e95821e557F5' },
  { symbol: 'BNCB', name: 'CEA Industries (bStocks Tokenized Stock)', address: '0x4902C5ebc598265Ed2212b559B042De8a5Eeec3f' },
  { symbol: 'BOTB', name: 'RoboStrategy (bStocks Tokenized Stock)', address: '0xD16c99B3F877b22A5Dd42EeF2fa77bD403306685' },
  { symbol: 'BRKBB', name: 'Berkshire Hathaway (bStocks Tokenized Stock)', address: '0xD42890342929F9Ee362a8dE900B638BC10095346' },
  { symbol: 'BSPB', name: 'Bending Spoons (bStocks Tokenized Stock)', address: '0xC895D166Fe59841Dc71003f80D7eF2f00F40a4BE' },
  { symbol: 'CBRSB', name: 'Cerebras (bStocks Tokenized Stock)', address: '0xe81C6bB0266cd68B4F17278531Dd03eA1F12dA4E' },
  { symbol: 'COHRB', name: 'Coherent (bStocks Tokenized Stock)', address: '0x5131859a059B2446AbeeFe0f5d313b3c54Ff3D36' },
  { symbol: 'COINB', name: 'Coinbase (bStocks Tokenized Stock)', address: '0x585BDE7C54ABB5cCD7791F923D6c2187635f3952' },
  { symbol: 'CRCLB', name: 'Circle Internet Group (bStocks Tokenized Stock)', address: '0x80f3D493EBCe97e343c53D29a137942416B4ffC0' },
  { symbol: 'CRDOB', name: 'Credo Technology (bStocks Tokenized Stock)', address: '0x6E7D451F9D30327D32020f116Fa79C23B24E9c8D' },
  { symbol: 'CRMB', name: 'Salesforce (bStocks Tokenized Stock)', address: '0x8C433eCa1be0e2a357015602F63751C768F6f643' },
  { symbol: 'CRWDB', name: 'CrowdStrike (bStocks Tokenized Stock)', address: '0x814981CF5df4a14D4D7328f9ABf0d02e9ED54CD1' },
  { symbol: 'CRWVB', name: 'CoreWeave (bStocks Tokenized Stock)', address: '0x33E7317e17838fEE56b10Fe8D0B9cA6CA3090c95' },
  { symbol: 'CYPHB', name: 'Cypherpunk Technologies (bStocks Tokenized Stock)', address: '0x0393c28065C54E48b45BDB05eFf5C401cF891DA1' },
  { symbol: 'DELLB', name: 'Dell (bStocks Tokenized Stock)', address: '0x0e7A51966c66648999d506e1372EFDeA1B78cb0B' },
  { symbol: 'DJTB', name: 'Trump Media & Technology Group Corp (bStocks Tokenized Stock)', address: '0xF2ec508422174Ee564de98187db9359D318AFB6b' },
  { symbol: 'DRAMB', name: 'Roundhill Memory ETF (bStocks Tokenized ETF)', address: '0x93862d63fd9Fd488B1328E9b47717d75e994a84B' },
  { symbol: 'EWJB', name: 'iShares MSCI Japan ETF (bStocks Tokenized ETF)', address: '0x26E32dAb9F844d7256Db4195b3a43750272A51E9' },
  { symbol: 'EWTB', name: 'iShares MSCI Taiwan ETF (bStocks Tokenized ETF)', address: '0x24824404bB9577697D11A07a5d88341191dE6578' },
  { symbol: 'EWYB', name: 'iShares MSCI South Korea ETF (bStocks Tokenized ETF)', address: '0xBE82F76637DBA2C114C41Df856c2C51e522E2Cb8' },
  { symbol: 'EWZB', name: 'iShares MSCI Brazil ETF (bStocks Tokenized ETF)', address: '0xB17d6EC90FD85315CD1BbcD330c3ebb07dcc822d' },
  { symbol: 'EWZSB', name: 'iShares MSCI Brazil Small-Cap ETF (bStocks Tokenized ETF)', address: '0xc5A784B9bc0D9C526A1ef582c107AB2Ff1C8Fe14' },
  { symbol: 'FLNCB', name: 'Fluence Energy (bStocks Tokenized Stock)', address: '0x4af1D41cd9dD950dcA43984b43aaA2A8702714Ac' },
  { symbol: 'FWDIB', name: 'Forward Industries (bStocks Tokenized Stock)', address: '0x83f1A739FAE6517c4672c5E10c8ea918925eB584' },
  { symbol: 'GEVB', name: 'GE Vernova (bStocks Tokenized Stock)', address: '0x5EADD95A428BC66698620C093eDdd8a4B3165269' },
  { symbol: 'GLWB', name: 'Corning (bStocks Tokenized Stock)', address: '0x740e075cBbEa22a082B9d6679e65e82767875b6A' },
  { symbol: 'GMEB', name: 'GameStop (bStocks Tokenized Stock)', address: '0x46cEeFDa28Dd7207059ed19B0acdc026955bb15C' },
  { symbol: 'GOOGLB', name: 'Alphabet (bStocks Tokenized Stock)', address: '0x3F53De71c126BdaBAe20f9cD64848d317f6C3238' },
  { symbol: 'GPROB', name: 'GoPro (bStocks Tokenized Stock)', address: '0x1ECfda023C46cA216b5c620eF357A6D0C03951E6' },
  { symbol: 'GSB', name: 'Goldman Sachs (bStocks Tokenized Stock)', address: '0x20CCe6656E5F7F79f280E2D0F5dB55b401BDbfCe' },
  { symbol: 'HIMSB', name: 'Hims & Hers (bStocks Tokenized Stock)', address: '0xee6F4bcc88C2C8583d5a65c7D0C877b464100711' },
  { symbol: 'HOODB', name: 'Robinhood (bStocks Tokenized Stock)', address: '0xA394dCEa3fd3847fD793afBFd163E2e3858B7c65' },
  { symbol: 'HPEB', name: 'Hewlett Packard (bStocks Tokenized Stock)', address: '0xd56Eb30d2Ea7b5866DC0066D33BbaaB36f7e8860' },
  { symbol: 'IBMB', name: 'IBM (bStocks Tokenized Stock)', address: '0xfA273B076Feb8c0FB34e554ae341082323D016A3' },
  { symbol: 'INTCB', name: 'Intel (bStocks Tokenized Stock)', address: '0xe614E2fc6C787035FF51f452e8E826Bfd32D5283' },
  { symbol: 'INTWB', name: 'GraniteShares 2X Long INTC ETF (bStocks Tokenized ETF)', address: '0x0735D9904b7e34e6fe39B0f66E00c111b3f2b681' },
  { symbol: 'IRENB', name: 'IREN Limited (bStocks Tokenized Stock)', address: '0xfdc2F2caB77b28f7Ef6c819A404706cfA9bCA33b' },
  { symbol: 'IWMB', name: 'iShares Russell 2000 Index Fund (bStocks Tokenized ETF)', address: '0x5E0ec7C48F2dA6D8db1A2c95D71C535BF8a77C41' },
  { symbol: 'JPMB', name: 'JPMorgan Chase (bStocks Tokenized Stock)', address: '0xbd49D695ba2cc46c8C603eb62aFcd7Fff4698281' },
  { symbol: 'KORUB', name: 'South Korea Bull 3X ETF (bStocks Tokenized ETF)', address: '0x1FFAD32d69c5FEAd99f88C25ca0191Edc3757636' },
  { symbol: 'KSTRB', name: 'KraneShares STAR Market 50 ETF (bStocks Tokenized ETF)', address: '0x5F1668b592CdF695B0C8E643A5A0078bB94cd80C' },
  { symbol: 'LITEB', name: 'Lumentum Holdings (bStocks Tokenized Stock)', address: '0x64748BeA17b6D19e242ADf20425DE2440c656142' },
  { symbol: 'LLYB', name: 'Eli Lilly (bStocks Tokenized Stock)', address: '0x5407912F1Aa4B9E05cBE6aBeb9721547a643eC6b' },
  { symbol: 'MDBB', name: 'MongoDB (bStocks Tokenized Stock)', address: '0x2E4127E92EbC1b7909267A820c9cb508373E5A5c' },
  { symbol: 'MELIB', name: 'MercadoLibre (bStocks Tokenized Stock)', address: '0xE1FC8B12EEDA0b7f8ed1330477ba330D3b5AfbC9' },
  { symbol: 'METAB', name: 'Meta Platforms (bStocks Tokenized Stock)', address: '0x7425889FE94F9d693E8daefE88BCCed6AcFEf4c0' },
  { symbol: 'MRNAB', name: 'Moderna (bStocks Tokenized Stock)', address: '0x5fd86da9B05abE396fe9d02a4A213A7c00556503' },
  { symbol: 'MRVLB', name: 'Marvell Technology (bStocks Tokenized Stock)', address: '0x16cd4fe7e8880ECc3ba222795229E20489fc2C76' },
  { symbol: 'MSFTB', name: 'Microsoft (bStocks Tokenized Stock)', address: '0x80106cb3EAD06659A5ad19DF39D9b4733863B9b0' },
  { symbol: 'MSTRB', name: 'Strategy (bStocks Tokenized Stock)', address: '0xE87afb3076AeB0f9B14E368DE8145ae6a2826A14' },
  { symbol: 'MUB', name: 'Micron Technology (bStocks Tokenized Stock)', address: '0xcdf2f3e0fa43C47A6662a91C9E4a7C5f69762699' },
  { symbol: 'MUUB', name: 'Direxion MU Bull 2X ETF (bStocks Tokenized ETF)', address: '0x0bB3fA77E0809f42948E435F04883C25415e8263' },
  { symbol: 'MVLLB', name: 'GraniteShares 2X Long MRVL ETF (bStocks Tokenized ETF)', address: '0x7C26a12f20507E2ceE22CeEBed9e88FDA47f866c' },
  { symbol: 'NBISB', name: 'Nebius (bStocks Tokenized Stock)', address: '0xE256BC2A4F5297F8ba6f043F180a46300eCbCbB1' },
  { symbol: 'NFLXB', name: 'Netflix (bStocks Tokenized Stock)', address: '0xD6829Ea836b6FA224d099D40E54B31262f874631' },
  { symbol: 'NOKB', name: 'Nokia (bStocks Tokenized Stock)', address: '0x7c4d7a180D737Dd5A70d8065a90E6746a69C37EA' },
  { symbol: 'NUB', name: 'Nu Holdings (bStocks Tokenized Stock)', address: '0x3cF7b2B634baC8C5e977E1576D79eA667E62F31C' },
  { symbol: 'NVDAB', name: 'NVIDIA (bStocks Tokenized Stock)', address: '0x02Fca66C1D1aFB4E2A7884261eB00F63598a7436' },
  { symbol: 'ORCLB', name: 'Oracle (bStocks Tokenized Stock)', address: '0x4684D9887fC1c71cBa7baB8E88835CEC217eB598' },
  { symbol: 'PDDB', name: 'PDD Holdings (bStocks Tokenized Stock)', address: '0x95b0409679B55C31772daA2fB4bEE7B125B77521' },
  { symbol: 'PENGB', name: 'Penguin Solutions (bStocks Tokenized Stock)', address: '0x7F732F9D2F2eA3E7E223C2e737e5257007F90E01' },
  { symbol: 'PLTRB', name: 'Palantir Technologies (bStocks Tokenized Stock)', address: '0x0Ca5D51D0277Bd006fd9607d3E560785EBad8222' },
  { symbol: 'PYPLB', name: 'Paypal (bStocks Tokenized Stock)', address: '0x2806a561fC1F9259B2d54A281796Bde0D92762aE' },
  { symbol: 'QCOMB', name: 'Qualcomm (bStocks Tokenized Stock)', address: '0x5F7A56e877B9130608Bf8BE962621011182fEfE1' },
  { symbol: 'QNTB', name: 'Quantinuum (bStocks Tokenized Stock)', address: '0xd721c192d612Db77621DF57A9fAb38418033c02E' },
  { symbol: 'QQQB', name: 'Invesco QQQ Trust (bStocks Tokenized Stock)', address: '0x205812CdBed920aFf76C6580abD681a46D11efc7' },
  { symbol: 'RDDTB', name: 'Reddit (bStocks Tokenized Stock)', address: '0x41622a9125A22767Df8C1dC79FC17299BAc4Bd0b' },
  { symbol: 'RKLBB', name: 'Rocket Lab (bStocks Tokenized Stock)', address: '0xC8Da12cbCCE7c45180692a6420b0076e03a5179a' },
  { symbol: 'SECZB', name: 'Securitize (bStocks Tokenized Stock)', address: '0x32c980F38907ACe4faC643c3765d9b32842AF60f' },
  { symbol: 'SHAZB', name: 'SharonAI (bStocks Tokenized Stock)', address: '0x0f31E21B7881F5583EA94ddBCb0bCaf22B1aBeAb' },
  { symbol: 'SKDDB', name: 'GraniteShares 2x Short SK Hynix Daily ETF (bStocks Tokenized ETF)', address: '0x515f386fc664980DB2Ab30c574EC210983232493' },
  { symbol: 'SKHYB', name: 'SK Hynix (bStocks Tokenized Stock)', address: '0xCA750eF65f295BBECd685Abf54e82CAf297BDB61' },
  { symbol: 'SKUUB', name: 'GraniteShares 2x Long SK Hynix Daily ETF (bStocks Tokenized ETF)', address: '0x97E8CFE35467d7AD6eD672d519E466200Fb394D0' },
  { symbol: 'SMCIB', name: 'Super Micro Computer (bStocks Tokenized Stock)', address: '0x387dEa1D2772D716d081A29116f3EfFA0fFE1F36' },
  { symbol: 'SMHB', name: 'VanEck Semiconductor ETF (bStocks Tokenized ETF)', address: '0xBE1fceD7047fdCE935F45700727845df2c76877a' },
  { symbol: 'SNDKB', name: 'SanDisk (bStocks Tokenized Stock)', address: '0x3eE4dF61bd4F867E349BEaE8bFE07bc31b4850fb' },
  { symbol: 'SNXXB', name: 'Tradr 2X Long SNDK ETF (bStocks Tokenized ETF)', address: '0x9e82e3da8f1115B73d24bB24113ab836FfDAb6b6' },
  { symbol: 'SOXLB', name: 'Semicon Bull 3X ETF (bStocks Tokenized ETF)', address: '0xd97d097a89113fa59b76c572E5b2Eb647E8eefaf' },
  { symbol: 'SOXSB', name: 'Direxion Semiconductor Bear 3X ETF (bStocks Tokenized ETF)', address: '0xE28Cd11C99AF2df76bb8aDA4Cd0ef3904378280F' },
  { symbol: 'SPCXB', name: 'SpaceX (bStocks Tokenized Stock)', address: '0xbe9D156892E55e7154BcD3cB0FEA677F9D3103E1' },
  { symbol: 'SPYB', name: 'SPY (bStocks Tokenized Stock)', address: '0x7138b48df7D98D7e3cc221BfE7192D0a178182D8' },
  { symbol: 'SQQQB', name: 'ProShares UltraPro Short QQQ (bStocks Tokenized Stock)', address: '0x25e572B466D152604D9E6C3e53B432B978825342' },
  { symbol: 'STXB', name: 'Seagate (bStocks Tokenized Stock)', address: '0x2E065f65F1699964f4092De1D39A8EFe6C8d6f32' },
  { symbol: 'TMFB', name: 'Direxion Daily 20 Year Treasury Bull 3X ETF (bStocks Tokenized ETF)', address: '0x19568bF80E61e6272ff04403c4D5B09833cC7C54' },
  { symbol: 'TQQQB', name: 'ProShares UltraPro QQQ (bStocks Tokenized Stock)', address: '0x462B5F13B7C7748279358962925c5De83BB9E598' },
  { symbol: 'TSLAB', name: 'Tesla (bStocks Tokenized Stock)', address: '0x5b1910eAaD6450E50f816082Aa078C41F10C292f' },
  { symbol: 'TSMB', name: 'TSMC (bStocks Tokenized Stock)', address: '0xAB78b89B5bb00236Be0B4B20704cBfa04EfC711c' },
  { symbol: 'USARB', name: 'USA Rare Earth (bStocks Tokenized Stock)', address: '0xcd345D4450e04cDeF422A60b97D9265d24e0bcEE' },
  { symbol: 'USDEB', name: 'StablecoinX (bStocks Tokenized Stock)', address: '0xDfD3Ba51D4591f243481a6f26059d1a5Ee95252F' },
  { symbol: 'UVXYB', name: 'ProShares Ultra VIX Short-Term Futures ETF (bStocks Tokenized ETF)', address: '0x63bA610118FfF2d6b6052cB681dcfAb78ceA1AA9' },
  { symbol: 'VSTB', name: 'Vistra Corp (bStocks Tokenized Stock)', address: '0xC7Fb9C23f359b7E072706eb43DB8cF489aa8F87f' },
  { symbol: 'WDCB', name: 'Western Digital (bStocks Tokenized Stock)', address: '0xebe29695F8047C13d36e7a790ca8c1b239FfAD1C' },
  { symbol: 'WENB', name: 'Wendy’s (bStocks Tokenized Stock)', address: '0xDed1c5FB38C262beb9CfF1E1116EfF3c5bf278Cd' },
  { symbol: 'ZMB', name: 'Zoom (bStocks Tokenized Stock)', address: '0xF4DDb292Fe88E476edDD9869d386705E6BFab7A2' },
];
interface BsRow { symbol: string; name: string; address: string; priceUsd: number | null; change24h: number | null; volume24h: number | null; liquidityUsd: number | null; fdvUsd: number | null; dexUrl: string | null }
let bsCache: { at: number; data: unknown } = { at: 0, data: null };
let bsBuilding: Promise<unknown> | null = null;
async function buildBsStocks(): Promise<unknown> {
  const rows: BsRow[] = new Array(BSTOCKS.length);
  let next = 0;
  const worker = async () => {
    while (next < BSTOCKS.length) {
      const i = next++; const t = BSTOCKS[i];
      let row: BsRow = { symbol: t.symbol, name: t.name, address: t.address, priceUsd: null, change24h: null, volume24h: null, liquidityUsd: null, fdvUsd: null, dexUrl: null };
      try {
        const r = await fetch('https://api.dexscreener.com/latest/dex/tokens/' + t.address, { headers: { Accept: 'application/json' }, signal: AbortSignal.timeout(8000) });
        if (r.ok) {
          const j: any = await r.json();
          const pairs = (j.pairs || []).filter((p: any) => p.chainId === 'bsc' && (p.baseToken?.address || '').toLowerCase() === t.address.toLowerCase());
          pairs.sort((a: any, b: any) => (b.liquidity?.usd || 0) - (a.liquidity?.usd || 0));
          const p = pairs[0];
          // Display name is ALWAYS the registry name: a pair's token-name
          // metadata is per-DEX and can be sloppy ("Invesqo QQQ") — the
          // pinned address is what's verified, the name is ours.
          if (p) row = { symbol: t.symbol, name: t.name, address: t.address, priceUsd: parseFloat(p.priceUsd || '0') || null, change24h: p.priceChange?.h24 ?? null, volume24h: p.volume?.h24 ?? null, liquidityUsd: p.liquidity?.usd ?? null, fdvUsd: p.fdv ?? null, dexUrl: p.url ?? null };
        }
      } catch { /* one token failing never sinks the list */ }
      rows[i] = row;
    }
  };
  await Promise.all(Array.from({ length: 8 }, worker));
  const data = { stocks: rows.sort((a, b) => (b.volume24h || 0) - (a.volume24h || 0) || (b.liquidityUsd || 0) - (a.liquidityUsd || 0)), at: Date.now() };
  bsCache = { at: Date.now(), data };
  return data;
}
app.get('/api/bstocks', async (_req, res) => {
  if (bsCache.data && Date.now() - bsCache.at < 120000) { res.json(bsCache.data); return; }
  if (bsCache.data) { // stale-while-revalidate: never make the list wait on 112 upstream calls
    res.json(bsCache.data);
    if (!bsBuilding) bsBuilding = buildBsStocks().catch(() => bsCache.data).finally(() => { bsBuilding = null; });
    return;
  }
  try {
    if (!bsBuilding) bsBuilding = buildBsStocks();
    res.json(await bsBuilding);
  } catch { res.status(502).json({ error: 'discovery unavailable' }); }
  finally { if (bsBuilding) bsBuilding.catch(() => {}).finally(() => { bsBuilding = null; }); }
});

// ---- DEX prices for tokens no index carries ----
// The client's price pipeline resolves CoinGecko ids first and Trust
// Wallet index entries second. Tokens the owner BOUGHT or added by
// contract — bStocks, Invest discoveries, swap outputs — are created
// with no CoinGecko id, and TW's index does not carry them either
// (verified live 2026-11-23: its tickers answer {} for NVDAB), so
// their holding rows sat at "Price unavailable" forever despite live
// DEX liquidity. This endpoint is the general fallback: price by
// chain + contract from DexScreener, the same source that prices the
// bStocks list above. A pair only counts when it sits on the asked
// chain AND its base token IS the asked contract (copycat pairs can
// never price a holding); the deepest-liquidity pair wins. Results
// (including honest nulls for pair-less tokens) cache for 60s in a
// bounded map — the set of asked tokens is small and owner-driven.
const DEX_CHAIN_IDS: Record<string, string> = {
  ethereum: 'ethereum', bnb: 'bsc', polygon: 'polygon', arbitrum: 'arbitrum',
  base: 'base', optimism: 'optimism', avalanche: 'avalanche', fantom: 'fantom',
  zksync: 'zksync', solana: 'solana', 'solana-tw': 'solana', 'solana-phantom': 'solana',
};
interface DexPriceEntry { usd: number; change24h: number | null; marketCap: number | null; volume24h: number | null }
const dexPriceCache = new Map<string, { at: number; entry: DexPriceEntry | null }>();
// The winning pair's address, recorded whenever a price lookup picks
// one — the DEX OHLC endpoint below charts THAT pool, so the history
// always belongs to the same market the spot price came from.
const dexPairCache = new Map<string, { at: number; pair: string | null }>();
async function dexPriceFor(chainId: string, contract: string): Promise<DexPriceEntry | null> {
  const dexChain = DEX_CHAIN_IDS[chainId];
  if (!dexChain) return null;
  const key = chainId + ':' + contract.toLowerCase();
  const hit = dexPriceCache.get(key);
  if (hit && Date.now() - hit.at < 60000) return hit.entry;
  let entry: DexPriceEntry | null = null;
  let pair: string | null = null;
  try {
    const r = await fetch('https://api.dexscreener.com/latest/dex/tokens/' + encodeURIComponent(contract), { headers: { Accept: 'application/json' }, signal: AbortSignal.timeout(8000) });
    if (r.ok) {
      const j: any = await r.json();
      const pairs = (j.pairs || []).filter((p: any) => p.chainId === dexChain && (p.baseToken?.address || '').toLowerCase() === contract.toLowerCase());
      pairs.sort((a: any, b: any) => (b.liquidity?.usd || 0) - (a.liquidity?.usd || 0));
      const p = pairs[0];
      if (p) {
        if (typeof p.pairAddress === 'string' && p.pairAddress) pair = p.pairAddress;
        const usd = parseFloat(p.priceUsd || '0');
        if (Number.isFinite(usd) && usd > 0) entry = { usd, change24h: typeof p.priceChange?.h24 === 'number' ? p.priceChange.h24 : null, marketCap: typeof p.marketCap === 'number' ? p.marketCap : (typeof p.fdv === 'number' ? p.fdv : null), volume24h: typeof p.volume?.h24 === 'number' ? p.volume.h24 : null };
      }
    }
  } catch { /* a failed lookup caches as null for the same 60s — no retry storm */ }
  dexPriceCache.set(key, { at: Date.now(), entry });
  dexPairCache.set(key, { at: Date.now(), pair });
  if (dexPriceCache.size > 500) { const sorted = [...dexPriceCache.entries()].sort((a, b) => a[1].at - b[1].at); for (const [k] of sorted.slice(0, dexPriceCache.size - 500)) dexPriceCache.delete(k); }
  if (dexPairCache.size > 500) { const sorted = [...dexPairCache.entries()].sort((a, b) => a[1].at - b[1].at); for (const [k] of sorted.slice(0, dexPairCache.size - 500)) dexPairCache.delete(k); }
  return entry;
}
/** Deepest-liquidity pair address for a DEX-priced token, or null. */
async function dexPairFor(chainId: string, contract: string): Promise<string | null> {
  const key = chainId + ':' + contract.toLowerCase();
  const hit = dexPairCache.get(key);
  if (hit && Date.now() - hit.at < 60000) return hit.pair;
  await dexPriceFor(chainId, contract); // populates the pair cache as a side effect
  return dexPairCache.get(key)?.pair ?? null;
}
app.post('/api/dex/prices', rateLimit(60), async (req, res) => {
  const list = Array.isArray(req.body?.tokens) ? req.body.tokens : [];
  const want: { chain: string; contract: string }[] = [];
  const seen = new Set<string>();
  for (const it of list.slice(0, 30)) {
    const chain = typeof it?.chain === 'string' ? it.chain : '';
    const contract = typeof it?.contract === 'string' ? it.contract.trim() : '';
    if (!DEX_CHAIN_IDS[chain]) continue;
    if (!(/^0x[0-9a-fA-F]{40}$/.test(contract) || /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(contract))) continue;
    const k = chain + ':' + contract.toLowerCase();
    if (seen.has(k)) continue;
    seen.add(k);
    want.push({ chain, contract });
  }
  const out: Record<string, DexPriceEntry> = {};
  let next = 0;
  const worker = async () => { while (next < want.length) { const w = want[next++]; const e = await dexPriceFor(w.chain, w.contract); if (e) out[w.chain + ':' + w.contract.toLowerCase()] = e; } };
  await Promise.all(Array.from({ length: Math.min(6, Math.max(want.length, 1)) }, worker));
  res.json({ prices: out, at: Date.now() });
});

// ---- DEX OHLC for tokens no index carries ----
// The detail chart's candle source for the same tokens /api/dex/prices
// prices. Two real-history sources, in order:
//   1. If CoinGecko lists the token as a coin (many do — every bStock
//      is CG-listed; the client TokenDef just doesn't carry the id),
//      resolve chain+contract -> CG id via CG's contract endpoint
//      (cached 24h) and serve the SAME candles as /api/ohlc. This
//      path exists because GeckoTerminal's free tier hard-rate-limits
//      this box's IP (429s even at wide spacing, verified live
//      2026-11-23) while the standard CG API — same data, the box's
//      healthy quota — serves these coins fine.
//   2. GeckoTerminal OHLCV for the token's deepest pool (the pair
//      dexPriceFor picked), for tokens only GT carries.
// Granularity mirrors /api/ohlc exactly — 1d as
// hourly candles, 7d/30d as 4h candles, 365d as daily candles — so the
// client's existing bucketing (hour/day/week/month) produces the same
// Day/Week/Month/Year periods as the CoinGecko path. Volumes arrive in
// USD and are converted to coin units with each candle's close, the
// same honest estimate /api/ohlc makes. GeckoTerminal's free tier is
// ~30 calls/min, so results cache 5 minutes per pool+range in a
// bounded map with in-flight coalescing, a stale copy is served when
// the upstream fails, and the upstream calls themselves pass through
// a serial pacing gate with 429 backoff (see gtCall below). A pool
// younger than the range simply returns fewer candles — history is
// never padded or invented.
const GT_NET_BY_DEX: Record<string, string> = {
  ethereum: 'eth', bsc: 'bsc', polygon: 'polygon_pos', arbitrum: 'arbitrum',
  base: 'base', optimism: 'optimism', avalanche: 'avax', fantom: 'fantom',
  zksync: 'zksync', solana: 'solana',
};
// CoinGecko asset-platform ids per wallet chain, for the contract ->
// coin-id lookup (CG's own naming, not the DexScreener/GT one).
const CG_PLATFORM_BY_CHAIN: Record<string, string> = {
  ethereum: 'ethereum', bnb: 'binance-smart-chain', polygon: 'polygon-pos', arbitrum: 'arbitrum-one',
  base: 'base', optimism: 'optimistic-ethereum', avalanche: 'avalanche', fantom: 'fantom',
  zksync: 'zksync', solana: 'solana', 'solana-tw': 'solana', 'solana-phantom': 'solana',
};
const cgIdCache = new Map<string, { at: number; id: string | null }>();
/** CoinGecko coin id for a chain+contract token, or null when CG does
 * not list it (or the lookup failed transiently — only a definitive
 * 404 is cached as a miss, for 24h, in a bounded map). */
async function cgIdForToken(chainId: string, contract: string): Promise<string | null> {
  const platform = CG_PLATFORM_BY_CHAIN[chainId];
  if (!platform) return null;
  const key = chainId + ':' + contract.toLowerCase();
  const hit = cgIdCache.get(key);
  if (hit && Date.now() - hit.at < 86400000) return hit.id;
  let id: string | null = null;
  let definitive = false;
  try {
    const j = await cgFetch(`https://api.coingecko.com/api/v3/coins/${platform}/contract/${encodeURIComponent(contract)}`);
    if (j && typeof j.id === 'string' && /^[a-z0-9-]{2,60}$/.test(j.id)) { id = j.id; definitive = true; }
  } catch (e) { if (e instanceof CgError && e.status === 404) definitive = true; }
  if (definitive) {
    cgIdCache.set(key, { at: Date.now(), id });
    if (cgIdCache.size > 500) { const sorted = [...cgIdCache.entries()].sort((a, b) => a[1].at - b[1].at); for (const [k] of sorted.slice(0, cgIdCache.size - 500)) cgIdCache.delete(k); }
  }
  return id;
}
const dexOhlcCache = new Map<string, { at: number; data: unknown }>();
const dexOhlcInflight = new Map<string, Promise<unknown>>();
let gtDexCooldownUntil = 0;
// GeckoTerminal's free tier is ~30 calls/min and this box's quota is
// visibly contended (429s in bursts even at 20s spacing, shared with
// the Invest trending polls). DEX-OHLC calls therefore pass through a
// serial gate — one call at a time, spaced — and a 429 retries with
// backoff (3s/6s/12s) inside the fetch: a cold chart open waits a few
// seconds in the loader instead of failing, and once a range lands it
// is cached for 5 minutes, so the pacing cost is paid once per token.
let gtGate: Promise<unknown> = Promise.resolve();
let gtLastCallAt = 0;
function gtCall<T>(fn: () => Promise<T>): Promise<T> {
  const run = async (): Promise<T> => {
    const wait = gtLastCallAt + 2200 - Date.now();
    if (wait > 0) await new Promise(r => setTimeout(r, wait));
    gtLastCallAt = Date.now();
    return fn();
  };
  const p = gtGate.then(run, run);
  gtGate = p.then(() => undefined, () => undefined);
  return p;
}
async function dexOhlcFetch(chainId: string, contract: string, days: string): Promise<unknown> {
  const pair = await dexPairFor(chainId, contract);
  if (!pair) return { chain: chainId, days: Number(days), candles: [], at: Date.now() };
  const gtNet = GT_NET_BY_DEX[DEX_CHAIN_IDS[chainId]];
  const [tf, agg, limit] = days === '1' ? ['hour', 1, 24] : days === '7' ? ['hour', 4, 42] : days === '30' ? ['hour', 4, 180] : ['day', 1, 365];
  const url = `https://api.geckoterminal.com/api/v2/networks/${gtNet}/pools/${pair}/ohlcv/${tf}?aggregate=${agg}&limit=${limit}&currency=usd`;
  let r: Awaited<ReturnType<typeof fetch>> | null = null;
  for (let attempt = 0; attempt < 4; attempt++) {
    if (attempt > 0) await new Promise(res => setTimeout(res, attempt * 3000));
    r = await gtCall(() => fetch(url, { headers: { Accept: 'application/json;version=20230302' }, signal: AbortSignal.timeout(10000) }));
    if (r.ok) break;
    if (r.status !== 429) break; // a non-429 failure will not heal by waiting
  }
  if (!r || !r.ok) { if (r?.status === 429) gtDexCooldownUntil = Date.now() + 60000; throw new Error('geckoterminal ' + (r?.status ?? 'unreachable')); }
  const j: any = await r.json();
  const list: any[] = j?.data?.attributes?.ohlcv_list || [];
  const candles = list
    .map((c: any) => { const t = Number(c[0]) * 1000, o = Number(c[1]), h = Number(c[2]), l = Number(c[3]), cl = Number(c[4]), vUsd = Number(c[5]); return [t, o, h, l, cl, cl > 0 && Number.isFinite(vUsd) ? vUsd / cl : 0]; })
    .filter((c: number[]) => c[4] > 0)
    .sort((a: number[], b: number[]) => a[0] - b[0]);
  return { chain: chainId, days: Number(days), candles, at: Date.now() };
}
app.get('/api/dex/ohlc', rateLimit(60), async (req, res) => {
  const chain = String(req.query.chain || '');
  const contract = String(req.query.contract || '').trim();
  const days = ['1', '7', '30', '365'].includes(String(req.query.days)) ? String(req.query.days) : '7';
  if (!DEX_CHAIN_IDS[chain] || !GT_NET_BY_DEX[DEX_CHAIN_IDS[chain]] || !(/^0x[0-9a-fA-F]{40}$/.test(contract) || /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(contract))) { res.status(400).json({ error: 'bad token' }); return; }
  const key = chain + ':' + contract.toLowerCase() + ':' + days;
  const hit = dexOhlcCache.get(key);
  if (hit && Date.now() - hit.at < 300000) { res.json(hit.data); return; }
  try {
    // Source 1: the token's CoinGecko coin candles, when CG lists it.
    const cgId = await cgIdForToken(chain, contract);
    if (cgId) {
      try {
        const { data } = await cgOhlcData(cgId, days);
        if (data && Array.isArray(data.candles) && data.candles.length) {
          dexOhlcCache.set(key, { at: Date.now(), data });
          res.json(data);
          return;
        }
      } catch { /* CG had the coin but no candles — fall through to the pool history */ }
    }
    // Source 2: GeckoTerminal OHLCV for the deepest pool.
    let p = dexOhlcInflight.get(key);
    if (!p) {
      p = dexOhlcFetch(chain, contract, days);
      dexOhlcInflight.set(key, p);
      // Cleanup on settle via then(done, done) — NOT p.finally():
      // a finally-derived promise re-rejects unobserved when p fails,
      // and an unhandled rejection kills the whole server process
      // (observed live 2026-11-23: a GT 429 crashed syn-wallet).
      const done = () => { if (dexOhlcInflight.get(key) === p) dexOhlcInflight.delete(key); };
      void p.then(done, done);
    }
    const data = await p;
    dexOhlcCache.set(key, { at: Date.now(), data });
    if (dexOhlcCache.size > 200) { const sorted = [...dexOhlcCache.entries()].sort((a, b) => a[1].at - b[1].at); for (const [k] of sorted.slice(0, dexOhlcCache.size - 200)) dexOhlcCache.delete(k); }
    res.json(data);
  } catch { if (hit) { res.json(hit.data); return; } res.status(502).json({ error: 'dex ohlc unavailable' }); }
});

// ---- Token logos for tokens no shipped file covers ----
// Built-in and catalog tokens ship self-hosted logo files; anything
// the owner bought or added by contract (bStocks, Invest discoveries,
// swap outputs) has no file, so its rows fell back to the monogram.
// This endpoint resolves the token's real artwork server-side — the
// browser only ever talks to this origin, no third-party host ever
// learns which tokens a wallet holds — from, in order:
//   1. the Trust Wallet assets repository (the same source this app's
//      shipped logos were fetched from at build time), by EIP-55
//      checksummed contract / Solana mint;
//   2. GeckoTerminal's token info image (CoinGecko-hosted artwork).
// Bytes are validated as a raster image and bounded, then cached in a
// bounded in-memory map (positives 24h, honest misses 10min) and
// served with a long browser cache. A miss is a plain 404: the
// client's icon renderer drops the <img> and the monogram shows —
// exactly the pre-existing no-logo state.
const TW_LOGO_CHAINS: Record<string, string> = {
  ethereum: 'ethereum', bnb: 'smartchain', polygon: 'polygon', arbitrum: 'arbitrum',
  base: 'base', optimism: 'optimism', avalanche: 'avalanchec', fantom: 'fantom',
  zksync: 'zksyncera', solana: 'solana', 'solana-tw': 'solana', 'solana-phantom': 'solana',
};
const LOGO_CTYPES = new Set(['image/png', 'image/jpeg', 'image/webp', 'image/gif']);
interface LogoEntry { at: number; body: Buffer | null; ctype: string }
const logoCache = new Map<string, LogoEntry>();
function eip55(addr: string): string {
  const lower = addr.toLowerCase().replace(/^0x/, '');
  const hash = Buffer.from(keccak_256(new TextEncoder().encode(lower))).toString('hex');
  let out = '0x';
  for (let i = 0; i < lower.length; i++) out += parseInt(hash[i], 16) >= 8 ? lower[i].toUpperCase() : lower[i];
  return out;
}
async function fetchLogoImage(url: string): Promise<{ body: Buffer; ctype: string } | null> {
  try {
    const r = await fetch(url, { headers: { Accept: 'image/*' }, signal: AbortSignal.timeout(8000), redirect: 'follow' });
    if (!r.ok) return null;
    const ctype = (r.headers.get('content-type') || '').split(';')[0].trim().toLowerCase();
    if (!LOGO_CTYPES.has(ctype)) return null;
    const buf = Buffer.from(await r.arrayBuffer());
    if (buf.length < 50 || buf.length > 1000000) return null;
    return { body: buf, ctype };
  } catch { return null; }
}
async function resolveTokenLogo(chainId: string, contract: string): Promise<{ body: Buffer; ctype: string } | null> {
  const tw = TW_LOGO_CHAINS[chainId];
  if (tw) {
    const addr = contract.startsWith('0x') ? eip55(contract) : contract;
    const hit = await fetchLogoImage(`https://raw.githubusercontent.com/trustwallet/assets/master/blockchains/${tw}/assets/${addr}/logo.png`);
    if (hit) return hit;
  }
  const gtNet = GT_NET_BY_DEX[DEX_CHAIN_IDS[chainId] || ''];
  if (gtNet && Date.now() >= gtDexCooldownUntil) {
    try {
      const r = await fetch(`https://api.geckoterminal.com/api/v2/networks/${gtNet}/tokens/${encodeURIComponent(contract)}`, { headers: { Accept: 'application/json;version=20230302' }, signal: AbortSignal.timeout(8000) });
      if (r.status === 429) gtDexCooldownUntil = Date.now() + 60000;
      if (r.ok) {
        const j: any = await r.json();
        const img = j?.data?.attributes?.image_url;
        if (typeof img === 'string' && /^https:\/\//i.test(img) && !/["'\s<>]/.test(img)) { const hit = await fetchLogoImage(img); if (hit) return hit; }
      }
    } catch { /* fall through to the honest miss */ }
  }
  return null;
}
app.get('/api/token-logo', rateLimit(120, 'token-logo'), async (req, res) => {
  const chain = String(req.query.chain || '');
  const contract = String(req.query.contract || '').trim();
  if (!TW_LOGO_CHAINS[chain] || !(/^0x[0-9a-fA-F]{40}$/.test(contract) || /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(contract))) { res.status(400).json({ error: 'bad token' }); return; }
  const key = chain + ':' + contract.toLowerCase();
  const hit = logoCache.get(key);
  if (hit && Date.now() - hit.at < (hit.body ? 86400000 : 600000)) {
    if (!hit.body) { res.status(404).json({ error: 'no logo' }); return; }
    res.setHeader('Content-Type', hit.ctype); res.setHeader('Cache-Control', 'public, max-age=86400'); res.send(hit.body); return;
  }
  const found = await resolveTokenLogo(chain, contract);
  logoCache.set(key, { at: Date.now(), body: found?.body ?? null, ctype: found?.ctype || '' });
  if (logoCache.size > 300) { const sorted = [...logoCache.entries()].sort((a, b) => a[1].at - b[1].at); for (const [k] of sorted.slice(0, logoCache.size - 300)) logoCache.delete(k); }
  if (!found) { res.setHeader('Cache-Control', 'public, max-age=600'); res.status(404).json({ error: 'no logo' }); return; }
  res.setHeader('Content-Type', found.ctype); res.setHeader('Cache-Control', 'public, max-age=86400'); res.send(found.body);
});

// ---- Polymarket (Invest → Prediction) ----
// Data path: the client reads Gamma + CLOB REST directly first (both
// are public and CORS-open) and falls back to these proxies when a
// direct read fails; the LIVE stream always comes through the WS
// relay below, because some networks/proxies kill the browser's
// direct wss upgrade to Polymarket while this server's upstream
// connection is clean. Public market data only — no user data and no
// credentials ever pass through these routes.
// Audit 2026-11-21: several caches were keyed by user/attacker-
// controlled values (addresses, gamma paths, token ids) and never
// evicted — unbounded growth toward OOM, and address-keyed user
// data retained in memory indefinitely, against the local-only
// design. cacheSet bounds every such map (oldest entry evicted).
function cacheSet<K, V>(map: Map<K, V>, key: K, val: V, max: number) {
  if (!map.has(key) && map.size >= max) { const first = map.keys().next().value; if (first !== undefined) map.delete(first as K); }
  map.set(key, val);
}
const polyCache = new Map<string, { at: number; body: string; status: number }>();
const polyRefreshInflight = new Set<string>();
// Stale-while-revalidate (2026-11-24): the gamma browse body is
// megabytes even after slimming, and a cold upstream fetch + parse
// on this box can take seconds. A phone on a carrier link must
// never wait for that chain when a previous answer exists: an
// expired hit is served instantly and refreshed in the background
// (deduped per key); only a never-fetched key pays the cold fetch.
async function polyFetchAndCache(cacheKey: string, url: string, opts?: { cap?: number; transform?: (body: string) => string }): Promise<{ body: string; status: number }> {
  const r = await fetch(url, { headers: { Accept: 'application/json' }, signal: AbortSignal.timeout(10000) });
  const raw = await readBodyCapped(r, opts?.cap);
  const body = opts?.transform ? opts.transform(raw) : raw;
  if (r.ok) cacheSet(polyCache, cacheKey, { at: Date.now(), body, status: r.status }, 400);
  return { body, status: r.status };
}
async function polyProxy(res: Response, cacheKey: string, url: string, ttlMs: number, opts?: { cap?: number; transform?: (body: string) => string }) {
  const hit = polyCache.get(cacheKey);
  if (hit && Date.now() - hit.at < ttlMs) { res.status(hit.status).type('json').send(hit.body); return; }
  if (hit) {
    // Expired but present: serve stale now, refresh behind it.
    res.status(hit.status).type('json').send(hit.body);
    if (!polyRefreshInflight.has(cacheKey)) {
      polyRefreshInflight.add(cacheKey);
      void polyFetchAndCache(cacheKey, url, opts).catch(() => { /* stale copy already served; next request retries */ }).finally(() => polyRefreshInflight.delete(cacheKey));
    }
    return;
  }
  try {
    const { body, status } = await polyFetchAndCache(cacheKey, url, opts);
    res.status(status).type('json').send(body);
  } catch { res.status(502).json({ error: 'polymarket upstream unavailable' }); }
}
// Gamma list payloads outgrew the 16 MB proxy cap (sports events
// carry 300-500 markets each, full descriptions included — the
// 24-event browse reached ~19.5 MB in 2026-11), so readBodyCapped
// threw and the Prediction panel reported Polymarket "unreachable"
// while every other gamma read (slug/condition lookups are small)
// kept working. The client parses a fixed field set (parseEvent /
// parseMarket in client/lib/polymarket.ts), so the gamma route now
// strips everything else server-side before caching/sending, and
// reads upstream with a higher — still bounded — cap sized for
// this one known public dataset. Slimmed browse: ~4.9 MB.
const GAMMA_MARKET_FIELDS = ['id', 'question', 'conditionId', 'slug', 'outcomes', 'outcomePrices', 'clobTokenIds', 'volume', 'volumeNum', 'volume24hr', 'liquidity', 'liquidityNum', 'endDate', 'negRisk', 'orderPriceMinTickSize', 'orderMinSize', 'closed', 'bestBid', 'bestAsk', 'lastTradePrice', 'spread', 'acceptingOrders', 'enableOrderBook', 'image', 'icon'];
const GAMMA_EVENT_FIELDS = ['id', 'title', 'slug', 'volume', 'volume24hr', 'liquidity', 'endDate', 'image', 'icon'];
function pickGammaFields(src: any, fields: string[]): any {
  const o: Record<string, unknown> = {};
  if (src && typeof src === 'object') for (const f of fields) if (f in src) o[f] = src[f];
  return o;
}
function slimGammaBody(body: string): string {
  try {
    const j = JSON.parse(body);
    const slimMarket = (m: any) => pickGammaFields(m, GAMMA_MARKET_FIELDS);
    const slimOne = (x: any): any => {
      if (!x || typeof x !== 'object') return x;
      if (Array.isArray(x.markets)) { const o = pickGammaFields(x, GAMMA_EVENT_FIELDS); o.markets = x.markets.map(slimMarket); if (Array.isArray(x.tags)) o.tags = x.tags; return o; }
      if ('conditionId' in x || 'clobTokenIds' in x) return slimMarket(x);
      return x;
    };
    if (Array.isArray(j)) return JSON.stringify(j.map(slimOne));
    if (j && Array.isArray(j.events)) { j.events = j.events.map(slimOne); return JSON.stringify(j); }
    return body;
  } catch { return body; }
}
app.get('/api/poly/gamma', rateLimit(90), async (req, res) => {
  const p = String(req.query.path || '');
  if (!/^\/(events|markets|tags|series|sports|search|public-search)(\?|$)/.test(p) || p.includes('..') || p.length > 600) { res.status(400).json({ error: 'path not allowed' }); return; }
  await polyProxy(res, 'g' + p, 'https://gamma-api.polymarket.com' + p, 15000, { cap: 40 * 1024 * 1024, transform: slimGammaBody });
});
app.get('/api/poly/book', rateLimit(180), async (req, res) => {
  const tid = String(req.query.token_id || '');
  if (!/^\d{10,}$/.test(tid)) { res.status(400).json({ error: 'bad token_id' }); return; }
  await polyProxy(res, 'b' + tid, 'https://clob.polymarket.com/book?token_id=' + tid, 3000);
});
app.get('/api/poly/history', rateLimit(120, 'poly-history'), async (req, res) => {
  const tid = String(req.query.token_id || '');
  const interval = ['max', '1w', '1d', '6h', '1h'].includes(String(req.query.interval)) ? String(req.query.interval) : '1d';
  const fidelity = Math.min(60, Math.max(1, Number(req.query.fidelity) || 10));
  if (!/^\d{10,}$/.test(tid)) { res.status(400).json({ error: 'bad token_id' }); return; }
  await polyProxy(res, `h${tid}${interval}${fidelity}`, `https://clob.polymarket.com/prices-history?market=${tid}&interval=${interval}&fidelity=${fidelity}`, 20000);
});
app.get('/api/poly/trades', rateLimit(120, 'poly-trades'), async (req, res) => {
  const cond = String(req.query.condition || '');
  if (!/^0x[0-9a-fA-F]{64}$/.test(cond)) { res.status(400).json({ error: 'bad condition' }); return; }
  const limit = Math.min(50, Math.max(1, Number(req.query.limit) || 25));
  await polyProxy(res, 't' + cond + ':' + limit, `https://data-api.polymarket.com/v2/trades?condition=${cond}&limit=${limit}`, 10000);
});
app.get('/api/poly/positions', rateLimit(60), async (req, res) => {
  const user = String(req.query.user || '');
  if (!/^0x[0-9a-fA-F]{40}$/.test(user)) { res.status(400).json({ error: 'bad address' }); return; }
  // Paginate the Data API (100/page) instead of silently capping a
  // user's positions at the first 100 — positions past the cap used
  // to be invisible (and unsellable) in Invest with no indication.
  // The v2 API is CURSOR-only (offset= is rejected with 400 —
  // that mistake briefly broke this endpoint in bb0904b): follow
  // pagination.next_cursor with ?cursor= while has_more. Pages
  // merge in the upstream envelope shape; hard stop at 10 pages
  // (1000 positions); the merged body caches as one entry.
  const key = 'pos' + user.toLowerCase();
  const hit = polyCache.get(key);
  if (hit && Date.now() - hit.at < 30000) { res.status(hit.status).type('json').send(hit.body); return; }
  try {
    const all: unknown[] = [];
    let envelope: Record<string, unknown> | null = null;
    let cursor = '';
    for (let page = 0; page < 10; page++) {
      const url = `https://data-api.polymarket.com/v2/positions?user=${user}&limit=100${cursor ? '&cursor=' + encodeURIComponent(cursor) : ''}`;
      const r = await fetch(url, { headers: { Accept: 'application/json' }, signal: AbortSignal.timeout(10000) });
      if (!r.ok) throw new Error('upstream ' + r.status);
      const j: any = await r.json();
      const arr: unknown[] = Array.isArray(j) ? j : Array.isArray(j?.data) ? j.data : [];
      if (!Array.isArray(j) && j && typeof j === 'object' && envelope === null) envelope = j as Record<string, unknown>;
      all.push(...arr);
      const next = j?.pagination?.next_cursor;
      if (!j?.pagination?.has_more || !next) break;
      cursor = String(next);
    }
    // The merged body holds every page, so its pagination must say
    // so — a stale has_more:true from page 1 would lie to callers.
    const body = JSON.stringify(envelope ? { ...envelope, data: all, pagination: { ...((envelope as any).pagination ?? {}), has_more: false, next_cursor: null } } : all);
    cacheSet(polyCache, key, { at: Date.now(), body, status: 200 }, 400);
    res.status(200).type('json').send(body);
  } catch { if (hit) { res.status(hit.status).type('json').send(hit.body); return; } res.status(502).json({ error: 'polymarket upstream unavailable' }); }
});
app.get('/api/poly/relayer-deployed', rateLimit(60), async (req, res) => {
  const addr = String(req.query.address || '');
  const type = req.query.type === 'WALLET' ? 'WALLET' : 'SAFE';
  if (!/^0x[0-9a-fA-F]{40}$/.test(addr)) { res.status(400).json({ error: 'bad address' }); return; }
  await polyProxy(res, `dep${addr.toLowerCase()}${type}`, `https://relayer-v2.polymarket.com/deployed?address=${addr}&type=${type}`, 60000);
});
// Builder identity (operator config in the systemd unit env).
// The builder CODE + ADDRESS are public identifiers: the code is a
// 32-byte value written into every attributed order's signed
// `builder` field and emitted on-chain in OrderFilled events — it is
// served to clients openly. The API key/secret/passphrase are a
// different thing: since the CLOB V2 cutover they no longer attribute
// orders (the POLY_BUILDER_* header flow is retired for orders); they
// still authenticate Builder API actions — creating Deposit Wallets
// for users and RELAYER submissions (gasless wallet ops) — via the
// remote-signing endpoint below.
function builderCode() {
  const code = process.env.POLYMARKET_BUILDER_CODE || '';
  return /^0x[0-9a-fA-F]{64}$/.test(code) ? code.toLowerCase() : '';
}
function builderAddress() {
  const addr = process.env.POLYMARKET_BUILDER_ADDRESS || '';
  return /^0x[0-9a-fA-F]{40}$/.test(addr) ? addr : '';
}
// Builder signing (REMOTE mode): the builder secret lives ONLY in
// this process's env (POLYMARKET_BUILDER_API_KEY / _SECRET /
// _PASSPHRASE, set in the systemd unit). Clients send just the
// request metadata the scheme needs — method, path, and the exact
// body string they are about to send — and get back the four
// POLY_BUILDER_* headers. No user key material is ever involved:
// the HMAC covers metadata only (verified against the official
// @polymarket/builder-signing-sdk construction). Remaining consumer:
// the client's relayer submissions — NOT order posting (V2 orders
// carry attribution in the signed builder field instead).
function builderCreds() {
  const key = process.env.POLYMARKET_BUILDER_API_KEY || '';
  const secret = process.env.POLYMARKET_BUILDER_SECRET || '';
  const passphrase = process.env.POLYMARKET_BUILDER_PASSPHRASE || '';
  return key && secret && passphrase ? { key, secret, passphrase } : null;
}
app.get('/api/polymarket/builder-status', (_req, res) => {
  const keys = !!builderCreds();
  const code = builderCode();
  res.json({ configured: keys, keysConfigured: keys, codeConfigured: !!code, code, address: builderAddress() });
});
app.post('/api/polymarket/relayer-submit', rateLimit(60), async (req, res) => {
  const creds = builderCreds();
  if (!creds) { res.status(503).json({ error: 'builder_not_configured' }); return; }
  // Deep audit 2026-11-22 (closes the 2026-11-21 P0 residual): the
  // old /api/polymarket/sign endpoint returned the builder API key +
  // passphrase + a valid HMAC to ANY unauthenticated caller for the
  // one pinned operation. It is GONE. Relayer submissions are now
  // proxied end-to-end here: the client sends only the unsigned
  // relayer transaction JSON, the builder headers are computed and
  // attached server-side, and the upstream response is returned —
  // builder credential material never reaches a browser again.
  const tx = req.body;
  if (!tx || typeof tx !== 'object' || Array.isArray(tx)) { res.status(400).json({ error: 'bad relayer transaction' }); return; }
  const body = JSON.stringify(tx);
  if (body.length > 64 * 1024) { res.status(400).json({ error: 'bad relayer transaction' }); return; }
  const ts = Math.floor(Date.now() / 1000);
  const message = `${ts}POST/submit${body}`;
  const sig = createHmac('sha256', Buffer.from(creds.secret, 'base64')).update(message).digest('base64').replace(/\+/g, '-').replace(/\//g, '_');
  try {
    const r = await fetch('https://relayer-v2.polymarket.com/submit', { method: 'POST', headers: { 'content-type': 'application/json', POLY_BUILDER_API_KEY: creds.key, POLY_BUILDER_TIMESTAMP: String(ts), POLY_BUILDER_PASSPHRASE: creds.passphrase, POLY_BUILDER_SIGNATURE: sig }, body, signal: AbortSignal.timeout(15000) });
    res.status(r.status).type('application/json').send(await readBodyCapped(r));
  } catch { res.status(502).json({ error: 'relayer unavailable' }); }
});
// Live relay: one upstream CLOB market-channel socket, the union of
// every connected client's subscriptions, events fanned back out
// verbatim (plus a relay_status frame so the UI can show LIVE only
// when the upstream really is open).
const polyClients = new Map<WsSocket, Set<string>>();
const polyUnion = new Set<string>();
const polyLastBook = new Map<string, number>();
let polyUp: WsSocket | null = null;
let polyUpOpen = false;
let polyRetryMs = 1000;
let polyPingTimer: ReturnType<typeof setInterval> | null = null;
function polySendStatus() { const m = JSON.stringify({ event_type: 'relay_status', state: polyUpOpen ? 'live' : 'connecting' }); for (const c of polyClients.keys()) if (c.readyState === 1) { try { c.send(m); } catch { /* closing */ } } }
function polyUpstreamConnect() {
  if (polyUp && (polyUp.readyState === 0 || polyUp.readyState === 1)) return;
  // handshakeTimeout: without it a hung handshake leaves readyState
  // stuck at CONNECTING and the guard above blocks every reconnect
  // until a process restart (audit 2026-11-21).
  const up = new WsSocket('wss://ws-subscriptions-clob.polymarket.com/ws/market', { handshakeTimeout: 10000 });
  polyUp = up;
  up.on('open', () => {
    polyUpOpen = true; polyRetryMs = 1000;
    if (polyUnion.size) { try { up.send(JSON.stringify({ assets_ids: [...polyUnion], type: 'market', custom_feature_enabled: true })); } catch { /* close handler retries */ } }
    polySendStatus();
    if (polyPingTimer) clearInterval(polyPingTimer);
    polyPingTimer = setInterval(() => { try { up.send('PING'); } catch { /* close handler retries */ } }, 10000);
  });
  up.on('message', (d: unknown) => {
    const raw = String(d);
    if (raw === 'PONG') return;
    const assets = new Set<string>();
    try {
      const j = JSON.parse(raw); const arr = Array.isArray(j) ? j : [j];
      for (const e of arr) {
        if (e && typeof e.asset_id === 'string') assets.add(e.asset_id);
        if (e && Array.isArray(e.price_changes)) for (const pc of e.price_changes) if (pc && typeof pc.asset_id === 'string') assets.add(pc.asset_id);
        if (e && e.event_type === 'book' && typeof e.asset_id === 'string') polyLastBook.set(e.asset_id, Date.now());
        // Deep audit 2026-11-22: polyLastBook grew one entry per asset
        // ever seen and was never pruned — subscriptions are
        // user-controlled, so the map was unbounded. Book timestamps
        // are only consulted for a 2.4 s staleness check; anything
        // older than 10 min is dead weight.
        if (polyLastBook.size > 2000) { const cut = Date.now() - 600000; for (const [k, v] of polyLastBook) if (v < cut) polyLastBook.delete(k); }
      }
    } catch { return; }
    if (!assets.size) return;
    for (const [c, subs] of polyClients) {
      if (c.readyState !== 1) continue;
      for (const a of assets) if (subs.has(a)) { try { c.send(raw); } catch { /* closing */ } break; }
    }
  });
  const down = () => {
    if (polyUp !== up) return;
    polyUpOpen = false; polySendStatus();
    if (polyPingTimer) { clearInterval(polyPingTimer); polyPingTimer = null; }
    const wait = polyRetryMs; polyRetryMs = Math.min(30000, polyRetryMs * 2);
    setTimeout(polyUpstreamConnect, wait);
  };
  up.on('close', down);
  up.on('error', () => { try { up.close(); } catch { /* already closed */ } });
}
function polySyncUnion() {
  const next = new Set<string>();
  for (const s of polyClients.values()) for (const a of s) next.add(a);
  const added = [...next].filter(a => !polyUnion.has(a));
  const removed = [...polyUnion].filter(a => !next.has(a));
  polyUnion.clear(); for (const a of next) polyUnion.add(a);
  if (!polyUpOpen || !polyUp) { polyUpstreamConnect(); return; }
  try {
    if (added.length) polyUp.send(JSON.stringify({ assets_ids: added, operation: 'subscribe', custom_feature_enabled: true }));
    if (removed.length) polyUp.send(JSON.stringify({ assets_ids: removed, operation: 'unsubscribe' }));
  } catch { /* close handler reconnects with the full union */ }
  // Watchdog: if a freshly added asset produces no book event, the
  // dynamic update was ignored upstream — heal with a full resubscribe.
  if (added.length) setTimeout(() => {
    if (!polyUpOpen || !polyUp) return;
    const stale = added.filter(a => polyUnion.has(a) && Date.now() - (polyLastBook.get(a) || 0) > 2400);
    if (stale.length) { try { polyUp.send(JSON.stringify({ assets_ids: [...polyUnion], type: 'market', custom_feature_enabled: true })); } catch { /* close handler retries */ } }
  }, 2600);
}
// ---- Chainlink price buffer (Polymarket real-time data socket) ----
// The Up or Down markets resolve on Chainlink TWAP streams, so the
// wallet's live ticker card reads that same stream: the current
// price, the price to beat (the stream value at the window's start)
// and the window's price path. The server keeps a per-symbol buffer
// fed by Polymarket's RTDS socket. The buffer is snapshotted to
// disk every few seconds and reloaded at boot: the socket's own
// backfill only reaches ~1 minute back, so without the snapshot
// every restart wiped the opening tick of the window in progress
// and Price To Beat came up blank. Prices are public market data —
// nothing per-user is stored.
const CL_SYMBOLS = ['btc/usd', 'eth/usd', 'sol/usd', 'xrp/usd', 'doge/usd', 'hype/usd'];
const CL_KEEP_MS = 2 * 60 * 60 * 1000;
const clBuffers = new Map<string, { t: number; v: number }[]>();
// Deep audit 2026-11-22: RTDS reconnects were a fixed 5 s for all six
// symbols — during an upstream outage all six sockets retried in
// lockstep forever. Per-symbol exponential backoff + jitter instead.
const clAttempts = new Map<string, number>();
function clRetryDelay(sym: string): number {
  const n = (clAttempts.get(sym) || 0) + 1; clAttempts.set(sym, n);
  return Math.min(60000, 5000 * 2 ** Math.min(n - 1, 4)) + Math.floor(Math.random() * 1000);
}
let clDirty = false;
function clPush(sym: string, t: number, v: number) {
  if (!Number.isFinite(t) || !Number.isFinite(v) || v <= 0) return;
  let buf = clBuffers.get(sym);
  if (!buf) { buf = []; clBuffers.set(sym, buf); }
  const last = buf[buf.length - 1];
  if (last && t <= last.t) return; // out-of-order or duplicate tick
  buf.push({ t, v });
  clDirty = true;
  const cut = t - CL_KEEP_MS;
  let drop = 0;
  while (drop < buf.length && buf[drop].t < cut) drop++;
  if (drop > 0) buf.splice(0, drop);
}
// RTDS honours only ONE crypto_prices_chainlink subscription per
// connection (verified live 2026-11-21: with all six on one socket,
// only one symbol streams — the rest get backfill once and then go
// silent, which froze the ETH/SOL/XRP ticker cards). So each symbol
// gets its own socket with its own reconnect loop.
function clConnect(sym: string) {
  let ws: WsSocket;
  // handshakeTimeout: a hung TLS/WS handshake otherwise parks the
  // socket in CONNECTING forever (audit 2026-11-21).
  try { ws = new WsSocket('wss://ws-live-data.polymarket.com', { handshakeTimeout: 10000 }); } catch { setTimeout(() => clConnect(sym), clRetryDelay(sym)); return; }
  // `ws` emits BOTH 'error' and 'close' for one failure — without
  // this guard each failure scheduled two reconnects, then four,
  // then eight (audit 2026-11-21).
  let gone = false;
  const retry = () => { if (gone) return; gone = true; try { ws.close(); } catch { /* already gone */ } setTimeout(() => clConnect(sym), clRetryDelay(sym)); };
  ws.on('open', () => {
    clAttempts.delete(sym);
    try {
      ws.send(JSON.stringify({
        action: 'subscribe',
        subscriptions: [{ topic: 'crypto_prices_chainlink', type: 'update', filters: JSON.stringify({ symbol: sym }) }],
      }));
    } catch { retry(); }
  });
  ws.on('message', (raw: Buffer) => {
    try {
      const msg = JSON.parse(raw.toString());
      const p = msg && msg.payload;
      if (!p) return;
      if (Array.isArray(p.data)) {
        // Subscribe backfill: per-second history for one symbol. The
        // symbol rides on the enclosing message when present; the
        // values themselves identify nothing, so attribute by the
        // topic's symbol field if present, else skip attribution for
        // symbols we cannot name (live updates carry their symbol).
        const sym = typeof p.symbol === 'string' ? p.symbol : null;
        if (sym && CL_SYMBOLS.includes(sym)) {
          for (const pt of p.data) clPush(sym, Number(pt.timestamp), Number(pt.value));
        }
        return;
      }
      if (typeof p.symbol === 'string' && CL_SYMBOLS.includes(p.symbol)) clPush(p.symbol, Number(p.timestamp), Number(p.value));
    } catch { /* a bad frame never kills the feed */ }
  });
  ws.on('error', retry);
  ws.on('close', retry);
}
app.get('/api/poly/chainlink', rateLimit(240), (req, res) => {
  const asset = String(req.query.symbol || '').toLowerCase();
  const full = asset + '/usd';
  if (!CL_SYMBOLS.includes(full)) { res.status(400).json({ error: 'unknown symbol' }); return; }
  const start = Number(req.query.start) * 1000, end = Number(req.query.end) * 1000;
  if (!Number.isFinite(start) || !Number.isFinite(end) || end <= start) { res.status(400).json({ error: 'bad window' }); return; }
  const buf = clBuffers.get(full) || [];
  const now = Date.now();
  const cur = buf.length ? buf[buf.length - 1] : null;
  // Price to beat: the last stream value at or before the window's
  // start. If the buffer begins just after the start (a restart gap
  // the backfill could not cover), accept the first sample within
  // five seconds; anything later would not be the opening value.
  let beat: { t: number; v: number } | null = null;
  for (const p of buf) { if (p.t <= start) beat = p; else break; }
  if (!beat && buf.length && buf[0].t > start && buf[0].t <= start + 5000) beat = buf[0];
  const win = buf.filter(p => p.t >= start && p.t <= Math.min(end, now));
  const stride = Math.max(1, Math.floor(win.length / 160));
  const samples = win.filter((_, i) => i % stride === 0 || i === win.length - 1).map(p => [p.t, p.v]);
  res.json({
    symbol: asset,
    beat: beat ? beat.v : null,
    current: cur && cur.t >= start - 60000 ? cur.v : null,
    currentAt: cur ? cur.t : null,
    samples,
  });
});
// Buffer snapshot: reloaded at boot so a restart never blanks the
// price to beat of the window in progress (see the header note).
const CL_SNAP_PATH = path.join(process.cwd(), 'data', 'cl-buffer.json');
function clLoadSnapshot() {
  try {
    const obj = JSON.parse(fs.readFileSync(CL_SNAP_PATH, 'utf8'));
    for (const sym of CL_SYMBOLS) {
      const arr = obj?.[sym];
      if (Array.isArray(arr)) for (const pt of arr) clPush(sym, Number(pt?.t), Number(pt?.v));
    }
  } catch { /* no snapshot yet — the stream reseeds from backfill */ }
}
function clSaveSnapshot() {
  if (!clDirty) return;
  clDirty = false;
  try {
    fs.mkdirSync(path.dirname(CL_SNAP_PATH), { recursive: true });
    const obj: Record<string, { t: number; v: number }[]> = {};
    for (const [sym, buf] of clBuffers) obj[sym] = buf;
    const tmp = CL_SNAP_PATH + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(obj));
    fs.renameSync(tmp, CL_SNAP_PATH);
  } catch { /* persistence is best-effort; the live buffer is unaffected */ }
}
clLoadSnapshot();
setInterval(clSaveSnapshot, 5000);
CL_SYMBOLS.forEach((sym, i) => setTimeout(() => clConnect(sym), i * 300));
function attachPolyRelay(server: http.Server | https.Server) {
  const wss = new WebSocketServer({ noServer: true, maxPayload: 64 * 1024 });
  server.on('upgrade', (req, socket, head) => {
    if ((req.url || '').split('?')[0] !== '/api/poly/ws') { socket.destroy(); return; }
    wss.handleUpgrade(req, socket, head, (c) => wss.emit('connection', c, req));
  });
  // Audit 2026-11-21: the relay had no connection bound and no
  // liveness reaping — dead half-open clients accumulated forever
  // and the union (and fan-out cost) grew with them. Cap total and
  // per-IP connections, and ping/reap on a 30s heartbeat.
  const clientIps = new Map<WsSocket, string>();
  const heartbeat = setInterval(() => {
    for (const c of polyClients.keys()) {
      if ((c as any).isAlive === false) { try { c.terminate(); } catch { /* gone */ } continue; }
      (c as any).isAlive = false;
      try { c.ping(); } catch { /* close handler cleans up */ }
    }
  }, 30000);
  heartbeat.unref?.();
  wss.on('connection', (c: WsSocket, req: http.IncomingMessage) => {
    const ip = (req.socket.remoteAddress || 'unknown').replace(/^::ffff:/, '');
    let perIp = 0;
    for (const v of clientIps.values()) if (v === ip) perIp++;
    if (polyClients.size >= 200 || perIp >= 20) { try { c.close(1013, 'relay busy'); } catch { /* gone */ } return; }
    (c as any).isAlive = true;
    c.on('pong', () => { (c as any).isAlive = true; });
    clientIps.set(c, ip);
    c.on('close', () => clientIps.delete(c));
    const subs = new Set<string>();
    polyClients.set(c, subs);
    try { c.send(JSON.stringify({ event_type: 'relay_status', state: polyUpOpen ? 'live' : 'connecting' })); } catch { /* closing */ }
    c.on('message', (d: unknown) => {
      try {
        const m = JSON.parse(String(d));
        // The client sends ONE bulk frame with every subscribed
        // asset on (re)connect, and that set grows with browsing —
        // a 60 cap silently unsubscribed the tail markets after any
        // reconnect. 1000 stays a bound but is unreachable in use.
        const list = Array.isArray(m.assets) ? m.assets.filter((x: unknown) => typeof x === 'string' && /^\d{10,}$/.test(x)).slice(0, 1000) : [];
        if (m.op === 'subscribe') { for (const a of list as string[]) subs.add(a); polySyncUnion(); }
        else if (m.op === 'unsubscribe') { for (const a of list as string[]) subs.delete(a); polySyncUnion(); }
      } catch { /* malformed frame — ignore */ }
    });
    c.on('close', () => { polyClients.delete(c); polySyncUnion(); });
    c.on('error', () => { try { c.close(); } catch { /* already closed */ } });
  });
}

// ---- Validator identities (Addition 7) ----
// validators.app's public API is keyless but sends no CORS headers, so
// browsers can't read it directly. The server fetches it (public data
// only — nothing about any user) and serves a trimmed list, cached 1h.
let validatorsCache: { at: number; data: { vote: string; name: string; skip: number | null }[] } | null = null;
app.get('/api/validators', async (_req, res) => {
  if (validatorsCache && Date.now() - validatorsCache.at < 3600_000) { res.json(validatorsCache.data); return; }
  try {
    const r = await fetch('https://www.validators.app/api/v1/validators/mainnet.json?limit=2000', { signal: AbortSignal.timeout(15000) });
    if (!r.ok) throw new Error('validators ' + r.status);
    const arr: any = await r.json();
    const data = (Array.isArray(arr) ? arr : []).filter((v: any) => typeof v?.vote_account === 'string').map((v: any) => ({ vote: v.vote_account as string, name: typeof v.name === 'string' ? v.name : '', icon: [v.avatar_file_url, v.avatar_url].find((u: any) => typeof u === 'string' && u.startsWith('https://')) || '', skip: v.skipped_slot_percent != null && !isNaN(parseFloat(v.skipped_slot_percent)) ? parseFloat(v.skipped_slot_percent) : null }));
    validatorsCache = { at: Date.now(), data };
    res.json(data);
  } catch { if (validatorsCache) res.json(validatorsCache.data); else res.status(502).json({ error: 'validators unavailable' }); }
});

// ---- Fiat FX rates (Addition 10) ----
// Display-currency conversion rates, USD-based, cached 6h in memory +
// persisted to data/fx-cache.json; on upstream failure the last real
// rates are served stale — rates are never invented. 502 only when no
// rates have ever been fetched.
// The majors come from Frankfurter (ECB reference rates, keyless; the
// API moved to api.frankfurter.dev). ARS and HNL are NOT in the ECB
// reference set (verified live 2026-11-19: Frankfurter silently omits
// both from its response), so those two are crossed from CoinGecko's
// /exchange_rates — this server's primary price source — whose per-BTC
// quotes for ARS, HNL and USD give each USD rate by division. Sanity
// check at build time: the same cross for EUR landed within 0.2% of
// the ECB figure, and HNL's unit there is literally "L".
const FX_CODES = ['EUR', 'GBP', 'JPY', 'CHF', 'CAD', 'AUD', 'CNY', 'BRL', 'MXN', 'INR', 'KRW'];
const FX_XCODES = ['ARS', 'HNL'];
const FX_ALL_CODES = [...FX_CODES, ...FX_XCODES];
const FX_CACHE_FILE = path.join(DATA_DIR, 'fx-cache.json');
let fxCache: { at: number; rates: Record<string, number> } | null = null;
try {
  const j = JSON.parse(fs.readFileSync(FX_CACHE_FILE, 'utf8'));
  // Audit M-13: the disk restore applies the SAME per-rate validation
  // as a fresh fetch — every rate a positive finite number, at least 6
  // of them, and a timestamp that is neither future nor ancient.
  if (j && typeof j.rates === 'object' && j.rates && typeof j.at === 'number' && Number.isFinite(j.at) && j.at <= Date.now() + 60000 && Date.now() - j.at < 7 * 24 * 3600_000) {
    const rates: Record<string, number> = {};
    for (const code of FX_ALL_CODES) { const v = j.rates[code]; if (typeof v === 'number' && Number.isFinite(v) && v > 0) rates[code] = v; }
    if (Object.keys(rates).length >= 6) fxCache = { at: j.at, rates };
  }
} catch { /* no cache yet */ }
// USD rates for the non-ECB codes, crossed from CoinGecko's per-BTC
// exchange_rates table. Best-effort by design: any failure leaves the
// codes absent (the client then honestly disables them) — a rate is
// never invented. A failed attempt backs off 15 minutes so a CoinGecko
// outage is not hammered once per /api/fx call.
let fxCrossNextTry = 0;
async function fxCrossRates(): Promise<Record<string, number>> {
  if (Date.now() < fxCrossNextTry) return {};
  const out: Record<string, number> = {};
  try {
    const j = await cgFetch('https://api.coingecko.com/api/v3/exchange_rates');
    const usd = j?.rates?.usd?.value;
    if (typeof usd === 'number' && Number.isFinite(usd) && usd > 0) {
      for (const code of FX_XCODES) { const v = j?.rates?.[code.toLowerCase()]?.value; if (typeof v === 'number' && Number.isFinite(v) && v > 0) out[code] = v / usd; }
    }
  } catch { /* cross codes stay absent */ }
  if (!Object.keys(out).length) fxCrossNextTry = Date.now() + 15 * 60_000;
  return out;
}
app.get('/api/fx', async (_req, res) => {
  if (fxCache && Date.now() - fxCache.at < 6 * 3600_000) {
    // A fresh cache can still miss the cross codes (written before they
    // existed, or while CoinGecko was unreachable): try to fill just
    // those before serving. The ECB table serves as-is either way.
    const cache = fxCache;
    if (FX_XCODES.some(code => !(cache.rates[code] > 0))) {
      const cross = await fxCrossRates();
      if (Object.keys(cross).length) {
        fxCache = { at: cache.at, rates: { ...cache.rates, ...cross } };
        try { fs.writeFileSync(FX_CACHE_FILE, JSON.stringify(fxCache)); } catch { /* cache is best-effort */ }
      }
    }
    const serve = fxCache ?? cache;
    res.json({ base: 'USD', rates: serve.rates, at: serve.at }); return;
  }
  try {
    const r = await fetch('https://api.frankfurter.dev/v1/latest?from=USD&to=' + FX_CODES.join(','), { signal: AbortSignal.timeout(12000) });
    if (!r.ok) throw new Error('fx ' + r.status);
    const j: any = await r.json();
    const rates: Record<string, number> = {};
    for (const code of FX_CODES) { const v = j?.rates?.[code]; if (typeof v === 'number' && v > 0) rates[code] = v; }
    if (Object.keys(rates).length < 6) throw new Error('fx payload incomplete');
    Object.assign(rates, await fxCrossRates());
    fxCache = { at: Date.now(), rates };
    try { fs.writeFileSync(FX_CACHE_FILE, JSON.stringify(fxCache)); } catch { /* cache is best-effort */ }
    res.json({ base: 'USD', rates, at: fxCache.at });
  } catch { if (fxCache) res.json({ base: 'USD', rates: fxCache.rates, at: fxCache.at, stale: true }); else res.status(502).json({ error: 'fx unavailable' }); }
});

// ---- Wave 2: swap provider pass-throughs (public market data only) ----
// Jupiter (Solana) and LI.FI (EVM + cross-chain) both run keyless tiers
// (verified from this server 2026-11-18). The browser cannot be relied on
// to reach every provider host directly, so quotes/builds pass through
// here exactly like RPC traffic: verbatim, unstored, unlogged. A quote
// request contains public addresses only — never key material (swap
// transactions are signed in the browser, always).
async function passThrough(res: Response, url: string, init?: { method?: string; body?: string }) {
  try {
    const r = await fetch(url, { method: init?.method || 'GET', headers: { 'content-type': 'application/json', accept: 'application/json' }, body: init?.body, signal: AbortSignal.timeout(30000) });
    res.status(r.status).type('application/json').send(await readBodyCapped(r));
  } catch { res.status(502).json({ error: 'Swap provider unreachable' }); }
}
app.get('/api/jupiter/quote', rateLimit(60), async (req, res) => {
  const qs = new URLSearchParams();
  for (const [k, v] of Object.entries(req.query)) if (typeof v === 'string' && v.length <= 200) qs.set(k, v);
  await passThrough(res, `https://lite-api.jup.ag/swap/v1/quote?${qs.toString()}`);
});
app.post('/api/jupiter/swap', rateLimit(60), async (req, res) => {
  await passThrough(res, 'https://lite-api.jup.ag/swap/v1/swap', { method: 'POST', body: JSON.stringify(req.body || {}) });
});
app.get('/api/lifi/quote', rateLimit(60), async (req, res) => {
  const qs = new URLSearchParams();
  for (const [k, v] of Object.entries(req.query)) if (typeof v === 'string' && v.length <= 200) qs.set(k, v);
  await passThrough(res, `https://li.quest/v1/quote?${qs.toString()}`);
});

// ---- EVM transaction history with fallback (audit pass, 2026-11-19) ----
// The client reads history from the chain's Blockscout instance
// directly, but some instances sit behind a bot wall for browser
// fetches (Polygon's does — a real, confirmed user transaction was
// invisible in Activity because of it). This endpoint is the fallback
// for EVERY EVM chain: it tries the chain's Blockscout server-side
// first, then Routescan's keyless Etherscan-compatible API, and
// normalises both to the client's row shape { hash, label, ts }.
// Verified live from this server 2026-11-19: Blockscout's API answers
// server-side when the request carries a browser User-Agent (without
// one, Cloudflare serves its challenge page even to the API path) —
// Polygon's response included the owner's real send that the
// browser-side fetch could never see. Routescan's keyless tier covers
// only some chains (verified: 1 and 43114 answer; 137/56/42161/8453/10
// return "chain not supported"), so it is the second source, never the
// only one. Rows merge + dedupe by hash on the client exactly like the
// primary pipeline. Nothing is stored or logged; a 20s in-memory cache
// absorbs repeat opens.
// Every host below was verified live from this server on 2026-11-19
// (200 + the Blockscout v2 {items} shape with the browser UA). Hosts
// that answered 404/HTML/unreachable were dropped rather than kept as
// decoration — a chain with no entry goes straight to Routescan, and
// if that fails too, the client degrades that chain honestly.
const BLOCKSCOUT_BY_CHAIN: Record<number, string> = {
  1: 'https://eth.blockscout.com', 137: 'https://polygon.blockscout.com', 8453: 'https://base.blockscout.com',
  42161: 'https://arbitrum.blockscout.com', 10: 'https://explorer.optimism.io', 100: 'https://gnosis.blockscout.com',
  534352: 'https://scroll.blockscout.com', 42220: 'https://celo.blockscout.com', 25: 'https://cronos.blockscout.com',
  33139: 'https://apechain.blockscout.com', 34443: 'https://explorer.mode.network', 122: 'https://explorer.fuse.io',
  // Audit 2026-11-21: zkSync Era (324) had NO working source — its
  // official explorer API is unreachable from this server and
  // Routescan answers "chain not supported", so /api/history/324
  // 502'd permanently. zksync.blockscout.com verified live from this
  // server (200 + Blockscout v2 shape).
  324: 'https://zksync.blockscout.com',
};
// dir/amt/cp/st/sym ride along for the client's Activity row design —
// all derived from fields the upstream item itself carries (value,
// from, to, status); amt is a decimal string in whole native units.
interface HistRow { hash: string; label: string; ts: number; dir?: 'in' | 'out'; amt?: string; cp?: string; st?: 'failed'; sym?: string }
function weiToDecimal(v: string, dec = 18): string | undefined {
  try {
    const b = BigInt(v);
    if (b <= 0n) return undefined;
    const base = 10n ** BigInt(dec);
    const whole = b / base;
    const frac = (b % base).toString().padStart(dec, '0').replace(/0+$/, '');
    return frac ? `${whole}.${frac}` : `${whole}`;
  } catch { return undefined; }
}
const histCache = new Map<string, { at: number; data: { rows: HistRow[]; source: string } }>();
const histInflight = new Map<string, Promise<{ rows: HistRow[]; source: string }>>();
// Blockscout sits behind Cloudflare: a browser UA is what separates
// the JSON API from the challenge page (verified live, see above).
const BROWSER_UA = 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1';
async function fetchHistory(chainId: number, address: string, symbol: string, limit = 15): Promise<{ rows: HistRow[]; source: string }> {
  const me = address.toLowerCase();
  const label = (sent: boolean) => `${sent ? 'Sent' : 'Received'}${symbol ? ' ' + symbol : ''}`;
  const bs = BLOCKSCOUT_BY_CHAIN[chainId];
  if (bs) {
    try {
      // Some Blockscout deployments (zkSync's) reject page_size as
      // an unexpected field (422) — retry bare; the rows are sliced
      // to the limit below either way.
      let r = await fetch(`${bs}/api/v2/addresses/${address}/transactions?page_size=${limit}`, { headers: { Accept: 'application/json', 'User-Agent': BROWSER_UA }, signal: AbortSignal.timeout(8000) });
      if (r.status === 422) r = await fetch(`${bs}/api/v2/addresses/${address}/transactions`, { headers: { Accept: 'application/json', 'User-Agent': BROWSER_UA }, signal: AbortSignal.timeout(8000) });
      if (r.ok) {
        const j: any = await r.json();
        if (Array.isArray(j?.items)) {
          const rows: HistRow[] = [];
          for (const t of j.items) {
            if (typeof t?.hash !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(t.hash)) continue;
            const from = String(t.from?.hash || ''); const to = String(t.to?.hash || '');
            // Audit 2026-11-21: direction is who sent, full stop.
            // The old value-based test labelled every zero-value
            // INCOMING tx (token transfers, contract calls) as sent
            // BY the user.
            const sent = from.toLowerCase() === me;
            const cp = from.toLowerCase() === me ? to : from;
            rows.push({ hash: t.hash, label: label(sent), ts: t.timestamp ? new Date(t.timestamp).getTime() || 0 : 0, dir: sent ? 'out' : 'in', amt: t.value ? weiToDecimal(String(t.value)) : undefined, cp: /^0x[0-9a-fA-F]{40}$/.test(cp) ? cp : undefined, st: t.status === 'error' ? 'failed' : undefined, sym: symbol || undefined });
          }
          return { rows: rows.slice(0, limit), source: 'blockscout' };
        }
      }
    } catch { /* fall through to the fallback source */ }
  }
  const qs = new URLSearchParams({ module: 'account', action: 'txlist', address, page: '1', offset: String(limit), sort: 'desc' });
  const r = await fetch(`https://api.routescan.io/v2/network/mainnet/evm/${chainId}/etherscan/api?${qs.toString()}`, { headers: { Accept: 'application/json' }, signal: AbortSignal.timeout(10000) });
  if (!r.ok) throw new Error('routescan ' + r.status);
  const j: any = await r.json();
  // Audit 2026-11-21: Routescan answers HTTP 200 with
  // {status:"0", message:"chain not supported", result:null} for
  // chains it does not index (BNB 56, Fantom 250, …). That is a
  // DEFINITIVE "no history source exists for this chain", not a
  // transient failure — the old code threw, the endpoint 502'd
  // forever, and the client showed "unavailable" instead of its
  // honest empty state. Answer with an empty list and source "none".
  // Other status:"0" payloads (rate limits etc.) still throw.
  if (!Array.isArray(j?.result) && typeof j?.message === 'string' && /not supported/i.test(j.message)) {
    return { rows: [], source: 'none' };
  }
  const list = Array.isArray(j?.result) ? j.result : null;
  if (!list) throw new Error('routescan payload');
  const rows: HistRow[] = [];
  for (const t of list) {
    if (typeof t?.hash !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(t.hash)) continue;
    const from = String(t.from || ''); const to = String(t.to || '');
    const sent = from.toLowerCase() === me; // direction = who sent (see Blockscout branch)
    const cp = from.toLowerCase() === me ? to : from;
    rows.push({ hash: t.hash, label: label(sent), ts: Number(t.timeStamp || 0) * 1000, dir: sent ? 'out' : 'in', amt: t.value ? weiToDecimal(String(t.value)) : undefined, cp: /^0x[0-9a-fA-F]{40}$/.test(cp) ? cp : undefined, st: String(t.isError || '0') === '1' ? 'failed' : undefined, sym: symbol || undefined });
  }
  return { rows: rows.slice(0, limit), source: 'routescan' };
}
app.get('/api/history/:chainId', rateLimit(120, 'history'), async (req, res) => {
  const chainId = Number(req.params.chainId);
  const address = String(req.query.address || '');
  const symbolRaw = String(req.query.symbol || '');
  const symbol = /^[A-Za-z0-9][A-Za-z0-9 ._-]{0,11}$/.test(symbolRaw) ? symbolRaw : '';
  if (!Number.isSafeInteger(chainId) || chainId <= 0 || !/^0x[0-9a-fA-F]{40}$/.test(address)) { res.status(400).json({ error: 'bad request' }); return; }
  // Activity "show more" asks for a deeper page (audit 2026-11-21);
  // the depth rides the cache key so depths never mix.
  const histLimit = Math.min(100, Math.max(15, Number(req.query.limit) || 15));
  const key = `${chainId}:${address.toLowerCase()}:${histLimit}`;
  const hit = histCache.get(key);
  if (hit && Date.now() - hit.at < 20000) { res.json({ ...hit.data, at: hit.at }); return; }
  try {
    let p = histInflight.get(key);
    if (!p) {
      p = fetchHistory(chainId, address, symbol, histLimit).then(data => { cacheSet(histCache, key, { at: Date.now(), data }, 300); return data; }).finally(() => histInflight.delete(key));
      histInflight.set(key, p);
    }
    const data = await p;
    res.json({ ...data, at: Date.now() });
  } catch { res.status(502).json({ error: 'history unavailable' }); }
});

app.get('/api/health', (_req, res) => {
  // no-store: the client's update check compares `build` against the id
  // baked into its own bundle — a cached answer would hide a new build.
  res.setHeader('Cache-Control', 'no-store');
  // Release-integrity state, written by scripts/integrity-check.mjs
  // (systemd timer, hourly + after deploys). Absent file = the checker
  // has not run yet on this box → "unknown", never silently "ok".
  let integrity: any = { status: 'unknown' };
  try {
    const j = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'integrity-status.json'), 'utf8'));
    // Audit 2026-11-21: never republish the checker's `detail` — on
    // failure it names served files and can carry a raw fs error with
    // an absolute server path. Status + timestamp + build suffice.
    if (j && (j.status === 'ok' || j.status === 'failed')) integrity = { status: j.status, checkedAt: j.checkedAt ?? null, build: j.build ?? null };
  } catch { /* checker has not run yet */ }
  res.json({ ok: true, service: 'syn-wallet', build: BUILD_ID, tls: TLS, at: Date.now(), integrity });
});

const publicDir = path.join(ROOT, 'public');
// Cache policy, per file class (owner's order — no service worker, the
// server is the single source of truth, exactly like the other Syn apps):
//  - Documents and code that are NOT content-hashed are `no-cache`:
//    index.html, sw.js (now a self-destructing kill-switch), the manifest,
//    stylesheets — every load revalidates, so a deploy is visible to
//    browsers immediately.
//  - IMAGE and FONT files are `immutable` for a year: a coin logo, network
//    icon, dapp logo or font never changes under a stable filename (a new
//    logo ships under a new name), so revalidating them on every render
//    was pure waste — it made every icon visibly reload on each tab
//    switch. Content-addressed by convention, cached like it.
//  - content-hashed bundles (vite emits `name-<8-char hash>.ext`) stay
//    immutable for a year: the name changes when the content does, and a
//    fresh (no-cache) index always names the new hash.
// serve-static's setHeaders runs on the send stream's `headers` event,
// before send applies its own Cache-Control — and send only sets one if
// none is present — so these values are what clients actually receive.
const HASHED_ASSET = /-[A-Za-z0-9_-]{8}\.[^.]+$/;
const IMMUTABLE_EXT = /\.(?:png|jpe?g|gif|svg|ico|webp|avif|woff2?|ttf|otf|eot)$/i;
app.use(express.static(publicDir, {
  index: false,
  setHeaders: (res, filePath) => {
    const base = path.basename(filePath);
    // Fixed-name boot files are NEVER immutable. boot-watchdog.js
    // carries the current bundle's hash pin, so a year-long cache on
    // it strands a client on a stale release forever — and it happened
    // in production (2026-11-20): HASHED_ASSET false-positives on
    // "boot-watchdog" because "watchdog" is exactly 8 characters, so
    // the watchdog shipped as immutable and a phone kept booting the
    // old build no matter how many fixes were deployed. The hashed-
    // asset rule is therefore also scoped to the vite output dir —
    // a content hash only proves anything under /assets/.
    if (base === 'boot-watchdog.js' || base === 'release-manifest.json') { res.setHeader('Cache-Control', 'no-cache'); return; }
    const inAssets = filePath.split(path.sep).includes('assets');
    if ((inAssets && HASHED_ASSET.test(base)) || IMMUTABLE_EXT.test(base)) res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
    else res.setHeader('Cache-Control', 'no-cache');
  },
}));
// Audit NEW LOW 8: unknown /api/* paths are a JSON 404, never the SPA
// shell with a 200 (a mistyped endpoint must fail loudly, not "load").
app.use('/api', (_req, res) => { res.status(404).json({ error: 'not found' }); });
// Audit NEW LOW 10: unmatched non-GET requests get JSON too — the
// default Express HTML error pages fingerprint the stack.
app.use((req, res, next) => {
  if (req.method !== 'GET' && req.method !== 'HEAD') { res.status(404).json({ error: 'not found' }); return; }
  next();
});
// SPA fallback: every unknown path is the app shell. Pre-setting the
// header works because send (used by sendFile) likewise only applies its
// own Cache-Control when none is already present.
app.get('*', (_req, res) => { res.setHeader('Cache-Control', 'no-cache'); res.sendFile(path.join(publicDir, 'index.html')); });
// Audit NEW LOW 10: one JSON error handler for everything (body-parser
// 413s included) — no Express HTML error pages anywhere.
// eslint-disable-next-line @typescript-eslint/no-unused-vars
app.use((err: any, _req: Request, res: Response, _next: NextFunction) => {
  const status = typeof err?.status === 'number' && err.status >= 400 && err.status < 600 ? err.status : 500;
  res.status(status).json({ error: status === 413 ? 'request too large' : 'request failed' });
});

if (TLS) {
  const mainServer = https.createServer({ key: fs.readFileSync(tlsKey), cert: fs.readFileSync(tlsCert) }, app);
  mainServer.listen(PORT, () => console.log(`Syn Wallet HTTPS on ${PORT}`));
  attachPolyRelay(mainServer);
  // Audit NEW LOW 7: never reflect an unvalidated Host header into the
  // redirect Location — accept only a plain hostname/IP shape, else
  // fall back to the deployment's own address.
  http.createServer((req, res) => { const raw = (req.headers.host || '').replace(/:\d+$/, ''); const host = /^(\d{1,3}\.){3}\d{1,3}$/.test(raw) || raw === 'localhost' ? raw : '79.108.164.56'; res.writeHead(301, { Location: `https://${host}:${PORT}${req.url}` }); res.end(); }).listen(REDIRECT_PORT, () => console.log(`Syn Wallet redirect HTTP ${REDIRECT_PORT} -> HTTPS ${PORT}`));
} else {
  // Deep audit 2026-11-22: the no-TLS fallback served the wallet over
  // plain HTTP — a silent downgrade for an app whose whole threat
  // model is key custody. Fail closed instead: if the self-signed
  // cert cannot be created, refuse to start so the failure is loud
  // in the service log, never a quiet HTTP wallet.
  console.error('Syn Wallet: TLS certificate unavailable — refusing to serve over plain HTTP.');
  process.exit(1);
}
