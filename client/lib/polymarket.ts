// Polymarket for Invest → Prediction.
// Data: Gamma (discovery) + CLOB REST (book/history) reads go through
// this app's server proxy ONLY (see fetchJson below — direct browser
// reads proved unreliable on real networks). The LIVE stream comes
// through the server's WS relay (/api/poly/ws): some networks kill
// the browser's direct wss upgrade to Polymarket, while the server's
// upstream CLOB market-channel connection is clean — the events the
// UI consumes are the genuine CLOB book / price_change /
// last_trade_price frames either way, never polling, never faked.
// Trading: the user's own keys stay on this device. L1 API creds are
// derived with an EIP-712 ClobAuth signature; orders are EIP-712
// signed locally (CLOB V2 struct — see the order section); L2 request
// auth is HMAC-SHA256 per the official client construction (API auth
// headers are unchanged in V2). Builder attribution in V2 is NOT a
// header: it is the `builder` bytes32 field inside the signed order
// (the POLY_BUILDER_* HMAC-header flow was retired at the V2 cutover,
// docs.polymarket.com/v2-migration). The builder code is a public
// identifier served by our server's config; the builder API
// key/secret/passphrase are still used — but only for
// Builder-authenticated RELAYER submissions (gasless wallet ops),
// whose headers come from our server's remote-signing endpoint (the
// builder secret never reaches the browser). Amount/rounding math
// ports the official clob-client helpers exactly (ROUNDING_CONFIG +
// raw-amount rules).
import { Wallet, TypedDataEncoder, verifyTypedData } from 'ethers';

export const GAMMA = 'https://gamma-api.polymarket.com';
export const CLOB = 'https://clob.polymarket.com';
export const DATA_API = 'https://data-api.polymarket.com';
export const RELAYER = 'https://relayer-v2.polymarket.com';
export const CHAIN_ID = 137;
export const CTF_EXCHANGE = '0x4bFb41d5B3570DeFd03C39a9A4D8dE6Bd8B8982E'; // legacy V1 — production CLOB is V2 (below)
export const NEG_RISK_EXCHANGE = '0xC5d563A36AE78145C45a50134d48A1215220f80a'; // legacy V1
// CLOB V2 (cutover 2026-04-28; docs.polymarket.com/resources/contracts):
export const CTF_EXCHANGE_V2 = '0xE111180000d2663C0091e4f400237545B87B996B';
export const NEG_RISK_EXCHANGE_V2 = '0xe2222d279d744050d28e00520010520000310F59';
export const NEG_RISK_ADAPTER = '0xd91E80cF2E7be2e162c6513ceD06f1dD0dA35296';
export const PUSD = '0xC011a7E12a19f7B1f670d46F03B03f3342E82DFB'; // V2 collateral (Polymarket USD, backed by USDC)
export const COLLATERAL_ONRAMP = '0x93070a847efEf7F70739046A929D47a521F5B8ee'; // wraps USDC.e -> pUSD 1:1
export const ZERO_BYTES32 = '0x' + '00'.repeat(32);
export const USDC_E = '0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174'; // V1 collateral; still the on-ramp input for pUSD
export const USDC_NATIVE = '0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359';

export interface PolyMarket {
  id: string; question: string; conditionId: string; slug: string;
  outcomes: string[]; prices: number[]; tokenIds: string[];
  volume: number; volume24hr: number; liquidity: number;
  endDate: string; negRisk: boolean; tickSize: number; minSize: number; closed: boolean;
  bestBid: number; bestAsk: number; lastTrade: number; spread: number;
  acceptingOrders: boolean; image: string;
}
export interface PolyEvent {
  id: string; title: string; slug: string; volume: number; volume24hr: number;
  liquidity: number; endDate: string; image: string; markets: PolyMarket[];
  tags: string[];
}
export interface PolyPosition {
  title: string; outcome: string; size: number; avgPrice: number; curPrice: number;
  currentValue: number; cashPnl: number; percentPnl: number; conditionId: string; asset: string; icon: string; endDate: string;
}
export interface BookLevel { price: number; size: number }
export interface Book { bids: BookLevel[]; asks: BookLevel[]; tickSize: number; negRisk: boolean; minSize: number }

const jparse = <T>(v: unknown, dflt: T): T => { if (Array.isArray(v) || (v && typeof v === 'object')) return v as T; if (typeof v === 'string') { try { return JSON.parse(v) as T; } catch { return dflt; } } return dflt; };
const num = (v: unknown, d = 0): number => { const n = typeof v === 'string' ? parseFloat(v) : typeof v === 'number' ? v : NaN; return Number.isFinite(n) ? n : d; };

export function parseMarket(m: any): PolyMarket {
  const outcomes = jparse<string[]>(m?.outcomes, []);
  const prices = jparse<any[]>(m?.outcomePrices, []).map(x => num(x));
  const tokenIds = jparse<string[]>(m?.clobTokenIds, []);
  return {
    id: String(m?.id || ''), question: String(m?.question || ''), conditionId: String(m?.conditionId || ''), slug: String(m?.slug || ''),
    outcomes, prices, tokenIds,
    volume: num(m?.volumeNum ?? m?.volume), volume24hr: num(m?.volume24hr), liquidity: num(m?.liquidityNum ?? m?.liquidity),
    endDate: String(m?.endDate || ''), negRisk: !!m?.negRisk, tickSize: num(m?.orderPriceMinTickSize, 0.01) || 0.01, minSize: num(m?.orderMinSize, 5), closed: !!m?.closed,
    bestBid: num(m?.bestBid), bestAsk: num(m?.bestAsk), lastTrade: num(m?.lastTradePrice), spread: num(m?.spread),
    acceptingOrders: m?.acceptingOrders !== false && !!m?.enableOrderBook, image: String(m?.image || m?.icon || ''),
  };
}
export function parseEvent(e: any): PolyEvent {
  return {
    id: String(e?.id || ''), title: String(e?.title || ''), slug: String(e?.slug || ''),
    volume: num(e?.volume), volume24hr: num(e?.volume24hr), liquidity: num(e?.liquidity),
    endDate: String(e?.endDate || ''), image: String(e?.image || e?.icon || ''),
    markets: (Array.isArray(e?.markets) ? e.markets : []).map(parseMarket),
    tags: (Array.isArray(e?.tags) ? e.tags : []).map((t: any) => String(t?.slug || '')).filter(Boolean),
  };
}

// ---- REST reads: server proxy ONLY ----
// Browsing reads never talk to Polymarket hosts from the browser.
// The direct-browser leg proved unreliable on real phones/networks
// (geo/CORS/ISP behaviour varies; in the proof rig it fails outright),
// while this app's own server reaches Gamma/CLOB/Data API cleanly and
// caches briefly — the same reasoning that put the live stream on the
// server WS relay. The page itself is served by that server, so the
// proxy being unreachable means the app is unreachable anyway; there
// is no second leg to fall back to. (Trading writes — credential
// derivation and order posting — are not reads and stay direct to the
// CLOB with the user's own auth, below.)
async function fetchJson(_url: string, proxyPath: string, timeoutMs = 12000): Promise<any> {
  const r = await fetch(proxyPath, { headers: { Accept: 'application/json' }, signal: AbortSignal.timeout(timeoutMs) });
  if (!r.ok) throw new Error('proxy http ' + r.status);
  return await r.json();
}
const gammaProxy = (p: string) => '/api/poly/gamma?path=' + encodeURIComponent(p);

// ---- Up or Down: the short-window crypto series (5m / 15m / 1h) ----
// These markets all carry Polymarket's own "hide-from-new" tag
// (id 102169), which the browse query above excludes — the same
// reason Polymarket's own homepage hides them: a fresh market every
// few minutes per asset would flood any general list. They get a
// dedicated view instead. Each window's event slug is deterministic
// — {asset}-updown-{tf}-{windowStartUnix} — so the current window
// is addressed directly, never searched for. Verified live against
// Gamma for every asset/timeframe pair below.
export interface UpDownAsset { slug: string; name: string; symbol: string }
export const UPDOWN_ASSETS: UpDownAsset[] = [
  { slug: 'btc', name: 'Bitcoin', symbol: 'BTC' },
  { slug: 'eth', name: 'Ethereum', symbol: 'ETH' },
  { slug: 'sol', name: 'Solana', symbol: 'SOL' },
  { slug: 'xrp', name: 'XRP', symbol: 'XRP' },
];
export const UPDOWN_TFS: { id: string; secs: number }[] = [
  { id: '5m', secs: 300 },
  { id: '15m', secs: 900 },
  { id: '1h', secs: 3600 },
];
export function upDownWindowStart(tfSecs: number, atMs = Date.now()): number {
  return Math.floor(atMs / 1000 / tfSecs) * tfSecs;
}
export function upDownSlug(asset: string, tfSecs: number, atMs = Date.now()): string {
  const tf = UPDOWN_TFS.find(t => t.secs === tfSecs);
  const label = tf ? tf.id : `${Math.round(tfSecs / 60)}m`;
  return `${asset}-updown-${label}-${upDownWindowStart(tfSecs, atMs)}`;
}
export function parseUpDownSlug(slug: string): { asset: string; tfSecs: number } | null {
  const mm = /^([a-z0-9]+)-updown-(5m|15m|1h)-\d+$/.exec(slug || '');
  if (!mm) return null;
  const tf = UPDOWN_TFS.find(t => t.id === mm[2]);
  return tf ? { asset: mm[1], tfSecs: tf.secs } : null;
}
export async function gammaEventBySlug(slug: string): Promise<PolyEvent | null> {
  const p = `/events?slug=${encodeURIComponent(slug)}`;
  const j = await fetchJson(GAMMA + p, gammaProxy(p));
  const evs = (Array.isArray(j) ? j : []).map(parseEvent).filter((e: PolyEvent) => e.markets.length);
  return evs[0] ?? null;
}

/** One market by condition id — used to open a position's detail. */
export async function gammaMarketByCondition(conditionId: string): Promise<PolyMarket | null> {
  const p = `/markets?condition_ids=${encodeURIComponent(conditionId)}`;
  const j = await fetchJson(GAMMA + p, gammaProxy(p));
  const ms = (Array.isArray(j) ? j : []).map(parseMarket).filter((m: PolyMarket) => m.tokenIds.length);
  return ms[0] ?? null;
}

export async function gammaEvents(params: { tag?: string; search?: string; limit?: number; offset?: number }): Promise<PolyEvent[]> {
  const limit = params.limit || 24;
  const offset = params.offset || 0;
  if (params.search) {
    // Gamma's public search returns events with nested markets.
    // (The endpoint is /public-search?q= — the older /search path 404s.)
    const p = `/public-search?q=${encodeURIComponent(params.search)}&limit_per_type=25&events_status=active`;
    const j = await fetchJson(GAMMA + p, gammaProxy(p));
    const evs = Array.isArray(j?.events) ? j.events : [];
    return evs.map(parseEvent).filter((e: PolyEvent) => e.markets.length);
  }
  const qs = `active=true&closed=false&archived=false&limit=${limit}&offset=${offset}&order=volume24hr&ascending=false&exclude_tag_id=102169${params.tag ? '&tag_slug=' + encodeURIComponent(params.tag) : ''}`;
  const p = `/events?${qs}`;
  const j = await fetchJson(GAMMA + p, gammaProxy(p));
  return (Array.isArray(j) ? j : []).map(parseEvent).filter(e => e.markets.length);
}

export async function clobBook(tokenId: string): Promise<Book> {
  const j = await fetchJson(`${CLOB}/book?token_id=${tokenId}`, '/api/poly/book?token_id=' + tokenId);
  const lv = (arr: any[]): BookLevel[] => (Array.isArray(arr) ? arr : []).map(l => ({ price: num(l?.price), size: num(l?.size) })).filter(l => l.price > 0 && l.size > 0);
  return { bids: lv(j?.bids), asks: lv(j?.asks), tickSize: num(j?.tick_size, 0.01) || 0.01, negRisk: !!j?.neg_risk, minSize: num(j?.min_order_size, 5) };
}
export async function clobHistory(tokenId: string, interval = '1d', fidelity = 5): Promise<{ t: number; p: number }[]> {
  const j = await fetchJson(`${CLOB}/prices-history?market=${tokenId}&interval=${interval}&fidelity=${fidelity}`, `/api/poly/history?token_id=${tokenId}&interval=${interval}&fidelity=${fidelity}`);
  const h = Array.isArray(j?.history) ? j.history : [];
  return h.map((x: any) => ({ t: num(x?.t) * 1000, p: num(x?.p) })).filter((x: { t: number; p: number }) => x.t > 0 && x.p >= 0);
}
export interface PolyTrade { side: string; outcomeIx: number; size: number; price: number; ts: number }
export async function polyTrades(conditionId: string, limit = 25): Promise<PolyTrade[]> {
  const j = await fetchJson('', '/api/poly/trades?condition=' + encodeURIComponent(conditionId) + '&limit=' + limit);
  const arr = Array.isArray(j) ? j : Array.isArray(j?.data) ? j.data : [];
  return arr.map((t: any) => ({
    side: String(t?.side || ''), outcomeIx: Number(t?.outcome_index ?? t?.outcomeIndex ?? 0),
    size: num(t?.size), price: num(t?.price), ts: Number(t?.timestamp) || 0,
  })).filter((t: PolyTrade) => t.size > 0 && t.price > 0);
}
export async function polyPositions(user: string): Promise<PolyPosition[]> {
  // Data API v2 (v1 was retired by Polymarket): envelope {data:[…]},
  // snake_case fields. camelCase fallbacks kept for safety.
  const j = await fetchJson(`${DATA_API}/v2/positions?user=${user}&limit=100`, '/api/poly/positions?user=' + user);
  const arr = Array.isArray(j) ? j : Array.isArray(j?.data) ? j.data : [];
  return arr.map((p: any) => ({
    title: String(p?.title || ''), outcome: String(p?.outcome || ''),
    size: num(p?.current_size ?? p?.size), avgPrice: num(p?.avg_price ?? p?.avgPrice), curPrice: num(p?.current_price ?? p?.curPrice),
    currentValue: num(p?.current_value ?? p?.currentValue), cashPnl: num(p?.unrealized_pnl ?? p?.cashPnl), percentPnl: num(p?.percent_pnl ?? p?.percentPnl),
    conditionId: String(p?.condition_id ?? p?.conditionId ?? ''), asset: String(p?.token_id ?? p?.asset ?? ''), icon: String(p?.icon || ''), endDate: String(p?.end_date ?? p?.endDate ?? ''),
    status: String(p?.status || ''),
  })).filter((p: PolyPosition & { status: string }) => p.size > 0 && (!p.status || p.status === 'OPEN'));
}

// ---- Live feed: CLOB market channel via the server relay ----
export type FeedStatus = 'connecting' | 'live' | 'down';
export interface FeedQuote { bestBid: number; bestAsk: number; lastTrade: number; at: number }
type Listener = (ev: any) => void;

class PolyFeedImpl {
  private ws: WebSocket | null = null;
  private subs = new Map<string, Set<Listener>>();
  private statusCbs = new Set<(s: FeedStatus) => void>();
  status: FeedStatus = 'connecting';
  private retryMs = 800;
  private closed = false;
  books = new Map<string, Book>();
  quotes = new Map<string, FeedQuote>();

  private url(): string {
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    return `${proto}//${location.host}/api/poly/ws`;
  }
  private setStatus(s: FeedStatus) { if (this.status === s) return; this.status = s; for (const cb of this.statusCbs) { try { cb(s); } catch { /* listener gone */ } } }
  onStatus(cb: (s: FeedStatus) => void): () => void { this.statusCbs.add(cb); cb(this.status); return () => this.statusCbs.delete(cb); }

  private ensure() {
    if (this.ws && (this.ws.readyState === 0 || this.ws.readyState === 1)) return;
    this.closed = false;
    let ws: WebSocket;
    try { ws = new WebSocket(this.url()); } catch { this.scheduleRetry(); return; }
    this.ws = ws;
    ws.onopen = () => {
      this.retryMs = 800;
      const ids = [...this.subs.keys()];
      if (ids.length) { try { ws.send(JSON.stringify({ op: 'subscribe', assets: ids })); } catch { /* close path retries */ } }
    };
    ws.onmessage = (m) => {
      if (typeof m.data !== 'string') return;
      let j: any; try { j = JSON.parse(m.data); } catch { return; }
      const arr = Array.isArray(j) ? j : [j];
      for (const e of arr) {
        if (!e || typeof e !== 'object') continue;
        if (e.event_type === 'relay_status') { this.setStatus(e.state === 'live' ? 'live' : 'connecting'); continue; }
        const touch = (assetId: string, fn: () => void) => { fn(); const set = this.subs.get(assetId); if (set) for (const cb of [...set]) { try { cb(e); } catch { /* listener gone */ } } };
        if (e.event_type === 'book' && typeof e.asset_id === 'string') {
          const lv = (a: any[]): BookLevel[] => (Array.isArray(a) ? a : []).map(l => ({ price: num(l?.price), size: num(l?.size) })).filter(l => l.price > 0 && l.size > 0);
          touch(e.asset_id, () => this.books.set(e.asset_id, { bids: lv(e.bids), asks: lv(e.asks), tickSize: this.books.get(e.asset_id)?.tickSize || 0.01, negRisk: this.books.get(e.asset_id)?.negRisk || false, minSize: this.books.get(e.asset_id)?.minSize || 5 }));
        } else if (e.event_type === 'price_change' && Array.isArray(e.price_changes)) {
          for (const pc of e.price_changes) {
            if (!pc || typeof pc.asset_id !== 'string') continue;
            touch(pc.asset_id, () => {
              const q = this.quotes.get(pc.asset_id) || { bestBid: 0, bestAsk: 0, lastTrade: 0, at: 0 };
              if (pc.best_bid !== undefined) q.bestBid = num(pc.best_bid);
              if (pc.best_ask !== undefined) q.bestAsk = num(pc.best_ask);
              q.at = Date.now();
              this.quotes.set(pc.asset_id, q);
              // Fold the delta into the cached book so the depth view
              // stays current between full book frames.
              const bk = this.books.get(pc.asset_id);
              if (bk) {
                const side = String(pc.side || '').toUpperCase();
                const arr = side === 'BUY' ? bk.bids : side === 'SELL' ? bk.asks : null;
                if (arr) {
                  const price = num(pc.price); const size = num(pc.size);
                  const ix = arr.findIndex(l => Math.abs(l.price - price) < 1e-9);
                  if (size <= 0) { if (ix >= 0) arr.splice(ix, 1); }
                  else if (ix >= 0) arr[ix].size = size;
                  else { arr.push({ price, size }); arr.sort((a, b) => side === 'BUY' ? b.price - a.price : a.price - b.price); }
                }
              }
            });
          }
        } else if (e.event_type === 'last_trade_price' && typeof e.asset_id === 'string') {
          touch(e.asset_id, () => { const q = this.quotes.get(e.asset_id) || { bestBid: 0, bestAsk: 0, lastTrade: 0, at: 0 }; q.lastTrade = num(e.price); q.at = Date.now(); this.quotes.set(e.asset_id, q); });
        }
      }
    };
    ws.onclose = () => { if (this.ws === ws) this.ws = null; if (!this.closed && this.subs.size) { this.setStatus('connecting'); this.scheduleRetry(); } else this.setStatus('down'); };
    ws.onerror = () => { try { ws.close(); } catch { /* already closed */ } };
  }
  private scheduleRetry() { const wait = this.retryMs; this.retryMs = Math.min(15000, this.retryMs * 2); setTimeout(() => { if (this.subs.size) this.ensure(); }, wait); }

  subscribe(assetId: string, cb: Listener): () => void {
    let set = this.subs.get(assetId);
    if (!set) { set = new Set(); this.subs.set(assetId, set); }
    const isNew = set.size === 0;
    set.add(cb);
    this.ensure();
    if (isNew && this.ws && this.ws.readyState === 1) { try { this.ws.send(JSON.stringify({ op: 'subscribe', assets: [assetId] })); } catch { /* close path retries */ } }
    return () => {
      const s = this.subs.get(assetId);
      if (!s) return;
      s.delete(cb);
      if (!s.size) {
        this.subs.delete(assetId);
        if (this.ws && this.ws.readyState === 1) { try { this.ws.send(JSON.stringify({ op: 'unsubscribe', assets: [assetId] })); } catch { /* closing anyway */ } }
        if (!this.subs.size) { this.closed = true; try { this.ws?.close(); } catch { /* already closed */ } this.ws = null; this.setStatus('down'); }
      }
    };
  }
  get socketCount(): number { return this.ws ? 1 : 0; }
}
export const polyFeed = new PolyFeedImpl();

// ---- HMAC (L2 + builder share the scheme; ported from the official
// SDK construction: base64-decoded secret, message
// `${timestamp}${method}${path}${body}`, base64url output) ----
function b64ToBytes(b64: string): Uint8Array {
  const clean = b64.replace(/-/g, '+').replace(/_/g, '/').replace(/[^A-Za-z0-9+/=]/g, '');
  const bin = atob(clean);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function bytesToB64(bytes: Uint8Array): string { let s = ''; for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]); return btoa(s); }
export async function polyHmac(secret: string, timestamp: number, method: string, path: string, body = ''): Promise<string> {
  const key = await crypto.subtle.importKey('raw', b64ToBytes(secret) as BufferSource, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(`${timestamp}${method}${path}${body}`));
  return bytesToB64(new Uint8Array(sig)).replace(/\+/g, '-').replace(/\//g, '_');
}

// ---- L1: derive or create the user's CLOB API credentials ----
// The signature is an EIP-712 ClobAuth message signed by the wallet's
// own key on this device. Creds live in memory only — never stored.
export interface ClobCreds { apiKey: string; secret: string; passphrase: string }
const CLOB_AUTH_TYPES = { ClobAuth: [{ name: 'address', type: 'address' }, { name: 'timestamp', type: 'string' }, { name: 'nonce', type: 'uint256' }, { name: 'message', type: 'string' }] };
const CLOB_AUTH_MSG = 'This message attests that I control the given wallet';

export async function deriveClobCreds(wallet: Wallet): Promise<ClobCreds> {
  const address = await wallet.getAddress();
  const ts = Math.floor(Date.now() / 1000);
  const signature = await wallet.signTypedData({ name: 'ClobAuthDomain', version: '1', chainId: CHAIN_ID }, CLOB_AUTH_TYPES, { address, timestamp: String(ts), nonce: 0, message: CLOB_AUTH_MSG });
  const headers = { POLY_ADDRESS: address, POLY_SIGNATURE: signature, POLY_TIMESTAMP: String(ts), POLY_NONCE: '0' };
  // Derive first (existing creds), create only when none exist.
  for (const [method, path] of [['GET', '/auth/derive-api-key'], ['POST', '/auth/api-key']] as const) {
    try {
      const r = await fetch(CLOB + path, { method, headers, signal: AbortSignal.timeout(12000) });
      if (!r.ok) continue;
      const j = await r.json();
      if (j?.apiKey && j?.secret && j?.passphrase) return { apiKey: String(j.apiKey), secret: String(j.secret), passphrase: String(j.passphrase) };
    } catch { /* try the next step */ }
  }
  throw new Error('Polymarket did not issue API credentials for this wallet.');
}

export async function l2Headers(creds: ClobCreds, address: string, method: string, path: string, body = ''): Promise<Record<string, string>> {
  const ts = Math.floor(Date.now() / 1000);
  const sig = await polyHmac(creds.secret, ts, method, path, body);
  return { POLY_ADDRESS: address, POLY_SIGNATURE: sig, POLY_TIMESTAMP: String(ts), POLY_API_KEY: creds.apiKey, POLY_PASSPHRASE: creds.passphrase };
}

// ---- Builder-authenticated relayer submissions ----
// In CLOB V2 the POLY_BUILDER_* headers no longer attribute orders
// (the signed `builder` field does that). They remain the auth for
// Builder-authenticated RELAYER submissions (gasless wallet
// deployment / approvals / transfers) — the only consumer is
// relayerSubmit below. Deep audit 2026-11-22: the browser no longer
// receives builder headers at all — submissions go through our
// server's /api/polymarket/relayer-submit proxy, which signs and
// forwards server-side, so the builder API key/passphrase never
// leave the server.
export async function builderConfigured(): Promise<boolean> {
  try { const r = await fetch('/api/polymarket/builder-status'); const j = await r.json(); return !!j?.configured; } catch { return false; }
}

// ---- Order math (ported exactly from @polymarket/clob-client) ----
export interface RoundConfig { price: number; size: number; amount: number }
export const ROUNDING_CONFIG: Record<string, RoundConfig> = {
  '0.1': { price: 1, size: 2, amount: 3 },
  '0.01': { price: 2, size: 2, amount: 4 },
  '0.001': { price: 3, size: 2, amount: 5 },
  '0.0001': { price: 4, size: 2, amount: 6 },
};
export function roundConfigFor(tickSize: number): RoundConfig { return ROUNDING_CONFIG[String(tickSize)] || ROUNDING_CONFIG['0.01']; }
const decimalPlaces = (x: number): number => { const s = String(x); const e = s.indexOf('e'); if (e >= 0) { const [m, ex] = s.split('e'); return Math.max(0, (m.split('.')[1]?.length || 0) - Number(ex)); } return s.split('.')[1]?.length || 0; };
export const roundDown = (x: number, dp: number): number => { const f = 10 ** dp; return Math.floor(x * f + 1e-9) / f; };
export const roundUp = (x: number, dp: number): number => { const f = 10 ** dp; return Math.ceil(x * f - 1e-9) / f; };
export const roundNormal = (x: number, dp: number): number => { const f = 10 ** dp; return Math.round(x * f) / f; };

export function limitRawAmounts(side: 'BUY' | 'SELL', size: number, price: number, cfg: RoundConfig): { rawMakerAmt: number; rawTakerAmt: number } {
  const rawPrice = roundNormal(price, cfg.price);
  if (side === 'BUY') {
    const rawTakerAmt = roundDown(size, cfg.size);
    let rawMakerAmt = rawTakerAmt * rawPrice;
    if (decimalPlaces(rawMakerAmt) > cfg.amount) { rawMakerAmt = roundUp(rawMakerAmt, cfg.amount + 4); if (decimalPlaces(rawMakerAmt) > cfg.amount) rawMakerAmt = roundDown(rawMakerAmt, cfg.amount); }
    return { rawMakerAmt, rawTakerAmt };
  }
  const rawMakerAmt = roundDown(size, cfg.size);
  let rawTakerAmt = rawMakerAmt * rawPrice;
  if (decimalPlaces(rawTakerAmt) > cfg.amount) { rawTakerAmt = roundUp(rawTakerAmt, cfg.amount + 4); if (decimalPlaces(rawTakerAmt) > cfg.amount) rawTakerAmt = roundDown(rawTakerAmt, cfg.amount); }
  return { rawMakerAmt, rawTakerAmt };
}
export function marketRawAmounts(side: 'BUY' | 'SELL', amount: number, price: number, cfg: RoundConfig): { rawMakerAmt: number; rawTakerAmt: number } {
  const rawPrice = roundDown(price, cfg.price);
  if (side === 'BUY') {
    const rawMakerAmt = roundDown(amount, cfg.size);
    let rawTakerAmt = rawMakerAmt / rawPrice;
    if (decimalPlaces(rawTakerAmt) > cfg.amount) { rawTakerAmt = roundUp(rawTakerAmt, cfg.amount + 4); if (decimalPlaces(rawTakerAmt) > cfg.amount) rawTakerAmt = roundDown(rawTakerAmt, cfg.amount); }
    return { rawMakerAmt, rawTakerAmt };
  }
  const rawMakerAmt = roundDown(amount, cfg.size);
  let rawTakerAmt = rawMakerAmt * rawPrice;
  if (decimalPlaces(rawTakerAmt) > cfg.amount) { rawTakerAmt = roundUp(rawTakerAmt, cfg.amount + 4); if (decimalPlaces(rawTakerAmt) > cfg.amount) rawTakerAmt = roundDown(rawTakerAmt, cfg.amount); }
  return { rawMakerAmt, rawTakerAmt };
}
/** Worst price to walk `amount` through a book side (FOK throws). */
export function walkPrice(levels: BookLevel[], side: 'BUY' | 'SELL', amount: number, orderType: 'FOK' | 'FAK'): number {
  if (!levels.length) throw new Error('no match');
  let sum = 0;
  for (let i = levels.length - 1; i >= 0; i--) {
    const p = levels[i];
    sum += side === 'BUY' ? p.size * p.price : p.size;
    if (sum >= amount) return p.price;
  }
  if (orderType === 'FOK') throw new Error('no match');
  return levels[0].price;
}

// ---- Order build + EIP-712 sign (CLOB V2) ----
// V2 signed struct (docs.polymarket.com/v2-migration): taker,
// expiration, nonce and feeRateBps left the signed struct; timestamp
// (ms), metadata and builder joined it. expiration still rides the
// POST /order wire body, unsigned. Fees are operator-set at match
// time — nothing fee-related is signed. The builder code is part of
// the signed struct ("Because it is part of the signed order, add it
// before signing" — Place Orders → Builder Attribution); zero bytes32
// means no attribution.
export const ORDER_TYPES = {
  Order: [
    { name: 'salt', type: 'uint256' }, { name: 'maker', type: 'address' }, { name: 'signer', type: 'address' },
    { name: 'tokenId', type: 'uint256' }, { name: 'makerAmount', type: 'uint256' }, { name: 'takerAmount', type: 'uint256' },
    { name: 'side', type: 'uint8' }, { name: 'signatureType', type: 'uint8' }, { name: 'timestamp', type: 'uint256' },
    { name: 'metadata', type: 'bytes32' }, { name: 'builder', type: 'bytes32' },
  ],
};
export interface SignedOrderPayload { [k: string]: unknown }
const toUnits6 = (x: number): string => { const [i, f = ''] = String(x).split('.'); const frac = (f + '000000').slice(0, 6); return (BigInt(i) * 1000000n + BigInt(frac || '0')).toString(); };
/** A builder code is a 32-byte hex string; anything else is treated as "no code" (zero bytes32). */
export function normalizeBuilderCode(code?: string | null): string {
  return typeof code === 'string' && /^0x[0-9a-fA-F]{64}$/.test(code) ? code.toLowerCase() : ZERO_BYTES32;
}
const orderDomain = (negRisk: boolean) => ({ name: 'Polymarket CTF Exchange', version: '2', chainId: CHAIN_ID, verifyingContract: negRisk ? NEG_RISK_EXCHANGE_V2 : CTF_EXCHANGE_V2 });
/** Rebuild the exact signed struct from a wire payload (expiration and signature are not signed in V2). */
function structFromPayload(payload: SignedOrderPayload): Record<string, unknown> {
  const p = payload as any;
  return {
    salt: String(p.salt), maker: p.maker, signer: p.signer, tokenId: p.tokenId,
    makerAmount: p.makerAmount, takerAmount: p.takerAmount,
    side: p.side === 'BUY' ? 0 : p.side === 'SELL' ? 1 : p.side, signatureType: p.signatureType,
    timestamp: String(p.timestamp), metadata: p.metadata, builder: p.builder,
  };
}

export async function buildSignedOrder(wallet: Wallet, args: {
  tokenId: string; side: 'BUY' | 'SELL'; rawMakerAmt: number; rawTakerAmt: number;
  negRisk: boolean; expiration?: string; signatureType?: number; maker?: string; builderCode?: string;
}): Promise<SignedOrderPayload> {
  const signer = await wallet.getAddress();
  const maker = args.maker || signer;
  const saltBytes = new Uint8Array(8); crypto.getRandomValues(saltBytes);
  const salt = (BigInt('0x' + [...saltBytes].map(b => b.toString(16).padStart(2, '0')).join('')) % 9007199254740991n).toString();
  const timestamp = Date.now();
  const order = {
    salt, maker, signer,
    tokenId: args.tokenId, makerAmount: toUnits6(args.rawMakerAmt), takerAmount: toUnits6(args.rawTakerAmt),
    side: args.side === 'BUY' ? 0 : 1, signatureType: args.signatureType ?? 0,
    timestamp: String(timestamp), metadata: ZERO_BYTES32, builder: normalizeBuilderCode(args.builderCode),
  };
  const signature = await wallet.signTypedData(orderDomain(args.negRisk), ORDER_TYPES, order);
  // Wire body: the eleven signed members (side as the string the REST
  // body uses) + the unsigned expiration + the signature.
  return {
    salt: Number(salt), maker, signer, tokenId: order.tokenId, makerAmount: order.makerAmount, takerAmount: order.takerAmount,
    side: args.side, signatureType: order.signatureType, timestamp, metadata: order.metadata, builder: order.builder,
    expiration: args.expiration || '0', signature,
  };
}

/** Verify locally that a signed order's signature recovers its signer. */
export function verifyOrderSignature(payload: SignedOrderPayload, negRisk: boolean): boolean {
  try {
    const p = payload as any;
    return verifyTypedData(orderDomain(negRisk), ORDER_TYPES, structFromPayload(payload), String(p.signature)).toLowerCase() === String(p.signer).toLowerCase();
  } catch { return false; }
}
export function orderDigest(payload: SignedOrderPayload, negRisk: boolean): string {
  return TypedDataEncoder.hash(orderDomain(negRisk), ORDER_TYPES, structFromPayload(payload));
}

export interface PostOrderResult { ok: boolean; orderId?: string; status?: string; error?: string; raw: unknown }
export async function postOrder(wallet: Wallet, creds: ClobCreds, signed: SignedOrderPayload, orderType: 'GTC' | 'GTD' | 'FOK' | 'FAK'): Promise<PostOrderResult> {
  const address = await wallet.getAddress();
  const bodyObj = { order: signed, owner: creds.apiKey, orderType, deferExec: false };
  const body = JSON.stringify(bodyObj);
  const path = '/order';
  // L2 headers only: in V2 the POLY_BUILDER_* headers are gone —
  // attribution travels in the signed order's builder field.
  const headers: Record<string, string> = { 'content-type': 'application/json', ...(await l2Headers(creds, address, 'POST', path, body)) };
  try {
    const r = await fetch(CLOB + path, { method: 'POST', headers, body, signal: AbortSignal.timeout(15000) });
    const j = await r.json().catch(() => ({}));
    if (r.ok && (j as any)?.success !== false) return { ok: true, orderId: String((j as any)?.orderID || ''), status: String((j as any)?.status || ''), raw: j };
    return { ok: false, error: String((j as any)?.error || (j as any)?.message || 'CLOB rejected the order (HTTP ' + r.status + ')'), raw: j };
  } catch (e) {
    return { ok: false, error: 'Network error posting the order: ' + (e instanceof Error ? e.message : String(e)), raw: null };
  }
}

// ---- Open orders (L2): list + cancel ----
// A resting GTC order commits real funds/shares. The app must be able
// to show and cancel it — posting and forgetting is not acceptable.
export interface PolyOpenOrder { id: string; market: string; assetId: string; side: string; price: number; originalSize: number; sizeMatched: number; outcome: string; status: string }
export async function getOpenOrders(creds: ClobCreds, address: string, conditionId?: string): Promise<PolyOpenOrder[]> {
  const path = '/data/orders' + (conditionId ? `?market=${encodeURIComponent(conditionId)}` : '');
  const headers = await l2Headers(creds, address, 'GET', path);
  const r = await fetch(CLOB + path, { method: 'GET', headers, signal: AbortSignal.timeout(12000) });
  if (!r.ok) throw new Error('CLOB open-orders read failed (HTTP ' + r.status + ')');
  const j = await r.json();
  const rows = Array.isArray((j as any)?.data) ? (j as any).data : [];
  return rows.map((o: any) => ({ id: String(o.id || ''), market: String(o.market || ''), assetId: String(o.asset_id || ''), side: String(o.side || ''), price: parseFloat(o.price || '0'), originalSize: parseFloat(o.original_size || '0'), sizeMatched: parseFloat(o.size_matched || '0'), outcome: String(o.outcome || ''), status: String(o.status || '') }));
}
export async function cancelPolyOrder(creds: ClobCreds, address: string, orderId: string): Promise<boolean> {
  const path = '/order';
  const body = JSON.stringify({ orderID: orderId });
  const headers: Record<string, string> = { 'content-type': 'application/json', ...(await l2Headers(creds, address, 'DELETE', path, body)) };
  const r = await fetch(CLOB + path, { method: 'DELETE', headers, body, signal: AbortSignal.timeout(12000) });
  if (!r.ok) return false;
  const j = await r.json().catch(() => ({}));
  return Array.isArray((j as any)?.canceled) && (j as any).canceled.includes(orderId);
}

// ---- Relayer (gasless onboarding via Builder credentials) ----
// Deploy/approval transactions are submitted through Polymarket's
// relayer with the same POLY_BUILDER_* headers (produced by our
// server's signing endpoint — the relayer request's own method, path
// and body are what gets signed). Without builder credentials these
// calls are never attempted; the panel keeps its honest gate.
export async function relayerDeployed(address: string, type: 'SAFE' | 'WALLET' = 'SAFE'): Promise<boolean | null> {
  try {
    const j = await fetchJson(`${RELAYER}/deployed?address=${address}&type=${type}`, `/api/poly/relayer-deployed?address=${address}&type=${type}`, 8000);
    return typeof j?.deployed === 'boolean' ? j.deployed : null;
  } catch { return null; }
}
export async function relayerSubmit(tx: Record<string, unknown>): Promise<{ ok: boolean; transactionId?: string; error?: string }> {
  try {
    const r = await fetch('/api/polymarket/relayer-submit', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(tx), signal: AbortSignal.timeout(20000) });
    const j = await r.json().catch(() => ({}));
    if ((j as any)?.error === 'builder_not_configured') return { ok: false, error: 'builder_not_configured' };
    if (r.ok && (j as any)?.transactionID) return { ok: true, transactionId: String((j as any).transactionID) };
    return { ok: false, error: String((j as any)?.error || 'relayer rejected the transaction (HTTP ' + r.status + ')') };
  } catch (e) { return { ok: false, error: 'Network error reaching the relayer: ' + (e instanceof Error ? e.message : String(e)) }; }
}
export async function relayerTxState(transactionId: string): Promise<string> {
  try { const r = await fetch(`${RELAYER}/transaction?id=${encodeURIComponent(transactionId)}`, { signal: AbortSignal.timeout(8000) }); const j = await r.json(); return String(j?.state || ''); } catch { return ''; }
}
