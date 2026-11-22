// Trust Wallet API — server-side client (HMAC-SHA256 signed).
//
// An OPTIONAL extra data source for the wallet, enabled only when the
// operator sets TWAK_ACCESS_ID + TWAK_HMAC_SECRET in the server
// environment (free keys from portal.trustwallet.com). The secret is
// used here and NEVER reaches the browser — clients only learn
// whether the source is configured, and call the /api/tw/* proxy
// routes. Nothing user-specific is stored: caches live in memory and
// key on public asset ids / the public addresses the client asks
// about, exactly like the GoPlus checks the client already runs.
//
// The free tier allows 1 request/second across ALL endpoints, so
// every upstream call goes through a serialized queue with a minimum
// gap, and responses are cached (tickers 60s, status/validate 10min).
import { createHmac, randomUUID } from 'node:crypto';

const TW_BASE = 'https://tws.trustwallet.com';

export function twConfigured(): boolean {
  return !!(process.env.TWAK_ACCESS_ID && process.env.TWAK_HMAC_SECRET);
}

// ---- HMAC-SHA256 signing (per the tw-agent-skills setup reference) ----
// plaintext = METHOD;PATH;SORTED_QUERY;ACCESS_ID;NONCE;DATE
// SORTED_QUERY: params sorted by key, joined k=v with &, RAW values.
export function twSortedQuery(q: Record<string, string>): string {
  return Object.keys(q).sort().map(k => `${k}=${q[k]}`).join('&');
}
export function twPlaintext(method: string, path: string, sortedQuery: string, accessId: string, nonce: string, date: string): string {
  return [method.toUpperCase(), path, sortedQuery, accessId, nonce, date].join(';');
}
export function twSignature(secret: string, plaintext: string): string {
  return createHmac('sha256', secret).update(plaintext).digest('base64');
}

// ---- serialized queue (free tier: 1 request/second) ----
let queue: Promise<unknown> = Promise.resolve();
let lastAt = 0;
function throughQueue<T>(fn: () => Promise<T>): Promise<T> {
  const run = async (): Promise<T> => {
    const wait = 1100 - (Date.now() - lastAt);
    if (wait > 0) await new Promise(r => setTimeout(r, wait));
    try { return await fn(); } finally { lastAt = Date.now(); }
  };
  const p = queue.then(run, run);
  queue = p.then(() => undefined, () => undefined);
  return p;
}

const cache = new Map<string, { at: number; v: any }>();
function cached<T>(key: string, ttlMs: number, fn: () => Promise<T | null>): Promise<T | null> {
  const hit = cache.get(key);
  if (hit && Date.now() - hit.at < ttlMs) return Promise.resolve(hit.v as T);
  return throughQueue(async () => {
    const v = await fn();
    if (v !== null && v !== undefined) {
      // Bounded (audit 2026-11-21): keys carry user addresses — an
      // unbounded map retains them indefinitely and grows to OOM.
      if (!cache.has(key) && cache.size >= 500) { const first = cache.keys().next().value; if (first !== undefined) cache.delete(first); }
      cache.set(key, { at: Date.now(), v });
    }
    return v;
  });
}

async function twCall(method: 'GET' | 'POST', path: string, query: Record<string, string>, body?: unknown): Promise<any | null> {
  const id = process.env.TWAK_ACCESS_ID || '';
  const secret = process.env.TWAK_HMAC_SECRET || '';
  if (!id || !secret) return null;
  const date = new Date().toUTCString();
  const nonce = randomUUID();
  const sig = twSignature(secret, twPlaintext(method, path, twSortedQuery(query), id, nonce, date));
  const qs = new URLSearchParams(query).toString();
  try {
    const r = await fetch(`${TW_BASE}${path}${qs ? '?' + qs : ''}`, {
      method,
      headers: {
        'X-TW-CREDENTIAL': id,
        'X-TW-NONCE': nonce,
        'X-TW-DATE': date,
        Authorization: `HMAC-SHA256 Signature=${sig}`,
        'Content-Type': 'application/json',
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
      signal: AbortSignal.timeout(15000),
    });
    if (!r.ok) return null;
    return await r.json();
  } catch { return null; }
}

// ---- coin status / token security ----
export interface TwRisk { warnings: string[]; notes: string[] }
function collectItems(items: any, warnings: string[]): void {
  // Item lists are NOT warnings: the live Solana payload fills them
  // with plain-language check results, mostly POSITIVE statements
  // ("The token cannot be minted.", "No Freeze Authority found.").
  // The counts (num_risks / num_warnings) carry the verdict; an item
  // is surfaced only when it carries an explicit negative marker.
  if (!Array.isArray(items)) return;
  for (const it of items) {
    if (!it || typeof it !== 'object') continue;
    const marker = String(it.level || it.type || it.severity || '').toLowerCase();
    const flagged = it.is_risk === true || it.risk === true || marker === 'risk' || marker === 'warning' || marker === 'high' || marker === 'critical';
    if (!flagged) continue;
    const m = it.message || it.title || it.description;
    if (typeof m === 'string' && m && !warnings.includes(m)) warnings.push(m);
  }
}
// The LIVE v1 wire shape (verified against the real API 2026-11-21):
// security_info { is_scanned, provider: "Blockaid", contract_security,
// honeypot_risk } with snake_case fields. The v2 endpoint described
// in the skill docs returns HTTP 500 upstream for every asset, so v1
// is what this client calls; the documented v2 camelCase shape is
// still parsed below as a fallback in case it ever comes back.
function parseV1Security(si: any, warnings: string[], notes: string[]): boolean {
  if (!si || typeof si !== 'object') return false;
  const provider = typeof si.provider === 'string' ? si.provider : '';
  if (si.is_scanned === false) { notes.push('Not yet scanned by Trust Wallet.'); return true; }
  const cs = si.contract_security;
  if (cs && typeof cs === 'object') {
    if (cs.is_counterfeit) warnings.push('Flagged as a counterfeit token.');
    if (typeof cs.num_risks === 'number' && cs.num_risks > 0) warnings.push(`Trust Wallet flags ${cs.num_risks} contract risk${cs.num_risks > 1 ? 's' : ''} on this token.`);
    else if (typeof cs.num_warnings === 'number' && cs.num_warnings > 0) warnings.push(`Trust Wallet flags ${cs.num_warnings} contract warning${cs.num_warnings > 1 ? 's' : ''} on this token.`);
    collectItems(cs.items, warnings);
  }
  const hp = si.honeypot_risk;
  if (hp && typeof hp === 'object') {
    if (typeof hp.num_risks === 'number' && hp.num_risks > 0) warnings.push('Flagged with honeypot risk — buyers may be unable to sell this token.');
    else if (typeof hp.num_warnings === 'number' && hp.num_warnings > 0) warnings.push('Trust Wallet flags honeypot-related warnings on this token.');
    collectItems(hp.items, warnings);
    const bt = typeof hp.buy_tax === 'number' ? hp.buy_tax : null;
    const st = typeof hp.sell_tax === 'number' ? hp.sell_tax : null;
    if ((bt !== null && bt > 0) || (st !== null && st > 0)) {
      const line = `Transfer taxes reported by Trust Wallet: buy ${bt ?? 0}% · sell ${st ?? 0}%.`;
      if ((bt ?? 0) > 10 || (st ?? 0) > 10) warnings.push(line); else notes.push(line);
    }
  }
  if (!warnings.length) notes.push(`Scanned by Trust Wallet${provider ? ` (via ${provider})` : ''} — no contract or honeypot risks found.`);
  return true;
}
export function normalizeCoinStatus(j: any): TwRisk | null {
  if (!j || typeof j !== 'object') return null;
  const warnings: string[] = []; const notes: string[] = [];
  if (parseV1Security(j.security_info, warnings, notes)) return { warnings, notes };
  const si = j.securityInfo; const sol = j.solanaSecurityInfo;
  if (si && typeof si === 'object') {
    if (si.isHoneypot) warnings.push('Flagged as a honeypot — buyers may be unable to sell this token.');
    if (si.canTakeBackOwnership) warnings.push('Ownership of the contract can be taken back by its deployer.');
    if (Array.isArray(si.warnings)) for (const w of si.warnings) if (typeof w === 'string' && w && !warnings.includes(w)) warnings.push(w);
    if (si.hasAudit) notes.push(`Contract audited${si.auditProvider ? ' by ' + String(si.auditProvider) : ''} (reported by Trust Wallet).`);
    else notes.push('No independent audit found by Trust Wallet.');
    if (si.hasMintFunction) notes.push('The issuer can mint new tokens, increasing supply.');
    if (si.isTradingCooldown) notes.push('A trading cooldown applies after buying.');
    if (si.riskLevel) notes.push(`Overall risk level: ${String(si.riskLevel)}.`);
  }
  if (sol && typeof sol === 'object') {
    if (sol.hasFreezeAuthority) warnings.push('Freeze authority is active — the issuer can freeze token accounts.');
    if (Array.isArray(sol.warnings)) for (const w of sol.warnings) if (typeof w === 'string' && w && !warnings.includes(w)) warnings.push(w);
    if (sol.hasMintAuthority) notes.push('Mint authority is active — the issuer can create new supply.');
    if (sol.hasFreezeAuthority === false) notes.push('Freeze authority is revoked.');
    if (sol.hasMintAuthority === false) notes.push('Mint authority is revoked.');
    if (sol.riskLevel) notes.push(`Overall risk level: ${String(sol.riskLevel)}.`);
  }
  if (!si && !sol) return null;
  return { warnings, notes };
}
export function twCoinStatus(assetId: string): Promise<TwRisk | null> {
  if (!twConfigured()) return Promise.resolve(null);
  return cached(`cs:${assetId}`, 600_000, async () => {
    // v1: the v2 endpoint 500s upstream for every asset (verified
    // live 2026-11-21); v1 returns the real security_info payload.
    const j = await twCall('GET', `/v1/coinstatus/${assetId}`, { include_security_info: 'true' });
    return normalizeCoinStatus(j);
  });
}

// ---- address validation ----
export interface TwValidation { result: string; isSanctioned: boolean; isContract: boolean; riskScore: number | null; labels: string[] }
export function normalizeValidate(j: any): TwValidation | null {
  if (!j || typeof j !== 'object') return null;
  // The live endpoint answers a bare {"status":"ok"} for addresses
  // with no flags (verified 2026-11-21) — that IS the neutral
  // verdict; the documented verdict fields only appear when there
  // is something to report.
  if (typeof j.result !== 'string') {
    if (j.status === 'ok') return { result: 'neutral', isSanctioned: false, isContract: false, riskScore: null, labels: [] };
    return null;
  }
  const d = (j.details && typeof j.details === 'object') ? j.details : {};
  return {
    result: j.result,
    isSanctioned: !!d.is_sanctioned,
    isContract: !!d.is_contract,
    riskScore: typeof d.risk_score === 'number' ? d.risk_score : null,
    labels: Array.isArray(d.labels) ? d.labels.filter((x: any) => typeof x === 'string') : [],
  };
}
export function twValidate(assetId: string, address: string): Promise<TwValidation | null> {
  if (!twConfigured()) return Promise.resolve(null);
  return cached(`va:${assetId}:${address.toLowerCase()}`, 600_000, async () => {
    const j = await twCall('GET', '/v1/validate', { address, asset_id: assetId, type: 'address' });
    return normalizeValidate(j);
  });
}

// ---- index prices (batched, up to 50 assets per call) ----
export interface TwTicker { usd: number; change24h: number | null; marketCap: number | null; volume24h: number | null }
export function normalizeTickers(j: any): Record<string, TwTicker> {
  const out: Record<string, TwTicker> = {};
  if (!j || !Array.isArray(j.tickers)) return out;
  for (const t of j.tickers) {
    if (t && typeof t.id === 'string' && typeof t.price === 'number' && t.price > 0) {
      out[t.id] = {
        usd: t.price,
        change24h: typeof t.change_24h === 'number' ? t.change_24h : null,
        marketCap: typeof t.market_cap === 'number' ? t.market_cap : null,
        volume24h: typeof t.volume_24h === 'number' ? t.volume_24h : null,
      };
    }
  }
  return out;
}
export async function twTickers(assetIds: string[]): Promise<Record<string, TwTicker>> {
  if (!twConfigured() || !assetIds.length) return {};
  const out: Record<string, TwTicker> = {}; const missing: string[] = [];
  for (const a of assetIds) {
    const hit = cache.get(`tk:${a}`);
    if (hit && Date.now() - hit.at < 60_000) out[a] = hit.v;
    else missing.push(a);
  }
  if (missing.length) {
    const fresh = await throughQueue(async () => {
      const j = await twCall('POST', '/v2/market/tickers', {}, { currency: 'USD', assets: missing.slice(0, 50) });
      return normalizeTickers(j);
    });
    for (const [k, v] of Object.entries(fresh)) { cache.set(`tk:${k}`, { at: Date.now(), v }); out[k] = v; }
  }
  return out;
}
