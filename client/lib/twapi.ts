// Trust Wallet API — client side.
//
// Every call goes through the Syn server proxy (/api/tw/*): the
// operator's TWAK keys live only in the server environment and never
// reach the browser. When the operator has not configured keys,
// /api/config reports twApiConfigured=false and every helper here is
// a no-op — the wallet behaves exactly as it did before this source
// existed. Trust Wallet data is a SECOND source next to the wallet's
// own checks (GoPlus for EVM, on-chain reads for Solana), never a
// replacement for them, and it is labelled as its own source in the
// UI — never presented as the wallet's own verdict.
import type { RiskReport } from './goplus';

// SLIP-44 coin ids for the chains this source covers (Trust Wallet's
// asset-id scheme: c{coinId} for the native asset,
// c{coinId}_t{contract} for a token). Chains not listed here simply
// have no Trust Wallet coverage in the wallet — an honest absence,
// not an error.
export const TW_COIN_IDS: Record<string, number> = {
  ethereum: 60, bnb: 714, polygon: 966, arbitrum: 10042221,
  optimism: 10000070, base: 10008453, avalanche: 10009000,
  fantom: 10000250, solana: 501, tron: 195, bitcoin: 0, litecoin: 2,
};

export function twAssetId(chainId: string, contract: string): string | null {
  const coin = TW_COIN_IDS[chainId];
  if (coin === undefined) return null;
  if (!contract || contract === 'native') return `c${coin}`;
  return `c${coin}_t${contract}`;
}

let enabled = false;
export function setTwEnabled(v: boolean): void { enabled = v; }
export function twEnabled(): boolean { return enabled; }

async function twGet(path: string): Promise<any | null> {
  try {
    const r = await fetch(path, { signal: AbortSignal.timeout(25000) });
    if (!r.ok) return null;
    return await r.json();
  } catch { return null; }
}

// Token security from Trust Wallet's coin-status endpoint, shaped as
// a RiskReport so it renders through the same risk UI as GoPlus and
// the on-chain Solana check — under its own source label.
export async function twCoinRisk(chainId: string, contract: string): Promise<RiskReport | null> {
  if (!enabled) return null;
  const asset = twAssetId(chainId, contract);
  if (!asset) return null;
  const j = await twGet(`/api/tw/coinstatus?asset=${encodeURIComponent(asset)}`);
  const risk = j?.risk;
  if (!risk || typeof risk !== 'object') return null;
  return {
    status: 'ok',
    warnings: Array.isArray(risk.warnings) ? risk.warnings.filter((w: any) => typeof w === 'string') : [],
    notes: Array.isArray(risk.notes) ? risk.notes.filter((w: any) => typeof w === 'string') : [],
    source: 'Trust Wallet',
  };
}

export interface TwAddrVerdict { result: string; isSanctioned: boolean; labels: string[] }
export async function twAddressVerdict(chainId: string, address: string): Promise<TwAddrVerdict | null> {
  if (!enabled) return null;
  const asset = twAssetId(chainId, 'native');
  if (!asset) return null;
  const j = await twGet(`/api/tw/validate?asset=${encodeURIComponent(asset)}&address=${encodeURIComponent(address)}`);
  const v = j?.validation;
  if (!v || typeof v.result !== 'string') return null;
  return { result: v.result, isSanctioned: !!v.isSanctioned, labels: Array.isArray(v.labels) ? v.labels.filter((x: any) => typeof x === 'string') : [] };
}

export interface TwTickerEntry { usd: number; change24h: number | null; marketCap: number | null; volume24h: number | null }
export async function twTickers(assets: string[]): Promise<Record<string, TwTickerEntry>> {
  if (!enabled || !assets.length) return {};
  try {
    const r = await fetch('/api/tw/tickers', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ assets }),
      signal: AbortSignal.timeout(30000),
    });
    if (!r.ok) return {};
    const j = await r.json();
    return (j?.tickers && typeof j.tickers === 'object') ? j.tickers : {};
  } catch { return {}; }
}
