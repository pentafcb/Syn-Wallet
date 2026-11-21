import { fmtFiat } from './currency';
// Swap providers (Wave 2) — verified KEYLESS from the deploy server on
// 2026-11-18, no API key, account or token needed for either:
//   Jupiter lite-api  (Solana <-> Solana): GET quote + POST swap build,
//     returns a base64 versioned transaction signed locally.
//   LI.FI             (EVM same-chain, EVM <-> EVM cross-chain, and
//     EVM <-> Solana cross-chain): GET quote returns either an EVM
//     transactionRequest {to,data,value,gasLimit} or, when Solana is the
//     source, {data: base64 versioned tx, svmTransactionVersion}.
// The legacy Jupiter v6 host (quote-api.jup.ag) is dead — lite-api is the
// live one. All traffic passes through the Syn server proxy (/api/jupiter/*,
// /api/lifi/*), a verbatim pass-through of public market data; signing is
// ALWAYS local, providers never see a key.
//
// Jupiter's priceImpactPct is a FRACTION (verified empirically against a
// 2,000 SOL quote: 0.000107 ~= 0.0107%); LI.FI impact is derived from its
// own USD estimates. Both are normalised to percent in SwapQuote.

export const LIFI_SOLANA_CHAIN_ID = 1151111081099710;
export const LIFI_NATIVE_EVM = '0x0000000000000000000000000000000000000000';
export const LIFI_NATIVE_SOL = '11111111111111111111111111111111';
export const JUP_SOL_MINT = 'So11111111111111111111111111111111111111112';

export interface SwapQuote {
  provider: 'jupiter' | 'lifi';
  outRaw: string;
  minOutRaw: string;
  outHuman: number;
  minOutHuman: number;
  /** out units per 1 in unit, human terms */
  rate: number;
  /** percent (0.5 means 0.5%); null when the provider gave no basis */
  priceImpactPct: number | null;
  feeLines: string[];
  routeLabel: string;
  etaSec: number | null;
  /** LI.FI only: ERC-20 spender that must hold an allowance (if any) */
  approvalAddress?: string;
  raw: any;
}

/** Exact decimal-string -> raw integer (no float rounding on the way in). */
export function parseRawAmount(s: string, decimals: number): bigint | null {
  const t = String(s).trim();
  if (!/^\d*(\.\d*)?$/.test(t) || t === '' || t === '.') return null;
  const [ip, fp = ''] = t.split('.');
  if (fp.length > decimals) return null;
  const whole = BigInt(ip || '0') * 10n ** BigInt(decimals);
  const frac = BigInt((fp + '0'.repeat(decimals)).slice(0, decimals) || '0');
  const out = whole + frac;
  return out > 0n ? out : null;
}

/** Raw integer -> human float (display only; execution never uses this). */
export function rawToHuman(raw: string | bigint, decimals: number): number {
  try {
    const v = typeof raw === 'bigint' ? raw : BigInt(raw);
    return Number(v) / 10 ** decimals;
  } catch { return 0; }
}

/** Raw integer -> trimmed human string with up to maxDp decimals (exact). */
export function fmtRaw(raw: string | bigint, decimals: number, maxDp = 6): string {
  let v: bigint;
  try { v = typeof raw === 'bigint' ? raw : BigInt(raw); } catch { return '0'; }
  const neg = v < 0n; if (neg) v = -v;
  const base = 10n ** BigInt(decimals);
  const ip = v / base; const fp = v % base;
  let fs = fp.toString().padStart(decimals, '0').slice(0, maxDp).replace(/0+$/, '');
  return (neg ? '-' : '') + ip.toString() + (fs ? '.' + fs : '');
}

/** Minimum-received from an expected out amount and slippage in bps. */
export function minOutFromBps(outRaw: string, slippageBps: number): string {
  try {
    const v = BigInt(outRaw);
    return ((v * BigInt(10000 - Math.round(slippageBps))) / 10000n).toString();
  } catch { return '0'; }
}

export function normalizeJupiterQuote(j: any, inRaw: string, inDec: number, outDec: number, slippageBps: number): SwapQuote | null {
  if (!j || typeof j.outAmount !== 'string' || !/^\d+$/.test(j.outAmount)) return null;
  const labels: string[] = [];
  for (const step of (Array.isArray(j.routePlan) ? j.routePlan : [])) {
    const l = step?.swapInfo?.label;
    if (l && !labels.includes(l)) labels.push(l);
  }
  const inHuman = rawToHuman(inRaw, inDec);
  const outHuman = rawToHuman(j.outAmount, outDec);
  const minRaw = typeof j.otherAmountThreshold === 'string' && /^\d+$/.test(j.otherAmountThreshold)
    ? j.otherAmountThreshold : minOutFromBps(j.outAmount, slippageBps);
  const impactFrac = Number(j.priceImpactPct);
  return {
    provider: 'jupiter',
    outRaw: j.outAmount,
    minOutRaw: minRaw,
    outHuman,
    minOutHuman: rawToHuman(minRaw, outDec),
    rate: inHuman > 0 ? outHuman / inHuman : 0,
    priceImpactPct: Number.isFinite(impactFrac) ? Math.max(0, impactFrac * 100) : null,
    feeLines: ['Network fee: paid in SOL at signing (shown by the network)'],
    routeLabel: labels.length ? labels.join(' → ') : 'Jupiter',
    etaSec: null,
    raw: j,
  };
}

function lifiFeeLines(est: any): string[] {
  const lines: string[] = [];
  // Sub-cent fees keep their significant figures (a $0.00003 fee
  // must not render as $0.0000 — the fixed-4-decimals trap).
  const fmtUsd = (v: any) => { const n = Number(v); if (!Number.isFinite(n) || n <= 0) return null; const dp = n >= 0.01 ? 2 : Math.min(10, Math.ceil(-Math.log10(n)) + 2); return fmtFiat(n, dp); };
  for (const f of (Array.isArray(est?.feeCosts) ? est.feeCosts : [])) {
    const usd = fmtUsd(f?.amountUSD);
    const amt = f?.amount && f?.token?.symbol ? `${fmtRaw(String(f.amount), Number(f.token.decimals ?? 18), 6)} ${f.token.symbol}` : '';
    lines.push(`${f?.name || 'Provider fee'}: ${[amt, usd ? '≈ ' + usd : ''].filter(Boolean).join(' ')}`.trim());
  }
  let gasUsd = 0; let gasAmt = ''; let gasSym = '';
  for (const g of (Array.isArray(est?.gasCosts) ? est.gasCosts : [])) {
    gasUsd += Number(g?.amountUSD) || 0;
    if (g?.amount && g?.token?.symbol) { gasAmt = fmtRaw(String(g.amount), Number(g.token.decimals ?? 18), 6); gasSym = g.token.symbol; }
  }
  if (gasAmt) lines.push(`Network fee (est.): ${gasAmt} ${gasSym}${gasUsd > 0 ? ' ≈ ' + fmtFiat(gasUsd) : ''}`);
  return lines;
}

export function normalizeLifiQuote(j: any, inDec: number, outDec: number): SwapQuote | null {
  const est = j?.estimate;
  if (!j || !est || typeof est.toAmount !== 'string' || !/^\d+$/.test(est.toAmount)) return null;
  const inHuman = rawToHuman(String(est.fromAmount ?? '0'), inDec);
  const outHuman = rawToHuman(est.toAmount, outDec);
  const minRaw = typeof est.toAmountMin === 'string' && /^\d+$/.test(est.toAmountMin) ? est.toAmountMin : est.toAmount;
  const fromUsd = Number(est.fromAmountUSD); const toUsd = Number(est.toAmountUSD);
  const impact = Number.isFinite(fromUsd) && Number.isFinite(toUsd) && fromUsd > 0 ? Math.max(0, (1 - toUsd / fromUsd) * 100) : null;
  const steps: string[] = [];
  for (const s of (Array.isArray(j.includedSteps) ? j.includedSteps : [])) {
    const n = s?.toolDetails?.name || s?.tool;
    if (n && !steps.includes(n)) steps.push(n);
  }
  const toolName = j.toolDetails?.name || j.tool || 'LI.FI';
  return {
    provider: 'lifi',
    outRaw: est.toAmount,
    minOutRaw: minRaw,
    outHuman,
    minOutHuman: rawToHuman(minRaw, outDec),
    rate: inHuman > 0 ? outHuman / inHuman : 0,
    priceImpactPct: impact,
    feeLines: lifiFeeLines(est),
    routeLabel: steps.length > 1 ? steps.join(' → ') : toolName,
    etaSec: Number.isFinite(Number(est.executionDuration)) ? Number(est.executionDuration) : null,
    approvalAddress: typeof est.approvalAddress === 'string' && /^0x[0-9a-fA-F]{40}$/.test(est.approvalAddress) ? est.approvalAddress : undefined,
    raw: j,
  };
}

async function getJson(url: string): Promise<any> {
  const r = await fetch(url, { signal: AbortSignal.timeout(30000) });
  const j = await r.json().catch(() => null);
  if (!r.ok) throw new Error(j?.message || j?.error || `Provider error (${r.status})`);
  return j;
}

export async function fetchJupiterQuote(inputMint: string, outputMint: string, rawAmount: string, slippageBps: number): Promise<any> {
  const qs = new URLSearchParams({ inputMint, outputMint, amount: rawAmount, slippageBps: String(Math.round(slippageBps)) });
  return getJson(`/api/jupiter/quote?${qs.toString()}`);
}
export async function fetchJupiterSwapTx(quoteResponse: any, userPublicKey: string): Promise<string> {
  const r = await fetch('/api/jupiter/swap', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ quoteResponse, userPublicKey, wrapAndUnwrapSol: true, dynamicComputeUnitLimit: true }), signal: AbortSignal.timeout(30000) });
  const j = await r.json().catch(() => null);
  if (!r.ok || !j?.swapTransaction) throw new Error(j?.error || j?.message || 'Jupiter could not build this swap.');
  return j.swapTransaction as string;
}
export interface LifiQuoteParams { fromChain: number; toChain: number; fromToken: string; toToken: string; fromAmountRaw: string; fromAddress: string; toAddress: string; slippage: number; }
export async function fetchLifiQuote(p: LifiQuoteParams): Promise<any> {
  const qs = new URLSearchParams({ fromChain: String(p.fromChain), toChain: String(p.toChain), fromToken: p.fromToken, toToken: p.toToken, fromAmount: p.fromAmountRaw, fromAddress: p.fromAddress, toAddress: p.toAddress, slippage: String(p.slippage) });
  return getJson(`/api/lifi/quote?${qs.toString()}`);
}

// ---------- Audit H-1 (2026-11-19): never blind-sign an aggregator tx ----------
// The transaction an aggregator BUILDS is a separate response from the
// quote the user reviewed. These pure verifiers compare the built tx
// against the reviewed quote and return a problem string (refuse to
// sign) or null (matches what was reviewed).

const LIFI_NATIVE_TOKENS = new Set(['0x0000000000000000000000000000000000000000', '0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee']);
const FORBIDDEN_SELECTORS = new Set(['0xa9059cbb', '0x095ea7b3', '0x23b872dd']); // transfer / approve / transferFrom as the OUTER call

export interface LifiTxExpect { fromChainId: number; fromToken: string; fromAmountRaw: string; toAddress: string; approvalAddress?: string; }
export function verifyLifiEvmTx(tr: any, exp: LifiTxExpect): string | null {
  if (!tr || typeof tr !== 'object') return 'LI.FI returned no transaction to verify.';
  const to = typeof tr.to === 'string' ? tr.to.toLowerCase() : '';
  if (!/^0x[0-9a-f]{40}$/.test(to)) return 'The built transaction has no valid destination.';
  if (exp.approvalAddress && to !== exp.approvalAddress.toLowerCase()) {
    return 'The built transaction goes to a different contract than the one in the reviewed quote. Refusing to sign.';
  }
  if (tr.chainId != null && Number(tr.chainId) !== exp.fromChainId) return 'The built transaction is for a different network than the reviewed quote. Refusing to sign.';
  const nativeIn = LIFI_NATIVE_TOKENS.has(exp.fromToken.toLowerCase());
  let value: bigint;
  try { value = BigInt(tr.value ?? '0'); } catch { return 'The built transaction carries an unreadable value.'; }
  if (nativeIn && value !== BigInt(exp.fromAmountRaw)) return 'The built transaction spends a different amount than the reviewed quote. Refusing to sign.';
  if (!nativeIn && value !== 0n) return 'The built transaction attaches native value to a token swap. Refusing to sign.';
  const data = typeof tr.data === 'string' ? tr.data.toLowerCase() : '';
  if (!/^0x[0-9a-f]{8,}$/.test(data)) return 'The built transaction has no callable data to verify.';
  if (FORBIDDEN_SELECTORS.has(data.slice(0, 10))) return 'The built transaction is a plain transfer/approval, not the reviewed swap. Refusing to sign.';
  const body = data.slice(2);
  if (!body.includes(exp.toAddress.toLowerCase().slice(2))) return 'The built transaction does not pay the reviewed recipient. Refusing to sign.';
  if (!nativeIn && !body.includes(exp.fromToken.toLowerCase().slice(2))) return 'The built transaction does not reference the reviewed input token. Refusing to sign.';
  const gas = tr.gasLimit != null ? Number(tr.gasLimit) : tr.gas != null ? Number(tr.gas) : NaN;
  if (Number.isFinite(gas) && gas > 20_000_000) return 'The built transaction asks for an unreasonable gas limit. Refusing to sign.';
  return null;
}

export interface SimTokenBalance { mint: string; owner?: string; uiTokenAmount?: { amount?: string } }
function sumMint(bals: SimTokenBalance[], owner: string, mint: string): bigint {
  let total = 0n;
  for (const b of bals || []) {
    if (b.mint === mint && (!b.owner || b.owner === owner)) {
      const a = b.uiTokenAmount?.amount;
      if (typeof a === 'string' && /^\d+$/.test(a)) total += BigInt(a);
    }
  }
  return total;
}
/**
 * Verdict for a simulated Solana swap (Jupiter or LI.FI SVM): the
 * simulation's pre/post balances must show the user's input mint
 * leaving by exactly the reviewed raw amount (or, for native SOL
 * input, lamports leaving within a fee tolerance) and the output mint
 * arriving at no less than the reviewed minimum-out.
 */
export function solSwapVerdict(sim: { err?: any; preTokenBalances?: SimTokenBalance[]; postTokenBalances?: SimTokenBalance[]; preBalances?: number[]; postBalances?: number[] }, owner: string, inMint: string, outMint: string, rawIn: string, minOutRaw: string, opts: { inputOnly?: boolean } = {}): string | null {
  if (!sim || sim.err) return 'Simulation of the built swap failed — refusing to sign an unverified transaction.';
  if (!opts.inputOnly) {
    const outDelta = sumMint(sim.postTokenBalances || [], owner, outMint) - sumMint(sim.preTokenBalances || [], owner, outMint);
    if (outDelta < BigInt(minOutRaw)) return 'The built swap returns less than the minimum you reviewed. Refusing to sign.';
  }
  if (inMint === JUP_SOL_MINT) {
    const pre = BigInt(sim.preBalances?.[0] ?? 0), post = BigInt(sim.postBalances?.[0] ?? 0);
    const spent = pre - post;
    const want = BigInt(rawIn);
    if (spent < want) return 'The built swap spends less SOL than the reviewed quote. Refusing to sign.';
    if (spent - want > 100_000_000n) return 'The built swap spends far more SOL than the reviewed quote (fees included). Refusing to sign.';
    return null;
  }
  const inDelta = sumMint(sim.preTokenBalances || [], owner, inMint) - sumMint(sim.postTokenBalances || [], owner, inMint);
  if (inDelta !== BigInt(rawIn)) return 'The built swap spends a different input amount than the reviewed quote. Refusing to sign.';
  return null;
}
