// EVM fee maths — pure functions, unit-tested. Used by the Send / token
// send / revoke confirm screens for Slow / Market / Fast presets and
// custom EIP-1559 fees. Nothing here touches the network.

export interface FeePreset { maxFeePerGas: bigint; maxPriorityFeePerGas: bigint; }
export type FeeLevel = 'slow' | 'market' | 'fast';

// Scale a bigint by a decimal factor with 0.1% precision.
function scale(x: bigint, f: number): bigint {
  return (x * BigInt(Math.round(f * 1000))) / 1000n;
}

// Presets from the live base fee + a priority-fee sample (e.g. from
// eth_feeHistory percentiles or eth_maxPriorityFeePerGas):
//   slow   — 0.8x priority, maxFee covers ~1.1 base-fee blocks
//   market — 1.0x priority, maxFee covers 2 base-fee blocks (ethers-style)
//   fast   — 1.5x priority, maxFee covers ~2.5 base-fee blocks
export function computePresets(baseFeePerGas: bigint, prioritySample: bigint): Record<FeeLevel, FeePreset> {
  const prio = prioritySample > 0n ? prioritySample : 1n;
  const mk = (pf: number, bf: number): FeePreset => {
    const p = scale(prio, pf);
    return { maxPriorityFeePerGas: p, maxFeePerGas: scale(baseFeePerGas, bf) + p };
  };
  return { slow: mk(0.8, 1.1), market: mk(1.0, 2.0), fast: mk(1.5, 2.5) };
}
// Legacy (pre-1559) chains price with a single gasPrice.
export function computeLegacyPresets(gasPrice: bigint): Record<FeeLevel, bigint> {
  return { slow: scale(gasPrice, 0.9), market: gasPrice, fast: scale(gasPrice, 1.25) };
}

// Decimal Gwei string -> wei. Returns null for anything malformed,
// negative, or with more than 9 decimal places.
export function parseGwei(s: string): bigint | null {
  const t = s.trim();
  if (!/^\d+(\.\d{1,9})?$/.test(t)) return null;
  const [ip, fp = ''] = t.split('.');
  return BigInt(ip) * 1000000000n + BigInt((fp + '000000000').slice(0, 9));
}
export function formatGwei(wei: bigint): string {
  const neg = wei < 0n; const v = neg ? -wei : wei;
  const ip = v / 1000000000n; const fp = (v % 1000000000n).toString().padStart(9, '0').replace(/0+$/, '');
  return (neg ? '-' : '') + ip.toString() + (fp ? '.' + fp : '');
}

// Validate user-entered custom fees against the live base fee.
// Errors block signing; warnings are shown in plain language but allow it.
export function validateCustomFees(maxFeeGwei: string, priorityGwei: string, baseFeePerGas: bigint | null): { error?: string; warning?: string } {
  const maxFee = parseGwei(maxFeeGwei);
  const prio = parseGwei(priorityGwei);
  if (maxFee === null || prio === null) return { error: 'Enter both fees as numbers in Gwei (e.g. 12.5).' };
  if (maxFee <= 0n) return { error: 'Max fee must be above zero.' };
  if (prio > maxFee) return { error: 'Priority fee cannot be higher than the max fee.' };
  if (baseFeePerGas !== null && maxFee < baseFeePerGas) return { warning: 'Your max fee is below the current base fee (' + formatGwei(baseFeePerGas) + ' Gwei) — the transaction will likely stay pending until the base fee falls.' };
  if (prio === 0n) return { warning: 'A zero priority fee may be ignored by validators — the transaction could wait a long time.' };
  if (maxFee > 1000n * 1000000000n) return { warning: 'That max fee is unusually high (over 1,000 Gwei). Double-check the number before signing.' };
  return {};
}

// The fee a transaction will actually be charged at most, for display:
// min(maxFee, baseFee + priority) per gas on 1559 chains.
export function effectiveGasPriceWei(p: FeePreset, baseFeePerGas: bigint | null): bigint {
  if (baseFeePerGas === null) return p.maxFeePerGas;
  const withPrio = baseFeePerGas + p.maxPriorityFeePerGas;
  return p.maxFeePerGas < withPrio ? p.maxFeePerGas : withPrio;
}
