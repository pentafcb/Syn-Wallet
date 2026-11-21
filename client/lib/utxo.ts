// Generalized UTXO stack for the Bitcoin-family chains (kind
// 'bitcoin' in the chain registry): Bitcoin and Litecoin today,
// built so another esplora-backed UTXO chain is a params entry, not
// a new stack. One derivation family (BIP84 native segwit, the same
// shape the wallet already uses for BTC), one coin-selection, one
// signer (@scure/btc-signer with per-chain network params), one
// data shape (esplora: address / utxo / txs / broadcast).
//
// DOGE and BCH are deliberately NOT params entries: DOGE has no
// keyless esplora-compatible data source and BCH signs with the
// SIGHASH_FORKID digest this signer does not produce — see
// ~/workspace/syn-wallet-coin-coverage-audit.md for the full audit.
import * as btc from '@scure/btc-signer';
import { base16 } from '@scure/base';

export interface UtxoNetParams {
  network: typeof btc.NETWORK;
  coinType: number;         // SLIP-0044 coin type for the BIP84 path
  dustSats: number;         // outputs below this are dust; change below it is folded into the fee
  legacyP2pkhPrefix: number; // for format reporting in tests/audit
  legacyP2shPrefix: number;
}
export const UTXO_CHAINS: Record<string, UtxoNetParams> = {
  bitcoin: { network: btc.NETWORK, coinType: 0, dustSats: 546, legacyP2pkhPrefix: 0x00, legacyP2shPrefix: 0x05 },
  litecoin: { network: { bech32: 'ltc', pubKeyHash: 0x30, scriptHash: 0x32, wif: 0xb0 }, coinType: 2, dustSats: 546, legacyP2pkhPrefix: 0x30, legacyP2shPrefix: 0x32 },
};
export function utxoParams(chainId: string): UtxoNetParams | null { return UTXO_CHAINS[chainId] || null; }

/** Strict address validation for a UTXO chain: decodes bech32 AND
 * base58check against THIS chain's network params, so a Bitcoin
 * address is rejected on Litecoin and vice versa, and a corrupted
 * checksum never passes. */
export function isValidUtxoAddress(chainId: string, addr: string): boolean {
  const p = utxoParams(chainId); if (!p) return false;
  const s = (addr || '').trim(); if (!s || s.length > 120) return false;
  try { btc.Address(p.network).decode(s); return true; } catch { return false; }
}

/** Address format label for audit/tests: 'bech32' | 'p2sh' | 'legacy'. */
export function utxoAddressFormat(chainId: string, addr: string): 'bech32' | 'p2sh' | 'legacy' | null {
  const p = utxoParams(chainId); if (!p) return null;
  try {
    const d = btc.Address(p.network).decode(addr.trim());
    if (d.type === 'wpkh' || d.type === 'wsh' || d.type === 'tr') return 'bech32';
    if (d.type === 'sh') return 'p2sh';
    if (d.type === 'pkh') return 'legacy';
    return null;
  } catch { return null; }
}

export interface Utxo { txid: string; vout: number; value: number; confirmed: boolean }
/** Virtual size of one P2WPKH input, and of an output by its script
 * type — the standard segwit weights (input 68 vB; wpkh output 31,
 * pkh 34, sh 32, tr 43), tx overhead 11 vB with a change output's
 * witness discount accounted in the per-item sizes. */
export const UTXO_INPUT_VB = 68;
export function outputVbytes(chainId: string, addr: string): number {
  const f = utxoAddressFormat(chainId, addr);
  return f === 'legacy' ? 34 : f === 'p2sh' ? 32 : 31;
}
export interface CoinSelection { inputs: Utxo[]; feeSats: number; changeSats: number; vbytes: number }
/** Largest-first selection until amount + fee is covered. Returns
 * null when the UTXO set cannot fund amount + fee at this rate.
 * Change below the dust limit is folded into the fee (no dust
 * output is ever created). Unconfirmed UTXOs are spendable (they
 * are the wallet's own incoming funds in this single-address
 * model) but confirmed ones are preferred by the sort. */
export function selectCoins(chainId: string, utxos: Utxo[], toAddr: string, changeAddr: string, amountSats: number, feeRateSatVb: number): CoinSelection | null {
  const p = utxoParams(chainId); if (!p) return null;
  const rate = Math.max(1, feeRateSatVb);
  const sorted = [...utxos].filter(u => u.value > 0).sort((a, b) => (Number(b.confirmed) - Number(a.confirmed)) || (b.value - a.value));
  const outVb = outputVbytes(chainId, toAddr) + outputVbytes(chainId, changeAddr);
  const inputs: Utxo[] = []; let sum = 0;
  for (const u of sorted) {
    inputs.push(u); sum += u.value;
    const vb = 11 + inputs.length * UTXO_INPUT_VB + outVb;
    const fee = Math.ceil(vb * rate);
    if (sum >= amountSats + fee) {
      const change = sum - amountSats - fee;
      if (change >= p.dustSats) return { inputs, feeSats: fee, changeSats: change, vbytes: vb };
      // Change would be dust: fold it into the fee, one less output.
      const vb2 = 11 + inputs.length * UTXO_INPUT_VB + outputVbytes(chainId, toAddr);
      const fee2 = Math.ceil(vb2 * rate);
      if (sum >= amountSats + fee2) return { inputs, feeSats: sum - amountSats, changeSats: 0, vbytes: vb2 };
    }
  }
  return null;
}

export interface BuiltUtxoTx { hex: string; txid: string; feeSats: number; changeSats: number; vbytes: number }
/** Build + sign a complete send from the wallet's single derived
 * address (all UTXOs belong to it). Throws a plain-language error
 * when the set cannot fund the send. */
export function buildUtxoSend(args: { chainId: string; utxos: Utxo[]; privKey: Uint8Array; pubKey: Uint8Array; fromAddress: string; toAddress: string; amountSats: number; feeRateSatVb: number }): BuiltUtxoTx {
  const p = utxoParams(args.chainId); if (!p) throw new Error('Unsupported UTXO chain.');
  if (!isValidUtxoAddress(args.chainId, args.toAddress)) throw new Error('That does not look like a valid address for this network.');
  const sel = selectCoins(args.chainId, args.utxos, args.toAddress, args.fromAddress, args.amountSats, args.feeRateSatVb);
  if (!sel) throw new Error('Insufficient balance to cover the amount plus the network fee.');
  const pay = btc.p2wpkh(args.pubKey, p.network);
  const tx = new btc.Transaction();
  for (const u of sel.inputs) tx.addInput({ txid: u.txid, index: u.vout, witnessUtxo: { script: pay.script, amount: BigInt(u.value) } });
  tx.addOutputAddress(args.toAddress, BigInt(args.amountSats), p.network);
  if (sel.changeSats > 0) tx.addOutputAddress(args.fromAddress, BigInt(sel.changeSats), p.network);
  tx.sign(args.privKey);
  tx.finalize();
  return { hex: base16.encode(tx.extract()).toLowerCase(), txid: tx.id, feeSats: sel.feeSats, changeSats: sel.changeSats, vbytes: sel.vbytes };
}

/** Rough fee estimate (sats) for the review screen before the real
 * selection runs at signing: the actual UTXO count when known,
 * capped at 3 inputs for the estimate. */
export function estimateUtxoFeeSats(chainId: string, utxoCount: number, toAddr: string, feeRateSatVb: number): number {
  const n = Math.max(1, Math.min(utxoCount || 1, 3));
  const vb = 11 + n * UTXO_INPUT_VB + outputVbytes(chainId, toAddr || '') + 31;
  return Math.ceil(vb * Math.max(1, feeRateSatVb));
}
