// Pure validation helpers for custom networks — shared by the UI and tests.
export interface CustomNetworkInput { name: string; rpc: string; chainId: number; symbol: string; explorer: string; }
export function parseChainIdResult(result: unknown): number | null {
  if (typeof result !== 'string' || !/^0x[0-9a-fA-F]+$/.test(result)) return null;
  const n = parseInt(result, 16);
  return Number.isSafeInteger(n) && n > 0 ? n : null;
}
// Audit NEW MEDIUM (2026-11-19): chain names/symbols are rendered across
// the app; a crafted name must never carry markup or control characters
// into storage in the first place (sinks also escape — defence in depth).
const NAME_OK = /^[\p{L}\p{N}][\p{L}\p{N} .&'()+-]*$/u;
const SYMBOL_OK = /^[A-Za-z0-9][A-Za-z0-9 ._-]*$/;
export function validateCustomNetwork(input: CustomNetworkInput, rpcChainId: number | null): string | null {
  const name = input.name.trim();
  if (!name) return 'Give the network a name.';
  if (name.length > 32 || !NAME_OK.test(name)) return 'Network name: letters, numbers and spaces only (max 32 characters).';
  if (!/^https:\/\//i.test(input.rpc.trim())) return 'RPC URL must start with https://';
  if (!Number.isSafeInteger(input.chainId) || input.chainId <= 0) return 'Chain ID must be a positive number.';
  const symbol = input.symbol.trim();
  if (!symbol || symbol.length > 12 || !SYMBOL_OK.test(symbol)) return 'Enter the native currency symbol (letters/numbers, max 12 characters).';
  if (input.explorer && !/^https:\/\//i.test(input.explorer.trim())) return 'Explorer URL must start with https://';
  if (rpcChainId == null) return 'The RPC did not answer with a chain ID — check the URL and try again.';
  if (rpcChainId !== input.chainId) return `Chain ID mismatch: the RPC reports chain ${rpcChainId}, not ${input.chainId}. Not saved.`;
  return null;
}

/**
 * Audit NEW HIGH (2026-11-19): token name/symbol text comes straight
 * from the token contract (or an imported backup) and is rendered on
 * Home and on send/swap REVIEW screens. Sanitise at the door: strip
 * control characters and angle brackets, cap lengths, and require a
 * sane symbol charset. Returns null when the text is unusable.
 */
export function sanitizeTokenText(raw: unknown, kind: 'name' | 'symbol'): string | null {
  if (typeof raw !== 'string') return null;
  const s = raw.replace(/[\u0000-\u001f\u007f<>]/g, '').trim().replace(/\s+/g, ' ');
  if (!s) return null;
  if (kind === 'symbol') {
    if (s.length > 12 || !SYMBOL_OK.test(s)) return null;
    return s;
  }
  if (s.length > 64 || !NAME_OK.test(s)) return null;
  return s;
}

// Audit M-7: TRON recipient validation verifies the Base58Check
// checksum (double-SHA256 of the first 21 bytes in the last 4), so a
// typo'd address is rejected instead of silently sending to a
// corrupted one. Lives here (not main.ts) so tests cover it.
import bs58 from 'bs58';
import { sha256 } from '@noble/hashes/sha2';
export function isValidTronAddress(a: string): boolean {
  try {
    const raw = bs58.decode(a);
    if (raw.length !== 25 || raw[0] !== 0x41) return false;
    const check = sha256(sha256(raw.slice(0, 21)));
    return raw[21] === check[0] && raw[22] === check[1] && raw[23] === check[2] && raw[24] === check[3];
  } catch { return false; }
}
