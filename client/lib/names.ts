// Name resolution helpers — ENS (.eth) + SNS (.sol).
// ENS itself is resolved with ethers against Ethereum mainnet (in main.ts);
// this module holds the pure classification logic plus the complete SNS
// derivation, re-implemented from the Bonfida SPL Name Service algorithm
// and verified live against the official SDK (2026-11-18):
//   bonfida.sol -> account Crf8hzfthWGbGbLTVCiqRqV5MVnbpHB1L9KQMd6gsinb
//                  owner   Fw1ETanDZafof7xEULsnq9UY6o71Tpds89tNwPkWLb1v
//   toly.sol    -> account FX1APjKbFu6M8GKb3dGXcZLXjxX4fGaYwvHqb5Vaee8q
//                  owner   86xCnPeV69n6t3DnyGvkKobf9FdN2H9oiVDdaMpo2MMY
import { PublicKey } from '@solana/web3.js';
import { sha256 } from '@noble/hashes/sha2';

export type NameKind = 'ens' | 'sns';

// Returns the name system for a syntactically valid name, else null.
// Only .eth (ENS) and .sol (SNS) are supported — other suffixes (.bnb,
// .arb, .crypto, ...) have no resolver we trust, so they return null and
// the caller must refuse rather than guess.
export function nameKindOf(input: string): NameKind | null {
  const s = input.trim().toLowerCase();
  if (/^[a-z0-9]([a-z0-9-_]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-_]*[a-z0-9])?)*\.eth$/.test(s)) return 'ens';
  if (/^[a-z0-9]([a-z0-9-_]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-_]*[a-z0-9])?)?\.sol$/.test(s)) return 'sns';
  return null;
}

// True when the input looks like an attempted name (contains a dot and a
// letter suffix) rather than a raw address — used to hard-block sends to
// names that fail to resolve or use an unsupported suffix.
export function looksLikeNameAttempt(input: string): boolean {
  const s = input.trim();
  return /^[^\s.]+\.[a-z]{2,}$/i.test(s) || /\.(eth|sol)$/i.test(s);
}

// ---------------- SNS (Bonfida SPL Name Service) ----------------
export const SNS_PROGRAM = 'namesLPneVptA9Z5rqUDD9tMTWEJwofgaYwp8cawRkX';
export const SNS_ROOT = '58PwtjSDuFHuUkYjH9BYnnQKHfwo9reZhC2zMJv9JPkx'; // the .sol TLD account
export const SNS_REVERSE_CLASS = '33m47vH6Eav6jr5Ry86XjhRft2jRBLDnDgPSHoquXi2Z';
export const SNS_FAVOURITE_PROGRAM = '85iDfUvr3HJyLM2zcq5BXSiDvUWfw6cSE1FfNBo8Ap29';
const ZERO32 = new Uint8Array(32);

export function snsHashedName(name: string): Uint8Array {
  return sha256(new TextEncoder().encode('SPL Name Service' + name));
}
export function snsNameKey(hashed: Uint8Array, parent?: PublicKey, nameClass?: PublicKey): PublicKey {
  const seeds: Uint8Array[] = [hashed, nameClass ? nameClass.toBuffer() : ZERO32, parent ? parent.toBuffer() : ZERO32];
  return PublicKey.findProgramAddressSync(seeds, new PublicKey(SNS_PROGRAM))[0];
}
// Domain key for "name.sol" or "sub.name.sol" (one subdomain level, the
// same subset the official SDK's getDomainKeySync accepts).
export function snsDomainKey(domain: string): PublicKey {
  let d = domain.trim().toLowerCase();
  if (d.endsWith('.sol')) d = d.slice(0, -4);
  const parts = d.split('.');
  if (parts.length === 2) {
    const parent = snsDomainKey(parts[1] + '.sol');
    return snsNameKey(snsHashedName('\0' + parts[0]), parent);
  }
  if (parts.length !== 1 || !parts[0]) throw new Error('malformed .sol domain');
  return snsNameKey(snsHashedName(d), new PublicKey(SNS_ROOT));
}
// NameRegistryState header: parentName [0..32), owner [32..64), class [64..96).
export function snsOwnerFromAccountData(data: Uint8Array): string | null {
  if (!data || data.length < 64) return null;
  const owner = new PublicKey(data.slice(32, 64));
  return owner.toBase58();
}
export function snsParentFromAccountData(data: Uint8Array): string | null {
  if (!data || data.length < 32) return null;
  return new PublicKey(data.slice(0, 32)).toBase58();
}
export function snsReverseKey(domainKey: PublicKey, parentKey?: PublicKey): PublicKey {
  return snsNameKey(snsHashedName(domainKey.toBase58()), parentKey, new PublicKey(SNS_REVERSE_CLASS));
}
// Reverse record data lives after the 96-byte header: u32 LE length + name.
export function snsNameFromReverseData(data: Uint8Array): string | null {
  if (!data || data.length <= 100) return null;
  const body = data.slice(96);
  const len = body[0] | (body[1] << 8) | (body[2] << 16) | (body[3] << 24);
  if (len <= 0 || 4 + len > body.length) return null;
  const name = new TextDecoder().decode(body.slice(4, 4 + len)).replace(/^\0/, '').trim();
  return name || null;
}
// A wallet's favourite (primary) domain account: PDA of the SNS offers
// program with seeds ["favourite_domain", wallet].
export function snsFavouriteKey(wallet: PublicKey): PublicKey {
  return PublicKey.findProgramAddressSync([new TextEncoder().encode('favourite_domain'), wallet.toBuffer()], new PublicKey(SNS_FAVOURITE_PROGRAM))[0];
}
// Favourite account data: tag u8 [0], nameAccount [1..33).
export function snsFavouriteNameAccount(data: Uint8Array): string | null {
  if (!data || data.length < 33) return null;
  return new PublicKey(data.slice(1, 33)).toBase58();
}
