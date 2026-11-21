import { generateMnemonic, validateMnemonic, mnemonicToSeedSync } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import { HDKey } from '@scure/bip32';
import { hmac } from '@noble/hashes/hmac';
import { sha512 } from '@noble/hashes/sha2';
import { base58, base16 } from '@scure/base';
import * as btc from '@scure/btc-signer';
import { ethers } from 'ethers';

export function createMnemonic(strength: 128 | 256 = 128): string { return generateMnemonic(wordlist, strength); }
export { wordlist as bip39Wordlist };
export function isValidMnemonic(m: string): boolean { return validateMnemonic(m.trim().toLowerCase().replace(/\s+/g, ' '), wordlist); }
export function normalizeMnemonic(m: string): string { return m.trim().toLowerCase().replace(/\s+/g, ' '); }

// SLIP-0010 ed25519 derivation (hardened only)
function slip10Master(seed: Uint8Array): { key: Uint8Array; chain: Uint8Array } {
  const I = hmac(sha512, new TextEncoder().encode('ed25519 seed'), seed);
  return { key: I.slice(0, 32), chain: I.slice(32) };
}
function slip10Child(key: Uint8Array, chain: Uint8Array, index: number): { key: Uint8Array; chain: Uint8Array } {
  const data = new Uint8Array(37);
  data[0] = 0;
  data.set(key, 1);
  const idx = index + 0x80000000;
  data[33] = (idx >>> 24) & 255; data[34] = (idx >>> 16) & 255; data[35] = (idx >>> 8) & 255; data[36] = idx & 255;
  const I = hmac(sha512, chain, data);
  return { key: I.slice(0, 32), chain: I.slice(32) };
}
export function deriveSolana(seed: Uint8Array, accountIndex = 0): { privateKey32: Uint8Array; address: string } {
  let { key, chain } = slip10Master(seed);
  for (const i of [44, 501, accountIndex, 0]) { const n = slip10Child(key, chain, i); key = n.key; chain = n.chain; }
  // Address needs ed25519 public key; computed lazily by caller via @solana/web3.js Keypair.fromSeed
  return { privateKey32: key, address: '' };
}
export interface DerivedAccounts { evmAddress: string; evmPrivateKey: string; btcAddress: string; btcPrivateKeyHex: string; solSeed32: Uint8Array; solAddress: string; }
export function deriveAll(mnemonic: string, accountIndex = 0): DerivedAccounts {
  const seed = mnemonicToSeedSync(normalizeMnemonic(mnemonic));
  const master = HDKey.fromMasterSeed(seed);
  const evmNode = master.derive(`m/44'/60'/0'/0/${accountIndex}`);
  if (!evmNode.privateKey) throw new Error('derivation failed');
  const evmPrivateKey = '0x' + base16.encode(evmNode.privateKey);
  const evmAddress = new ethers.Wallet(evmPrivateKey).address;
  const btcNode = master.derive(`m/84'/0'/0'/0/${accountIndex}`);
  if (!btcNode.privateKey || !btcNode.publicKey) throw new Error('btc derivation failed');
  const p2wpkh = btc.p2wpkh(btcNode.publicKey, btc.NETWORK);
  const btcAddress = p2wpkh.address!;
  const sol = deriveSolana(seed, accountIndex);
  return { evmAddress, evmPrivateKey, btcAddress, btcPrivateKeyHex: base16.encode(btcNode.privateKey), solSeed32: sol.privateKey32, solAddress: solanaAddressFromSeed32(sol.privateKey32) };
}
import { ed25519 } from '@noble/curves/ed25519';
export function solanaAddressFromSeed32(seed32: Uint8Array): string {
  return base58.encode(ed25519.getPublicKey(seed32));
}
// Vault — AES-GCM + PBKDF2 (WebCrypto)
export interface VaultBlob { v: 1; salt: string; iv: string; ct: string; }
const b64 = (b: Uint8Array) => btoa(String.fromCharCode(...b));
const unb64 = (s: string) => Uint8Array.from(atob(s), c => c.charCodeAt(0));
async function vaultKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', salt: salt as BufferSource, iterations: 600000, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
// Minimum length for a NEW wallet password, enforced by the
// set-password screen (wallet creation + every import flow — they
// all share that one screen). Audit finding M-4 recommended raising
// the floor to 12; the user explicitly overrode that on 2026-11-19
// ("Keep the 8 character passwords"), so the floor is 8. Unlock and
// decrypt never check length — existing passwords of any length
// keep working, and nothing else about the vault crypto changes.
export const MIN_PASSWORD_LENGTH = 8;
export async function encryptVault(plaintext: string, password: string): Promise<VaultBlob> {
  const salt = crypto.getRandomValues(new Uint8Array(32));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await vaultKey(password, salt);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv as BufferSource }, key, new TextEncoder().encode(plaintext)));
  return { v: 1, salt: b64(salt), iv: b64(iv), ct: b64(ct) };
}
export async function decryptVault(blob: VaultBlob, password: string): Promise<string> {
  const key = await vaultKey(password, unb64(blob.salt));
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(blob.iv) as BufferSource }, key, unb64(blob.ct) as BufferSource);
  return new TextDecoder().decode(pt);
}
export { base58, base16 };

// ================= Wave 1A: multi-family derivation + vault v2 =================
import { keccak_256, sha3_256 } from '@noble/hashes/sha3';
import { ripemd160 } from '@noble/hashes/legacy';
import { blake2b } from '@noble/hashes/blake2';
import { sha256 } from '@noble/hashes/sha2';
import { bech32 } from '@scure/base';

// Generalized SLIP-0010 ed25519 derivation along an arbitrary hardened path.
export function slip10Derive(seed: Uint8Array, path: number[]): Uint8Array {
  let { key, chain } = slip10Master(seed);
  for (const i of path) { const n = slip10Child(key, chain, i); key = n.key; chain = n.chain; }
  return key;
}
// Base58Check with a custom alphabet (needed for TRON + XRP classic addresses).
function b58checkEncode(payload: Uint8Array, alphabet: string): string {
  const checksum = sha256(sha256(payload)).slice(0, 4);
  const full = new Uint8Array(payload.length + 4); full.set(payload); full.set(checksum, payload.length);
  let zeros = 0; while (zeros < full.length && full[zeros] === 0) zeros++;
  let num = 0n; for (const b of full) num = num * 256n + BigInt(b);
  let out = '';
  while (num > 0n) { out = alphabet[Number(num % 58n)] + out; num /= 58n; }
  return alphabet[0].repeat(zeros) + out;
}
const B58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const XRP_ALPHABET = 'rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz';

export interface DerivedAccounts2 extends DerivedAccounts {
  accountIndex: number;
  ltcPrivateKeyHex: string; ltcAddress: string; ltcLegacyAddress: string; ltcNestedAddress: string;
  solTWSeed32: Uint8Array; solTWAddress: string;
  tronPrivateKeyHex: string; tronAddress: string;
  xrpPrivateKeyHex: string; xrpAddress: string;
  cosmosPrivateKeyHex: string; cosmosAddress: string;
  suiSeed32: Uint8Array; suiAddress: string;
  aptosSeed32: Uint8Array; aptosAddress: string;
}
export function deriveAll2(mnemonic: string, accountIndex = 0): DerivedAccounts2 {
  const base = deriveAll(mnemonic, accountIndex);
  const seed = mnemonicToSeedSync(normalizeMnemonic(mnemonic));
  const master = HDKey.fromMasterSeed(seed);
  const acct = accountIndex;
  // Solana — Trust Wallet path m/44'/501'/acct' (account level, no change/index legs)
  const solTWSeed32 = slip10Derive(seed, [44, 501, acct]);
  const solTWAddress = solanaAddressFromSeed32(solTWSeed32);
  // TRON — secp256k1 m/44'/195'/0'/0/acct
  const tronNode = master.derive(`m/44'/195'/0'/0/${acct}`);
  if (!tronNode.privateKey || !tronNode.publicKey) throw new Error('tron derivation failed');
  const tronPrivateKeyHex = base16.encode(tronNode.privateKey);
  const tronPubUncompressed = secp256k1Point(tronNode.privateKey, false); // 65 bytes, 0x04 prefix
  const tronHash = keccak_256(tronPubUncompressed.slice(1)).slice(-20);
  const tronPayload = new Uint8Array(21); tronPayload[0] = 0x41; tronPayload.set(tronHash, 1);
  const tronAddress = b58checkEncode(tronPayload, B58_ALPHABET);
  // XRP — secp256k1 m/44'/144'/0'/0/acct, accountID = RIPEMD160(SHA256(pubkey))
  const xrpNode = master.derive(`m/44'/144'/0'/0/${acct}`);
  if (!xrpNode.privateKey || !xrpNode.publicKey) throw new Error('xrp derivation failed');
  const xrpPrivateKeyHex = base16.encode(xrpNode.privateKey);
  const xrpAccountId = ripemd160(sha256(xrpNode.publicKey));
  const xrpPayload = new Uint8Array(21); xrpPayload[0] = 0x00; xrpPayload.set(xrpAccountId, 1);
  const xrpAddress = b58checkEncode(xrpPayload, XRP_ALPHABET);
  // Cosmos — secp256k1 m/44'/118'/0'/0/acct, bech32 of RIPEMD160(SHA256(pubkey))
  const cosNode = master.derive(`m/44'/118'/0'/0/${acct}`);
  if (!cosNode.privateKey || !cosNode.publicKey) throw new Error('cosmos derivation failed');
  const cosmosPrivateKeyHex = base16.encode(cosNode.privateKey);
  const cosmosHash = ripemd160(sha256(cosNode.publicKey));
  const cosmosAddress = bech32.encode('cosmos', bech32.toWords(cosmosHash));
  // Sui — ed25519 SLIP-0010 m/44'/784'/acct'/0'/0', address = BLAKE2b-256(0x00 || pubkey)
  const suiSeed32 = slip10Derive(seed, [44, 784, acct, 0, 0]);
  const suiPub = ed25519.getPublicKey(suiSeed32);
  const suiInput = new Uint8Array(33); suiInput[0] = 0; suiInput.set(suiPub, 1);
  const suiAddress = '0x' + base16.encode(blake2b(suiInput, { dkLen: 32 })).toLowerCase();
  // Aptos — ed25519 SLIP-0010 m/44'/637'/acct'/0'/0', address = SHA3-256(pubkey || 0x00)
  const aptosSeed32 = slip10Derive(seed, [44, 637, acct, 0, 0]);
  const aptosPub = ed25519.getPublicKey(aptosSeed32);
  const aptosInput = new Uint8Array(33); aptosInput.set(aptosPub, 0); aptosInput[32] = 0;
  const aptosAddress = '0x' + base16.encode(sha3_256(aptosInput)).toLowerCase();
  // Litecoin — SLIP-0044 coin type 2. Primary address is BIP84
  // native segwit (ltc1q…), the same derivation shape as Bitcoin's;
  // the BIP44 legacy (L…) and BIP49 nested-segwit (M…) addresses of
  // the same account are derived too (cross-checked against
  // bitcoinjs-lib — see tests/test-utxo.ts). The BIP84 key is the
  // spend key for the wallet's LTC address.
  const LTC_NET = { bech32: 'ltc', pubKeyHash: 0x30, scriptHash: 0x32, wif: 0xb0 };
  const ltcNode = master.derive(`m/84'/2'/0'/0/${acct}`);
  if (!ltcNode.privateKey || !ltcNode.publicKey) throw new Error('ltc derivation failed');
  const ltcPrivateKeyHex = base16.encode(ltcNode.privateKey);
  const ltcAddress = btc.p2wpkh(ltcNode.publicKey, LTC_NET).address!;
  const ltc44 = master.derive(`m/44'/2'/0'/0/${acct}`);
  const ltcLegacyAddress = btc.p2pkh(ltc44.publicKey!, LTC_NET).address!;
  const ltc49 = master.derive(`m/49'/2'/0'/0/${acct}`);
  const ltcNestedAddress = btc.p2sh(btc.p2wpkh(ltc49.publicKey!, LTC_NET), LTC_NET).address!;
  return { ...base, accountIndex, ltcPrivateKeyHex, ltcAddress, ltcLegacyAddress, ltcNestedAddress, solTWSeed32, solTWAddress, tronPrivateKeyHex, tronAddress, xrpPrivateKeyHex, xrpAddress, cosmosPrivateKeyHex, cosmosAddress, suiSeed32, suiAddress, aptosSeed32, aptosAddress };
}
import { secp256k1 } from '@noble/curves/secp256k1';
function secp256k1Point(priv: Uint8Array, compressed: boolean): Uint8Array {
  return secp256k1.getPublicKey(priv, compressed);
}

// ---- Canonical private-key EXPORT formats (Addition 9) ----
// Each function renders a derived key in the encoding the chain's own
// ecosystem uses for import/export, so a key shown in Settings can be
// pasted into Phantom/Trust/MetaMask/Keplr/Petra etc. and reproduce the
// exact same account. Pure functions of the derived material — no I/O.
/** Solana (Phantom/Solflare export): base58 of the 64-byte secret key (seed ‖ public key). */
export function solanaSecretKeyBase58(seed32: Uint8Array): string {
  const pub = ed25519.getPublicKey(seed32);
  const full = new Uint8Array(64); full.set(seed32, 0); full.set(pub, 32);
  return base58.encode(full);
}
/** Bitcoin WIF (compressed, mainnet): base58check of 0x80 ‖ key ‖ 0x01 — matches the p2wpkh derivation above. */
export function btcWifFromPrivateKey(priv: Uint8Array): string {
  return utxoWifFromPrivateKey(priv, 0x80);
}
/** UTXO-family WIF (compressed) with the chain's version byte —
 * Litecoin uses 0xb0 (its WIFs start with 'T'). */
export function utxoWifFromPrivateKey(priv: Uint8Array, wifPrefix: number): string {
  const payload = new Uint8Array(34); payload[0] = wifPrefix; payload.set(priv, 1); payload[33] = 0x01;
  return b58checkEncode(payload, B58_ALPHABET);
}
/** Sui (Sui Wallet / Suiet export): bech32 'suiprivkey' over flag byte 0x00 (ed25519) ‖ 32-byte key. */
export function suiPrivateKeyBech32(seed32: Uint8Array): string {
  const payload = new Uint8Array(33); payload[0] = 0; payload.set(seed32, 1);
  return bech32.encode('suiprivkey', bech32.toWords(payload));
}
/** Aptos (AIP-80 / Petra export): 'ed25519-priv-0x' + hex of the 32-byte key. */
export function aptosPrivateKeyExport(seed32: Uint8Array): string {
  return 'ed25519-priv-0x' + base16.encode(seed32).toLowerCase();
}

// ---- Vault v2: multi-wallet payload (migration-safe) ----
export interface WalletEntry { id: string; name: string; kind: 'mnemonic' | 'privateKey'; secret: string; chain?: string; createdAt: number; accounts: number; hlAgent?: { key: string; approved: string[] }; }
export interface VaultPayload { v: 2; wallets: WalletEntry[]; activeId: string; }
export function newWalletId(): string { return 'w-' + base16.encode(crypto.getRandomValues(new Uint8Array(6))).toLowerCase(); }
export function packVaultPayload(p: VaultPayload): string { return JSON.stringify(p); }
export function parseVaultPlaintext(plain: string, legacyMeta?: { kind: 'mnemonic' | 'privateKey'; chain?: string; createdAt?: number } | null): { payload: VaultPayload; migrated: boolean } {
  try {
    const j = JSON.parse(plain);
    if (j && j.v === 2 && Array.isArray(j.wallets) && j.wallets.length > 0 && j.wallets.every((w: any) => w && typeof w.secret === 'string')) {
      const wallets: WalletEntry[] = j.wallets.map((w: any) => ({ id: String(w.id || newWalletId()), name: String(w.name || 'Wallet'), kind: w.kind === 'privateKey' ? 'privateKey' : 'mnemonic', secret: String(w.secret), chain: w.chain ? String(w.chain) : undefined, createdAt: Number(w.createdAt || Date.now()), accounts: Math.max(1, Number(w.accounts || 1)), hlAgent: (w.hlAgent && typeof w.hlAgent.key === 'string' && /^0x[0-9a-fA-F]{64}$/.test(w.hlAgent.key) && Array.isArray(w.hlAgent.approved)) ? { key: w.hlAgent.key, approved: w.hlAgent.approved.filter((a: unknown) => typeof a === 'string').map((a: string) => a.toLowerCase()) } : undefined }));
      const activeId = wallets.some(w => w.id === j.activeId) ? String(j.activeId) : wallets[0].id;
      return { payload: { v: 2, wallets, activeId }, migrated: false };
    }
  } catch { /* not JSON — legacy raw secret */ }
  const w: WalletEntry = { id: 'w-legacy', name: 'Main wallet', kind: legacyMeta?.kind || 'mnemonic', secret: plain, chain: legacyMeta?.chain, createdAt: legacyMeta?.createdAt || Date.now(), accounts: 1 };
  return { payload: { v: 2, wallets: [w], activeId: w.id }, migrated: true };
}

// ---- Raw-key AES-GCM wrap (passkey PRF output wraps a copy of the password) ----
export interface KeyWrapBlob { v: 1; iv: string; ct: string; }
export async function wrapWithRawKey(plaintext: string, rawKey: Uint8Array): Promise<KeyWrapBlob> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await crypto.subtle.importKey('raw', rawKey as BufferSource, 'AES-GCM', false, ['encrypt']);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv as BufferSource }, key, new TextEncoder().encode(plaintext)));
  return { v: 1, iv: b64(iv), ct: b64(ct) };
}
export async function unwrapWithRawKey(blob: KeyWrapBlob, rawKey: Uint8Array): Promise<string> {
  const key = await crypto.subtle.importKey('raw', rawKey as BufferSource, 'AES-GCM', false, ['decrypt']);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(blob.iv) as BufferSource }, key, unb64(blob.ct) as BufferSource);
  return new TextDecoder().decode(pt);
}
