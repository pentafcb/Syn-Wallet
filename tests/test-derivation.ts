import assert from 'node:assert';
import { deriveAll, deriveAll2, isValidMnemonic, solanaSecretKeyBase58, btcWifFromPrivateKey, utxoWifFromPrivateKey, suiPrivateKeyBech32, aptosPrivateKeyExport } from '../client/lib/wallet.js';
import { Keypair } from '@solana/web3.js';
import { ethers } from 'ethers';
import { base58, base16, bech32 } from '@scure/base';
import { sha256 } from '@noble/hashes/sha2';
import { ripemd160 } from '@noble/hashes/legacy';
import { keccak_256 } from '@noble/hashes/sha3';
import { secp256k1 } from '@noble/curves/secp256k1';
import * as btc from '@scure/btc-signer';
const MN = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
assert.equal(isValidMnemonic(MN), true);
assert.equal(isValidMnemonic('not a real mnemonic phrase at all not a real mnemonic phrase'), false, 'nonsense must fail');
const d = deriveAll(MN);
console.log('ETH', d.evmAddress); console.log('BTC', d.btcAddress); console.log('SOL', d.solAddress);
assert.equal(d.evmAddress, '0x9858EfFD232B4033E47d90003D41EC34EcaEda94', 'ETH vector');
assert.equal(d.btcAddress, 'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu', 'BTC segwit vector');
// Solana: address must equal @solana/web3.js Keypair.fromSeed(derived seed32)
assert.equal(Keypair.fromSeed(d.solSeed32).publicKey.toBase58(), d.solAddress, 'SOL consistency with web3.js');
// The primary Solana account is m/44'/501'/0'/0' — pinned literally so
// the Phantom addition below can never silently move existing users.
assert.equal(d.solAddress, 'HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk', 'SOL primary path vector (m/44\'/501\'/0\'/0\')');
// Second known ETH vector: same mnemonic via m/44'/60'/0'/0/0 is the standard MetaMask first account

// ---- Addition 9: canonical private-key EXPORT formats round-trip ----
// The key Settings reveals for a chain, re-imported through that chain's
// standard tooling, must reproduce the wallet's address for that chain
// exactly. Polygon is an EVM network: the EVM key IS the Polygon key.
const d2 = deriveAll2(MN);
const reimported = new ethers.Wallet(d2.evmPrivateKey);
assert.equal(reimported.address, d2.evmAddress, 'EVM/Polygon: revealed key re-imports to the wallet address');
assert.equal(d2.evmPrivateKey.startsWith('0x'), true, 'EVM key is 0x hex');
// Solana Phantom format: base58 of the 64-byte secret key.
const solRaw = base58.decode(solanaSecretKeyBase58(d2.solSeed32));
assert.equal(solRaw.length, 64, 'Solana export is 64 bytes');
assert.equal(Keypair.fromSecretKey(solRaw).publicKey.toBase58(), d2.solAddress, 'Solana: revealed key re-imports to the wallet address');
const solTwRaw = base58.decode(solanaSecretKeyBase58(d2.solTWSeed32));
assert.equal(Keypair.fromSecretKey(solTwRaw).publicKey.toBase58(), d2.solTWAddress, 'Solana TW path: revealed key re-imports to the wallet address');
// Solana Phantom path m/44'/501'/0'/0'/0': the expectation was computed
// independently of wallet.ts (a from-spec SLIP-0010 implementation over
// the same standard phrase) and matches the deep audit's live probe
// pair (app HAgk14Jp… vs Phantom B9sVeu4r…).
assert.equal(d2.solPhantomAddress, 'B9sVeu4rJU12oUrUtzjc6BSNuEXdfvurZkdcaTVkP2LY', 'Solana Phantom path vector (m/44\'/501\'/0\'/0\'/0\')');
assert.equal(Keypair.fromSeed(d2.solPhantomSeed32).publicKey.toBase58(), d2.solPhantomAddress, 'Solana Phantom: consistency with web3.js');
assert.notEqual(d2.solPhantomAddress, d2.solAddress, 'Phantom account is a different address from the primary Solana account');
assert.notEqual(d2.solPhantomAddress, d2.solTWAddress, 'Phantom account is a different address from the TW-path account');
const solPhRaw = base58.decode(solanaSecretKeyBase58(d2.solPhantomSeed32));
assert.equal(Keypair.fromSecretKey(solPhRaw).publicKey.toBase58(), d2.solPhantomAddress, 'Solana Phantom path: revealed key re-imports to the wallet address (into Phantom itself)');
// Bitcoin WIF: base58check 0x80 || key || 0x01, checksum valid, key matches.
const wif = btcWifFromPrivateKey(base16.decode(d2.btcPrivateKeyHex));
const wifRaw = base58.decode(wif);
assert.equal(wifRaw[0], 0x80, 'WIF mainnet prefix');
assert.equal(wifRaw[33], 0x01, 'WIF compressed marker');
assert.equal(base16.encode(wifRaw.slice(1, 33)).toLowerCase(), d2.btcPrivateKeyHex.toLowerCase(), 'WIF carries the derived key');
const wifBody = wifRaw.slice(0, wifRaw.length - 4);
assert.deepEqual([...sha256(sha256(wifBody)).slice(0, 4)], [...wifRaw.slice(wifRaw.length - 4)], 'WIF checksum valid');
// Sui: bech32 suiprivkey over 0x00 || seed32.
const suiDec = bech32.decode(suiPrivateKeyBech32(d2.suiSeed32) as any);
assert.equal(suiDec.prefix, 'suiprivkey', 'Sui export prefix');
const suiBytes = bech32.fromWords(suiDec.words);
assert.equal(suiBytes[0], 0, 'Sui ed25519 flag byte');
assert.equal(base16.encode(Uint8Array.from(suiBytes.slice(1))), base16.encode(d2.suiSeed32), 'Sui export carries the derived key');
// Aptos AIP-80: ed25519-priv-0x<hex of seed32>.
assert.equal(aptosPrivateKeyExport(d2.aptosSeed32), 'ed25519-priv-0x' + base16.encode(d2.aptosSeed32).toLowerCase(), 'Aptos AIP-80 format');
// TRON/XRP/Cosmos exports are the derived hex keys themselves — each
// must recompute the wallet's address for that chain from the key alone.
assert.equal(d2.tronPrivateKeyHex.length, 64, 'TRON hex key');
assert.equal(new ethers.Wallet('0x' + d2.tronPrivateKeyHex).address.length, 42, 'TRON key is a valid secp256k1 key');
function b58checkEncode(payload: Uint8Array, alphabet: string): string {
  const checksum = sha256(sha256(payload)).slice(0, 4);
  const full = new Uint8Array(payload.length + 4); full.set(payload); full.set(checksum, payload.length);
  let zeros = 0; while (zeros < full.length && full[zeros] === 0) zeros++;
  let num = 0n; for (const b of full) num = num * 256n + BigInt(b);
  let out = '';
  while (num > 0n) { out = alphabet[Number(num % 58n)] + out; num /= 58n; }
  return alphabet[0].repeat(zeros) + out;
}
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const XRP_A = 'rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz';
// TRON: address = base58check(0x41 || last20(keccak256(uncompressed pub)))
const tronPub = secp256k1.getPublicKey(base16.decode(d2.tronPrivateKeyHex), false);
const tronPayload = new Uint8Array(21); tronPayload[0] = 0x41; tronPayload.set(keccak_256(tronPub.slice(1)).slice(-20), 1);
assert.equal(b58checkEncode(tronPayload, B58), d2.tronAddress, 'TRON: revealed key recomputes the wallet address');
// XRP: address = base58check(0x00 || RIPEMD160(SHA256(compressed pub)), XRP alphabet)
const xrpPub = secp256k1.getPublicKey(base16.decode(d2.xrpPrivateKeyHex), true);
const xrpPayload = new Uint8Array(21); xrpPayload[0] = 0x00; xrpPayload.set(ripemd160(sha256(xrpPub)), 1);
assert.equal(b58checkEncode(xrpPayload, XRP_A), d2.xrpAddress, 'XRP: revealed key recomputes the wallet address');
// Cosmos: address = bech32('cosmos', RIPEMD160(SHA256(compressed pub)))
const cosPub = secp256k1.getPublicKey(base16.decode(d2.cosmosPrivateKeyHex), true);
assert.equal(bech32.encode('cosmos', bech32.toWords(ripemd160(sha256(cosPub)))), d2.cosmosAddress, 'Cosmos: revealed key recomputes the wallet address');
// Litecoin WIF: 0xb0 prefix (WIFs start with 'T'), carries the BIP84 key,
// and that key re-derives the wallet's ltc1q address.
const ltcWif = utxoWifFromPrivateKey(base16.decode(d2.ltcPrivateKeyHex), 0xb0);
assert.equal(ltcWif.startsWith('T'), true, 'LTC WIF prefix shape');
const ltcRaw = base58.decode(ltcWif);
assert.equal(ltcRaw[0], 0xb0, 'LTC WIF version byte');
assert.equal(ltcRaw[33], 0x01, 'LTC WIF compressed marker');
assert.equal(base16.encode(ltcRaw.slice(1, 33)).toLowerCase(), d2.ltcPrivateKeyHex.toLowerCase(), 'LTC WIF carries the derived key');
const ltcBody = ltcRaw.slice(0, ltcRaw.length - 4);
assert.deepEqual([...sha256(sha256(ltcBody)).slice(0, 4)], [...ltcRaw.slice(ltcRaw.length - 4)], 'LTC WIF checksum valid');
const LTC_NET = { bech32: 'ltc', pubKeyHash: 0x30, scriptHash: 0x32, wif: 0xb0 };
assert.equal(btc.p2wpkh(secp256k1.getPublicKey(base16.decode(d2.ltcPrivateKeyHex), true), LTC_NET).address, d2.ltcAddress, 'LTC: revealed key re-derives the wallet address');
console.log('ALL DERIVATION TESTS PASSED');
