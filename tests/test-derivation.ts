import assert from 'node:assert';
import { deriveAll, deriveAll2, isValidMnemonic, solanaSecretKeyBase58, btcWifFromPrivateKey, suiPrivateKeyBech32, aptosPrivateKeyExport } from '../client/lib/wallet.js';
import { Keypair } from '@solana/web3.js';
import { ethers } from 'ethers';
import { base58, base16, bech32 } from '@scure/base';
import { sha256 } from '@noble/hashes/sha2';
const MN = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
assert.equal(isValidMnemonic(MN), true);
assert.equal(isValidMnemonic('not a real mnemonic phrase at all not a real mnemonic phrase'), false, 'nonsense must fail');
const d = deriveAll(MN);
console.log('ETH', d.evmAddress); console.log('BTC', d.btcAddress); console.log('SOL', d.solAddress);
assert.equal(d.evmAddress, '0x9858EfFD232B4033E47d90003D41EC34EcaEda94', 'ETH vector');
assert.equal(d.btcAddress, 'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu', 'BTC segwit vector');
// Solana: address must equal @solana/web3.js Keypair.fromSeed(derived seed32)
assert.equal(Keypair.fromSeed(d.solSeed32).publicKey.toBase58(), d.solAddress, 'SOL consistency with web3.js');
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
// TRON/XRP/Cosmos exports are the derived hex keys themselves.
assert.equal(d2.tronPrivateKeyHex.length, 64, 'TRON hex key');
assert.equal(new ethers.Wallet('0x' + d2.tronPrivateKeyHex).address.length, 42, 'TRON key is a valid secp256k1 key');
console.log('ALL DERIVATION TESTS PASSED');
