import assert from 'node:assert';
import { deriveAll2, encryptVault, decryptVault, packVaultPayload, parseVaultPlaintext, wrapWithRawKey, unwrapWithRawKey, type VaultPayload } from '../client/lib/wallet.js';
import { Keypair } from '@solana/web3.js';
const MN = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const d = deriveAll2(MN, 0);
// Cross-checked 2026-11-18 against reference implementations in a scratch env:
// TRON via tronweb (address.fromPrivateKey), Cosmos via @cosmjs/proto-signing,
// Sui via @mysten/sui Ed25519Keypair.deriveKeypair, Aptos via @aptos-labs/ts-sdk
// Ed25519PrivateKey.fromDerivationPath, XRP via ripple-address-codec encodeAccountID.
console.log('TRON', d.tronAddress); console.log('XRP', d.xrpAddress); console.log('COSMOS', d.cosmosAddress); console.log('SUI', d.suiAddress); console.log('APTOS', d.aptosAddress); console.log('SOL-TW', d.solTWAddress);
assert.equal(d.tronAddress, 'TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH', 'TRON vector');
assert.equal(d.xrpAddress, 'rHsMGQEkVNJmpGWs8XUBoTBiAAbwxZN5v3', 'XRP vector');
assert.equal(d.cosmosAddress, 'cosmos19rl4cm2hmr8afy4kldpxz3fka4jguq0auqdal4', 'Cosmos vector');
assert.equal(d.suiAddress, '0x5e93a736d04fbb25737aa40bee40171ef79f65fae833749e3c089fe7cc2161f1', 'Sui vector');
assert.equal(d.aptosAddress, '0xeb663b681209e7087d681c5d3eed12aaa8e1915e7c87794542c3f96e94b3d3bf', 'Aptos vector');
// Solana Trust Wallet path must differ from the Phantom path and be web3.js-consistent
assert.notEqual(d.solTWAddress, d.solAddress, 'TW and Phantom SOL paths must differ');
assert.equal(Keypair.fromSeed(d.solTWSeed32).publicKey.toBase58(), d.solTWAddress, 'SOL-TW consistency with web3.js');
// Account index changes every family address
const d1 = deriveAll2(MN, 1);
assert.notEqual(d1.evmAddress, d.evmAddress); assert.notEqual(d1.solAddress, d.solAddress); assert.notEqual(d1.tronAddress, d.tronAddress); assert.notEqual(d1.cosmosAddress, d.cosmosAddress);
console.log('WAVE1A DERIVATION VECTORS PASSED (TRON/XRP/Cosmos/Sui/Aptos/SOL-TW + account index)');

// ---- Vault migration: v1 blob (raw secret plaintext) -> v2 payload ----
const PW = 'correct horse battery';
const v1Blob = await encryptVault(MN, PW);
const plain = await decryptVault(v1Blob, PW);
assert.equal(plain, MN, 'v1 decrypt returns raw mnemonic');
const mig = parseVaultPlaintext(plain, { kind: 'mnemonic', createdAt: 1700000000000 });
assert.equal(mig.migrated, true, 'legacy plaintext must be flagged as migration');
assert.equal(mig.payload.wallets.length, 1);
assert.equal(mig.payload.wallets[0].secret, MN);
assert.equal(mig.payload.wallets[0].createdAt, 1700000000000, 'legacy createdAt preserved');
const v2Blob = await encryptVault(packVaultPayload(mig.payload), PW);
const plain2 = await decryptVault(v2Blob, PW);
const back = parseVaultPlaintext(plain2, null);
assert.equal(back.migrated, false);
assert.equal(back.payload.wallets[0].secret, MN, 'migrated vault yields identical secret');
assert.equal(deriveAll2(back.payload.wallets[0].secret, 0).evmAddress, d.evmAddress, 'migrated vault yields identical ETH address');
assert.equal(deriveAll2(back.payload.wallets[0].secret, 0).solAddress, d.solAddress, 'migrated vault yields identical SOL address');
// Multi-wallet payload round-trip
const multi: VaultPayload = { v: 2, wallets: [mig.payload.wallets[0], { id: 'w-test2', name: 'Second', kind: 'privateKey', secret: '0x' + '11'.repeat(32), chain: 'evm', createdAt: 1700000001000, accounts: 1 }], activeId: 'w-test2' };
const mb = await encryptVault(packVaultPayload(multi), PW);
const mback = parseVaultPlaintext(await decryptVault(mb, PW), null);
assert.equal(mback.payload.wallets.length, 2); assert.equal(mback.payload.activeId, 'w-test2');
console.log('VAULT MIGRATION + MULTI-WALLET TESTS PASSED');

// ---- Backup file round-trip (export wrap -> parse -> decrypt -> same payload) ----
const backupFile = JSON.stringify({ app: 'syn-wallet', kind: 'syn-wallet-backup', v: 2, createdAt: Date.now(), vault: v2Blob, config: { enabledChains: ['solana', 'ethereum'] } });
const parsedBackup = JSON.parse(backupFile);
assert.equal(parsedBackup.kind, 'syn-wallet-backup');
const restored = parseVaultPlaintext(await decryptVault(parsedBackup.vault, PW), null);
assert.equal(restored.payload.wallets[0].secret, MN, 'backup restore yields identical secret');
let bw = false; try { await decryptVault(parsedBackup.vault, 'wrong password'); } catch { bw = true; }
assert.equal(bw, true, 'backup with wrong password must fail');
console.log('BACKUP EXPORT/IMPORT ROUND-TRIP PASSED');

// ---- Passkey-style raw-key wrap (PRF output wraps a copy of the password) ----
const fakePrf = new Uint8Array(32).fill(7);
const wrapped = await wrapWithRawKey(PW, fakePrf);
assert.equal(await unwrapWithRawKey(wrapped, fakePrf), PW, 'wrap/unwrap round-trip');
let wf = false; try { await unwrapWithRawKey(wrapped, new Uint8Array(32).fill(9)); } catch { wf = true; }
assert.equal(wf, true, 'unwrap with wrong PRF key must fail');
console.log('PASSKEY KEY-WRAP TESTS PASSED');
console.log('ALL WAVE 1A TESTS PASSED');

// ---- Custom-network chainId validation logic ----
import { parseChainIdResult, validateCustomNetwork } from '../client/lib/netvalidate.js';
assert.equal(parseChainIdResult('0x89'), 137);
assert.equal(parseChainIdResult('0x1'), 1);
assert.equal(parseChainIdResult('137'), null, 'decimal string is not a hex chainId');
assert.equal(parseChainIdResult(null), null);
assert.equal(validateCustomNetwork({ name: 'Mine', rpc: 'https://rpc.example.com', chainId: 137, symbol: 'MATIC', explorer: '' }, 137), null, 'matching chainId passes');
const mismatch = validateCustomNetwork({ name: 'Mine', rpc: 'https://rpc.example.com', chainId: 1, symbol: 'ETH', explorer: '' }, 137);
assert.ok(mismatch && mismatch.includes('mismatch'), 'mismatched chainId is rejected');
assert.ok(validateCustomNetwork({ name: 'Mine', rpc: 'http://rpc.example.com', chainId: 137, symbol: 'MATIC', explorer: '' }, 137), 'http RPC rejected');
assert.ok(validateCustomNetwork({ name: 'Mine', rpc: 'https://rpc.example.com', chainId: 137, symbol: 'MATIC', explorer: '' }, null), 'unreachable RPC rejected');
console.log('CUSTOM-NETWORK CHAINID VALIDATION TESTS PASSED');
