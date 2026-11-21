// UTXO family tests (Bitcoin + Litecoin): derivation vectors,
// address validation, coin selection, and a full fixture build+sign.
//
// The Litecoin vectors below are the standard BIP39 test mnemonic
// ("abandon" x11 + "about") at account 0. They were cross-checked
// on 2026-11-20 against bitcoinjs-lib + bip32 (a fully independent
// implementation), which produced byte-identical addresses for all
// three formats; the same scure code path with Bitcoin params
// reproduces the published BIP84 vector bc1qcr8te4kr609gcawut…,
// anchoring the harness itself.
import assert from 'node:assert';
import { deriveAll2, utxoWifFromPrivateKey, base16 } from '../client/lib/wallet';
import { isValidUtxoAddress, utxoAddressFormat, selectCoins, buildUtxoSend, estimateUtxoFeeSats, type Utxo } from '../client/lib/utxo';

const MN = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const d = deriveAll2(MN, 0);

// --- derivation vectors (independent-implementation cross-check) ---
assert.equal(d.btcAddress, 'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu', 'BTC BIP84 published vector');
assert.equal(d.ltcAddress, 'ltc1qjmxnz78nmc8nq77wuxh25n2es7rzm5c2rkk4wh', 'LTC BIP84 vector (bitcoinjs-lib cross-check)');
assert.equal(d.ltcLegacyAddress, 'LUWPbpM43E2p7ZSh8cyTBEkvpHmr3cB8Ez', 'LTC BIP44 legacy vector');
assert.equal(d.ltcNestedAddress, 'M7wtsL7wSHDBJVMWWhtQfTMSYYkyooAAXM', 'LTC BIP49 nested vector');
assert.equal(utxoWifFromPrivateKey(base16.decode(d.ltcPrivateKeyHex), 0xb0), 'T5ZCYhLqXu6EJKk2nhjvwsaLH357CisixhLGWpKXEiqWTUtzte6o', 'LTC WIF (0xb0) vector');
const d1 = deriveAll2(MN, 1);
assert.notEqual(d1.ltcAddress, d.ltcAddress, 'account 1 derives a different LTC address');
assert.ok(d1.ltcAddress.startsWith('ltc1q'), 'account 1 LTC address is bech32');

// --- validation: formats accepted per chain, cross-chain rejected ---
assert.equal(isValidUtxoAddress('litecoin', d.ltcAddress), true, 'ltc bech32 valid on litecoin');
assert.equal(isValidUtxoAddress('litecoin', d.ltcLegacyAddress), true, 'ltc legacy valid on litecoin');
assert.equal(isValidUtxoAddress('litecoin', d.ltcNestedAddress), true, 'ltc nested valid on litecoin');
assert.equal(isValidUtxoAddress('bitcoin', d.btcAddress), true, 'btc bech32 valid on bitcoin');
assert.equal(isValidUtxoAddress('litecoin', d.btcAddress), false, 'BTC address rejected on Litecoin');
assert.equal(isValidUtxoAddress('bitcoin', d.ltcAddress), false, 'LTC address rejected on Bitcoin');
assert.equal(isValidUtxoAddress('bitcoin', d.ltcLegacyAddress), false, 'LTC legacy rejected on Bitcoin (0x30 != 0x00)');
assert.equal(isValidUtxoAddress('litecoin', 'ltc1qjmxnz78nmc8nq77wuxh25n2es7rzm5c2rkk4wj'), false, 'corrupted bech32 checksum rejected');
assert.equal(isValidUtxoAddress('litecoin', 'LUWPbpM43E2p7ZSh8cyTBEkvpHmr3cB8Ezz'), false, 'corrupted base58 checksum rejected');
assert.equal(isValidUtxoAddress('litecoin', ''), false, 'empty rejected');
assert.equal(isValidUtxoAddress('dogecoin', d.ltcAddress), false, 'unknown chain rejected');
assert.equal(utxoAddressFormat('litecoin', d.ltcAddress), 'bech32');
assert.equal(utxoAddressFormat('litecoin', d.ltcLegacyAddress), 'legacy');
assert.equal(utxoAddressFormat('litecoin', d.ltcNestedAddress), 'p2sh');

// --- coin selection ---
const U = (value: number, confirmed = true): Utxo => ({ txid: 'aa'.repeat(32), vout: 0, value, confirmed });
const sel = selectCoins('litecoin', [U(10_000), U(50_000), U(5_000)], d.ltcLegacyAddress, d.ltcAddress, 20_000, 1);
assert.ok(sel, 'selection succeeds when funded');
assert.equal(sel!.inputs.length, 1, 'largest-first: one 50k input covers 20k + fee');
assert.ok(sel!.changeSats >= 546, 'change above dust is kept');
assert.equal(sel!.inputs[0].value - 20_000 - sel!.feeSats, sel!.changeSats, 'inputs = amount + fee + change');
assert.equal(selectCoins('litecoin', [U(1_000)], d.ltcLegacyAddress, d.ltcAddress, 20_000, 1), null, 'underfunded returns null');
const dust = selectCoins('litecoin', [U(20_400)], d.ltcLegacyAddress, d.ltcAddress, 20_000, 1);
assert.ok(dust && dust.changeSats === 0, 'sub-dust change folds into the fee, no dust output');
assert.ok(estimateUtxoFeeSats('litecoin', 1, '', 1) > 0, 'fee estimate positive');

// --- full fixture build + sign (deterministic) ---
const priv = base16.decode(d.ltcPrivateKeyHex);
import { secp256k1 } from '@noble/curves/secp256k1';
const pub = secp256k1.getPublicKey(priv, true);
const fixture: Utxo[] = [{ txid: '11'.repeat(32), vout: 1, value: 100_000, confirmed: true }];
const built = buildUtxoSend({ chainId: 'litecoin', utxos: fixture, privKey: priv, pubKey: pub, fromAddress: d.ltcAddress, toAddress: d.ltcLegacyAddress, amountSats: 25_000, feeRateSatVb: 1 });
assert.ok(/^[0-9a-f]+$/.test(built.hex) && built.hex.length > 200, 'signed tx hex produced');
assert.ok(/^[0-9a-f]{64}$/.test(built.txid), 'txid shape');
assert.equal(built.changeSats, 100_000 - 25_000 - built.feeSats, 'change arithmetic');
assert.ok(built.feeSats > 0 && built.feeSats < 1_000, 'fee sane at 1 sat/vB');
const built2 = buildUtxoSend({ chainId: 'litecoin', utxos: fixture, privKey: priv, pubKey: pub, fromAddress: d.ltcAddress, toAddress: d.ltcLegacyAddress, amountSats: 25_000, feeRateSatVb: 1 });
assert.equal(built2.hex, built.hex, 'signing is deterministic (RFC 6979) — same fixture, same tx');
assert.throws(() => buildUtxoSend({ chainId: 'litecoin', utxos: fixture, privKey: priv, pubKey: pub, fromAddress: d.ltcAddress, toAddress: d.btcAddress, amountSats: 25_000, feeRateSatVb: 1 }), /valid address/, 'BTC recipient rejected in LTC build');
assert.throws(() => buildUtxoSend({ chainId: 'litecoin', utxos: fixture, privKey: priv, pubKey: pub, fromAddress: d.ltcAddress, toAddress: d.ltcLegacyAddress, amountSats: 200_000, feeRateSatVb: 1 }), /Insufficient/, 'overspend rejected');

console.log('test-utxo: OK');
