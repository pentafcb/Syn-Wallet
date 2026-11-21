import assert from 'node:assert';
import { encryptVault, decryptVault, parseVaultPlaintext, packVaultPayload } from '../client/lib/wallet.js';
const blob = await encryptVault('abandon abandon test phrase', 'correct horse battery');
const pt = await decryptVault(blob, 'correct horse battery');
assert.equal(pt, 'abandon abandon test phrase');
let failed = false; try { await decryptVault(blob, 'wrong password'); } catch { failed = true; }
assert.equal(failed, true, 'wrong password must fail');
const tampered = { ...blob, ct: blob.ct.slice(0, -4) + (blob.ct.slice(-4) === 'AAAA' ? 'BBBB' : 'AAAA') };
let tf = false; try { await decryptVault(tampered as any, 'correct horse battery'); } catch { tf = true; }
assert.equal(tf, true, 'tampered ciphertext must fail (GCM tag)');
console.log('VAULT ROUND-TRIP + TAMPER TESTS PASSED (AES-256-GCM + PBKDF2 600k, 32-byte salt)');

// ---- Vault parser forward-tolerance (boot-hang regression guard) ----
// A vault written by ANY earlier build must parse: fields added by
// later waves are optional and default, never a rejection. The
// pre-Wave-25 shape has no hlAgent anywhere (Wave 25 added it).
const preWave25 = JSON.stringify({
  v: 2,
  wallets: [
    { id: 'w-aaa', name: 'Main wallet', kind: 'mnemonic', secret: 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about', createdAt: 1763000000000, accounts: 2 },
    { id: 'w-bbb', name: 'Ledger watch', kind: 'privateKey', secret: '0x' + '11'.repeat(32), chain: 'ethereum', createdAt: 1763100000000, accounts: 1 },
  ],
  activeId: 'w-bbb',
});
const parsedOld = parseVaultPlaintext(preWave25, null);
assert.equal(parsedOld.migrated, false, 'pre-Wave-25 v2 payload must not be treated as legacy');
assert.equal(parsedOld.payload.wallets.length, 2);
assert.equal(parsedOld.payload.activeId, 'w-bbb');
assert.equal(parsedOld.payload.wallets[0].hlAgent, undefined, 'missing hlAgent defaults to undefined, never a throw');
assert.equal(parsedOld.payload.wallets[0].accounts, 2);
// Round-trip: re-packing the parsed payload parses again identically.
const reparsed = parseVaultPlaintext(packVaultPayload(parsedOld.payload), null);
assert.equal(reparsed.payload.activeId, 'w-bbb');
assert.equal(reparsed.payload.wallets.length, 2);
// A malformed hlAgent (hand-edited / future shape) is dropped, not fatal.
const badAgent = JSON.stringify({ v: 2, wallets: [{ id: 'w-x', name: 'W', kind: 'mnemonic', secret: 'seed words', createdAt: 1, accounts: 1, hlAgent: { key: 'not-a-key', approved: 'nope' } }], activeId: 'w-x' });
const parsedBad = parseVaultPlaintext(badAgent, null);
assert.equal(parsedBad.payload.wallets.length, 1);
assert.equal(parsedBad.payload.wallets[0].hlAgent, undefined, 'malformed hlAgent is dropped, wallet kept');
// A valid hlAgent survives intact.
const goodAgent = { key: '0x' + 'ab'.repeat(32), approved: ['0xABC'] };
const withAgent = JSON.stringify({ v: 2, wallets: [{ id: 'w-y', name: 'W', kind: 'mnemonic', secret: 'seed words', createdAt: 1, accounts: 1, hlAgent: goodAgent }], activeId: 'w-y' });
const parsedGood = parseVaultPlaintext(withAgent, null);
assert.deepEqual(parsedGood.payload.wallets[0].hlAgent, { key: goodAgent.key, approved: ['0xabc'] });
// Legacy v1 plaintext (the raw secret itself) migrates to a v2 payload.
const legacy = parseVaultPlaintext('abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about', { kind: 'mnemonic', createdAt: 1700000000000 });
assert.equal(legacy.migrated, true);
assert.equal(legacy.payload.wallets.length, 1);
assert.equal(legacy.payload.wallets[0].kind, 'mnemonic');
console.log('VAULT PARSER FORWARD-TOLERANCE TESTS PASSED (pre-Wave-25 shape, malformed hlAgent, legacy v1)');
