// Deep audit 2026-11-22 — regression tests for the deeper-audit fixes
// that live in pure library code. Each block names the finding it
// would have caught.
import assert from 'node:assert';
import { sha256 } from '@noble/hashes/sha2';
import { base16 } from '@scure/base';
import { verifyTronTransferTx, encryptVault, decryptVault } from '../client/lib/wallet.js';
import { verifyLifiEvmTx } from '../client/lib/swap.js';
import { isSafeMediaUrl } from '../client/lib/nfts.js';

// ---------- P1: TRON remotely-built transfer verification ----------
{
  const ownerHex = '41' + '11'.repeat(20);
  const toHex = '41' + '22'.repeat(20);
  const rawData = { contract: [{ type: 'TransferContract', parameter: { value: { owner_address: ownerHex.slice(2), to_address: toHex.slice(2), amount: 1500000 } } }], timestamp: 1 };
  // TronGrid's raw_data addresses carry no 0x41 prefix in the contract
  // value; the verifier compares against the full hex form, so build
  // the fixture the way the caller does (tronToHex output = 41-prefixed).
  const rawData2 = { contract: [{ type: 'TransferContract', parameter: { value: { owner_address: ownerHex, to_address: toHex, amount: 1500000 } } }], timestamp: 1 };
  const rawHex = base16.encode(new TextEncoder().encode(JSON.stringify(rawData2)));
  const tx: any = { txID: base16.encode(sha256(base16.decode(rawHex))), raw_data_hex: rawHex, raw_data: rawData2 };
  void rawData;
  assert.equal(verifyTronTransferTx(tx, ownerHex, toHex, 1500000), true, 'honest TronGrid tx must verify');
  assert.equal(verifyTronTransferTx(tx, ownerHex, toHex, 1500001), false, 'amount substitution must fail');
  assert.equal(verifyTronTransferTx(tx, ownerHex, '41' + '33'.repeat(20), 1500000), false, 'recipient substitution must fail');
  assert.equal(verifyTronTransferTx(tx, '41' + '44'.repeat(20), toHex, 1500000), false, 'owner substitution must fail');
  const tampered: any = { ...tx, txID: base16.encode(sha256(base16.decode(base16.encode(new TextEncoder().encode('other'))))) };
  assert.equal(verifyTronTransferTx(tampered, ownerHex, toHex, 1500000), false, 'txID/raw mismatch must fail');
  const twoContracts: any = { ...tx, raw_data: { contract: [rawData2.contract[0], rawData2.contract[0]] } };
  assert.equal(verifyTronTransferTx(twoContracts, ownerHex, toHex, 1500000), false, 'extra contract must fail');
  assert.equal(verifyTronTransferTx(null, ownerHex, toHex, 1), false, 'null tx must fail');
  assert.equal(verifyTronTransferTx({}, ownerHex, toHex, 1), false, 'empty tx must fail');
}

// ---------- P2: LI.FI payload verifier — target + amount pinning ----------
// Signature: verifyLifiEvmTx(builtTx, expectations) -> null when the
// payload matches the reviewed quote, otherwise a refusal string.
{
  const DIAMOND = '0x1231deb6f5749ef6ce6943a275a1d3e7486f4eae';
  const TOKEN = '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48';
  const RECIP = '0x' + '11'.repeat(20);
  const amountWord = (1500000n).toString(16).padStart(64, '0');
  const word = (a: string) => a.slice(2).padStart(64, '0');
  const data = '0x12345678' + word(TOKEN) + word(RECIP) + amountWord;
  const exp = { fromChainId: 1, fromToken: TOKEN, fromAmountRaw: '1500000', toAddress: RECIP };
  assert.equal(verifyLifiEvmTx({ to: DIAMOND, data, value: '0', chainId: 1 }, exp), null, 'diamond tx with exact amount word must pass');
  assert.match(String(verifyLifiEvmTx({ to: '0x' + '99'.repeat(20), data, value: '0', chainId: 1 }, exp)), /different contract/, 'tx to an unapproved address must be refused');
  const wrongAmtData = '0x12345678' + word(TOKEN) + word(RECIP) + (1500001n).toString(16).padStart(64, '0');
  assert.match(String(verifyLifiEvmTx({ to: DIAMOND, data: wrongAmtData, value: '0', chainId: 1 }, exp)), /input amount/, 'calldata without the exact input amount must be refused');
  assert.match(String(verifyLifiEvmTx({ to: DIAMOND, data, value: '5', chainId: 1 }, exp)), /native value/, 'native value attached to a token swap must be refused');
  // The quote's own approvalAddress (part of the reviewed quote) is
  // the one accepted alternative target — LI.FI's documented model.
  const SPENDER = '0x' + '55'.repeat(20);
  assert.equal(verifyLifiEvmTx({ to: SPENDER, data, value: '0', chainId: 1 }, { ...exp, approvalAddress: SPENDER }), null, 'tx to the reviewed quote approvalAddress must pass');
  assert.match(String(verifyLifiEvmTx({ to: DIAMOND, data, value: '0', chainId: 1 }, { ...exp, approvalAddress: SPENDER })), /different contract/, 'with an approvalAddress set, the diamond alone is not the reviewed target');
}

// ---------- P2: vault blob version gate ----------
{
  const blob: any = await encryptVault('{"kind":"v2","wallets":[]}', 'password-123');
  assert.equal(await decryptVault(blob, 'password-123'), '{"kind":"v2","wallets":[]}', 'v1 blob must still decrypt');
  const future: any = { ...blob, v: 2 };
  await assert.rejects(() => decryptVault(future, 'password-123'), /Unsupported vault version/, 'a newer blob version must be refused, not mis-decrypted');
  const nov: any = { ...blob }; delete nov.v;
  await assert.rejects(() => decryptVault(nov, 'password-123'), /Unsupported vault version/, 'a missing version must be refused');
}

// ---------- P2: NFT media URL filter — private/loopback literals ----------
{
  assert.equal(isSafeMediaUrl('https://example.com/a.png'), true);
  assert.equal(isSafeMediaUrl('http://127.0.0.1/a.png'), false, 'loopback must be refused');
  assert.equal(isSafeMediaUrl('http://localhost/a.png'), false, 'localhost must be refused');
  assert.equal(isSafeMediaUrl('http://192.168.1.5/a.png'), false, 'RFC1918 must be refused');
  assert.equal(isSafeMediaUrl('http://10.0.0.9/a.png'), false, 'RFC1918 10/8 must be refused');
  assert.equal(isSafeMediaUrl('http://172.16.0.1/a.png'), false, 'RFC1918 172.16/12 must be refused');
  assert.equal(isSafeMediaUrl('http://169.254.169.254/latest/meta-data'), false, 'link-local metadata endpoint must be refused');
  assert.equal(isSafeMediaUrl('http://100.64.0.1/a.png'), false, 'CGNAT must be refused');
  assert.equal(isSafeMediaUrl('http://[::1]/a.png'), false, 'IPv6 loopback must be refused');
  assert.equal(isSafeMediaUrl('http://printer.local/a.png'), false, '.local must be refused');
  assert.equal(isSafeMediaUrl('https://8.8.8.8/a.png'), true, 'public IP literal stays allowed');
}

console.log('test-deep-audit: all assertions passed');
