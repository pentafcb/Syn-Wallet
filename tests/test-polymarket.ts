// Polymarket tests — Addition 4/5 + builder wiring (CLOB V2).
// 1. The L2 HMAC construction must match the official SDK byte for
//    byte (buildHmacSignature: base64-decoded secret, message
//    `${ts}${method}${path}${body}`, base64url output). API auth
//    headers are unchanged in V2, so this still gates order posting.
// 2. Order EIP-712 signing is the V2 struct (domain version "2", V2
//    exchange contracts): it must verify (signature recovery) against
//    both exchange domains, carry the builder code in the signed
//    struct, and tampering — including with the builder field — must
//    fail. V1 fields (taker/nonce/feeRateBps) must be absent.
// 3. The SDK rounding / raw-amount / book-walk helpers ported into
//    client/lib/polymarket.ts keep their reference behaviour.
import assert from 'node:assert';
import { createHmac } from 'node:crypto';
import { ethers } from 'ethers';
import {
  polyHmac, buildSignedOrder, verifyOrderSignature, orderDigest, normalizeBuilderCode,
  roundDown, roundUp, roundNormal, roundConfigFor, limitRawAmounts, marketRawAmounts, walkPrice,
  USDC_E, USDC_NATIVE, CTF_EXCHANGE, NEG_RISK_EXCHANGE,
  CTF_EXCHANGE_V2, NEG_RISK_EXCHANGE_V2, NEG_RISK_ADAPTER, PUSD, COLLATERAL_ONRAMP, ZERO_BYTES32,
} from '../client/lib/polymarket';

// --- 1. HMAC vs the SDK construction ---
const secret = Buffer.from('test-secret-0123456789abcdef', 'utf8').toString('base64');
const ts = 1700000000;
const body = JSON.stringify({ order: { salt: 123 }, owner: 'k' });
const sdkSig = createHmac('sha256', Buffer.from(secret, 'base64'))
  .update(String(ts) + 'POST' + '/order' + body).digest('base64')
  .replace(/\+/g, '-').replace(/\//g, '_');
assert.equal(await polyHmac(secret, ts, 'POST', '/order', body), sdkSig, 'HMAC matches the official builder-signing-sdk construction');
const noBody = await polyHmac(secret, ts, 'GET', '/book?token_id=1');
assert.notEqual(noBody, sdkSig, 'no-body variant produces its own signature');
assert.ok(!/[+/]/.test(noBody), 'signature is base64url (no + or /)');

// --- 2. Order signing (V2 struct + builder code) ---
const BUILDER_CODE = '0xd5983d4936c08c03e38dc18713008e27f73658be912fc074582bab7bc4ebc935'; // the operator's live code
const wallet = new ethers.Wallet('0x' + '11'.repeat(32));
const signed = await buildSignedOrder(wallet, {
  tokenId: '52172892585277497617994913633462512062921895529741863127095472929774251405331',
  side: 'BUY', rawMakerAmt: 25, rawTakerAmt: 50, negRisk: false, builderCode: BUILDER_CODE,
});
assert.equal(signed.maker, wallet.address, 'maker is the wallet');
assert.equal(signed.signer, wallet.address, 'signer is the wallet (signatureType 0)');
assert.equal(signed.makerAmount, '25000000', 'maker amount scaled to 6dp');
assert.equal(signed.takerAmount, '50000000', 'taker amount scaled to 6dp');
assert.equal(signed.builder, BUILDER_CODE, 'built order payload carries the exact builder code');
assert.equal(signed.metadata, ZERO_BYTES32, 'metadata defaults to zero bytes32');
assert.ok(Number(signed.timestamp) > 1700000000000, 'timestamp is milliseconds (V2 uniqueness)');
assert.equal(signed.expiration, '0', 'expiration rides the wire body, unsigned');
for (const gone of ['taker', 'nonce', 'feeRateBps']) assert.ok(!(gone in signed), `V1 field ${gone} is absent from the V2 payload`);
assert.ok(verifyOrderSignature(signed, false), 'signature recovers the signer under the CTF Exchange V2 domain');
assert.match(orderDigest(signed, false), /^0x[0-9a-f]{64}$/, 'order digest is a 32-byte hash');
assert.equal(verifyOrderSignature({ ...signed, takerAmount: '51000000' }, false), false, 'tampered amounts fail verification');
assert.equal(verifyOrderSignature({ ...signed, builder: ZERO_BYTES32 }, false), false, 'stripping the builder code breaks the signature (it is part of the signed order)');
assert.equal(verifyOrderSignature({ ...signed, builder: '0x' + 'ff'.repeat(32) }, false), false, 'swapping in a foreign builder code breaks the signature');
assert.equal(verifyOrderSignature(signed, true), false, 'CTF order does not verify under the neg-risk V2 domain');
const neg = await buildSignedOrder(wallet, { tokenId: '123', side: 'SELL', rawMakerAmt: 10, rawTakerAmt: 4.5, negRisk: true, builderCode: BUILDER_CODE });
assert.ok(verifyOrderSignature(neg, true), 'neg-risk order verifies under the neg-risk V2 domain');
assert.equal(neg.builder, BUILDER_CODE, 'neg-risk order also carries the builder code');
const bare = await buildSignedOrder(wallet, { tokenId: '123', side: 'BUY', rawMakerAmt: 5, rawTakerAmt: 10, negRisk: false });
assert.equal(bare.builder, ZERO_BYTES32, 'no code configured -> zero bytes32 (no attribution)');
assert.ok(verifyOrderSignature(bare, false), 'unattributed order still verifies');
assert.equal(normalizeBuilderCode(BUILDER_CODE.toUpperCase().replace('0X', '0x')), BUILDER_CODE, 'builder code normalises case');
assert.equal(normalizeBuilderCode('0x1234'), ZERO_BYTES32, 'malformed code falls back to zero');
assert.equal(normalizeBuilderCode(undefined), ZERO_BYTES32, 'missing code falls back to zero');

// --- 3. Rounding / amounts / walking (SDK reference behaviour) ---
const cfg = roundConfigFor('0.01');
assert.equal(roundDown(1.23456, cfg.size), 1.23, 'size rounds down to 2dp');
assert.ok(Math.abs(roundUp(1.23111, cfg.amount) - 1.2312) < 1e-9, 'amount rounds up to 4dp');
assert.ok(Math.abs(roundNormal(0.12549, cfg.price) - 0.13) < 1e-9, 'price rounds to tick decimals');
const lb = limitRawAmounts('BUY', 100, 0.3333, cfg);
assert.equal(lb.rawTakerAmt, 100, 'limit BUY: taker = shares');
assert.equal(lb.rawMakerAmt, 33, 'limit BUY: maker = shares x tick-rounded price (100 x 0.33)');
const ls = limitRawAmounts('SELL', 100, 0.3333, cfg);
assert.equal(ls.rawMakerAmt, 100, 'limit SELL: maker = shares');
const mb = marketRawAmounts('BUY', 25, 0.5, cfg);
assert.deepEqual([mb.rawMakerAmt, mb.rawTakerAmt], [25, 50], 'market BUY $25 @ 0.5 = 50 shares');
const ms = marketRawAmounts('SELL', 10, 0.5, cfg);
assert.deepEqual([ms.rawMakerAmt, ms.rawTakerAmt], [10, 5], 'market SELL 10 @ 0.5 = $5');
// Book walking — the SDK consumes asks sorted DESC and bids ASC.
assert.equal(walkPrice([{ price: 0.6, size: 10 }, { price: 0.5, size: 100 }], 'BUY', 30, 'FOK'), 0.5, 'buy walks down the asks to the last level touched');
assert.throws(() => walkPrice([{ price: 0.6, size: 10 }], 'BUY', 100000, 'FOK'), /no match/, 'walking past the book depth throws (no match)');
assert.equal(walkPrice([{ price: 0.4, size: 5 }, { price: 0.5, size: 100 }], 'SELL', 20, 'FOK'), 0.5, 'sell walks up the bids');

// --- Contract constants (Polygon mainnet, from the CLOB docs) ---
assert.equal(USDC_E, '0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174');
assert.equal(USDC_NATIVE, '0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359');
assert.equal(CTF_EXCHANGE, '0x4bFb41d5B3570DeFd03C39a9A4D8dE6Bd8B8982E'); // legacy V1
assert.equal(NEG_RISK_EXCHANGE, '0xC5d563A36AE78145C45a50134d48A1215220f80a'); // legacy V1
// V2 set (docs.polymarket.com/resources/contracts):
assert.equal(CTF_EXCHANGE_V2, '0xE111180000d2663C0091e4f400237545B87B996B');
assert.equal(NEG_RISK_EXCHANGE_V2, '0xe2222d279d744050d28e00520010520000310F59');
assert.equal(NEG_RISK_ADAPTER, '0xd91E80cF2E7be2e162c6513ceD06f1dD0dA35296');
assert.equal(PUSD, '0xC011a7E12a19f7B1f670d46F03B03f3342E82DFB');
assert.equal(COLLATERAL_ONRAMP, '0x93070a847efEf7F70739046A929D47a521F5B8ee');

console.log('test-polymarket: all assertions passed');
