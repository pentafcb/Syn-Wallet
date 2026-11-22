import assert from 'node:assert';
import { twSortedQuery, twPlaintext, twSignature, normalizeCoinStatus, normalizeValidate, normalizeTickers } from '../src/tw.js';
import { twAssetId, twCoinRisk, twAddressVerdict, twEnabled } from '../client/lib/twapi.js';

// ---------- HMAC signing (spec vector, computed independently) ----------
const q = twSortedQuery({ type: 'address', asset_id: 'c60', address: '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045' });
assert.equal(q, 'address=0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045&asset_id=c60&type=address', 'query params sort by key with raw values');
assert.equal(twSortedQuery({}), '');
const pt = twPlaintext('get', '/v1/validate', q, 'TESTACCESSID', '123e4567-e89b-12d3-a456-426614174000', 'Thu, 27 Feb 2026 12:00:00 GMT');
assert.equal(pt, 'GET;/v1/validate;address=0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045&asset_id=c60&type=address;TESTACCESSID;123e4567-e89b-12d3-a456-426614174000;Thu, 27 Feb 2026 12:00:00 GMT');
assert.equal(twSignature('test-hmac-secret', pt), 'pkFhKkDK2WQKhNGjb2eVVr/shCXXoW1q42x7TGkkVew=', 'HMAC-SHA256 signature matches the spec vector');
console.log('TW SIGNING PASSED');

// ---------- coin status normalization ----------
// Live v1 wire shape, captured from the real API (USDC, 2026-11-21).
const usdc = normalizeCoinStatus({ asset: { name: 'USDC', symbol: 'USDC' }, messages: [], security_info: { is_scanned: true, provider: 'Blockaid', contract_security: null, honeypot_risk: { num_risks: 0, num_warnings: 0, items: [], buy_tax: null, sell_tax: null } } })!;
assert.equal(usdc.warnings.length, 0);
assert.ok(usdc.notes.some(n => n.includes('Scanned by Trust Wallet') && n.includes('Blockaid')));
// Flagged v1 fixture: counterfeit + honeypot risk + heavy taxes.
const pot = normalizeCoinStatus({ security_info: { is_scanned: true, provider: 'Blockaid', contract_security: { num_risks: 1, num_warnings: 0, is_counterfeit: true, items: [] }, honeypot_risk: { num_risks: 1, num_warnings: 0, items: [], buy_tax: 15, sell_tax: 15 } } })!;
assert.ok(pot.warnings.some(w => w.includes('counterfeit')));
assert.ok(pot.warnings.some(w => w.includes('honeypot risk')));
assert.ok(pot.warnings.some(w => w.includes('Transfer taxes') && w.includes('15%')), 'heavy taxes are a warning, not a note');
// Item lists are check RESULTS, mostly positive statements (the live
// BONK payload) — never warnings by themselves. Only an item with an
// explicit negative marker surfaces.
const bonkLike = normalizeCoinStatus({ security_info: { is_scanned: true, provider: 'Blockaid', contract_security: { num_risks: 0, num_warnings: 0, items: ['The token cannot be minted.', 'No Freeze Authority found.', 'The token is not considered high risk.'] }, honeypot_risk: null } })!;
assert.equal(bonkLike.warnings.length, 0, 'positive check statements are not warnings');
assert.ok(bonkLike.notes.some(n => n.includes('no contract or honeypot risks found')));
const marked = normalizeCoinStatus({ security_info: { is_scanned: true, provider: 'Blockaid', contract_security: { num_risks: 1, num_warnings: 0, items: [{ level: 'risk', message: 'Sell is restricted for this token' }, 'A plain positive statement'] }, honeypot_risk: null } })!;
assert.ok(marked.warnings.includes('Sell is restricted for this token'));
assert.ok(!marked.warnings.includes('A plain positive statement'));
const unscanned = normalizeCoinStatus({ security_info: { is_scanned: false } })!;
assert.equal(unscanned.warnings.length, 0);
assert.ok(unscanned.notes.some(n => n.includes('Not yet scanned')));
// Documented v2 camelCase shape still parses as a fallback.
const v2shape = normalizeCoinStatus({ securityInfo: { riskLevel: 'low', isHoneypot: false, hasAudit: true, auditProvider: 'OpenZeppelin', hasMintFunction: true, canTakeBackOwnership: false, isTradingCooldown: false, warnings: [] } })!;
assert.ok(v2shape.notes.some(n => n.includes('audited') && n.includes('OpenZeppelin')));
const solActive = normalizeCoinStatus({ solanaSecurityInfo: { riskLevel: 'medium', hasFreezeAuthority: true, hasMintAuthority: true, warnings: ['Token has active freeze authority'] } })!;
assert.ok(solActive.warnings.some(w => w.includes('Freeze authority is active')));
assert.equal(normalizeCoinStatus(null), null);
assert.equal(normalizeCoinStatus({}), null, 'no security sections -> null, not an empty ok');
assert.equal(normalizeCoinStatus('junk'), null);
console.log('TW COIN STATUS PASSED');

// ---------- validate normalization ----------
const wl = normalizeValidate({ valid: true, result: 'whitelist', details: { is_contract: false, is_sanctioned: false, risk_score: 0, labels: [] } })!;
assert.equal(wl.result, 'whitelist'); assert.equal(wl.isSanctioned, false);
const sanc = normalizeValidate({ valid: false, result: 'blacklist', details: { is_sanctioned: true, risk_score: 95, labels: ['sanctioned'] } })!;
assert.equal(sanc.isSanctioned, true); assert.deepEqual(sanc.labels, ['sanctioned']); assert.equal(sanc.riskScore, 95);
// Live sparse shape: a bare {"status":"ok"} is the neutral verdict.
const sparse = normalizeValidate({ status: 'ok' })!;
assert.equal(sparse.result, 'neutral'); assert.equal(sparse.isSanctioned, false);
assert.equal(normalizeValidate({}), null);
assert.equal(normalizeValidate(null), null);
console.log('TW VALIDATE PASSED');

// ---------- tickers normalization ----------
const tk = normalizeTickers({ currency: 'USD', tickers: [
  { id: 'c60', price: 3456.78, change_24h: 2.34, market_cap: 415000000000, volume_24h: 12000000000 },
  { id: 'c501_tSo11111111111111111111111111111111111111112', price: 0, change_24h: 0 },
  { id: 'bad', price: '12' },
  null,
] });
assert.equal(tk['c60'].usd, 3456.78);
assert.equal(tk['c60'].change24h, 2.34);
assert.equal(Object.keys(tk).length, 1, 'zero/invalid prices are dropped, never served as real');
assert.deepEqual(normalizeTickers(null), {});
console.log('TW TICKERS PASSED');

// ---------- client asset ids + disabled no-ops ----------
assert.equal(twAssetId('ethereum', 'native'), 'c60');
assert.equal(twAssetId('ethereum', '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48'), 'c60_t0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48');
assert.equal(twAssetId('solana', 'DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263'), 'c501_tDezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263');
assert.equal(twAssetId('bnb', 'native'), 'c714');
assert.equal(twAssetId('no-such-chain', 'native'), null);
assert.equal(twEnabled(), false, 'TW source starts disabled until /api/config says otherwise');
assert.equal(await twCoinRisk('ethereum', '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48'), null, 'disabled coin risk is a no-op');
assert.equal(await twAddressVerdict('ethereum', '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045'), null, 'disabled validate is a no-op');
console.log('TW CLIENT PASSED');

console.log('ALL TW TESTS PASSED');
