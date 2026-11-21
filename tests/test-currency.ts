// Currency tests: ARS + HNL joined the switcher (2026-11-20). The
// ECB/Frankfurter set does NOT publish either, so the server derives
// them as crosses from CoinGecko's per-BTC table (see src/server.ts
// fxCrossRates) — the client side pinned here: both currencies are
// listed with honest symbols, ARS renders via es-AR with the ISO
// code (never a bare "$" that reads as USD), HNL via es-HN with the
// "L" symbol, and large conversions keep full grouping.
import assert from 'node:assert';
import { CURRENCIES, renderFiat, currencyDecimals } from '../client/lib/currency';

const ars = CURRENCIES.find(c => c.code === 'ARS');
const hnl = CURRENCIES.find(c => c.code === 'HNL');
assert.ok(ars && ars.symbol === 'AR$' && ars.name === 'Argentine Peso', 'ARS entry: AR$ · Argentine Peso');
assert.ok(hnl && hnl.symbol === 'L' && hnl.name === 'Honduran Lempira', 'HNL entry: L · Honduran Lempira');
assert.equal(currencyDecimals('ARS'), 2, 'ARS keeps 2 fraction digits');
assert.equal(currencyDecimals('HNL'), 2, 'HNL keeps 2 fraction digits');

// ARS: es-AR grouping (dots) + explicit code — never a bare $
const a = renderFiat('ARS', 1234567.89);
assert.ok(a.startsWith('ARS'), `ARS renders with its code, got: ${a}`);
assert.ok(a.includes('1.234.567'), `ARS uses es-AR thousands grouping, got: ${a}`);
assert.ok(!a.startsWith('$'), 'ARS never renders as a bare $');
// HNL: es-HN with the L symbol
const h = renderFiat('HNL', 1234567.89);
assert.ok(h.startsWith('L'), `HNL renders with L, got: ${h}`);
assert.ok(h.includes('1,234,567'), `HNL groups en-style, got: ${h}`);
// dust + defaults unchanged for the majors
assert.equal(renderFiat('USD', 0), '$0.00', 'USD zero unchanged');
assert.equal(renderFiat('USD', 0.00009), '$0.00', 'sub-cent rounds to zero at 2dp');
assert.ok(renderFiat('USD', 0.00009, 2, true).startsWith('$0.000'), 'dust flag extends precision instead of a fake zero');
assert.ok(renderFiat('ARS', 0).startsWith('ARS'), 'ARS zero still coded');
// a realistic large conversion (BTC-sized balance in ARS) keeps grouping, no exponent form
const big = renderFiat('ARS', 97941.29 * 1563.9);
assert.ok(!/e\+/i.test(big) && big.includes('.'), `large ARS amount formats plainly, got: ${big}`);

console.log('test-currency: OK');
