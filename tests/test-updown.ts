import assert from 'node:assert';
import { upDownWindowStart, upDownSlug, parseUpDownSlug, UPDOWN_ASSETS, UPDOWN_TFS } from '../client/lib/polymarket.js';

// Window math against REAL live slugs (verified on Gamma 2026-11-21:
// btc-updown-5m-1766162100 was the live 11:35-11:40AM ET window).
assert.equal(upDownWindowStart(300, 1766162100000), 1766162100);
assert.equal(upDownSlug('btc', 300, 1766162100000), 'btc-updown-5m-1766162100');
assert.equal(upDownSlug('btc', 300, 1766162222000), 'btc-updown-5m-1766162100', 'mid-window maps to the same window');
assert.equal(upDownSlug('eth', 900, 1766162100000), 'eth-updown-15m-1766161800');
assert.equal(upDownSlug('btc', 3600, 1766162100000), 'btc-updown-1h-1766160000');
assert.equal(upDownSlug('sol', 300, 1766162399000), 'sol-updown-5m-1766162100', 'last second of the window still maps to it');
assert.equal(upDownSlug('sol', 300, 1766162400000), 'sol-updown-5m-1766162400', 'the boundary opens the next window');
console.log('UPDOWN SLUGS PASSED');

assert.deepEqual(parseUpDownSlug('btc-updown-5m-1766162100'), { asset: 'btc', tfSecs: 300 });
assert.deepEqual(parseUpDownSlug('xrp-updown-15m-1766161800'), { asset: 'xrp', tfSecs: 900 });
assert.deepEqual(parseUpDownSlug('hype-updown-1h-1766160000'), { asset: 'hype', tfSecs: 3600 });
assert.equal(parseUpDownSlug('will-bitcoin-reach-100k'), null);
assert.equal(parseUpDownSlug('btc-updown-4h-1766160000'), null, 'timeframes outside the supported set do not claim rollover');
assert.equal(parseUpDownSlug(''), null);
assert.equal(parseUpDownSlug('btc-updown-5m'), null);
for (const a of UPDOWN_ASSETS) for (const t of UPDOWN_TFS) {
  const s = upDownSlug(a.slug, t.secs, 1766162100000);
  assert.deepEqual(parseUpDownSlug(s), { asset: a.slug, tfSecs: t.secs }, 'roundtrip ' + s);
}
console.log('UPDOWN PARSE PASSED');
console.log('ALL UPDOWN TESTS PASSED');
