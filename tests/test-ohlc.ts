// OHLC aggregation tests — the price chart's Day/Week/Month/Year periods
// are bucketed from raw candles (30m or 1h for 1d, 4h for 7d/30d, 4d for
// 365d). The merge must keep first-open / max-high / min-low / last-close
// and sum volumes.
import assert from 'node:assert';
import { bucketCandles, buildPeriods, type OhlcCandle } from '../client/lib/ohlc';

const H = 3600 * 1000, D = 24 * H;
const c = (time: number, open: number, high: number, low: number, close: number, volume: number): OhlcCandle => ({ time, open, high, low, close, volume });

// --- daily bucketing of 4h candles ---
const day1 = Date.UTC(2026, 10, 10); // Tue 2026-11-10
const fourHour = [
  c(day1 + 0 * H, 100, 110, 95, 105, 10),
  c(day1 + 4 * H, 105, 120, 100, 115, 20),
  c(day1 + 8 * H, 115, 118, 90, 95, 30),
  c(day1 + D, 95, 99, 80, 85, 5), // next day
];
const days = bucketCandles(fourHour, 'day');
assert.equal(days.length, 2, 'two calendar days');
assert.deepEqual(days[0], { time: day1, open: 100, high: 120, low: 90, close: 95, volume: 60 }, 'day merge: first open, max high, min low, last close, summed volume');
assert.equal(days[1].time, day1 + D, 'second bucket starts next UTC day');

// --- unsorted input is normalised oldest-first ---
const shuffled = bucketCandles([fourHour[2], fourHour[0], fourHour[3], fourHour[1]], 'day');
assert.deepEqual(shuffled, days, 'input order does not matter');

// --- weekly bucketing (ISO weeks start Monday) ---
// 2026-11-08 is a Sunday; it belongs to the week starting Mon 2026-11-02.
const sunday = Date.UTC(2026, 10, 8, 12);
const monday = Date.UTC(2026, 10, 9, 12);
const weeks = bucketCandles([c(sunday, 1, 2, 0.5, 1.5, 3), c(monday, 1.5, 3, 1, 2.5, 4)], 'week');
assert.equal(weeks.length, 2, 'Sunday and Monday fall in different ISO weeks');
assert.equal(weeks[0].time, Date.UTC(2026, 10, 2), 'Sunday buckets to the previous Monday');
assert.equal(weeks[1].time, Date.UTC(2026, 10, 9), 'Monday starts its own week');

// --- monthly bucketing ---
const months = bucketCandles([c(Date.UTC(2026, 0, 31), 1, 1, 1, 1, 1), c(Date.UTC(2026, 1, 1), 2, 2, 2, 2, 2), c(Date.UTC(2026, 1, 15), 3, 3, 3, 3, 3)], 'month');
assert.equal(months.length, 2, 'Jan 31 and Feb candles split by month');
assert.equal(months[1].open, 2, 'February bucket opens with Feb 1 candle');
assert.equal(months[1].close, 3, 'February bucket closes with the last Feb candle');

// --- hourly bucketing (the 1D range): CoinGecko's 30-minute candles
// merge into hours; Binance 1h klines pass through 1:1 ---
const halfHour = [
  c(day1 + 0 * H, 100, 110, 95, 105, 10),
  c(day1 + 0.5 * H, 105, 120, 100, 115, 20),
  c(day1 + 1 * H, 115, 118, 90, 95, 30),
];
const hours = bucketCandles(halfHour, 'hour');
assert.equal(hours.length, 2, 'two 30m candles merge into one hour; the next hour stands alone');
assert.deepEqual(hours[0], { time: day1, open: 100, high: 120, low: 95, close: 115, volume: 30 }, 'hour merge: first open, max high, min low, last close, summed volume');
assert.equal(hours[1].time, day1 + H, 'second bucket starts at the next UTC hour');

// --- buildPeriods: labels/units, empty ranges omitted, never fabricated ---
const periods = buildPeriods(halfHour, fourHour, fourHour, []);
assert.deepEqual(periods.map(p => [p.value, p.label, p.unit]), [['day', 'D', 'hour'], ['week', 'W', 'day'], ['month', 'M', 'week']], 'day=hourly first, week=daily, month=weekly; empty year omitted');
assert.equal(periods[0].candles.length, 2, 'day period carries the merged hourly buckets');
assert.equal(buildPeriods([], [], [], []).length, 0, 'all-empty input yields no periods (unavailable state, not fake candles)');

console.log('test-ohlc: all assertions passed');
