// OHLC aggregation for the ExpoKit PriceChart port. Pure functions (no
// DOM) so the test suite can exercise them directly. Input candles come
// from the server's /api/ohlc proxy (Binance klines, else CoinGecko OHLC
// + volumes in coin units); output is the ChartPeriod shape the chart
// consumes — Day (hourly) / Week (daily) / Month (weekly) / Year
// (monthly) buckets of real candles, oldest first.

export interface OhlcCandle { time: number; open: number; high: number; low: number; close: number; volume: number }
export type AxisUnit = 'hour' | 'day' | 'week' | 'month';
export interface ChartPeriod { value: string; label: string; name: string; unit: AxisUnit; candles: OhlcCandle[] }

const DAY = 24 * 3600 * 1000;

function bucketStart(time: number, unit: AxisUnit): number {
  const d = new Date(time);
  if (unit === 'hour') return Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate(), d.getUTCHours());
  if (unit === 'day') return Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate());
  if (unit === 'month') return Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), 1);
  // ISO week: Monday 00:00 UTC of the candle's week.
  const dayStart = Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate());
  const dow = new Date(dayStart).getUTCDay(); // 0 = Sunday
  return dayStart - ((dow + 6) % 7) * DAY;
}

/** Merge candles into calendar buckets: first open, max high, min low, last close, summed volume. Oldest first. */
export function bucketCandles(candles: OhlcCandle[], unit: AxisUnit): OhlcCandle[] {
  const sorted = [...candles].sort((a, b) => a.time - b.time);
  const out: OhlcCandle[] = [];
  for (const c of sorted) {
    const start = bucketStart(c.time, unit);
    const last = out[out.length - 1];
    if (last && last.time === start) {
      last.high = Math.max(last.high, c.high);
      last.low = Math.min(last.low, c.low);
      last.close = c.close;
      last.volume += c.volume;
    } else {
      out.push({ time: start, open: c.open, high: c.high, low: c.low, close: c.close, volume: c.volume });
    }
  }
  return out;
}

/**
 * Build the chart's Day / Week / Month / Year periods from the four raw
 * ranges. Granularity: the 1d range arrives as 1h klines (Binance) or
 * 30-minute candles (CoinGecko) — bucketing normalises both to 24 hourly
 * buckets; 7d and 30d arrive as 4h candles, 365d as 4-day candles —
 * bucketing normalises them to daily / weekly / monthly.
 * Periods with no candles are omitted rather than padded with fake data.
 */
export function buildPeriods(day: OhlcCandle[], week: OhlcCandle[], month: OhlcCandle[], year: OhlcCandle[]): ChartPeriod[] {
  const periods: ChartPeriod[] = [];
  const d = bucketCandles(day, 'hour');
  if (d.length) periods.push({ value: 'day', label: 'D', name: 'Day', unit: 'hour', candles: d });
  const w = bucketCandles(week, 'day');
  if (w.length) periods.push({ value: 'week', label: 'W', name: 'Week', unit: 'day', candles: w });
  const m = bucketCandles(month, 'week');
  if (m.length) periods.push({ value: 'month', label: 'M', name: 'Month', unit: 'week', candles: m });
  const y = bucketCandles(year, 'month');
  if (y.length) periods.push({ value: 'year', label: 'Y', name: 'Year', unit: 'month', candles: y });
  return periods;
}
