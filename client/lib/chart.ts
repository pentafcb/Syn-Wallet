// Live Ticker Chart — native re-implementation of the UImaxxing pattern.
// Real data only: caller passes CoinGecko [ts, price] points; polling appends real prices.
import { fmtFiat } from './currency';
export interface TickerOpts { height?: number; live?: boolean; }
/** The app-wide fiat formatter — delegates to the currency store
 * (Addition 10): values are USD-sourced and converted for display in
 * the user's selected currency. Name kept for the many call sites. */
export function fmtUsd(n: number, dp = 2): string {
  return fmtFiat(n, dp);
}
/** Decimals for a UNIT PRICE: the usual 2 above $1 and 4 under $1,
 * but enough decimals to keep 3 significant figures for sub-cent
 * prices — PEPE at $0.0000034 must never render as $0.0000 (that
 * reads as "no price" and was half of the user's 2026-11-20
 * "new tokens get no prices" report). */
export function priceDp(n: number): number {
  const a = Math.abs(n);
  if (a === 0 || a >= 1) return 2;
  if (a >= 0.01) return 4;
  return Math.min(10, Math.ceil(-Math.log10(a)) + 2);
}
export function fmtPrice(n: number): string {
  return fmtFiat(n, priceDp(n));
}
export function renderTickerChart(el: HTMLElement, points: [number, number][], opts: TickerOpts = {}): void {
  if (!points.length) { el.innerHTML = '<div class="chartEmpty">No chart data available right now.</div>'; return; }
  const W = 640, H = opts.height ?? 190, GUT = 92, AXIS = 20;
  const plotW = W - GUT, plotH = H - AXIS;
  const prices = points.map(p => p[1]);
  let min = Math.min(...prices), max = Math.max(...prices);
  const pad = (max - min) * 0.12 || max * 0.01 || 1; min -= pad; max += pad;
  const x = (i: number) => (i / Math.max(1, points.length - 1)) * (plotW - 14);
  const y = (v: number) => plotH - ((v - min) / (max - min)) * plotH;
  const d = points.map((p, i) => `${i === 0 ? 'M' : 'L'}${x(i).toFixed(1)},${y(p[1]).toFixed(1)}`).join(' ');
  const area = `${d} L${x(points.length - 1).toFixed(1)},${plotH} L0,${plotH} Z`;
  const grid = [0, 0.25, 0.5, 0.75, 1].map(f => {
    const gy = plotH * f, val = max - (max - min) * f;
    return `<line x1="0" y1="${gy}" x2="${plotW}" y2="${gy}" class="gridLine"/><text x="${plotW + 8}" y="${gy + 3}" class="gutterLabel">${fmtUsd(val, val < 10 ? 3 : 2).replace('$', '$ ')}</text>`;
  }).join('');
  const last = points[points.length - 1];
  const tFmt = (ts: number) => new Date(ts).toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit' });
  const dFmt = (ts: number) => new Date(ts).toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
  const span = last[0] - points[0][0];
  const tick = (f: number) => { const ts = points[0][0] + span * f; return span > 86400000 * 2 ? dFmt(ts) : tFmt(ts); };
  const axis = [0, 0.33, 0.66, 1].map(f => `<text x="${plotW * f}" y="${H - 4}" class="axisLabel" text-anchor="${f === 0 ? 'start' : f === 1 ? 'end' : 'middle'}">${f === 1 ? 'Now' : tick(f)}</text>`).join('');
  el.innerHTML = `<svg viewBox="0 0 ${W} ${H}" class="tickerSvg" role="img" aria-label="Price chart">
    <defs><linearGradient id="tf" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="#c7d0da" stop-opacity="0.22"/><stop offset="100%" stop-color="#c7d0da" stop-opacity="0"/></linearGradient></defs>
    ${grid}<path d="${area}" fill="url(#tf)"/><path d="${d}" class="tickerLine"/>
    <line x1="${x(points.length - 1)}" y1="0" x2="${x(points.length - 1)}" y2="${plotH}" class="nowLine"/>
    <circle cx="${x(points.length - 1)}" cy="${y(last[1])}" r="10" class="nowPulse"/><circle cx="${x(points.length - 1)}" cy="${y(last[1])}" r="4" class="nowDot"/>
    ${axis}</svg>`;
}
