// ExpoKit PriceChart — faithful web port on canvas.
//
// Source design: ExpoKit's PriceChart (expo-charts 2.0.3, MIT), a React
// Native component built on react-native-svg — it cannot run in this
// vanilla-TS web client, so its design and behaviour are re-implemented
// here from the published docs + the package's own PriceChart source:
//
//  - a smooth line + gradient area fill (their fillVariant "gradient"),
//    stroke width 2, NO grid, NO axes, NO dots, NO tooltip bubble;
//  - the whole chart is tinted by trend — green up / red down — and the
//    tint follows the finger: while scrubbing, trend is measured from
//    the range's first value to the point under the finger, so the line
//    itself flips colour as you cross the start (their `tint` logic);
//  - a dashed baseline at the FIRST value of the range (their
//    showBaseline reference line, "previous close");
//  - scrubbing drives a headline: the host paints the scrubbed value
//    big, the change in ExpoKit's own format ("+$1,240.50 (+12.34%)"),
//    and the point's label ("Oct 21, 3:30 PM" in theirs; our 1D buckets
//    are hours, so labels are times of day, and the longer ranges'
//    buckets are day/week/month, so their labels are dates) — on release everything
//    returns to the latest value (their onScrub(point|null) contract);
//  - range tabs BELOW the chart as a segmented track with a sliding
//    pill highlight (260ms), selected tab bright/600, rest muted/500;
//  - entrance is a left-to-right wipe (their animationType), ~420ms.
//
// Data: the SAME real OHLC buckets the candle chart used (lib/ohlc.ts,
// from /api/ohlc). The ExpoKit design is a line chart, so each bucket
// contributes its CLOSE — no series is invented; a bucket's open/high/
// low simply aren't drawn by a line design. Periods are Day / Week /
// Month / Year, labelled 1D / 1W / 1M / 1Y like ExpoKit's tabs; the 1D
// range plots 24 hourly closes and its scrub labels are times of day.
// (ExpoKit's ALL key is deliberately NOT offered: our sources cannot
// honestly serve all-time history for every asset.)
// Approximations vs the RN original: data refreshes redraw the line in
// place instead of morphing the path (and NEVER re-run the wipe or
// disturb an active scrub — the wipe belongs to first paint and range
// changes only); there are no haptics on web/iOS; the scrub "when"
// label rides in the host's headline instead of sitting beside the
// change text.
//
// Touch contract (the ExpoKit onScrubStart-pauses-ScrollView behaviour,
// translated to the web): the canvas is `touch-action: pan-y`, so a
// vertical-dominant drag is the browser's page scroll and a horizontal-
// dominant drag is the chart's scrub — decided by a gesture classifier
// BEFORE anything is painted. A touch only becomes a scrub once it has
// moved >10px horizontally-dominant; until then nothing is captured and
// the headline is untouched, so a scroll that starts on the chart never
// flickers the scrub state. Mouse input scrubs immediately (hover or
// drag), as before — there is no scroll gesture to fight on desktop.
import type { ChartPeriod } from './ohlc';
import { prefersReducedMotion } from './fx';

export interface ScrubInfo { value: number; label: string; change: number; pct: number; up: boolean }
export interface PriceChartOpts {
  periods: ChartPeriod[];
  selected?: string;
  onPeriodChange?: (value: string) => void;
  onScrub?: (info: ScrubInfo | null) => void;
}
export interface PriceChartHandle {
  update(periods: ChartPeriod[]): void;
  destroy(): void;
}

const UP = '#34d399';
const escHtml = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
const DOWN = '#f87171';
const BASELINE = 'rgba(139,149,165,.5)';
const GUIDE = 'rgba(199,208,218,.4)';
const PAD_X = 4;
const WIPE_MS = 420;

interface Pt { value: number; label: string }
function pointsOf(p: ChartPeriod): Pt[] {
  const lf = (t: number): string => {
    const d = new Date(t);
    // 1D buckets are hours of the current day — the label is the point's
    // local time of day ("14:00"), like ExpoKit's intraday labels.
    if (p.unit === 'hour') return d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' });
    if (p.unit === 'month') return d.toLocaleDateString('en-US', { month: 'short', year: 'numeric', timeZone: 'UTC' });
    if (p.unit === 'week') return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric', timeZone: 'UTC' });
    return d.toLocaleDateString('en-US', { weekday: 'short', month: 'short', day: 'numeric', timeZone: 'UTC' });
  };
  return p.candles.map(c => ({ value: c.close, label: lf(c.time) }));
}
const TAB_LABEL: Record<string, string> = { day: '1D', week: '1W', month: '1M', year: '1Y' };

export function mountPriceChart(host: HTMLElement, opts: PriceChartOpts): PriceChartHandle {
  const reduced = prefersReducedMotion();
  let periods = opts.periods;
  let sel = opts.selected || periods[0]?.value || 'week';
  let points: Pt[] = [];
  let scrub = -1;
  let destroyed = false;
  let reveal = reduced ? 1 : 0;
  let revealStart = 0;
  let raf = 0;

  host.innerHTML = `<div class="pchart">
    <div class="pchartStage"><canvas class="pchartCanvas"></canvas></div>
    ${periods.length > 1 ? `<div class="pchartTabs" role="tablist"><span class="pchartPill"></span>${periods.map(p => `<button class="pchartTab ${p.value === sel ? 'on' : ''}" data-p="${escHtml(p.value)}" role="tab" aria-selected="${p.value === sel}">${escHtml(TAB_LABEL[p.value] || p.label)}</button>`).join('')}</div>` : ''}
  </div>`;
  const canvas = host.querySelector('.pchartCanvas') as HTMLCanvasElement;
  const tabsEl = host.querySelector('.pchartTabs') as HTMLElement | null;
  let pill = host.querySelector('.pchartPill') as HTMLElement | null;
  const tabBtns: HTMLElement[] = [...host.querySelectorAll('.pchartTab')];
  const ctx = canvas.getContext('2d')!;

  const period = (): ChartPeriod | undefined => periods.find(p => p.value === sel) || periods[0];
  function rebuild() { const p = period(); points = p ? pointsOf(p) : []; }
  rebuild();

  const first = (): number => (points.length ? points[0].value : 0);
  const activeValue = (): number => (scrub >= 0 && scrub < points.length ? points[scrub].value : points.length ? points[points.length - 1].value : 0);
  const tint = (): string => ((activeValue() - first()) >= 0 ? UP : DOWN);

  function layoutPill() {
    if (!tabsEl || !pill) return;
    const n = periods.length; if (!n) return;
    const w = (tabsEl.clientWidth - 6) / n;
    const i = Math.max(0, periods.findIndex(p => p.value === sel));
    pill.style.width = w + 'px';
    pill.style.transform = `translateX(${i * w}px)`;
  }

  function draw() {
    if (destroyed) return;
    const W = canvas.clientWidth; const H = canvas.clientHeight;
    if (!W || !H || !points.length) return;
    const dpr = Math.min(window.devicePixelRatio || 1, 3);
    if (canvas.width !== Math.round(W * dpr) || canvas.height !== Math.round(H * dpr)) {
      canvas.width = Math.round(W * dpr); canvas.height = Math.round(H * dpr);
    }
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, W, H);

    let lo = Infinity, hi = -Infinity;
    for (const p of points) { if (p.value < lo) lo = p.value; if (p.value > hi) hi = p.value; }
    if (!(hi > lo)) { const m = Math.max(1, Math.abs(hi) * 0.01); hi += m; lo -= m; }
    const pad = (hi - lo) * 0.1; hi += pad; lo -= pad;
    const iw = W - PAD_X * 2;
    const x = (i: number) => PAD_X + (i / (points.length - 1)) * iw;
    const y = (v: number) => 8 + (hi - v) / (hi - lo) * (H - 16);
    const col = tint();

    // smooth path through the points (Catmull-Rom → Bézier, in px space)
    const path = () => {
      ctx.beginPath();
      ctx.moveTo(x(0), y(points[0].value));
      for (let i = 0; i < points.length - 1; i++) {
        const i0 = Math.max(0, i - 1), i3 = Math.min(points.length - 1, i + 2);
        const cp1x = x(i) + (x(i + 1) - x(i0)) / 6;
        const cp1y = y(points[i].value) + (y(points[i + 1].value) - y(points[i0].value)) / 6;
        const cp2x = x(i + 1) - (x(i3) - x(i)) / 6;
        const cp2y = y(points[i + 1].value) - (y(points[i3].value) - y(points[i].value)) / 6;
        ctx.bezierCurveTo(cp1x, cp1y, cp2x, cp2y, x(i + 1), y(points[i + 1].value));
      }
    };

    ctx.save();
    if (reveal < 1) { ctx.beginPath(); ctx.rect(0, 0, W * reveal, H); ctx.clip(); }
    if (points.length === 1) {
      // A lone bucket: dashed baseline + one dot at centre — the chart
      // must never sit blank just because a range has a single point.
      const cy = y(points[0].value);
      ctx.strokeStyle = BASELINE; ctx.lineWidth = 1; ctx.setLineDash([4, 4]);
      ctx.beginPath(); ctx.moveTo(0, cy); ctx.lineTo(W, cy); ctx.stroke();
      ctx.setLineDash([]);
      ctx.fillStyle = col;
      ctx.beginPath(); ctx.arc(W / 2, cy, 4.5, 0, Math.PI * 2); ctx.fill();
      ctx.restore();
      return;
    }
    // gradient area fill under the line
    path();
    ctx.save();
    ctx.lineTo(x(points.length - 1), H); ctx.lineTo(x(0), H); ctx.closePath();
    const g = ctx.createLinearGradient(0, 0, 0, H);
    g.addColorStop(0, col + '42'); g.addColorStop(1, col + '00');
    ctx.fillStyle = g; ctx.fill();
    ctx.restore();
    // the line itself
    path();
    ctx.strokeStyle = col; ctx.lineWidth = 2; ctx.lineJoin = 'round'; ctx.lineCap = 'round';
    ctx.stroke();
    // dashed baseline at the range's first value (ExpoKit showBaseline)
    ctx.strokeStyle = BASELINE; ctx.lineWidth = 1; ctx.setLineDash([4, 4]);
    ctx.beginPath(); ctx.moveTo(0, y(first())); ctx.lineTo(W, y(first())); ctx.stroke();
    ctx.setLineDash([]);
    ctx.restore();

    // scrub indicator: guide line + ringed dot on the point
    if (scrub >= 0 && scrub < points.length) {
      const cx = x(scrub); const cy = y(points[scrub].value);
      ctx.strokeStyle = GUIDE; ctx.lineWidth = 1;
      ctx.beginPath(); ctx.moveTo(cx, 4); ctx.lineTo(cx, H - 4); ctx.stroke();
      ctx.fillStyle = col + '2e';
      ctx.beginPath(); ctx.arc(cx, cy, 9, 0, Math.PI * 2); ctx.fill();
      ctx.fillStyle = col;
      ctx.beginPath(); ctx.arc(cx, cy, 4.5, 0, Math.PI * 2); ctx.fill();
      ctx.strokeStyle = '#12151c'; ctx.lineWidth = 2;
      ctx.beginPath(); ctx.arc(cx, cy, 4.5, 0, Math.PI * 2); ctx.stroke();
    }
  }

  function startReveal() {
    if (reduced) { reveal = 1; draw(); return; }
    reveal = 0; revealStart = performance.now();
    cancelAnimationFrame(raf);
    const tick = (now: number) => {
      if (destroyed) return;
      const t = Math.min(1, (now - revealStart) / WIPE_MS);
      reveal = 1 - Math.pow(1 - t, 3); // easeOutCubic
      draw();
      if (t < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
  }

  function scrubInfo(i: number): ScrubInfo {
    const v = points[i].value; const f = first();
    const change = v - f;
    const pct = f ? (change / Math.abs(f)) * 100 : 0;
    return { value: v, label: points[i].label, change, pct, up: change >= 0 };
  }
  function endScrub() {
    if (scrub < 0) return;
    scrub = -1; draw();
    opts.onScrub?.(null);
  }
  function scrubTo(e: PointerEvent) {
    if (points.length < 2) return;
    const r = canvas.getBoundingClientRect();
    const px = e.clientX - r.left - PAD_X;
    const idx = Math.max(0, Math.min(points.length - 1, Math.round((px / (r.width - PAD_X * 2)) * (points.length - 1))));
    if (idx !== scrub) { scrub = idx; draw(); opts.onScrub?.(scrubInfo(idx)); }
  }
  // Gesture classifier for touch/pen (see the header comment): a touch
  // starts 'pending'; horizontal-dominant movement past the slop turns
  // it into a scrub (capture + paint), vertical-dominant movement hands
  // it to the page scroll ('scroll' — the browser's pan-y takes over
  // and pointercancel follows). Nothing is painted while pending, so a
  // scroll that starts on the chart never touches the headline.
  const SLOP = 10;
  let gState: 'idle' | 'pending' | 'scrub' | 'scroll' = 'idle';
  let gId = -1; let gX = 0; let gY = 0;
  function capture(id: number) { try { canvas.setPointerCapture?.(id); } catch { /* inactive/synthetic pointer */ } }
  function onDown(e: PointerEvent) {
    if (e.pointerType === 'mouse') { capture(e.pointerId); scrubTo(e); return; }
    if (gState !== 'idle') return;
    gState = 'pending'; gId = e.pointerId; gX = e.clientX; gY = e.clientY;
  }
  function onMove(e: PointerEvent) {
    if (e.pointerType === 'mouse') { scrubTo(e); return; }
    if (e.pointerId !== gId) return;
    if (gState === 'pending') {
      const dx = e.clientX - gX; const dy = e.clientY - gY;
      if (Math.abs(dy) >= SLOP && Math.abs(dy) >= Math.abs(dx)) { gState = 'scroll'; return; }
      if (Math.abs(dx) >= SLOP && Math.abs(dx) > Math.abs(dy)) { gState = 'scrub'; capture(e.pointerId); scrubTo(e); }
      return;
    }
    if (gState === 'scrub') scrubTo(e);
  }
  function onUp(e: PointerEvent) {
    if (e.pointerType === 'mouse') { endScrub(); return; }
    if (e.pointerId !== gId) return;
    if (gState === 'scrub') endScrub();
    gState = 'idle'; gId = -1;
  }
  function onLeave(e: PointerEvent) { if (e.pointerType === 'mouse') endScrub(); }
  canvas.addEventListener('pointerdown', onDown);
  canvas.addEventListener('pointermove', onMove);
  canvas.addEventListener('pointerup', onUp);
  canvas.addEventListener('pointercancel', onUp);
  canvas.addEventListener('pointerleave', onLeave);

  function bindTabs() {
    for (const b of tabBtns) {
      b.onclick = () => {
        const v = b.dataset.p!; if (v === sel) return;
        sel = v; endScrub();
        tabBtns.forEach(x => { const on = x === b; x.classList.toggle('on', on); x.setAttribute('aria-selected', String(on)); });
        rebuild(); layoutPill(); startReveal();
        opts.onPeriodChange?.(v);
      };
    }
  }
  bindTabs();

  const ro = new ResizeObserver(() => { layoutPill(); draw(); });
  ro.observe(canvas);
  if (tabsEl) ro.observe(tabsEl);
  layoutPill();
  startReveal();

  return {
    update(next: ChartPeriod[]) {
      if (destroyed || !next.length) return;
      // Background refresh contract: redraw in place, silently. The
      // entrance wipe belongs to first paint and range changes ONLY —
      // re-running it on every poll made the chart visibly restart
      // under the user. An active scrub is preserved across the
      // refresh (index clamped to the new series) and its headline is
      // re-emitted from the refreshed points, so the finger and the
      // figure never fight.
      const wasScrubbing = scrub >= 0;
      periods = next;
      if (!periods.some(p => p.value === sel)) {
        sel = periods[0].value;
        opts.onPeriodChange?.(sel); // keep the host's caption in sync with the fallback
      }
      if (tabsEl && periods.length > 1 && tabBtns.length !== periods.length) {
        // the period set changed (a range that was missing arrived)
        tabsEl.innerHTML = `<span class="pchartPill"></span>${periods.map(p => `<button class="pchartTab ${p.value === sel ? 'on' : ''}" data-p="${escHtml(p.value)}" role="tab" aria-selected="${p.value === sel}">${escHtml(TAB_LABEL[p.value] || p.label)}</button>`).join('')}`;
        pill = tabsEl.querySelector('.pchartPill') as HTMLElement | null;
        tabBtns.length = 0;
        tabBtns.push(...tabsEl.querySelectorAll('.pchartTab'));
        bindTabs();
      } else {
        tabBtns.forEach(x => { const on = x.dataset.p === sel; x.classList.toggle('on', on); x.setAttribute('aria-selected', String(on)); });
      }
      rebuild(); layoutPill();
      if (wasScrubbing) {
        if (points.length >= 2) {
          scrub = Math.min(scrub, points.length - 1);
          opts.onScrub?.(scrubInfo(scrub));
        } else { scrub = -1; opts.onScrub?.(null); }
      }
      reveal = 1;
      cancelAnimationFrame(raf);
      draw();
    },
    destroy() {
      destroyed = true;
      cancelAnimationFrame(raf);
      ro.disconnect();
      canvas.removeEventListener('pointerdown', onDown);
      canvas.removeEventListener('pointermove', onMove);
      canvas.removeEventListener('pointerup', onUp);
      canvas.removeEventListener('pointercancel', onUp);
      canvas.removeEventListener('pointerleave', onLeave);
    },
  };
}

export type { ChartPeriod };
