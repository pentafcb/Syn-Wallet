// Animated wave art for the Home total-balance card — the owner's ask:
// "on main balance card do like a background wave animated".
//
// Wave 3 shipped this at 34–58s periods and alpha <= 0.13: defensible on
// paper, but on the owner's real iPhone it read as a static gradient —
// he reported "wave not moving". Wave 4 made the motion unmistakable
// (5.2–11s periods), but at fill alpha 0.19 with ~1-period wavelengths
// the layers read on his phone as HEAVY GREY SLABS — one big dune of
// muddy fill across the bottom 40% of the card. This pass (Wave 6) is
// purely how it DRAWS; the loop, clock, toggle and lifecycle are
// unchanged:
//  - fills DOWN: front 0.10 / mid 0.07 / back 0.045 (were .19/.11/.06);
//  - definition UP: a soft 1.5px chrome stroke (alpha .26–.34) along
//    each layer's top edge, so the curves read as wave LINES;
//  - more wave, less hill: 1.6–2.0 full sine periods across the width
//    per layer (were ~0.7–1.25), amplitudes cut to 5–7px;
//  - lower band: waterlines sit at 50/64/77% of the canvas, and the
//    canvas is the card's bottom 58% — so the whole system occupies
//    roughly the bottom 30% of the card and the balance figures always
//    sit over flat card;
//  - clean edges: the path samples the curve's exact value at x=w
//    before closing, so no diagonal cut where a band meets the right
//    edge (the old step-loop ended mid-sample and slashed to (w,h)).
// Worst-case composite is now far lighter than Wave 4's ~#51565e, so
// figure legibility only improves.
//
// Cheap by construction: ONE small canvas behind the card's text, three
// sine fills, no WebGL, no DOM snapshots. The phase is computed from
// the requestAnimationFrame timestamp — a monotonic clock — never from
// accumulated frame deltas, so a stalled or throttled frame cannot
// desync or freeze the phase.
//
// Lifecycle discipline:
//  - the loop runs continuously while Home is mounted and the document
//    is visible; IntersectionObserver is kept ONLY as an optimisation
//    (pause when the card is fully scrolled away) and the default
//    assumption is "visible" — starting never depends on it;
//  - pauses on document.hidden, resumes on visibilitychange;
//  - self-terminates (and drops its listeners) when the canvas leaves
//    the DOM on a view swap;
//  - reduced motion is NOT a frozen frame: an ultra-slow, extra-faint
//    drift (~40s periods, alphas halved) — motion reduced, not dead;
//  - the caller's isEnabled() (Settings → Wave effects) is checked
//    every frame: turning it off clears the canvas and stops the loop,
//    so the card goes flat immediately. OFF stays fully flat, in both
//    motion modes.
import { prefersReducedMotion } from './fx';

interface Layer { amp: number; periods: number; phaseOff: number; base: number; periodMs: number; dir: 1 | -1; fill: string; stroke: string }
// periods = full sine cycles across the canvas width; base = resting
// height of the layer's waterline as a fraction of the canvas height
// (the canvas spans the card's lower ~58%, so base .50/.64/.77 puts
// the band system in roughly the card's bottom 30%).
const LAYERS: Layer[] = [
  { amp: 5, periods: 1.6, phaseOff: 0.0, base: 0.50, periodMs: 11000, dir: 1, fill: 'rgba(147,169,192,0.045)', stroke: 'rgba(147,169,192,0.26)' },
  { amp: 7, periods: 1.8, phaseOff: 2.1, base: 0.64, periodMs: 7200, dir: -1, fill: 'rgba(199,208,218,0.07)', stroke: 'rgba(199,208,218,0.30)' },
  { amp: 6, periods: 2.0, phaseOff: 4.2, base: 0.77, periodMs: 5200, dir: 1, fill: 'rgba(238,242,247,0.10)', stroke: 'rgba(238,242,247,0.34)' },
];
// Reduced motion: same geometry, ~40s periods and alphas halved — a
// drift you have to watch for, not a freeze-frame.
const LAYERS_REDUCED: Layer[] = [
  { amp: 5, periods: 1.6, phaseOff: 0.0, base: 0.50, periodMs: 46000, dir: 1, fill: 'rgba(147,169,192,0.022)', stroke: 'rgba(147,169,192,0.14)' },
  { amp: 7, periods: 1.8, phaseOff: 2.1, base: 0.64, periodMs: 40000, dir: -1, fill: 'rgba(199,208,218,0.035)', stroke: 'rgba(199,208,218,0.16)' },
  { amp: 6, periods: 2.0, phaseOff: 4.2, base: 0.77, periodMs: 43000, dir: 1, fill: 'rgba(238,242,247,0.05)', stroke: 'rgba(238,242,247,0.18)' },
];

export function startHeroWave(canvas: HTMLCanvasElement, isEnabled: () => boolean): void {
  const ctx = canvas.getContext('2d');
  if (!ctx) return;
  const layers = prefersReducedMotion() ? LAYERS_REDUCED : LAYERS;
  let raf = 0;
  let running = false;
  let inView = true; // assume visible; the observer may only ever pause us

  function sizeCanvas() {
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    const w = canvas.clientWidth; const h = canvas.clientHeight;
    if (!w || !h) return false;
    const W = Math.round(w * dpr); const H = Math.round(h * dpr);
    if (canvas.width !== W || canvas.height !== H) { canvas.width = W; canvas.height = H; }
    ctx!.setTransform(dpr, 0, 0, dpr, 0, 0);
    return true;
  }

  function frame(now: number) {
    const w = canvas.clientWidth; const h = canvas.clientHeight;
    ctx!.clearRect(0, 0, w, h);
    for (const L of layers) {
      // Phase from the rAF timestamp (monotonic) — never accumulated.
      const phase = L.phaseOff + L.dir * (now / L.periodMs) * Math.PI * 2;
      const k = (Math.PI * 2 * L.periods) / w; // radians per px
      const yBase = h * L.base;
      // One curve function per layer per frame; the harmonic keeps the
      // line organic without forming a second dune. Both the fill and
      // the edge stroke use these exact samples — including x=0 and
      // x=w — so the band meets both side edges ON the curve, never
      // via a diagonal cut to the corner.
      const yAt = (x: number) => yBase + Math.sin(x * k + phase) * L.amp
        + Math.sin(x * k * 2.63 + phase * 1.7) * L.amp * 0.28;
      ctx!.beginPath();
      ctx!.moveTo(0, h);
      ctx!.lineTo(0, yAt(0));
      for (let x = 6; x < w; x += 6) ctx!.lineTo(x, yAt(x));
      ctx!.lineTo(w, yAt(w));
      ctx!.lineTo(w, h);
      ctx!.closePath();
      ctx!.fillStyle = L.fill;
      ctx!.fill();
      ctx!.beginPath();
      ctx!.moveTo(0, yAt(0));
      for (let x = 6; x < w; x += 6) ctx!.lineTo(x, yAt(x));
      ctx!.lineTo(w, yAt(w));
      ctx!.strokeStyle = L.stroke;
      ctx!.lineWidth = 1.5;
      ctx!.stroke();
    }
  }

  function cleanup() {
    io.disconnect();
    mo.disconnect();
    document.removeEventListener('visibilitychange', onVis);
  }
  function stop() { running = false; cancelAnimationFrame(raf); }
  function start() {
    if (running || !canvas.isConnected || document.hidden || !inView) return;
    running = true;
    raf = requestAnimationFrame(loop);
  }
  function loop(now: number) {
    if (!canvas.isConnected) { stop(); cleanup(); return; }
    if (!isEnabled()) { ctx!.clearRect(0, 0, canvas.clientWidth, canvas.clientHeight); stop(); return; }
    if (sizeCanvas()) frame(now);
    raf = requestAnimationFrame(loop);
  }

  // Optimisation only: pause when the card is fully scrolled away.
  // The initial value is "visible" and start() below runs regardless —
  // a missed or late observer callback can never strand a flat card.
  const io = new IntersectionObserver((es) => {
    inView = es.some(e => e.isIntersecting);
    if (inView) start(); else stop();
  }, { threshold: 0.02 });
  const onVis = () => { if (document.hidden) stop(); else start(); };
  // Self-clean the listeners when the canvas leaves the DOM.
  const mo = new MutationObserver(() => {
    if (!canvas.isConnected) { cleanup(); stop(); }
  });

  if (!isEnabled()) return;
  io.observe(canvas);
  document.addEventListener('visibilitychange', onVis);
  mo.observe(document.body, { childList: true, subtree: true });
  start();
}
