// Motion effects — pure CSS/WAAPI. No DOM snapshot, no canvas, no WebGL.
//
// History: confirm -> receipt celebrations and button pulses used to run
// the libraries.dev "distortion-waves" engine, which pictures both
// screens (SVG foreignObject -> WebGL texture) before it can move. On a
// real phone that read as weird and laggy, and the perf pass confirmed
// why (headless rig, real confirm screen): the snapshot phase cost
// ~1.5 s cold / ~150-200 ms warm with the package defaults, and after
// tuning (0.5x capture resolution, style duration 3.62 s -> 0.63 s) it
// still blew the 250 ms guard in the real send flow — post-broadcast
// app churn plus snapshot contention kept prepare() past 650 ms, so
// the guard abandoned every celebration in the rig. An effect that
// cannot be trusted to appear is worse than a simpler one that always
// lands, so the engine was removed entirely (the pre-Allo chrome-ring
// style, rebuilt on WAAPI):
//
//  - celebrateFx: the receipt swaps in IMMEDIATELY — the effect never
//    delays a completed transaction — and three chrome rings + a soft
//    glow expand from the pressed button over the landed receipt
//    (~720 ms, transform/opacity only, decorative overlay).
//  - pressPulse: a 230 ms scale/brightness nudge on pressed controls.
//
// Reduced motion disables both (callers also gate on the user's
// "Wave effects" setting). Seed, backup and unlock screens never run
// either: celebrations only fire inside the shell and the pulse listener
// is gated on the shell being mounted.

export function prefersReducedMotion(): boolean {
  try { return !!window.matchMedia('(prefers-reduced-motion: reduce)').matches; } catch { return false; }
}

/** Celebration count for support/proofs. */
export const waveStats = { plays: 0 };
try { (window as any).__synWaveStats = waveStats; } catch { /* non-browser */ }

let activeOverlay: HTMLElement | null = null;
let activeAnims: Animation[] = [];

/** Remove a running celebration overlay (navigation interrupts it). */
export function cancelActiveFx(): void {
  activeAnims.forEach(a => { try { a.cancel(); } catch { /* done */ } });
  activeAnims = [];
  if (activeOverlay) { activeOverlay.remove(); activeOverlay = null; }
}

/**
 * Celebrate a completed action from `source`: swap() runs FIRST and the
 * receipt lands instantly; the chrome rings are pure decoration on top.
 */
export function celebrateFx(source: Element | null, swap: () => void): void {
  cancelActiveFx();
  if (prefersReducedMotion() || !source || !(source as HTMLElement).isConnected) { swap(); return; }
  const r = (source as HTMLElement).getBoundingClientRect();
  const cx = r.left + r.width / 2;
  const cy = r.top + r.height / 2;
  swap();
  waveStats.plays++;
  try {
    const overlay = document.createElement('div');
    overlay.className = 'fxOverlay';
    const glow = document.createElement('div');
    glow.className = 'fxGlow';
    glow.style.left = cx + 'px'; glow.style.top = cy + 'px';
    overlay.appendChild(glow);
    const rings: HTMLElement[] = [];
    for (let i = 0; i < 3; i++) {
      const ring = document.createElement('div');
      ring.className = 'fxRing';
      ring.style.left = cx + 'px'; ring.style.top = cy + 'px';
      overlay.appendChild(ring);
      rings.push(ring);
    }
    document.body.appendChild(overlay);
    activeOverlay = overlay;
    const D = 720;
    const ease = 'cubic-bezier(.22,.9,.3,1)';
    activeAnims = [
      glow.animate([
        { opacity: 0.5, transform: 'translate(-50%,-50%) scale(0.2)' },
        { opacity: 0, transform: 'translate(-50%,-50%) scale(1)' },
      ], { duration: D, easing: ease, fill: 'forwards' }),
      ...rings.map((ring, i) => ring.animate([
        { opacity: 0.75 - i * 0.18, transform: 'translate(-50%,-50%) scale(0.06)' },
        { opacity: 0, transform: 'translate(-50%,-50%) scale(1)' },
      ], { duration: D, delay: i * 90, easing: ease, fill: 'forwards' })),
    ];
    const done = () => { if (activeOverlay === overlay) { overlay.remove(); activeOverlay = null; activeAnims = []; } };
    Promise.allSettled(activeAnims.map(a => a.finished)).then(done).catch(done);
    setTimeout(done, D + 700);
  } catch { /* decoration only — the receipt already landed */ }
}

/** A short, soft press nudge: scale down with a brightness lift.
 *  minScale defaults to 0.955; large surfaces (the home action tiles)
 *  pass a gentler 0.97 so the bigger element doesn't lurch. */
export function pressPulse(el: Element | null, minScale = 0.955): void {
  if (prefersReducedMotion() || !el || !(el as HTMLElement).isConnected) return;
  try {
    (el as HTMLElement).animate([
      { transform: 'scale(1)', filter: 'brightness(1)' },
      { transform: `scale(${minScale})`, filter: 'brightness(1.18)', offset: 0.35 },
      { transform: 'scale(1)', filter: 'brightness(1)' },
    ], { duration: 230, easing: 'ease-out' });
  } catch { /* visual only — never break a press */ }
}
