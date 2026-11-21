// The Wave loading indicator — Syn Wallet's SINGLE loading affordance,
// implementing the loading-ui Wave the user specified: five vertical bars
// (heights 50% / 75% / 100% / 75% / 50%) breathing via a scaleY 1 -> 0.6
// keyframe, staggered by calc(var(--delay) * index), with a --duration
// knob, coloured by currentColor so it inherits the chrome/context colour
// wherever it sits. The matching CSS (.waveLoad + @keyframes
// loading-ui-wave) lives in style.css; the React twin for the chart
// island is client/chart/components/ui/wave.tsx. Reduced motion renders
// the bars static (see the media query in style.css).
export function waveLoadHTML(extraClass = ''): string {
  return `<span class="waveLoad${extraClass ? ' ' + extraClass : ''}" role="status"><span></span><span></span><span></span><span></span><span></span><span class="srOnly">Loading</span></span>`;
}
// Centred first-open loader block: a surface with NO data yet shows this
// in the middle of its content area (the .loadCenter CSS does the
// centring) — the bare inline loader inside a left-aligned paragraph
// used to strand it in the top-left corner. `sm` shrinks the block for
// section-level slots inside a scrolling page.
export function waveLoadBlockHTML(label = 'Loading…', sm = false): string {
  const escLabel = label.replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]!));
  return `<div class="loadCenter${sm ? ' sm' : ''}">${waveLoadHTML('lg')}<span>${escLabel}</span></div>`;
}
