// THE icon-resolution path for the whole app — home rows, the balance
// card's network list, the token section, Activity chips, send/swap
// pickers, receive pill and detail headers all render through here, so a
// logo is resolved (or honestly absent) in exactly one place.
//
// Resolution order:
//  - Chains: the chain's own shipped logo (BASE_CHAINS carry one each) →
//    the registry map (long-tail EVM chains whose real logo was fetched
//    from the Trust Wallet assets repo and verified on disk — see
//    icon-map.ts) → no URL.
//  - Tokens: built-ins ship a real logo under /assets/tokens/<id>.png
//    (fetched from the Trust Wallet assets repo by checksummed contract /
//    mint, verified on disk) → any other token WITH a contract on a
//    covered chain resolves its real artwork through the server's
//    /api/token-logo (which fetches + caches it from the same Trust
//    Wallet repo, then GeckoTerminal's token info — the browser never
//    talks to a third-party host) → a token with no artwork anywhere
//    keeps the monogram.
//
// "No URL" is NOT a broken image: the renderer draws the fallback tile —
// the symbol's letters as a chrome monogram on a #1a1f28 disc — and when
// an <img> IS emitted it sits on top of that same tile, so if the file
// ever fails at runtime the global error handler removes the <img> and
// the monogram shows through. A broken-image glyph is impossible.
import { REGISTRY_ICONS } from './icon-map';
import { UNDERLYING_ICONS } from './underlying-icons';
import { STOCK_ICONS } from './stock-icons';

export interface IconChainLike { id: string; name: string; symbol: string; img?: string; evmId?: number }
export interface IconTokenLike { id: string; symbol: string; name?: string; builtin?: boolean; logo?: boolean; chainId?: string; contract?: string }

const esc = (s: string) => s.replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]!));

/** Self-hosted logo URL for a chain, or '' when none exists (monogram). */
export function chainIconUrl(c: IconChainLike): string {
  if (c.img) return c.img;
  if (c.evmId != null && REGISTRY_ICONS[c.evmId]) return REGISTRY_ICONS[c.evmId];
  return '';
}

// Chains whose tokens the server's /api/token-logo can resolve
// artwork for (Trust Wallet repo path and/or GeckoTerminal network
// exists). Mirrors TW_LOGO_CHAINS in src/server.ts.
const TOKEN_LOGO_CHAINS: Record<string, true> = { ethereum: true, bnb: true, polygon: true, arbitrum: true, base: true, optimism: true, avalanche: true, fantom: true, zksync: true, solana: true, 'solana-tw': true, 'solana-phantom': true };

/** Logo URL for a token, or '' when none exists (monogram). */
export function tokenIconUrl(t: IconTokenLike): string {
  // Built-ins and catalog tokens carry a self-hosted logo file at
  // /assets/tokens/<id>.png (catalog entries are flagged logo:true
  // only when their file was actually fetched — and a missing file
  // still degrades safely: the global error handler removes a broken
  // .coinImg, revealing the monogram).
  if (t.builtin || t.logo) return `/assets/tokens/${t.id}.png`;
  // Any other token with a real contract on a covered chain — bStocks,
  // Invest discoveries, swap outputs, hand-added tokens — resolves its
  // real logo through the server (same-origin; the server fetches and
  // caches the artwork). A 404 degrades exactly like a missing file:
  // the <img> is removed and the monogram shows.
  if (t.chainId && t.contract && t.contract !== 'native' && TOKEN_LOGO_CHAINS[t.chainId]) return `/api/token-logo?chain=${encodeURIComponent(t.chainId)}&contract=${encodeURIComponent(t.contract)}`;
  return '';
}

export interface IconOpts { lg?: boolean; sm?: boolean; tick?: boolean }

/**
 * The one icon element: a disc carrying the monogram letters, with the
 * real logo layered over it when one resolves. Fixed box (CSS .coinIc)
 * + decoding="async" + intrinsic size hints, so icons never flash or
 * shift layout while loading. `tick` is the 19px disc used by the
 * welcome ticker and the welcome hero label.
 */
export function iconHTML(url: string, symbol: string, name: string, opts: IconOpts = {}): string {
  const cls = 'coinIc' + (opts.lg ? ' lg' : '') + (opts.sm ? ' sm' : '') + (opts.tick ? ' tick' : '');
  const px = opts.tick ? 19 : opts.sm ? 22 : 42;
  // Audit NEW LOW 3: the URL goes into an attribute — escape it, and only
  // ever emit same-origin paths or https: URLs (never a peer-supplied
  // javascript:/data: string).
  const okUrl = url && (/^\/(?!\/)/.test(url) || /^https:\/\//i.test(url)) && !/["'\s<>]/.test(url) ? url : '';
  const img = okUrl ? `<img class="coinImg" src="${esc(okUrl)}" alt="${esc(name)} logo" width="${px}" height="${px}" decoding="async" loading="lazy">` : '';
  // Monogram: the FULL symbol, never truncated (a sliced ticker reads
  // as a misspelling — GOOGL -> "GOO", BRENT -> "BRE"). The type
  // scales down as the symbol grows so the whole word fits the disc
  // at one consistent weight.
  const mono = symbol.toUpperCase();
  const scale = mono.length <= 2 ? 1 : mono.length === 3 ? 0.95 : mono.length === 4 ? 0.85 : mono.length === 5 ? 0.72 : mono.length === 6 ? 0.62 : 0.54;
  return `<span class="${cls}"><span class="coinLetter" style="font-size:${scale}em">${esc(mono)}</span>${img}</span>`;
}

/**
 * Designed icon for a commodity underlying (Hyperliquid commodity
 * perps): metals get their chemical symbol on the chrome disc (GOLD
 * -> Au, SILVER -> Ag, COPPER -> Cu, PLATINUM -> Pt, PALLADIUM -> Pd,
 * ALUMINIUM -> Al), energy and grains get a deliberate Remix glyph
 * (oil drop, gas flame, seedling). Anything else falls back to the
 * full-ticker monogram. No letters are ever sliced off a name.
 */
const CHEM_SYMBOLS: Record<string, string> = { GOLD: 'Au', GOLDJM: 'Au', SILVER: 'Ag', SILVERJM: 'Ag', COPPER: 'Cu', PLATINUM: 'Pt', PALLADIUM: 'Pd', ALUMINIUM: 'Al' };
const COMMODITY_GLYPHS: Record<string, string> = { CL: 'ri-drop-line', BRENTOIL: 'ri-drop-line', OIL: 'ri-drop-line', WTI: 'ri-drop-line', USOIL: 'ri-drop-line', NATGAS: 'ri-fire-line', GAS: 'ri-fire-line', CORN: 'ri-seedling-line', WHEAT: 'ri-seedling-line' };
export function commodityIcon(base: string, name: string, opts: IconOpts = {}): string {
  const b = (base || '').toUpperCase();
  const cls = 'coinIc' + (opts.lg ? ' lg' : '') + (opts.sm ? ' sm' : '') + (opts.tick ? ' tick' : '');
  const chem = CHEM_SYMBOLS[b];
  if (chem) return `<span class="${cls} cmDisc"><span class="coinSym">${chem}</span></span>`;
  const glyph = COMMODITY_GLYPHS[b];
  if (glyph) return `<span class="${cls} cmDisc"><i class="${glyph}"></i></span>`;
  return iconHTML('', base, name, opts);
}

/** Logo-only icon for tight overlapped stacks (audit L-6): at 16-22px a
 * monogram letter half-covered by the next disc reads as garbled
 * fragments, so stacks render real logos only; chains without a logo
 * are simply absent from the stack (the label text carries the count). */
export function stackIconHTML(url: string, name: string): string {
  const okUrl = url && (/^\/(?!\/)/.test(url) || /^https:\/\//i.test(url)) && !/["'\s<>]/.test(url) ? url : '';
  if (!okUrl) return '';
  return `<span class="coinIc"><img class="coinImg" src="${esc(okUrl)}" alt="${esc(name)} logo" width="22" height="22" decoding="async"></span>`;
}

/**
 * Self-hosted logo for a MARKET underlying (Hyperliquid perps,
 * bStocks, pre-IPO names) — the files under /assets/u/ were sourced
 * (CoinGecko for crypto, company logo CDNs for stocks) and verified as
 * real images on disk; see lib/underlying-icons.ts. Aliases resolve
 * the venue's naming onto the asset (kPEPE → PEPE, 1000PEPE → PEPE,
 * RNDR → RENDER, MATIC → POL). Anything unmapped returns '' and the
 * renderer draws the chrome monogram — the designed final state, so a
 * broken image stays impossible on market surfaces too.
 */
export function underlyingIconUrl(base: string): string {
  let b = (base || '').toUpperCase();
  if (b.startsWith('1000') && UNDERLYING_ICONS[b.slice(4)]) b = b.slice(4);
  if (/^K[A-Z]/.test(b) && UNDERLYING_ICONS[b.slice(1)]) b = b.slice(1);
  if (b === 'RNDR') b = 'RENDER';
  if (b === 'MATIC') b = 'POL';
  // Self-hosted hauls only: crypto (/assets/u/) and stocks (/assets/s/
  // — real company logos for bStock and HL stock underlyings). Both
  // maps are local files, so rows never depend on a remote icon CDN.
  return UNDERLYING_ICONS[b] || STOCK_ICONS[b] || '';
}

export function underlyingIcon(base: string, name: string, opts: IconOpts = {}): string {
  return iconHTML(underlyingIconUrl(base), base, name, opts);
}

/**
 * Stock logo tile (bStocks + Hyperliquid stock underlyings). Stock
 * logos are NOT round brand marks: the FMP haul mixes wordmarks,
 * glyphs and baked squares, and clipping them into the round coin
 * disc cropped wordmarks and floated white boxes — it read as buggy.
 * So stock assets are pre-normalized into uniform tiles by
 * scripts/normalize-stock-icons.py (logo contained, never cropped,
 * on a flat tile tone) and this renderer is just a rounded-square
 * frame the tile fills exactly. No logo -> the ticker monogram on
 * the same rounded-square frame (letters behind the img, so a failed
 * load falls back to them exactly like iconHTML).
 */
export function stockIconUrl(base: string): string {
  let b = (base || '').toUpperCase();
  if (b.startsWith('1000') && STOCK_ICONS[b.slice(4)]) b = b.slice(4);
  if (/^K[A-Z]/.test(b) && STOCK_ICONS[b.slice(1)]) b = b.slice(1);
  return STOCK_ICONS[b] || '';
}

export function stockIcon(base: string, name: string, opts: IconOpts = {}): string {
  const cls = 'stockIc' + (opts.lg ? ' lg' : '') + (opts.sm ? ' sm' : '');
  const px = opts.sm ? 22 : 42;
  const url = stockIconUrl(base);
  const okUrl = url && (/^\/(?!\/)/.test(url) || /^https:\/\//i.test(url)) && !/["'\s<>]/.test(url) ? url : '';
  const img = okUrl ? `<img class="stockImg" src="${esc(okUrl)}" alt="${esc(name)} logo" width="${px}" height="${px}" decoding="async">` : '';
  const mono = (base || '').toUpperCase();
  const scale = mono.length <= 2 ? 1 : mono.length === 3 ? 0.95 : mono.length === 4 ? 0.85 : mono.length === 5 ? 0.72 : mono.length === 6 ? 0.62 : 0.54;
  return `<span class="${cls}"><span class="coinLetter" style="font-size:${scale}em">${esc(mono)}</span>${img}</span>`;
}

export function chainIcon(c: IconChainLike, lg = false): string {
  return iconHTML(chainIconUrl(c), c.symbol, c.name, { lg });
}

export function tokenIcon(t: IconTokenLike, lg = false): string {
  return iconHTML(tokenIconUrl(t), t.symbol, t.name || t.symbol, { lg });
}
