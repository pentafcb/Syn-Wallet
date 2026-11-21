// Display currency (Addition 10) — ONE store for the whole app.
// The balance-card chip and the Settings row both read/write through
// here, so they can never disagree. Prices underneath stay USD-sourced
// (our price stack is USD); conversion is display-only, using real
// reference rates served by our own /api/fx (ECB via Frankfurter for
// the majors; ARS/HNL crossed server-side from CoinGecko market rates
// because neither is in the ECB set) — never a rate invented
// client-side. Selection + last-known rates persist in localStorage
// (local-only rule: nothing leaves the device).
export interface CurrencyDef { code: string; symbol: string; name: string }
export const CURRENCIES: CurrencyDef[] = [
  { code: 'USD', symbol: '$', name: 'US Dollar' },
  { code: 'EUR', symbol: '€', name: 'Euro' },
  { code: 'GBP', symbol: '£', name: 'British Pound' },
  { code: 'JPY', symbol: '¥', name: 'Japanese Yen' },
  { code: 'CHF', symbol: 'CHF', name: 'Swiss Franc' },
  { code: 'CAD', symbol: '$', name: 'Canadian Dollar' },
  { code: 'AUD', symbol: '$', name: 'Australian Dollar' },
  { code: 'CNY', symbol: '¥', name: 'Chinese Yuan' },
  { code: 'BRL', symbol: 'R$', name: 'Brazilian Real' },
  { code: 'MXN', symbol: '$', name: 'Mexican Peso' },
  { code: 'ARS', symbol: 'AR$', name: 'Argentine Peso' },
  { code: 'HNL', symbol: 'L', name: 'Honduran Lempira' },
  { code: 'INR', symbol: '₹', name: 'Indian Rupee' },
  { code: 'KRW', symbol: '₩', name: 'South Korean Won' },
];
const ZERO_DEC = new Set(['JPY', 'KRW']);
const CODE_KEY = 'syn-display-currency';
const RATES_KEY = 'syn-fx-rates';
const store: { get(k: string): string | null; set(k: string, v: string): void } = {
  get: k => { try { return localStorage.getItem(k); } catch { return null; } },
  set: (k, v) => { try { localStorage.setItem(k, v); } catch { /* private mode */ } },
};
let cur = 'USD';
let rates: Record<string, number> | null = null; // units per 1 USD
let ratesAt = 0;
try {
  const saved = store.get(CODE_KEY);
  if (saved && CURRENCIES.some(c => c.code === saved)) cur = saved;
  const rj = JSON.parse(store.get(RATES_KEY) || 'null');
  if (rj && typeof rj === 'object' && rj.rates && typeof rj.rates === 'object') { rates = rj.rates; ratesAt = Number(rj.at || 0); }
} catch { /* defaults stand */ }

export function currencyCode(): string { return cur; }
export function currencyDef(): CurrencyDef { return CURRENCIES.find(c => c.code === cur) || CURRENCIES[0]; }
export function currencySymbol(): string { return currencyDef().symbol; }
export function fxRates(): Record<string, number> | null { return rates; }
export function fxRateFor(code: string): number | null { if (code === 'USD') return 1; const r = rates?.[code]; return typeof r === 'number' && r > 0 ? r : null; }
/** The currency values can actually be shown in right now: the selected
 * one when a real rate for it is on hand, else USD (never a fake rate). */
export function effectiveCode(): string { return cur === 'USD' || fxRateFor(cur) != null ? cur : 'USD'; }
export function convertUsd(usd: number): number { const code = effectiveCode(); return code === 'USD' ? usd : usd * (fxRateFor(code) as number); }
/** Select a currency. Refuses (returns false) when no real rate for it
 * is available — the caller surfaces the honest refusal in the UI. */
export function setCurrency(code: string): boolean {
  if (!CURRENCIES.some(c => c.code === code)) return false;
  if (code !== 'USD' && fxRateFor(code) == null) return false;
  cur = code; store.set(CODE_KEY, code);
  return true;
}
let fxInFlight: Promise<boolean> | null = null;
/** Fetch fresh rates through our server. Resolves true when rates are
 * on hand afterwards (fresh or previously cached), false when none. */
export function fetchFxRates(): Promise<boolean> {
  if (fxInFlight) return fxInFlight;
  fxInFlight = (async () => {
    try {
      const r = await fetch('/api/fx', { signal: AbortSignal.timeout(12000) });
      if (!r.ok) return rates != null;
      const j = await r.json();
      if (!j || typeof j.rates !== 'object' || !j.rates) return rates != null;
      const clean: Record<string, number> = {};
      for (const [k, v] of Object.entries(j.rates)) if (typeof v === 'number' && v > 0) clean[k] = v;
      if (!Object.keys(clean).length) return rates != null;
      rates = clean; ratesAt = Number(j.at || Date.now());
      store.set(RATES_KEY, JSON.stringify({ at: ratesAt, rates }));
      return true;
    } catch { return rates != null; } finally { fxInFlight = null; }
  })();
  return fxInFlight;
}
/**
 * THE app-wide fiat formatter (chart.ts fmtUsd delegates here, so every
 * surface converts). Semantics mirror the historical fmtUsd: dp is the
 * caller's intended precision (dust callers pass 4), values under 1 USD
 * may use up to 4 fraction digits, JPY/KRW render whole units unless
 * the caller asked for dust precision.
 */
// Per-currency Intl presentation. ARS renders with es-AR number
// conventions but the ISO code in place of the currency sign: es-AR's
// own sign for pesos is a bare "$", which at a glance reads as USD —
// an ARS amount must never look like dollars. HNL renders via es-HN,
// whose lempira sign is "L". Everything else keeps the en-US form the
// app has always used.
const LOCALE_FMT: Record<string, { locale: string; display?: 'code' }> = {
  ARS: { locale: 'es-AR', display: 'code' },
  HNL: { locale: 'es-HN' },
};
/** Pure renderer behind fmtFiat (exported for tests): formats an
 * ALREADY-converted value in the given currency. `dust` mirrors
 * fmtFiat's sub-1-USD precision rule. */
export function renderFiat(code: string, v: number, dp = 2, dust = false): string {
  const effDp = ZERO_DEC.has(code) ? (dp >= 4 ? 4 : 0) : dp;
  const lf = LOCALE_FMT[code];
  return v.toLocaleString(lf?.locale || 'en-US', { style: 'currency', currency: code, ...(lf?.display ? { currencyDisplay: lf.display } : {}), minimumFractionDigits: effDp, maximumFractionDigits: dust ? Math.max(4, effDp) : effDp });
}
export function fmtFiat(n: number, dp = 2): string {
  return renderFiat(effectiveCode(), convertUsd(n), dp, n < 1);
}

/** Fraction digits for amount ENTRY in a fiat currency (audit M-17):
 * JPY/KRW take whole units, everything else 2. */
export function currencyDecimals(code: string): number {
  return ZERO_DEC.has(code) ? 0 : 2;
}