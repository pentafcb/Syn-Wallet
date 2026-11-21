// Picker asset-set construction (Send / Swap / Receive) — pure
// functions over plain chain/token shapes, extracted from main.ts so
// the sets the shared picker sheet shows are pinned by unit tests
// (tests/test-picker.ts) instead of living as untestable UI closures.
//
// The rules encoded here, each one a fixed defect:
// - A network's set is COMPLETE: its native asset + every registered
//   token hosted on it (built-ins and the user's custom tokens alike).
// - Tokens stored against 'solana-tw' belong to 'solana': the Trust
//   Wallet entry is an account variant of Solana, not a network, and
//   the enabled-set check elsewhere keys on 'solana' — without this
//   mapping such tokens vanish from every list.
// - The same contract registered twice under different ids collapses
//   to ONE row per network (first registration wins): no duplicates.
// - Ordering discipline (held first by USD value, then majors, then
//   A–Z) is a sort over the complete set, never a filter: zero-balance
//   tokens stay listed.
export interface PickerChainLike { id: string; kind: string; name: string; symbol: string; decimals: number }
export interface PickerTokenLike { id: string; chainId: string; contract: string; name: string; symbol: string; decimals: number }
export interface PickerAsset { key: string; chainId: string; contract: string; symbol: string; name: string; decimals: number; tokenId?: string }

/** The chain a token belongs to in picker sets ('solana-tw' → 'solana'). */
export function pickerChainId(chainId: string): string { return chainId === 'solana-tw' ? 'solana' : chainId; }

// Chain kinds that can host registered tokens at all. (TRON hosts no
// token class in this wallet — no builtin TRC-20s exist and the token
// metadata reader supports only EVM + Solana — so TRON contributes
// its native asset only, consistently across every flow.)
const TOKEN_HOST_KINDS = new Set(['evm', 'solana', 'solana-tw']);

/** Natives for every given chain + the tokens hosted on each
 * token-capable chain, de-duped by key. The 'solana-tw' chain entry
 * contributes its native (a distinct account's SOL) but hosts no
 * token rows of its own — its tokens live under 'solana'. */
export function buildPickerAssets(chains: readonly PickerChainLike[], tokens: readonly PickerTokenLike[]): PickerAsset[] {
  const out: PickerAsset[] = []; const seen = new Set<string>();
  const push = (a: PickerAsset) => { if (!seen.has(a.key)) { seen.add(a.key); out.push(a); } };
  for (const c of chains) {
    push({ key: c.id + ':native', chainId: c.id, contract: 'native', symbol: c.symbol, name: c.name, decimals: c.decimals });
    if (!TOKEN_HOST_KINDS.has(c.kind) || c.kind === 'solana-tw') continue;
    for (const t of tokens) if (pickerChainId(t.chainId) === c.id) push({ key: c.id + ':' + t.contract, chainId: c.id, contract: t.contract, symbol: t.symbol, name: t.name, decimals: t.decimals, tokenId: t.id });
  }
  return out;
}

/** Send's cut of the full set: natives of sendable chains + tokens on
 * EVM/Solana chains. `sendableKinds` is the caller's SENDABLE_KINDS. */
export function filterSendableAssets(assets: readonly PickerAsset[], kindOf: (chainId: string) => string | undefined, sendableKinds: ReadonlySet<string>): PickerAsset[] {
  return assets.filter(a => { const k = kindOf(a.chainId); if (!k) return false; return a.contract === 'native' ? sendableKinds.has(k) : k === 'evm' || k === 'solana'; });
}

/** One network's slice of a set ('' = the whole set, "All networks"). */
export function assetsForNetwork(assets: readonly PickerAsset[], net: string): PickerAsset[] {
  return !net ? [...assets] : assets.filter(a => a.chainId === net);
}

/** The pickers' ordering: held assets first (USD value desc), then
 * majors (natives + the dollar stables, by chain rank then symbol),
 * then the rest A–Z. A sort, never a filter. */
export function sortPickerAssets(assets: readonly PickerAsset[], usdOf: (a: PickerAsset) => number, chainRankOf: (a: PickerAsset) => number): PickerAsset[] {
  const held = assets.filter(a => usdOf(a) > 0).sort((x, y) => usdOf(y) - usdOf(x));
  const heldKeys = new Set(held.map(a => a.key));
  const isMajor = (a: PickerAsset) => a.contract === 'native' || a.symbol === 'USDC' || a.symbol === 'USDT';
  const majors = assets.filter(a => !heldKeys.has(a.key) && isMajor(a)).sort((x, y) => chainRankOf(x) - chainRankOf(y) || x.symbol.localeCompare(y.symbol));
  const majorKeys = new Set(majors.map(a => a.key));
  const rest = assets.filter(a => !heldKeys.has(a.key) && !majorKeys.has(a.key)).sort((x, y) => x.symbol.localeCompare(y.symbol));
  return [...held, ...majors, ...rest];
}
