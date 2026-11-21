// Picker asset-set tests: the Send / Receive / Swap sheets must show
// each network's COMPLETE token set — native asset, every hosted
// token (builtin + custom), zero-balance tokens included — deduped,
// under the right network, with the solana-tw storage alias folded
// onto solana. Fixture mirrors a real wallet: builtin tokens, a
// custom EVM token, a custom Solana mint, a token stored under the
// solana-tw alias, and a duplicate registration of one contract.
import assert from 'node:assert';
import { buildPickerAssets, filterSendableAssets, assetsForNetwork, sortPickerAssets, pickerChainId, type PickerChainLike, type PickerTokenLike } from '../client/lib/pickerassets';

const chains: PickerChainLike[] = [
  { id: 'ethereum', name: 'Ethereum', symbol: 'ETH', kind: 'evm', decimals: 18 },
  { id: 'polygon', name: 'Polygon', symbol: 'MATIC', kind: 'evm', decimals: 18 },
  { id: 'solana', name: 'Solana', symbol: 'SOL', kind: 'solana', decimals: 9 },
  { id: 'solana-tw', name: 'Solana (Trust Wallet)', symbol: 'SOL', kind: 'solana-tw', decimals: 9 },
  { id: 'bitcoin', name: 'Bitcoin', symbol: 'BTC', kind: 'bitcoin', decimals: 8 },
  { id: 'litecoin', name: 'Litecoin', symbol: 'LTC', kind: 'bitcoin', decimals: 8 },
  { id: 'tron', name: 'TRON', symbol: 'TRX', kind: 'tron', decimals: 6 },
  { id: 'xrp', name: 'XRP', symbol: 'XRP', kind: 'xrp', decimals: 6 },
];
const T = (id: string, chainId: string, contract: string, symbol: string, name = symbol): PickerTokenLike => ({ id, chainId, contract, symbol, name, decimals: 18 });
const tokens: PickerTokenLike[] = [
  T('tk-usdc-pol', 'polygon', '0xusdc', 'USDC', 'USD Coin'),
  T('tk-custom-pol', 'polygon', '0xcustom', 'CSTM', 'Custom Token'),
  T('tk-mint-sol', 'solana', 'Mint111', 'MINT', 'Solana Mint'),
  T('tk-tw-sol', 'solana-tw', 'Mint222', 'TWM', 'TW Stored Mint'), // stored under the alias — must surface under solana
  T('tk-usdc-pol-dup', 'polygon', '0xusdc', 'USDC', 'USD Coin'), // same contract, second registration — must dedupe
  T('tk-eth-dai', 'ethereum', '0xdai', 'DAI', 'Dai'),
];

const assets = buildPickerAssets(chains, tokens);
const byNet = (id: string) => assetsForNetwork(assets, id);

// every chain contributes its native asset, incl. the UTXO family
for (const id of ['ethereum', 'polygon', 'solana', 'bitcoin', 'litecoin', 'tron', 'xrp']) {
  assert.ok(byNet(id).some(a => a.contract === 'native'), `${id} native present`);
}
// solana-tw contributes its own NATIVE only (a distinct account's
// SOL) — but hosts no token rows; its tokens live under solana.
assert.deepEqual(assetsForNetwork(assets, 'solana-tw').map(a => a.contract), ['native'], 'solana-tw: native only, no token rows');
// polygon: native + USDC (once) + custom
assert.deepEqual(byNet('polygon').map(a => a.symbol).sort(), ['CSTM', 'MATIC', 'USDC'], 'polygon set complete + deduped');
// solana: native + both mints (incl. the alias-stored one)
assert.deepEqual(byNet('solana').map(a => a.symbol).sort(), ['MINT', 'SOL', 'TWM'], 'solana set includes alias-stored token');
// litecoin: native only (no token standard hosted)
assert.deepEqual(byNet('litecoin').map(a => a.symbol), ['LTC'], 'litecoin native only');
// keys unique across the whole set
assert.equal(new Set(assets.map(a => a.key)).size, assets.length, 'no duplicate keys');
assert.equal(pickerChainId('solana-tw'), 'solana');
assert.equal(pickerChainId('polygon'), 'polygon');

// sendable filter: xrp (receive-only kind) drops out, utxo natives stay
const sendable = filterSendableAssets(assets, (id) => chains.find(c => c.id === pickerChainId(id))?.kind, new Set(['evm', 'solana', 'solana-tw', 'tron', 'bitcoin']));
assert.ok(!sendable.some(a => a.chainId === 'xrp'), 'xrp excluded from send');
assert.ok(sendable.some(a => a.chainId === 'litecoin' && a.contract === 'native'), 'LTC sendable');
assert.ok(sendable.some(a => a.chainId === 'polygon' && a.symbol === 'CSTM'), 'custom token sendable');

// sorting: held (by USD) first, then majors, then A–Z; zero-balance stays listed
const usd = new Map<string, number>([['polygon:0xcustom', 5], ['solana:native', 100]]);
const sorted = sortPickerAssets(assets, a => usd.get(a.key) ?? 0, a => chains.findIndex(c => c.id === a.chainId));
assert.equal(sorted[0].symbol, 'SOL', 'largest holding first');
assert.ok(sorted.some(a => a.symbol === 'DAI'), 'zero-balance token still listed after sort');
assert.ok(sorted.findIndex(a => a.symbol === 'CSTM') < sorted.findIndex(a => a.symbol === 'DAI'), 'held before unheld');

console.log('test-picker: OK');
