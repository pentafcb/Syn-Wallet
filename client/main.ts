import '@fontsource/dotgothic16/latin-400.css';
import './style.css';
import { createMnemonic, isValidMnemonic, normalizeMnemonic, deriveAll, deriveAll2, encryptVault, decryptVault, bip39Wordlist, parseVaultPlaintext, packVaultPayload, newWalletId, wrapWithRawKey, unwrapWithRawKey, solanaSecretKeyBase58, btcWifFromPrivateKey, utxoWifFromPrivateKey, suiPrivateKeyBech32, aptosPrivateKeyExport, verifyTronTransferTx, base16, MIN_PASSWORD_LENGTH, type VaultBlob, type VaultPayload, type WalletEntry, type DerivedAccounts2, type KeyWrapBlob } from './lib/wallet';
import { isValidUtxoAddress, buildUtxoSend, estimateUtxoFeeSats, selectCoins, utxoParams, type Utxo } from './lib/utxo';
import { EVM_REGISTRY } from './lib/chains-data';
import { validateCustomNetwork, parseChainIdResult, sanitizeTokenText, isValidTronAddress } from './lib/netvalidate';
import { getAssociatedTokenAddressSync, createAssociatedTokenAccountInstruction, createTransferCheckedInstruction, createTransferInstruction, createRevokeInstruction } from '@solana/spl-token';
import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha2';
import { ed25519 } from '@noble/curves/ed25519';
import { nameKindOf, looksLikeNameAttempt, snsDomainKey, snsOwnerFromAccountData, snsParentFromAccountData, snsReverseKey, snsNameFromReverseData, snsFavouriteKey, snsFavouriteNameAccount, SNS_ROOT, type NameKind } from './lib/names';
import { parseSignInMessage, signInTimingProblem, looksLikeBlindBlob } from './lib/signing';
import { computePresets, computeLegacyPresets, parseGwei, formatGwei, validateCustomFees, effectiveGasPriceWei, type FeeLevel, type FeePreset } from './lib/fees';
import { gpTokenRisk, gpAddressRisk, gpApprovals, isUnlimitedAmount, formatTokenAmount, extractSolMintRisks, type RiskReport, type ApprovalRow } from './lib/goplus';
import { twAssetId, twCoinRisk, twAddressVerdict, twTickers as twTickersFetch, setTwEnabled, twEnabled } from './lib/twapi';
import { renderTickerChart, fmtUsd, fmtPrice, priceDp } from './lib/chart';
import { CURRENCIES, currencyCode, currencySymbol, convertUsd, setCurrency, fetchFxRates, fxRateFor, effectiveCode, currencyDecimals } from './lib/currency';
import { chainIcon, tokenIcon, chainIconUrl, tokenIconUrl, iconHTML, stackIconHTML, underlyingIcon, underlyingIconUrl, commodityIcon, stockIcon } from './lib/icons';
import { TOKEN_CATALOG, POPULAR_TOKEN_IDS } from './lib/token-catalog';
import { gammaEvents, gammaEventBySlug, gammaMarketByCondition, upDownSlug, parseUpDownSlug, UPDOWN_ASSETS, UPDOWN_TFS, clobBook, clobHistory, polyPositions, polyTrades, polyFeed, deriveClobCreds, buildSignedOrder, postOrder, getOpenOrders, cancelPolyOrder, verifyOrderSignature, limitRawAmounts, marketRawAmounts, walkPrice, roundConfigFor, relayerDeployed, CTF_EXCHANGE_V2, NEG_RISK_EXCHANGE_V2, PUSD, USDC_E, USDC_NATIVE, type PolyEvent, type PolyMarket, type PolyPosition, type PolyOpenOrder, type ClobCreds, type Book } from './lib/polymarket';
import { hlInfo, hlPostL1, hlApproveAgent, hlOrderWire, hlOrderAction, hlUpdateLeverageAction, hlCancelAction, hlOrderStatusLines, hlAssetId, hlRoundPrice, hlRoundSize, hlEstLiqPx, HL_BRIDGE_ADDRESS, HL_ARBITRUM_USDC, HL_MIN_DEPOSIT_USDC, HL_MIN_ORDER_USD, type HlOrderWire } from './lib/hl';
import { waveLoadHTML, waveLoadBlockHTML } from './lib/waveload';
import { celebrateFx, cancelActiveFx, pressPulse, prefersReducedMotion } from './lib/fx';
import { buildPeriods, type ChartPeriod, type OhlcCandle } from './lib/ohlc';
import { mountPriceChart, type PriceChartHandle, type ScrubInfo } from './lib/pricechart';
import { parseRawAmount, rawToHuman, fmtRaw, normalizeJupiterQuote, normalizeLifiQuote, fetchJupiterQuote, fetchJupiterSwapTx, fetchLifiQuote, verifyLifiEvmTx, solSwapVerdict, LIFI_SOLANA_CHAIN_ID, LIFI_NATIVE_EVM, LIFI_NATIVE_SOL, JUP_SOL_MINT, type SwapQuote } from './lib/swap';
import { STAKE_PROGRAM_ID, parseStakeAccountBytes, parseStakeAccountParsed, sortValidators, stakeStateOf, type StakeAccountInfo, type ValidatorInfo } from './lib/stake';
import { METADATA_PROGRAM_ID, TOKEN_PROGRAM_ID, TOKEN_2022_PROGRAM_ID, rewriteMediaUrl, parseMetaplexMetadata, metadataJsonFields, metadataAttributes, mediaCandidates, isSafeMediaUrl, safeMediaUrl, isSpamNft, normalizeBlockscoutNfts, type NftItem } from './lib/nfts';
import { buildNamespaces, classifyRequest, parseWcEvmTx, decodeWcSignMessage, decodeErc20Call, wcInit, wcPair, wcApprove, wcReject, wcRespond, wcRejectRequest, wcSessions, wcDisconnect, wcClientReady, wcWipeStorage, type WcAccounts } from './lib/walletconnect';
import { buildPickerAssets, filterSendableAssets, sortPickerAssets, pickerChainId, type PickerAsset } from './lib/pickerassets';
import { Connection, Keypair, PublicKey, SystemProgram, Transaction, VersionedTransaction, StakeProgram, Authorized, Lockup, LAMPORTS_PER_SOL } from '@solana/web3.js';
import { ethers } from 'ethers';
import QRCode from 'qrcode';
import bs58 from 'bs58';

export type ChainKind = 'evm' | 'solana' | 'solana-tw' | 'solana-phantom' | 'bitcoin' | 'tron' | 'xrp' | 'cosmos' | 'sui' | 'aptos';
interface Chain { id: string; name: string; symbol: string; cg: string; decimals: number; explorerAddr: string; explorerTx: string; evmId?: number; blockscout?: string; img: string; kind: ChainKind; rpc?: string; proxy?: boolean; custom?: boolean; }
const BASE_CHAINS: Chain[] = [
  { id: 'solana', name: 'Solana', symbol: 'SOL', cg: 'solana', decimals: 9, explorerAddr: 'https://solscan.io/account/', explorerTx: 'https://solscan.io/tx/', img: '/assets/coins/solana.png', kind: 'solana', proxy: true },
  { id: 'solana-tw', name: 'Solana (Trust Wallet)', symbol: 'SOL', cg: 'solana', decimals: 9, explorerAddr: 'https://solscan.io/account/', explorerTx: 'https://solscan.io/tx/', img: '/assets/coins/solana.png', kind: 'solana-tw', proxy: true },
  { id: 'solana-phantom', name: 'Solana (Phantom)', symbol: 'SOL', cg: 'solana', decimals: 9, explorerAddr: 'https://solscan.io/account/', explorerTx: 'https://solscan.io/tx/', img: '/assets/coins/solana.png', kind: 'solana-phantom', proxy: true },
  { id: 'ethereum', name: 'Ethereum', symbol: 'ETH', cg: 'ethereum', decimals: 18, explorerAddr: 'https://etherscan.io/address/', explorerTx: 'https://etherscan.io/tx/', evmId: 1, blockscout: 'https://eth.blockscout.com', img: '/assets/coins/ethereum.png', kind: 'evm', proxy: true },
  { id: 'polygon', name: 'Polygon', symbol: 'MATIC', cg: 'polygon-ecosystem-token', decimals: 18, explorerAddr: 'https://polygonscan.com/address/', explorerTx: 'https://polygonscan.com/tx/', evmId: 137, blockscout: 'https://polygon.blockscout.com', img: '/assets/coins/polygon.png', kind: 'evm', proxy: true },
  { id: 'bnb', name: 'BNB Chain', symbol: 'BNB', cg: 'binancecoin', decimals: 18, explorerAddr: 'https://bscscan.com/address/', explorerTx: 'https://bscscan.com/tx/', evmId: 56, blockscout: 'https://bsc.blockscout.com', img: '/assets/coins/bnb.png', kind: 'evm', proxy: true },
  { id: 'arbitrum', name: 'Arbitrum', symbol: 'ETH', cg: 'ethereum', decimals: 18, explorerAddr: 'https://arbiscan.io/address/', explorerTx: 'https://arbiscan.io/tx/', evmId: 42161, blockscout: 'https://arbitrum.blockscout.com', img: '/assets/coins/arbitrum.png', kind: 'evm', proxy: true },
  { id: 'base', name: 'Base', symbol: 'ETH', cg: 'ethereum', decimals: 18, explorerAddr: 'https://basescan.org/address/', explorerTx: 'https://basescan.org/tx/', evmId: 8453, blockscout: 'https://base.blockscout.com', img: '/assets/coins/base.png', kind: 'evm', proxy: true },
  { id: 'optimism', name: 'Optimism', symbol: 'ETH', cg: 'ethereum', decimals: 18, explorerAddr: 'https://optimistic.etherscan.io/address/', explorerTx: 'https://optimistic.etherscan.io/tx/', evmId: 10, img: '/assets/coins/optimism.png', kind: 'evm', proxy: true },
  { id: 'avalanche', name: 'Avalanche', symbol: 'AVAX', cg: 'avalanche-2', decimals: 18, explorerAddr: 'https://snowscan.xyz/address/', explorerTx: 'https://snowscan.xyz/tx/', evmId: 43114, img: '/assets/coins/avalanche.png', kind: 'evm', proxy: true },
  { id: 'fantom', name: 'Fantom', symbol: 'FTM', cg: 'fantom', decimals: 18, explorerAddr: 'https://ftmscan.com/address/', explorerTx: 'https://ftmscan.com/tx/', evmId: 250, img: '/assets/coins/fantom.png', kind: 'evm', proxy: true },
  { id: 'zksync', name: 'zkSync Era', symbol: 'ETH', cg: 'ethereum', decimals: 18, explorerAddr: 'https://era.zksync.network/address/', explorerTx: 'https://era.zksync.network/tx/', evmId: 324, img: '/assets/coins/zksync.png', kind: 'evm', proxy: true },
  { id: 'bitcoin', name: 'Bitcoin', symbol: 'BTC', cg: 'bitcoin', decimals: 8, explorerAddr: 'https://blockstream.info/address/', explorerTx: 'https://blockstream.info/tx/', img: '/assets/coins/bitcoin.png', kind: 'bitcoin' },
  { id: 'litecoin', name: 'Litecoin', symbol: 'LTC', cg: 'litecoin', decimals: 8, explorerAddr: 'https://litecoinspace.org/address/', explorerTx: 'https://litecoinspace.org/tx/', img: '/assets/coins/litecoin.png', kind: 'bitcoin' },
  { id: 'tron', name: 'TRON', symbol: 'TRX', cg: 'tron', decimals: 6, explorerAddr: 'https://tronscan.org/#/address/', explorerTx: 'https://tronscan.org/#/transaction/', img: '/assets/coins/tron.png', kind: 'tron' },
  { id: 'xrp', name: 'XRP Ledger', symbol: 'XRP', cg: 'ripple', decimals: 6, explorerAddr: 'https://xrpscan.com/account/', explorerTx: 'https://xrpscan.com/tx/', img: '/assets/coins/xrp.png', kind: 'xrp' },
  { id: 'cosmos', name: 'Cosmos Hub', symbol: 'ATOM', cg: 'cosmos', decimals: 6, explorerAddr: 'https://www.mintscan.io/cosmos/account/', explorerTx: 'https://www.mintscan.io/cosmos/tx/', img: '/assets/coins/cosmos.png', kind: 'cosmos' },
  { id: 'sui', name: 'Sui', symbol: 'SUI', cg: 'sui', decimals: 9, explorerAddr: 'https://suiscan.xyz/mainnet/account/', explorerTx: 'https://suiscan.xyz/mainnet/tx/', img: '/assets/coins/sui.png', kind: 'sui' },
  { id: 'aptos', name: 'Aptos', symbol: 'APT', cg: 'aptos', decimals: 8, explorerAddr: 'https://aptoscan.com/account/', explorerTx: 'https://aptoscan.com/transaction/', img: '/assets/coins/aptos.png', kind: 'aptos' },
];
const DEFAULT_ENABLED = ['solana', 'ethereum', 'polygon', 'bnb', 'arbitrum', 'base', 'optimism', 'avalanche', 'fantom', 'zksync', 'bitcoin', 'litecoin', 'tron', 'xrp', 'cosmos', 'sui', 'aptos'];
const TICKER_ITEMS: { cg: string; sym: string }[] = [
  { cg: 'bitcoin', sym: 'BTC' },
  { cg: 'ethereum', sym: 'ETH' },
  { cg: 'solana', sym: 'SOL' },
  { cg: 'binancecoin', sym: 'BNB' },
  { cg: 'polygon-ecosystem-token', sym: 'MATIC' },
];
// Welcome-surface coin icon (ticker items, hero label): the SHARED
// icons.ts resolution — real logo layered over the chrome monogram
// disc at 19px — never a bare <img> with a hardcoded path.
function tickIcon(cg: string, sym: string): string {
  const ch = CHAINS.find(c => c.cg === cg);
  return iconHTML(ch ? chainIconUrl(ch) : '', sym, ch?.name || sym, { tick: true });
}
// Icon rendering lives in lib/icons.ts (the single resolution path):
// real self-hosted logo over a chrome monogram tile; if the image ever
// fails to load it removes itself and the monogram shows through (CSP
// forbids inline handlers, hence this capture-phase listener).
document.addEventListener('error', (e) => { const t = e.target as HTMLElement; if (t && t.classList && (t.classList.contains('coinImg') || t.classList.contains('nftImg') || t.classList.contains('nftHero'))) t.remove(); }, true);
function coinIcon(c: Chain, lg = false): string { return chainIcon(c, lg); }
export let CHAINS: Chain[] = [...BASE_CHAINS];
function fmtCrypto(b: number, symbol: string): string {
  // Audit NEW HIGH (2026-11-19): the symbol can be attacker-controlled
  // (a crafted token/chain symbol persisted via Add-Token or a backup
  // import) and this string lands in innerHTML on Home AND on send /
  // swap REVIEW screens — escape it here, at the single choke point.
  if (b > 0 && Number(b.toFixed(4)) === 0) return `<0.0001 ${esc(symbol)}`;
  return `${b.toFixed(4)} ${esc(symbol)}`;
}
// Scoped to the current view (V()): during a navTo slide transition the
// leaving layer still holds the old screen's nodes — with the same ids —
// earlier in document order, so a document-wide query bound handlers
// (e.g. #bk) onto the dying layer and the new screen's controls were
// dead. Falls back to the document for shell-level elements.
const $ = (s: string) => (V().querySelector(s) || document.querySelector(s)) as HTMLElement;
const app = () => document.querySelector('#app') as HTMLElement;
const esc = (s: string) => s.replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]!));
const VAULT_KEY = 'syn-wallet-vault-v1'; const META_KEY = 'syn-wallet-meta-v1';
type Meta = { kind: 'mnemonic' | 'privateKey'; chain?: string; createdAt: number };
let secret: string | null = null; // active wallet's mnemonic OR private key (memory only)
let meta: Meta | null = null;
// Wave 1A: the vault now encrypts a multi-wallet payload. `secret`/`meta`
// above stay as mirrors of the ACTIVE wallet so every screen keeps working;
// `appPassword` is held in memory only while unlocked (same model as
// MetaMask's in-memory keyring) so wallet changes can re-encrypt the vault.
let vaultPayload: VaultPayload | null = null;
let flowMode: 'setup' | 'add' = 'setup';
async function unlockWithPassword(pw: string): Promise<boolean> {
  try {
    const plain = await decryptVault(getVault()!, pw);
    clearAuthFailures('unlock');
    const parsed = parseVaultPlaintext(plain, getMeta());
    vaultPayload = parsed.payload; appPassword = pw;
    if (parsed.migrated) await persistPayload();
    applyActiveWallet(); applyDataCache(); touchLock(); showApp('wallet');
    return true;
  } catch { return false; }
}
// ---------- flow entry context (first-run vs in-app add-wallet) ----------
// The create / import flows are shared between first-run onboarding
// (no wallet exists; exit = the welcome menu) and Settings → Add a
// wallet (an unlocked wallet exists; exit = back to the Wallets &
// accounts screen the user entered from). flowMode tracks which, and
// flowReturn captures the exact nav stack at entry so cancelling —
// or finishing — restores it. Flow screens replace #app wholesale
// (destroying #view + the tab bar), so returning also rebuilds the
// shell (shellMounted reset → mountShell remounts it).
let flowReturn: { stack: RouteEntry[]; idx: number } | null = null;
function enterAddFlow() { flowMode = 'add'; flowReturn = { stack: [...navStack], idx: navIdx }; }
function returnFromFlow() {
  pendingMnemonic = '';
  flowMode = 'setup';
  const r = flowReturn; flowReturn = null;
  shellMounted = false;
  if (r && r.stack.length) {
    navStack = r.stack; navIdx = Math.max(0, Math.min(r.idx, r.stack.length - 1));
    mountShell();
    history.replaceState({ i: navIdx }, '');
    renderRoute(navStack[navIdx], false);
  } else { goTab('settings'); go({ route: 'accounts' }); }
}
// Step-1 Back / Cancel of a shared flow: in-app it exits the flow
// (the half-finished wallet is discarded — nothing was written);
// first-run it lands on the welcome menu, as before.
function flowStepBack() { if (flowMode === 'add') returnFromFlow(); else showOnboarding(); }
async function finishAddWallet(plain: string, m: Meta) {
  if (!vaultPayload || !appPassword) return;
  const w: WalletEntry = { id: newWalletId(), name: m.kind === 'privateKey' ? 'Imported account' : 'Wallet ' + (vaultPayload.wallets.length + 1), kind: m.kind, secret: plain, chain: m.chain, createdAt: m.createdAt, accounts: 1 };
  vaultPayload.wallets.push(w); vaultPayload.activeId = w.id;
  await persistPayload();
  applyActiveWallet(); clearAccountCaches();
  // In-app completion returns INTO the app — the Wallets & accounts
  // screen, with the new wallet listed — never the first-run path.
  // The entry was encrypted with the EXISTING app password by
  // persistPayload (vault v2 semantics); no password step was shown.
  returnFromFlow();
}
function clearAccountCaches() { balances = new Map(); activityCache = new Map(); tokenBalances = new Map(); paintedVals.clear(); lastBalanceAt = 0; hlAcct = null; hlAcctAt = 0; hlAcctAddr = ''; hlAcctFailed = false; }
let appPassword: string | null = null;
function activeWallet(): WalletEntry | null { if (!vaultPayload) return null; return vaultPayload.wallets.find(w => w.id === vaultPayload!.activeId) || vaultPayload.wallets[0] || null; }
function accountIdx(): number { const w = activeWallet(); if (!w) return 0; return Math.max(0, Math.min(config.accountIndex[w.id] || 0, Math.max(0, w.accounts - 1))); }
function accKey(): string { const w = activeWallet(); return w ? w.id + ':' + accountIdx() : ''; }
function vaultSaveAlert() {
  if (document.getElementById('vaultSaveAlert')) return;
  const d = document.createElement('div');
  d.id = 'vaultSaveAlert';
  d.setAttribute('style', 'position:fixed;top:calc(10px + env(safe-area-inset-top));left:12px;right:12px;z-index:9999;background:#3a1420;border:1px solid #ff5c7a;color:#ffd7de;border-radius:14px;padding:12px 14px;font-size:13px;line-height:1.45;box-shadow:0 12px 32px rgba(0,0,0,.5)');
  d.textContent = 'Your wallet could not be saved on this device — storage is full or blocked. Free space or check the browser storage settings before making changes, or they will be lost when this tab closes.';
  const x = document.createElement('button');
  x.textContent = 'Dismiss'; x.setAttribute('style', 'margin-top:8px;background:transparent;border:1px solid #ff5c7a;color:#ffd7de;border-radius:999px;padding:5px 12px;font-size:12px');
  x.onclick = () => d.remove();
  d.appendChild(document.createElement('br')); d.appendChild(x);
  document.body.appendChild(d);
}
async function persistPayload() {
  if (!vaultPayload || !appPassword) return;
  const blob = await encryptVault(packVaultPayload(vaultPayload), appPassword);
  const text = JSON.stringify(blob);
  try { localStorage.setItem(VAULT_KEY, text); }
  catch {
    // Deep audit 2026-11-22: this was the one unguarded vault write
    // in the app — on a full/blocked store the new wallet state
    // silently never persisted. Free the disposable caches and retry
    // once; if it still fails, say so loudly and fail the operation —
    // a wallet that cannot save must never pretend it did.
    try { localStorage.removeItem(DATA_CACHE_KEY); localStorage.removeItem(SNAPS_KEY); } catch { /* ignore */ }
    try { localStorage.setItem(VAULT_KEY, text); }
    catch { vaultSaveAlert(); throw new Error('Could not save the wallet on this device — storage is full or blocked.'); }
  }
  const w = activeWallet(); if (w) localStorage.setItem(META_KEY, JSON.stringify({ kind: w.kind, chain: w.chain, createdAt: w.createdAt } satisfies Meta));
}
function applyActiveWallet() {
  const w = activeWallet();
  secret = w ? w.secret : null;
  meta = w ? { kind: w.kind, chain: w.chain, createdAt: w.createdAt } : null;
  setupDerived();
}
let derived: ReturnType<typeof deriveAll> | null = null;
let importedAddr = ''; let importedSolKp: Keypair | null = null;
let prices: any = null; let balances = new Map<string, number | null>();
let hideBal = false; let lockTimer: any = null; let chartTimer: any = null; let welcomeTimer: any = null;
// Balance snapshots: the total balance is recorded LOCALLY (localStorage)
// each time home loads; they power the balance change pill on home (delta vs
// the oldest snapshot in the last 24h). Nothing is sent to or stored on a server.
type Snap = { t: number; v: number };
const SNAPS_KEY = 'syn-wallet-portfolio-snaps-v1';
function loadSnaps(): Snap[] { try { const s = JSON.parse(localStorage.getItem(SNAPS_KEY) || '[]'); return Array.isArray(s) ? s.filter(x => x && typeof x.t === 'number' && typeof x.v === 'number') : []; } catch { return []; } }
function recordSnap(total: number) {
  const now = Date.now(); const snaps = loadSnaps(); const last = snaps[snaps.length - 1];
  if (last && now - last.t < 5 * 60 * 1000 && Math.abs(last.v - total) < 0.005) return;
  snaps.push({ t: now, v: total });
  // Audit L-5: the delta pill only ever reads a 20min–24h reference
  // window, so retention is capped at 48h / 300 points — the previous
  // 90-day / 2000-point history was plaintext financial history sitting
  // in localStorage far beyond any feature's need.
  const pruned = snaps.filter(s => s.t >= now - 48 * 3600000).slice(-300);
  try { localStorage.setItem(SNAPS_KEY, JSON.stringify(pruned)); } catch { /* storage full/blocked */ }
}

// ---------- central data store (stale-while-revalidate, local-only) ----------
// Prices, balances and activity rows are cached in memory AND persisted to
// localStorage, so every screen paints INSTANTLY from cache and refreshes in
// the background. Nothing here ever leaves the device (the cache is data the
// public chains/APIs already know — never keys or secrets).
// Activity rows carry a small presentation model alongside the label:
// dir/sym/amt/cp/st/img/cgid are populated ONLY where the source data
// honestly provides them (explorer value/from/to, the broadcast site's
// own amount+recipient for local records) — renderers derive or omit,
// never invent. amt is in whole asset units and is DISPLAY ONLY (send
// paths never read it back).
type ActDir = 'in' | 'out' | 'swap' | 'stake' | 'approve' | 'nft' | 'other';
type ActivityRow = { hash: string; label: string; sub: string; ts: number; chainId?: string; dir?: ActDir; sym?: string; amt?: number; cp?: string; st?: 'pending' | 'failed'; img?: string; cgid?: string };
let activityCache = new Map<string, ActivityRow[]>();
// Local broadcast records: every transaction THIS app broadcasts is written
// here the moment the network accepts it, so Activity shows it immediately.
// Chain explorers (Blockscout & co.) index slowly and are sometimes outright
// unreachable (Cloudflare challenges) — a send the user just made must never
// depend on them. A record reconciles away once the chain source returns
// the same hash (matched case-insensitively for hex hashes).
type LocalTx = { hash: string; chainId: string; label: string; ts: number; acc: string; dir?: ActDir; sym?: string; amt?: string; cp?: string; img?: string; cgid?: string };
const LOCALTX_KEY = 'syn-wallet-localtx-v1';
function loadLocalTxs(): LocalTx[] { try { const v = JSON.parse(localStorage.getItem(LOCALTX_KEY) || '[]'); return Array.isArray(v) ? v : []; } catch { return []; } }
function recordLocalTx(chainId: string, hash: string, label: string, extra?: { dir?: ActDir; sym?: string; amt?: string; cp?: string; img?: string; cgid?: string }) {
  if (!hash) return;
  try {
    const acc = accKey();
    const all = loadLocalTxs().filter(t => !(t.acc === acc && t.chainId === chainId && t.hash.toLowerCase() === hash.toLowerCase()));
    all.unshift({ hash, chainId, label, ts: Date.now(), acc, ...(extra || {}) });
    localStorage.setItem(LOCALTX_KEY, JSON.stringify(all.slice(0, 60)));
    updateTabDot();
  } catch { /* storage unavailable — Activity falls back to chain sources */ }
}
function localTxRows(chainId: string): ActivityRow[] {
  const acc = accKey();
  return loadLocalTxs().filter(t => t.acc === acc && t.chainId === chainId).map(t => {
    const n = t.amt != null && t.amt !== '' ? Number(t.amt) : NaN;
    return { hash: t.hash, label: t.label, sub: 'Sent from this device · confirming', ts: t.ts, dir: t.dir, sym: t.sym, amt: Number.isFinite(n) && n > 0 ? n : undefined, cp: t.cp, img: t.img, cgid: t.cgid, st: 'pending' as const };
  });
}
function pruneLocalTxs(chainId: string, fetched: ActivityRow[]) {
  try {
    const acc = accKey(); const hashes = new Set(fetched.map(r => r.hash.toLowerCase()));
    const all = loadLocalTxs();
    const kept = all.filter(t => !(t.acc === acc && t.chainId === chainId && hashes.has(t.hash.toLowerCase())));
    if (kept.length !== all.length) { localStorage.setItem(LOCALTX_KEY, JSON.stringify(kept)); updateTabDot(); }
  } catch { /* ignore */ }
}
// Audit M-9: recent counterparty addresses (recipients of sends made
// from this device, plus counterparties seen in fetched Activity) feed
// the address-poisoning check in BOTH send flows. Addresses only,
// capped at 100, stored locally like the local-tx records.
function loadCounterparties(): string[] { try { const v = JSON.parse(localStorage.getItem(COUNTERPARTY_KEY) || '[]'); return Array.isArray(v) ? v.filter((x: any) => typeof x === 'string') : []; } catch { return []; } }
function recordCounterparty(addr: string) {
  if (!addr || addr.length > 128) return;
  try { const all = loadCounterparties().filter(a => a !== addr); all.unshift(addr); localStorage.setItem(COUNTERPARTY_KEY, JSON.stringify(all.slice(0, 100))); } catch { /* storage unavailable */ }
}
const DATA_CACHE_KEY = 'syn-wallet-data-cache-v1';
function saveDataCache() {
  try {
    // Validator list + identities are public network data, cached so
    // the Stake screen paints instantly (names and icons included)
    // on the next cold start instead of waiting on Solana reads.
    let valInfo: [string, { name: string; skip: number | null; icon: string }][] | undefined;
    if (validatorInfo && stakeValidators.length) { const keep = new Set(stakeValidators.map(v => v.votePubkey)); valInfo = [...validatorInfo.entries()].filter(([k]) => keep.has(k)); }
    localStorage.setItem(DATA_CACHE_KEY, JSON.stringify({ prices, balances: Object.fromEntries(balances), activity: Object.fromEntries(activityCache), tokens: Object.fromEntries(tokenBalances), explore: exploreVals, promo: promoPolyCache, nfts: nftItems ? { items: nftItems.slice(0, 300), notes: nftNotes, forKey: nftForKey } : undefined, validators: stakeValidators.length ? stakeValidators.slice(0, 150) : undefined, valInfo, accKey: accKey(), at: Date.now() }));
  } catch { /* storage full/blocked */ }
}
let pendingCache: any = null;
function loadDataCache() {
  try {
    const j = JSON.parse(localStorage.getItem(DATA_CACHE_KEY) || 'null'); if (!j) return;
    if (j.prices) prices = j.prices; // prices are account-independent — safe to paint pre-unlock
    if (Array.isArray(j.validators) && j.validators.length) { stakeValidators = j.validators.filter((v: any) => v && typeof v.votePubkey === 'string'); stakeValidatorsAt = typeof j.at === 'number' ? j.at : 0; }
    if (Array.isArray(j.valInfo) && j.valInfo.length) validatorInfo = new Map(j.valInfo);
    pendingCache = j;
  } catch { /* ignore corrupt cache */ }
}
// Balances/activity belong to ONE wallet+account: they are only restored
// when the cache was written by the same account, so switching accounts can
// never paint another account's numbers, even briefly.
function applyDataCache() {
  if (!pendingCache) return;
  if (pendingCache.accKey && pendingCache.accKey === accKey()) {
    if (pendingCache.balances) balances = new Map(Object.entries(pendingCache.balances));
    if (pendingCache.activity) activityCache = new Map(Object.entries(pendingCache.activity));
    if (pendingCache.tokens) tokenBalances = new Map(Object.entries(pendingCache.tokens));
    if (pendingCache.explore && pendingCache.explore.key === pendingCache.accKey) exploreVals = pendingCache.explore;
    // The two announcement cards' data restores with the rest, so
    // neither card ever paints a loading state on a cold start: the
    // Predictions line shows the last trending market and Collectibles
    // shows the last NFT read, both refreshed silently in the
    // background (the NFT restore is flagged stale so the warms and
    // the screen revalidate it once).
    if (pendingCache.promo && pendingCache.promo.q) promoPolyCache = pendingCache.promo;
    if (pendingCache.nfts && pendingCache.nfts.forKey === pendingCache.accKey && Array.isArray(pendingCache.nfts.items)) {
      nftItems = pendingCache.nfts.items; nftNotes = pendingCache.nfts.notes || []; nftForKey = pendingCache.nfts.forKey; nftStale = true;
    }
  }
  pendingCache = null;
}
let tokenBalances = new Map<string, number | null>();
// ---------- load state: PENDING vs FAILED ----------
// A figure may be called "unavailable" ONLY after a fetch round for it
// has completed and failed. Until then it is PENDING and surfaces render
// a quiet loading placeholder — never the word "Unavailable" and never
// a fake 0. Prices settle as one round (pricesSettled); balances settle
// per chain/token: an entry exists in the map only once that fetch has
// completed, win (number) or lose (null).
let pricesSettled = false;
type LoadState = 'ok' | 'pending' | 'failed';
function priceStateOf(cgId: string | undefined): LoadState {
  if (!cgId) return 'failed'; // no price source exists for this asset at all
  if (prices?.[cgId]?.usd != null) return 'ok';
  return pricesSettled ? 'failed' : 'pending';
}
// Price entry for a token: CoinGecko-keyed first; tokens CoinGecko
// does not carry fall back to the Trust Wallet index entry, stored in
// the same map under the token's TW asset id (see fetchPrices).
function priceEntry(t: TokenDef): any | null {
  if (t.cg) return prices?.[t.cg] ?? null;
  const a = twAssetId(t.chainId, t.contract);
  return a ? (prices?.[a] ?? null) : null;
}
function tokenUsd(t: TokenDef): number | null { const e = priceEntry(t); return e?.usd ?? null; }
function tokenChg(t: TokenDef): number | null { const e = priceEntry(t); return e?.change24h ?? null; }
function balStateOf(id: string): LoadState {
  if (balances.get(id) != null) return 'ok';
  return balances.has(id) ? 'failed' : 'pending';
}
function tokStateOf(id: string): LoadState {
  if (tokenBalances.get(id) != null) return 'ok';
  return tokenBalances.has(id) ? 'failed' : 'pending';
}
// First-round gate for a cold boot (no cached data at all): showApp arms
// this promise, the first full refreshData round settles it, and the
// boot splash stays up until it settles (or a hard timeout releases it).
let firstRoundP: Promise<void> | null = null;
let firstRoundDone: (() => void) | null = null;
function armFirstRound(): Promise<void> {
  if (!firstRoundP) firstRoundP = new Promise<void>(r => { firstRoundDone = r; });
  return firstRoundP;
}
function settleFirstRound() { if (firstRoundDone) { const r = firstRoundDone; firstRoundDone = null; r(); } }
// In-place value updates with a subtle tint flash when a figure changes.
const paintedVals = new Map<string, number>();
let homeSortSig = '';
function flashSet(el: HTMLElement | null, key: string, text: string, val?: number | null) {
  if (!el) return;
  const prev = paintedVals.get(key);
  el.textContent = text;
  if (val != null && prev != null && val !== prev) { el.classList.remove('flashUp', 'flashDown'); void el.offsetWidth; el.classList.add(val > prev ? 'flashUp' : 'flashDown'); }
  if (val != null) paintedVals.set(key, val);
}
// Background refresh: prices first (cheap), balances on their own cadence.
// One chain failing (e.g. Polygon's flaky RPC) never blocks the others —
// fetchBalance already resolves null per chain and Promise.all settles all.
let lastBalanceAt = 0;
async function refreshData(forceBalances = false) {
  await fetchPrices();
  if (forceBalances || Date.now() - lastBalanceAt >= 40000) {
    lastBalanceAt = Date.now();
    await Promise.all(visibleChains().map(async c => balances.set(c.id, await fetchBalance(c))));
    await probeSolTW();
    await Promise.all(visibleTokens().map(async t => tokenBalances.set(t.id, await fetchTokenBalance(t))));
    saveDataCache();
    settleFirstRound();
  }
  paintLive();
}
// Trust Wallet derives Solana at m/44'/501'/acct' — a different address from
// the same words. Probe it in the background: if it holds funds, or the
// Phantom-path account is empty, both Solana accounts are surfaced (the TW
// one clearly labelled) so an imported Trust Wallet seed finds its address.
async function probeSolTW() {
  if (!meta || meta.kind !== 'mnemonic' || !derived2) return;
  const tw = findChain('solana-tw'); if (!tw) return;
  const twBal = await fetchBalance(tw);
  if (twBal != null) balances.set('solana-tw', twBal);
  const phBal = balances.get('solana');
  const shouldShow = twBal != null && (twBal > 0 || phBal === 0);
  if (shouldShow !== showSolTW) { showSolTW = shouldShow; if (shellMounted && currentRoute === 'wallet') renderRoute({ route: 'wallet' }); }
}
// Live engine: one loop while unlocked. Prices ~25s, balances ~40-50s.
// Pauses itself when the tab is hidden (ticks are skipped, nothing blanks);
// on return it refreshes silently in place.
let engineTimer: any = null; let engineTicks = 0;
function startEngine() {
  if (engineTimer) return;
  engineTimer = setInterval(async () => {
    if (document.hidden || !secret) return;
    engineTicks++; (window as any).__synTicks = engineTicks;
    await fetchPrices(); paintLive();
    // Chart prefetch re-warm rides the engine's cadence (which already
    // pauses while the tab is hidden) — no separate polling loop.
    if (Date.now() - chartPrefetchAt >= 10 * 60 * 1000) void prefetchCharts();
    if (Date.now() - lastBalanceAt >= 40000) {
      lastBalanceAt = Date.now();
      await Promise.all(visibleChains().map(async c => balances.set(c.id, await fetchBalance(c))));
      await probeSolTW();
      await Promise.all(visibleTokens().map(async t => tokenBalances.set(t.id, await fetchTokenBalance(t))));
      saveDataCache(); paintLive();
    }
  }, 25000);
}
function paintLive() {
  if (!shellMounted) return;
  if (currentRoute === 'wallet') paintHomeValues();
  else if (currentRoute === 'asset' && currentChain) paintDetailValues(CHAINS.find(x => x.id === currentChain)!);
  else if (currentRoute === 'token') paintTokenValues();
  else if (currentRoute === 'swap') onSwapPricesTick();
}
let currentTokenId = '';
// Addition 5: when a grouped token's "By network" row is tapped, the
// single-chain view for that member is shown; this marks which member
// is focused so showToken renders the classic per-chain layout (and
// its back returns to the aggregated view) instead of re-aggregating.
let tokenFocusChain: string | null = null;
function solanaRpcUrl(): string { return config.rpcOverrides['solana'] || rpcUrl('solana'); }
async function solanaRpcCall(method: string, params: any[]): Promise<any> {
  const url = config.rpcOverrides['solana'];
  if (!url) return rpc('solana', method, params);
  const r = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) });
  const j = await r.json(); if (j.error) throw new Error(j.error.message || 'RPC error'); return j.result;
}

function getVault(): VaultBlob | null { try { const r = localStorage.getItem(VAULT_KEY); return r ? JSON.parse(r) : null; } catch { return null; } }
function getMeta(): Meta | null { try { const r = localStorage.getItem(META_KEY); return r ? JSON.parse(r) : null; } catch { return null; } }
async function saveVault(plain: string, password: string, m: Meta) {
  const w: WalletEntry = { id: newWalletId(), name: m.kind === 'privateKey' ? 'Imported account' : 'Main wallet', kind: m.kind, secret: plain, chain: m.chain, createdAt: m.createdAt, accounts: 1 };
  vaultPayload = { v: 2, wallets: [w], activeId: w.id };
  appPassword = password;
  await persistPayload();
  applyActiveWallet();
}
function setupDerived() {
  derived = null; derived2 = null; importedAddr = ''; importedSolKp = null;
  if (!secret || !meta) return;
  if (meta.kind === 'mnemonic') { derived2 = deriveAll2(secret, accountIdx()); derived = derived2; }
  else if (meta.chain === 'solana') { const raw = bs58.decode(secret); importedSolKp = raw.length === 64 ? Keypair.fromSecretKey(raw) : Keypair.fromSeed(raw.slice(0, 32)); importedAddr = importedSolKp.publicKey.toBase58(); }
  else { importedAddr = new ethers.Wallet(secret.startsWith('0x') ? secret : '0x' + secret).address; }
}
function addressFor(c: Chain): string {
  if (!c || !meta) return '';
  if (meta.kind === 'privateKey') {
    if (meta.chain === 'solana') return c.kind === 'solana' ? importedAddr : '';
    return c.kind === 'evm' ? importedAddr : '';
  }
  if (!derived2) return '';
  switch (c.kind) {
    case 'solana': return derived2.solAddress;
    case 'solana-tw': return derived2.solTWAddress;
    case 'solana-phantom': return derived2.solPhantomAddress;
    case 'bitcoin': return c.id === 'litecoin' ? derived2.ltcAddress : derived2.btcAddress;
    case 'tron': return derived2.tronAddress;
    case 'xrp': return derived2.xrpAddress;
    case 'cosmos': return derived2.cosmosAddress;
    case 'sui': return derived2.suiAddress;
    case 'aptos': return derived2.aptosAddress;
    case 'evm': return derived2.evmAddress;
    default: return '';
  }
}
function visibleChains(): Chain[] { const en = enabledSet(); return CHAINS.filter(c => en.has(c.id === 'solana-tw' || c.id === 'solana-phantom' ? 'solana' : c.id) && (c.id !== 'solana-tw' || showSolTW) && addressFor(c)); }
// ---------- app config + chain assembly (Wave 1A) ----------
// Non-secret app configuration lives in localStorage next to the vault:
// enabled networks, custom networks, RPC overrides, custom tokens, the
// selected account per wallet, and the passkey wrap. None of it is key
// material; all of it stays on this device only.
export interface TokenDef { id: string; chainId: string; contract: string; name: string; symbol: string; decimals: number; cg?: string; builtin?: boolean; logo?: boolean; }
interface CustomNet { id: string; name: string; rpc: string; chainId: number; symbol: string; explorer: string; }
interface PasskeyCfg { credId: string; salt: string; wrap: KeyWrapBlob; }
interface AppConfig { enabled: string[] | null; customNetworks: CustomNet[]; rpcOverrides: Record<string, string>; tokens: TokenDef[]; hiddenTokens: string[]; addedTokens: string[]; accountIndex: Record<string, number>; passkey: PasskeyCfg | null; hiddenNfts: string[]; reportedNfts: string[]; spamOkNfts: string[]; waveFx: boolean; }
const CONFIG_KEY = 'syn-wallet-config-v1';
// Built-in stablecoins — every contract below was verified ON-CHAIN during
// the Wave 1A build (symbol() + decimals() read back from the contract
// itself via public RPC, 2026-11-18; Solana mints via getTokenSupply).
const BUILTIN_TOKENS: TokenDef[] = [
  { id: 'bt-eth-usdt', chainId: 'ethereum', contract: '0xdAC17F958D2ee523a2206206994597C13D831ec7', name: 'Tether USD', symbol: 'USDT', decimals: 6, cg: 'tether', builtin: true },
  { id: 'bt-eth-usdc', chainId: 'ethereum', contract: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48', name: 'USD Coin', symbol: 'USDC', decimals: 6, cg: 'usd-coin', builtin: true },
  { id: 'bt-pol-usdt', chainId: 'polygon', contract: '0xc2132D05D31c914a87C6611C10748AEb04B58e8F', name: 'Tether USD', symbol: 'USDT', decimals: 6, cg: 'tether', builtin: true },
  { id: 'bt-pol-usdc', chainId: 'polygon', contract: '0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359', name: 'USD Coin', symbol: 'USDC', decimals: 6, cg: 'usd-coin', builtin: true },
  { id: 'bt-bnb-usdt', chainId: 'bnb', contract: '0x55d398326f99059fF775485246999027B3197955', name: 'Tether USD', symbol: 'USDT', decimals: 18, cg: 'tether', builtin: true },
  { id: 'bt-bnb-usdc', chainId: 'bnb', contract: '0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d', name: 'USD Coin', symbol: 'USDC', decimals: 18, cg: 'usd-coin', builtin: true },
  { id: 'bt-arb-usdt', chainId: 'arbitrum', contract: '0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9', name: 'Tether USD', symbol: 'USDT', decimals: 6, cg: 'tether', builtin: true },
  { id: 'bt-arb-usdc', chainId: 'arbitrum', contract: '0xaf88d065e77c8cC2239327C5EDb3A432268e5831', name: 'USD Coin', symbol: 'USDC', decimals: 6, cg: 'usd-coin', builtin: true },
  { id: 'bt-base-usdc', chainId: 'base', contract: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913', name: 'USD Coin', symbol: 'USDC', decimals: 6, cg: 'usd-coin', builtin: true },
  { id: 'bt-op-usdt', chainId: 'optimism', contract: '0x94b008aA00579c1307B0EF2c499aD98a8ce58e58', name: 'Tether USD', symbol: 'USDT', decimals: 6, cg: 'tether', builtin: true },
  { id: 'bt-op-usdc', chainId: 'optimism', contract: '0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85', name: 'USD Coin', symbol: 'USDC', decimals: 6, cg: 'usd-coin', builtin: true },
  { id: 'bt-avax-usdt', chainId: 'avalanche', contract: '0x9702230A8Ea53601f5cD2dc00fDBc13d4dF4A8c7', name: 'Tether USD', symbol: 'USDT', decimals: 6, cg: 'tether', builtin: true },
  { id: 'bt-avax-usdc', chainId: 'avalanche', contract: '0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E', name: 'USD Coin', symbol: 'USDC', decimals: 6, cg: 'usd-coin', builtin: true },
  { id: 'bt-sol-usdc', chainId: 'solana', contract: 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v', name: 'USD Coin', symbol: 'USDC', decimals: 6, cg: 'usd-coin', builtin: true },
  { id: 'bt-sol-usdt', chainId: 'solana', contract: 'Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB', name: 'Tether USD', symbol: 'USDT', decimals: 6, cg: 'tether', builtin: true },
  // Lido stETH — contract verified on-chain during the Wave 2 build
  // (name() = "Liquid staked Ether 2.0", symbol() = "stETH", code present).
  { id: 'bt-eth-steth', chainId: 'ethereum', contract: '0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84', name: 'Lido Staked Ether', symbol: 'stETH', decimals: 18, cg: 'staked-ether', builtin: true },
  // pUSD — Polymarket's V2 collateral on Polygon; REQUIRED to trade
  // there, so it is a first-class built-in, not just a catalog entry.
  // Verified on-chain 2026-11-20 via Polygon RPC: name() =
  // "Polymarket USD", symbol() = "pUSD", decimals() = 6; CoinGecko id
  // 'polymarket-usd' prices it (~$0.999).
  { id: 'bt-pol-pusd', chainId: 'polygon', contract: '0xC011a7E12a19f7B1f670d46F03B03f3342E82DFB', name: 'Polymarket USD', symbol: 'pUSD', decimals: 6, cg: 'polymarket-usd', builtin: true },
];
let config: AppConfig = { enabled: null, customNetworks: [], rpcOverrides: {}, tokens: [], hiddenTokens: [], addedTokens: [], accountIndex: {}, passkey: null, hiddenNfts: [], reportedNfts: [], spamOkNfts: [], waveFx: true };
// Audit NEW MEDIUM + M-5 (2026-11-19): config is a trust boundary —
// it can arrive from a backup FILE, and its fields (custom RPCs,
// explorer prefixes, token/chain names+symbols) steer requests and
// render on review screens. Every entry is re-validated on load with
// the same rules the manual Add flows enforce; anything failing is
// dropped, never rendered or dialled.
function sanitizeCustomNet(n: any): CustomNet | null {
  if (!n || typeof n !== 'object') return null;
  const name = sanitizeTokenText(typeof n.name === 'string' ? n.name : '', 'name');
  const symbol = sanitizeTokenText(typeof n.symbol === 'string' ? n.symbol : '', 'symbol');
  if (!name || !symbol) return null;
  if (typeof n.id !== 'string' || !/^[a-zA-Z0-9-]{1,64}$/.test(n.id)) return null;
  if (typeof n.rpc !== 'string' || !/^https:\/\//i.test(n.rpc) || n.rpc.length > 300) return null;
  if (!Number.isSafeInteger(n.chainId) || n.chainId <= 0) return null;
  const explorer = typeof n.explorer === 'string' && /^https:\/\//i.test(n.explorer) && n.explorer.length <= 200 ? n.explorer : '';
  return { id: n.id, name, rpc: n.rpc, chainId: n.chainId, symbol, explorer };
}
function sanitizeTokenDef(t: any): TokenDef | null {
  if (!t || typeof t !== 'object') return null;
  const name = sanitizeTokenText(t.name, 'name');
  const symbol = sanitizeTokenText(t.symbol, 'symbol');
  if (!name || !symbol) return null;
  if (typeof t.id !== 'string' || !/^[a-zA-Z0-9-]{1,80}$/.test(t.id)) return null;
  if (typeof t.chainId !== 'string' || !/^[a-zA-Z0-9-]{1,40}$/.test(t.chainId)) return null;
  if (typeof t.contract !== 'string' || t.contract.length > 128) return null;
  const base = BASE_CHAINS.find(c => c.id === t.chainId);
  if (base?.kind === 'evm' && !/^0x[0-9a-fA-F]{40}$/.test(t.contract)) return null;
  if ((base?.kind === 'solana' || base?.kind === 'solana-tw' || base?.kind === 'solana-phantom') && !/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(t.contract)) return null;
  if (!Number.isInteger(t.decimals) || t.decimals < 0 || t.decimals > 36) return null;
  return { id: t.id, chainId: t.chainId, contract: t.contract, name, symbol, decimals: t.decimals, cg: typeof t.cg === 'string' && /^[a-z0-9-]{1,60}$/.test(t.cg) ? t.cg : undefined, builtin: t.builtin === true ? true : undefined, logo: t.logo === true ? true : undefined };
}
function sanitizeRpcOverrides(o: any): Record<string, string> {
  const out: Record<string, string> = {};
  if (o && typeof o === 'object') for (const [k, v] of Object.entries(o)) if (/^[a-zA-Z0-9-]{1,40}$/.test(k) && typeof v === 'string' && /^https:\/\//i.test(v) && v.length <= 300) out[k] = v;
  return out;
}
function loadConfig() {
  try {
    const j = JSON.parse(localStorage.getItem(CONFIG_KEY) || 'null');
    if (j && typeof j === 'object') config = { enabled: Array.isArray(j.enabled) ? j.enabled.filter((x: any) => typeof x === 'string') : null, customNetworks: Array.isArray(j.customNetworks) ? j.customNetworks.map(sanitizeCustomNet).filter(Boolean) as CustomNet[] : [], rpcOverrides: sanitizeRpcOverrides(j.rpcOverrides), tokens: Array.isArray(j.tokens) ? j.tokens.map(sanitizeTokenDef).filter(Boolean) as TokenDef[] : [], hiddenTokens: Array.isArray(j.hiddenTokens) ? j.hiddenTokens.filter((x: any) => typeof x === 'string') : [], addedTokens: Array.isArray(j.addedTokens) ? j.addedTokens.filter((x: any) => typeof x === 'string') : [], accountIndex: j.accountIndex && typeof j.accountIndex === 'object' ? j.accountIndex : {}, passkey: j.passkey || null, hiddenNfts: Array.isArray(j.hiddenNfts) ? j.hiddenNfts : [], reportedNfts: Array.isArray(j.reportedNfts) ? j.reportedNfts : [], spamOkNfts: Array.isArray(j.spamOkNfts) ? j.spamOkNfts : [], waveFx: j.waveFx !== false };
  } catch { /* fresh config */ }
  rebuildChains();
}
function saveConfig() { try { localStorage.setItem(CONFIG_KEY, JSON.stringify(config)); } catch { /* storage full/blocked */ } rebuildChains(); }
function rebuildChains() {
  const out: Chain[] = [...BASE_CHAINS];
  const seenEvm = new Set(out.filter(c => c.evmId).map(c => c.evmId!));
  for (const n of config.customNetworks) {
    if (seenEvm.has(n.chainId)) continue; seenEvm.add(n.chainId);
    out.push({ id: n.id, name: n.name, symbol: n.symbol, cg: '', decimals: 18, explorerAddr: n.explorer ? n.explorer.replace(/\/$/, '') + '/address/' : '', explorerTx: n.explorer ? n.explorer.replace(/\/$/, '') + '/tx/' : '', evmId: n.chainId, img: '', kind: 'evm', rpc: n.rpc, custom: true });
  }
  for (const r of EVM_REGISTRY) {
    if (seenEvm.has(r.chainId)) continue; seenEvm.add(r.chainId);
    out.push({ id: 'evm-' + r.chainId, name: r.name, symbol: r.symbol, cg: r.cg, decimals: 18, explorerAddr: r.explorer ? r.explorer + '/address/' : '', explorerTx: r.explorer ? r.explorer + '/tx/' : '', evmId: r.chainId, img: '', kind: 'evm', rpc: r.rpc, proxy: r.rpc === '' });
  }
  CHAINS = out;
}
function findChain(id: string): Chain | undefined { return CHAINS.find(c => c.id === id); }
function enabledSet(): Set<string> { return new Set(config.enabled ?? DEFAULT_ENABLED); }
function visibleTokens(): TokenDef[] {
  const all = [...BUILTIN_TOKENS.filter(t => !config.tokens.some(x => x.id === t.id)), ...config.tokens];
  // pickerChainId: a token stored against 'solana-tw' keys its enabled
  // check on 'solana' (visibleChains does the same mapping) — without
  // it such tokens were invisible in EVERY list, Home and pickers alike.
  return all.filter(t => !config.hiddenTokens.includes(t.id) && enabledSet().has(pickerChainId(t.chainId)) && !!addressFor(findChain(t.chainId) || ({} as Chain)));
}
// ---------- token grouping by canonical asset (Addition 5) ----------
// Home's Tokens section groups the per-chain rows of the SAME canonical
// asset into one row. The grouping key is the built-in registry's
// CoinGecko asset id, and ONLY for exact built-in registry entries (id +
// contract + cg all matching BUILTIN_TOKENS) — never symbol matching: a
// custom token that merely copies a ticker (the classic fake-USDC scam)
// is not a registry entry, so it always stays its own row and is never
// folded into a canonical total. Display-only: balances, the Home total
// and every send/swap path keep working per chain+contract as before.
interface TokenGroup { key: string; asset: string | null; members: TokenDef[]; rep: TokenDef; }
function tokenGroupKey(t: TokenDef): string {
  if (t.cg && BUILTIN_TOKENS.some(b => b.id === t.id && b.contract === t.contract && b.cg === t.cg)) return 'asset:' + t.cg;
  return 'single:' + t.id;
}
function tokenGroups(): TokenGroup[] {
  const map = new Map<string, TokenDef[]>();
  for (const t of visibleTokens()) { const k = tokenGroupKey(t); const arr = map.get(k); if (arr) arr.push(t); else map.set(k, [t]); }
  return [...map.entries()].map(([key, members]) => ({ key, asset: key.startsWith('asset:') ? key.slice(6) : null, members, rep: members[0] }));
}
function groupOf(t: TokenDef): TokenGroup { const k = tokenGroupKey(t); return tokenGroups().find(g => g.key === k) || { key: k, asset: null, members: [t], rep: t }; }
function groupPrice(g: TokenGroup): number | null { const cg = g.asset || g.rep.cg; return cg ? (prices?.[cg]?.usd ?? null) : null; }
function groupChange(g: TokenGroup): number | null { const cg = g.asset || g.rep.cg; return cg ? (prices?.[cg]?.change24h ?? null) : null; }
function groupTotals(g: TokenGroup): { amount: number | null; fiat: number | null; pending: boolean; held: boolean } {
  let amount = 0; let any = false; let pending = false;
  for (const m of g.members) { const b = tokenBalances.get(m.id); if (b == null) { if (!tokenBalances.has(m.id)) pending = true; continue; } amount += b; any = true; }
  const p = groupPrice(g);
  return { amount: any ? amount : null, fiat: any && p != null ? amount * p : null, pending, held: any && amount > 0 };
}
function tokenShowsOnHome(t: TokenDef): boolean {
  if (config.addedTokens.includes(t.id)) return true; // owner pinned it from Add token
  // Member-level version of the group rule in visibleTokenGroups: a
  // canonical (cross-chain) asset's member shows on Home when it is
  // held on that network or its balance there is still loading;
  // custom singles always show.
  if (groupOf(t).asset == null) return true;
  return !tokenBalances.has(t.id) || (tokenBalances.get(t.id) ?? 0) > 0;
}
function tokenFiat(t: TokenDef): number | null {
  const b = tokenBalances.get(t.id); if (b == null) return null;
  const pr = tokenUsd(t);
  return pr != null ? b * pr : null;
}
function homeTokenRowsHTML(): string {
  // Wave 21b (owner correction): NO per-network blocks — natives and
  // tokens from every network live in ONE Tokens list, sorted by
  // value; each row names its own network.
  const rows: { fiat: number | null; html: string }[] = [];
  for (const c of sortedChains()) { const b = balances.get(c.id); const pr = priceOf(c); rows.push({ fiat: b != null && pr != null ? b * pr : null, html: homeRowHTML(c) }); }
  for (const t of visibleTokens()) { if (!tokenShowsOnHome(t)) continue; rows.push({ fiat: tokenFiat(t), html: tokenRowHTML(singleGroup(t)) }); }
  rows.sort((a, b) => { if (a.fiat == null && b.fiat == null) return 0; if (a.fiat == null) return 1; if (b.fiat == null) return -1; return b.fiat - a.fiat; });
  return rows.map(r => r.html).join('');
}
function singleGroup(t: TokenDef): TokenGroup { return { key: 'single:' + t.id, asset: null, members: [t], rep: t }; }
function visibleTokenGroups(): TokenGroup[] {
  // A canonical group appears only when the asset is held on at least
  // one network (or its balances are still loading — pending is never
  // read as zero). Custom singles always show: the user added them
  // explicitly. Sorted by total fiat desc.
  const gs = tokenGroups().filter(g => g.asset == null || groupTotals(g).held || g.members.some(m => !tokenBalances.has(m.id)));
  return gs.sort((a, b2) => { const fa = groupTotals(a).fiat, fb = groupTotals(b2).fiat; if (fa == null && fb == null) return 0; if (fa == null) return 1; if (fb == null) return -1; return fb - fa; });
}
let derived2: DerivedAccounts2 | null = null;
let showSolTW = false;
const AUTOLOCK_KEY = 'syn-wallet-autolock-min';
function autoLockMin(): number { const v = Number(localStorage.getItem(AUTOLOCK_KEY)); return [1, 5, 15].includes(v) ? v : 5; }
// Audit M-2 (2026-11-19): auto-lock is driven by an ACTIVITY TIMESTAMP,
// not a lone setTimeout. Timers freeze in a suspended/backgrounded tab,
// so on pointerdown (capture phase — before the tapped control runs),
// on visibility return, on focus and on a slow interval we compare the
// elapsed time against the setting and lock FIRST if it has passed.
let lastActiveAt = Date.now();
function touchLock() { lastActiveAt = Date.now(); clearTimeout(lockTimer); lockTimer = setTimeout(() => lock(), autoLockMin() * 60 * 1000); }
function autoLockOverdue(): boolean { return !!secret && Date.now() - lastActiveAt > autoLockMin() * 60 * 1000; }
// Audit fix: market cards and the Invest promo card are divs with
// role="button" + tabindex but only mouse/touch wiring — keyboard and
// switch users could focus them and Enter/Space did nothing. One
// delegated handler activates them like a click. Elements with their
// own keydown (position rows) preventDefault, which skips this.
document.addEventListener('keydown', (e) => {
  if (e.defaultPrevented || (e.key !== 'Enter' && e.key !== ' ')) return;
  const t = e.target as HTMLElement;
  const el = t?.closest?.('[data-polym], [data-poly-pos], #promoPolyCard') as HTMLElement | null;
  if (!el || el.tagName === 'BUTTON' || t.closest('button, a, input, textarea, select')) return;
  e.preventDefault();
  el.click();
});
document.addEventListener('pointerdown', () => { if (autoLockOverdue()) lock(); }, true);
document.addEventListener('pointerdown', touchLock);
document.addEventListener('visibilitychange', () => { document.documentElement.classList.toggle('animPaused', document.hidden); if (!document.hidden && autoLockOverdue()) lock(); });
window.addEventListener('focus', () => { if (autoLockOverdue()) lock(); });
setInterval(() => { if (autoLockOverdue()) lock(); }, 20000);
// Deep audit 2026-11-22: two unlocked tabs hold two in-memory copies
// of the vault payload, and a save from the staler tab would silently
// overwrite the fresher tab's wallets/accounts (last-writer-wins on
// the whole encrypted blob). If ANOTHER tab rewrites or wipes the
// vault while this tab is unlocked, lock this tab — unlocking again
// reloads the fresh payload instead of clobbering it.
window.addEventListener('storage', (e) => { if (e.key === VAULT_KEY && secret) lock(); });
// ---------- persisted auth-failure throttling (audit M-3) ----------
// Failure state lives in localStorage (survives new tabs and reloads —
// sessionStorage let an attacker reset the clock by opening a tab),
// the cap escalates to 15 minutes, and passkey-unwrap failures count
// against the same unlock counter (the passkey path used to bypass it).
const FAIL_KEY = 'syn-wallet-fails-v1';
interface FailState { unlock: number; unlockWaitUntil: number; reveal: number; revealWaitUntil: number; }
function failState(): FailState { try { const j = JSON.parse(localStorage.getItem(FAIL_KEY) || 'null'); if (j && typeof j === 'object') return { unlock: Number(j.unlock) || 0, unlockWaitUntil: Number(j.unlockWaitUntil) || 0, reveal: Number(j.reveal) || 0, revealWaitUntil: Number(j.revealWaitUntil) || 0 }; } catch { /* fresh */ } return { unlock: 0, unlockWaitUntil: 0, reveal: 0, revealWaitUntil: 0 }; }
function saveFailState(s: FailState) { try { localStorage.setItem(FAIL_KEY, JSON.stringify(s)); } catch { /* storage blocked */ } }
function noteAuthFailure(kind: 'unlock' | 'reveal'): number { const s = failState(); const f = kind === 'unlock' ? ++s.unlock : ++s.reveal; const wait = f < 3 ? 0 : Math.min(900000, 2000 * 2 ** (f - 3)); if (kind === 'unlock') s.unlockWaitUntil = Date.now() + wait; else s.revealWaitUntil = Date.now() + wait; saveFailState(s); return wait; }
function authWaitRemaining(kind: 'unlock' | 'reveal'): number { const s = failState(); return Math.max(0, (kind === 'unlock' ? s.unlockWaitUntil : s.revealWaitUntil) - Date.now()); }
function clearAuthFailures(kind: 'unlock' | 'reveal') { const s = failState(); if (kind === 'unlock') { s.unlock = 0; s.unlockWaitUntil = 0; } else { s.reveal = 0; s.revealWaitUntil = 0; } saveFailState(s); }
// iOS collapsing large title: on the tab screens (Wallet has its own
// topbar; Activity/Settings carry .ltWrap) the 28px title shrinks into a
// compact frosted bar once the user scrolls — a class toggle on a rAF
// flag, transform/font-size transition in CSS, no per-frame DOM work.
let ltTicking = false;
window.addEventListener('scroll', () => {
  if (ltTicking) return; ltTicking = true;
  requestAnimationFrame(() => {
    ltTicking = false;
    const w = document.querySelector('.ltWrap');
    if (w) w.classList.toggle('ltSmall', window.scrollY > 30);
  });
}, { passive: true });
// Audit M-1 + M-6 + H-3 (2026-11-19): ONE session teardown and ONE
// full local wipe, shared by lock(), both wipe paths and backup
// import. The old lock() left the imported Solana Keypair, the pending
// mnemonic, the sign-tool draft and every send draft alive in memory;
// the old wipes left the local-tx records, the 90-day portfolio
// snapshots, the OHLC cache and the throttle counters behind.
function clearSessionSecrets() {
  cleanupKeyGate();
  secret = null; derived = null; derived2 = null; vaultPayload = null; appPassword = null;
  importedSolKp = null; importedAddr = ''; pendingMnemonic = ''; signDraftText = ''; signParsed = null;
  sendDrafts.clear();
  tokenBalances = new Map(); balances = new Map(); activityCache = new Map(); paintedVals.clear();
}
const COUNTERPARTY_KEY = 'syn-wallet-counterparties-v1';
function wipeAllLocalState() {
  clearSessionSecrets();
  for (const k of [VAULT_KEY, META_KEY, CONFIG_KEY, DATA_CACHE_KEY, LOCALTX_KEY, SNAPS_KEY, OHLC_CACHE_KEY, AUTOLOCK_KEY, FAIL_KEY, COUNTERPARTY_KEY]) { try { localStorage.removeItem(k); } catch { /* ignore */ } }
  try { sessionStorage.clear(); } catch { /* ignore */ }
  config = { enabled: null, customNetworks: [], rpcOverrides: {}, tokens: [], hiddenTokens: [], addedTokens: [], accountIndex: {}, passkey: null, hiddenNfts: [], reportedNfts: [], spamOkNfts: [], waveFx: true };
  CHAINS = [...BASE_CHAINS];
  void wcWipeStorage(); // audit M-10: SDK storage outside the vault goes too
}
function lock() { clearSessionSecrets(); clearInterval(chartTimer); shellMounted = false; navStack = []; navIdx = -1; currentRoute = ''; showUnlock(); }
async function copySecret(t: string, btn?: HTMLElement, onClearFail?: () => void) {
  await copyText(t, btn);
  setTimeout(async () => {
    // Audit L-2: the 20s auto-clear used to fail silently (denied
    // read-back + failed fallback write left the secret on the
    // clipboard forever). If the clear cannot be confirmed, say so.
    let cleared = false;
    try {
      const cur = await navigator.clipboard.readText();
      if (cur === t) { await navigator.clipboard.writeText(''); }
      cleared = true;
    } catch {
      try { await navigator.clipboard.writeText(''); cleared = true; } catch { /* cannot clear */ }
    }
    if (!cleared && onClearFail) onClearFail();
  }, 20000);
}
async function copyText(t: string, btn?: HTMLElement) { try { await navigator.clipboard.writeText(t); if (btn) { const o = btn.innerHTML; btn.innerHTML = '<i class="ri-check-line"></i>'; setTimeout(() => btn.innerHTML = o, 1200); } } catch { /* clipboard unavailable */ } }

// ---------- onboarding (auth-card pattern) ----------
function shell(inner: string, hero = false, opts: { centered?: boolean; bg?: boolean } = {}): string { clearInterval(chartTimer); clearInterval(welcomeTimer); const httpWarn = location.protocol === 'http:' && !['localhost','127.0.0.1'].includes(location.hostname) ? `<div style="padding:16px 16px 0"><div class="err">Warning: this page loaded over plain HTTP, which is not safe for seed phrases. Use the HTTPS address instead.</div></div>` : ''; // The big animated hero belongs ONLY to the welcome screen, where
  // it is the design. Every flow step (create, verify, both imports,
  // set-password, unlock) gets the compact brand header instead — a
  // modest chrome S with tight margins — so no step reserves the
  // hero's ~146px of vertical space for content it never renders.
  const head = hero
    ? `<div class="heroZone rise" style="--d:0s"><div class="heroLogo"><span class="heroGlow"></span><img class="heroImg" src="/assets/logo-sm.png" alt="Syn"><span class="heroSheen" aria-hidden="true"><span class="sheenBand"></span></span></div></div>`
    : `<div class="brandZone rise" style="--d:0s"><img class="brandImg" src="/assets/logo-sm.png" alt="Syn"></div>`;
  // bg: the user's chrome-globe artwork backs EXACTLY two screens —
  // first-run welcome and welcome-back (unlock). Layer order there
  // (user's correction): (1) the artwork at the BACK, (2) the Wave-9
  // steel gradient IN FRONT of the image as a translucent overlay
  // (.screenGrad), so the globe reads through a surface that stays
  // continuous with the in-app gradient, (3) content on top. The
  // ambient glows stay off on these two screens; every other screen
  // keeps the plain Wave-9 gradient. centered: the brand mark + card
  // compose as ONE vertically centred group (the unlock gate) instead
  // of pinning to the top over dead space.
  const bgLayer = opts.bg ? '<div class="screenBg" aria-hidden="true"></div><div class="screenGrad" aria-hidden="true"></div>' : '';
  const ambient = opts.bg ? '' : '<div class="ambient" aria-hidden="true"><span class="glow g1"></span><span class="glow g2"></span><span class="glow g3"></span></div>';
  const body = opts.centered ? `<div class="centerGroup">${head}${inner}</div>` : `${head}${inner}`;
  return httpWarn + `<main class="shellMain${opts.centered ? ' centered' : ''}${opts.bg ? ' composed' : ''}">${bgLayer}${ambient}${body}</main>`; }
// The bg screens' artwork layer starts at opacity 0 (the Wave-9
// gradient is the instant base from the first frame); once the exact
// asset the CSS will use is decoded, the layer fades in as ONE piece
// over the gradient. The <link rel="preload"> in index.html means it
// is normally decoded before the shell even paints.
function armScreenBg() {
  const bg = document.querySelector('.screenBg') as HTMLElement | null; if (!bg) return;
  const wide = window.matchMedia('(min-width: 700px) and (orientation: landscape)').matches;
  const img = new Image();
  img.src = wide ? '/assets/welcome-bg-wide.jpg' : '/assets/welcome-bg.jpg';
  const on = () => { if (bg.isConnected) bg.classList.add('bgOn'); };
  if (img.complete && img.naturalWidth > 0) { on(); return; }
  img.onload = on;
  if (img.decode) img.decode().then(on).catch(() => { /* onload still arms it */ });
}
function showOnboarding(err = '') {
  flowMode = 'setup';
  app().innerHTML = shell(`<div class="tickerStrip" id="priceTicker" aria-hidden="true"><div class="tickerTrack" id="tickerTrack"></div></div>
  <div class="card">
    <h1 class="heroH rise" style="--d:.24s">Welcome to <span>Syn Wallet</span></h1>
    <p class="heroSub rise" style="--d:.32s">A non-custodial wallet for Solana, Ethereum, Bitcoin and more. Your keys are generated and encrypted on this device only — Syn never sees them.</p>
    <div class="wcWrap rise" style="--d:.42s"><div class="wcHead"><span class="wcName">${tickIcon('solana', 'SOL')}Solana · SOL</span><span class="liveDot">LIVE</span></div><div class="wcPriceRow"><span class="wcPrice" id="wcPrice">…</span><span class="delta" id="wcChange"></span></div><div id="welcomeChart"></div></div>
    <div style="height:20px"></div>${err ? `<div class="err">${esc(err)}</div>` : ''}
    <button class="optRow rise" style="--d:.52s" id="obCreate"><span class="optLeft"><i class="ri-add-circle-line"></i><span><span class="optLabel"><b>Create new wallet</b></span><div class="optSub">12-word recovery phrase</div></span></span><span class="arrowChip grad"><i class="ri-arrow-right-line"></i></span></button>
    <div class="divider rise" style="--d:.58s"><span>OR</span></div>
    <button class="optRow rise" style="--d:.64s" id="obImportSeed"><span class="optLeft"><i class="ri-file-list-3-line"></i><span><span class="optLabel">Import <b>seed phrase</b></span><div class="optSub">12 or 24 words</div></span></span><span class="arrowChip"><i class="ri-arrow-right-line"></i></span></button>
    <button class="optRow rise" style="--d:.72s" id="obImportKey"><span class="optLeft"><i class="ri-key-2-line"></i><span><span class="optLabel">Import <b>private key</b></span><div class="optSub">Solana or Ethereum wallet</div></span></span><span class="arrowChip"><i class="ri-arrow-right-line"></i></span></button>
    <button class="optRow rise" style="--d:.8s" id="obBackup"><span class="optLeft"><i class="ri-file-download-line"></i><span><span class="optLabel">Restore <b>backup file</b></span><div class="optSub">Encrypted Syn Wallet backup (.json)</div></span></span><span class="arrowChip"><i class="ri-arrow-right-line"></i></span></button>
    <div class="footRow rise" style="--d:.8s"><span class="muted">Non-custodial</span><span class="act">No account needed</span></div>
  </div><p class="securityNote rise" style="padding:0 24px;text-align:center;--d:.88s">Everything is saved locally on this device — Syn's servers store nothing. If you clear your browser data or lose this device without your recovery phrase, your wallet <b>cannot be recovered by Syn</b>. <b>Back it up offline.</b></p>`, true, { bg: true });
  $('#obCreate').onclick = showCreate;
  $('#obImportSeed').onclick = () => showImportSeed();
  $('#obImportKey').onclick = () => showImportKey();
  ($('#obBackup') as HTMLElement).onclick = () => pickBackupFile(m => showOnboarding(m));
  armScreenBg();
  initWelcomeMotion();
}
// ---------- welcome motion: live ticker strip + hero chart (real data only) ----------
function tickGroupHTML(): string {
  // Both loop groups are generated from the SAME string, icons
  // included, so the duplicated track is byte-identical and the
  // marquee loop stays seamless. The track is built once per welcome
  // render; the 45s poll only patches prices/changes in place
  // (updateTicker), so neither the icons nor the loop ever restart.
  const items = TICKER_ITEMS.map(t => `<span class="tickItem" data-tick="${t.cg}">${tickIcon(t.cg, t.sym)}<b>${t.sym}</b><span data-tp>—</span><span class="chg" data-tc></span></span>`).join('');
  return `<div class="tickGroup">${items}</div><div class="tickGroup" aria-hidden="true">${items}</div>`;
}
function updateTicker() {
  if (!prices) return;
  document.querySelectorAll('[data-tick]').forEach(el => {
    const d = prices[el.getAttribute('data-tick')!]; const h = el as HTMLElement;
    if (!d || d.usd == null) { h.style.display = 'none'; return; }
    h.style.display = '';
    const tp = el.querySelector('[data-tp]'); if (tp) tp.textContent = fmtPrice(d.usd);
    const tc = el.querySelector('[data-tc]');
    if (tc && d.change24h != null) { const up = d.change24h >= 0; tc.className = 'chg ' + (up ? 'pos' : 'neg'); tc.innerHTML = `<i class="${up ? 'ri-arrow-up-s-fill' : 'ri-arrow-down-s-fill'}"></i>${Math.abs(d.change24h).toFixed(2)}%`; }
  });
}
// Paint the ticker strip + SOL spot from whatever the price store
// ALREADY holds (local cache at boot, in-memory after) — synchronous,
// so a warm Welcome composes complete in its first frame. Returns
// true when usable prices were on screen. Fresh data later swaps in
// place via the same path; the strip's box is reserved by CSS from
// the first paint either way, so nothing ever moves.
function paintWelcomePrices(): boolean {
  const strip = document.getElementById('priceTicker'); const track = document.getElementById('tickerTrack');
  const usable = !!prices && Object.values(prices).some((v: any) => v && typeof v === 'object' && v.usd != null);
  if (usable && strip && track) {
    if (!track.innerHTML) track.innerHTML = tickGroupHTML();
    updateTicker(); strip.classList.remove('hidden');
  }
  const sol = CHAINS[0]; const sp = priceOf(sol); const sch = changeOf(sol);
  const wp = document.getElementById('wcPrice'); if (wp && sp != null) wp.textContent = fmtUsd(sp);
  const wc = document.getElementById('wcChange');
  if (wc && sch != null) { const up = sch >= 0; wc.className = 'delta ' + (up ? 'pos' : 'neg'); wc.innerHTML = `<i class="${up ? 'ri-arrow-up-s-fill' : 'ri-arrow-down-s-fill'}"></i>${Math.abs(sch).toFixed(2)}% · 24h`; }
  return usable;
}
async function initWelcomeMotion() {
  const strip = document.getElementById('priceTicker');
  paintWelcomePrices(); // cache-first: same task as the shell paint
  loadChart(document.getElementById('welcomeChart'), CHAINS[0], '24h', 118); // self-seeds from its caches
  await fetchPrices();
  if (!paintWelcomePrices() && strip) {
    // A full round completed with nothing usable and nothing cached:
    // the honest failure state — the reserved strip collapses and the
    // spot says so. (Pending never reaches here; this is settled.)
    strip.classList.add('hidden');
    const wp = document.getElementById('wcPrice'); if (wp) wp.textContent = 'Unavailable';
  }
  clearInterval(welcomeTimer);
  welcomeTimer = setInterval(async () => { if (document.hidden) return; await fetchPrices(); if (document.getElementById('tickerTrack')) paintWelcomePrices(); }, 45000);
}
// ---------- step progress (Coinvexa "Secure your wallet" pattern) ----------
function stepHead(title: string, cur: number, total: number): string {
  const segs = Array.from({ length: total }, (_, i) => `<span class="${i < cur ? 'on' : ''}"></span>`).join('');
  return `<div class="stepMeta"><span class="st">${esc(title)}</span><span class="sn">Step ${cur} of ${total}</span></div><div class="stepSegs">${segs}</div>`;
}
let pendingMnemonic = '';
function showCreate() {
  app().innerHTML = shell(`<button class="backBtn" id="bk" aria-label="Back"><i class="ri-arrow-left-s-line"></i></button>${stepHead('Secure your wallet', 1, 3)}<div class="frostCard">
    <div class="stepHead"><span class="stepChip"><i class="ri-shield-keyhole-line"></i></span><div><div class="stepTitle">Protect your recovery phrase</div><p class="stepDesc"><b>Never share it.</b> Anyone who has it can take your funds. Syn will never ask for it. Only enter it in Syn Wallet at this address — and make sure nobody can see your screen.</p></div></div>
    <div style="height:16px"></div>
    <div class="field"><label>Recovery phrase length</label><div class="seg" id="wcSeg"><button data-n="12" class="on">12 words</button><button data-n="24">24 words · stronger</button></div></div>
    <button class="ctaWide" id="revealBtn">Show my phrase</button>
    <div id="seedZone"></div></div>`);
  ($('#bk') as HTMLElement).onclick = () => flowStepBack();
  let wc: 128 | 256 = 128;
  app().querySelectorAll('#wcSeg button').forEach(b => (b as HTMLElement).onclick = () => { wc = (b as HTMLElement).dataset.n === '24' ? 256 : 128; app().querySelectorAll('#wcSeg button').forEach(x => x.classList.toggle('on', x === b)); });
  ($('#revealBtn') as HTMLElement).onclick = () => {
    pendingMnemonic = createMnemonic(wc);
    const words = pendingMnemonic.split(' ');
    const zone = $('#seedZone');
    zone.innerHTML = `<div style="height:14px"></div><p class="heroSub">Write these ${words.length} words down, in order, and keep them offline. Everything is saved locally on this device only — if you clear browser data or lose this device without this phrase, Syn cannot recover your wallet.</p><div style="height:12px"></div>
    <div class="wordGrid" id="wGrid" style="filter:blur(7px)">${words.map((w, i) => `<div class="wordCell"><b>${i + 1}</b>${esc(w)}</div>`).join('')}</div>
    <p class="small muted" id="tapHint" style="text-align:center;margin-top:10px">Tap the words to reveal them</p>
    <div style="height:12px"></div><button class="btnGhost" id="cpSeed"><i class="ri-file-copy-line"></i> Copy phrase (clipboard clears in 20s)</button>
    <div style="height:10px"></div><button class="ctaWide" id="cont">I saved it</button>`;
    const grid = $('#wGrid'); let shown = false;
    grid.onclick = () => { shown = !shown; grid.style.filter = shown ? 'none' : 'blur(7px)'; const h = $('#tapHint'); if (h) h.textContent = shown ? 'Tap again to hide' : 'Tap the words to reveal them'; };
    const onVis = () => { if (document.hidden) { grid.style.filter = 'blur(7px)'; shown = false; } };
    document.addEventListener('visibilitychange', onVis);
    ($('#cpSeed') as HTMLElement).onclick = (e) => copySecret(pendingMnemonic, e.currentTarget as HTMLElement);
    ($('#cont') as HTMLButtonElement).onclick = () => { document.removeEventListener('visibilitychange', onVis); showVerify(); };
  };
}
function showVerify(err = '') {
  const words = pendingMnemonic.split(' ');
  const idxs = [1, 5, 9].map(n => n - 1);
  const pool = [...words].sort(() => Math.random() - 0.5);
  const chosen = new Map<number, string>();
  app().innerHTML = shell(`<button class="backBtn" id="bk" aria-label="Back"><i class="ri-arrow-left-s-line"></i></button>${stepHead('Secure your wallet', 2, 3)}<div class="frostCard">
    <div class="stepHead"><span class="stepChip"><i class="ri-checkbox-circle-line"></i></span><div><div class="stepTitle">Verify your backup</div><p class="stepDesc">Tap the correct word for each position — this proves your written backup is right before the wallet is created.</p></div></div><div style="height:14px"></div>${err ? `<div class="err">${esc(err)}</div>` : ''}
    ${idxs.map(ix => `<div class="field"><label>Word #${ix + 1}</label><div class="box" id="slot${ix}" style="min-height:20px;font-size:13px">${chosen.get(ix) || '<span class="muted">Tap a word below</span>'}</div></div>`).join('')}
    <div id="pool">${pool.map(w => `<button class="chipPick" data-w="${esc(w)}">${esc(w)}</button>`).join('')}</div>
    <div style="height:8px"></div><button class="ctaWide" id="cont">Continue</button></div>`);
  $('#bk').onclick = () => showCreate();
  // Audit fix: a mis-tapped word can be undone — tap a filled slot to
  // clear it (the chip frees up); the next pick fills the first empty
  // slot. Previously the only recovery was failing the whole quiz.
  const chipFor = new Map<number, HTMLElement>();
  app().querySelectorAll('.chipPick').forEach(b => (b as HTMLElement).onclick = () => {
    const target = idxs.find(x => !chosen.has(x)); if (target === undefined) return;
    chosen.set(target, (b as HTMLElement).dataset.w!); b.classList.add('picked'); chipFor.set(target, b as HTMLElement);
    const slot = document.getElementById('slot' + target); if (slot) { slot.textContent = (b as HTMLElement).dataset.w!; slot.style.cursor = 'pointer'; }
  });
  idxs.forEach(ix => {
    const slot = document.getElementById('slot' + ix); if (!slot) return;
    slot.onclick = () => {
      if (!chosen.has(ix)) return;
      chosen.delete(ix);
      const chip = chipFor.get(ix); if (chip) chip.classList.remove('picked'); chipFor.delete(ix);
      slot.innerHTML = '<span class="muted">Tap a word below</span>'; slot.style.cursor = '';
    };
  });
  ($('#cont') as HTMLButtonElement).onclick = () => {
    for (const ix of idxs) if (chosen.get(ix) !== words[ix]) { showVerify('One of those words is not right. Check your backup and try again.'); return; }
    showSetPassword(pendingMnemonic, { kind: 'mnemonic', createdAt: Date.now() }, '', { title: 'Secure your wallet', cur: 3, total: 3 });
  };
}
type FlowStep = { title: string; cur: number; total: number };
function showSetPassword(plain: string, m: Meta, err = '', flow?: FlowStep) {
  if (flowMode === 'add') {
    app().innerHTML = shell(`<div class="frostCard"><div class="stepHead"><span class="stepChip"><i class="ri-wallet-3-line"></i></span><div><div class="stepTitle">Add this wallet?</div><p class="stepDesc">It joins your vault on this device, protected by your existing app password. You can switch wallets any time from the account menu.</p></div></div><div style="height:16px"></div>
    <button class="ctaWide" id="addGo">Add wallet</button><div style="height:10px"></div><button class="btnGhost" id="addBack" style="border-radius:999px">Cancel</button></div>`);
    ($('#addGo') as HTMLButtonElement).onclick = async () => { btnBusy($('#addGo') as HTMLButtonElement, 'Encrypting…'); await finishAddWallet(plain, m); };
    ($('#addBack') as HTMLElement).onclick = () => returnFromFlow();
    return;
  }
  app().innerHTML = shell(`${flow ? stepHead(flow.title, flow.cur, flow.total) : ''}<div class="frostCard"><div class="stepHead"><span class="stepChip"><i class="ri-lock-password-line"></i></span><div><div class="stepTitle">Set a password</div><p class="stepDesc">This password encrypts your wallet on this device (AES-GCM, PBKDF2 600,000 rounds). It is never sent anywhere.</p></div></div><div style="height:16px"></div>${err ? `<div class="err">${esc(err)}</div>` : ''}
    <div class="field"><label>Password</label><div class="box"><input type="password" id="pw1" placeholder="At least ${MIN_PASSWORD_LENGTH} characters" autocomplete="new-password"></div></div>
    <div class="field"><label>Confirm password</label><div class="box"><input type="password" id="pw2" placeholder="Repeat password" autocomplete="new-password"></div></div>
    <p class="small muted" id="pwStrength" style="margin:0 4px 12px">Use at least ${MIN_PASSWORD_LENGTH} characters — longer is stronger. Anyone who copies your encrypted backup file can attack this password offline, so length is what protects you. It cannot be reset by Syn.</p>
    <button class="ctaWide" id="cont">${flow && flow.total === 2 ? 'Import wallet' : 'Create wallet'}</button></div>`);
  ($('#pw1') as unknown as HTMLInputElement).addEventListener('input', (e) => {
    const v = (e.target as HTMLInputElement).value; const el = $('#pwStrength'); if (!el) return;
    const score = (v.length >= MIN_PASSWORD_LENGTH ? 1 : 0) + (v.length >= 12 ? 1 : 0) + (/[A-Z]/.test(v) && /[a-z]/.test(v) ? 1 : 0) + (/\d/.test(v) ? 1 : 0) + (/[^A-Za-z0-9]/.test(v) ? 1 : 0);
    el.textContent = v.length < MIN_PASSWORD_LENGTH ? 'Too short — at least ' + MIN_PASSWORD_LENGTH + ' characters.' : score <= 2 ? 'Strength: Weak — add length, numbers or symbols.' : score <= 3 ? 'Strength: Fair.' : 'Strength: Strong.';
  });
  ($('#cont') as HTMLButtonElement).onclick = async () => {
    const p1 = ($('#pw1') as unknown as HTMLInputElement).value; const p2 = ($('#pw2') as unknown as HTMLInputElement).value;
    if (p1.length < MIN_PASSWORD_LENGTH) { showSetPassword(plain, m, 'Password must be at least ' + MIN_PASSWORD_LENGTH + ' characters.', flow); return; }
    if (p1 !== p2) { showSetPassword(plain, m, 'Passwords do not match.', flow); return; }
    btnBusy($('#cont') as HTMLButtonElement, 'Encrypting…');
    await saveVault(plain, p1, m); pendingMnemonic = ''; showApp('wallet');
  };
}
function showImportSeed(err = '') {
  // Seed import (Wave 6 redesign): compact 3-col grid, paste-the-whole-
  // phrase (button + paste into any cell distributes from cell 1),
  // suggestion chips with focus advance, and LIVE validation state —
  // the CTA is a dimmed non-chrome button until every word is a real
  // BIP39 word AND the checksum verifies. The DOM never re-renders on
  // state changes, so typed words and focus are never lost. Security
  // model unchanged: local @scure/bip39 validation only, words never
  // leave the device, nothing is logged.
  app().innerHTML = shell(`<button class="backBtn" id="bk" aria-label="Back"><i class="ri-arrow-left-s-line"></i></button>${stepHead('Import wallet', 1, 2)}<div class="frostCard">
    <div class="stepHead"><span class="stepChip"><i class="ri-file-list-3-line"></i></span><div><div class="stepTitle">Import with seed phrase</div><p class="stepDesc">Words are validated on this device only — never sent anywhere.</p></div></div><div style="height:14px"></div>
    <div class="field"><label>Words</label><div class="seg" id="nSeg"><button data-n="12" class="on">12 words</button><button data-n="24">24 words</button></div></div>
    <div class="wGridHead"><span class="wProg" id="wProg">0 of 12 words</span><button class="linkBtn" id="wPaste" type="button"><i class="ri-clipboard-line"></i> Paste phrase</button></div>
    <div class="wordGrid imp" id="wInputs"></div>
    <div class="wChips" id="wChips"></div>
    <div class="wMsg" id="wMsg" role="alert"></div>
    <button class="ctaWide off" id="cont" disabled>Import wallet</button></div>`);
  ($('#bk') as HTMLElement).onclick = () => flowStepBack();
  let n = 12;
  let active = -1;
  const grid = $('#wInputs') as HTMLElement;
  const chipsEl = $('#wChips') as HTMLElement;
  const msgEl = $('#wMsg') as HTMLElement;
  const progEl = $('#wProg') as HTMLElement;
  const cont = $('#cont') as HTMLButtonElement;
  const inputs = (): HTMLInputElement[] => [...grid.querySelectorAll('.wIn')] as HTMLInputElement[];
  const cellOf = (inp: HTMLInputElement): HTMLElement => inp.closest('.wCell') as HTMLElement;

  function renderInputs(keep: string[] = []) {
    grid.innerHTML = Array.from({ length: n }, (_, i) => `<div class="wCell"><span class="wNum">${i + 1}</span><input class="wIn" data-i="${i}" value="${esc(keep[i] || '')}" autocomplete="off" autocapitalize="none" spellcheck="false" enterkeyhint="${i === n - 1 ? 'done' : 'next'}"><i class="ri-check-line wOk"></i></div>`).join('');
    inputs().forEach(inp => {
      inp.addEventListener('input', onInput);
      inp.addEventListener('keydown', onKey);
      inp.addEventListener('paste', onPaste);
      inp.addEventListener('focus', () => { active = Number(inp.dataset.i); paintChips(); });
    });
    refresh();
  }
  function paintChips() {
    const ins = inputs();
    const inp = active >= 0 ? ins[active] : null;
    const v = inp ? inp.value.trim().toLowerCase() : '';
    if (!inp || !v || bip39Wordlist.includes(v)) { chipsEl.innerHTML = ''; return; }
    const m = bip39Wordlist.filter(w => w.startsWith(v)).slice(0, 6);
    chipsEl.innerHTML = m.map(w => `<button class="wChip" data-w="${w}" type="button">${w}</button>`).join('');
    chipsEl.querySelectorAll('.wChip').forEach(b => (b as HTMLElement).onclick = () => pickWord((b as HTMLElement).dataset.w!));
  }
  function refresh() {
    const ins = inputs();
    const vals = ins.map(i => i.value.trim().toLowerCase());
    let filled = 0; let firstBad = -1;
    ins.forEach((inp, i) => {
      const v = vals[i]; const cell = cellOf(inp);
      if (v) filled++;
      const ok = !!v && bip39Wordlist.includes(v);
      cell.classList.toggle('ok', ok);
      cell.classList.toggle('bad', !!v && !ok);
      if (v && !ok && firstBad < 0) firstBad = i;
    });
    progEl.textContent = `${filled} of ${n} words`;
    let ready = false;
    if (firstBad >= 0) msgEl.textContent = `Word ${firstBad + 1} isn't a recognised BIP39 word`;
    else if (filled === n) {
      if (isValidMnemonic(vals.join(' '))) { msgEl.textContent = ''; ready = true; }
      else msgEl.textContent = `This phrase doesn't verify — check the words and their order`;
    } else msgEl.textContent = '';
    cont.disabled = !ready;
    cont.classList.toggle('off', !ready);
    paintChips();
  }
  function advanceFrom(i: number) {
    const ins = inputs();
    for (let k = i + 1; k < n; k++) if (!ins[k].value.trim()) { ins[k].focus(); return; }
    for (let k = 0; k < i; k++) if (!ins[k].value.trim()) { ins[k].focus(); return; }
  }
  function pickWord(w: string) {
    if (active < 0) return;
    inputs()[active].value = w;
    refresh();
    advanceFrom(active);
  }
  function distribute(toks: string[]) {
    if ((toks.length === 12 || toks.length === 24) && toks.length !== n) {
      n = toks.length;
      app().querySelectorAll('#nSeg button').forEach(x => x.classList.toggle('on', Number((x as HTMLElement).dataset.n) === n));
      renderInputs();
    }
    const ins = inputs();
    ins.forEach((inp, i) => { inp.value = toks[i] || ''; });
    refresh();
    const fe = ins.findIndex(inp => !inp.value.trim());
    ins[fe >= 0 ? fe : n - 1].focus();
  }
  function onInput(e: Event) {
    const inp = e.target as HTMLInputElement;
    if (/\s/.test(inp.value)) {
      const toks = inp.value.trim().toLowerCase().split(/\s+/).filter(Boolean);
      if (toks.length >= 2) { distribute(toks); return; }
      inp.value = toks[0] || '';
    }
    refresh();
  }
  function onKey(e: KeyboardEvent) {
    if (e.key !== ' ' && e.key !== 'Enter') return;
    const inp = e.target as HTMLInputElement;
    const v = inp.value.trim().toLowerCase();
    if (!v || !bip39Wordlist.includes(v)) return;
    e.preventDefault();
    inp.value = v;
    refresh();
    const i = Number(inp.dataset.i);
    if (i === n - 1 && !cont.disabled) { cont.click(); return; }
    advanceFrom(i);
  }
  function onPaste(e: Event) {
    const text = (e as ClipboardEvent).clipboardData?.getData('text') || '';
    const toks = text.trim().toLowerCase().split(/\s+/).filter(Boolean);
    if (toks.length >= 2) { e.preventDefault(); distribute(toks); }
  }
  ($('#wPaste') as HTMLElement).onclick = async () => {
    try {
      const text = await navigator.clipboard.readText();
      const toks = text.trim().toLowerCase().split(/\s+/).filter(Boolean);
      if (toks.length >= 2) { distribute(toks); return; }
      if (toks.length === 1) { const ins = inputs(); const t = ins.find(x => !x.value.trim()) || ins[0]; t.value = toks[0]; refresh(); t.focus(); return; }
      msgEl.textContent = 'Clipboard is empty — copy your phrase first.';
    } catch { msgEl.textContent = `Couldn't read the clipboard — paste into any word box instead.`; }
  };
  app().querySelectorAll('#nSeg button').forEach(b => (b as HTMLElement).onclick = () => {
    const nn = Number((b as HTMLElement).dataset.n);
    if (nn === n) return;
    const keep = inputs().map(i => i.value);
    n = nn;
    app().querySelectorAll('#nSeg button').forEach(x => x.classList.toggle('on', x === b));
    renderInputs(keep);
  });
  cont.onclick = () => {
    const vals = inputs().map(i => i.value.trim().toLowerCase());
    if (vals.some(v => !v) || !isValidMnemonic(vals.join(' '))) { refresh(); return; }
    showSetPassword(vals.join(' '), { kind: 'mnemonic', createdAt: Date.now() }, '', { title: 'Import wallet', cur: 2, total: 2 });
  };
  renderInputs();
  if (err) msgEl.textContent = err;
}
function showImportKey(err = '') {
  app().innerHTML = shell(`<button class="backBtn" id="bk" aria-label="Back"><i class="ri-arrow-left-s-line"></i></button>${stepHead('Import wallet', 1, 2)}<div class="frostCard">
    <div class="stepHead"><span class="stepChip"><i class="ri-key-2-line"></i></span><div><div class="stepTitle">Import with private key</div><p class="stepDesc">Creates a single-chain imported account. Solana keys are base58; Ethereum keys are hex.</p></div></div><div style="height:12px"></div><div class="warn">A private key controls one account completely. Only paste it on your own device, in this app — never on a website that asks for it.</div>${err ? `<div class="err">${esc(err)}</div>` : ''}
    <div class="field"><label>Chain</label><div class="seg" id="kchain"><button data-c="solana" class="on">Solana</button><button data-c="evm">Ethereum / EVM</button></div></div>
    <div class="field"><label>Private key</label><div class="box"><textarea id="pk" placeholder="Paste private key" autocomplete="off" autocapitalize="none" spellcheck="false"></textarea></div></div>
    <button class="ctaWide" id="cont">Import wallet</button></div>`);
  $('#bk').onclick = () => flowStepBack();
  let chain = 'solana';
  app().querySelectorAll('#kchain button').forEach(b => (b as HTMLElement).onclick = () => { chain = (b as HTMLElement).dataset.c!; app().querySelectorAll('#kchain button').forEach(x => x.classList.toggle('on', x === b)); });
  ($('#cont') as HTMLButtonElement).onclick = () => {
    const v = ($('#pk') as unknown as HTMLTextAreaElement).value.trim();
    try {
      if (chain === 'solana') { const raw = bs58.decode(v); if (![32, 64].includes(raw.length)) throw new Error('bad length'); Keypair.fromSecretKey(raw.length === 64 ? raw : Uint8Array.from([...raw, ...Keypair.fromSeed(raw).publicKey.toBytes()])); }
      else { new ethers.Wallet(v.startsWith('0x') ? v : '0x' + v); }
    } catch { showImportKey('That private key is not valid for the selected chain.'); return; }
    showSetPassword(v, { kind: 'privateKey', chain, createdAt: Date.now() }, '', { title: 'Import wallet', cur: 2, total: 2 });
  };
}
function showUnlock(err = '') {
  if (!getVault()) { showOnboarding(); return; }
  app().innerHTML = shell(`<div class="card rise" style="--d:.16s"><h1 class="heroH">Hello <span>again</span></h1><p class="heroSub">Unlock your wallet on this device.</p><div style="height:18px"></div>${err ? `<div class="err">${esc(err)}</div>` : ''}
    <div class="pill"><div class="fld"><label>Wallet password</label><input type="password" id="pw" placeholder="Enter password" autocomplete="current-password"></div><button class="gradBtn" id="go" aria-label="Unlock"><i class="ri-arrow-right-line"></i></button></div>
    <div style="height:14px"></div>
    ${config.passkey ? '<button class="ctaWide" id="pkUnlock" type="button"><i class="ri-fingerprint-line" style="margin-right:8px"></i>Use Face ID / passkey</button><div style="height:10px"></div>' : ''}
    <button class="optRow" id="ubImport" type="button"><span class="optLeft"><i class="ri-file-download-line"></i><span class="optLabel">Restore from <b>backup file</b></span></span><span class="arrowChip"><i class="ri-arrow-right-line"></i></span></button>
    <div class="footRow"><span class="muted">Forgot password?</span><button class="act" id="wipeLink">Wipe &amp; start over</button></div></div>`, false, { bg: true, centered: true });
  armScreenBg();
  const pku = $('#pkUnlock'); if (pku) pku.onclick = async () => { const err = await tryPasskeyUnlock(); if (err) showUnlock(err); };
  ($('#ubImport') as HTMLElement).onclick = () => { if (confirm('Restoring a backup replaces the wallet currently on this device. Continue?')) pickBackupFile(m => showUnlock(m)); };
  const go = async () => {
    const waitLeft = authWaitRemaining('unlock');
    if (waitLeft > 0) { showUnlock(`Too many failed attempts — wait ${Math.ceil(waitLeft / 1000)}s and try again.`); return; }
    const pw = ($('#pw') as unknown as HTMLInputElement).value;
    const gb = $('#go') as HTMLButtonElement; btnBusy(gb);
    const ok = await unlockWithPassword(pw);
    if (!ok) { const wait = noteAuthFailure('unlock'); showUnlock(`Wrong password. Try again.${wait > 0 ? ' Unlock is paused after repeated failures.' : ''}`); }
  };
  ($('#go') as HTMLButtonElement).onclick = go;
  ($('#pw') as unknown as HTMLInputElement).addEventListener('keydown', e => { if ((e as KeyboardEvent).key === 'Enter') go(); });
  // Keyboard sanity for the centred gate: when the iOS keyboard opens
  // and the visible viewport shrinks past the submit button, nudge the
  // page so password + submit stay reachable — never covered.
  ($('#pw') as unknown as HTMLInputElement).addEventListener('focus', () => setTimeout(() => {
    const vv = window.visualViewport; const b = $('#go') as HTMLElement | null; if (!vv || !b) return;
    const r = b.getBoundingClientRect();
    if (r.bottom > vv.height - 4 || r.top < 0) b.scrollIntoView({ block: 'nearest' });
  }, 350));
  ($('#wipeLink') as HTMLElement).onclick = () => { if (confirm('Wipe this wallet from this device? You can only restore it with your recovery phrase or private key.')) { wipeAllLocalState(); showOnboarding(); } };
}

// ---------- data ----------
const rpcUrl = (chain: string) => `${location.origin}/api/rpc/${chain}`;
async function rpc(chain: string, method: string, params: any[]): Promise<any> {
  const r = await fetch(rpcUrl(chain), { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) });
  const j = await r.json(); if (j.error) throw new Error(j.error.message || 'RPC error'); return j.result;
}
async function fetchPrices() {
  try {
    // Priority order matters (bug found 2026-11-20: newly added
    // tokens never got prices). The old build put ticker + chain
    // ids first and sliced the set at 40 — a token the user had
    // just added landed past the cut and its price was never even
    // requested. Now the user's own tokens come first, then chain
    // natives, then the welcome ticker, and the full set is
    // fetched in ≤40-id chunks (the /api/markets cap) and merged.
    const ids = new Set<string>();
    for (const t of visibleTokens()) if (t.cg) ids.add(t.cg);
    for (const c of visibleChains()) if (c.cg) ids.add(c.cg);
    for (const t of TICKER_ITEMS) ids.add(t.cg);
    const list = [...ids];
    if (!list.length) { pricesSettled = true; return prices; }
    for (let i = 0; i < list.length; i += 40) {
      try {
        const r = await fetch('/api/markets?ids=' + encodeURIComponent(list.slice(i, i + 40).join(',')));
        // Merge, don't replace: an id the server couldn't serve
        // this round keeps its last real price.
        if (r.ok) { const j = await r.json(); if (j && typeof j === 'object' && !j.error) prices = { ...(prices || {}), ...j }; }
      } catch { /* a failed chunk keeps last prices for its ids */ }
    }
    // Trust Wallet index prices for the tokens CoinGecko does not
    // carry (most of the long-tail catalog): ONE batched call through
    // the server proxy, only when the operator configured TWAK keys.
    // Entries land in the same map under the TW asset id, where
    // priceEntry() finds them for tokens with no cg id.
    if (twEnabled()) {
      const byAsset = new Map<string, string>();
      for (const t of visibleTokens()) {
        if (t.cg) continue;
        const a = twAssetId(t.chainId, t.contract);
        if (a) byAsset.set(a, a);
      }
      const assets = [...byAsset.keys()].slice(0, 50);
      if (assets.length) {
        const tickers = await twTickersFetch(assets);
        for (const a of assets) {
          const e = tickers[a];
          if (e) prices = { ...(prices || {}), [a]: { usd: e.usd, change24h: e.change24h ?? undefined, marketCap: e.marketCap ?? undefined, volume24h: e.volume24h ?? undefined } };
        }
      }
    }
    saveDataCache();
  } catch { /* keep last */ }
  pricesSettled = true; // a full round completed — missing ids are now honestly "failed", not pending
  return prices;
}
async function evmCall(c: Chain, method: string, params: any[]): Promise<any> {
  const url = config.rpcOverrides[c.id] || c.rpc;
  if (url) {
    const r = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) });
    const j = await r.json(); if (j.error) throw new Error(j.error.message || 'RPC error'); return j.result;
  }
  return rpc(c.id, method, params);
}
function evmProviderUrl(c: Chain): string { return config.rpcOverrides[c.id] || c.rpc || `${location.origin}/api/rpc/${c.id}`; }
// Balance engine: built-in chains are read through OUR server's balance
// service (its RPC pools + failover + coalescing absorb upstream rate
// limits — the phone only ever talks to Syn's server for these). If the
// service can't answer, ONE direct attempt via the chain's own RPC runs
// before the balance is declared unavailable. A user-configured custom
// RPC override always goes direct: it's the user's own endpoint.
const BALANCE_SERVICE_CHAINS = new Set(['solana', 'ethereum', 'polygon', 'bnb', 'arbitrum', 'base', 'optimism', 'avalanche', 'fantom', 'zksync', 'bitcoin', 'litecoin', 'tron', 'xrp', 'cosmos', 'sui', 'aptos']);
async function fetchBalance(c: Chain): Promise<number | null> {
  const addr = addressFor(c); if (!addr) return null;
  const overrideKey = c.kind === 'solana-tw' || c.kind === 'solana-phantom' ? 'solana' : c.id;
  if (config.rpcOverrides[overrideKey]) return fetchBalanceDirect(c);
  const svc = c.kind === 'solana-tw' || c.kind === 'solana-phantom' ? 'solana' : c.id;
  if (BALANCE_SERVICE_CHAINS.has(svc)) {
    try {
      const r = await fetch(`/api/balance/${svc}?address=${encodeURIComponent(addr)}`);
      if (r.ok) { const j = await r.json(); if (typeof j.balance === 'number') return j.balance; }
    } catch { /* one direct attempt below */ }
    return fetchBalanceDirect(c);
  }
  return fetchBalanceDirect(c);
}
async function fetchBalanceDirect(c: Chain): Promise<number | null> {
  const addr = addressFor(c); if (!addr) return null;
  try {
    switch (c.kind) {
      case 'solana': case 'solana-tw': case 'solana-phantom': { const v = await solanaRpcCall('getBalance', [addr]); return (v?.value ?? v) / 1e9; }
      case 'bitcoin': { const r = await fetch(`/api/utxo/${c.id}/address/${addr}`); if (!r.ok) return null; const j = await r.json(); return ((j.chain_stats?.funded_txo_sum || 0) - (j.chain_stats?.spent_txo_sum || 0)) / 1e8; }
      case 'tron': { const r = await fetch(`https://api.trongrid.io/v1/accounts/${addr}`); if (!r.ok) return null; const j = await r.json(); const a = j?.data?.[0]; return a ? (a.balance || 0) / 1e6 : 0; }
      case 'xrp': { const r = await fetch('https://xrplcluster.com/', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ method: 'account_info', params: [{ account: addr, ledger_index: 'validated' }] }) }); const j = await r.json(); if (j?.result?.error === 'actNotFound') return 0; const bal = j?.result?.account_data?.Balance; return bal != null ? Number(bal) / 1e6 : null; }
      case 'cosmos': { for (const base of ['https://rest.cosmos.directory/cosmoshub', 'https://cosmos-rest.publicnode.com']) { try { const r = await fetch(`${base}/cosmos/bank/v1beta1/balances/${addr}`); if (!r.ok) continue; const j = await r.json(); const u = (j.balances || []).find((b: any) => b.denom === 'uatom'); return u ? Number(u.amount) / 1e6 : 0; } catch { /* try next */ } } return null; }
      case 'sui': { const r = await fetch('https://graphql.mainnet.sui.io/graphql', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ query: `query { address(address: "${addr}") { balance(coinType: "0x2::sui::SUI") { totalBalance } } }` }) }); const j = await r.json(); const tb = j?.data?.address?.balance?.totalBalance; if (tb != null) return Number(tb) / 1e9; return j?.data && j.data.address === null ? 0 : null; }
      case 'aptos': { const r = await fetch(`https://api.mainnet.aptoslabs.com/v1/accounts/${addr}/resource/0x1::coin::CoinStore%3C0x1::aptos_coin::AptosCoin%3E`); if (r.status === 404) return 0; if (!r.ok) return null; const j = await r.json(); const v = j?.data?.coin?.value; return v != null ? Number(v) / 1e8 : null; }
      default: { const hex = await evmCall(c, 'eth_getBalance', [addr, 'latest']); return Number(BigInt(hex)) / 1e18; }
    }
  } catch { return null; }
}
async function fetchTokenBalance(t: TokenDef): Promise<number | null> {
  const c = findChain(t.chainId); if (!c) return null;
  const addr = addressFor(c); if (!addr) return null;
  const overrideKey = c.kind === 'solana-tw' || c.kind === 'solana-phantom' ? 'solana' : c.id;
  if (config.rpcOverrides[overrideKey]) return fetchTokenBalanceDirect(t);
  const svc = c.kind === 'solana-tw' || c.kind === 'solana-phantom' ? 'solana' : c.id;
  if ((c.kind === 'evm' || c.kind === 'solana' || c.kind === 'solana-tw' || c.kind === 'solana-phantom') && BALANCE_SERVICE_CHAINS.has(svc)) {
    try {
      const r = await fetch(`/api/balance/${svc}?address=${encodeURIComponent(addr)}&token=${encodeURIComponent(t.contract)}&decimals=${t.decimals}`);
      if (r.ok) { const j = await r.json(); if (typeof j.balance === 'number') return j.balance; }
    } catch { /* one direct attempt below */ }
    return fetchTokenBalanceDirect(t);
  }
  return fetchTokenBalanceDirect(t);
}
async function fetchTokenBalanceDirect(t: TokenDef): Promise<number | null> {
  const c = findChain(t.chainId); if (!c) return null;
  const addr = addressFor(c); if (!addr) return null;
  try {
    if (c.kind === 'solana' || c.kind === 'solana-tw' || c.kind === 'solana-phantom') {
      const v = await solanaRpcCall('getTokenAccountsByOwner', [addr, { mint: t.contract }, { encoding: 'jsonParsed' }]);
      let sum = 0; for (const a of (v?.value || [])) sum += a?.account?.data?.parsed?.info?.tokenAmount?.uiAmount || 0;
      return sum;
    }
    if (c.kind === 'evm') {
      const data = '0x70a08231' + addr.slice(2).toLowerCase().padStart(64, '0');
      const res = await evmCall(c, 'eth_call', [{ to: t.contract, data }, 'latest']);
      return Number(BigInt(res)) / 10 ** t.decimals;
    }
    return null;
  } catch { return null; }
}
async function refreshBalances() { lastBalanceAt = Date.now(); await fetchPrices(); await Promise.all(visibleChains().map(async c => balances.set(c.id, await fetchBalance(c)))); saveDataCache(); }
function totalUsd(): { total: number | null; partial: boolean } {
  let total = 0, any = false, partial = false;
  for (const c of visibleChains()) { const b = balances.get(c.id); const p = priceOf(c);
    if (b == null || p == null) { if (balances.has(c.id) || b != null) partial = true; else if (b == null) partial = true; continue; } total += b * p; any = true; }
  for (const t of visibleTokens()) { const tb = tokenBalances.get(t.id); const tp = tokenUsd(t); if (tb != null && tp != null) { total += tb * tp; any = true; } }
  return { total: any ? total : null, partial };
}
function priceOf(c: Chain): number | null { return c.cg ? (prices?.[c.cg]?.usd ?? null) : null; }
function changeOf(c: Chain): number | null { return c.cg ? (prices?.[c.cg]?.change24h ?? null) : null; }

// ---------- app shell: persistent chrome + in-app navigation ----------
// The floating tab bar mounts ONCE after unlock and never unmounts; only
// #view changes, with a short fade/slide transition — no blank frames.
// Navigation is an in-app stack wired to history.pushState/popstate, so the
// phone/browser Back gesture moves inside the app instead of reloading the
// document. Scroll position is saved per route and restored on return.
let shellMounted = false;
let currentRoute = ''; let currentChain = '';
interface RevokePayload { family: 'evm' | 'solana'; chainId: string; tokenAddress: string; tokenSymbol: string; tokenName: string; decimals: number; spender: string; spenderName: string; tokenAccount?: string; tokenProgram?: string; }
interface SwapConfirmPayload { quote: SwapQuote; from: SwapAsset; to: SwapAsset; amountStr: string; rawIn: string; slippageBps: number; }
interface StakeConfirmPayload { chainId: string; action: 'create' | 'deactivate' | 'withdraw'; amtStr?: string; voter?: string; stakePubkey?: string; stakeLamports?: number; }
type RouteEntry = { route: string; chainId?: string; tokenId?: string; confirm?: { c: Chain; to: string; amtStr: string; poisonWarn: string; nameLabel?: string }; tokenConfirm?: { t: TokenDef; to: string; amtStr: string; nameLabel?: string; poisonWarn?: string }; revoke?: RevokePayload; signTab?: 'msg' | 'siwe'; swapConfirm?: SwapConfirmPayload; stakeConfirm?: StakeConfirmPayload; nftKey?: string; nftConfirm?: { nft: NftItem; to: string }; lidoAmt?: string };
let navStack: RouteEntry[] = []; let navIdx = -1;
const scrollPos = new Map<string, number>();
const routeKey = (e: RouteEntry) => e.route + ':' + (e.chainId || '');
// While a navigation transition (navTo) is being staged, V() resolves
// to its incoming layer so setView paints there.
let viewOverride: HTMLElement | null = null;
function setViewTarget(el: HTMLElement | null) { viewOverride = el; }
// Set by renderRoute while it re-renders the route already on screen
// (eye toggle, currency change, a data-driven repaint): the swap must
// be invisible — replaying the viewIn entrance fade on the same
// screen reads as a reload. Consumed by the setView call inside the
// dispatch and cleared by renderRoute right after it.
let quietViewIn = false;
const V = () => viewOverride || (document.querySelector('#view') as HTMLElement) || app();
function setView(html: string) { cleanupKeyGate(); if (chartHandle) { chartHandle.destroy(); chartHandle = null; } const v = V(); v.innerHTML = html; if (!viewOverride && !quietViewIn) { v.classList.remove('viewIn'); void v.offsetWidth; v.classList.add('viewIn'); } window.scrollTo(0, 0); initRails(v); }
// ---------- shared pill rails (see the rail system in style.css) ----------
// Every horizontal chip rail gets: edge-fade classes driven by its own
// scroll metrics, and its selected pill scrolled fully into view on
// open. Reveal touches ONLY the rail's horizontal scroll — never the
// page (the old scrollIntoView call on Activity also dragged the page).
function railFades(rail: HTMLElement) {
  const can = rail.scrollWidth > rail.clientWidth + 1;
  rail.classList.toggle('railFL', can && rail.scrollLeft > 1);
  rail.classList.toggle('railFR', can && rail.scrollLeft + rail.clientWidth < rail.scrollWidth - 1);
}
function railReveal(btn: HTMLElement, smooth = false) {
  const rail = btn.parentElement; if (!rail) return;
  const br = btn.getBoundingClientRect(); const rr = rail.getBoundingClientRect();
  const pad = 16; let dx = 0;
  if (br.left < rr.left + pad) dx = br.left - rr.left - pad;
  else if (br.right > rr.right - pad) dx = br.right - rr.right + pad;
  if (dx) rail.scrollBy({ left: dx, behavior: smooth && !prefersReducedMotion() ? 'smooth' : 'auto' });
  railFades(rail);
}
let railsResizeWired = false;
function initRails(root: ParentNode) {
  root.querySelectorAll<HTMLElement>('.chipRail,.polyCats').forEach(rail => {
    if (!rail.dataset.railWired) {
      rail.dataset.railWired = '1';
      rail.addEventListener('scroll', () => railFades(rail), { passive: true });
    }
    railFades(rail);
    const on = rail.querySelector<HTMLElement>('button.on');
    if (on) railReveal(on);
  });
  if (!railsResizeWired) {
    railsResizeWired = true;
    window.addEventListener('resize', () => initRails(document));
  }
}
function tabFor(route: string): string { return route === 'activity' ? 'activity' : route === 'settings' ? 'settings' : route === 'invest' || route === 'hlmarket' || route === 'investtoken' || route === 'polymarket' ? 'invest' : 'wallet'; }
// The selected tab is the ROOT of the current navigation stack — the
// tab this stack was entered from — never the leaf route. A Settings
// sub-screen (Add token, Networks, Private keys…) keeps SETTINGS
// selected; a Wallet-pushed screen (asset detail, Swap, Stake…) keeps
// WALLET selected. renderRoute → setTabActive runs on every push, pop
// and tab switch, and direct-setView screens (the key-reveal gate)
// leave the stack untouched, so this one rule covers every screen
// with no per-screen patches.
function currentTab(): string {
  const root = navStack[0]?.route;
  if (root === 'wallet' || root === 'invest' || root === 'activity' || root === 'settings') return root;
  return tabFor(currentRoute);
}
// Tab icons are inline SVG (Remix path data), not the icon font: the font's
// uneven glyph bearings decenter icons over their labels, the SVG paths are
// centred on the 24 grid by construction.
const TAB_IC_WALLET = `<span class="ic"><svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M22.0049 6.99979H23.0049V16.9998H22.0049V19.9998C22.0049 20.5521 21.5572 20.9998 21.0049 20.9998H3.00488C2.4526 20.9998 2.00488 20.5521 2.00488 19.9998V3.99979C2.00488 3.4475 2.4526 2.99979 3.00488 2.99979H21.0049C21.5572 2.99979 22.0049 3.4475 22.0049 3.99979V6.99979ZM20.0049 16.9998H14.0049C11.2435 16.9998 9.00488 14.7612 9.00488 11.9998C9.00488 9.23836 11.2435 6.99979 14.0049 6.99979H20.0049V4.99979H4.00488V18.9998H20.0049V16.9998ZM21.0049 14.9998V8.99979H14.0049C12.348 8.99979 11.0049 10.3429 11.0049 11.9998C11.0049 13.6566 12.348 14.9998 14.0049 14.9998H21.0049ZM14.0049 10.9998H17.0049V12.9998H14.0049V10.9998Z"/></svg></span>`;
const TAB_IC_INVEST = `<span class="ic"><svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M5 3V19H21V21H3V3H5ZM20.2929 6.29289L21.7071 7.70711L16 13.4142L13 10.415L8.70711 14.7071L7.29289 13.2929L13 7.58579L16 10.585L20.2929 6.29289Z"/></svg></span>`;
const TAB_IC_ACTIVITY = `<span class="ic"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M2.5 12h4l2.4-6.8 4.2 13.6 2.4-6.8h6"/></svg></span>`;
const TAB_IC_SETTINGS = `<span class="ic"><svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M3.33946 17.0002C2.90721 16.2515 2.58277 15.4702 2.36133 14.6741C3.3338 14.1779 3.99972 13.1668 3.99972 12.0002C3.99972 10.8345 3.3348 9.824 2.36353 9.32741C2.81025 7.71651 3.65857 6.21627 4.86474 4.99001C5.7807 5.58416 6.98935 5.65534 7.99972 5.072C9.01009 4.48866 9.55277 3.40635 9.4962 2.31604C11.1613 1.8846 12.8847 1.90004 14.5031 2.31862C14.4475 3.40806 14.9901 4.48912 15.9997 5.072C17.0101 5.65532 18.2187 5.58416 19.1346 4.99007C19.7133 5.57986 20.2277 6.25151 20.66 7.00021C21.0922 7.7489 21.4167 8.53025 21.6381 9.32628C20.6656 9.82247 19.9997 10.8336 19.9997 12.0002C19.9997 13.166 20.6646 14.1764 21.6359 14.673C21.1892 16.2839 20.3409 17.7841 19.1347 19.0104C18.2187 18.4163 17.0101 18.3451 15.9997 18.9284C14.9893 19.5117 14.4467 20.5941 14.5032 21.6844C12.8382 22.1158 11.1148 22.1004 9.49633 21.6818C9.55191 20.5923 9.00929 19.5113 7.99972 18.9284C6.98938 18.3451 5.78079 18.4162 4.86484 19.0103C4.28617 18.4205 3.77172 17.7489 3.33946 17.0002ZM8.99972 17.1964C10.0911 17.8265 10.8749 18.8227 11.2503 19.9659C11.7486 20.0133 12.2502 20.014 12.7486 19.9675C13.1238 18.8237 13.9078 17.8268 14.9997 17.1964C16.0916 16.5659 17.347 16.3855 18.5252 16.6324C18.8146 16.224 19.0648 15.7892 19.2729 15.334C18.4706 14.4373 17.9997 13.2604 17.9997 12.0002C17.9997 10.74 18.4706 9.5632 19.2729 8.6665C19.1688 8.4405 19.0538 8.21822 18.9279 8.00021C18.802 7.78219 18.667 7.57148 18.5233 7.36842C17.3457 7.61476 16.0911 7.43414 14.9997 6.80405C13.9083 6.17395 13.1246 5.17768 12.7491 4.03455C12.2509 3.98714 11.7492 3.98646 11.2509 4.03292C10.8756 5.17671 10.0916 6.17364 8.99972 6.80405C7.9078 7.43447 6.65245 7.61494 5.47428 7.36803C5.18485 7.77641 4.93463 8.21117 4.72656 8.66637C5.52881 9.56311 5.99972 10.74 5.99972 12.0002C5.99972 13.2604 5.52883 14.4372 4.72656 15.3339C4.83067 15.5599 4.94564 15.7822 5.07152 16.0002C5.19739 16.2182 5.3324 16.4289 5.47612 16.632C6.65377 16.3857 7.90838 16.5663 8.99972 17.1964ZM11.9997 15.0002C10.3429 15.0002 8.99972 13.6571 8.99972 12.0002C8.99972 10.3434 10.3429 9.00021 11.9997 9.00021C13.6566 9.00021 14.9997 10.3434 14.9997 12.0002C14.9997 13.6571 13.6566 15.0002 11.9997 15.0002ZM11.9997 13.0002C12.552 13.0002 12.9997 12.5525 12.9997 12.0002C12.9997 11.4479 12.552 11.0002 11.9997 11.0002C11.4474 11.0002 10.9997 11.4479 10.9997 12.0002C10.9997 12.5525 11.4474 13.0002 11.9997 13.0002Z"/></svg></span>`;
let gliderTab = '';
function placeTabGlider(animate: boolean) {
  const g = document.getElementById('tabGlider'); if (!g) return;
  const active = document.querySelector<HTMLElement>('#tabbar button.on') || document.querySelector<HTMLElement>('#tabbar [data-tab="wallet"]'); if (!active) return;
  g.style.width = active.offsetWidth + 'px';
  const x = 'translateX(' + active.offsetLeft + 'px)';
  const tab = active.dataset.tab || '';
  if (!animate || gliderTab === tab || prefersReducedMotion()) {
    const prev = g.style.transition; g.style.transition = 'none'; g.style.transform = x; void g.offsetHeight; g.style.transition = prev;
  } else {
    g.style.transform = x;
    const inner = document.getElementById('tabGliderIn');
    if (inner && inner.animate) inner.animate([{ transform: 'scaleX(1)' }, { transform: 'scaleX(1.09)', offset: 0.35 }, { transform: 'scaleX(1)' }], { duration: 480, easing: 'ease-out' });
  }
  gliderTab = tab;
}
function updateTabDot() {
  const d = document.getElementById('tabDot'); if (!d) return;
  let pend = false;
  try { pend = loadLocalTxs().some(t => t.acc === accKey()); } catch { pend = false; }
  d.style.display = pend ? '' : 'none';
}
function setTabActive() { const t = currentTab(); document.querySelectorAll('#tabbar [data-tab]').forEach(b => b.classList.toggle('on', (b as HTMLElement).dataset.tab === t)); placeTabGlider(true); updateTabDot(); }
function mountShell() {
  if (shellMounted) return; shellMounted = true;
  app().innerHTML = `<div id="view"></div><nav class="tabbar" id="tabbar">
    <div class="railBrand" aria-hidden="true"><img src="/assets/logo-sm.png" alt=""><span class="railWord">Syn Wallet</span></div>
    <span class="tabTrack" id="tabTrack"></span>
    <span class="tabGlider" id="tabGlider"><span class="tabGliderIn" id="tabGliderIn"><span class="tabSheen"></span></span></span>
    <button data-tab="wallet">${TAB_IC_WALLET}Wallet</button>
    <button data-tab="invest">${TAB_IC_INVEST}Invest</button>
    <button data-tab="activity">${TAB_IC_ACTIVITY}<span class="dot" id="tabDot" style="display:none"></span>Activity</button>
    <button data-tab="settings">${TAB_IC_SETTINGS}Settings</button></nav>`;
  document.querySelectorAll('#tabbar [data-tab]').forEach(b => (b as HTMLElement).onclick = () => {
    const t = (b as HTMLElement).dataset.tab!;
    // Standard iOS behaviour: re-tapping the tab you are already on
    // pops that tab's stack back to its root; re-tapping it AT the
    // root scrolls the screen back to the top instead of re-rendering
    // it. The collapsing header is expanded FIRST — if it re-expanded
    // mid-animation, its growth would shift the layout and strand the
    // scroll a few pixels short of the top. "Already on" is judged by
    // the stack's root tab (currentTab), not the leaf route, so a
    // re-tap deep inside Settings pops to the Settings root.
    if (t === currentTab() && currentRoute === t && navIdx <= 0) { document.querySelector('.ltWrap')?.classList.remove('ltSmall'); window.scrollTo({ top: 0, behavior: prefersReducedMotion() ? 'auto' : 'smooth' }); return; }
    goTab(t, b as HTMLElement);
  });
  placeTabGlider(false);
  updateTabDot();
  window.addEventListener('resize', () => placeTabGlider(false), { passive: true });
  const bar = document.getElementById('tabbar'), track = document.getElementById('tabTrack');
  if (bar && track) {
    let tick = false;
    bar.addEventListener('pointermove', (e: PointerEvent) => {
      if (tick) return; tick = true;
      requestAnimationFrame(() => { const r = bar.getBoundingClientRect(); track.style.transform = 'translateX(' + (e.clientX - r.left) + 'px)'; tick = false; });
    }, { passive: true });
  }
  startEngine();
}
function saveScroll() { if (currentRoute) scrollPos.set(currentRoute + ':' + currentChain, window.scrollY); }
function renderRoute(e: RouteEntry, restore = true) {
  if (!secret) { showUnlock(); return; }
  if (e.route !== 'polymarket') polyDetailCleanup();
  if (e.route !== 'invest') polyListCleanup();
  const prevRoute = currentRoute;
  currentRoute = e.route; currentChain = e.chainId || ''; setTabActive();
  // Desktop layout hook: style.css keys per-screen desktop grids off
  // this attribute (≥1024px only; inert on phone).
  const vwEl = document.getElementById('view'); if (vwEl) vwEl.dataset.route = e.route;
  quietViewIn = prevRoute === e.route && prevRoute !== '';
  if (e.route === 'wallet') showHome();
  else if (e.route === 'activity') showActivity();
  else if (e.route === 'settings') showSettings();
  else if (e.route === 'asset') showAsset(e.chainId!);
  else if (e.route === 'receive') showReceive(e.chainId!);
  else if (e.route === 'send') showSend(e.chainId!);
  else if (e.route === 'confirm' && e.confirm) showSendConfirm(e.confirm.c, e.confirm.to, e.confirm.amtStr, '', e.confirm.poisonWarn, e.confirm.nameLabel || '');
  else if (e.route === 'networks') showNetworks();
  else if (e.route === 'netedit') showNetEdit(e.chainId!);
  else if (e.route === 'accounts') showAccounts();
  else if (e.route === 'keys') showKeys();
  else if (e.route === 'token') showToken(e.tokenId!);
  else if (e.route === 'addtoken') showAddToken();
  else if (e.route === 'tokenconfirm' && e.tokenConfirm) showTokenConfirm(e.tokenConfirm.t, e.tokenConfirm.to, e.tokenConfirm.amtStr, '', e.tokenConfirm.nameLabel || '', e.tokenConfirm.poisonWarn || '');
  else if (e.route === 'sign') showSign(e.signTab || 'msg');
  else if (e.route === 'approvals') showApprovals();
  else if (e.route === 'revoke' && e.revoke) showRevokeConfirm(e.revoke);
  else if (e.route === 'swap') showSwap();
  else if (e.route === 'swapconfirm' && e.swapConfirm) showSwapConfirm(e.swapConfirm);
  else if (e.route === 'stake') showStake(e.chainId || 'solana');
  else if (e.route === 'stakeconfirm' && e.stakeConfirm) showStakeConfirm(e.stakeConfirm);
  else if (e.route === 'lido') showLidoStake();
  else if (e.route === 'lidoconfirm' && e.lidoAmt != null) showLidoConfirm(e.lidoAmt);
  else if (e.route === 'nfts') showNfts();
  else if (e.route === 'nft' && e.nftKey) showNft(e.nftKey);
  else if (e.route === 'nftconfirm' && e.nftConfirm) showNftConfirm(e.nftConfirm.nft, e.nftConfirm.to);
  else if (e.route === 'discover') showDiscover();
  else if (e.route === 'invest') showInvest();
  else if (e.route === 'hlaccount') showHlAccount();
  else if (e.route === 'hlmarket') showHlMarket();
  else if (e.route === 'investtoken') showInvestToken();
  else if (e.route === 'polymarket') showPolyMarket();
  else if (e.route === 'connect') showConnect();
  else if (e.route === 'buy') showBuy();
  quietViewIn = false;
  const y = restore ? (scrollPos.get(routeKey(e)) || 0) : 0;
  // A return to a scrolled position paints the sticky top bar already
  // in its compact state — otherwise it lands tall and visibly
  // shrinks a beat later when the scroll listener catches up.
  if (y > 30) document.querySelector('.ltWrap')?.classList.add('ltSmall');
  if (y) requestAnimationFrame(() => window.scrollTo(0, y));
}
// ---------- navigation transitions (native slide, no snapshot) ----------
// Forward pushes slide the new screen in from the right over a parallax
// dim of the current one; Back reverses it; tab switches crossfade. Both
// screens stay LIVE DOM in a grid stack inside #view and only transform /
// opacity / filter animate (WAAPI), so the transition is GPU-composited
// and holds 60fps by construction — no canvas, no WebGL, no DOM snapshot
// (the old Distortion Wave navigation did one per navigation and read as
// weird and laggy on a real phone). Interruptible: a new navigation
// force-lands the running one instantly. Reduced motion -> plain swap.
const NAV_MS = 280;
const TAB_MS = 180;
const NAV_EASE = 'cubic-bezier(.32,.72,.24,1)';
let navAnim: { finish: () => void } | null = null;
function navTo(swap: () => void, kind: 'fwd' | 'back' | 'fade') {
  cancelActiveFx();
  if (navAnim) navAnim.finish();
  const view = document.querySelector('#view') as HTMLElement | null;
  if (!view || prefersReducedMotion() || viewOverride || !view.firstElementChild) { swap(); return; }
  let leave: HTMLElement | null = null;
  let enter: HTMLElement | null = null;
  try {
    leave = document.createElement('div'); leave.className = 'navLayer';
    enter = document.createElement('div'); enter.className = 'navLayer';
    while (view.firstChild) leave.appendChild(view.firstChild);
    view.append(leave, enter);
    view.classList.add('navStaging');
    setViewTarget(enter);
    swap();
    setViewTarget(null);
    if (!enter.firstElementChild) throw new Error('empty enter layer');
    const D = kind === 'fade' ? TAB_MS : NAV_MS;
    let enterAnim: Animation; let leaveAnim: Animation;
    if (kind === 'fwd') {
      enter.style.zIndex = '2';
      enterAnim = enter.animate([{ transform: 'translateX(100%)' }, { transform: 'translateX(0)' }], { duration: D, easing: NAV_EASE, fill: 'forwards' });
      leaveAnim = leave.animate([{ transform: 'translateX(0)', opacity: 1, filter: 'brightness(1)' }, { transform: 'translateX(-30%)', opacity: 0.55, filter: 'brightness(0.6)' }], { duration: D, easing: NAV_EASE, fill: 'forwards' });
    } else if (kind === 'back') {
      leave.style.zIndex = '2';
      enterAnim = enter.animate([{ transform: 'translateX(-30%)', opacity: 0.55, filter: 'brightness(0.6)' }, { transform: 'translateX(0)', opacity: 1, filter: 'brightness(1)' }], { duration: D, easing: NAV_EASE, fill: 'forwards' });
      leaveAnim = leave.animate([{ transform: 'translateX(0)' }, { transform: 'translateX(100%)' }], { duration: D, easing: NAV_EASE, fill: 'forwards' });
    } else {
      enterAnim = enter.animate([{ opacity: 0 }, { opacity: 1 }], { duration: D, easing: 'ease-out', fill: 'forwards' });
      leaveAnim = leave.animate([{ opacity: 1 }, { opacity: 0 }], { duration: D, easing: 'ease-out', fill: 'forwards' });
    }
    leave.style.pointerEvents = 'none';
    const state = {
      done: false,
      finish: () => {
        if (state.done) return;
        state.done = true;
        if (navAnim === state) navAnim = null;
        try { enterAnim.cancel(); leaveAnim.cancel(); } catch { /* already done */ }
        view.classList.remove('navStaging');
        if (leave && leave.isConnected) leave.remove();
        if (enter && enter.isConnected) {
          while (enter.firstChild) view.appendChild(enter.firstChild);
          enter.remove();
        }
      },
    };
    navAnim = state;
    enterAnim.finished.then(() => state.finish()).catch(() => state.finish());
    setTimeout(() => state.finish(), D + 150);
  } catch {
    // Staging failed anywhere — land the new screen if it painted, else
    // restore the old one. The user keeps a working screen either way.
    setViewTarget(null);
    view.classList.remove('navStaging');
    try {
      if (enter && enter.isConnected && enter.firstElementChild) {
        if (leave && leave.isConnected) leave.remove();
        while (enter.firstChild) view.appendChild(enter.firstChild);
        enter.remove();
      } else if (leave && leave.isConnected) {
        if (enter && enter.isConnected) enter.remove();
        while (leave.firstChild) view.appendChild(leave.firstChild);
        leave.remove();
      }
    } catch { /* last resort: leave the DOM exactly as it stands */ }
  }
}
// The origin element argument is kept on go/goTab for call-site shape;
// the slide no longer needs a source — it always runs the same way.
function isSameScreen(e: RouteEntry): boolean {
  return currentRoute === e.route && currentChain === (e.chainId || '') && (e.route !== 'token' || currentTokenId === (e.tokenId || '')) && e.route !== 'confirm' && e.route !== 'revoke' && e.route !== 'tokenconfirm' && e.route !== 'swapconfirm' && e.route !== 'stakeconfirm' && e.route !== 'nftconfirm' && e.route !== 'lidoconfirm';
}
function go(e: RouteEntry, originEl?: HTMLElement | null) {
  if (isSameScreen(e)) { goNow(e); return; }
  navTo(() => goNow(e), 'fwd');
}
function goNow(e: RouteEntry) {
  mountShell();
  if (isSameScreen(e)) { renderRoute(e, false); return; }
  saveScroll();
  navStack = navStack.slice(0, navIdx + 1); navStack.push(e); navIdx++;
  history.pushState({ i: navIdx }, '');
  renderRoute(e);
}
function goTab(tab: string, originEl?: HTMLElement | null) {
  if (currentRoute === tab) { goTabNow(tab); return; }
  navTo(() => goTabNow(tab), 'fade');
}
function goTabNow(tab: string) {
  mountShell(); saveScroll();
  navStack = [{ route: tab }]; navIdx = 0;
  history.replaceState({ i: 0 }, '');
  renderRoute(navStack[0]);
}
function goBack(fallback: RouteEntry) {
  if (navIdx > 0) { history.back(); return; }
  if (fallback.route === 'wallet' || fallback.route === 'invest' || fallback.route === 'activity' || fallback.route === 'settings') { goTab(fallback.route); return; }
  goTab('wallet'); go(fallback);
}
window.addEventListener('popstate', (ev) => {
  if (!shellMounted) return;
  const i = ev.state && typeof ev.state.i === 'number' ? ev.state.i : 0;
  if (i === navIdx || i < 0 || i >= navStack.length) return;
  saveScroll();
  const dir = i < navIdx ? 'back' : 'fwd';
  const entry = navStack[i];
  navTo(() => { navIdx = i; renderRoute(entry); }, dir);
});
function showApp(tab: string) {
  // Cold boot — no cached data at all for this wallet: keep the
  // first-load boot screen (logo + wave loader, the #splash design) up
  // until the first prices+balances round settles, success OR failure,
  // so the user's first sight of Home is real figures or honest
  // Unavailable states — never Unavailable flashed mid-load. A hard
  // 12s timeout releases the gate so a dead network can't trap anyone.
  // With any cache present this is skipped entirely: instant paint
  // from cache + silent refresh, exactly as before.
  const cold = prices == null && balances.size === 0 && tokenBalances.size === 0;
  const gate = cold ? armFirstRound() : null;
  goTab(tab);
  if (gate) {
    const sp = document.createElement('div');
    sp.id = 'splash'; sp.className = 'bootGate';
    sp.innerHTML = `<img src="/assets/logo-sm.png" alt="Syn"><p>Wallet</p>${waveLoadHTML('lg')}`;
    document.body.appendChild(sp);
    void Promise.race([gate, new Promise(r => setTimeout(r, 12000))]).then(() => sp.remove());
  }
  // Chart prefetch warms in the background once Home is interactive —
  // invisible, idle-scheduled, never blocking first paint.
  const ric = (window as any).requestIdleCallback as ((cb: () => void, opts?: any) => void) | undefined;
  if (ric) ric(() => void prefetchCharts(), { timeout: 4000 });
  else setTimeout(() => void prefetchCharts(), 2500);
  // Explore live values (NFT count, staked SOL) warm the same way —
  // near-immediately, so the data beats the user's first tap.
  setTimeout(() => void warmExplore(), 900);
  // Whole-app warm: Invest sections + Activity history load in the
  // background so no tab or section opens on a loader.
  setTimeout(() => void warmApp(), 1200);
  // FX rates warm in the background too; if the stored display currency
  // had no rate at first paint (values rendered in USD), repaint once
  // the real rates land so the chosen currency takes effect.
  const fxBefore = effectiveCode();
  void fetchFxRates().then(() => { if (effectiveCode() !== fxBefore) rerenderCurrent(); });
}

// Addition 6: Explore row live values. Filled only from data that has
// actually loaded (background); absent data shows nothing — never a
// spinner, never a fake 0.
// Addition 9: an Explore value counts up to its real number when it
// first lands (the standalone design's count-up). Wave FX off (or the
// value already showing) sets it directly — never a fake intermediate.
function countUpVal(el: HTMLElement, target: number, suffix: string, delayMs = 0) {
  if (!wavesFxOn() || el.textContent) { el.textContent = String(target) + suffix; return; }
  const run = () => {
    const t0 = performance.now(); const dur = 950;
    const step = (t: number) => { const k = Math.min(1, (t - t0) / dur); const e = 1 - Math.pow(1 - k, 3); el.textContent = String(Math.round(target * e)) + suffix; if (k < 1) requestAnimationFrame(step); };
    requestAnimationFrame(step);
  };
  if (delayMs > 0) setTimeout(run, delayMs); else run();
}
// Explore values paint from whatever is ALREADY known, synchronously
// with the Home paint: live in-memory caches first, then the values
// persisted in the data cache (exploreVals, keyed to the account that
// produced them). The count-up flourish plays ONCE per session per
// value — its first genuine landing; every later paint, including
// every tab return, sets the final value directly in the same frame.
const exploreFxDone = new Set<string>();
// The Explore entrance choreography (rows cascading in, values
// popping in late) plays on the FIRST Home mount of the session only.
// Every later mount — tab switch, back navigation, same-screen
// re-render — paints the section settled and complete, like a native
// tab screen that was never unloaded (user report 2026-11-20: "every
// time I change tab or go back it reloads again").
let homeFxPlayed = false;
let exploreVals: { key: string; nftCount: number; stakedSol: number } | null = null;
function paintExploreValues() {
  const n = document.getElementById('exValNfts');
  if (n) {
    let count: number | null = null;
    if (nftItems != null && nftForKey === accKey()) {
      const hidden = new Set(config.hiddenNfts);
      const ok = new Set(config.spamOkNfts);
      count = nftItems.filter(x => !hidden.has(x.key) && (!isSpamNft(x) || ok.has(x.key))).length;
    } else if (exploreVals && exploreVals.key === accKey()) count = exploreVals.nftCount;
    if (count != null && n.textContent !== String(count)) {
      if (!exploreFxDone.has('nft') && wavesFxOn()) { exploreFxDone.add('nft'); countUpVal(n as HTMLElement, count, ''); }
      else n.textContent = String(count);
    }
  }
  const s = document.getElementById('exValStake');
  if (s) {
    let sol: number | null = null;
    if (stakeListCache) sol = stakeListCache.rows.reduce((a, r) => a + r.info.delegatedLamports, 0) / 1e9;
    else if (exploreVals && exploreVals.key === accKey()) sol = exploreVals.stakedSol;
    if (sol != null) s.textContent = sol > 0 ? trimNum(sol, 4) + ' SOL staked' : '';
  }
  const w = document.getElementById('exValWc');
  if (w) {
    let count = 0;
    try { count = wcClientReady() ? wcSessions().length : 0; } catch { count = 0; }
    w.textContent = count > 0 ? count + ' connected' : '';
  }
}
let exploreWarmKey = '';
async function warmExplore() {
  const key = accKey();
  if (exploreWarmKey === key || !vaultPayload) return;
  exploreWarmKey = key;
  if (nftItems == null || nftForKey !== key || nftStale) { try { await loadAllNfts(); } catch { /* notes carry it */ } }
  // Preload the first pieces' artwork into the browser cache, so the
  // Collectibles grid and the NFT card's live line paint WITH their
  // images when the screen opens instead of fetching them on show.
  if (nftItems) {
    const hidden = new Set(config.hiddenNfts);
    let warmed = 0;
    for (const it of nftItems) {
      if (hidden.has(it.key)) continue;
      const u = it.image || (it.images && it.images[0]);
      if (u) { const im = new Image(); im.src = u; if (++warmed >= 8) break; }
    }
  }
  const sol = visibleChains().find(c => c.kind === 'solana' || c.kind === 'solana-tw');
  if (sol && (!stakeListCache || stakeListCache.key !== key + ':' + sol.id)) {
    try { const rows = await fetchStakeAccounts(addressFor(sol)); if (rows) stakeListCache = { key: key + ':' + sol.id, rows }; } catch { /* row stays valueless */ }
  }
  // Persist the derived values (account-keyed) so the NEXT cold start
  // paints Explore complete from the data cache instead of waiting
  // for this warm-up to run again.
  const rec: { key: string; nftCount: number; stakedSol: number } = { key, nftCount: exploreVals && exploreVals.key === key ? exploreVals.nftCount : 0, stakedSol: exploreVals && exploreVals.key === key ? exploreVals.stakedSol : 0 };
  if (nftItems != null && nftForKey === key) {
    const hidden = new Set(config.hiddenNfts);
    const ok = new Set(config.spamOkNfts);
    rec.nftCount = nftItems.filter(x => !hidden.has(x.key) && (!isSpamNft(x) || ok.has(x.key))).length;
  }
  if (stakeListCache && stakeListCache.key.startsWith(key + ':')) rec.stakedSol = stakeListCache.rows.reduce((a, r) => a + r.info.delegatedLamports, 0) / 1e9;
  if (!exploreVals || exploreVals.key !== rec.key || exploreVals.nftCount !== rec.nftCount || exploreVals.stakedSol !== rec.stakedSol) { exploreVals = rec; saveDataCache(); }
  if (currentRoute === 'wallet') paintExploreValues();
}

// Whole-app background warm (user's order, 2026-11-19): every tab and
// section's data loads BEFORE it is opened, so navigation never
// lands on a loader. Runs once per account, staggered after Home is
// interactive (charts, Explore and FX already warm the same way), and
// fills the SAME caches the sections read — opening a section then
// paints instantly and refreshes silently as it does today. Every
// step is best-effort: a failed warm changes nothing, the section
// just loads on open as before. Deep per-item data (one token's
// chart beyond the prefetched mains, one market's book, swap quotes)
// is per-selection and still fetched on open.
let warmAppKey = '';
async function warmApp() {
  const key = accKey();
  if (warmAppKey === key || !vaultPayload) return;
  warmAppKey = key;
  const still = () => warmAppKey === key && accKey() === key && !!secret;
  const step = async (fn: () => Promise<unknown>) => { try { await fn(); } catch { /* best-effort */ } };
  // Wave 1 (parallel): the light Invest sections — Hyperliquid
  // markets, the Predictions trending list (same key and call
  // paintInvestPoly makes, so its cache-hit path takes over), and the
  // Crypto section's trending pools for every network in its default
  // All view. Parallel so one slow source never holds up the rest.
  await Promise.allSettled([
    step(() => loadHlMarkets()),
    step(async () => { const evs = await gammaEvents({ limit: 24 }); if (evs && evs.length) polyListMem.set('tag:trending', evs); }),
    step(async () => { await Promise.allSettled(INVEST_NETS.slice(1).map(n => loadGt(n.id))); }),
  ]);
  if (!still()) return;
  // Wave 2 (parallel): the heavy pack — the bStocks catalog (a
  // 112-market aggregation server-side) and the Activity history.
  await Promise.allSettled([
    step(() => loadBstocks()),
    step(async () => {
      await Promise.all(visibleChains().map(async c => {
        const addr = addressFor(c); if (!addr) return;
        try { const rows = await fetchChainActivity(c, addr); pruneLocalTxs(c.id, rows); activityCache.set(c.id, rows); } catch { /* tab degrades as today */ }
      }));
      saveDataCache();
    }),
  ]);
}
// Addition 7: app-wide image fallback. Any <img> that fails steps
// through its data-cands gateway list; when every candidate is dead
// the img hides itself, revealing the designed placeholder/monogram
// behind it. A browser broken-image glyph can never appear anywhere.
document.addEventListener('error', (e) => {
  const t = e.target as HTMLElement | null;
  if (!t || t.tagName !== 'IMG') return;
  const img = t as HTMLImageElement;
  const cands = (img.dataset.cands || '').split('|').filter(Boolean);
  const ix = Number(img.dataset.cix || 0);
  if (ix + 1 < cands.length) { img.dataset.cix = String(ix + 1); img.src = cands[ix + 1]; return; }
  img.style.display = 'none';
}, true);

/** data-cands attribute for an image with gateway fallbacks. */
function candsAttr(images?: string[]): string {
  if (!images || images.length < 2) return '';
  return ` data-cands="${esc(images.join('|'))}" data-cix="0"`;
}

// Addition 7: a generic iOS bottom sheet (dApp details, NFT coverage
// notes). Same motion/scaffold as the swap selector sheet.
function openSheet(title: string, bodyHTML: string): () => void {
  closeSheetEl();
  const wrap = document.createElement('div');
  wrap.className = 'sheetWrap'; wrap.id = 'genericSheetWrap';
  wrap.innerHTML = `<div class="sheetBk"></div><div class="sheet" role="dialog" aria-label="${esc(title)}">
    <div class="sheetGrabZone"><div class="sheetGrab"></div></div>
    <div class="sheetHead"><span class="sheetTitle">${esc(title)}</span><button class="sheetX" type="button" aria-label="Close"><i class="ri-close-line"></i></button></div>
    <div class="sheetBody">${bodyHTML}</div></div>`;
  document.body.appendChild(wrap);
  requestAnimationFrame(() => requestAnimationFrame(() => wrap.classList.add('open')));
  const close = () => { wrap.classList.remove('open'); setTimeout(() => wrap.remove(), 260); };
  (wrap.querySelector('.sheetBk') as HTMLElement).onclick = close;
  (wrap.querySelector('.sheetX') as HTMLElement).onclick = close;
  return close;
}
function closeSheetEl() { document.getElementById('genericSheetWrap')?.remove(); }

/** Re-render the current route in place (config changes like the
 * display currency repaint visible fiat values with no reload). */
function rerenderCurrent() {
  const e = navStack[navIdx];
  if (e && secret) renderRoute(e, false);
}

// Addition 10: display-currency picker — the SAME sheet from the
// balance-card chip and from Settings (one store: lib/currency).
function openCurrencySheet() {
  const paint = () => {
    const body = document.querySelector('#genericSheetWrap .sheetBody');
    if (!body) return;
    const cur = currencyCode();
    const noRates = fxRateFor('EUR') == null;
    body.innerHTML = `${noRates ? '<p class="small muted" style="padding:2px 2px 10px">Exchange rates unavailable right now — only USD can be selected until rates load.</p>' : `<p class="small muted" style="padding:2px 2px 10px">Prices stay USD-sourced; amounts are converted for display with live reference rates.</p>`}
    ${CURRENCIES.map(c => { const avail = c.code === 'USD' || fxRateFor(c.code) != null; return `<button class="curRow" data-cur="${c.code}" type="button" ${avail ? '' : 'disabled'}><span class="curSym">${esc(c.symbol)}</span><span class="curTx"><span class="curCode">${c.code}</span><span class="curName">${esc(c.name)}</span></span>${c.code === cur ? '<i class="ri-check-line curCheck"></i>' : ''}</button>`; }).join('')}`;
    body.querySelectorAll('[data-cur]').forEach(b => (b as HTMLElement).onclick = () => {
      const code = (b as HTMLElement).dataset.cur!;
      if (setCurrency(code)) { closeSheetEl(); rerenderCurrent(); }
      else paint();
    });
  };
  openSheet('Display currency', '<p class="small muted" style="padding:2px 2px 10px">Loading rates…</p>');
  paint();
  if (fxRateFor('EUR') == null) void fetchFxRates().then(() => paint());
}

function orbPair(primary: 'receive' | 'send', onR: () => void, onS: () => void): string {
  // Detail screens' Send/Receive: ONE segmented pair in a single grouped
  // control — two halves sharing one card, the primary half in chrome —
  // not two floating slabs. (Ids kept: bindOrb binds #orbReceive/#orbSend.)
  return `<div class="dPair">
    <button class="dPairBtn ${primary === 'receive' ? 'prime' : ''}" id="orbReceive"><span class="dPairIc"><i class="ri-arrow-down-line"></i></span><span>Receive</span></button>
    <button class="dPairBtn ${primary === 'send' ? 'prime' : ''}" id="orbSend"><span class="dPairIc"><i class="ri-arrow-up-line"></i></span><span>Send</span></button></div>`;
}
function bindOrb(onR: (el: HTMLElement) => void, onS: (el: HTMLElement) => void) { const r = $('#orbReceive'), s = $('#orbSend'); if (r) r.onclick = () => onR(r); if (s) s.onclick = () => onS(s); }

function sortedChains(): Chain[] {
  return [...visibleChains()].sort((a, b2) => {
    const va = (balances.get(a.id) ?? null) != null && priceOf(a) != null ? balances.get(a.id)! * priceOf(a)! : null;
    const vb = (balances.get(b2.id) ?? null) != null && priceOf(b2) != null ? balances.get(b2.id)! * priceOf(b2)! : null;
    if (va == null && vb == null) return 0; if (va == null) return 1; if (vb == null) return -1; return vb - va;
  });
}
function homeRowHTML(c: Chain): string {
  const b = balances.get(c.id); const p = priceOf(c); const ch = changeOf(c);
  const ps = priceStateOf(c.cg); const bs = balStateOf(c.id);
  return `<button class="aRow" data-chain="${c.id}">
    ${coinIcon(c)}
    <span class="aMid"><span class="aName">${esc(c.name)} <span class="aSym">${esc(c.symbol)}</span></span>
    <span class="aSub"><span data-f="price">${p != null ? fmtPrice(p) : ps === 'pending' ? '…' : 'Price unavailable'}</span><span data-f="chg">${ch != null ? `<span class="chgPill ${ch >= 0 ? 'pos' : 'neg'}">${ch >= 0 ? '+' : ''}${ch.toFixed(2)}%</span>` : ''}</span></span></span>
    <span class="aRight"><span class="amt" data-f="usd">${hideBal ? '••••' : b != null && p != null ? fmtUsd(b * p) : ps === 'pending' || bs === 'pending' ? '…' : '—'}</span><span class="usd" data-f="crypto">${hideBal ? '' : b == null ? (bs === 'pending' ? 'Loading…' : 'Unavailable') : fmtCrypto(b, c.symbol)}</span></span>
    <i class="ri-arrow-right-s-line aChev"></i></button>`;
}
function tokenRowHTML(g: TokenGroup): string {
  const rep = g.rep;
  const tp = groupPrice(g); const ch = groupChange(g);
  const { amount, fiat, pending } = groupTotals(g);
  const ps = priceStateOf(g.asset || rep.cg);
  const multi = g.members.length > 1;
  const heldMembers = g.members.filter(m => (tokenBalances.get(m.id) ?? 0) > 0);
  const stackMembers = heldMembers.length ? heldMembers : g.members;
  const stack = multi ? `<span class="miniStack">${stackMembers.map(m => { const mc = findChain(m.chainId); return mc && chainIconUrl(mc) ? `<span class="hStackIc">${stackIconHTML(chainIconUrl(mc), mc.name)}</span>` : ''; }).join('')}</span>` : '';
  return `<button class="aRow" data-token="${rep.id}">${tokenIcon(rep)}
    <span class="aMid"><span class="aName">${esc(rep.symbol)} <span class="aSym">${multi ? esc(rep.name) : esc(findChain(rep.chainId)?.name || '')}</span></span>
    <span class="aSub"><span data-tok="price">${tp != null ? fmtPrice(tp) : ps === 'pending' ? '…' : 'Price unavailable'}</span><span data-tok="chg">${ch != null ? `<span class="chgPill ${ch >= 0 ? 'pos' : 'neg'}">${ch >= 0 ? '+' : ''}${ch.toFixed(2)}%</span>` : ''}</span>${stack}</span></span>
    <span class="aRight"><span class="amt" data-tok="usd">${fiat != null ? fmtUsd(fiat) : pending || ps === 'pending' ? '…' : '—'}</span><span class="usd" data-tok="crypto">${amount == null ? (pending ? 'Loading…' : 'Unavailable') : fmtCrypto(amount, rep.symbol)}</span></span>
    <i class="ri-arrow-right-s-line aChev"></i></button>`;
}
function showHome() {
  clearInterval(chartTimer);
  if (!secret) { showUnlock(); return; }
  // Prefetch the promo card's trending market so the first Invest
  // open usually paints its live line instantly (self-guarded by the
  // cache's freshness window — a no-op when already fresh).
  if (!promoPolyDismissed()) void fillPromoPolyLive();
  // Balance-card network stack: the top chains' logos overlapping like
  // an iOS avatar stack (ring in the card's tone), +N for the rest —
  // resolved through the one icon path, monogram where no logo exists.
  const stackChains = sortedChains().slice(0, 5);
  const stackHTML = `<span class="heroStack" aria-hidden="true">${stackChains.filter(c => chainIconUrl(c)).map(c => `<span class="hStackIc">${stackIconHTML(chainIconUrl(c), c.name)}</span>`).join('')}${visibleChains().length > 5 ? `<span class="hStackMore">+${visibleChains().length - 5}</span>` : ''}</span>`;
  const tokenRowsHTML = homeTokenRowsHTML();
  setView(`<main class="homeMain"><div class="ptr" id="ptr"><i class="ri-arrow-down-line"></i></div><div class="ltWrap homeLt"><div class="topbar"><span class="logoChip"><img src="/assets/logo-sm.png" alt="Syn"></span><button class="acctBtn" id="acctBtn" type="button"><span class="t">Syn Wallet</span><div class="optSub">${esc(activeWallet()?.name || 'Wallet')}${(activeWallet()?.accounts || 1) > 1 || accountIdx() > 0 ? ' · Account ' + (accountIdx() + 1) : ''} <i class="ri-arrow-down-s-line"></i></div></button><span class="sp"></span>
    <button class="iconBtn" id="eyeBtn" aria-label="Toggle balance visibility"><i class="${hideBal ? 'ri-eye-off-line' : 'ri-eye-line'}"></i></button>
    <button class="iconBtn" id="refBtn" aria-label="Refresh balances"><i class="ri-refresh-line"></i></button></div></div>
    <section class="heroCard"><svg class="heroLine" viewBox="0 0 600 200" preserveAspectRatio="none" aria-hidden="true"><path id="heroLinePath" fill="none" stroke="rgba(233,237,242,.5)" stroke-width="2.6" stroke-linecap="butt" vector-effect="non-scaling-stroke"/></svg><div class="heroFx heroFxHalo" aria-hidden="true"><div class="heroBeam"></div></div><div class="heroFx heroFxCore" aria-hidden="true"><div class="heroBeam"></div></div><div class="heroTop"><span class="heroLabel">Total Balance</span><span class="heroTopR">${stackHTML}<button class="usdChip" id="curChip" type="button" aria-label="Change display currency">${currencyCode()}</button></span></div>
    <div class="balRow"><div class="balanceBig" id="totalBal">…</div></div><div class="deltaLine" id="deltaSlot"></div><div class="heroNote" id="totalNote"></div></section>
    <div class="actionGrid">
    <button class="actionBtn primary alive" id="actSend"><i class="sendFx fxFlow"></i><i class="sendFx fxSheen"></i><i class="ri-arrow-up-line"></i><span class="albl">Send</span></button>
    <button class="actionBtn" id="actReceive"><i class="ri-arrow-down-line"></i><span class="albl">Receive</span></button>
    <button class="actionBtn" id="actSwap"><i class="ri-arrow-left-right-line"></i><span class="albl">Swap</span></button>
    <button class="actionBtn" id="actBuy"><i class="ri-bank-card-line"></i><span class="albl">Buy</span></button>
    <button class="actionBtn" id="actActivity"><i class="ri-time-line"></i><span class="albl">Activity</span></button>
    <button class="actionBtn" id="actLock"><i class="ri-lock-line"></i><span class="albl">Lock</span></button></div>
    <section class="homeSec"><div class="secHead"><span class="secTitle">Tokens</span><button class="linkBtn" id="hmAddTok" type="button"><i class="ri-add-line"></i> Add token</button></div>
    ${tokenRowsHTML ? `<div class="iosList homeList" id="tokenList">${tokenRowsHTML}</div>` : '<p class="small muted secEmpty">No tokens yet — stablecoins on your enabled networks appear here automatically.</p>'}</section>
    <section class="homeSec"><div class="secHead"><span class="secTitle">Explore</span></div>
    <div class="iosList homeList exploreList" id="exploreList"><span class="exBeamHalo" aria-hidden="true"></span><span class="exBeam" aria-hidden="true"></span>
    <button class="aRow exploreRow" id="exNfts" style="--i:0"><span class="exSheen" aria-hidden="true"></span><span class="coinIc"><i class="ri-image-2-line"></i></span><span class="aMid"><span class="aName">Collectibles</span><span class="aSub">Your NFTs on Solana &amp; EVM</span></span><span class="exVal" id="exValNfts"></span><i class="ri-arrow-right-s-line aChev"></i></button>
    ${visibleChains().some(c => c.kind === 'solana' || c.kind === 'solana-tw') ? '<button class="aRow exploreRow" id="exStake" style="--i:1"><span class="exSheen" aria-hidden="true"></span><span class="coinIc"><i class="ri-seedling-line"></i></span><span class="aMid"><span class="aName">Stake SOL</span><span class="aSub">Native staking with validators</span></span><span class="exVal" id="exValStake"></span><i class="ri-arrow-right-s-line aChev"></i></button>' : ''}
    <button class="aRow exploreRow" id="exDiscover" style="--i:2"><span class="exSheen" aria-hidden="true"></span><span class="coinIc"><i class="ri-compass-3-line"></i></span><span class="aMid"><span class="aName">Discover dApps</span><span class="aSub">Uniswap, Jupiter, Aave &amp; more</span></span><span class="exVal" id="exValDapps">${DAPPS.length} dApps</span><i class="ri-arrow-right-s-line aChev"></i></button>
    <button class="aRow exploreRow" id="exConnect" style="--i:3"><span class="exSheen" aria-hidden="true"></span><span class="coinIc"><i class="ri-qr-scan-2-line"></i></span><span class="aMid"><span class="aName">WalletConnect</span><span class="aSub">Connect this wallet to a dApp</span></span><span class="exVal" id="exValWc"></span><i class="ri-arrow-right-s-line aChev"></i></button>
    </div></section>
    </main>`);
  ($('#eyeBtn') as HTMLElement).onclick = () => { hideBal = !hideBal; renderRoute({ route: 'wallet' }, false); };
  const cc = $('#curChip'); if (cc) cc.onclick = () => openCurrencySheet();
  ($('#refBtn') as HTMLElement).onclick = () => { const b = $('#refBtn') as HTMLElement; const orig = b.innerHTML; b.innerHTML = waveLoadHTML('sm'); refreshData(true).finally(() => { if (b.isConnected) b.innerHTML = orig; }); };
  const actSend = $('#actSend') as HTMLElement; actSend.onclick = () => { const c = visibleChains()[0]; if (c) go({ route: 'send', chainId: c.id }, actSend); };
  const actReceive = $('#actReceive') as HTMLElement; actReceive.onclick = () => { const c = visibleChains()[0]; if (c) go({ route: 'receive', chainId: c.id }, actReceive); };
  const actActivity = $('#actActivity') as HTMLElement; actActivity.onclick = () => goTab('activity', actActivity);
  ($('#actLock') as HTMLElement).onclick = () => lock();
  const actSwap = $('#actSwap') as HTMLElement; actSwap.onclick = () => go({ route: 'swap' }, actSwap);
  const actBuy = $('#actBuy') as HTMLElement; actBuy.onclick = () => go({ route: 'buy' }, actBuy);
  const exN = $('#exNfts'); if (exN) exN.onclick = () => go({ route: 'nfts' }, exN as HTMLElement);
  const exS = $('#exStake'); if (exS) exS.onclick = () => go({ route: 'stake', chainId: visibleChains().find(c => c.kind === 'solana')?.id || 'solana' }, exS as HTMLElement);
  const exD = $('#exDiscover'); if (exD) exD.onclick = () => go({ route: 'discover' }, exD as HTMLElement);
  const exC = $('#exConnect'); if (exC) exC.onclick = () => go({ route: 'connect' }, exC as HTMLElement);
  V().querySelectorAll('[data-chain]').forEach(b => (b as HTMLElement).onclick = () => go({ route: 'asset', chainId: (b as HTMLElement).dataset.chain! }, b as HTMLElement));
  V().querySelectorAll('[data-token]').forEach(b => (b as HTMLElement).onclick = () => go({ route: 'token', tokenId: (b as HTMLElement).dataset.token! }, b as HTMLElement));
  const ab = $('#acctBtn'); if (ab) ab.onclick = () => go({ route: 'accounts' }, ab);
  const ht = $('#hmAddTok'); if (ht) ht.onclick = () => go({ route: 'addtoken' }, ht);
  initPullToRefresh();
  paintHomeValues();
  paintExploreValues();
  // Addition 9: Explore alive — fx class gates every Explore animation
  // (same wavesFxOn gate as the balance-card breach), and the dApps
  // value counts up to DAPPS.length like the standalone design.
  const xl = $('#exploreList'); if (xl && wavesFxOn()) { xl.classList.add('fxOn'); if (homeFxPlayed) xl.classList.add('settled'); else homeFxPlayed = true; }
  const dv = $('#exValDapps'); if (dv && wavesFxOn() && !exploreFxDone.has('dapps')) { exploreFxDone.add('dapps'); dv.textContent = ''; countUpVal(dv, DAPPS.length, ' dApps', 450); }
  // Balance-card line + breach: a silver line sweeps the card's lower
  // half and a bright segment rides it, exiting at the right edge. The
  // light layers are masked by the line's own shape (a data-URI SVG
  // built from the same path as the drawn line), so the light can only
  // ever sit on the line. Off when Wave effects are off in Settings.
  const lineD = 'M-10,176 C60,156 110,134 175,126 C225,120 245,132 295,112 C335,97 365,103 420,92 C465,84 495,68 528,53 L612,1';
  const lp = $('#heroLinePath'); if (lp) lp.setAttribute('d', lineD);
  const lineMask = (w: number) => `url("data:image/svg+xml,${encodeURIComponent(`<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 600 200' preserveAspectRatio='none'><path d='${lineD}' fill='none' stroke='white' stroke-width='${w}' stroke-linecap='butt'/></svg>`)}")`;
  V().querySelectorAll('.heroFx').forEach(el => {
    const h = el as HTMLElement;
    if (!wavesFxOn()) { h.style.display = 'none'; return; }
    const m = lineMask(h.classList.contains('heroFxHalo') ? 13 : 4.6);
    h.style.setProperty('-webkit-mask-image', m); h.style.maskImage = m;
  });
  // Send's alive chrome layers follow the same gate as the breach:
  // wave effects off (or reduced motion) = static silver tile.
  if (!wavesFxOn()) {
    V().querySelectorAll('.sendFx').forEach(el => { (el as HTMLElement).style.display = 'none'; });
    const sb = $('#actSend'); if (sb) sb.classList.remove('alive');
  }
  refreshData();
}
// Paint (or repaint, in place) every live figure on Home from the store.
function paintHomeValues() {
  if (currentRoute !== 'wallet' || !document.querySelector('#totalBal')) return;
  const { total, partial } = totalUsd();
  if (total != null) recordSnap(total);
  // While ANY figure the total depends on is still PENDING (its first
  // fetch round hasn't completed), the total shows a quiet '…' — never
  // "Unavailable", and pending balances are never summed in as zero
  // (totalUsd only sums settled figures; the rest just aren't in yet).
  const anyPending = !pricesSettled || visibleChains().some(c => !balances.has(c.id)) || visibleTokens().some(t => !tokenBalances.has(t.id));
  flashSet($('#totalBal'), 'total', hideBal ? '••••••' : total == null ? (anyPending ? '…' : 'Unavailable') : fmtUsd(total), hideBal ? null : total);
  // Audit fix: .balanceBig is nowrap at 44px — very large totals (or
  // long currency formats) clipped at the hero card's edge. Shrink to
  // fit by formatted length.
  const tbEl = $('#totalBal'); if (tbEl && total != null && !hideBal) { const len = fmtUsd(total).length; tbEl.style.fontSize = len > 15 ? '27px' : len > 12 ? '33px' : len > 10 ? '38px' : ''; }
  const tn = $('#totalNote');
  if (tn) { const note = total == null ? (anyPending ? '' : 'Prices or balances unavailable — pull to refresh.') : partial && !anyPending ? 'Some chains unavailable — total is partial.' : ''; tn.textContent = note; }
  renderDelta(total);
  const order = sortedChains();
  for (const c of order) {
    const row = document.querySelector(`#tokenList [data-chain="${c.id}"]`); if (!row) continue;
    const b = balances.get(c.id); const p = priceOf(c); const ch = changeOf(c);
    flashSet(row.querySelector('[data-f="usd"]'), 'usd:' + c.id, hideBal ? '••••' : b != null && p != null ? fmtUsd(b * p) : '—', hideBal ? null : b != null && p != null ? b * p : null);
    const cr = row.querySelector('[data-f="crypto"]'); if (cr) cr.textContent = hideBal ? '' : b == null ? (balStateOf(c.id) === 'pending' ? 'Loading…' : 'Unavailable') : fmtCrypto(b, c.symbol);
    const pr = row.querySelector('[data-f="price"]'); if (pr) pr.textContent = p != null ? fmtPrice(p) : priceStateOf(c.cg) === 'pending' ? '…' : 'Price unavailable';
    const cg = row.querySelector('[data-f="chg"]');
    if (cg) { const html = ch != null ? `<span class="chgPill ${ch >= 0 ? 'pos' : 'neg'}">${ch >= 0 ? '+' : ''}${ch.toFixed(2)}%</span>` : ''; if (cg.innerHTML !== html) cg.innerHTML = html; }
  }
  const tsec = $('#tokenList');
  if (tsec) {
    // A token that just became held (e.g. a receive landed while Home
    // is open) has no row yet — re-render once to add it.
    const shouldShow = visibleTokens().filter(tokenShowsOnHome);
    if (shouldShow.some(t => !tsec.querySelector(`[data-token="${t.id}"]`))) { renderRoute({ route: 'wallet' }, false); return; }
    for (const t of shouldShow) {
      const row = tsec.querySelector(`[data-token="${t.id}"]`); if (!row) continue;
      const amount = tokenBalances.has(t.id) ? tokenBalances.get(t.id)! : null;
      const tp = tokenUsd(t);
      const fiat = amount != null && tp != null ? amount * tp : null;
      flashSet(row.querySelector('[data-tok="usd"]'), 'tokusd:' + t.id, hideBal ? '••••' : fiat != null ? fmtUsd(fiat) : '—', hideBal ? null : fiat);
      const cr = row.querySelector('[data-tok="crypto"]'); if (cr) cr.textContent = hideBal ? '' : amount == null ? (priceStateOf(t.cg) === 'pending' ? 'Loading…' : 'Unavailable') : fmtCrypto(amount, t.symbol);
      const pr = row.querySelector('[data-tok="price"]'); if (pr) pr.textContent = tp != null ? fmtPrice(tp) : priceStateOf(t.cg) === 'pending' ? '…' : 'Price unavailable';
      const cgEl = row.querySelector('[data-tok="chg"]'); if (cgEl) { const ch = tokenChg(t); const html = ch != null ? `<span class="chgPill ${ch >= 0 ? 'pos' : 'neg'}">${ch >= 0 ? '+' : ''}${ch.toFixed(2)}%</span>` : ''; if (cgEl.innerHTML !== html) cgEl.innerHTML = html; }
    }
    // One list for natives + tokens, sorted by value — but the DOM
    // order is only rewritten when the row SET changes (account
    // switch, a token appearing/disappearing). Audit fix: re-sorting
    // on every price paint moved rows under the user's finger while
    // they were reaching for one; values still update in place above.
    const fiatOf = new Map<string, number | null>();
    for (const c of order) { const b = balances.get(c.id); const pr = priceOf(c); fiatOf.set('c:' + c.id, b != null && pr != null ? b * pr : null); }
    for (const t of shouldShow) fiatOf.set('t:' + t.id, tokenFiat(t));
    const rows = [...tsec.querySelectorAll('[data-chain],[data-token]')] as HTMLElement[];
    const setSig = accKey() + '|' + rows.map(r => r.dataset.chain ? 'c:' + r.dataset.chain : 't:' + r.dataset.token).sort().join(',');
    if (setSig !== homeSortSig) {
      homeSortSig = setSig;
      rows.sort((a, b) => { const ka = a.dataset.chain ? 'c:' + a.dataset.chain : 't:' + a.dataset.token; const kb = b.dataset.chain ? 'c:' + b.dataset.chain : 't:' + b.dataset.token; const fa = fiatOf.get(ka) ?? null, fb = fiatOf.get(kb) ?? null; if (fa == null && fb == null) return 0; if (fa == null) return 1; if (fb == null) return -1; return fb - fa; });
      rows.forEach(r => tsec.appendChild(r));
    }
  }
}
// Pull-to-refresh on Home: drag down from the top → background refresh,
// nothing blanks, the spinner is the only thing that moves.
function initPullToRefresh() {
  const view = V(); const ptr = $('#ptr'); if (!ptr) return;
  let startY = 0; let pulling = false;
  view.addEventListener('touchstart', (e) => { if (window.scrollY <= 0) { startY = e.touches[0].clientY; pulling = true; } }, { passive: true });
  view.addEventListener('touchmove', (e) => {
    if (!pulling) return;
    const dy = e.touches[0].clientY - startY;
    if (dy > 0 && window.scrollY <= 0) { ptr.style.transition = 'none'; ptr.style.transform = `translate(-50%, ${Math.min(dy * 0.5, 64) - 64}px)`; ptr.style.opacity = String(Math.min(1, dy / 90)); }
    else { pulling = false; ptr.style.transform = ''; ptr.style.opacity = '0'; }
  }, { passive: true });
  view.addEventListener('touchend', (e) => {
    if (!pulling) return; pulling = false;
    const dy = e.changedTouches[0].clientY - startY;
    ptr.style.transition = 'transform .25s ease, opacity .25s ease';
    if (dy > 130) { ptr.style.transform = 'translate(-50%, 14px)'; ptr.style.opacity = '1'; refreshData(true).finally(() => { ptr.style.transform = ''; ptr.style.opacity = '0'; }); }
    else { ptr.style.transform = ''; ptr.style.opacity = '0'; }
  });
}

// Balance change pill: delta vs the oldest locally recorded snapshot that is
// at least 20 minutes and at most 24 hours old. Hidden when there is no honest
// reference point yet (new wallet) — never a fabricated change figure.
function renderDelta(total: number | null) {
  const slot = $('#deltaSlot'); if (!slot) return;
  if (hideBal || total == null) { slot.innerHTML = ''; return; }
  const now = Date.now();
  const ref = loadSnaps().find(s => now - s.t >= 20 * 60 * 1000 && now - s.t <= 24 * 3600 * 1000);
  if (!ref || ref.v <= 0) { slot.innerHTML = ''; return; }
  const d = total - ref.v; const pct = (d / ref.v) * 100;
  slot.innerHTML = `<span class="deltaPill ${d >= 0 ? 'pos' : 'neg'}"><i class="${d >= 0 ? 'ri-arrow-up-s-fill' : 'ri-arrow-down-s-fill'}"></i>${d >= 0 ? '+' : '−'}${fmtUsd(Math.abs(d))} · ${Math.abs(pct).toFixed(1)}%</span>`;
}
async function fetchChartSeries(c: Chain, range: string): Promise<[number, number][] | null> {
  try {
    const r = await fetch(`/api/chart/${c.cg}?range=${range}`); if (!r.ok) return null;
    const j = await r.json(); const pts: [number, number][] = j.prices || [];
    return pts.length ? pts : null;
  } catch { return null; }
}
// Fallback series for the line chart: the coin's OHLC candle closes. Real
// recent data from a different server cache key — when the primary range
// is cold (e.g. the server just deployed into an upstream rate-limit
// window), the 7-day candles are very likely already cached.
async function fetchOhlcLine(c: Chain): Promise<[number, number][] | null> {
  if (!c.cg) return null;
  const candles = await fetchOhlc(c.cg, 7);
  if (!candles || !candles.length) return null;
  return candles.map(cd => [cd.time, cd.close] as [number, number]);
}
// Last painted series per asset+range, kept in memory so a screen
// that re-opens (Welcome re-entry, flow back-navigation) paints its
// chart INSTANTLY and refreshes in place — the same stale-while-
// revalidate pattern as the price and OHLC disk caches.
const chartSeriesCache = new Map<string, [number, number][]>();
async function loadChart(el: HTMLElement | null, c: Chain, range: string, height = 190) {
  if (!el) return;
  const cacheKey = (c.cg || c.id) + ':' + range;
  const paint = (pts: [number, number][]) => {
    chartSeriesCache.set(cacheKey, pts);
    renderTickerChart(el, pts, { height });
    clearInterval(chartTimer);
    const baseLen = pts.length;
    chartTimer = setInterval(async () => {
      // Audit fix: the old callback returned forever on a detached
      // element — the interval leaked for the whole session, polling
      // prices and growing the series unbounded. Self-clear instead,
      // and cap the appended live tail.
      if (!el.isConnected) { clearInterval(chartTimer); return; }
      const p = await fetchPrices(); const cur = c.cg ? p?.[c.cg]?.usd : null; if (!cur) return;
      pts.push([Date.now(), cur]);
      if (pts.length > baseLen + 500) pts.splice(baseLen, pts.length - baseLen - 500);
      renderTickerChart(el, pts, { height });
    }, 25000);
  };
  // Instant seed, before any await: the in-memory series from a
  // previous visit, else the disk OHLC closes (the day range, else
  // the week — the same substitution fetchOhlcLine already makes for
  // this chart). Real data only; the fresh series replaces it in
  // place when it lands, inside the slot's reserved box.
  let seeded = false;
  const mem = chartSeriesCache.get(cacheKey);
  if (mem && mem.length > 1) { renderTickerChart(el, mem, { height }); seeded = true; }
  else if (c.cg) {
    const disk = ohlcFromDisk(c.cg);
    const rows = disk && disk.d && disk.d.length > 1 ? disk.d : disk && disk.w && disk.w.length > 1 ? disk.w : null;
    if (rows) { renderTickerChart(el, rows.map(cd => [cd.time, cd.close] as [number, number]), { height }); seeded = true; }
  }
  let pts = await fetchChartSeries(c, range);
  if (!pts) pts = await fetchOhlcLine(c);
  if (pts) { paint(pts); return; }
  // A seeded chart is never wiped by a failure message — it stays on
  // screen and the self-retry below keeps trying to refresh it.
  if (!seeded) el.innerHTML = '<div class="chartEmpty">Live chart unavailable right now. The price above is still live.</div>';
  // Self-retry: a cold server cache during an upstream rate-limit window
  // recovers on its own — keep trying quietly while this screen is open.
  let tries = 0;
  const retry = setInterval(async () => {
    if (!el.isConnected || ++tries > 6) { clearInterval(retry); return; }
    let p2 = await fetchChartSeries(c, range);
    if (!p2) p2 = await fetchOhlcLine(c);
    if (p2) { clearInterval(retry); paint(p2); }
  }, 20000);
}

// ---------- ExpoKit PriceChart (canvas port, lib/pricechart.ts) ----------
// Real OHLC candles from /api/ohlc aggregated to Day (hourly) / Week
// (daily) / Month (weekly) / Year (monthly) periods. The ExpoKit design
// is a line chart, so the port plots each bucket's CLOSE from that same
// data — smooth line + gradient fill, dashed baseline at the period's
// first close, trend-tinted, with 1D/1W/1M/1Y pill tabs under the plot. While
// the user scrubs, the screen's ONE price headline follows the finger
// (value + change vs the period's first close, ExpoKit-style) and
// returns to the live spot price on release. Candles are cached in
// memory AND in localStorage (public market data only, like the price
// cache), so revisiting a detail screen paints the chart INSTANTLY
// from cache and refreshes it in place; when OHLC can't be fetched and
// nothing is cached, the chart area says so, honestly. The selected
// period's close + change is captioned under the chart in app
// typography (last close minus first open — the same math as always).
// In-flight coalescing: the same (asset, range) is never fetched twice
// concurrently — the background chart prefetch and a user opening that
// asset's detail share ONE request instead of competing.
const ohlcInflight = new Map<string, Promise<OhlcCandle[] | null>>();
function fetchOhlc(cgId: string, days: number): Promise<OhlcCandle[] | null> {
  const key = cgId + ':' + days;
  const hit = ohlcInflight.get(key);
  if (hit) return hit;
  const p = (async (): Promise<OhlcCandle[] | null> => {
    try {
      const r = await fetch(`/api/ohlc?id=${encodeURIComponent(cgId)}&days=${days}`);
      if (!r.ok) return null;
      const j = await r.json();
      const rows: number[][] = Array.isArray(j.candles) ? j.candles : [];
      if (!rows.length) return null;
      return rows.map(a => ({ time: a[0], open: a[1], high: a[2], low: a[3], close: a[4], volume: a[5] || 0 }));
    } catch { return null; }
  })();
  ohlcInflight.set(key, p);
  void p.finally(() => { if (ohlcInflight.get(key) === p) ohlcInflight.delete(key); });
  return p;
}
type OhlcRanges = { d: OhlcCandle[] | null; w: OhlcCandle[] | null; m: OhlcCandle[] | null; y: OhlcCandle[] | null; at: number };
const ohlcMem = new Map<string, OhlcRanges>();
const OHLC_CACHE_KEY = 'syn-wallet-ohlc-v1';
function ohlcFromDisk(cgId: string): OhlcRanges | null {
  try {
    const j = JSON.parse(localStorage.getItem(OHLC_CACHE_KEY) || 'null');
    const e = j?.[cgId];
    // Entries written before the 1D range existed have no `d` — they
    // still paint W/M/Y instantly; the day range joins on fresh fetch.
    if (e && Array.isArray(e.w) && Array.isArray(e.m) && Array.isArray(e.y)) return { d: Array.isArray(e.d) ? e.d : null, w: e.w, m: e.m, y: e.y, at: e.at || 0 };
  } catch { /* no cache */ }
  return null;
}
function ohlcToDisk(cgId: string, r: OhlcRanges) {
  try {
    const j = JSON.parse(localStorage.getItem(OHLC_CACHE_KEY) || '{}');
    j[cgId] = { d: r.d, w: r.w, m: r.m, y: r.y, at: r.at };
    // keep the cache bounded: the 12 most recently refreshed assets
    // (matches the chart-prefetch cap so warmed mains survive on disk)
    const keys = Object.keys(j).sort((a, b) => (j[b].at || 0) - (j[a].at || 0));
    for (const k of keys.slice(12)) delete j[k];
    localStorage.setItem(OHLC_CACHE_KEY, JSON.stringify(j));
  } catch { /* storage full/blocked */ }
}
// ---------- chart prefetch (background, invisible) ----------
// Once Home is interactive, warm the OHLC store for the native assets
// of the ENABLED chains — the two ranges a detail screen opens with
// (1W, the default) and is likeliest to tap next (1D) — so opening a
// main asset paints its chart instantly from the store, exactly as if
// the user had opened it before. No UI of any kind; requests run
// sequentially with a stagger, skip anything still fresh, and share
// in-flight requests with the detail screen via fetchOhlc coalescing.
// Re-warm rides the live engine's cadence (see startEngine) and only
// touches entries that have gone stale — no separate polling loop.
const CHART_PREFETCH_MAX = 12;
const CHART_FRESH_MS = 5 * 60 * 1000;
let chartPrefetchAt = 0;
let chartPrefetchRunning = false;
function mainChartAssets(): string[] {
  const en = enabledSet();
  const rank = (id: string) => { const i = DEFAULT_ENABLED.indexOf(id); return i < 0 ? 99 : i; };
  const ids: string[] = [];
  for (const c of [...CHAINS].sort((a, b) => rank(a.id) - rank(b.id))) {
    if (en.has(c.id) && c.cg && !ids.includes(c.cg)) ids.push(c.cg);
    if (ids.length >= CHART_PREFETCH_MAX) break;
  }
  return ids;
}
async function prefetchCharts() {
  if (chartPrefetchRunning || !secret) return;
  chartPrefetchRunning = true; chartPrefetchAt = Date.now();
  try {
    for (const cgId of mainChartAssets()) {
      if (!secret) break; // locked mid-run — stop quietly
      const cur = ohlcMem.get(cgId) || ohlcFromDisk(cgId);
      if (cur && cur.d && cur.w && Date.now() - cur.at < CHART_FRESH_MS) continue; // already fresh
      const [d, w] = await Promise.all([
        cur?.d && Date.now() - cur.at < CHART_FRESH_MS ? Promise.resolve(cur.d) : fetchOhlc(cgId, 1),
        cur?.w && Date.now() - cur.at < CHART_FRESH_MS ? Promise.resolve(cur.w) : fetchOhlc(cgId, 7),
      ]);
      if (d || w) {
        const merged: OhlcRanges = { d: d ?? cur?.d ?? null, w: w ?? cur?.w ?? null, m: cur?.m ?? null, y: cur?.y ?? null, at: Date.now() };
        ohlcMem.set(cgId, merged); ohlcToDisk(cgId, merged);
      }
      await new Promise(r => setTimeout(r, 350)); // stagger — never a burst
    }
  } finally { chartPrefetchRunning = false; }
}
let chartHandle: PriceChartHandle | null = null;
let chartPeriods: ChartPeriod[] = [];
let chartPeriodSel = 'week';
let chartGen = 0;
let chartScrubbing = false;
function paintChartCaption() {
  const el = $('#chartCaption'); if (!el) return;
  const p = chartPeriods.find(x => x.value === chartPeriodSel) ?? chartPeriods[0];
  const cs = p?.candles ?? [];
  if (!p || !cs.length) { el.textContent = ''; return; }
  const first = cs[0]; const last = cs[cs.length - 1];
  const chg = last.close - first.open;
  const pct = first.open > 0 ? (chg / first.open) * 100 : 0;
  const dec = (v: number) => priceDp(v);
  el.innerHTML = `${esc(p.name)} close <b>${fmtUsd(last.close, dec(last.close))}</b> · <span class="${chg >= 0 ? 'pos' : 'neg'}">${chg >= 0 ? '+' : '−'}${fmtUsd(Math.abs(chg), dec(chg))} (${Math.abs(pct).toFixed(1)}%)</span>`;
}
async function loadPriceChart(host: HTMLElement, cgId: string, onScrub: (info: ScrubInfo | null) => void) {
  const gen = ++chartGen;
  chartScrubbing = false;
  const scrub = (info: ScrubInfo | null) => { chartScrubbing = !!info; onScrub(info); };
  // 1) Instant paint from cache (memory first, then disk). The default
  // range is Week even though Day now sorts first in the period list.
  const cached = ohlcMem.get(cgId) || ohlcFromDisk(cgId);
  if (cached) {
    const p0 = buildPeriods(cached.d ?? [], cached.w ?? [], cached.m ?? [], cached.y ?? []);
    if (p0.length) {
      chartPeriods = p0; chartPeriodSel = (p0.find(p => p.value === 'week') ?? p0[0]).value;
      chartHandle = mountPriceChart(host, { periods: p0, selected: chartPeriodSel, onPeriodChange: (v) => { chartPeriodSel = v; paintChartCaption(); }, onScrub: scrub });
      paintChartCaption();
    }
  }
  // 2) Fresh candles — one retry for any range that failed (upstream
  // rate limits are bursty), then update the SAME chart in place. On
  // the FIRST pass of a mount, ranges the chart prefetch already
  // warmed (and that are still fresh) are not refetched at all — the
  // open is a pure store paint with zero network wait for 1D/1W; the
  // 60s refresh cadence below fetches everything as before.
  let firstApply = true;
  const fetchRanges = async (): Promise<OhlcRanges> => {
    const cur = ohlcMem.get(cgId) || ohlcFromDisk(cgId);
    const warm = firstApply && cur && Date.now() - cur.at < CHART_FRESH_MS ? cur : null;
    firstApply = false;
    let [d, w, m, y] = await Promise.all([
      warm?.d ? Promise.resolve(warm.d) : fetchOhlc(cgId, 1),
      warm?.w ? Promise.resolve(warm.w) : fetchOhlc(cgId, 7),
      warm?.m ? Promise.resolve(warm.m) : fetchOhlc(cgId, 30),
      warm?.y ? Promise.resolve(warm.y) : fetchOhlc(cgId, 365),
    ]);
    if (!d || !w || !m || !y) {
      await new Promise(r => setTimeout(r, 1000));
      [d, w, m, y] = await Promise.all([d ?? fetchOhlc(cgId, 1), w ?? fetchOhlc(cgId, 7), m ?? fetchOhlc(cgId, 30), y ?? fetchOhlc(cgId, 365)]);
    }
    return { d, w, m, y, at: Date.now() };
  };
  const applyFresh = async () => {
    const r = await fetchRanges();
    if (!host.isConnected || gen !== chartGen) return;
    const periods = buildPeriods(r.d ?? [], r.w ?? [], r.m ?? [], r.y ?? []);
    if (!periods.length) {
      if (!chartHandle) host.innerHTML = '<div class="chartEmpty">Live chart unavailable right now. The price above is still live.</div>';
      return;
    }
    ohlcMem.set(cgId, r); ohlcToDisk(cgId, r);
    chartPeriods = periods;
    if (chartHandle) chartHandle.update(periods);
    else {
      chartPeriodSel = (periods.find(p => p.value === 'week') ?? periods[0]).value;
      chartHandle = mountPriceChart(host, { periods, selected: chartPeriodSel, onPeriodChange: (v) => { chartPeriodSel = v; paintChartCaption(); }, onScrub: scrub });
    }
    paintChartCaption();
  };
  await applyFresh();
  if (!host.isConnected || gen !== chartGen) return;
  // 3) Refresh on the server's cache cadence while this screen stays open.
  clearInterval(chartTimer);
  chartTimer = setInterval(() => { if (!host.isConnected || gen !== chartGen) { clearInterval(chartTimer); return; } void applyFresh(); }, 60000);
}

// 24h range bar (detail Stats): a slim track with a dot positioned at
// the current price between the real 24h low and high. Painted only
// when all three figures exist and high > low — otherwise the whole
// block hides rather than implying a range we don't have. Element ids
// are <base>, <base>Dot, <base>Low, <base>High.
function paintRangeEls(base: string, d: any, price: number | null) {
  const wrap = document.getElementById(base); if (!wrap) return;
  const hi = d?.high24h ?? null; const lo = d?.low24h ?? null;
  if (price == null || hi == null || lo == null || !(hi > lo)) { wrap.style.display = 'none'; return; }
  wrap.style.display = '';
  const pct = Math.max(0, Math.min(100, ((price - lo) / (hi - lo)) * 100));
  const dot = document.getElementById(base + 'Dot'); if (dot) dot.style.left = pct.toFixed(1) + '%';
  const dec = (v: number) => priceDp(v);
  const l = document.getElementById(base + 'Low'); if (l) l.textContent = fmtUsd(lo, dec(lo));
  const h = document.getElementById(base + 'High'); if (h) h.textContent = fmtUsd(hi, dec(hi));
}
// Market-cap 24h change, rendered as a small delta beside the cap
// value. Real CoinGecko figure via the server store; blank when the
// current source never published one (never derived or faked).
function paintMcapChg(id: string, d: any) {
  const el = document.getElementById(id); if (!el) return;
  const mv = d?.marketCapChange24h ?? null;
  if (mv == null) { el.textContent = ''; el.className = 'delta'; return; }
  el.textContent = (mv >= 0 ? '+' : '−') + Math.abs(mv).toFixed(2) + '%';
  el.className = 'delta ' + (mv >= 0 ? 'pos' : 'neg');
}

// ---------- asset detail + ExpoKit price chart ----------
// Paints INSTANTLY from the store (no awaits before first paint), then a
// background refresh updates the figures in place via paintDetailValues.
function showAsset(chainId: string) {
  const c = CHAINS.find(x => x.id === chainId)!; const addr = addressFor(c);
  clearInterval(chartTimer);
  setView(`<main><button class="backBtn" id="bk" aria-label="Back"><i class="ri-arrow-left-s-line"></i></button>
    <div class="dHead">
      <div class="dIdRow">${coinIcon(c, true)}<div class="dIdTx"><div class="dName">${esc(c.name)}</div><div class="dSym">${esc(c.symbol)} · ${esc(addr.slice(0, 6))}…${esc(addr.slice(-4))}</div></div><span class="liveDot">LIVE</span></div>
      <div class="dBalBlock"><div class="dEyebrow">YOUR BALANCE</div><div class="dBalHero" id="dBalCrypto">…</div><div class="dBalUsd" id="dBalUsd"></div></div>
      <div class="dPriceBlock"><div class="dEyebrow" id="dEyebrow">CURRENT PRICE</div><div class="dPriceRow"><span class="dPriceVal" id="dPrice">…</span><span id="dChange"></span></div></div>
    </div>
    ${c.cg ? `<div class="dChart"><div id="priceChart" class="pchartHost"><div class="chartEmpty">${waveLoadHTML()} Loading live chart…</div></div></div><div class="chartCap" id="chartCaption"></div>` : '<div class="dNote">No price source for this network — the balance above is read live from its RPC.</div>'}
    ${orbPair('send', () => go({ route: 'receive', chainId: c.id }), () => go({ route: 'send', chainId: c.id }))}
    <div class="gGroup"><div class="gHead">Actions</div><div class="gCard">
      <button class="sRow" id="dSwap"><span class="sIco"><i class="ri-swap-line"></i></span><span class="sTx"><span class="sLbl">Swap <b>${esc(c.symbol)}</b></span></span><span class="sChev"><i class="ri-arrow-right-s-line"></i></span></button>
      ${(c.kind === 'solana' || c.kind === 'solana-tw' || c.kind === 'solana-phantom') ? '<button class="sRow" id="dStake"><span class="sIco"><i class="ri-seedling-line"></i></span><span class="sTx"><span class="sLbl">Stake <b>SOL</b></span></span><span class="sChev"><i class="ri-arrow-right-s-line"></i></span></button>' : ''}
      ${c.id === 'ethereum' ? '<button class="sRow" id="dLido"><span class="sIco"><i class="ri-drop-line"></i></span><span class="sTx"><span class="sLbl">Stake with <b>Lido</b></span></span><span class="sChev"><i class="ri-arrow-right-s-line"></i></span></button>' : ''}
      ${(c.kind === 'solana' || c.kind === 'solana-tw' || c.kind === 'solana-phantom' || c.blockscout) ? '<button class="sRow" id="dNfts"><span class="sIco"><i class="ri-image-2-line"></i></span><span class="sTx"><span class="sLbl">Your <b>collectibles</b></span></span><span class="sChev"><i class="ri-arrow-right-s-line"></i></span></button>' : ''}
      <button class="sRow" id="expBtn"><span class="sIco"><i class="ri-external-link-line"></i></span><span class="sTx"><span class="sLbl">View on <b>explorer</b></span></span><span class="sChev"><i class="ri-arrow-right-s-line"></i></span></button>
      ${keyTargetForChain(c) ? keyRowHTML('dKey') : ''}
    </div></div>
    <div class="gGroup"><div class="gHead">Stats</div><div class="gCard flushHair">
      <div class="sRow stat"><span class="sTx"><span class="sLbl">Price</span></span><span class="sVal strong" id="stPrice">…</span></div>
      <div class="sRow stat"><span class="sTx"><span class="sLbl">24h change</span></span><span class="sVal strong" id="stChg">…</span></div>
      <div class="sRow stat"><span class="sTx"><span class="sLbl">24h high</span></span><span class="sVal strong" id="stHigh">…</span></div>
      <div class="sRow stat"><span class="sTx"><span class="sLbl">24h low</span></span><span class="sVal strong" id="stLow">…</span></div>
      <div class="rangeWrap" id="stRange" style="display:none"><div class="rangeTrack"><div class="rangeDot" id="stRangeDot"></div></div><div class="rangeEnds"><span id="stRangeLow"></span><span class="rangeMid">24h range</span><span id="stRangeHigh"></span></div></div>
      <div class="sRow stat"><span class="sTx"><span class="sLbl">Market cap</span></span><span class="sVal strong"><span id="stMcap">…</span><span class="delta" id="stMcapChg"></span></span></div>
      ${c.cg ? '<div class="sRow stat"><span class="sTx"><span class="sLbl">Market data</span></span><button class="monoChip" id="cgBtn">CoinGecko <i class="ri-arrow-right-up-line"></i></button></div>' : ''}
      <div class="sRow stat"><span class="sTx"><span class="sLbl">Your address</span><div class="sSub">Tap the chip to copy</div></span><button class="monoChip" id="dAddrCopy">${esc(shortAddr(addr))}</button></div>
    </div></div>
    </main>`);
  bindOrb((el) => go({ route: 'receive', chainId: c.id }, el), (el) => go({ route: 'send', chainId: c.id }, el));
  const dSw = $('#dSwap'); if (dSw) dSw.onclick = () => { presetSwapFrom(c.id); go({ route: 'swap' }, dSw); };
  const dSt = $('#dStake'); if (dSt) dSt.onclick = () => go({ route: 'stake', chainId: c.id }, dSt);
  const dLi = $('#dLido'); if (dLi) dLi.onclick = () => go({ route: 'lido' }, dLi);
  const dNf = $('#dNfts'); if (dNf) dNf.onclick = () => go({ route: 'nfts' }, dNf);
  ($('#bk') as HTMLElement).onclick = () => goBack({ route: 'wallet' });
  const eb = $('#expBtn'); if (eb) { if (!c.explorerAddr) eb.style.display = 'none'; else eb.onclick = () => window.open(c.explorerAddr + addr, '_blank'); }
  const dK = $('#dKey'); if (dK) dK.onclick = () => openChainKey(c, () => showAsset(c.id));
  ($('#dAddrCopy') as HTMLElement).onclick = (e) => copyText(addr, e.currentTarget as HTMLElement);
  const cgBtn = $('#cgBtn'); if (cgBtn && c.cg) cgBtn.onclick = () => window.open(`https://www.coingecko.com/en/coins/${c.cg}`, '_blank');
  paintDetailValues(c);
  if (c.cg) { const host = $('#priceChart'); if (host) void loadPriceChart(host, c.cg, (info) => paintAssetScrub(c, info)); }
  (async () => { await fetchPrices(); if (!balances.has(c.id)) balances.set(c.id, await fetchBalance(c)); saveDataCache(); paintDetailValues(c); })();
}
function fmtMcap(v: number): string { const cv = convertUsd(v); const sym = currencySymbol(); if (v >= 1e9) return sym + (cv / 1e9).toFixed(2) + 'B'; if (v >= 1e6) return sym + (cv / 1e6).toFixed(1) + 'M'; return fmtUsd(v, 0); }
// ExpoKit scrub headline: while the finger is on the chart, the
// screen's one headline shows the scrubbed close, the change vs the
// period's first close in ExpoKit's format, and the point's date in
// the eyebrow; on release the live spot headline is repainted.
function paintAssetScrub(c: Chain, info: ScrubInfo | null) {
  const eb = $('#dEyebrow');
  if (!info) { if (eb) eb.textContent = 'CURRENT PRICE'; paintDetailValues(c); return; }
  if (currentRoute !== 'asset' || currentChain !== c.id) return;
  if (eb) eb.textContent = info.label.toUpperCase();
  const dp = $('#dPrice'); if (dp) dp.textContent = fmtPrice(info.value);
  const dc = $('#dChange');
  if (dc) dc.innerHTML = `<span class="delta ${info.up ? 'pos' : 'neg'}">${info.up ? '+' : '−'}${fmtPrice(Math.abs(info.change))} (${info.up ? '+' : '−'}${Math.abs(info.pct).toFixed(2)}%)</span>`;
}
function paintDetailValues(c: Chain) {
  if (currentRoute !== 'asset' || currentChain !== c.id) return;
  const p = priceOf(c); const ch = changeOf(c); const b = balances.get(c.id);
  const d = c.cg ? prices?.[c.cg] : null;
  const un = priceStateOf(c.cg) === 'pending' ? '…' : 'Unavailable'; // pending paints '…', never "Unavailable"
  if (!chartScrubbing) {
    flashSet($('#dPrice'), 'price:' + c.id, p != null ? fmtPrice(p) : un, p);
    const dc = $('#dChange');
    if (dc) dc.innerHTML = ch != null ? `<span class="delta ${ch >= 0 ? 'pos' : 'neg'}"><i class="${ch >= 0 ? 'ri-arrow-up-s-fill' : 'ri-arrow-down-s-fill'}"></i>${Math.abs(ch).toFixed(2)}% · 24h</span>` : '';
  }
  const bc = $('#dBalCrypto');
  if (bc) { bc.textContent = b == null ? (balStateOf(c.id) === 'pending' ? 'Loading…' : 'Unavailable') : b.toFixed(6) + ' ' + c.symbol; const bl = bc.textContent.length; bc.style.fontSize = bl > 20 ? '22px' : bl > 16 ? '26px' : ''; }
  const bu = $('#dBalUsd');
  if (bu) bu.textContent = b != null && p != null ? fmtUsd(b * p) : '';
  const set = (id: string, txt: string) => { const el = $(id); if (el) el.textContent = txt; };
  set('#stPrice', p != null ? fmtPrice(p) : un);
  const sc = $('#stChg'); if (sc) { sc.textContent = ch != null ? (ch >= 0 ? '+' : '') + ch.toFixed(2) + '%' : un; sc.className = 'sVal strong ' + (ch == null ? '' : ch >= 0 ? 'pos' : 'neg'); }
  set('#stHigh', d?.high24h != null ? fmtPrice(d.high24h) : un);
  set('#stLow', d?.low24h != null ? fmtPrice(d.low24h) : un);
  paintRangeEls('stRange', d, p);
  set('#stMcap', d?.marketCap != null ? fmtMcap(d.marketCap) : un);
  paintMcapChg('stMcapChg', d);
}


// ---------- confirm -> receipt celebration (chrome rings) ----------
// Pure CSS/WAAPI rings from the pressed button — see lib/fx.ts for why
// the snapshot-based Distortion Wave was removed. Every call site runs
// AFTER its transaction has broadcast, and celebrateFx swaps the receipt
// in before the rings play, so the effect never delays or gates it; with
// wave effects off (Settings) or reduced motion the receipt just lands.
// Seed/backup/verify screens never pass through here — they render
// outside the shell.
function wavesFxOn(): boolean { return config.waveFx !== false && !prefersReducedMotion(); }
function celebrate(originEl: HTMLElement | null, swap: () => void) {
  if (!originEl || !document.body.contains(originEl) || !wavesFxOn()) { swap(); return; }
  celebrateFx(originEl, swap);
}
// Press feedback: a short scale / brightness nudge on the pressed
// control (lib/fx.ts). Fired from a passive pointerdown listener; the
// control's own handler is untouched. Only inside the unlocked shell,
// so onboarding, seed and unlock screens stay still; controls that
// navigate or confirm are generally excluded — their slide /
// celebration is their feedback. The one exception is the home action
// tiles: they are large touch targets whose old disc press animation
// set the expectation, so they get a gentler 0.97 tile pulse.
document.addEventListener('pointerdown', (e) => {
  if (!shellMounted || !wavesFxOn()) return;
  const t = e.target as HTMLElement;
  const tile = t.closest('.actionBtn') as HTMLElement | null;
  if (tile) { if (!tile.hasAttribute('disabled')) pressPulse(tile, 0.97); return; }
  const b = t.closest('#keypad button, .seg button, .pctChips button, .chipPick, .switch, .iconBtn, .pasteBtn, .convPill, .assetPick, .netPill, .monoChip, .pillBtn, .linkBtn, .gradBtn, .sheetX') as HTMLElement | null;
  if (b && !b.hasAttribute('disabled')) pressPulse(b);
}, { passive: true });
// Audit fix: review/confirm sheets truncated the recipient (and other
// security-relevant values) to first10…last8 while the copy told the
// user to "check every character" — the full value was unreachable.
// Any .monoChip carrying data-full now toggles truncated/full on tap.
document.addEventListener('click', (e) => {
  const chip = (e.target as HTMLElement).closest?.('.monoChip[data-full]') as HTMLElement | null;
  if (!chip) return;
  const full = chip.dataset.full || '';
  if (chip.classList.toggle('open')) chip.textContent = full;
  else chip.textContent = chip.dataset.trunc || (full.length > 20 ? full.slice(0, 10) + '…' + full.slice(-8) : full);
});
// A button's pending state: the Wave loader plus its label, replacing
// the old text-only "Signing & broadcasting…" swaps.
function btnBusy(btn: HTMLButtonElement, label?: string) {
  btn.disabled = true;
  btn.innerHTML = waveLoadHTML() + (label ? `<span style="margin-left:9px">${esc(label)}</span>` : '');
}

// ---------- name resolution (ENS .eth / SNS .sol) ----------
// ENS resolves on Ethereum mainnet no matter which EVM chain the send is
// on (the same behaviour as MetaMask); SNS reads the Bonfida name account
// through the wallet's Solana RPC. A name that does not resolve, or whose
// suffix we do not support, hard-blocks the send — it is never guessed.
function b64Bytes(s: string): Uint8Array { const bin = atob(s); const out = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i); return out; }
function ensProvider(): ethers.JsonRpcProvider { const eth = findChain('ethereum')!; return new ethers.JsonRpcProvider(evmProviderUrl(eth), 1); }
type NameResolution = { address: string; kind: NameKind } | { error: string };
async function resolveNameFor(c: Chain, rawInput: string): Promise<NameResolution> {
  const input = rawInput.trim().toLowerCase();
  const kind = nameKindOf(input);
  if (!kind) return { error: 'Only .eth (ENS) and .sol (SNS) names are supported. Other name services are not resolved by Syn Wallet — use the raw address instead.' };
  if (kind === 'ens') {
    if (c.kind !== 'evm') return { error: 'ENS (.eth) names only work on EVM networks. Switch the network, or use the raw address.' };
    try {
      const addr = await ensProvider().resolveName(input);
      if (!addr) return { error: `The ENS name ${input} does not resolve to an address.` };
      return { address: addr, kind };
    } catch { return { error: `Could not resolve ${input} — the name service could not be reached. The send is blocked rather than guessed.` }; }
  }
  if (c.kind !== 'solana' && c.kind !== 'solana-tw' && c.kind !== 'solana-phantom') return { error: 'SNS (.sol) names only work on Solana. Switch the network, or use the raw address.' };
  try {
    const key = snsDomainKey(input);
    const v = await solanaRpcCall('getAccountInfo', [key.toBase58(), { encoding: 'base64' }]);
    const data = v?.value?.data?.[0];
    if (!v?.value || !data) return { error: `The domain ${input} does not exist.` };
    const owner = snsOwnerFromAccountData(b64Bytes(data));
    if (!owner || owner === '11111111111111111111111111111111') return { error: `The domain ${input} has no owner address.` };
    return { address: owner, kind };
  } catch { return { error: `Could not resolve ${input} — the name service could not be reached. The send is blocked rather than guessed.` }; }
}
// Best-effort reverse display (never blocks anything): ENS primary name
// for an EVM address, favourite .sol domain for a Solana address.
async function reverseNameFor(c: Chain, address: string): Promise<string | null> {
  try {
    if (c.kind === 'evm') { const n = await ensProvider().lookupAddress(address); return n || null; }
    if (c.kind === 'solana' || c.kind === 'solana-tw' || c.kind === 'solana-phantom') {
      const wallet = new PublicKey(address);
      const fav = await solanaRpcCall('getAccountInfo', [snsFavouriteKey(wallet).toBase58(), { encoding: 'base64' }]);
      const favData = fav?.value?.data?.[0]; if (!favData) return null;
      const nameAcct = snsFavouriteNameAccount(b64Bytes(favData)); if (!nameAcct) return null;
      const acct = await solanaRpcCall('getAccountInfo', [nameAcct, { encoding: 'base64' }]);
      const acctData = acct?.value?.data?.[0]; if (!acctData) return null;
      const acctBytes = b64Bytes(acctData);
      const parent = snsParentFromAccountData(acctBytes);
      const revKey = snsReverseKey(new PublicKey(nameAcct), parent && parent !== SNS_ROOT ? new PublicKey(parent) : undefined);
      const rev = await solanaRpcCall('getAccountInfo', [revKey.toBase58(), { encoding: 'base64' }]);
      const revData = rev?.value?.data?.[0]; if (!revData) return null;
      const name = snsNameFromReverseData(b64Bytes(revData)); if (!name) return null;
      if (parent && parent !== SNS_ROOT) {
        const prevKey = snsReverseKey(new PublicKey(parent));
        const prev = await solanaRpcCall('getAccountInfo', [prevKey.toBase58(), { encoding: 'base64' }]);
        const prevData = prev?.value?.data?.[0];
        const parentName = prevData ? snsNameFromReverseData(b64Bytes(prevData)) : null;
        return parentName ? `${name}.${parentName}.sol` : `${name}.sol`;
      }
      return `${name}.sol`;
    }
  } catch { /* reverse display is best-effort */ }
  return null;
}
// Is this input already a syntactically valid raw address for the chain?
function isRawAddressFor(c: Chain, input: string): boolean {
  const s = input.trim();
  if (c.kind === 'solana' || c.kind === 'solana-tw' || c.kind === 'solana-phantom') { try { new PublicKey(s); return true; } catch { return false; } }
  if (c.kind === 'tron') return isValidTronAddress(s);
  if (c.kind === 'bitcoin') return isValidUtxoAddress(c.id, s);
  if (c.kind === 'evm') return ethers.isAddress(s);
  return false;
}

// ---------- GoPlus risk rendering (never a bare "safe" verdict) ----------
function riskReportHTML(rep: RiskReport, subject: string): string {
  if (rep.status === 'unavailable') return `<p class="small muted" style="line-height:1.55"><i class="ri-shield-line"></i> Risk check unavailable — ${esc(rep.reason || 'the check could not be completed.')} Nothing here has been verified either way; do your own research.</p>`;
  const src = rep.source ?? 'GoPlus';
  const parts: string[] = [];
  if (rep.warnings.length) parts.push(`<div class="warn" style="margin:0 0 8px"><b>${esc(src)} flags for this ${esc(subject)}:</b><br>${rep.warnings.map(w => '• ' + esc(w)).join('<br>')}</div>`);
  if (rep.notes.length) parts.push(`<p class="small muted" style="line-height:1.6">${rep.notes.map(n => '• ' + esc(n)).join('<br>')}</p>`);
  if (!rep.warnings.length && !rep.notes.length) parts.push(`<p class="small muted" style="line-height:1.55">No risks found by ${esc(src)} for this ${esc(subject)}. That is not a guarantee — always verify addresses and contracts yourself.</p>`);
  else if (!rep.warnings.length) parts.push(`<p class="small muted" style="line-height:1.55">No risk flags from ${esc(src)} for this ${esc(subject)} — the notes above are properties of the contract, not a guarantee of safety.</p>`);
  return parts.join('');
}
async function paintAddressRisk(el: HTMLElement | null, address: string, c: Chain) {
  if (!el) return;
  if (c.kind !== 'evm' && c.kind !== 'solana' && c.kind !== 'solana-tw' && c.kind !== 'solana-phantom') { el.innerHTML = '<p class="small muted">Address risk check is not available for this network.</p>'; return; }
  el.innerHTML = `<p class="small muted">${waveLoadHTML()} Checking this address with GoPlus…</p>`;
  const rep = await gpAddressRisk(address, c.kind === 'evm' ? String(c.evmId) : 'solana');
  if (!el.isConnected) return;
  el.innerHTML = rep.status === 'unavailable'
    ? '<p class="small muted">Address risk check unavailable right now — the send is not blocked by this, but verify the address carefully yourself.</p>'
    : rep.warnings.length
      ? `<div class="err" style="margin:0">GoPlus flags this address: ${rep.warnings.map(esc).join(' · ')}. Think twice before sending.</div>`
      : '<p class="small muted">No risks found by GoPlus for this address. That is not a guarantee — verify every character yourself.</p>';
  // Second source: Trust Wallet's address validation adds the
  // sanctions/blacklist layer GoPlus's free check does not carry.
  const verdict = await twAddressVerdict(c.id, address);
  if (!verdict || !el.isConnected) return;
  if (verdict.isSanctioned || verdict.result === 'blacklist') {
    el.insertAdjacentHTML('beforeend', `<div class="err" style="margin-top:8px">Trust Wallet flags this address as ${verdict.isSanctioned ? 'sanctioned' : 'blacklisted'}${verdict.labels.length ? ` (${verdict.labels.map(esc).join(', ')})` : ''}. Do not send.</div>`);
  } else if (verdict.result === 'whitelist') {
    el.insertAdjacentHTML('beforeend', '<p class="small muted" style="margin-top:6px">Trust Wallet lists this address as known (whitelist).</p>');
  }
}

// ---------- receive / send ----------
async function showReceive(chainId: string, tokenId?: string) {
  const c = CHAINS.find(x => x.id === chainId)!; const addr = addressFor(c);
  // A token picked in the Receive sheet scopes this screen to that
  // asset (same address — it is the network's address — but the
  // warning and the pill name the token, so nothing is ambiguous).
  const t0 = tokenId ? findToken(tokenId) : undefined;
  const tok = t0 && pickerChainId(t0.chainId) === chainId ? t0 : undefined;
  // Chain-specific receive notes ONLY where the chain genuinely needs
  // one (tags/memos are an exchange-account concept — a personal
  // wallet address never needs one). Other chains show no note.
  const note = c.kind === 'xrp' ? 'No destination tag is needed to receive at this address — it is your own wallet, not an exchange account. If a sending service insists on a tag, 0 is the standard placeholder.'
    : c.kind === 'cosmos' ? 'No memo is needed to receive at this address — it is your own wallet, not an exchange account.'
    : '';
  setView(`<main><button class="backBtn" id="bk" aria-label="Back"><i class="ri-arrow-left-s-line"></i></button>
  <div class="largeTitle" style="padding-top:2px">Receive</div>
  <div style="padding:0 16px"><p class="small muted" style="line-height:1.55">${tok ? `Only send ${esc(tok.name)} (${esc(tok.symbol)}) on ${esc(c.name)} to this address — sending another asset or network may lose funds.` : `Only send ${esc(c.name)} (${esc(c.symbol)}) assets to this address — sending another network may lose funds.`}</p></div>
  <div style="height:16px"></div>
  <div style="text-align:center"><button class="netPill" id="netPill">${tok ? `${iconHTML(tokenIconUrl(tok), tok.symbol, tok.name)}<span>${esc(tok.symbol)} · ${esc(c.name)}</span>` : `${coinIcon(c)}<span>${esc(c.name)}</span>`}<i class="ri-arrow-down-s-line"></i></button></div>
  <div class="qrCard"><div class="qrCardIn"><div class="qrInner"><canvas id="qr"></canvas></div>
  <button class="qrAddr" id="qrAddr" type="button"><span class="mono">${esc(addr.slice(0, 16))}…${esc(addr.slice(-14))}</span><i class="ri-file-copy-line"></i></button></div></div>
  <div style="text-align:center"><button class="linkBtn" id="qrFull" type="button">Show full address</button></div>
  <p class="mono" id="qrFullAddr" style="display:none;text-align:center;margin:2px 22px 0;font-size:12px;line-height:1.6;word-break:break-all;color:var(--silver)">${esc(addr)}</p>
  <div class="tileRow">
    <button class="actionBtn primary" id="cpAddr" type="button"><i class="ri-file-copy-line"></i><span class="albl">Copy address</span></button>
    <button class="actionBtn" id="shareBtn" type="button"><i class="ri-share-line"></i><span class="albl">Share</span></button>
  </div>
  ${note ? `<p class="small muted" style="text-align:center;margin:14px 22px 0;line-height:1.55">${note}</p>` : ''}
  </main>`);
  ($('#bk') as HTMLElement).onclick = () => goBack({ route: 'wallet' });
  ($('#cpAddr') as HTMLElement).onclick = (e) => copyText(addr, e.currentTarget as HTMLElement);
  ($('#qrAddr') as HTMLElement).onclick = (e) => copyText(addr, e.currentTarget as HTMLElement);
  // Audit fix: the full address was never visible on Receive (only a
  // truncated chip) — it can now be revealed for visual verification.
  ($('#qrFull') as HTMLElement).onclick = () => { const p = $('#qrFullAddr'); const b = $('#qrFull'); if (!p || !b) return; const show = p.style.display === 'none'; p.style.display = show ? 'block' : 'none'; b.textContent = show ? 'Hide full address' : 'Show full address'; };
  ($('#shareBtn') as HTMLElement).onclick = async (e) => {
    const btn = e.currentTarget as HTMLElement;
    if (navigator.share) { try { await navigator.share({ title: `My ${c.name} address`, text: addr }); return; } catch { /* dismissed — fall through to copy */ } }
    await copyText(addr, btn);
  };
  ($('#netPill') as HTMLElement).onclick = () => openReceivePicker(c, tok?.id);
  try { await QRCode.toCanvas(document.getElementById('qr') as HTMLCanvasElement, addr, { width: 216, margin: 0 }); } catch { /* QR unavailable */ }
}
// Receive configuration of the shared picker: a network rail over
// the SAME complete asset set Send/Swap use — the selected network's
// native asset (with its receive address) plus every token hosted on
// it. Every listed asset receives at the selected network's address
// by construction: a row's network IS the address's network, so there
// are no dead entries. Picking any row opens that asset's receive
// screen.
function receiveRowInner(a: SwapAsset, current: Chain, tokenId?: string): string {
  const c = findChain(a.chainId);
  const selected = a.contract === 'native' ? (a.chainId === current.id && !tokenId) : a.tokenId === tokenId;
  const check = selected ? '<span class="arrowChip grad"><i class="ri-check-line"></i></span>' : '';
  if (a.contract === 'native') { const addr = c ? addressFor(c) : ''; return `${c ? coinIcon(c) : ''}<span class="shTx"><span class="shName">${esc(a.name)} <span class="aSym">${esc(a.symbol)}</span></span><span class="shNet mono">${esc(addr.slice(0, 12))}…${esc(addr.slice(-8))}</span></span>${check}`; }
  const b = a.tokenId ? tokenBalances.get(a.tokenId) : null;
  return `${iconHTML(a.img, a.symbol, a.name)}<span class="shTx"><span class="shName">${esc(a.name)} <span class="aSym">${esc(a.symbol)}</span></span><span class="shNet">${esc(c?.name || '')}</span></span>${b != null ? `<span class="shRight"><span class="shBal">${trimNum(b)} ${esc(a.symbol)}</span></span>` : ''}${check}`;
}
function openReceivePicker(current: Chain, tokenId?: string) {
  const assets = swapAssets();
  const h = openPickerSheet({
    title: 'Select asset',
    placeholder: 'Search name or symbol',
    networks: pickerNetworks(assets),
    initialNet: current.id,
    rows: () => assets.map(a => ({ key: a.key, net: a.chainId, searchText: (a.name + ' ' + a.symbol + ' ' + (findChain(a.chainId)?.name || '')).toLowerCase(), html: receiveRowInner(a, current, tokenId) })),
    onPick: (key) => { const a = assets.find(x => x.key === key); if (!a) return; h.close(); showReceive(a.chainId, a.tokenId); },
    emptyText: (q) => `No assets match '${q}'`,
    footer: 'Tokens receive at their own network\u2019s address, shown on the network\u2019s row. Every EVM network uses the same address.',
  });
}
// Send drafts survive re-renders (errors, chain switching) per chain.
export const SENDABLE_KINDS = new Set<ChainKind>(['evm', 'solana', 'solana-tw', 'solana-phantom', 'tron', 'bitcoin']);
function hexToBytes(hex: string): Uint8Array { const h = hex.replace(/^0x/, ''); const out = new Uint8Array(h.length / 2); for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16); return out; }
function tronToHex(base58Addr: string): string { const raw = bs58.decode(base58Addr); return Array.from(raw.slice(0, 21)).map(b => b.toString(16).padStart(2, '0')).join(''); }
function tronHexToBase58(hex: string): string {
  try {
    const h = hex.replace(/^0x/i, '');
    if (!/^[0-9a-fA-F]{42}$/.test(h)) return '';
    const raw = Uint8Array.from(h.match(/.{2}/g)!.map(b => parseInt(b, 16)));
    const chk = sha256(sha256(raw)).slice(0, 4);
    const full = new Uint8Array(25); full.set(raw); full.set(chk, 21);
    return bs58.encode(full);
  } catch { return ''; }
}
// Audit M-9: shared address-poisoning check for BOTH send flows —
// near-miss (same first 6 / last 4, not identical) against the user's
// own addresses on every visible chain and against recent
// counterparties. Hex addresses compare case-insensitively; base58
// addresses compare exactly (case is significant there).
function poisonWarning(to: string): string {
  const near = (a: string, b: string): boolean => {
    const hex = /^0x/i.test(a) && /^0x/i.test(b);
    const x = hex ? a.toLowerCase() : a; const y = hex ? b.toLowerCase() : b;
    return x !== y && x.slice(0, 6) === y.slice(0, 6) && x.slice(-4) === y.slice(-4);
  };
  for (const oc of visibleChains()) { const oa = addressFor(oc); if (oa && near(oa, to)) return 'This recipient starts and ends like one of your own addresses but is not identical to it. That pattern is used in address-poisoning attacks — double-check the full address before sending.'; }
  for (const cp of loadCounterparties()) if (near(cp, to)) return 'This recipient starts and ends like an address you have transacted with before, but is not identical to it. That pattern is used in address-poisoning attacks — double-check the full address before sending.';
  return '';
}
type SendDraft = { to: string; amt: string; mode: 'usd' | 'crypto' };
const sendDrafts = new Map<string, SendDraft>();
function draftFor(id: string): SendDraft { let d = sendDrafts.get(id); if (!d) { d = { to: '', amt: '', mode: 'usd' }; sendDrafts.set(id, d); } return d; }
function sanitizeAmt(s: string, maxDec: number): string {
  s = s.replace(/[^0-9.]/g, '');
  const firstDot = s.indexOf('.');
  if (firstDot >= 0) s = s.slice(0, firstDot + 1) + s.slice(firstDot + 1).replace(/\./g, '');
  const [ip, fp] = s.split('.');
  let out = (ip || '').replace(/^0+(?=\d)/, '');
  if (fp !== undefined) out += '.' + fp.slice(0, maxDec);
  return out.slice(0, 14);
}
function trimNum(n: number, dec = 6): string { return parseFloat(n.toFixed(dec)).toString(); }
function showSend(chainId: string, err = '', done = '') {
  const c = CHAINS.find(x => x.id === chainId)!; const b = balances.get(c.id);
  const sendable = SENDABLE_KINDS.has(c.kind);
  const d = draftFor(chainId);
  const p = priceOf(c);
  // Audit M-17: fiat mode is denominated in the DISPLAY currency, not
  // silently in USD — with EUR selected, "10" means €10. fxr converts
  // display-fiat -> USD (rates are units per 1 USD); the keypad shows
  // the display currency's own symbol and fraction digits.
  const fiatCode = effectiveCode(); const fxr = fxRateFor(fiatCode) ?? 1; const fiatSym = CURRENCIES.find(x => x.code === fiatCode)?.symbol || '$'; const fiatDec = currencyDecimals(fiatCode);
  const maxDec = () => d.mode === 'usd' ? fiatDec : Math.min(8, c.decimals);
  setView(`<main><button class="backBtn" id="bk" aria-label="Back"><i class="ri-arrow-left-s-line"></i></button>
  <div class="card" style="position:relative">
    <h1 class="heroH">Send</h1><p class="heroSub" style="margin-top:2px">Step 1 of 2</p>
    ${err ? `<div style="height:12px"></div><div class="err">${esc(err)}</div>` : ''}${done ? `<div style="height:12px"></div><div class="ok">${done}</div>` : ''}
    ${!sendable ? `<div style="height:16px"></div><div class="warn">${esc(c.name)} sending is coming soon in Syn Wallet. You can receive and track ${esc(c.symbol)} now — no fake send is offered.</div>` : `
    <div style="height:16px"></div>
    <button class="assetPick" id="assetPick">${coinIcon(c)}<span><div class="apName">${esc(c.name)}</div><div class="apBal">Balance: ${b == null ? (balStateOf(c.id) === 'pending' ? 'Loading…' : 'Unavailable') : trimNum(b) + ' ' + esc(c.symbol)}</div></span><i class="ri-arrow-down-s-line"></i></button>
    <div style="height:14px"></div>
    <div class="toPill"><div class="fld"><label>To</label><input id="toAddr" placeholder="${(c.kind === 'solana' || c.kind === 'solana-tw' || c.kind === 'solana-phantom') ? 'Solana address or name.sol' : c.kind === 'tron' ? 'TRON address (starts with T)' : '0x address or name.eth'}" value="${esc(d.to)}" autocomplete="off" autocapitalize="none" spellcheck="false"></div><button class="pasteBtn" id="pasteBtn">Paste</button></div>
    <div id="nameBox"></div>
    <div class="amtWrap" id="amtWrap"><span class="amtDisplay" id="amtDisplay"></span><span class="amtCursor"></span></div>
    <input id="amtHidden" inputmode="decimal" autocomplete="off" style="position:absolute;opacity:0;height:1px;width:1px;pointer-events:none" aria-label="Amount">
    <div class="convRow"><button class="convPill" id="convPill"></button></div>
    <div class="pctChips" id="pctChips">${[25, 50, 75, 100].map(pc => `<button data-pct="${pc}" ${b == null || b <= 0 ? 'disabled' : ''}>${pc === 100 ? 'MAX' : pc + '%'}</button>`).join('')}</div>
    <div class="keypad" id="keypad">${['1', '2', '3', '4', '5', '6', '7', '8', '9', '.', '0', 'del'].map(k => `<button data-k="${k}" class="${k === 'del' ? 'kFn' : ''}" aria-label="${k === 'del' ? 'Delete' : k}">${k === 'del' ? '<i class="ri-delete-back-2-line"></i>' : k}</button>`).join('')}</div>
    <div class="feeLine"><i class="ri-information-line"></i><span>Network fee is paid in ${esc(c.symbol)} — the exact fee and speed are set on the review step.</span></div>
    <div style="height:14px"></div>
    <button class="ctaWide" id="reviewBtn" disabled>Review</button><div style="height:104px"></div>`}
    </div></main>`);
  ($('#bk') as HTMLElement).onclick = () => goBack({ route: 'asset', chainId: c.id });
  if (!sendable) return;
  const cryptoAmt = (): number => { const v = parseFloat(d.amt); if (!(v > 0)) return 0; if (d.mode === 'crypto') return v; return p != null ? (v / fxr) / p : NaN; };
  const updateUI = () => {
    const disp = $('#amtDisplay'); if (!disp) return;
    disp.innerHTML = d.amt ? esc((d.mode === 'usd' ? fiatSym : '') + d.amt + (d.mode === 'crypto' ? ' ' + c.symbol : '')) : `<span class="ph">${d.mode === 'usd' ? fiatSym + '0' : '0 ' + c.symbol}</span>`;
    const conv = $('#convPill') as HTMLButtonElement | null;
    if (conv) {
      const ca = cryptoAmt();
      if (p == null) { conv.innerHTML = '<i class="ri-swap-line"></i> Price unavailable'; conv.disabled = true; }
      else { conv.disabled = false; conv.innerHTML = d.mode === 'usd' ? `<i class="ri-swap-line"></i> ≈ ${ca > 0 ? trimNum(ca) : '0.0000'} ${esc(c.symbol)}` : `<i class="ri-swap-line"></i> ≈ ${fmtUsd((parseFloat(d.amt) || 0) * p)}`; }
    }
    const rb = $('#reviewBtn') as HTMLButtonElement | null;
    if (rb) { const ca = cryptoAmt(); rb.disabled = !(d.to.trim() && ca > 0 && (b == null || ca <= b)); }
    const hid = $('#amtHidden') as unknown as HTMLInputElement | null;
    if (hid && document.activeElement !== hid) hid.value = d.amt;
  };
  const toInput = $('#toAddr') as unknown as HTMLInputElement;
  // Live name feedback: names resolve as you type (debounced) and raw
  // addresses get a best-effort reverse-name lookup. Review re-resolves
  // authoritatively — this box is display only.
  let nameTimer: any = null; let nameSeq = 0;
  const paintNameBox = async () => {
    const box = $('#nameBox'); if (!box) return;
    const v = d.to.trim(); const seq = ++nameSeq;
    if (!v) { box.innerHTML = ''; return; }
    if (looksLikeNameAttempt(v) && !isRawAddressFor(c, v)) {
      box.innerHTML = `<p class="small muted" style="margin-top:10px">${waveLoadHTML()} Resolving name…</p>`;
      const r = await resolveNameFor(c, v);
      if (seq !== nameSeq || !box.isConnected) return;
      box.innerHTML = 'error' in r
        ? `<div class="err" style="margin-top:10px">${esc(r.error)}</div>`
        : `<div class="ok" style="margin-top:10px">${esc(v.toLowerCase())} → ${esc(r.address)}</div>`;
      return;
    }
    if (isRawAddressFor(c, v)) {
      const rn = await reverseNameFor(c, v);
      if (seq !== nameSeq || !box.isConnected) return;
      box.innerHTML = rn ? `<p class="small muted" style="margin-top:10px">Primary name for this address: <b style="color:var(--silver)">${esc(rn)}</b></p>` : '';
      return;
    }
    box.innerHTML = '';
  };
  toInput.addEventListener('input', () => { d.to = toInput.value; updateUI(); clearTimeout(nameTimer); nameTimer = setTimeout(paintNameBox, 550); });
  if (d.to.trim()) void paintNameBox();
  ($('#pasteBtn') as HTMLElement).onclick = async () => { try { const t = await navigator.clipboard.readText(); if (t) { d.to = t.trim(); toInput.value = d.to; updateUI(); void paintNameBox(); } } catch { /* clipboard unavailable */ } };
  ($('#amtWrap') as HTMLElement).onclick = () => { ($('#amtHidden') as unknown as HTMLInputElement).focus(); };
  ($('#amtHidden') as unknown as HTMLInputElement).addEventListener('input', (e) => { d.amt = sanitizeAmt((e.target as HTMLInputElement).value, maxDec()); updateUI(); });
  ($('#convPill') as HTMLElement).onclick = () => {
    if (p == null) return;
    const v = parseFloat(d.amt);
    if (v > 0) d.amt = d.mode === 'usd' ? trimNum((v / fxr) / p, Math.min(8, c.decimals)) : (v * p * fxr).toFixed(fiatDec);
    d.mode = d.mode === 'usd' ? 'crypto' : 'usd';
    d.amt = sanitizeAmt(d.amt, maxDec()); updateUI();
  };
  app().querySelectorAll('#pctChips [data-pct]').forEach(btn => (btn as HTMLElement).onclick = () => {
    if (b == null || b <= 0) return;
    const pc = Number((btn as HTMLElement).dataset.pct);
    const ca = b * pc / 100;
    d.amt = d.mode === 'usd' ? (p != null ? (ca * p * fxr).toFixed(fiatDec) : '') : trimNum(ca, Math.min(8, c.decimals));
    app().querySelectorAll('#pctChips [data-pct]').forEach(x => x.classList.toggle('on', x === btn));
    updateUI();
    // Audit fix: MAX (100%) used to fill the FULL balance, leaving
    // nothing for the network fee — the send then predictably failed
    // at broadcast after a review screen showing a negative
    // balance-after. Reserve the estimated fee: once it lands, if the
    // amount still stands at the full balance, trim it to b − fee.
    if (pc === 100) {
      void estimateFee(c).then(fee => {
        if (fee == null || !(fee > 0) || b == null) return;
        if (!$('#pctChips')) return; // screen changed
        if (!(cryptoAmt() >= b * 0.999)) return; // user edited since
        const maxCa = b - fee;
        if (!(maxCa > 0)) return;
        d.amt = d.mode === 'usd' ? (p != null ? (maxCa * p * fxr).toFixed(fiatDec) : '') : trimNum(maxCa, Math.min(8, c.decimals));
        updateUI();
      });
    }
  });
  ($('#assetPick') as HTMLElement).onclick = () => {
    openSendPicker(c.id + ':native', (a) => {
      if (a.contract === 'native') { if (a.chainId !== c.id) showSend(a.chainId); }
      else if (a.tokenId) showTokenSend(a.tokenId);
    }, c.id);
  };
  app().querySelectorAll('#keypad [data-k]').forEach(btn => (btn as HTMLElement).onclick = () => {
    const k = (btn as HTMLElement).dataset.k!;
    app().querySelectorAll('#pctChips [data-pct]').forEach(x => x.classList.remove('on'));
    if (k === 'del') d.amt = d.amt.slice(0, -1);
    else if (k === '.') { if (!d.amt.includes('.')) d.amt = (d.amt || '0') + '.'; }
    else d.amt = sanitizeAmt(d.amt + k, maxDec());
    d.amt = sanitizeAmt(d.amt, maxDec()); updateUI();
  });
  updateUI();
  ($('#reviewBtn') as HTMLElement).onclick = async () => {
    const rawTo = d.to.trim(); const amt = cryptoAmt();
    if (!rawTo) return showSend(chainId, 'Enter a destination address.');
    if (!(amt > 0)) return showSend(chainId, 'Enter an amount greater than zero.');
    if (b != null && amt > b) return showSend(chainId, 'Amount exceeds your available balance.');
    // Names resolve authoritatively here: an unresolved or unsupported
    // name hard-blocks the send — funds never go to a guessed address.
    let to = rawTo; let nameLabel = '';
    if (!isRawAddressFor(c, rawTo) && looksLikeNameAttempt(rawTo)) {
      const rb = $('#reviewBtn') as HTMLButtonElement; btnBusy(rb, 'Resolving name…');
      const r = await resolveNameFor(c, rawTo);
      if ('error' in r) return showSend(chainId, r.error);
      to = r.address; nameLabel = rawTo.trim().toLowerCase();
    }
    if (c.kind === 'solana' || c.kind === 'solana-tw' || c.kind === 'solana-phantom') { try { new PublicKey(to); } catch { return showSend(chainId, 'That does not look like a valid Solana address.'); } }
    if (c.kind === 'tron' && !isValidTronAddress(to)) return showSend(chainId, 'That does not look like a valid TRON address.');
    if (c.kind === 'bitcoin' && !isValidUtxoAddress(c.id, to)) return showSend(chainId, `That does not look like a valid ${c.name} address. Check the network — a ${c.id === 'litecoin' ? 'Bitcoin' : 'Litecoin'} address cannot receive ${c.symbol}.`);
    if (c.evmId) {
      if (!ethers.isAddress(to)) return showSend(chainId, 'That does not look like a valid EVM address.');
      const mixed = to !== to.toLowerCase() && to !== to.toUpperCase();
      if (mixed && !nameLabel) { try { ethers.getAddress(to); } catch { return showSend(chainId, 'Address checksum (EIP-55) failed — this address may have been altered. Send blocked.'); } }
    }
    const poisonWarn = poisonWarning(to);
    // Audit H-4: the amount that reaches the signer is an exact
    // decimal STRING — the entered crypto string verbatim, or the
    // fiat conversion rendered once to a bounded decimal string.
    // No float ever crosses into doSend.
    const amtStr = d.mode === 'crypto' ? d.amt : trimNum(amt, Math.min(8, c.decimals));
    feeState = freshFeeState();
    go({ route: 'confirm', chainId: c.id, confirm: { c, to, amtStr, poisonWarn, nameLabel } }, $('#reviewBtn') as HTMLElement);
  };
}
// ---------- EVM gas customization ----------
// The fee choice lives in module state so confirm screens can re-render
// (e.g. after an error) without losing it; it is reset every time a send
// review begins. The chosen values are applied to the signed transaction
// itself — EIP-1559 fields where the chain supports them, a legacy
// gasPrice where it does not.
interface FeeState { mode: 'auto' | FeeLevel | 'custom'; maxFee: string; prio: string }
function freshFeeState(): FeeState { return { mode: 'auto', maxFee: '', prio: '' }; }
let feeState: FeeState = freshFeeState();
interface FeeInfo { supports1559: boolean; baseFee: bigint | null; priority: bigint | null; gasPrice: bigint | null; presets: Record<FeeLevel, FeePreset> | null; legacy: Record<FeeLevel, bigint> | null }
let feeInfo: FeeInfo | null = null;
async function fetchFeeInfo(c: Chain): Promise<FeeInfo | null> {
  try {
    const provider = new ethers.JsonRpcProvider(evmProviderUrl(c), c.evmId);
    const fd = await provider.getFeeData();
    if (fd.maxFeePerGas != null && fd.maxPriorityFeePerGas != null) {
      let baseFee: bigint | null = null;
      try { const hist: any = await provider.send('eth_feeHistory', ['0x5', 'latest', []]); const arr = hist?.baseFeePerGas; if (Array.isArray(arr) && arr.length) baseFee = BigInt(arr[arr.length - 1]); } catch { /* fall through */ }
      if (baseFee === null) { const d = fd.maxFeePerGas - fd.maxPriorityFeePerGas; baseFee = d > 0n ? d : 0n; }
      return { supports1559: true, baseFee, priority: fd.maxPriorityFeePerGas, gasPrice: fd.gasPrice, presets: computePresets(baseFee, fd.maxPriorityFeePerGas), legacy: null };
    }
    if (fd.gasPrice != null) return { supports1559: false, baseFee: null, priority: null, gasPrice: fd.gasPrice, presets: null, legacy: computeLegacyPresets(fd.gasPrice) };
    return null;
  } catch { return null; }
}
// Effective per-gas price + the exact overrides to sign with.
function chosenFees(state: FeeState, info: FeeInfo | null): { effPrice: bigint; overrides: Record<string, bigint> } | null {
  if (!info) return null;
  if (info.supports1559 && info.presets) {
    if (state.mode === 'auto') { if (info.baseFee === null || info.priority === null) return null; return { effPrice: info.baseFee + info.priority, overrides: {} }; }
    if (state.mode === 'custom') { const mf = parseGwei(state.maxFee); const pr = parseGwei(state.prio); if (mf === null || pr === null) return null; const withPrio = (info.baseFee ?? 0n) + pr; return { effPrice: mf < withPrio ? mf : withPrio, overrides: { maxFeePerGas: mf, maxPriorityFeePerGas: pr } }; }
    const p = info.presets[state.mode]; return { effPrice: effectiveGasPriceWei(p, info.baseFee), overrides: { maxFeePerGas: p.maxFeePerGas, maxPriorityFeePerGas: p.maxPriorityFeePerGas } };
  }
  if (!info.supports1559 && info.legacy) {
    if (state.mode === 'auto') return info.gasPrice !== null ? { effPrice: info.gasPrice, overrides: {} } : null;
    if (state.mode === 'custom') { const gp = parseGwei(state.maxFee); return gp !== null ? { effPrice: gp, overrides: { gasPrice: gp } } : null; }
    return { effPrice: info.legacy[state.mode], overrides: { gasPrice: info.legacy[state.mode] } };
  }
  return null;
}
function feeCostText(c: Chain, gasLimit: bigint): string | null {
  const ch = chosenFees(feeState, feeInfo);
  if (!ch) return null;
  return '~' + trimNum(Number(ethers.formatEther(ch.effPrice * gasLimit)), 8) + ' ' + c.symbol;
}
function customFeeProblem(): string | null {
  if (feeState.mode !== 'custom') return null;
  if (feeInfo && !feeInfo.supports1559) { const gp = parseGwei(feeState.maxFee); return gp === null || gp <= 0n ? 'Enter a gas price in Gwei (e.g. 20).' : null; }
  const v = validateCustomFees(feeState.maxFee, feeState.prio, feeInfo?.baseFee ?? null);
  return v.error || null;
}
function gasBoxHTML(c: Chain): string {
  if (c.kind !== 'evm') return '';
  return `<div class="gasBox"><div class="gasHead"><span class="sl">NETWORK FEE SPEED</span><span class="sv" id="gasModeLabel">Automatic</span></div>
  <div class="seg" id="gasSeg"><button data-g="auto" class="on" type="button">Auto</button><button data-g="slow" type="button">Slow</button><button data-g="market" type="button">Market</button><button data-g="fast" type="button">Fast</button><button data-g="custom" type="button">Custom</button></div>
  <div id="gasDetail" class="small muted" style="margin-top:9px;line-height:1.55">${waveLoadHTML('sm')} Fetching live fee data…</div>
  <div id="gasCustom" class="hidden" style="margin-top:10px">
    <div class="field"><label id="gMaxLabel">Max fee (Gwei)</label><div class="box"><input id="gMaxFee" inputmode="decimal" placeholder="e.g. 40" autocomplete="off" spellcheck="false"></div></div>
    <div class="field" id="gPrioField"><label>Priority fee (Gwei)</label><div class="box"><input id="gPrio" inputmode="decimal" placeholder="e.g. 2" autocomplete="off" spellcheck="false"></div></div>
    <div id="gasWarn"></div>
  </div></div>`;
}
function bindGasBox(c: Chain, getGasLimit: () => bigint, onFeeChange: () => void) {
  feeInfo = null;
  const seg = $('#gasSeg'); if (!seg) return;
  const label = () => { const l = $('#gasModeLabel'); if (l) l.textContent = feeState.mode === 'auto' ? 'Automatic' : feeState.mode === 'custom' ? 'Custom' : feeState.mode[0].toUpperCase() + feeState.mode.slice(1); };
  const paintDetail = () => {
    label();
    const d = $('#gasDetail'); const gw = $('#gasWarn');
    const legacyMode = feeInfo && !feeInfo.supports1559;
    const pf = $('#gPrioField'); if (pf) pf.style.display = legacyMode ? 'none' : '';
    const ml = $('#gMaxLabel'); if (ml) ml.textContent = legacyMode ? 'Gas price (Gwei)' : 'Max fee (Gwei)';
    if (gw) {
      if (feeState.mode === 'custom' && feeInfo) { const v = validateCustomFees(feeState.maxFee, legacyMode ? feeState.maxFee : feeState.prio, legacyMode ? null : feeInfo.baseFee); gw.innerHTML = v.error ? `<div class="err" style="margin:0">${esc(v.error)}</div>` : v.warning ? `<div class="warn" style="margin:0">${esc(v.warning)}</div>` : ''; }
      else gw.innerHTML = '';
    }
    if (d) {
      if (!feeInfo) { d.innerHTML = `${waveLoadHTML('sm')} Fetching live fee data…`; }
      else if (feeInfo.supports1559 && feeInfo.presets) {
        if (feeState.mode === 'auto') d.innerHTML = `Automatic — the network default. Current base fee ${feeInfo.baseFee !== null ? formatGwei(feeInfo.baseFee) : '—'} Gwei, priority ~${feeInfo.priority !== null ? formatGwei(feeInfo.priority) : '—'} Gwei. Estimated cost ${feeCostText(c, getGasLimit()) || '—'}.`;
        else if (feeState.mode === 'custom') d.innerHTML = `Your values are signed into the transaction exactly as entered. Estimated cost ${feeCostText(c, getGasLimit()) || '—'}.`;
        else { const p = feeInfo.presets[feeState.mode]; d.innerHTML = `Max fee ${formatGwei(p.maxFeePerGas)} Gwei · priority ${formatGwei(p.maxPriorityFeePerGas)} Gwei. Estimated cost ${feeCostText(c, getGasLimit()) || '—'}.`; }
      } else if (feeInfo.legacy) {
        if (feeState.mode === 'auto') d.innerHTML = `This network uses legacy gas pricing. Current gas price ${feeInfo.gasPrice !== null ? formatGwei(feeInfo.gasPrice) : '—'} Gwei. Estimated cost ${feeCostText(c, getGasLimit()) || '—'}.`;
        else if (feeState.mode === 'custom') d.innerHTML = `Legacy network — enter a single gas price. Estimated cost ${feeCostText(c, getGasLimit()) || '—'}.`;
        else d.innerHTML = `Gas price ${formatGwei(feeInfo.legacy[feeState.mode])} Gwei. Estimated cost ${feeCostText(c, getGasLimit()) || '—'}.`;
      } else d.textContent = feeState.mode === 'auto' ? 'Live fee data unavailable — the wallet default will be used at signing.' : 'Live fee data unavailable — a non-Auto fee choice cannot be applied, so sending is blocked until fee data loads.';
    }
    onFeeChange();
  };
  seg.querySelectorAll('[data-g]').forEach(b => (b as HTMLElement).onclick = () => {
    feeState.mode = (b as HTMLElement).dataset.g as FeeState['mode'];
    seg.querySelectorAll('[data-g]').forEach(x => x.classList.toggle('on', x === b));
    const gc = $('#gasCustom'); if (gc) gc.classList.toggle('hidden', feeState.mode !== 'custom');
    paintDetail();
  });
  const mf = $('#gMaxFee') as unknown as HTMLInputElement | null; const pf2 = $('#gPrio') as unknown as HTMLInputElement | null;
  if (mf) { mf.value = feeState.maxFee; mf.addEventListener('input', () => { feeState.maxFee = mf.value; paintDetail(); }); }
  if (pf2) { pf2.value = feeState.prio; pf2.addEventListener('input', () => { feeState.prio = pf2.value; paintDetail(); }); }
  seg.querySelectorAll('[data-g]').forEach(x => x.classList.toggle('on', (x as HTMLElement).dataset.g === feeState.mode));
  if (feeState.mode === 'custom') { const gc = $('#gasCustom'); if (gc) gc.classList.remove('hidden'); }
  paintDetail();
  fetchFeeInfo(c).then(info => { feeInfo = info; paintDetail(); });
}

// UTXO data helpers (esplora via our server): the wallet's own UTXO
// set + the current fee rate for a chain of the bitcoin family.
async function fetchUtxos(c: Chain): Promise<Utxo[]> {
  const addr = addressFor(c); if (!addr) return [];
  const r = await fetch(`/api/utxo/${c.id}/utxo/${addr}`);
  if (!r.ok) throw new Error(`${c.name} data unavailable — try again in a moment.`);
  const j = await r.json();
  return (Array.isArray(j) ? j : []).map((u: any) => ({ txid: String(u.txid), vout: Number(u.vout), value: Number(u.value), confirmed: u.status?.confirmed !== false }));
}
async function fetchUtxoFeeRate(c: Chain): Promise<number> {
  const r = await fetch(`/api/utxo/${c.id}/fees`);
  if (!r.ok) throw new Error('Fee data unavailable — try again in a moment.');
  const j = await r.json(); const v = Number(j?.satVb);
  // Deep audit 2026-11-22: sanity ceiling — a broken or hostile fee
  // source must not be able to quote an absurd rate into the review
  // screen (real-world BTC/LTC rates stay far below this).
  if (!(v > 0) || v > 5000) throw new Error('Fee data unavailable — try again in a moment.');
  return v;
}
async function estimateFee(c: Chain, toAddr = '', amtStr = ''): Promise<number | null> {
  try {
    if (c.kind === 'solana' || c.kind === 'solana-tw' || c.kind === 'solana-phantom') return 0.000005;
    if (c.kind === 'tron') return 0; // covered by free daily bandwidth in the normal case
    if (c.kind === 'bitcoin') {
      const [rate, utxos] = await Promise.all([fetchUtxoFeeRate(c), fetchUtxos(c).catch(() => [] as Utxo[])]);
      // Deep audit 2026-11-22: when the amount + recipient are known
      // (the review screen), run the REAL coin selection the signer
      // will run — the old rough estimate capped inputs at 3 and
      // could understate the fee ~3x on fragmented wallets. Fall back
      // to the rough estimate when selection can't fund the send.
      const sats = amtStr ? parseRawAmount(amtStr, 8) : null;
      if (sats != null && sats > 0n && toAddr) {
        const sel = selectCoins(c.id, utxos, toAddr, addressFor(c), Number(sats), rate);
        if (sel) return sel.feeSats / 1e8;
      }
      return estimateUtxoFeeSats(c.id, utxos.length, toAddr, rate) / 1e8;
    }
    const provider = new ethers.JsonRpcProvider(evmProviderUrl(c), c.evmId);
    const fd = await provider.getFeeData(); const gp = fd.gasPrice ?? 0n; return Number(ethers.formatEther(gp * 21000n));
  } catch { return null; }
}
function showSendConfirm(c: Chain, to: string, amtStr: string, err = '', poisonWarn = '', nameLabel = '') {
  const amt = parseFloat(amtStr) || 0; // display + estimates only — the signer receives amtStr verbatim (audit H-4)
  const p = priceOf(c);
  setView(`<main><button class="backBtn" id="bk" aria-label="Back"><i class="ri-arrow-left-s-line"></i></button>
  <div class="card" style="position:relative"><h1 class="heroH">Review <span>send</span></h1><p class="heroSub" style="margin-top:2px">Step 2 of 2</p><div style="height:8px"></div>${err ? `<div class="err">${esc(err)}</div>` : ''}
    <div class="sumAmt">${trimNum(amt, 8)} ${esc(c.symbol)}</div>
    ${p != null ? `<p class="small muted" style="text-align:center">≈ ${fmtUsd(amt * p)}</p>` : ''}
    <div style="height:8px"></div>
    <div class="sumRow"><span class="sl">Network</span><span class="sv" style="display:inline-flex;align-items:center;gap:8px">${coinIcon(c)} ${esc(c.name)}</span></div>
    ${nameLabel ? `<div class="sumRow"><span class="sl">Name</span><span class="sv">${esc(nameLabel)}</span></div>` : ''}
    <div class="sumRow"><span class="sl">To</span><span class="sv"><span class="monoChip" style="max-width:210px" data-full="${esc(to)}">${esc(to.slice(0, 10))}…${esc(to.slice(-8))}</span></span></div>
    <div class="sumRow"><span class="sl">Estimated fee</span><span class="sv" id="feeCell">${waveLoadHTML('sm')}</span></div>
    <div class="sumRow"><span class="sl">Balance after</span><span class="sv" id="afterCell">…</span></div>
    ${gasBoxHTML(c)}
    <div id="riskBox" style="margin-top:12px"></div>
    ${poisonWarn ? `<div class="warn" style="margin-top:12px">${esc(poisonWarn)}</div>` : ''}
    ${c.kind === 'tron' ? `<div class="warn" style="margin-top:12px">TRON transfers use your free daily bandwidth. Sending to a brand-new TRON address that has never been used burns an extra 1 TRX activation fee, charged by the network.</div>` : ''}
    <p class="securityNote" style="margin:12px 0">Signing happens locally on this device — your key never leaves it. Check every character of the recipient: transactions cannot be reversed.</p>
    <button class="ctaWide" id="sendBtn">Send ${esc(c.symbol)}</button><div style="height:10px"></div><button class="btnGhost" id="cancelBtn" style="border-radius:999px">Cancel</button></div></main>`);
  const GAS_LIMIT = 21000n;
  const updateFeeUI = () => {
    const fc = $('#feeCell'); const ac = $('#afterCell'); const b = balances.get(c.id);
    if (c.kind === 'evm') {
      const txt = feeCostText(c, GAS_LIMIT);
      if (fc) { if (txt) fc.textContent = txt; else if (feeState.mode === 'custom') fc.textContent = 'Enter valid custom fees'; else fc.innerHTML = waveLoadHTML('sm'); }
      if (ac) { const ch = chosenFees(feeState, feeInfo); ac.textContent = b == null ? (balStateOf(c.id) === 'pending' ? 'Loading…' : 'Unavailable') : ch ? `${trimNum(b - amt - Number(ethers.formatEther(ch.effPrice * GAS_LIMIT)), 6)} ${c.symbol}` : `${(b - amt).toFixed(6)} ${c.symbol} (before fee)`; }
      return;
    }
    estimateFee(c, to, amtStr).then(fee => { if (fc && fc.isConnected) fc.textContent = fee == null ? 'Unavailable — shown at signing' : `~${fee} ${c.symbol}`; if (ac && ac.isConnected) ac.textContent = b == null ? (balStateOf(c.id) === 'pending' ? 'Loading…' : 'Unavailable') : fee == null ? `${(b - amt).toFixed(6)} ${c.symbol} (before fee)` : `${(b - amt - fee).toFixed(6)} ${c.symbol}`; });
  };
  if (c.kind === 'evm') bindGasBox(c, () => GAS_LIMIT, updateFeeUI);
  updateFeeUI();
  void paintAddressRisk($('#riskBox'), to, c);
  ($('#bk') as HTMLElement).onclick = () => goBack({ route: 'send', chainId: c.id }); ($('#cancelBtn') as HTMLElement).onclick = () => goBack({ route: 'send', chainId: c.id });
  ($('#sendBtn') as HTMLButtonElement).onclick = async () => {
    const problem = customFeeProblem();
    if (problem) { showSendConfirm(c, to, amtStr, problem, poisonWarn, nameLabel); return; }
    // Audit M-8: a deliberate fee choice (Slow/Fast/Custom) must never
    // be silently dropped — when live fee data is unavailable the send
    // BLOCKS instead of falling back to provider defaults.
    if (c.kind === 'evm' && feeState.mode !== 'auto' && !chosenFees(feeState, feeInfo)) { showSendConfirm(c, to, amtStr, 'Live fee data is unavailable, so your chosen fee speed can\'t be applied. Check your connection, or switch the fee back to Auto.', poisonWarn, nameLabel); return; }
    // Audit fix: never let amount + fee exceed the balance reach the
    // signer — it could only fail at broadcast. (MAX on step 1 now
    // reserves the fee; this guards hand-typed full-balance amounts.)
    const bNow = balances.get(c.id);
    if (bNow != null) {
      let feeNow: number | null = null;
      if (c.kind === 'evm') { const ch = chosenFees(feeState, feeInfo); feeNow = ch ? Number(ethers.formatEther(ch.effPrice * GAS_LIMIT)) : null; }
      else feeNow = await estimateFee(c, to, amtStr);
      if (feeNow != null && amt + feeNow > bNow) { showSendConfirm(c, to, amtStr, `Amount plus the network fee (~${trimNum(feeNow, 8)} ${c.symbol}) exceeds your balance. Go back and reduce the amount — the MAX shortcut leaves room for the fee.`, poisonWarn, nameLabel); return; }
    }
    const btn = $('#sendBtn') as HTMLButtonElement; btnBusy(btn, 'Signing & broadcasting…');
    try { const overrides = c.kind === 'evm' ? (chosenFees(feeState, feeInfo)?.overrides || {}) : {}; const hash = await doSend(c, to, amtStr, overrides); recordLocalTx(c.id, hash, `Sent ${c.symbol}`, { dir: 'out', sym: c.symbol, amt: amtStr, cp: to }); recordCounterparty(to); balances.delete(c.id); sendDrafts.delete(c.id);
      celebrate(btn, () => {
        setView(receiptHTML({ title: 'Sent', amount: `${trimNum(amt, 8)} ${c.symbol}`, fiat: priceOf(c) ? fmtUsd(amt * priceOf(c)!) : '', toLine: `To ${shortAddr(to)}`, sub: `on ${c.name}`, hash, doneLabel: 'Done' }));
        bindReceipt(hash, c.explorerTx, (el) => goTab('wallet', el));
      });
    } catch (e: any) {
      // Audit M-11 (EVM side): an error carrying a tx hash means the
      // transaction may already be broadcast — record it locally and
      // say so, instead of presenting a clean "failed, retry" state.
      const eh = (e as any)?.hash || (e as any)?.transactionHash;
      if (typeof eh === 'string' && /^0x[0-9a-fA-F]{64}$/.test(eh)) { recordLocalTx(c.id, eh, `Sent ${c.symbol}`, { dir: 'out', sym: c.symbol, amt: amtStr, cp: to }); recordCounterparty(to); showSendConfirm(c, to, amtStr, 'The network may have accepted this transaction already (check Activity before trying again).', poisonWarn, nameLabel); return; }
      showSendConfirm(c, to, amtStr, 'Send failed: ' + (e?.shortMessage || e?.message || String(e)), poisonWarn, nameLabel);
    }
  };
}
// Audit M-11 (2026-11-19): Solana broadcast with an ambiguity guard.
// The signature is known BEFORE broadcast (it is computed at signing),
// so when the RPC errors or times out we can ask the chain whether the
// transaction landed instead of guessing — a retry after a dropped
// response must never double-send. Definite failures (simulation /
// preflight rejection) rethrow untouched; anything ambiguous is
// labelled "may have been submitted — check Activity".
async function pollSigStatus(conn: Connection, sig: string, ms: number): Promise<'landed' | 'failed' | 'unknown'> {
  const t0 = Date.now();
  for (;;) {
    try { const v = (await conn.getSignatureStatus(sig))?.value; if (v) { if (v.err) return 'failed'; if (v.confirmationStatus) return 'landed'; } } catch { /* keep polling */ }
    if (Date.now() - t0 >= ms) return 'unknown';
    await new Promise(r => setTimeout(r, 1500));
  }
}
async function sendSolanaSigned(conn: Connection, raw: Uint8Array, sig: string): Promise<string> {
  try {
    await conn.sendRawTransaction(raw, { skipPreflight: false });
  } catch (e: any) {
    const msg = e?.message || String(e);
    if ((e as any)?.transactionError || /simulation failed/i.test(msg)) throw e;
    const st = await pollSigStatus(conn, sig, 8000);
    if (st === 'landed') return sig;
    if (st === 'failed') throw new Error('Transaction failed on-chain.');
    throw new Error(msg + ' — the transaction may have been submitted. Check Activity before trying again.');
  }
  const st = await pollSigStatus(conn, sig, 45000);
  if (st === 'failed') throw new Error('Transaction failed on-chain.');
  if (st === 'landed') return sig;
  throw new Error('Transaction sent but not confirmed yet — check Activity before trying again.');
}
async function doSend(c: Chain, to: string, amtStr: string, feeOverrides: Record<string, bigint> = {}): Promise<string> {
  const amt = parseFloat(amtStr) || 0; // float ONLY where a third-party API demands one; signing paths parse amtStr exactly
  if (!SENDABLE_KINDS.has(c.kind)) throw new Error(`${c.name} sending is coming soon.`);
  if (c.kind === 'bitcoin') {
    // UTXO family (Bitcoin + Litecoin): fetch the wallet's UTXOs and
    // the live fee rate through our server, select coins, sign
    // locally with the chain's BIP84 key, broadcast the raw hex.
    if (!derived2) throw new Error(`${c.name} sending needs a seed wallet.`);
    const params = utxoParams(c.id); if (!params) throw new Error(`${c.name} sending is not supported.`);
    const sats = parseRawAmount(amtStr, 8); if (sats == null || sats <= 0n) throw new Error('Invalid amount.');
    const from = addressFor(c);
    const privHex = c.id === 'litecoin' ? derived2.ltcPrivateKeyHex : derived2.btcPrivateKeyHex;
    const priv = base16.decode(privHex);
    const pub = secp256k1.getPublicKey(priv, true);
    const [utxos, rate] = await Promise.all([fetchUtxos(c), fetchUtxoFeeRate(c)]);
    const built = buildUtxoSend({ chainId: c.id, utxos, privKey: priv, pubKey: pub, fromAddress: from, toAddress: to, amountSats: Number(sats), feeRateSatVb: rate });
    const br = await fetch(`/api/utxo/${c.id}/tx`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ hex: built.hex }) });
    const bj = await br.json().catch(() => null);
    if (!br.ok || !bj?.txid) throw new Error(bj?.error || 'Broadcast rejected by the network.');
    if (String(bj.txid).toLowerCase() !== built.txid.toLowerCase()) throw new Error('Broadcast returned a different transaction id — check Activity before trying again.');
    return String(bj.txid);
  }
  if (c.kind === 'tron') {
    if (!derived2) throw new Error('TRON sending needs a seed wallet.');
    const sun = Number(parseRawAmount(amtStr, 6) ?? 0n);
    const res = await fetch('https://api.trongrid.io/wallet/createtransaction', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ owner_address: tronToHex(derived2.tronAddress), to_address: tronToHex(to), amount: sun, visible: false }) });
    const tx = await res.json();
    if (!tx || !tx.txID || !tx.raw_data_hex) throw new Error('TronGrid could not build this transaction — the account may not be activated on TRON yet.');
    // Deep audit 2026-11-22 (P1): TRON was the one sendable family
    // still blind-signing a remotely built transaction — TronGrid
    // builds it and the wallet signed its hash unchecked, so a
    // compromised/MITM'd response could substitute any recipient or
    // amount under the reviewed confirm screen. Verify before
    // signing, exactly like the aggregator checks (H-1): (1) the
    // txID must be the sha256 of the raw data we are about to sign;
    // (2) the single TransferContract inside must name THIS wallet
    // as owner and the reviewed recipient + amount as its payload.
    if (!verifyTronTransferTx(tx, tronToHex(derived2.tronAddress), tronToHex(to), sun)) throw new Error('The transaction TronGrid built does not match the reviewed recipient and amount — refusing to sign.');
    const sig = secp256k1.sign(hexToBytes(tx.txID), hexToBytes(derived2.tronPrivateKeyHex));
    tx.signature = [sig.r.toString(16).padStart(64, '0') + sig.s.toString(16).padStart(64, '0') + (sig.recovery + 27).toString(16).padStart(2, '0')];
    const bc = await fetch('https://api.trongrid.io/wallet/broadcasttransaction', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(tx) });
    const bj = await bc.json();
    if (bj?.result !== true) throw new Error('Broadcast rejected by the network.');
    return tx.txID as string;
  }
  if (c.kind === 'solana' || c.kind === 'solana-tw' || c.kind === 'solana-phantom') {
    const kp: Keypair = c.kind === 'solana-tw' ? Keypair.fromSeed(derived2!.solTWSeed32) : c.kind === 'solana-phantom' ? Keypair.fromSeed(derived2!.solPhantomSeed32) : meta?.kind === 'privateKey' ? importedSolKp! : Keypair.fromSeed(derived2!.solSeed32);
    const conn = new Connection(solanaRpcUrl(), 'confirmed');
    const lamports = parseRawAmount(amtStr, 9);
    if (lamports == null) throw new Error('Invalid amount.');
    const tx = new Transaction().add(SystemProgram.transfer({ fromPubkey: kp.publicKey, toPubkey: new PublicKey(to), lamports: Number(lamports) }));
    const { blockhash } = await conn.getLatestBlockhash('confirmed'); tx.recentBlockhash = blockhash; tx.feePayer = kp.publicKey; tx.sign(kp);
    return await sendSolanaSigned(conn, tx.serialize(), bs58.encode(tx.signature!));
  }
  const pk = meta?.kind === 'privateKey' ? (secret!.startsWith('0x') ? secret! : '0x' + secret!) : derived2!.evmPrivateKey;
  const provider = new ethers.JsonRpcProvider(evmProviderUrl(c), c.evmId);
  const wallet = new ethers.Wallet(pk, provider);
  // User-chosen fees (Slow/Market/Fast/Custom) are signed into the
  // transaction exactly as shown on the confirm screen; Auto keeps the
  // wallet defaults. gasLimit is pinned for plain transfers when the user
  // picked a fee so the estimate they saw is the fee that applies.
  const txReq: ethers.TransactionRequest = { to, value: ethers.parseEther(amtStr) };
  if (Object.keys(feeOverrides).length) { Object.assign(txReq, feeOverrides); txReq.gasLimit = 21000n; }
  const tx = await wallet.sendTransaction(txReq);
  return tx.hash;
}

// ---------- activity ----------
// Chain filter: a horizontally scrollable chip rail — network ICON +
// chain NAME per chip (never a bare gas ticker: three EVM chains all
// read "ETH" that way). One chip per enabled chain, selected = chrome.
// Rows group by date (Today / Yesterday / date). Switching chips keeps
// the previous list on screen under a slim loading strip — no blank flash.
function actGroupLabel(ts: number): string {
  if (!ts) return 'Earlier';
  const d = new Date(ts); const now = new Date();
  const sameDay = (a: Date, b: Date) => a.getFullYear() === b.getFullYear() && a.getMonth() === b.getMonth() && a.getDate() === b.getDate();
  if (sameDay(d, now)) return 'Today';
  const y = new Date(now); y.setDate(now.getDate() - 1);
  if (sameDay(d, y)) return 'Yesterday';
  return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
}
function shortHash(h: string): string { return h.length > 14 ? `${h.slice(0, 6)}…${h.slice(-4)}` : h; }
function shortAddr(a: string): string { return a.length > 14 ? `${a.slice(0, 6)}…${a.slice(-4)}` : a; }
// Shared receipt: a CENTRED moment — chrome-ring check, clean white title,
// DotGothic amount with fiat under it, shortened recipient, ONE quiet
// truncated hash row with copy — never a top-pinned card or a raw-hash slab.
function receiptHTML(o: { title: string; amount?: string; fiat?: string; toLine?: string; sub?: string; hash: string; extra?: string; doneLabel: string }): string {
  return `<main class="receiptMain"><div class="receiptCard">
    <div class="receiptRing"><i class="ri-check-line"></i></div>
    <h1 class="receiptTitle">${esc(o.title)}</h1>
    ${o.amount ? `<div class="receiptAmt">${esc(o.amount)}</div>` : ''}
    ${o.fiat ? `<div class="receiptFiat">${esc(o.fiat)}</div>` : ''}
    ${o.toLine ? `<p class="receiptTo">${esc(o.toLine)}</p>` : ''}
    ${o.sub ? `<p class="receiptSub">${esc(o.sub)}</p>` : ''}
    <button class="hashRow" id="rcHash"><span class="mono">${esc(shortHash(o.hash))}</span><i class="ri-file-copy-line"></i></button>
    ${o.extra || ''}
    <button class="btnPrimary" id="rcExp">View on explorer</button>
    <button class="btnGhost" id="rcDone">${esc(o.doneLabel)}</button>
  </div></main>`;
}
function bindReceipt(hash: string, explorerTx: string, done: (el: HTMLElement) => void) {
  const hb = $('#rcHash'); if (hb) hb.onclick = (e) => copyText(hash, e.currentTarget as HTMLElement);
  const ex = $('#rcExp'); if (ex) { if (explorerTx) ex.onclick = () => window.open(explorerTx + hash, '_blank'); else (ex as HTMLElement).style.display = 'none'; }
  const dn = $('#rcDone'); if (dn) dn.onclick = (ev: any) => done(ev.currentTarget as HTMLElement);
}
// One chain's activity from its sources. EVM chains try their
// Blockscout instance directly, then FALL BACK to the server's history
// endpoint (Blockscout server-side, then Routescan) when the direct
// read fails or the chain has no Blockscout — a chain's history must
// never hinge on one bot-walled instance (audit pass, 2026-11-19: a
// real confirmed Polygon send was invisible in Activity because
// polygon.blockscout.com answers browser fetches with a Cloudflare
// challenge). Throws when every source failed, so callers can render
// the honest UNAVAILABLE state (never a fake empty).
async function fetchChainActivity(c: Chain, addr: string, limit = 15): Promise<ActivityRow[]> {
  if (c.kind === 'solana' || c.kind === 'solana-tw' || c.kind === 'solana-phantom') { const conn = new Connection(solanaRpcUrl()); const sigs = await conn.getSignaturesForAddress(new PublicKey(addr), { limit }); return sigs.map(s => ({ hash: s.signature, label: s.err ? 'Failed transaction' : 'Transaction', sub: s.blockTime ? new Date(s.blockTime * 1000).toLocaleString() : '', ts: s.blockTime ? s.blockTime * 1000 : 0, dir: 'other' as ActDir, sym: 'SOL', st: s.err ? 'failed' as const : undefined })); }
  if (c.kind === 'bitcoin') { const r = await fetch(`/api/utxo/${c.id}/txs/${addr}`); const j = await r.json(); return (Array.isArray(j) ? j : []).slice(0, limit).map((t: any) => {
    // Direction/amount/counterparty derive from the tx's own vin/vout —
    // the passthrough returns the full esplora transaction.
    const vins: any[] = Array.isArray(t.vin) ? t.vin : []; const vouts: any[] = Array.isArray(t.vout) ? t.vout : [];
    const mine = (a: any) => typeof a === 'string' && a === addr;
    let dir: ActDir | undefined; let sats = 0; let cp = '';
    if (vins.some(v => mine(v.prevout?.scriptpubkey_address))) { dir = 'out'; for (const o of vouts) { if (!mine(o.scriptpubkey_address)) { sats += Number(o.value) || 0; if (!cp && o.scriptpubkey_address) cp = o.scriptpubkey_address; } } }
    else if (vouts.some(o => mine(o.scriptpubkey_address))) { dir = 'in'; for (const o of vouts) if (mine(o.scriptpubkey_address)) sats += Number(o.value) || 0; const f = vins.find(v => v.prevout?.scriptpubkey_address && !mine(v.prevout.scriptpubkey_address)); cp = f?.prevout?.scriptpubkey_address || ''; }
    return { hash: t.txid, label: dir === 'out' ? `Sent ${c.symbol}` : dir === 'in' ? `Received ${c.symbol}` : `${c.name} transaction`, sub: t.status?.block_time ? new Date(t.status.block_time * 1000).toLocaleString() : 'Unconfirmed', ts: t.status?.block_time ? t.status.block_time * 1000 : 0, dir, sym: c.symbol, amt: dir && sats > 0 ? sats / 1e8 : undefined, cp: cp || undefined, st: t.status && t.status.confirmed === false ? 'pending' as const : undefined };
  }); }
  if (c.kind === 'tron') { const r = await fetch(`https://api.trongrid.io/v1/accounts/${addr}/transactions?limit=${limit}&only_confirmed=true`); const j = await r.json(); const myHex = tronToHex(addr).toLowerCase(); return (j.data || []).map((t: any) => {
    const base: ActivityRow = { hash: t.txID, label: 'TRX transfer', sub: t.block_timestamp ? new Date(t.block_timestamp).toLocaleString() : '', ts: t.block_timestamp || 0, dir: 'other', sym: 'TRX', st: t.ret?.[0]?.contractRet && t.ret[0].contractRet !== 'SUCCESS' ? 'failed' : undefined };
    const k = t.raw_data?.contract?.[0];
    if (k?.type === 'TransferContract') {
      const v = k.parameter?.value || {}; const owner = String(v.owner_address || '').toLowerCase(); const to = String(v.to_address || '').toLowerCase();
      const amt = typeof v.amount === 'number' && v.amount > 0 ? v.amount / 1e6 : undefined;
      if (owner === myHex && to) { const cp = tronHexToBase58(to); return { ...base, label: 'Sent TRX', dir: 'out' as ActDir, amt, cp: cp || undefined }; }
      if (to === myHex && owner) { const cp = tronHexToBase58(owner); return { ...base, label: 'Received TRX', dir: 'in' as ActDir, amt, cp: cp || undefined }; }
    }
    return base;
  }); }
  if (c.kind === 'xrp') { const r = await fetch('https://xrplcluster.com/', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ method: 'account_tx', params: [{ account: addr, limit, ledger_index_min: -1, ledger_index_max: -1 }] }) }); const j = await r.json(); return (j.result?.transactions || []).map((x: any) => {
    const base: ActivityRow = { hash: x.tx.hash, label: 'XRP transaction', sub: x.tx.date ? new Date((x.tx.date + 946684800) * 1000).toLocaleString() : '', ts: x.tx.date ? (x.tx.date + 946684800) * 1000 : 0, dir: 'other', sym: 'XRP', st: x.meta?.TransactionResult && x.meta.TransactionResult !== 'tesSUCCESS' ? 'failed' : undefined };
    if (x.tx.TransactionType === 'Payment') {
      const raw = x.meta?.delivered_amount ?? x.tx.Amount;
      let amt: number | undefined; let sym = 'XRP';
      if (typeof raw === 'string') { const n = Number(raw); if (Number.isFinite(n) && n > 0) amt = n / 1e6; }
      else if (raw && typeof raw === 'object') { const n = parseFloat(raw.value); if (Number.isFinite(n) && n > 0) { amt = n; sym = String(raw.currency || 'XRP'); } }
      if (x.tx.Account === addr && x.tx.Destination) return { ...base, label: `Sent ${sym}`, dir: 'out' as ActDir, amt, sym, cp: String(x.tx.Destination) };
      if (x.tx.Destination === addr && x.tx.Account) return { ...base, label: `Received ${sym}`, dir: 'in' as ActDir, amt, sym, cp: String(x.tx.Account) };
    }
    return base;
  }); }
  if (c.kind === 'sui') { const r = await fetch('https://graphql.mainnet.sui.io/graphql', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ query: `query { transactions(first: ${limit}, filter: { affectedAddress: "${addr}" }) { nodes { digest effects { timestamp } } } }` }) }); const j = await r.json(); return (j?.data?.transactions?.nodes || []).map((t: any) => ({ hash: t.digest, label: 'Sui transaction', sub: t.effects?.timestamp ? new Date(t.effects.timestamp).toLocaleString() : '', ts: t.effects?.timestamp ? new Date(t.effects.timestamp).getTime() : 0, dir: 'other' as ActDir, sym: 'SUI' })); }
  if (c.kind === 'aptos') { const r = await fetch(`https://api.mainnet.aptoslabs.com/v1/accounts/${encodeURIComponent(addr)}/transactions?limit=${limit}`); const j = await r.json(); return (Array.isArray(j) ? j : []).map((t: any) => ({ hash: t.hash, label: 'Aptos transaction', sub: t.timestamp ? new Date(Math.floor(Number(t.timestamp) / 1000)).toLocaleString() : '', ts: t.timestamp ? Math.floor(Number(t.timestamp) / 1000) : 0, dir: 'other' as ActDir, sym: 'APT', st: t.success === false ? 'failed' as const : undefined })); }
  if (c.kind === 'cosmos') { throw new Error('cosmos-activity-unavailable'); }
  if (c.kind === 'evm') {
    if (c.blockscout) {
      try {
        const r = await fetch(`${c.blockscout}/api/v2/addresses/${addr}/transactions?page_size=${limit}`);
        if (!r.ok) throw new Error('blockscout ' + r.status);
        const j = await r.json();
        if (!Array.isArray(j.items)) throw new Error('blockscout payload');
        return j.items.map((t: any) => {
          const from = String(t.from?.hash || ''); const to = String(t.to?.hash || '');
          const mine = from.toLowerCase() === addr.toLowerCase();
          const other = mine ? to : from;
          if (other) recordCounterparty(other);
          let valueWei = 0n; try { valueWei = t.value ? BigInt(t.value) : 0n; } catch { valueWei = 0n; }
          const hasValue = valueWei > 0n;
          // Audit fix: labels used to derive from value alone, so an
          // ERC-20 transfer or approval read as "Sent {native}" and a
          // zero-value inbound call read as sent BY the user. Use the
          // indexer's own classification (tx_types / method) and stay
          // generic rather than invent a token or amount.
          const types: string[] = Array.isArray(t.tx_types) ? t.tx_types : [];
          const base = { hash: t.hash, sub: t.timestamp ? new Date(t.timestamp).toLocaleString() : '', ts: t.timestamp ? new Date(t.timestamp).getTime() : 0, sym: c.symbol, cp: other || undefined, st: t.status === 'error' ? 'failed' as const : undefined };
          if (!hasValue && types.includes('token_transfer')) return { ...base, label: 'Token transfer', dir: (mine ? 'out' : 'in') as ActDir, amt: undefined };
          if (!hasValue && (types.includes('contract_call') || (t.method && t.method !== 'transfer'))) return { ...base, label: t.method ? `Contract call · ${String(t.method)}` : 'Contract call', dir: (mine ? 'out' : undefined) as ActDir | undefined, amt: undefined };
          const received = hasValue && !mine;
          return { ...base, label: `${received ? 'Received' : 'Sent'} ${c.symbol}`, dir: (received ? 'in' : 'out') as ActDir, amt: hasValue ? Number(valueWei) / 10 ** c.decimals : undefined };
        });
      } catch { /* primary source failed — the fallback below answers instead */ }
    }
    if (c.evmId != null) {
      const r = await fetch(`/api/history/${c.evmId}?address=${encodeURIComponent(addr)}&symbol=${encodeURIComponent(c.symbol)}&limit=${limit}`);
      if (!r.ok) throw new Error('history-unavailable');
      const j = await r.json();
      if (!Array.isArray(j.rows)) throw new Error('history-unavailable');
      return j.rows.map((t: any) => { const n = t.amt != null ? Number(t.amt) : NaN; return { hash: String(t.hash), label: String(t.label || 'Transaction'), sub: t.ts ? new Date(t.ts).toLocaleString() : '', ts: Number(t.ts) || 0, dir: (t.dir === 'in' || t.dir === 'out' ? t.dir : undefined) as ActDir | undefined, sym: typeof t.sym === 'string' && t.sym ? t.sym : c.symbol, amt: Number.isFinite(n) && n > 0 ? n : undefined, cp: typeof t.cp === 'string' && t.cp ? t.cp : undefined, st: t.st === 'failed' ? 'failed' as const : undefined }; });
    }
    throw new Error('no-activity-source');
  }
  throw new Error('no-activity-source');
}
// ---------- activity row presentation ----------
// The row design reads ONLY the presentation fields on ActivityRow
// (dir/sym/amt/cp/st/img/cgid). Rows persisted by older builds lack
// them, so direction/symbol fall back to the app's own label wording —
// the label was always generated by this app, so the parse is exact,
// and anything unrecognised renders as a plain generic row.
const ACT_GLYPH: Record<ActDir, string> = { in: 'ri-arrow-left-down-line', out: 'ri-arrow-right-up-line', swap: 'ri-arrow-left-right-line', stake: 'ri-plant-line', approve: 'ri-shield-check-line', nft: 'ri-nft-line', other: 'ri-exchange-line' };
function actDirOf(rw: ActivityRow): ActDir {
  if (rw.dir) return rw.dir;
  const l = rw.label;
  if (/^Received/.test(l)) return 'in';
  if (/^Swap/.test(l)) return 'swap';
  if (/^(Staked|Unstaking|Withdrew)/.test(l)) return 'stake';
  if (/^Revoked/.test(l)) return 'approve';
  if (/^Sent NFT/.test(l)) return 'nft';
  if (/^Sent/.test(l)) return 'out';
  return 'other';
}
function actSymOf(rw: ActivityRow, c?: Chain): string {
  if (rw.sym) return rw.sym;
  const m = /^(?:Sent|Received) ([A-Za-z0-9]{1,12})$/.exec(rw.label);
  if (m) return m[1];
  const s = /^Swap (\S+?)(?: →| ->)/.exec(rw.label);
  if (s) return s[1];
  if (/^(Staked|Unstaking|Withdrew) SOL/.test(rw.label)) return 'SOL';
  return c?.symbol || '';
}
function actStatusOf(rw: ActivityRow): 'pending' | 'failed' | undefined {
  return rw.st || (rw.label === 'Failed transaction' ? 'failed' : undefined);
}
function actPriceUsd(rw: ActivityRow, c?: Chain): number | null {
  if (rw.cgid) return prices?.[rw.cgid]?.usd ?? null;
  const sym = rw.sym; if (!sym || !c) return null;
  if (sym === c.symbol) return priceOf(c);
  const t = [...BUILTIN_TOKENS, ...config.tokens].find(t => t.chainId === c.id && t.symbol === sym);
  return t ? tokenUsd(t) : null;
}
function actAmtText(a: number): string { if (a > 0 && a < 0.000001) return '<0.000001'; return trimNum(a, 6); }
function actSign(rw: ActivityRow, dir: ActDir): string {
  if (dir === 'in') return '+';
  if (dir === 'out' || dir === 'swap') return '−';
  if (dir === 'stake') return /^Withdrew/.test(rw.label) ? '+' : /^Staked/.test(rw.label) ? '−' : '';
  return '';
}
function actWhen(rw: ActivityRow): string { return rw.ts ? new Date(rw.ts).toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit' }) : ''; }
// Transaction detail sheet — rows used to jump straight to the block
// explorer; the sheet keeps the facts (and the copy buttons) in-app and
// demotes the explorer to one chrome action at the bottom. Fields the
// row doesn't honestly carry (counterparty for a Solana signature, an
// amount the source never gave) are simply absent — never reconstructed.
function openTxDetail(rw: ActivityRow, chain?: Chain) {
  const c = chain || CHAINS.find(x => x.id === rw.chainId);
  const dir = actDirOf(rw); const sym = actSymOf(rw, c); const st = actStatusOf(rw);
  const own = c ? addressFor(c) : '';
  const from = rw.cp && own ? (dir === 'in' ? rw.cp : own) : '';
  const to = rw.cp && own ? (dir === 'in' ? own : rw.cp) : '';
  const p = actPriceUsd(rw, c);
  const fiat = p != null && rw.amt ? fmtUsd(rw.amt * p) : '';
  const when = rw.ts ? new Date(rw.ts).toLocaleString('en-US', { month: 'short', day: 'numeric', year: 'numeric', hour: 'numeric', minute: '2-digit' }) : rw.sub;
  const statusHTML = st === 'failed' ? '<span class="neg">Failed</span>' : st === 'pending' ? '<span class="actAmber">Pending</span>' : '<span class="pos">Confirmed</span>';
  const addrRow = (lbl: string, a: string) => a ? `<div class="detRow"><span class="detLbl">${lbl}</span><span class="detAddr"><span class="mono">${esc(a)}</span><button class="detCopy" data-copy="${esc(a)}" aria-label="Copy ${lbl} address" type="button"><i class="ri-file-copy-line"></i></button></span></div>` : '';
  const body = `
    <div class="detHero"><span class="actMed lg ${st === 'pending' ? 'pend' : ''} ${st === 'failed' ? 'fail' : ''}"><i class="${ACT_GLYPH[dir]}"></i></span>
    ${rw.amt != null && rw.amt > 0 && sym ? `<div class="detAmt">${actSign(rw, dir)}${actAmtText(rw.amt)} ${esc(sym)}</div>${fiat ? `<div class="detFiat">${esc(fiat)}</div>` : ''}` : ''}</div>
    <div class="detCard">
      <div class="detRow"><span class="detLbl">Status</span><span class="detVal">${statusHTML}</span></div>
      ${addrRow('From', from)}
      ${addrRow('To', to)}
      ${c ? `<div class="detRow"><span class="detLbl">Network</span><span class="detVal">${iconHTML(chainIconUrl(c), c.symbol, c.name, { sm: true })}<span>${esc(c.name)}</span></span></div>` : ''}
      ${when ? `<div class="detRow"><span class="detLbl">Date</span><span class="detVal">${esc(when)}</span></div>` : ''}
      <div class="detRow"><span class="detLbl">Transaction</span><span class="detAddr"><span class="mono">${esc(shortHash(rw.hash))}</span><button class="detCopy" data-copy="${esc(rw.hash)}" aria-label="Copy transaction hash" type="button"><i class="ri-file-copy-line"></i></button></span></div>
    </div>
    ${c?.explorerTx ? '<button class="btnPrimary" id="txExp" style="margin-top:16px">View on explorer</button>' : ''}`;
  openSheet(rw.label, body);
  const wrap = document.getElementById('genericSheetWrap');
  wrap?.querySelectorAll('[data-copy]').forEach(b => (b as HTMLElement).onclick = () => copyText((b as HTMLElement).dataset.copy!, b as HTMLElement));
  const ex = wrap?.querySelector('#txExp') as HTMLElement | null;
  if (ex && c?.explorerTx) ex.onclick = () => window.open(c.explorerTx + rw.hash, '_blank');
}
function showActivity() {
  // "All networks" is the FIRST chip and the DEFAULT selection on every
  // fresh open of the tab (user's order, 2026-11-19).
  setView(`<main><div class="ltWrap"><div class="largeTitle">Activity</div></div><div class="chipRail" id="actRail"><button class="netChip on" data-c="all">${iconHTML('', 'ALL', 'All networks', { sm: true })}<span>All networks</span></button>${visibleChains().map(x => `<button class="netChip" data-c="${x.id}">${iconHTML(chainIconUrl(x), x.symbol, x.name, { sm: true })}<span>${esc(x.name)}</span></button>`).join('')}</div><div id="actList" style="padding:2px 16px 0">${waveLoadBlockHTML()}</div></main>`);
  let actChain = 'all';
  let paintedChain = '';
  // Audit fix: Activity was hard-capped (15 per source, 20/40 after
  // merge) with no way to reach older transactions. Depth now grows
  // via the "Show more" button (15 → 50 → 100 per source).
  let actDepth = 15;
  // Row anatomy (fixed height, so a status flip can never shift layout):
  // chrome-ring direction medallion · asset icon with the network mark
  // as a corner badge · two-line text (action label, then counterparty
  // or status + time) · right-aligned value block (signed amount, fiat
  // under it; the time alone when the source gave no amount).
  const rowHTML = (rw: ActivityRow, idx: number, chain?: Chain) => {
    const c = chain || CHAINS.find(x => x.id === rw.chainId);
    const dir = actDirOf(rw); const sym = actSymOf(rw, c); const st = actStatusOf(rw);
    const when = actWhen(rw);
    const parts: string[] = [];
    if (st === 'failed') parts.push('<span class="actFailTx">Failed</span>');
    else if (st === 'pending') parts.push('Pending');
    if (rw.cp) parts.push(`${dir === 'in' ? 'From' : 'To'} ${esc(shortAddr(rw.cp))}`);
    if (when) parts.push(esc(when));
    const sub = parts.length ? parts.join(' · ') : esc(rw.sub);
    let val = '';
    if (rw.amt != null && rw.amt > 0 && sym) {
      const p = actPriceUsd(rw, c);
      const fiat = p != null ? fmtUsd(rw.amt * p) : '';
      val = `<span class="actAmt${dir === 'in' ? ' pos' : ''}">${actSign(rw, dir)}${actAmtText(rw.amt)} ${esc(sym)}</span>${fiat ? `<span class="actFiat">${esc(fiat)}</span>` : '<span class="actFiat">&nbsp;</span>'}`;
    } else if (when) {
      val = `<span class="actFiat">${esc(when)}</span>`;
    }
    const assetUrl = rw.img !== undefined ? rw.img : (c ? chainIconUrl(c) : '');
    const netUrl = c ? chainIconUrl(c) : '';
    return `<button class="actRow" data-idx="${idx}" data-hash="${esc(rw.hash)}" data-chain="${esc(rw.chainId || '')}"><span class="actMed${st === 'pending' ? ' pend' : ''}${st === 'failed' ? ' fail' : ''}"><i class="${ACT_GLYPH[dir]}"></i></span><span class="actAsset">${iconHTML(assetUrl, sym || '?', rw.label)}${netUrl ? `<span class="actNetBadge"><img class="coinImg" src="${esc(netUrl)}" alt="" width="14" height="14"></span>` : ''}</span><span class="actTx"><span class="actLabel">${esc(rw.label)}</span><span class="actSub">${sub}</span></span><span class="actVal">${val}</span></button>`;
  };
  const groupHTML = (rows: ActivityRow[], chain?: Chain) => {
    let html = ''; let lastGroup = ''; let inCard = false;
    rows.forEach((rw, i) => {
      const g = actGroupLabel(rw.ts || 0);
      if (g !== lastGroup) { if (inCard) html += '</div>'; html += `<div class="actGroupH">${esc(g)}</div><div class="actCard">`; lastGroup = g; inCard = true; }
      html += rowHTML(rw, i, chain);
    });
    if (inCard) html += '</div>';
    return html;
  };
  const bindRows = (el: HTMLElement, rows: ActivityRow[], chain?: Chain) => {
    el.querySelectorAll('.actRow').forEach(b => (b as HTMLElement).onclick = () => {
      const rw = rows[Number((b as HTMLElement).dataset.idx)];
      if (rw) openTxDetail(rw, chain || CHAINS.find(x => x.id === rw.chainId));
    });
  };
  const paintMoreBtn = (el: HTMLElement, shown: number, cap: number) => {
    if (actDepth >= 100 || shown < cap - 5) return;
    const wrap = document.createElement('div');
    wrap.style.padding = '14px 16px 6px';
    wrap.innerHTML = '<button class="btnGhost" type="button">Show more activity</button>';
    (wrap.querySelector('button') as HTMLButtonElement).onclick = () => { actDepth = Math.min(100, actDepth + 35); void load(actChain); };
    el.appendChild(wrap);
  };
  const paintRows = (c: Chain, rows: ActivityRow[]) => {
    const el = $('#actList'); if (!el || actChain !== c.id) return;
    paintedChain = c.id;
    if (!rows.length) {
      el.innerHTML = `<div class="emptyState"><span class="emptyIc"><i class="ri-history-line"></i></span><div class="emptyT">No activity yet</div><p class="emptySub">Transfers on ${esc(c.name)} will appear here.</p></div>`;
      return;
    }
    el.innerHTML = groupHTML(rows, c);
    bindRows(el, rows, c);
    paintMoreBtn(el, rows.length, actDepth + 10);
  };
  // Local records + chain rows merged by hash, newest first — a send
  // appears the moment it broadcasts and is never duplicated when the
  // explorer record lands. Audit fix: when both exist, the LOCAL
  // record's presentation wins (it knows "Swap USDC → …" precisely,
  // where the chain row can only guess "Sent ETH"); the chain row
  // still supplies status and timestamp.
  const mergeRows = (locals: ActivityRow[], fetched: ActivityRow[]): ActivityRow[] => {
    const localByHash = new Map(locals.map(r => [r.hash.toLowerCase(), r]));
    const merged = fetched.map(f => { const l = localByHash.get(f.hash.toLowerCase()); return l ? { ...f, label: l.label, dir: l.dir ?? f.dir, sym: l.sym ?? f.sym, amt: l.amt ?? f.amt, img: l.img ?? f.img, cgid: l.cgid ?? f.cgid, cp: l.cp ?? f.cp } : f; });
    const seen = new Set(fetched.map(r => r.hash.toLowerCase()));
    return [...merged, ...locals.filter(r => !seen.has(r.hash.toLowerCase()))].sort((a, b) => (b.ts || 0) - (a.ts || 0)).slice(0, actDepth + 10);
  };
  const tagChain = (rows: ActivityRow[], chainId: string): ActivityRow[] => rows.map(r => ({ ...r, chainId }));
  const mergeAll = (perChain: ActivityRow[][]): ActivityRow[] => {
    const seen = new Set<string>(); const out: ActivityRow[] = [];
    for (const rows of perChain) for (const r of rows) {
      const k = (r.chainId || '') + ':' + r.hash.toLowerCase();
      if (seen.has(k)) continue; seen.add(k); out.push(r);
    }
    return out.sort((a, b) => (b.ts || 0) - (a.ts || 0)).slice(0, Math.min(actDepth * 4, 200));
  };
  const paintAll = (rows: ActivityRow[], failedNames: string[]) => {
    const el = $('#actList'); if (!el || actChain !== 'all') return;
    paintedChain = 'all';
    if (!rows.length) {
      el.innerHTML = `<div class="emptyState"><span class="emptyIc"><i class="ri-history-line"></i></span><div class="emptyT">No activity yet</div><p class="emptySub">Transfers on any network will appear here.</p></div>`;
      return;
    }
    // One chain's failed source degrades ONLY that chain's contribution:
    // its cached/local rows (already merged in) still show, and a quiet
    // footnote names the networks that couldn't be reached — the rest
    // of the list is complete and stays put.
    el.innerHTML = groupHTML(rows) + (failedNames.length ? `<p class="emptySub" style="text-align:center;padding:12px 8px 4px">Couldn't reach ${esc(failedNames.join(', '))} — showing everything else.</p>` : '');
    bindRows(el, rows);
    paintMoreBtn(el, rows.length, Math.min(actDepth * 4, 200));
  };
  const loadAll = async () => {
    actChain = 'all';
    const chains = visibleChains();
    const el = $('#actList'); if (!el) return;
    const snapshot = () => chains.map(c => tagChain(mergeRows(localTxRows(c.id), activityCache.get(c.id) || []), c.id));
    const first = mergeAll(snapshot());
    if (first.length) paintAll(first, []);
    else { paintedChain = ''; el.innerHTML = waveLoadBlockHTML(); }
    const failedNames: string[] = [];
    await Promise.all(chains.map(async c => {
      const addr = addressFor(c); if (!addr) return;
      try {
        const rows = await fetchChainActivity(c, addr, actDepth);
        pruneLocalTxs(c.id, rows);
        activityCache.set(c.id, rows);
      } catch {
        if (!activityCache.has(c.id) && !localTxRows(c.id).length) failedNames.push(c.name);
      }
    }));
    saveDataCache();
    if (actChain !== 'all') return;
    const merged = mergeAll(snapshot());
    if (!merged.length && failedNames.length) {
      const el2 = $('#actList'); if (el2) { paintedChain = ''; el2.innerHTML = `<div class="emptyState"><span class="emptyIc"><i class="ri-cloud-off-line"></i></span><div class="emptyT">Activity unavailable</div><p class="emptySub">Activity is unavailable right now — no network source could be reached.</p></div>`; }
      return;
    }
    paintAll(merged, failedNames);
  };
  const load = async (chainId: string) => {
    if (chainId === 'all') { await loadAll(); return; }
    actChain = chainId;
    const c = CHAINS.find(x => x.id === chainId)!; const addr = addressFor(c); const el = $('#actList'); if (!el) return;
    const cached = activityCache.get(chainId);
    const locals = localTxRows(chainId);
    // ONE coherent state per selected chain: this chain's own cached/local
    // rows paint instantly (silent refresh follows), or — with nothing of
    // this chain to show — the CENTRED block loader. Never another chain's
    // rows, never a loader strip over stale content, never an empty state
    // under a loader.
    if (cached || locals.length) paintRows(c, mergeRows(locals, cached || []));
    else { paintedChain = ''; el.innerHTML = waveLoadBlockHTML(); }
    try {
      const rows = await fetchChainActivity(c, addr, actDepth);
      pruneLocalTxs(chainId, rows);
      activityCache.set(chainId, rows); saveDataCache();
      paintRows(c, mergeRows(localTxRows(chainId), rows));
    } catch (e: any) {
      // A failed fetch never masquerades as "no activity": local records
      // and any cache still paint; only a chain with neither gets the
      // honest UNAVAILABLE state (EMPTY is reserved for a completed,
      // successful fetch that returned zero).
      const left = localTxRows(chainId);
      if (left.length || activityCache.has(chainId)) paintRows(c, mergeRows(left, activityCache.get(chainId) || []));
      else { const el2 = $('#actList'); if (el2 && actChain === chainId) { paintedChain = ''; el2.innerHTML = `<div class="emptyState"><span class="emptyIc"><i class="ri-cloud-off-line"></i></span><div class="emptyT">Activity unavailable</div><p class="emptySub">${e?.message === 'cosmos-activity-unavailable' ? 'Activity for Cosmos Hub is not available in Syn Wallet yet.' : 'Activity is unavailable for this chain right now.'}</p></div>`; } }
    }
  };
  V().querySelectorAll('#actRail button').forEach(b => (b as HTMLElement).onclick = () => { V().querySelectorAll('#actRail button').forEach(x => x.classList.toggle('on', x === b)); railReveal(b as HTMLElement, true); load((b as HTMLElement).dataset.c!); });
  void loadAll();
}

// ---------- settings (account-settings pattern) ----------
function showSettings(err = '', msg = '') {
  if (!meta) return;
  const created = new Date(meta.createdAt).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
  const nWallets = vaultPayload ? vaultPayload.wallets.length : 1;
  const ico = (n: string, red = false) => `<span class="sIco${red ? ' red' : ''}"><i class="ri-${n}"></i></span>`;
  const chev = '<i class="ri-arrow-right-s-line sChev"></i>';
  setView(`<main><div class="ltWrap"><div class="largeTitle">Settings</div></div>${err ? `<div style="padding:0 16px"><div class="err">${esc(err)}</div></div>` : ''}${msg ? `<div style="padding:0 16px"><div class="ok">${esc(msg)}</div></div>` : ''}
  <button class="wHead" id="wHead" type="button"><span class="wHeadLogo"><img src="/assets/logo-sm.png" alt="Syn"></span><span class="wHeadTx"><span class="wHeadName">${esc(activeWallet()?.name || 'Main wallet')}</span><div class="wHeadSub">Multi-chain wallet</div></span>${chev}</button>
  <div class="gGroup"><div class="gHead">Wallet</div><div class="gCard">
    <button class="sRow" id="setWallets" type="button">${ico('wallet-3-line')}<span class="sTx"><span class="sLbl">Wallets &amp; accounts</span></span><span class="sVal">${nWallets} ${nWallets === 1 ? 'wallet' : 'wallets'}</span>${chev}</button>
    <button class="sRow" id="setAddToken" type="button">${ico('coins-line')}<span class="sTx"><span class="sLbl">Add token</span><div class="sSub">Browse the token catalog or add by contract</div></span>${chev}</button>
    <div class="sRow">${ico('key-2-line')}<span class="sTx"><span class="sLbl">Wallet type</span><div class="sSub">Keys generated &amp; encrypted locally</div></span><span class="sVal">Non-custodial</span></div>
    <div class="sRow">${ico('calendar-line')}<span class="sTx"><span class="sLbl">Created</span></span><span class="sVal">${created}</span></div>
  </div><div class="gFoot">This wallet lives only on this device. There is no Syn account and no server copy.</div></div>
  ${hlMasterAddr() ? `<div class="gGroup"><div class="gHead">Trading</div><div class="gCard">
    <button class="sRow" id="setHl" type="button">${ico('line-chart-line')}<span class="sTx"><span class="sLbl">Your Hyperliquid account</span><div class="sSub">Value, positions and trading key</div></span>${hlAcct && hlAcctAddr === hlMasterAddr() ? `<span class="sVal">${fmtUsd(hlAcct.accountValue)}</span>` : ''}${chev}</button>
  </div><div class="gFoot">Perpetuals trading built into Syn Wallet — the trading key lives in your encrypted vault and can never withdraw.</div></div>` : ''}
  <div class="gGroup"><div class="gHead">Networks</div><div class="gCard">
    ${visibleChains().map(c => `<div class="sRow"><span class="sCoin">${coinIcon(c)}</span><span class="sTx"><span class="sLbl">${esc(c.name)}</span></span><span class="sVal">Enabled</span></div>`).join('')}
    <button class="sRow" id="setAddNet" type="button">${ico('add-circle-line')}<span class="sTx"><span class="sLbl">Add more</span><div class="sSub">Enable more networks or add a custom one</div></span>${chev}</button>
  </div><div class="gFoot">${enabledSet().size} of ${CHAINS.length} networks enabled — disabled networks and their tokens stay hidden across the wallet.</div></div>
  <div class="gGroup"><div class="gHead">Backup</div><div class="gCard">
    <button class="sRow" id="expBackup" type="button">${ico('file-download-line')}<span class="sTx"><span class="sLbl">Export encrypted backup</span><div class="sSub">syn-wallet-backup file (.json)</div></span></button>
    <button class="sRow" id="impBackup" type="button">${ico('file-upload-line')}<span class="sTx"><span class="sLbl">Import backup</span><div class="sSub">Replaces the wallet on this device</div></span></button>
  </div><div class="gFoot">One encrypted file holding every wallet in this vault. <b>Store it in your own iCloud or Drive</b> — Syn never sees it and keeps no copy. Without your wallet password the file is useless to anyone. Importing a backup replaces the wallet currently on this device.</div></div>
  <div class="gGroup"><div class="gHead">Security</div><div class="gCard">
    <button class="sRow" id="lockBtn" type="button">${ico('lock-line')}<span class="sTx"><span class="sLbl">Lock now</span><div class="sSub">Require password to reopen</div></span></button>
    <div class="sRow">${ico('time-line')}<span class="sTx"><span class="sLbl">Auto-lock</span><div class="sSub">Locks after inactivity; keys are wiped from memory</div></span><span class="sVal">${autoLockMin()} min</span></div>
    <div class="sBlock"><div class="seg" id="alSeg"><button data-m="1">1 min</button><button data-m="5">5 min</button><button data-m="15">15 min</button></div></div>
    <button class="sRow" id="chgPwBtn" type="button">${ico('lock-password-line')}<span class="sTx"><span class="sLbl">Change password</span><div class="sSub">Re-encrypts the vault with a new password</div></span>${chev}</button>
    <button class="sRow" id="pkBtn" type="button">${ico('fingerprint-line')}<span class="sTx"><span class="sLbl">Face ID / passkey unlock</span><div class="sSub" id="pkDesc">${config.passkey ? 'Enabled — your password still works as a fallback.' : 'Checking support…'}</div></span><span class="sVal">${config.passkey ? 'On' : 'Off'}</span></button>
    ${meta.kind === 'mnemonic' ? `<button class="sRow" id="revealBtn" type="button">${ico('eye-line')}<span class="sTx"><span class="sLbl">Reveal recovery phrase</span><div class="sSub">Opens the secure reveal — password &amp; warning required</div></span>${chev}</button>` : `<div class="sRow">${ico('key-2-line')}<span class="sTx"><span class="sLbl">Imported account</span><div class="sSub">Private-key import — no recovery phrase</div></span><span class="sVal">${meta.chain === 'solana' ? 'Solana' : 'EVM'}</span></div>`}
    <button class="sRow" id="keysBtn" type="button">${ico('key-2-line')}<span class="sTx"><span class="sLbl">Private keys &amp; recovery phrase</span><div class="sSub">Per wallet, per chain — password and warning required</div></span>${chev}</button>
  </div><div class="gFoot">Your password and phrase never leave this device.</div></div>
  <div class="gGroup"><div class="gHead">Tools</div><div class="gCard">
    <button class="sRow" id="setSign" type="button">${ico('quill-pen-line')}<span class="sTx"><span class="sLbl">Sign a message</span><div class="sSub">personal_sign, Solana signMessage, and sign-in requests (SIWE / Solana) with clear-signing review</div></span>${chev}</button>
    <button class="sRow" id="setApprovals" type="button">${ico('shield-check-line')}<span class="sTx"><span class="sLbl">Token approvals</span><div class="sSub">Review and revoke ERC-20 allowances (GoPlus) and Solana token delegates</div></span>${chev}</button>
    <button class="sRow" id="setWc" type="button">${ico('links-line')}<span class="sTx"><span class="sLbl">WalletConnect</span><div class="sSub">Pair with dApps and review every session request before signing</div></span>${chev}</button>
    <button class="sRow" id="setBuy" type="button">${ico('money-dollar-circle-line')}<span class="sTx"><span class="sLbl">Buy &amp; sell</span><div class="sSub">Card on-ramp via MoonPay's hosted pages</div></span>${chev}</button>
  </div><div class="gFoot">Signing and permissions — always with full review on this device.</div></div>
  <div class="gGroup"><div class="gHead">Appearance</div><div class="gCard">
    <button class="sRow" id="setCurrency" type="button">${ico('exchange-dollar-line')}<span class="sTx"><span class="sLbl">Display currency</span><div class="sSub">Fiat values across the app, converted with live reference rates</div></span><span class="sVal">${currencyCode()}</span>${chev}</button>
    <div class="sRow">${ico('pulse-line')}<span class="sTx"><span class="sLbl">Wave effects</span><div class="sSub">A short chrome wave when a transaction lands, plus a soft pulse on buttons. Screen transitions stay either way.</div></span><button class="switch ${config.waveFx !== false ? 'on' : ''}" id="waveFxTgl" role="switch" aria-checked="${config.waveFx !== false}" aria-label="Toggle wave effects" type="button"><span></span></button></div>
  </div><div class="gFoot">Motion preferences, stored on this device only.</div></div>
  <div class="gGroup"><div class="gHead">About</div><div class="gCard">
    <div class="sRow">${ico('information-line')}<span class="sTx"><span class="sLbl">Version</span></span><span class="sVal">Syn Wallet · Public release (Wave 2)</span></div>
  </div><div class="gFoot">Seed phrases and private keys are generated, derived and used for signing <b>entirely in your browser</b>. The vault is encrypted with <b>AES-GCM</b> using a key derived from your password via <b>PBKDF2 (600,000 rounds)</b>. The server only hosts the app and passes prices/RPC through without storing or logging anything about you. <b>Everything is saved locally on this device. Syn's servers store nothing — no seed, no keys, no accounts.</b> No analytics or tracking run anywhere in the app. If you clear browser data or lose this device without your recovery phrase, this wallet cannot be recovered by Syn — <b>Syn can never recover your wallet; only your recovery phrase can.</b></div>
  <div class="gFoot" style="padding-top:10px">Anti-phishing: Syn will <b>never</b> ask for your recovery phrase or private key — not by email, message or website. Only enter your phrase inside Syn Wallet at its real address (79.108.164.56:8801). Optional passkey unlock uses WebAuthn PRF to wrap a copy of your password on devices that support it — your password always remains a working fallback, and nothing is ever gated behind biometrics alone. A compromised device or browser is outside what any web wallet can protect against — keep your device updated and locked.</div></div>
  <div class="gGroup"><div class="gHead">Danger zone</div><div class="gCard">
    <button class="sRow" id="wipeBtn" type="button">${ico('delete-bin-line', true)}<span class="sTx"><span class="sLbl red">Wipe wallet</span><div class="sSub">Removes the encrypted vault from this device. Only your backup can restore it.</div></span></button>
  </div></div></main>`);
  V().querySelectorAll('[data-copy]').forEach(b => (b as HTMLElement).onclick = () => copyText((b as HTMLElement).dataset.copy!, b as HTMLElement));
  ($('#lockBtn') as HTMLElement).onclick = () => lock();
  const setGo = (id: string, e: RouteEntry) => { const b = $(id) as HTMLElement | null; if (b) b.onclick = () => go(e, b); };
  setGo('#wHead', { route: 'accounts' });
  setGo('#setSign', { route: 'sign' });
  setGo('#setApprovals', { route: 'approvals' });
  setGo('#setWc', { route: 'connect' });
  setGo('#setBuy', { route: 'buy' });
  setGo('#setWallets', { route: 'accounts' });
  setGo('#keysBtn', { route: 'keys' });
  setGo('#setAddNet', { route: 'networks' });
  setGo('#setAddToken', { route: 'addtoken' });
  setGo('#setHl', { route: 'hlaccount' });
  ($('#expBackup') as HTMLElement).onclick = () => { exportBackup(); showSettings('', 'Backup file downloaded. Store it in your own iCloud or Drive — Syn never sees it, and without your password it is useless to anyone.'); };
  ($('#impBackup') as HTMLElement).onclick = () => { if (confirm('Importing a backup replaces the wallet currently on this device. Continue?')) pickBackupFile(m => showSettings(m)); };
  const pkb = $('#pkBtn'); if (pkb) {
    if (!config.passkey) passkeyPrfAvailable().then(ok => { const d = $('#pkDesc'); if (d && !config.passkey) d.textContent = ok ? 'Not enabled. Wraps a copy of your password with your device passkey (WebAuthn PRF).' : 'Not supported on this device/browser.'; if (!ok) (pkb as HTMLButtonElement).disabled = true; });
    pkb.onclick = async () => {
      if (config.passkey) { config.passkey = null; saveConfig(); showSettings('', 'Passkey unlock turned off. Your password is unchanged.'); return; }
      btnBusy(pkb as HTMLButtonElement, 'Waiting for device…');
      const err = await enablePasskey();
      if (err) showSettings(err); else showSettings('', 'Passkey unlock enabled. Your password still works as a fallback.');
    };
  }
  ($('#wipeBtn') as HTMLElement).onclick = () => { if (confirm('Wipe this wallet from this device? Without your backup it cannot be restored.')) { wipeAllLocalState(); shellMounted = false; navStack = []; navIdx = -1; currentRoute = ''; showOnboarding(); } };
  app().querySelectorAll('#alSeg button').forEach(b => { (b as HTMLElement).classList.toggle('on', Number((b as HTMLElement).dataset.m) === autoLockMin()); (b as HTMLElement).onclick = () => { localStorage.setItem(AUTOLOCK_KEY, (b as HTMLElement).dataset.m!); touchLock(); showSettings('', 'Auto-lock set to ' + (b as HTMLElement).dataset.m + ' minutes.'); }; });
  const wft = $('#waveFxTgl'); if (wft) (wft as HTMLElement).onclick = () => { config.waveFx = config.waveFx === false ? true : false; saveConfig(); showSettings('', config.waveFx ? 'Wave effects on.' : 'Wave effects off — transactions now land with a plain swap and buttons stay still.'); };
  const scur = $('#setCurrency'); if (scur) scur.onclick = () => openCurrencySheet();
  // Audit H-2 (2026-11-19): the old inline reveal decrypted the phrase
  // into an UNBLURRED box with no warning step and no throttle — it is
  // deleted. This row now routes to the gated KeyGate reveal (fresh
  // password, warning + "I understand", blur, 45s wipe), the same door
  // as "Private keys & recovery phrase".
  const rb = $('#revealBtn'); if (rb) rb.onclick = () => go({ route: 'keys' }, rb);
  // Deep audit 2026-11-22: there was NO way to change the wallet
  // password short of wipe + re-import. Safe order of operations:
  // prove the current password by decrypting the stored blob, build
  // the new blob, write it, and only then swap the in-memory
  // password — a failure anywhere leaves the old password working.
  const cp = $('#chgPwBtn'); if (cp) cp.onclick = () => {
    const close = openSheet('Change password', `<div style="padding:2px 2px 0">
      <div class="fld"><label>Current password</label><input type="password" id="cpCur" placeholder="Enter current password" autocomplete="current-password"></div>
      <div class="fld" style="margin-top:10px"><label>New password</label><input type="password" id="cpNew" placeholder="At least ${MIN_PASSWORD_LENGTH} characters" autocomplete="new-password"></div>
      <div class="fld" style="margin-top:10px"><label>Confirm new password</label><input type="password" id="cpNew2" placeholder="Repeat new password" autocomplete="new-password"></div>
      <div class="err" id="cpErr" style="display:none"></div>
      <p class="small muted" style="margin-top:10px">The vault is re-encrypted with the new password (AES-GCM, PBKDF2 600,000 rounds). Encrypted backups you exported earlier still open with the OLD password. Passkey unlock wraps a copy of your password, so a password change turns it off — re-enable it afterwards.</p>
      <div style="height:12px"></div><button class="ctaWide" id="cpGo">Change password</button></div>`);
    ($('#cpGo') as HTMLElement).onclick = async () => {
      const er = $('#cpErr'); const fail = (t: string) => { if (er) { er.style.display = 'block'; er.textContent = t; } };
      const cur = ($('#cpCur') as HTMLInputElement).value;
      const nw = ($('#cpNew') as HTMLInputElement).value;
      const nw2 = ($('#cpNew2') as HTMLInputElement).value;
      if (nw.length < MIN_PASSWORD_LENGTH) return fail(`New password needs at least ${MIN_PASSWORD_LENGTH} characters.`);
      if (nw !== nw2) return fail('The new passwords do not match.');
      if (nw === cur) return fail('The new password is the same as the current one.');
      if (!vaultPayload || !appPassword) return fail('Wallet is locked.');
      const btn = $('#cpGo') as HTMLButtonElement; btn.disabled = true;
      let stage = 'verify';
      try {
        const raw = localStorage.getItem(VAULT_KEY); if (!raw) throw new Error('No vault on this device.');
        await decryptVault(JSON.parse(raw), cur);
        stage = 'save';
        const blob = await encryptVault(packVaultPayload(vaultPayload), nw);
        try { localStorage.setItem(VAULT_KEY, JSON.stringify(blob)); }
        catch { vaultSaveAlert(); throw new Error('storage'); }
        appPassword = nw;
        const hadPasskey = !!config.passkey;
        if (hadPasskey) { config.passkey = null; saveConfig(); }
        close();
        showSettings('', 'Password changed. Your vault now opens with the new password.' + (hadPasskey ? ' Passkey unlock was turned off (it wrapped the old password) — re-enable it in Security.' : ''));
      } catch { fail(stage === 'save' ? 'Could not save the re-encrypted vault — storage is full or blocked. Your password was NOT changed.' : 'Current password is incorrect — nothing was changed.'); btn.disabled = false; }
    };
  };
}


// ---------- Addition 9: private keys & recovery phrase ----------
// The most sensitive surface in the app. Rules enforced here:
//  - The VALUE shown is derived from a FRESH decryption of the vault
//    with a password the user re-enters on this screen (passkey unlock
//    never substitutes), throttled like unlock.
//  - A plain-words warning + explicit "I understand" comes first.
//  - The secret renders blurred behind a tap; it is wiped from the DOM
//    after 45s, instantly on tab hide, and on any navigation (setView
//    and lock() both run cleanupKeyGate). Nothing in the flow makes a
//    network call, writes storage, or logs anything.
interface KeyTarget { id: string; label: string; sub: string; address: string; value: string }
type KeyTargetMeta = Omit<KeyTarget, 'value'>;
// Audit L-1 (2026-11-19): the revealed secret lives in ONE module-level
// holder so cleanup can actually clear it — it used to sit in a submit()
// closure that survived the DOM wipe. Cleared by cleanupKeyGate().
let keyGateSecret = '';
let keysWalletId = '';
let keysAcct = 0;
let keyGateCleanup: (() => void) | null = null;
function cleanupKeyGate() { keyGateSecret = ''; if (keyGateCleanup) { const f = keyGateCleanup; keyGateCleanup = null; try { f(); } catch { /* already gone */ } } }

// EVM key targets carry per-network ids ('evm-<chainId>' /
// 'pk-evm-<chainId>') so the Settings list can show one row per
// enabled EVM network — all of them resolve to the SAME key, which
// every row states in its subtitle.
const isEvmKeyId = (id: string) => id === 'evm' || id === 'pk-evm' || id.startsWith('evm-') || id.startsWith('pk-evm-');
// Enabled EVM networks in the wallet's enabled order (the stored
// enabled list first, registry order for anything it omits).
function enabledEvmChains(): Chain[] {
  const en = enabledSet();
  const byId = new Map(CHAINS.filter(c => c.kind === 'evm' && en.has(c.id)).map(c => [c.id, c]));
  const out: Chain[] = [];
  for (const id of config.enabled ?? DEFAULT_ENABLED) { const ch = byId.get(id); if (ch) { out.push(ch); byId.delete(id); } }
  for (const ch of byId.values()) out.push(ch);
  return out;
}
function evmKeyMetaRows(prefix: string, address: string): KeyTargetMeta[] {
  const chains = enabledEvmChains();
  if (!chains.length) return [{ id: prefix, label: 'Ethereum & all EVM networks', sub: 'Private key · 0x hex', address }];
  return chains.map(ch => ({ id: `${prefix}-${ch.id}`, label: ch.name, sub: 'Private key · 0x hex · shared EVM key', address }));
}
function findKeyTargetMeta(list: KeyTargetMeta[], id: string): KeyTargetMeta | undefined {
  return list.find(t => t.id === id) || (isEvmKeyId(id) ? list.find(t => isEvmKeyId(t.id)) : undefined);
}

// Audit L-1: pre-password surfaces (the keys list, the gate's own
// header) work from METADATA ONLY — labels and addresses. The export
// string for a target is computed by keyValueFor AFTER the fresh
// password check, for that ONE target, never for every chain at once.
function keyTargetMetasFor(w: WalletEntry, acct: number): KeyTargetMeta[] {
  if (w.kind === 'privateKey') {
    if (w.chain === 'solana') {
      const raw = bs58.decode(w.secret);
      const kp = raw.length === 64 ? Keypair.fromSecretKey(raw) : Keypair.fromSeed(raw.slice(0, 32));
      return [{ id: 'pk-solana', label: 'Solana', sub: 'Private key · base58 (Phantom format)', address: kp.publicKey.toBase58() }];
    }
    const pk = w.secret.startsWith('0x') ? w.secret : '0x' + w.secret;
    return evmKeyMetaRows('pk-evm', new ethers.Wallet(pk).address);
  }
  const d = deriveAll2(w.secret, acct);
  const words = w.secret.trim().split(/\s+/).length;
  return [
    { id: 'phrase', label: 'Recovery phrase', sub: `${words} words · controls every chain in this wallet`, address: '' },
    ...evmKeyMetaRows('evm', d.evmAddress),
    { id: 'solana', label: 'Solana', sub: 'Private key · base58 (Phantom format)', address: d.solAddress },
    { id: 'solana-tw', label: 'Solana · Trust Wallet path', sub: 'Private key · base58 (Phantom format)', address: d.solTWAddress },
    { id: 'solana-phantom', label: 'Solana · Phantom path', sub: 'Private key · base58 (Phantom format)', address: d.solPhantomAddress },
    { id: 'bitcoin', label: 'Bitcoin', sub: 'Private key · WIF', address: d.btcAddress },
    { id: 'litecoin', label: 'Litecoin', sub: 'Private key · WIF', address: d.ltcAddress },
    { id: 'tron', label: 'TRON', sub: 'Private key · hex', address: d.tronAddress },
    { id: 'xrp', label: 'XRP', sub: 'Private key · hex', address: d.xrpAddress },
    { id: 'cosmos', label: 'Cosmos Hub', sub: 'Private key · hex', address: d.cosmosAddress },
    { id: 'sui', label: 'Sui', sub: 'Private key · suiprivkey (bech32)', address: d.suiAddress },
    { id: 'aptos', label: 'Aptos', sub: 'Private key · AIP-80', address: d.aptosAddress },
  ];
}
function keyValueFor(w: WalletEntry, acct: number, targetId: string): string | null {
  if (w.kind === 'privateKey') {
    if (w.chain === 'solana') {
      if (targetId !== 'pk-solana') return null;
      const raw = bs58.decode(w.secret);
      const kp = raw.length === 64 ? Keypair.fromSecretKey(raw) : Keypair.fromSeed(raw.slice(0, 32));
      return bs58.encode(kp.secretKey);
    }
    return isEvmKeyId(targetId) ? (w.secret.startsWith('0x') ? w.secret : '0x' + w.secret) : null;
  }
  if (targetId === 'phrase') return w.secret;
  const d = deriveAll2(w.secret, acct);
  if (isEvmKeyId(targetId)) return d.evmPrivateKey;
  switch (targetId) {
    case 'solana': return solanaSecretKeyBase58(d.solSeed32);
    case 'solana-tw': return solanaSecretKeyBase58(d.solTWSeed32);
    case 'solana-phantom': return solanaSecretKeyBase58(d.solPhantomSeed32);
    case 'bitcoin': return btcWifFromPrivateKey(base16.decode(d.btcPrivateKeyHex));
    case 'litecoin': return utxoWifFromPrivateKey(base16.decode(d.ltcPrivateKeyHex), 0xb0);
    case 'tron': return d.tronPrivateKeyHex;
    case 'xrp': return d.xrpPrivateKeyHex;
    case 'cosmos': return d.cosmosPrivateKeyHex;
    case 'sui': return suiPrivateKeyBech32(d.suiSeed32);
    case 'aptos': return aptosPrivateKeyExport(d.aptosSeed32);
    default: return null;
  }
}

let keysInit = false;
function showKeys() {
  if (!vaultPayload) return;
  const wallets = vaultPayload.wallets;
  if (!keysInit) { keysInit = true; keysWalletId = vaultPayload.activeId; keysAcct = config.accountIndex[keysWalletId] || 0; }
  if (!wallets.some(w => w.id === keysWalletId)) keysWalletId = vaultPayload.activeId;
  const w = wallets.find(x => x.id === keysWalletId) || wallets[0];
  keysAcct = Math.max(0, Math.min(keysAcct, Math.max(0, w.accounts - 1)));
  const targets = keyTargetMetasFor(w, keysAcct);
  const phrase = targets.find(t => t.id === 'phrase');
  const keys = targets.filter(t => t.id !== 'phrase');
  const ico = (n: string) => `<span class="sIco"><i class="ri-${n}"></i></span>`;
  const chev = '<i class="ri-arrow-right-s-line sChev"></i>';
  const rowFor = (t: KeyTargetMeta) => `<button class="sRow" data-key="${t.id}" type="button">${ico('key-2-line')}<span class="sTx"><span class="sLbl">${esc(t.label)}</span><div class="sSub">${esc(t.sub)}</div></span>${t.address ? `<span class="sVal mono">${esc(t.address.slice(0, 8))}…${esc(t.address.slice(-6))}</span>` : ''}${chev}</button>`;
  setView(`<main><button class="backBtn" id="bk" aria-label="Back"><i class="ri-arrow-left-s-line"></i></button><div class="largeTitle" style="padding-top:2px">Private keys &amp;<br>recovery phrase</div>
  <div style="padding:0 16px"><p class="small muted" style="line-height:1.55">Export the keys for one wallet at a time. Every reveal asks for your wallet password again, shows a warning first, and hides itself automatically. Keys are derived on this device only — nothing is sent or stored anywhere new.</p></div><div style="height:8px"></div>
  ${wallets.length > 1 ? `<div class="gGroup"><div class="gHead">Wallet</div><div class="gCard">${wallets.map(x => `<button class="sRow" data-wallet="${x.id}" type="button">${ico('wallet-3-line')}<span class="sTx"><span class="sLbl">${esc(x.name)}</span><div class="sSub">${x.kind === 'mnemonic' ? 'Recovery phrase wallet' : 'Imported private key'}</div></span>${x.id === w.id ? '<i class="ri-check-line curCheck"></i>' : ''}</button>`).join('')}</div></div>` : ''}
  ${w.kind === 'mnemonic' && w.accounts > 1 ? `<div class="gGroup"><div class="gHead">Account</div><div class="gCard"><div class="sBlock"><div class="seg" id="keysAcctSeg">${Array.from({ length: w.accounts }, (_, i) => `<button data-a="${i}" class="${i === keysAcct ? 'on' : ''}">Account ${i + 1}</button>`).join('')}</div></div></div><div class="gFoot">Keys below belong to the selected account — the address on each row is that account's address on the chain.</div></div>` : ''}
  <div class="gGroup"><div class="gHead">Recovery phrase</div><div class="gCard">
    ${phrase ? rowFor(phrase) : `<div class="sRow">${ico('file-list-3-line')}<span class="sTx"><span class="sLbl">No recovery phrase</span><div class="sSub">Imported with a private key — this wallet has no recovery phrase. Its key is listed below.</div></span></div>`}
  </div></div>
  <div class="gGroup"><div class="gHead">Private keys · Account ${keysAcct + 1}</div><div class="gCard">
    ${keys.map(rowFor).join('')}
  </div><div class="gFoot">The EVM key is the <b>same key on every EVM network</b> — Ethereum, Polygon, BNB Chain and all the rest. Whoever holds it controls this account on all of them.</div></div>
  </main>`);
  ($('#bk') as HTMLElement).onclick = () => goBack({ route: 'settings' });
  V().querySelectorAll('[data-wallet]').forEach(b => (b as HTMLElement).onclick = () => { keysWalletId = (b as HTMLElement).dataset.wallet!; keysAcct = config.accountIndex[keysWalletId] || 0; showKeys(); });
  const seg = $('#keysAcctSeg'); if (seg) seg.querySelectorAll('[data-a]').forEach(b => (b as HTMLElement).onclick = () => { keysAcct = Number((b as HTMLElement).dataset.a); showKeys(); });
  V().querySelectorAll('[data-key]').forEach(b => (b as HTMLElement).onclick = () => showKeyGate(w.id, keysAcct, (b as HTMLElement).dataset.key!));
}

function showKeyGate(walletId: string, acct: number, targetId: string, err = '', opts: { back?: () => void; title?: string } = {}) {
  // One reveal flow, several doors: Settings passes nothing (back =
  // the keys list, title = the target's own label); a coin/token
  // detail screen passes its chain title and a back that re-renders
  // that detail. The gating itself is identical either way.
  const backFn = opts.back || (() => showKeys());
  const wMem = vaultPayload?.wallets.find(x => x.id === walletId);
  if (!wMem) { backFn(); return; }
  const tMem = findKeyTargetMeta(keyTargetMetasFor(wMem, acct), targetId);
  if (!tMem) { backFn(); return; }
  const title = opts.title || tMem.label;
  const isPhrase = targetId === 'phrase';
  const thing = isPhrase ? 'recovery phrase' : 'private key';
  setView(`<main><button class="backBtn" id="bk" aria-label="Back"><i class="ri-arrow-left-s-line"></i></button><div class="largeTitle" style="padding-top:2px">${esc(title)}</div>
  <div style="padding:0 16px">${tMem.address ? `<p class="small muted" style="line-height:1.55">For account address <span class="mono">${esc(tMem.address)}</span></p><div style="height:10px"></div>` : ''}${err ? `<div class="err">${esc(err)}</div><div style="height:10px"></div>` : ''}
  <div class="gCard" style="padding:16px"><div class="fld"><label>Wallet password</label><input type="password" id="kgPw" placeholder="Enter password" autocomplete="current-password"></div>
  <p class="small muted" style="line-height:1.55;margin:10px 0 14px">Re-enter your app password to continue. A passkey can't be used for this — password only.</p>
  <button class="ctaWide" id="kgGo" type="button">Continue</button></div></div></main>`);
  ($('#bk') as HTMLElement).onclick = () => backFn();
  const submit = async () => {
    // Audit M-3: the reveal throttle is the persisted, escalating one
    // (localStorage, up to 15 min) — not the old sessionStorage counter
    // a new tab could reset.
    const waitLeft = authWaitRemaining('reveal');
    if (waitLeft > 0) { showKeyGate(walletId, acct, targetId, `Too many failed attempts — wait ${Math.ceil(waitLeft / 1000)}s and try again.`, opts); return; }
    const pw = ($('#kgPw') as unknown as HTMLInputElement).value;
    const btn = $('#kgGo') as HTMLButtonElement; btnBusy(btn);
    try {
      const plain = await decryptVault(getVault()!, pw);
      const parsed = parseVaultPlaintext(plain, getMeta());
      const w = parsed.payload.wallets.find(x => x.id === walletId);
      if (!w) throw new Error('wallet missing');
      const v = keyValueFor(w, acct, targetId);
      if (v == null) throw new Error('target missing');
      keyGateSecret = v;
    } catch {
      noteAuthFailure('reveal');
      showKeyGate(walletId, acct, targetId, 'Wrong password — nothing was revealed.', opts);
      return;
    }
    clearAuthFailures('reveal');
    // Step 2 — the warning, before any secret exists on screen.
    setView(`<main><button class="backBtn" id="bk" aria-label="Back"><i class="ri-arrow-left-s-line"></i></button><div class="largeTitle" style="padding-top:2px">Before you continue</div>
    <div style="padding:0 16px"><div class="warn" style="font-size:13.5px;line-height:1.6">Anyone who has this ${thing} can take the funds it controls — no password, no warning, no undo.<br><br>Syn will <b>never</b> ask for it. Never share it, never type or paste it into a website, and make sure nobody can see your screen.${isEvmKeyId(targetId) ? '<br><br>This key controls this account on <b>all EVM networks</b> — Ethereum, Polygon, BNB Chain and every other EVM network share it.' : ''}${isPhrase ? '<br><br>This phrase controls <b>every chain</b> in this wallet.' : ''}</div>
    <button class="ctaWide" id="kgUnderstand" type="button">I understand</button>
    <div style="height:10px"></div><button class="btnGhost" id="kgCancel" type="button">Cancel</button></div></main>`);
    ($('#bk') as HTMLElement).onclick = () => backFn();
    ($('#kgCancel') as HTMLElement).onclick = () => backFn();
    ($('#kgUnderstand') as HTMLElement).onclick = () => {
      // Step 3 — the reveal: blurred until tapped, wiped at 45s,
      // wiped instantly when the tab hides.
      setView(`<main><button class="backBtn" id="bk" aria-label="Back"><i class="ri-arrow-left-s-line"></i></button><div class="largeTitle" style="padding-top:2px">${esc(title)}</div>
      <div style="padding:0 16px">${tMem.address ? `<p class="small muted" style="line-height:1.55">Account <span class="mono">${esc(tMem.address)}</span></p><div style="height:10px"></div>` : ''}
      <div class="gCard" style="padding:16px"><div class="fld"><label>${isPhrase ? 'Recovery phrase' : 'Private key'} · ${esc(tMem.sub.split('·')[1]?.trim() || '')}</label>
      <div class="keyBox" id="keyBox" style="filter:blur(8px)">${esc(keyGateSecret)}</div>
      <p class="small muted" id="keyHint" style="text-align:center;margin-top:10px">Tap the ${isPhrase ? 'phrase' : 'key'} to reveal it</p></div>
      <div style="height:12px"></div><button class="btnGhost" id="kgCopy" type="button"><i class="ri-file-copy-line"></i> Copy ${isPhrase ? 'phrase' : 'key'} (clipboard clears in 20s)</button>
      <p class="small muted" id="kgCopyNote" style="text-align:center;margin-top:8px"></p></div></div></main>`);
      ($('#bk') as HTMLElement).onclick = () => backFn();
      const box = $('#keyBox');
      let shown = false;
      box.onclick = () => { shown = !shown; box.style.filter = shown ? 'none' : 'blur(8px)'; const h = $('#keyHint'); if (h) h.textContent = shown ? `Tap again to hide · hides itself in 45s` : `Tap the ${isPhrase ? 'phrase' : 'key'} to reveal it`; };
      ($('#kgCopy') as HTMLElement).onclick = (e) => { void copySecret(keyGateSecret, e.currentTarget as HTMLElement, () => { const n2 = $('#kgCopyNote'); if (n2) n2.textContent = 'Copied — but the clipboard could not be cleared automatically. Clear it manually.'; }); const n = $('#kgCopyNote'); if (n) n.textContent = 'Copied — clipboard clears in 20s'; };
      const wipe = () => {
        cleanupKeyGate();
        setView(`<main><button class="backBtn" id="bk" aria-label="Back"><i class="ri-arrow-left-s-line"></i></button><div class="largeTitle" style="padding-top:2px">Hidden again</div>
        <div style="padding:0 16px"><p class="small muted" style="line-height:1.55">The ${thing} was removed from the screen for safety. Go back and repeat the steps if you need it again.</p></div></main>`);
        ($('#bk') as HTMLElement).onclick = () => backFn();
      };
      const onVis = () => { if (document.hidden) wipe(); };
      document.addEventListener('visibilitychange', onVis);
      const timer = setTimeout(wipe, 45000);
      keyGateCleanup = () => { document.removeEventListener('visibilitychange', onVis); clearTimeout(timer); };
    };
  };
  ($('#kgGo') as HTMLButtonElement).onclick = submit;
  ($('#kgPw') as unknown as HTMLInputElement).addEventListener('keydown', e => { if ((e as KeyboardEvent).key === 'Enter') void submit(); });
}

// Which key target a coin/token detail screen reveals, titled for
// the chain the user is standing on. Returns null when the active
// wallet honestly has no exportable key for that chain (e.g. a
// Solana-only private-key import viewing an EVM detail) — the
// detail screen then shows no key row at all, never a dead one.
function keyTargetForChain(c: Chain): { id: string; title: string } | null {
  const w = activeWallet(); if (!w) return null;
  if (w.kind === 'privateKey') {
    if (w.chain === 'solana') return (c.kind === 'solana' || c.kind === 'solana-tw') ? { id: 'pk-solana', title: 'Solana private key' } : null;
    return c.kind === 'evm' ? { id: 'pk-evm-' + c.id, title: `${c.name} — EVM private key` } : null;
  }
  switch (c.kind) {
    case 'evm': return { id: 'evm-' + c.id, title: `${c.name} — EVM private key` };
    case 'solana': return { id: 'solana', title: 'Solana private key' };
    case 'solana-tw': return { id: 'solana-tw', title: 'Solana (Trust Wallet) private key' };
    case 'solana-phantom': return { id: 'solana-phantom', title: 'Solana (Phantom) private key' };
    case 'bitcoin': return c.id === 'litecoin' ? { id: 'litecoin', title: 'Litecoin private key' } : { id: 'bitcoin', title: 'Bitcoin private key' };
    case 'tron': return { id: 'tron', title: 'TRON private key' };
    case 'xrp': return { id: 'xrp', title: 'XRP private key' };
    case 'cosmos': return { id: 'cosmos', title: 'Cosmos Hub private key' };
    case 'sui': return { id: 'sui', title: 'Sui private key' };
    case 'aptos': return { id: 'aptos', title: 'Aptos private key' };
  }
}
// Opens the (single, shared) Addition-9 reveal flow pre-selected to
// this chain + the account the detail screens are showing, with the
// gate's Back returning to that same detail screen.
function openChainKey(c: Chain, back: () => void) {
  const w = activeWallet(); const kt = keyTargetForChain(c);
  if (!w || !kt) return;
  showKeyGate(w.id, accountIdx(), kt.id, '', { back, title: kt.title });
}
const keyRowHTML = (id: string) => `<button class="sRow" id="${id}"><span class="sIco"><i class="ri-key-line"></i></span><span class="sTx"><span class="sLbl">Show <b>private key</b></span></span><span class="sChev"><i class="ri-arrow-right-s-line"></i></span></button>`;

// ---------- Wave 1A screens: networks, accounts, tokens, backup, passkey ----------
let netQuery = '';
function netRowHTML(c: Chain, en: Set<string>): string {
  return `<div class="setRow"><span class="optLeft">${coinIcon(c)}<span><span class="setLabel">${esc(c.name)}</span><div class="setDesc">${esc(c.symbol)}${c.evmId ? ' · Chain ' + c.evmId : ''}${c.custom ? ' · Custom network' : ''}</div></span></span><span style="display:inline-flex;gap:8px;align-items:center">${(c.kind === 'evm' || c.kind === 'solana') ? `<button class="pillBtn" data-rpc="${c.id}" type="button">RPC</button>` : ''}<button class="switch ${en.has(c.id) ? 'on' : ''}" data-tgl="${c.id}" role="switch" aria-checked="${en.has(c.id)}" aria-label="Toggle ${esc(c.name)}" type="button"><span></span></button></span></div>`;
}
function showNetworks(err = '') {
  const en = enabledSet();
  const q = netQuery.trim().toLowerCase();
  const all = CHAINS.filter(c => c.id !== 'solana-tw' && c.id !== 'solana-phantom');
  const filtered = all.filter(c => !q || c.name.toLowerCase().includes(q) || c.symbol.toLowerCase().includes(q) || String(c.evmId || '').includes(q));
  const enabledList = all.filter(c => en.has(c.id));
  setView(`<main><button class="backBtn" id="bk" aria-label="Back"><i class="ri-arrow-left-s-line"></i></button><div class="largeTitle" style="padding-top:2px">Networks</div>
  <div style="padding:0 16px"><p class="small muted" style="line-height:1.55">${CHAINS.filter(c => c.kind === 'evm').length} EVM networks in the registry — every RPC was verified live — plus Solana, Bitcoin, TRON, XRP, Cosmos, Sui and Aptos. Enabled networks appear on Home; balances for long-tail networks load only while they are enabled.</p><div style="height:12px"></div>${err ? `<div class="err">${esc(err)}</div><div style="height:10px"></div>` : ''}<div class="field"><div class="box"><input id="netSearch" placeholder="Search networks" value="${esc(netQuery)}" autocomplete="off" autocapitalize="none" spellcheck="false"></div></div></div>
  <div class="setPanel"><div class="setH">Enabled (${enabledList.length})</div>${enabledList.map(c => netRowHTML(c, en)).join('') || '<p class="small muted">None enabled.</p>'}</div>
  <div class="setPanel"><div class="setH">All networks</div><div id="netAll">${filtered.slice(0, 260).map(c => netRowHTML(c, en)).join('') || '<p class="small muted">No network matches that search.</p>'}</div></div>
  <div class="setPanel"><div class="setH">Add custom network</div><div class="setHSub">EVM networks only. The chain ID you enter is checked against the RPC's own answer before anything is saved.</div>
    <div id="cnErr"></div>
    <div class="field"><label>Network name</label><div class="box"><input id="cnName" placeholder="My Network" autocomplete="off"></div></div>
    <div class="field"><label>RPC URL (https)</label><div class="box"><input id="cnRpc" placeholder="https://…" autocomplete="off" autocapitalize="none" spellcheck="false"></div></div>
    <div class="field"><label>Chain ID</label><div class="box"><input id="cnChain" inputmode="numeric" placeholder="e.g. 1234" autocomplete="off"></div></div>
    <div class="field"><label>Currency symbol</label><div class="box"><input id="cnSym" placeholder="e.g. ETH" autocomplete="off" autocapitalize="none"></div></div>
    <div class="field"><label>Block explorer URL (optional)</label><div class="box"><input id="cnExp" placeholder="https://…" autocomplete="off" autocapitalize="none" spellcheck="false"></div></div>
    <button class="ctaWide" id="cnAdd" type="button">Verify &amp; add network</button>
  </div></main>`);
  ($('#bk') as HTMLElement).onclick = () => goBack({ route: 'wallet' });
  const bindRows = () => {
    V().querySelectorAll('[data-tgl]').forEach(b => (b as HTMLElement).onclick = () => {
      const id = (b as HTMLElement).dataset.tgl!; const set = enabledSet();
      if (set.has(id)) set.delete(id); else set.add(id);
      config.enabled = [...set]; saveConfig(); showNetworks(); refreshData(true);
    });
    V().querySelectorAll('[data-rpc]').forEach(b => (b as HTMLElement).onclick = () => go({ route: 'netedit', chainId: (b as HTMLElement).dataset.rpc! }, b as HTMLElement));
  };
  bindRows();
  const si = $('#netSearch') as unknown as HTMLInputElement;
  si.addEventListener('input', () => {
    netQuery = si.value; const q2 = netQuery.trim().toLowerCase(); const en2 = enabledSet();
    const f2 = all.filter(c => !q2 || c.name.toLowerCase().includes(q2) || c.symbol.toLowerCase().includes(q2) || String(c.evmId || '').includes(q2));
    const na = $('#netAll'); if (na) { na.innerHTML = f2.slice(0, 260).map(c => netRowHTML(c, en2)).join('') || '<p class="small muted">No network matches that search.</p>'; bindRows(); }
  });
  ($('#cnAdd') as HTMLButtonElement).onclick = async () => {
    const errBox = $('#cnErr'); const btn = $('#cnAdd') as HTMLButtonElement;
    const input = { name: ($('#cnName') as unknown as HTMLInputElement).value.trim(), rpc: ($('#cnRpc') as unknown as HTMLInputElement).value.trim(), chainId: Number(($('#cnChain') as unknown as HTMLInputElement).value), symbol: ($('#cnSym') as unknown as HTMLInputElement).value.trim(), explorer: ($('#cnExp') as unknown as HTMLInputElement).value.trim() };
    btnBusy(btn, 'Verifying with the RPC…');
    let rpcChainId: number | null = null;
    try { const r = await fetch(input.rpc, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_chainId', params: [] }) }); const j = await r.json(); rpcChainId = parseChainIdResult(j?.result); } catch { rpcChainId = null; }
    const err = validateCustomNetwork(input, rpcChainId);
    if (err) { if (errBox) errBox.innerHTML = `<div class="err" style="margin-bottom:10px">${esc(err)}</div>`; btn.disabled = false; btn.innerHTML = 'Verify &amp; add network'; return; }
    if (CHAINS.some(c => c.evmId === input.chainId)) { if (errBox) errBox.innerHTML = `<div class="err" style="margin-bottom:10px">Chain ${input.chainId} is already in the registry — enable it from the list instead.</div>`; btn.disabled = false; btn.innerHTML = 'Verify &amp; add network'; return; }
    config.customNetworks.push({ id: 'custom-' + input.chainId + '-' + Math.random().toString(36).slice(2, 6), name: input.name, rpc: input.rpc, chainId: input.chainId, symbol: input.symbol.toUpperCase(), explorer: input.explorer.replace(/\/$/, '') });
    const set = enabledSet(); config.enabled = [...set]; const nid = config.customNetworks[config.customNetworks.length - 1].id; set.add(nid); config.enabled = [...set];
    saveConfig(); showNetworks(); refreshData(true);
  };
}
function showNetEdit(chainId: string) {
  const c = findChain(chainId); if (!c) { go({ route: 'networks' }); return; }
  const override = config.rpcOverrides[c.id] || '';
  const builtin = c.rpc || (c.proxy ? 'Syn relay (built-in endpoint)' : '');
  setView(`<main><button class="backBtn" id="bk" aria-label="Back"><i class="ri-arrow-left-s-line"></i></button><div class="largeTitle" style="padding-top:2px">RPC endpoint</div>
  <div style="padding:0 16px"><p class="small muted" style="line-height:1.55">${esc(c.name)} — balances and sends use this endpoint. A custom RPC is stored only on this device.${c.custom ? ' This is your custom network; its RPC is set from the network definition.' : ''}</p><div style="height:12px"></div><div id="neErr"></div>
  <div class="setRow" style="padding-left:0;padding-right:0"><span class="setLabel">Current endpoint</span><span class="sv" style="max-width:55%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(override || builtin)}</span></div>
  <div class="field"><label>Custom RPC URL (https)</label><div class="box"><input id="neRpc" value="${esc(override)}" placeholder="${esc(builtin)}" autocomplete="off" autocapitalize="none" spellcheck="false"></div></div>
  <p class="small muted" style="margin:0 4px 12px">${c.kind === 'evm' ? 'Saving verifies the endpoint answers with chain ID ' + c.evmId + '.' : 'Saving verifies the endpoint answers a Solana version request.'}</p>
  <button class="ctaWide" id="neSave" type="button">Verify &amp; save</button><div style="height:10px"></div>
  ${override ? '<button class="btnGhost" id="neReset" type="button" style="border-radius:999px">Reset to default</button>' : ''}</div></main>`);
  ($('#bk') as HTMLElement).onclick = () => goBack({ route: 'networks' });
  const rst = $('#neReset'); if (rst) rst.onclick = () => { delete config.rpcOverrides[c.id]; saveConfig(); showNetEdit(chainId); };
  ($('#neSave') as HTMLButtonElement).onclick = async () => {
    const url = ($('#neRpc') as unknown as HTMLInputElement).value.trim(); const errBox = $('#neErr'); const btn = $('#neSave') as HTMLButtonElement;
    const fail = (m: string) => { if (errBox) errBox.innerHTML = `<div class="err" style="margin-bottom:10px">${esc(m)}</div>`; btn.disabled = false; btn.innerHTML = 'Verify &amp; save'; };
    if (!url) { delete config.rpcOverrides[c.id]; saveConfig(); showNetworks(); return; }
    if (!/^https:\/\//i.test(url)) return fail('RPC URL must start with https://');
    btnBusy(btn, 'Verifying…');
    try {
      if (c.kind === 'evm') {
        const r = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_chainId', params: [] }) });
        const j = await r.json(); const got = parseChainIdResult(j?.result);
        if (got !== c.evmId) return fail(`That endpoint reports chain ${got ?? '—'}, not ${c.evmId} (${c.name}). Not saved.`);
      } else {
        const r = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'getVersion', params: [] }) });
        const j = await r.json(); if (!j?.result) return fail('That endpoint did not answer as a Solana RPC. Not saved.');
      }
    } catch { return fail('Could not reach that endpoint. Not saved.'); }
    config.rpcOverrides[c.id] = url; saveConfig(); showNetworks();
  };
}

// ---------- accounts ----------
function walletPreview(w: WalletEntry, idx: number): string {
  try {
    if (w.kind === 'privateKey') {
      if (w.chain === 'solana') { const raw = bs58.decode(w.secret.replace(/^0x/, '')); const kp = raw.length === 64 ? Keypair.fromSecretKey(raw) : Keypair.fromSeed(raw.slice(0, 32)); return kp.publicKey.toBase58(); }
      return new ethers.Wallet(w.secret.startsWith('0x') ? w.secret : '0x' + w.secret).address;
    }
    const d = deriveAll2(w.secret, idx); return d.evmAddress;
  } catch { return ''; }
}
let accountsOpenId: string | null = null;
function showAccounts() {
  const pw = vaultPayload; if (!pw) return;
  const openId = accountsOpenId && pw.wallets.some(w => w.id === accountsOpenId) ? accountsOpenId : pw.activeId;
  const panels = pw.wallets.map(w => {
    const isActive = w.id === pw.activeId;
    const open = w.id === openId;
    const curIdx = isActive ? accountIdx() : (config.accountIndex[w.id] || 0);
    const count = w.kind === 'mnemonic' ? w.accounts : 1;
    const rowFor = (i: number, label: string, sub: string, icon: string) => {
      const on = isActive && i === curIdx;
      return `<button class="sRow" data-sw="${w.id}:${i}" type="button"><i class="${icon} acctIco"></i><span class="sTx"><span class="sLbl">${on ? '<b>' + label + '</b>' : label}</span><div class="sSub">${sub}</div></span>${on ? '<span class="sChev on"><i class="ri-check-line"></i></span>' : '<span class="sChev"><i class="ri-arrow-right-s-line"></i></span>'}</button>`;
    };
    const acctRows = w.kind === 'mnemonic'
      ? Array.from({ length: w.accounts }, (_, i) => rowFor(i, 'Account ' + (i + 1), esc(shortAddr(walletPreview(w, i))) + ' · EVM address', 'ri-user-3-line')).join('')
      : rowFor(0, 'Imported account', esc(walletPreview(w, 0).slice(0, 10)) + '…', 'ri-key-2-line');
    return `<section class="walletAcc${open ? ' open' : ''}"><button class="accHead" data-whead="${w.id}" type="button"><span class="accName">${esc(w.name)}</span><span class="accCount">${count} account${count === 1 ? '' : 's'}</span><span class="accChev"><i class="ri-arrow-down-s-line"></i></span><span class="accMeta">${w.kind === 'mnemonic' ? 'Recovery-phrase wallet' : 'Private-key import'} · added ${new Date(w.createdAt).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })}${isActive ? ' · <b>Active</b>' : ''}</span></button><div class="wBody"><div class="wBodyIn"><div class="scrollWrap"><div class="gCard bareHair acctScroll">${acctRows}${isActive && w.kind === 'mnemonic' ? '<button class="sRow addRow" id="addAcct" type="button"><i class="ri-add-line acctIco"></i><span class="sTx"><span class="sLbl">Add account</span></span></button>' : ''}</div><span class="fade"></span></div></div></div></section>`;
  }).join('');
  setView(`<main><button class="backBtn" id="bk" aria-label="Back"><i class="ri-arrow-left-s-line"></i></button><div class="largeTitle" style="padding-top:2px">Wallets &amp; accounts</div>
  <div style="padding:0 16px"><p class="small muted" style="line-height:1.55">One app password protects every wallet in this vault. Each wallet keeps its own encrypted recovery phrase or key, stored only on this device.</p></div>
  ${panels}
  <section class="walletAcc"><div class="accHead static"><span class="accName">Add a wallet</span></div><div class="gCard bareHair">
    <button class="sRow" id="awCreate" type="button"><i class="ri-add-circle-line acctIco"></i><span class="sTx"><span class="sLbl"><b>Create new wallet</b></span><div class="sSub">Fresh recovery phrase</div></span><span class="sChev"><i class="ri-arrow-right-s-line"></i></span></button>
    <button class="sRow" id="awSeed" type="button"><i class="ri-file-list-3-line acctIco"></i><span class="sTx"><span class="sLbl">Import <b>seed phrase</b></span><div class="sSub">12 or 24 words</div></span><span class="sChev"><i class="ri-arrow-right-s-line"></i></span></button>
    <button class="sRow" id="awKey" type="button"><i class="ri-key-2-line acctIco"></i><span class="sTx"><span class="sLbl">Import <b>private key</b></span><div class="sSub">Solana or Ethereum wallet</div></span><span class="sChev"><i class="ri-arrow-right-s-line"></i></span></button>
  </div></section><div style="height:24px"></div></main>`);
  ($('#bk') as HTMLElement).onclick = () => goBack({ route: 'wallet' });
  V().querySelectorAll('[data-whead]').forEach(b => (b as HTMLElement).onclick = () => { accountsOpenId = (b as HTMLElement).dataset.whead || null; showAccounts(); });
  V().querySelectorAll('[data-sw]').forEach(b => (b as HTMLElement).onclick = () => { const [wid, idx] = ((b as HTMLElement).dataset.sw || '').split(':'); if (wid) switchWallet(wid, Number(idx || 0)); });
  const sc = V().querySelector('.walletAcc.open .acctScroll') as HTMLElement | null;
  if (sc) { const wrap = sc.parentElement; const paint = () => { if (!wrap) return; const more = sc.scrollHeight > sc.clientHeight + 2; wrap.classList.toggle('more', more); wrap.classList.toggle('atEnd', !more || sc.scrollTop + sc.clientHeight >= sc.scrollHeight - 2); }; sc.addEventListener('scroll', paint, { passive: true }); requestAnimationFrame(paint); }
  const aa = $('#addAcct'); if (aa) aa.onclick = async () => { const w = activeWallet(); if (!w) return; w.accounts += 1; config.accountIndex[w.id] = w.accounts - 1; saveConfig(); await persistPayload(); applyActiveWallet(); clearAccountCaches(); showAccounts(); const sc2 = V().querySelector('.walletAcc.open .acctScroll') as HTMLElement | null; if (sc2) sc2.scrollTop = sc2.scrollHeight; refreshData(true); };
  ($('#awCreate') as HTMLElement).onclick = () => { enterAddFlow(); showCreate(); };
  ($('#awSeed') as HTMLElement).onclick = () => { enterAddFlow(); showImportSeed(); };
  ($('#awKey') as HTMLElement).onclick = () => { enterAddFlow(); showImportKey(); };
}
function switchWallet(wid: string, idx: number) {
  if (!vaultPayload) return;
  vaultPayload.activeId = wid; config.accountIndex[wid] = idx; saveConfig();
  void persistPayload();
  applyActiveWallet(); clearAccountCaches(); goTab('wallet');
}

// ---------- tokens ----------
function findToken(id: string): TokenDef | undefined { return [...BUILTIN_TOKENS, ...config.tokens].find(t => t.id === id); }
function showToken(tokenId: string) {
  const t = findToken(tokenId); if (!t) { goTab('wallet'); return; }
  currentTokenId = tokenId;
  if (tokenFocusChain && tokenFocusChain !== tokenId) tokenFocusChain = null;
  const grp = groupOf(t);
  if (grp.asset != null && grp.members.length > 1 && tokenFocusChain !== tokenId) { showTokenAggregated(t, grp); return; }
  const c = findChain(t.chainId); if (!c) { goTab('wallet'); return; }
  const addr = addressFor(c);
  setView(`<main><button class="backBtn" id="bk" aria-label="Back"><i class="ri-arrow-left-s-line"></i></button>
  <div class="dHead">
    <div class="dIdRow">${tokenIcon(t, true)}<div class="dIdTx"><div class="dName">${esc(t.name)}</div><div class="dSym">${esc(t.symbol)} · ${esc(c.name)}</div></div><span class="liveDot">LIVE</span></div>
    <div class="dBalBlock"><div class="dEyebrow">YOUR BALANCE</div><div class="dBalHero" id="tkBal">…</div><div class="dBalUsd" id="tkUsd"></div></div>
    <div class="dPriceBlock"><div class="dEyebrow" id="tkEyebrow">PRICE</div><div class="dPriceRow"><span class="dPriceVal" id="tkPriceVal">…</span><span id="tkPriceChg"></span></div></div>
  </div>
  ${t.cg ? `<div class="dChart"><div id="priceChart" class="pchartHost"><div class="chartEmpty">${waveLoadHTML()} Loading live chart…</div></div></div><div class="chartCap" id="chartCaption"></div>` : ''}
  ${orbPair('send', () => go({ route: 'receive', chainId: c.id }), () => showTokenSend(t.id))}
  <div class="gGroup"><div class="gHead">Actions</div><div class="gCard">
    <button class="sRow" id="tkSwap"><span class="sIco"><i class="ri-swap-line"></i></span><span class="sTx"><span class="sLbl">Swap <b>${esc(t.symbol)}</b></span></span><span class="sChev"><i class="ri-arrow-right-s-line"></i></span></button>
    ${keyTargetForChain(c) ? keyRowHTML('tkKey') : ''}
  </div></div>
  ${t.cg ? `<div class="gGroup"><div class="gHead">Stats</div><div class="gCard flushHair">
    <div class="sRow stat"><span class="sTx"><span class="sLbl">Price</span></span><span class="sVal strong" id="tkStPrice">…</span></div>
    <div class="sRow stat"><span class="sTx"><span class="sLbl">24h change</span></span><span class="sVal strong" id="tkStChg">…</span></div>
    <div class="sRow stat"><span class="sTx"><span class="sLbl">24h high</span></span><span class="sVal strong" id="tkStHigh">…</span></div>
    <div class="sRow stat"><span class="sTx"><span class="sLbl">24h low</span></span><span class="sVal strong" id="tkStLow">…</span></div>
    <div class="rangeWrap" id="tkRange" style="display:none"><div class="rangeTrack"><div class="rangeDot" id="tkRangeDot"></div></div><div class="rangeEnds"><span id="tkRangeLow"></span><span class="rangeMid">24h range</span><span id="tkRangeHigh"></span></div></div>
    <div class="sRow stat"><span class="sTx"><span class="sLbl">Market cap</span></span><span class="sVal strong"><span id="tkStMcap">…</span><span class="delta" id="tkMcapChg"></span></span></div>
    <div class="sRow stat"><span class="sTx"><span class="sLbl">Market data</span></span><button class="monoChip" id="cgBtn">CoinGecko <i class="ri-arrow-right-up-line"></i></button></div>
  </div></div>` : ''}
  <div class="gGroup"><div class="gHead">Token details</div><div class="gCard flushHair">
    <div class="sRow stat"><span class="sTx"><span class="sLbl">Network</span></span><span class="sVal strong">${esc(c.name)}</span></div>
    <div class="sRow stat"><span class="sTx"><span class="sLbl">${c.kind === 'solana' || c.kind === 'solana-tw' || c.kind === 'solana-phantom' ? 'Mint address' : 'Contract'}</span><div class="sSub">Tap the chip to copy</div></span><button class="monoChip" id="tkContract">${esc(shortAddr(t.contract))}</button></div>
    <div class="sRow stat"><span class="sTx"><span class="sLbl">Decimals</span></span><span class="sVal strong">${t.decimals}</span></div>
    <div class="sRow stat"><span class="sTx"><span class="sLbl">Your ${esc(c.name)} address</span><div class="sSub">Tap the chip to copy</div></span><button class="monoChip" id="tkAddr">${esc(shortAddr(addr))}</button></div>
    <div class="sRow stat"><span class="sTx"><span class="sLbl">${t.builtin ? 'Hide token' : 'Remove token'}</span><div class="sSub">${t.builtin ? 'Built-in token — it can be hidden, not deleted' : 'Removes this custom token from this device'}</div></span><button class="pillBtn danger" id="tkRemove">${t.builtin ? 'Hide' : 'Remove'}</button></div>
  </div></div>
  <div class="gGroup"><div class="gHead">Security check</div><div class="gCard"><div class="gPad" id="tkRiskSlot"><p class="small muted">Checking…</p></div></div><div class="gFoot">Token risk data from the GoPlus free API, read live for this contract.</div></div></main>`);
  paintTokenRisk(t, c);
  bindOrb((el) => go({ route: 'receive', chainId: c.id }, el), () => showTokenSend(t.id));
  const tkSw = $('#tkSwap'); if (tkSw) tkSw.onclick = () => { presetSwapFrom(c.id, t.id); go({ route: 'swap' }, tkSw); };
  const tkK = $('#tkKey'); if (tkK) tkK.onclick = () => openChainKey(c, () => showToken(t.id));
  ($('#bk') as HTMLElement).onclick = () => { if (tokenFocusChain === t.id) { tokenFocusChain = null; goBack({ route: 'token', tokenId: grp.rep.id }); } else goBack({ route: 'wallet' }); };
  const tkCg = $('#cgBtn'); if (tkCg && t.cg) tkCg.onclick = () => window.open(`https://www.coingecko.com/en/coins/${t.cg}`, '_blank');
  ($('#tkContract') as HTMLElement).onclick = (e) => copyText(t.contract, e.currentTarget as HTMLElement);
  ($('#tkAddr') as HTMLElement).onclick = (e) => copyText(addr, e.currentTarget as HTMLElement);
  ($('#tkRemove') as HTMLElement).onclick = () => {
    if (t.builtin) config.hiddenTokens.push(t.id); else config.tokens = config.tokens.filter(x => x.id !== t.id);
    config.addedTokens = config.addedTokens.filter(x => x !== t.id);
    tokenBalances.delete(t.id); saveConfig(); goTab('wallet');
  };
  paintTokenValues();
  if (t.cg) { const host = $('#priceChart'); if (host) void loadPriceChart(host, t.cg, (info) => paintTokenScrub(info)); }
  void refreshData(true);
}
// Addition 5 — the aggregated token view: one canonical asset held on
// several networks. Total balance + total fiat up top, the asset's own
// chart/stats (one price — the members ARE the same asset), then a
// "By network" card whose rows open the classic single-chain view for
// that network (which carries its contract, Send/Swap and key rows).
function showTokenAggregated(t: TokenDef, grp: TokenGroup) {
  const rep = grp.rep; const cg = grp.asset!;
  const tp = groupPrice(grp);
  const members = [...grp.members].sort((a, b2) => ((tokenBalances.get(b2.id) ?? -1) - (tokenBalances.get(a.id) ?? -1)));
  setView(`<main><button class="backBtn" id="bk" aria-label="Back"><i class="ri-arrow-left-s-line"></i></button>
  <div class="dHead">
    <div class="dIdRow">${tokenIcon(rep, true)}<div class="dIdTx"><div class="dName">${esc(rep.name)}</div><div class="dSym">${esc(rep.symbol)} · ${grp.members.length} networks</div></div><span class="liveDot">LIVE</span></div>
    <div class="dBalBlock"><div class="dEyebrow">TOTAL BALANCE</div><div class="dBalHero" id="tkBal">…</div><div class="dBalUsd" id="tkUsd"></div></div>
    <div class="dPriceBlock"><div class="dEyebrow" id="tkEyebrow">PRICE</div><div class="dPriceRow"><span class="dPriceVal" id="tkPriceVal">…</span><span id="tkPriceChg"></span></div></div>
  </div>
  <div class="dChart"><div id="priceChart" class="pchartHost"><div class="chartEmpty">${waveLoadHTML()} Loading live chart…</div></div></div><div class="chartCap" id="chartCaption"></div>
  ${orbPair('send', () => {}, () => {})}
  <div class="gGroup"><div class="gHead">By network</div><div class="gCard">
    ${members.map(m => { const mc = findChain(m.chainId); const b = tokenBalances.get(m.id); const f = b != null && tp != null ? b * tp : null; return `<button class="sRow" data-net="${m.id}">${mc ? coinIcon(mc) : ''}<span class="sTx"><span class="sLbl">${esc(mc?.name || m.chainId)}</span><div class="sSub">${b == null ? 'Balance unavailable' : fmtCrypto(b, m.symbol)}</div></span><span class="sVal strong">${f != null ? fmtUsd(f) : '—'}</span><i class="ri-arrow-right-s-line sChev"></i></button>`; }).join('')}
  </div><div class="gFoot">One asset, held on ${grp.members.length} networks — the total above is the sum of these balances. Tap a network for its own contract, send and key options.</div></div>
  <div class="gGroup"><div class="gHead">Actions</div><div class="gCard">
    <button class="sRow" id="tkSwapAgg"><span class="sIco"><i class="ri-swap-line"></i></span><span class="sTx"><span class="sLbl">Swap <b>${esc(rep.symbol)}</b></span><div class="sSub">Uses your largest balance above</div></span><span class="sChev"><i class="ri-arrow-right-s-line"></i></span></button>
  </div></div>
  <div class="gGroup"><div class="gHead">Stats</div><div class="gCard flushHair">
    <div class="sRow stat"><span class="sTx"><span class="sLbl">Price</span></span><span class="sVal strong" id="tkStPrice">…</span></div>
    <div class="sRow stat"><span class="sTx"><span class="sLbl">24h change</span></span><span class="sVal strong" id="tkStChg">…</span></div>
    <div class="sRow stat"><span class="sTx"><span class="sLbl">24h high</span></span><span class="sVal strong" id="tkStHigh">…</span></div>
    <div class="sRow stat"><span class="sTx"><span class="sLbl">24h low</span></span><span class="sVal strong" id="tkStLow">…</span></div>
    <div class="rangeWrap" id="tkRange" style="display:none"><div class="rangeTrack"><div class="rangeDot" id="tkRangeDot"></div></div><div class="rangeEnds"><span id="tkRangeLow"></span><span class="rangeMid">24h range</span><span id="tkRangeHigh"></span></div></div>
    <div class="sRow stat"><span class="sTx"><span class="sLbl">Market cap</span></span><span class="sVal strong"><span id="tkStMcap">…</span><span class="delta" id="tkMcapChg"></span></span></div>
    <div class="sRow stat"><span class="sTx"><span class="sLbl">Market data</span></span><button class="monoChip" id="cgBtn">CoinGecko <i class="ri-arrow-right-up-line"></i></button></div>
  </div></div></main>`);
  ($('#bk') as HTMLElement).onclick = () => goBack({ route: 'wallet' });
  const pickMember = (title: string, cb: (m: TokenDef) => void) => {
    const h = openPickerSheet({
      title, placeholder: 'Search networks',
      rows: () => grp.members.map(m => { const mc = findChain(m.chainId); const b = tokenBalances.get(m.id); return { key: m.id, searchText: (mc?.name || '').toLowerCase(), html: `${mc ? coinIcon(mc) : ''}<span class="shTx"><span class="shName">${esc(mc?.name || '')}</span><span class="shNet">${b == null ? 'Balance unavailable' : fmtCrypto(b, m.symbol)}</span></span>` }; }),
      onPick: (key) => { h.close(); const m = grp.members.find(x => x.id === key); if (m) cb(m); },
    });
  };
  bindOrb(() => pickMember('Receive ' + rep.symbol + ' on', (m) => go({ route: 'receive', chainId: m.chainId })), () => pickMember('Send ' + rep.symbol + ' from', (m) => showTokenSend(m.id)));
  V().querySelectorAll('[data-net]').forEach(b => (b as HTMLElement).onclick = () => { const m = grp.members.find(x => x.id === (b as HTMLElement).dataset.net); if (m) { tokenFocusChain = m.id; go({ route: 'token', tokenId: m.id }, b as HTMLElement); } });
  const sw = $('#tkSwapAgg'); if (sw) sw.onclick = () => { const best = members[0] || rep; presetSwapFrom(best.chainId, best.id); go({ route: 'swap' }, sw); };
  const cgB = $('#cgBtn'); if (cgB) cgB.onclick = () => window.open(`https://www.coingecko.com/en/coins/${cg}`, '_blank');
  paintTokenValues();
  const host = $('#priceChart'); if (host) void loadPriceChart(host, cg, (info) => paintTokenScrub(info));
  void refreshData(true);
}
// ExpoKit scrub on token detail: the balance headline is the user's
// own balance and is never hijacked — the scrub drives the Price block
// under it (eyebrow becomes the point's date, value + change follow
// the finger), and release repaints the live price block.
function paintTokenScrub(info: ScrubInfo | null) {
  if (!info) { paintTokenValues(); return; }
  if (currentRoute !== 'token') return;
  const eb = $('#tkEyebrow'); if (eb) eb.textContent = info.label.toUpperCase();
  const pv = $('#tkPriceVal'); if (pv) pv.textContent = fmtPrice(info.value);
  const pc = $('#tkPriceChg');
  if (pc) pc.innerHTML = `<span class="delta ${info.up ? 'pos' : 'neg'}">${info.up ? '+' : '−'}${fmtPrice(Math.abs(info.change))} (${info.up ? '+' : '−'}${Math.abs(info.pct).toFixed(2)}%)</span>`;
}
function paintTokenValues() {
  if (currentRoute !== 'token' || !currentTokenId) return;
  const t = findToken(currentTokenId); if (!t) return;
  const grp = groupOf(t);
  const aggregated = grp.asset != null && grp.members.length > 1 && tokenFocusChain !== t.id;
  const gt = aggregated ? groupTotals(grp) : null;
  const tb = aggregated ? gt!.amount : tokenBalances.get(t.id); const tp = tokenUsd(t);
  const un = priceStateOf(t.cg) === 'pending' ? '…' : 'Unavailable';
  const b = $('#tkBal'); if (b) b.textContent = tb == null ? ((aggregated ? gt!.pending : tokStateOf(t.id) === 'pending') ? 'Loading…' : 'Unavailable') : fmtCrypto(tb, t.symbol);
  const u = $('#tkUsd'); if (u) u.textContent = tb != null && tp != null ? fmtUsd(tb * tp) : '';
  const d = priceEntry(t);
  if (!chartScrubbing) {
    const eb = $('#tkEyebrow'); if (eb) eb.textContent = 'PRICE';
    const pv = $('#tkPriceVal'); if (pv) pv.textContent = tp != null ? fmtPrice(tp) : un;
    const pc = $('#tkPriceChg');
    if (pc) { const ch = d?.change24h ?? null; pc.innerHTML = ch != null ? `<span class="delta ${ch >= 0 ? 'pos' : 'neg'}"><i class="${ch >= 0 ? 'ri-arrow-up-s-fill' : 'ri-arrow-down-s-fill'}"></i>${Math.abs(ch).toFixed(2)}% · 24h</span>` : ''; }
  }
  const set = (id: string, txt: string) => { const el = $(id); if (el) el.textContent = txt; };
  set('#tkStPrice', tp != null ? fmtPrice(tp) : un);
  const tc = $('#tkStChg'); if (tc) { const ch = d?.change24h ?? null; tc.textContent = ch != null ? (ch >= 0 ? '+' : '') + ch.toFixed(2) + '%' : un; tc.className = 'sVal strong ' + (ch == null ? '' : ch >= 0 ? 'pos' : 'neg'); }
  set('#tkStHigh', d?.high24h != null ? fmtPrice(d.high24h) : un);
  set('#tkStLow', d?.low24h != null ? fmtPrice(d.low24h) : un);
  paintRangeEls('tkRange', d, tp);
  set('#tkStMcap', d?.marketCap != null ? fmtMcap(d.marketCap) : un);
  paintMcapChg('tkMcapChg', d);
}
// Token risk for token detail / import screens and the swap review.
// EVM tokens go through GoPlus; Solana tokens are checked ON-CHAIN —
// GoPlus serves no SPL security on its free keyless API (verified
// 2026-11-18), but the mint account itself carries the mint and freeze
// authorities, which is what a Solana risk check actually needs.
async function tokenRiskReport(contract: string, c: Chain): Promise<RiskReport> {
  if (c.kind === 'solana' || c.kind === 'solana-tw' || c.kind === 'solana-phantom') {
    if (!contract || contract === 'native') return { status: 'unavailable', warnings: [], notes: [], reason: 'This is the native asset — there is no token mint to check.' };
    try {
      const info = await solanaRpcCall('getAccountInfo', [contract, { encoding: 'base64' }]);
      const b64 = info?.value?.data?.[0];
      if (typeof b64 !== 'string' || !b64) return { status: 'unavailable', warnings: [], notes: [], reason: 'The mint account could not be read on-chain.' };
      const bytes = Uint8Array.from(atob(b64), (ch) => ch.charCodeAt(0));
      const ex = extractSolMintRisks(bytes);
      if (!ex) return { status: 'unavailable', warnings: [], notes: [], reason: 'This mint account could not be parsed.' };
      return { status: 'ok', warnings: ex.warnings, notes: ex.notes, source: 'On-chain check' };
    } catch { return { status: 'unavailable', warnings: [], notes: [], reason: 'The mint account could not be read (network error).' }; }
  }
  if (c.kind !== 'evm') return { status: 'unavailable', warnings: [], notes: [], reason: 'No token risk source covers this network.' };
  if (!contract || contract === 'native') return { status: 'unavailable', warnings: [], notes: [], reason: 'This is the native asset — there is no token contract to check.' };
  return gpTokenRisk(c.evmId!, contract);
}
async function paintTokenRisk(t: TokenDef, c: Chain) {
  const slot = $('#tkRiskSlot'); if (!slot) return;
  const seq = ++riskPaintSeq;
  const rep = await tokenRiskReport(t.contract, c);
  if (slot.isConnected) slot.innerHTML = riskReportHTML(rep, 'token');
  void appendTwRisk(slot, t.contract, c, seq);
}
// Trust Wallet's token check runs as a SECOND source next to the
// wallet's own (GoPlus / on-chain): appended under its own label when
// the operator configured TWAK keys, skipped silently otherwise. A
// paint sequence guards against a slow answer landing on a screen
// the user has already left.
let riskPaintSeq = 0;
async function appendTwRisk(slot: HTMLElement, contract: string, c: Chain, seq: number) {
  const rep = await twCoinRisk(c.id, contract);
  if (!rep || seq !== riskPaintSeq || !slot.isConnected) return;
  if (!rep.warnings.length && !rep.notes.length) return;
  slot.insertAdjacentHTML('beforeend', `<div style="margin-top:10px">${riskReportHTML(rep, 'token')}</div>`);
}
function decodeErc20String(hex: string): string {
  try {
    const bytes = hexToBytes(hex);
    if (bytes.length >= 64) {
      const len = Number(BigInt('0x' + Array.from(bytes.slice(32, 64)).map(b => b.toString(16).padStart(2, '0')).join('')));
      // Audit NEW HIGH: bound the declared length to the payload that
      // actually arrived — a crafted contract can claim any length.
      if (!(len >= 0) || len > bytes.length - 64 || len > 256) return '';
      return new TextDecoder().decode(bytes.slice(64, 64 + len));
    }
    return new TextDecoder().decode(bytes).replace(/\0/g, '');
  } catch { return ''; }
}
async function fetchTokenMeta(c: Chain, contract: string): Promise<{ name: string; symbol: string; decimals: number } | null> {
  if (c.kind === 'solana' || c.kind === 'solana-tw' || c.kind === 'solana-phantom') {
    const info = await solanaRpcCall('getAccountInfo', [contract, { encoding: 'jsonParsed' }]);
    const parsed = info?.value?.data?.parsed?.info;
    if (!parsed || typeof parsed.decimals !== 'number') return null;
    return { name: '', symbol: '', decimals: parsed.decimals };
  }
  if (c.kind !== 'evm') return null;
  const [n, s, d] = await Promise.all([
    evmCall(c, 'eth_call', [{ to: contract, data: '0x06fdde03' }, 'latest']),
    evmCall(c, 'eth_call', [{ to: contract, data: '0x95d89b41' }, 'latest']),
    evmCall(c, 'eth_call', [{ to: contract, data: '0x313ce567' }, 'latest']),
  ]);
  const rawName = decodeErc20String(n); const rawSymbol = decodeErc20String(s); const decimals = Number(BigInt(d));
  if (!(decimals >= 0 && decimals <= 36)) return null;
  // Audit NEW HIGH: chain-supplied name/symbol are sanitised HERE, at
  // the source — a contract returning markup in its symbol() gets its
  // token rejected (or its name dropped), never persisted verbatim.
  const symbol = sanitizeTokenText(rawSymbol, 'symbol');
  if (!symbol) return null;
  const name = sanitizeTokenText(rawName, 'name') || symbol;
  return { name, symbol, decimals };
}
// One honest meaning of "Added" across Add token (user correction
// 2026-11-20: Popular rows claimed "Added" for every built-in —
// including pUSD, which he had never added and which did not show
// in his wallet — because the old rule was just "not hidden"). A
// token is Added when it is pinned to Home (addedTokens) or
// actually held > 0, and it is not hidden. Tapping a row that is
// not Added now PINS the token (the action matches the label);
// tapping an Added row opens the token.
function tokenIsAdded(t: TokenDef): boolean {
  if (config.hiddenTokens.includes(t.id)) return false;
  if (config.addedTokens.includes(t.id)) return true;
  const b = tokenBalances.get(t.id);
  return b != null && b > 0;
}
function catalogIsAdded(t: TokenDef): boolean {
  const existing = findTokenByContract(t.chainId, t.contract);
  if (existing) return tokenIsAdded(existing);
  return config.addedTokens.includes(t.id) && !config.hiddenTokens.includes(t.id);
}
// Add token screen state: chain filter + the search text, kept at
// module level so switching chains re-renders without losing either.
let addTokenChain = 'all';
let addTokenQuery = '';
function addTokenChains(): Chain[] {
  const ids = new Set<string>();
  for (const t of BUILTIN_TOKENS) ids.add(t.chainId);
  for (const t of TOKEN_CATALOG) ids.add(t.chainId);
  return visibleChains().filter(c => ids.has(c.id));
}
function popTokenRowHTML(t: TokenDef): string {
  const c = findChain(t.chainId); if (!c) return '';
  const added = tokenIsAdded(t);
  return `<button class="lRow" data-pop="${t.id}" type="button">${iconHTML(tokenIconUrl(t), t.symbol, t.name)}<span class="aMain"><span class="aName">${esc(t.name)} <span class="aSym">${esc(t.symbol)}</span></span><span class="aSub">${esc(c.name)}</span></span>${added ? '<span class="popAdded"><i class="ri-check-line"></i> Added</span>' : '<span class="popAdd">Add</span>'}</button>`;
}
// The Popular list (user order 2026-11-20: "add actual popular
// tokens" — the old list was just the built-in stablecoins).
// POPULAR_TOKEN_IDS resolves against builtins first, then the
// catalog, in curated order; rows keep each source's own add
// behaviour (builtins pin, catalog tokens copy in + pin).
function popularTokens(): TokenDef[] {
  const out: TokenDef[] = [];
  for (const id of POPULAR_TOKEN_IDS) {
    const t = BUILTIN_TOKENS.find(b => b.id === id) || (TOKEN_CATALOG.find(c => c.id === id) as TokenDef | undefined);
    if (t) out.push(t);
  }
  return out;
}
function popCatRowHTML(t: TokenDef): string {
  const c = findChain(t.chainId); if (!c) return '';
  const added = catalogIsAdded(t);
  return `<button class="lRow" data-popcat="${t.id}" type="button">${iconHTML(tokenIconUrl(t), t.symbol, t.name)}<span class="aMain"><span class="aName">${esc(t.name)} <span class="aSym">${esc(t.symbol)}</span></span><span class="aSub">${esc(c.name)}</span></span>${added ? '<span class="popAdded"><i class="ri-check-line"></i> Added</span>' : '<span class="popAdd">Add</span>'}</button>`;
}
function popListHTML(q: string): string {
  const query = q.trim().toLowerCase();
  const list = popularTokens().filter(t => { const c = findChain(t.chainId); return !!c && enabledSet().has(t.chainId) && (addTokenChain === 'all' || t.chainId === addTokenChain) && (!query || t.name.toLowerCase().includes(query) || t.symbol.toLowerCase().includes(query) || c.name.toLowerCase().includes(query)); });
  if (!list.length) return '<p class="small muted secEmpty" style="padding:14px 2px">No popular token matches — add it by contract below.</p>';
  return `<div class="iosList">${list.map(t => t.builtin ? popTokenRowHTML(t) : popCatRowHTML(t)).join('')}</div>`;
}
function showAddToken(err = '', stage?: { c: Chain; contract: string; meta: { name: string; symbol: string; decimals: number } }) {
  const candidates = visibleChains().filter(c => c.kind === 'evm' || c.kind === 'solana' || c.kind === 'solana-tw' || c.kind === 'solana-phantom');
  setView(`<main><button class="backBtn" id="bk" aria-label="Back"><i class="ri-arrow-left-s-line"></i></button><div class="largeTitle" style="padding-top:2px">Add token</div>
  <div style="padding:0 16px">${err ? `<div class="err">${esc(err)}</div><div style="height:10px"></div>` : ''}
  ${stage ? `<div class="setPanel" style="margin:0 0 12px"><div class="setH">Found on ${esc(stage.c.name)}</div>
    <div class="setRow"><span class="setLabel">Contract</span><span class="sv" style="max-width:55%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(stage.contract)}</span></div>
    <div class="setRow"><span class="setLabel">Decimals (from chain)</span><span class="sv">${stage.meta.decimals}</span></div>
    <div class="setH" style="margin-top:14px">Security check</div><div id="tkRiskSlot" style="margin-top:8px"><p class="small muted">Checking this token with GoPlus…</p></div></div>
    <div class="field"><label>Token name</label><div class="box"><input id="tkName" value="${esc(stage.meta.name)}" placeholder="Token name" autocomplete="off"></div></div>
    <div class="field"><label>Symbol</label><div class="box"><input id="tkSym" value="${esc(stage.meta.symbol)}" placeholder="e.g. USDC" autocomplete="off" autocapitalize="none"></div></div>
    <button class="ctaWide" id="tkAddGo" type="button">Add token</button>`
  : `<div class="searchBox"><i class="ri-search-line"></i><input id="popSearch" placeholder="Search tokens or networks" autocomplete="off" autocapitalize="none" spellcheck="false" value="${esc(addTokenQuery)}"></div>
    <div class="chipRail" style="margin-top:12px"><button class="netChip${addTokenChain === 'all' ? ' on' : ''}" data-atchain="all" type="button"><span>All chains</span></button>${addTokenChains().map(c => `<button class="netChip${addTokenChain === c.id ? ' on' : ''}" data-atchain="${c.id}" type="button"><span>${esc(c.name)}</span></button>`).join('')}</div>
    <div class="secHead" style="margin-top:16px"><span class="secTitle">Popular</span></div>
    <div id="popList">${popListHTML(addTokenQuery)}</div>
    <div class="secHead" style="margin-top:20px"><span class="secTitle">Catalog</span><span class="small muted" id="catCount"></span></div>
    <div id="catList"></div>
    <div id="catSentinel" style="height:1px"></div>
    <div class="secHead" style="margin-top:20px"><span class="secTitle">Custom token</span></div>
    <p class="small muted" style="line-height:1.55;margin-bottom:12px">Not in the list? Paste a token contract (EVM) or mint (Solana). Syn reads the name, symbol and decimals from the chain itself and only adds the token if the contract answers like a real token.</p>
    <div class="field"><label>Network</label><div class="box"><select id="tkChain">${candidates.map(c => `<option value="${c.id}">${esc(c.name)}</option>`).join('')}</select></div></div>
    <div class="field"><label>Contract / mint address</label><div class="box"><input id="tkContractIn" placeholder="0x… or Solana mint" autocomplete="off" autocapitalize="none" spellcheck="false"></div></div>
    <button class="ctaWide" id="tkFetch" type="button">Fetch token info</button>`}
  </div></main>`);
  ($('#bk') as HTMLElement).onclick = () => goBack({ route: 'wallet' });
  if (!stage) {
    const paintPop = () => { const host = $('#popList'); if (!host) return; host.innerHTML = popListHTML(($('#popSearch') as unknown as HTMLInputElement)?.value ?? ''); wirePop(); };
    const wirePop = () => { document.querySelectorAll('[data-pop]').forEach(el => { (el as HTMLElement).onclick = () => { const t = BUILTIN_TOKENS.find(x => x.id === (el as HTMLElement).dataset.pop); if (!t) return; if (!tokenIsAdded(t)) { config.hiddenTokens = config.hiddenTokens.filter(x => x !== t.id); if (!config.addedTokens.includes(t.id)) config.addedTokens.push(t.id); saveConfig(); void fetchTokenBalance(t).then(v => { tokenBalances.set(t.id, v); saveDataCache(); }); void fetchPrices(); paintPop(); } else go({ route: 'token', tokenId: t.id }); }; });
      document.querySelectorAll('[data-popcat]').forEach(el => { (el as HTMLElement).onclick = () => { const t = TOKEN_CATALOG.find(x => x.id === (el as HTMLElement).dataset.popcat) as TokenDef | undefined; if (!t) return; if (catalogIsAdded(t)) { const existing = findTokenByContract(t.chainId, t.contract); go({ route: 'token', tokenId: existing ? existing.id : t.id }, el as HTMLElement); return; } addCatalogToken(t); const row = document.querySelector(`[data-popcat="${t.id}"]`); if (row) row.outerHTML = popCatRowHTML(t); const crow = document.querySelector(`[data-cat="${t.id}"]`); if (crow) crow.outerHTML = catRowHTML(t); wirePop(); }; }); };
    wirePop();
    document.querySelectorAll('[data-atchain]').forEach(b => { (b as HTMLElement).onclick = () => { addTokenChain = (b as HTMLElement).dataset.atchain || 'all'; showAddToken(); }; });
    // Token catalog (up to 500, lib/token-catalog): SMART LOADING —
    // the list renders in 40-row chunks appended as the sentinel
    // scrolls into view, never as one 500-row DOM blast; one delegated
    // click listener serves every row; search is debounced. A catalog
    // token becomes a real wallet token only when added (its def is
    // copied into config.tokens), so the catalog itself costs no
    // balance fetches.
    const CAT_PAGE = 40;
    let catItems: TokenDef[] = [];
    let catShown = 0;
    let catObserver: IntersectionObserver | null = null;
    const catRowHTML = (t: TokenDef): string => {
      const c = findChain(t.chainId); if (!c) return '';
      const added = catalogIsAdded(t);
      return `<button class="lRow" data-cat="${t.id}" type="button">${iconHTML(tokenIconUrl(t), t.symbol, t.name)}<span class="aMain"><span class="aName">${esc(t.name)} <span class="aSym">${esc(t.symbol)}</span></span><span class="aSub">${esc(c.name)}</span></span>${added ? '<span class="popAdded"><i class="ri-check-line"></i> Added</span>' : '<span class="popAdd">Add</span>'}</button>`;
    };
    const paintCat = (reset: boolean) => {
      const host = $('#catList'); if (!host) return;
      if (reset) {
        const q = (($('#popSearch') as unknown as HTMLInputElement)?.value ?? '').trim().toLowerCase();
        catItems = TOKEN_CATALOG.filter(t => { const c = findChain(t.chainId); return !!c && enabledSet().has(t.chainId) && (addTokenChain === 'all' || t.chainId === addTokenChain) && (!q || t.name.toLowerCase().includes(q) || t.symbol.toLowerCase().includes(q) || c.name.toLowerCase().includes(q)); }) as TokenDef[];
        catShown = 0;
        host.innerHTML = catItems.length ? '<div class="iosList"></div>' : '<p class="small muted secEmpty" style="padding:14px 2px">No catalog token matches — add it by contract below.</p>';
        const cc = $('#catCount'); if (cc) cc.textContent = catItems.length ? catItems.length + ' tokens' : '';
      }
      const listEl = host.querySelector('.iosList'); if (!listEl) return;
      const next = catItems.slice(catShown, catShown + CAT_PAGE);
      if (next.length) { listEl.insertAdjacentHTML('beforeend', next.map(catRowHTML).join('')); catShown += next.length; }
      const sentinel = $('#catSentinel');
      if (sentinel) {
        if (catObserver) catObserver.disconnect();
        if (catShown < catItems.length && 'IntersectionObserver' in window) {
          catObserver = new IntersectionObserver(entries => { if (entries.some(e => e.isIntersecting)) paintCat(false); }, { rootMargin: '600px' });
          catObserver.observe(sentinel);
        }
      }
    };
    // The one catalog add flow, shared by the Catalog list and the
    // Popular rows that resolve to catalog tokens: register the def
    // in the wallet (once — an existing token with the same contract
    // is pinned instead of duplicated), pin it, fetch its balance.
    const addCatalogToken = (t: TokenDef): TokenDef => {
      let def = findTokenByContract(t.chainId, t.contract);
      if (!def) { def = { ...t }; config.tokens.push(def); }
      if (!config.addedTokens.includes(def.id)) config.addedTokens.push(def.id);
      config.hiddenTokens = config.hiddenTokens.filter(x => x !== def!.id);
      saveConfig();
      void fetchTokenBalance(def).then(v => { tokenBalances.set(def!.id, v); saveDataCache(); });
      void fetchPrices(); // the new token's price lands now, not at the next interval
      return def;
    };
    const catHost = $('#catList');
    if (catHost) catHost.addEventListener('click', (ev) => {
      const el = (ev.target as HTMLElement).closest('[data-cat]') as HTMLElement | null; if (!el) return;
      const t = TOKEN_CATALOG.find(x => x.id === el.dataset.cat) as TokenDef | undefined; if (!t) return;
      const existing = findTokenByContract(t.chainId, t.contract);
      if (catalogIsAdded(t)) { go({ route: 'token', tokenId: existing ? existing.id : t.id }, el); return; }
      addCatalogToken(t);
      el.outerHTML = catRowHTML(t);
      const prow = document.querySelector(`[data-popcat="${t.id}"]`); if (prow) { prow.outerHTML = popCatRowHTML(t); wirePop(); }
    });
    paintCat(true);
    let searchTimer: ReturnType<typeof setTimeout> | null = null;
    ($('#popSearch') as unknown as HTMLInputElement).addEventListener('input', () => {
      addTokenQuery = ($('#popSearch') as unknown as HTMLInputElement).value;
      if (searchTimer) clearTimeout(searchTimer);
      searchTimer = setTimeout(() => { paintPop(); paintCat(true); }, 120);
    });
  }
  if (stage) {
    void paintTokenRisk({ id: 'stage', chainId: stage.c.id, contract: stage.contract, name: stage.meta.name, symbol: stage.meta.symbol, decimals: stage.meta.decimals }, stage.c);
    ($('#tkAddGo') as HTMLButtonElement).onclick = () => {
      // Audit NEW HIGH: name/symbol render on Home and on REVIEW
      // screens — validate charset + length before anything is stored.
      const name = sanitizeTokenText(($('#tkName') as unknown as HTMLInputElement).value, 'name');
      const symbolRaw = sanitizeTokenText(($('#tkSym') as unknown as HTMLInputElement).value, 'symbol');
      const symbol = symbolRaw ? symbolRaw.toUpperCase() : null;
      if (!name || !symbol) { showAddToken('Give the token a name (letters/numbers, max 64 characters) and a symbol (letters/numbers, max 12 characters).', stage); return; }
      const t: TokenDef = { id: 'ct-' + Date.now().toString(36), chainId: pickerChainId(stage.c.id), contract: stage.contract, name, symbol, decimals: stage.meta.decimals };
      config.tokens.push(t); saveConfig();
      void fetchTokenBalance(t).then(v => { tokenBalances.set(t.id, v); saveDataCache(); });
      go({ route: 'token', tokenId: t.id });
    };
    return;
  }
  ($('#tkFetch') as HTMLButtonElement).onclick = async () => {
    const c = findChain(($('#tkChain') as unknown as HTMLSelectElement).value); const contract = ($('#tkContractIn') as unknown as HTMLInputElement).value.trim();
    if (!c) return;
    if (c.kind === 'evm' && !ethers.isAddress(contract)) { showAddToken('That is not a valid contract address for ' + c.name + '.'); return; }
    if ((c.kind === 'solana' || c.kind === 'solana-tw' || c.kind === 'solana-phantom')) { try { new PublicKey(contract); } catch { showAddToken('That is not a valid Solana mint address.'); return; } }
    const btn = $('#tkFetch') as HTMLButtonElement; btn.disabled = true; btn.textContent = 'Reading from the chain…';
    try { const meta = await fetchTokenMeta(c, contract); if (!meta) { showAddToken('That contract did not answer like a token (no symbol/decimals). Nothing was added.'); return; } showAddToken('', { c, contract, meta }); }
    catch { showAddToken('Could not read that contract from the network. Nothing was added.'); }
  };
}
function showTokenSend(tokenId: string, err = '') {
  const t = findToken(tokenId); if (!t) { goTab('wallet'); return; }
  const c = findChain(t.chainId)!; const tb = tokenBalances.get(t.id);
  const tp = tokenUsd(t);
  setView(`<main><button class="backBtn" id="bk" aria-label="Back"><i class="ri-arrow-left-s-line"></i></button>
  <div class="card" style="position:relative"><h1 class="heroH">Send <span>${esc(t.symbol)}</span></h1><p class="heroSub" style="margin-top:2px">On ${esc(c.name)} · Step 1 of 2</p>
  ${err ? `<div style="height:12px"></div><div class="err">${esc(err)}</div>` : ''}<div style="height:16px"></div>
  <button class="assetPick" id="tkAssetPick">${iconHTML(tokenIconUrl(t), t.symbol, t.name)}<span><div class="apName">${esc(t.name)}</div><div class="apBal">Balance: ${tb == null ? (tokStateOf(t.id) === 'pending' ? 'Loading…' : 'Unavailable') : trimNum(tb) + ' ' + esc(t.symbol)}</div></span><i class="ri-arrow-down-s-line"></i></button>
  <div style="height:14px"></div>
  <div class="toPill"><div class="fld"><label>To</label><input id="tkTo" placeholder="${c.kind === 'tron' ? 'TRON address' : (c.kind === 'solana' || c.kind === 'solana-tw' || c.kind === 'solana-phantom') ? 'Solana address or name.sol' : '0x address or name.eth'}" autocomplete="off" autocapitalize="none" spellcheck="false"></div><button class="pasteBtn" id="tkPaste" type="button">Paste</button></div>
  <div class="field" style="margin-top:14px"><label>Amount (${esc(t.symbol)})</label><div class="box"><input id="tkAmt" inputmode="decimal" placeholder="0.0" autocomplete="off"></div></div>
  <div style="display:flex;justify-content:space-between;align-items:center;margin-top:8px;min-height:26px"><span class="small muted" id="tkFiat"></span><button class="pillBtn" id="tkMax" type="button">MAX</button></div>
  <div class="feeLine"><i class="ri-information-line"></i><span>Network fee is paid in ${esc(c.symbol)} — the exact fee and speed are set on the review step.</span></div>
  <div style="height:14px"></div>
  <button class="ctaWide stickyCta" id="tkReview" type="button">Review</button></div></main>`);
  ($('#bk') as HTMLElement).onclick = () => goBack({ route: 'token', tokenId: t.id });
  ($('#tkPaste') as HTMLElement).onclick = async () => { try { const x = await navigator.clipboard.readText(); if (x) ($('#tkTo') as unknown as HTMLInputElement).value = x.trim(); } catch { /* clipboard unavailable */ } };
  ($('#tkAssetPick') as HTMLElement).onclick = () => {
    openSendPicker(pickerChainId(t.chainId) + ':' + t.contract, (a) => {
      if (a.contract === 'native') showSend(a.chainId);
      else if (a.tokenId && a.tokenId !== t.id) showTokenSend(a.tokenId);
    }, pickerChainId(t.chainId));
  };
  const tkAmtIn = $('#tkAmt') as unknown as HTMLInputElement;
  const paintTkFiat = () => { const el = $('#tkFiat'); if (!el) return; const v = parseFloat(tkAmtIn.value); el.textContent = v > 0 && tp != null ? '≈ ' + fmtUsd(v * tp) : ''; };
  tkAmtIn.addEventListener('input', paintTkFiat);
  ($('#tkMax') as HTMLElement).onclick = () => { if (tb != null && tb > 0) { tkAmtIn.value = trimNum(tb, Math.min(8, t.decimals)); paintTkFiat(); } };
  ($('#tkReview') as HTMLButtonElement).onclick = async () => {
    const rawTo = ($('#tkTo') as unknown as HTMLInputElement).value.trim();
    // Audit H-4: the amount travels as the exact entered STRING
    // (sanitised to the token's decimals) — never a free parseFloat.
    const amtStr = sanitizeAmt(($('#tkAmt') as unknown as HTMLInputElement).value.trim(), Math.min(8, t.decimals));
    const amt = parseFloat(amtStr);
    if (!rawTo) return showTokenSend(tokenId, 'Enter a destination address.');
    if (!(amt > 0) || parseRawAmount(amtStr, t.decimals) == null) return showTokenSend(tokenId, 'Enter an amount greater than zero.');
    if (tb != null && amt > tb) return showTokenSend(tokenId, 'Amount exceeds your token balance.');
    let to = rawTo; let nameLabel = '';
    if (!isRawAddressFor(c, rawTo) && looksLikeNameAttempt(rawTo)) {
      const btn = $('#tkReview') as HTMLButtonElement; btnBusy(btn, 'Resolving name…');
      const r = await resolveNameFor(c, rawTo);
      if ('error' in r) return showTokenSend(tokenId, r.error);
      to = r.address; nameLabel = rawTo.trim().toLowerCase();
    }
    if (c.kind === 'evm') {
      if (!ethers.isAddress(to)) return showTokenSend(tokenId, 'That does not look like a valid EVM address.');
      const mixed = to !== to.toLowerCase() && to !== to.toUpperCase();
      if (mixed && !nameLabel) { try { ethers.getAddress(to); } catch { return showTokenSend(tokenId, 'Address checksum (EIP-55) failed — send blocked.'); } }
    }
    if (c.kind === 'solana' || c.kind === 'solana-tw' || c.kind === 'solana-phantom') { try { new PublicKey(to); } catch { return showTokenSend(tokenId, 'That does not look like a valid Solana address.'); } }
    // Audit M-9: token sends get the SAME poisoning check as native sends.
    const poisonWarn = poisonWarning(to);
    feeState = freshFeeState();
    go({ route: 'tokenconfirm', tokenConfirm: { t, to, amtStr, nameLabel, poisonWarn } }, $('#tkReview') as HTMLElement);
  };
}
function showTokenConfirm(t: TokenDef, to: string, amtStr: string, err = '', nameLabel = '', poisonWarn = '') {
  const amt = parseFloat(amtStr) || 0; // display only — the signer receives amtStr verbatim (audit H-4)
  const c = findChain(t.chainId)!; const tb = tokenBalances.get(t.id); const tp = tokenUsd(t);
  setView(`<main><button class="backBtn" id="bk" aria-label="Back"><i class="ri-arrow-left-s-line"></i></button>
  <div class="card" style="position:relative"><h1 class="heroH">Review <span>send</span></h1><p class="heroSub" style="margin-top:2px">Step 2 of 2</p><div style="height:8px"></div>${err ? `<div class="err">${esc(err)}</div>` : ''}
  <div class="sumAmt">${trimNum(amt, 8)} ${esc(t.symbol)}</div>
  ${tp != null ? `<p class="small muted" style="text-align:center">≈ ${fmtUsd(amt * tp)}</p>` : ''}
  <div style="height:8px"></div>
  <div class="sumRow"><span class="sl">Token</span><span class="sv">${esc(t.name)} (${esc(t.symbol)})</span></div>
  <div class="sumRow"><span class="sl">Network</span><span class="sv">${esc(c.name)}</span></div>
  ${nameLabel ? `<div class="sumRow"><span class="sl">Name</span><span class="sv">${esc(nameLabel)}</span></div>` : ''}
  <div class="sumRow"><span class="sl">To</span><span class="sv"><span class="monoChip" style="max-width:210px" data-full="${esc(to)}">${esc(to.slice(0, 10))}…${esc(to.slice(-8))}</span></span></div>
  <div class="sumRow"><span class="sl">Network fee</span><span class="sv" id="tkFeeCell">Estimating…</span></div>
  <div class="sumRow"><span class="sl">Token balance after</span><span class="sv">${tb == null ? (tokStateOf(t.id) === 'pending' ? 'Loading…' : 'Unavailable') : trimNum(tb - amt) + ' ' + esc(t.symbol)}</span></div>
  ${gasBoxHTML(c)}
  <div id="riskBox" style="margin-top:12px"></div>
  ${poisonWarn ? `<div class="warn" style="margin-top:12px">${esc(poisonWarn)}</div>` : ''}
  <p class="securityNote" style="margin:12px 0">Clear signing: the token, amount and recipient above are exactly what gets signed, locally on this device. Transactions cannot be reversed.</p>
  <button class="ctaWide" id="tkSendBtn" type="button">Send ${esc(t.symbol)}</button><div style="height:10px"></div><button class="btnGhost" id="tkCancel" type="button" style="border-radius:999px">Cancel</button></div></main>`);
  let gasLimitEst = 65000n;
  const updateTkFee = () => {
    const fc = $('#tkFeeCell'); if (!fc) return;
    if (c.kind === 'evm') { const txt = feeCostText(c, gasLimitEst); fc.textContent = txt ? txt + ` (paid in ${c.symbol})` : feeState.mode === 'custom' ? 'Enter valid custom fees' : 'Estimating…'; return; }
    estimateFee(c).then(fee => { if (fc.isConnected) fc.textContent = fee == null ? 'Unavailable — shown at signing' : `~${fee} ${c.symbol} (paid in ${c.symbol})`; });
  };
  if (c.kind === 'evm') {
    bindGasBox(c, () => gasLimitEst, updateTkFee);
    (async () => { try { const pk = meta?.kind === 'privateKey' ? (secret!.startsWith('0x') ? secret! : '0x' + secret!) : derived2!.evmPrivateKey; const provider = new ethers.JsonRpcProvider(evmProviderUrl(c), c.evmId); const contract = new ethers.Contract(t.contract, ['function transfer(address to, uint256 value) returns (bool)'], new ethers.Wallet(pk, provider)); gasLimitEst = await contract.transfer.estimateGas(to, ethers.parseUnits(amtStr, t.decimals)); updateTkFee(); } catch { /* keep the 65k display estimate */ } })();
  }
  updateTkFee();
  void paintAddressRisk($('#riskBox'), to, c);
  ($('#bk') as HTMLElement).onclick = () => goBack({ route: 'token', tokenId: t.id }); ($('#tkCancel') as HTMLElement).onclick = () => goBack({ route: 'token', tokenId: t.id });
  ($('#tkSendBtn') as HTMLButtonElement).onclick = async () => {
    const problem = customFeeProblem();
    if (problem) { showTokenConfirm(t, to, amtStr, problem, nameLabel, poisonWarn); return; }
    // Audit M-8: same fee-choice protection as native sends.
    if (c.kind === 'evm' && feeState.mode !== 'auto' && !chosenFees(feeState, feeInfo)) { showTokenConfirm(t, to, amtStr, 'Live fee data is unavailable, so your chosen fee speed can\'t be applied. Check your connection, or switch the fee back to Auto.', nameLabel, poisonWarn); return; }
    const btn = $('#tkSendBtn') as HTMLButtonElement; btnBusy(btn, 'Signing & broadcasting…');
    try {
      const overrides = c.kind === 'evm' ? (chosenFees(feeState, feeInfo)?.overrides || {}) : {};
      const hash = await doTokenSend(t, to, amtStr, overrides); recordLocalTx(t.chainId, hash, `Sent ${t.symbol}`, { dir: 'out', sym: t.symbol, amt: amtStr, cp: to, img: tokenIconUrl(t), cgid: t.cg }); recordCounterparty(to); tokenBalances.delete(t.id);
      celebrate(btn, () => {
        setView(receiptHTML({ title: 'Sent', amount: `${trimNum(amt, 8)} ${t.symbol}`, toLine: `To ${shortAddr(to)}`, sub: `on ${c.name}`, hash, doneLabel: 'Done' }));
        bindReceipt(hash, c.explorerTx, (el) => goTab('wallet', el));
      });
    } catch (e: any) {
      const eh = (e as any)?.hash || (e as any)?.transactionHash;
      if (typeof eh === 'string' && /^0x[0-9a-fA-F]{64}$/.test(eh)) { recordLocalTx(t.chainId, eh, `Sent ${t.symbol}`, { dir: 'out', sym: t.symbol, amt: amtStr, cp: to, img: tokenIconUrl(t), cgid: t.cg }); recordCounterparty(to); showTokenConfirm(t, to, amtStr, 'The network may have accepted this transaction already (check Activity before trying again).', nameLabel, poisonWarn); return; }
      showTokenConfirm(t, to, amtStr, 'Send failed: ' + (e?.shortMessage || e?.message || String(e)), nameLabel, poisonWarn);
    }
  };
}
async function doTokenSend(t: TokenDef, to: string, amtStr: string, feeOverrides: Record<string, bigint> = {}): Promise<string> {
  const c = findChain(t.chainId)!;
  if (c.kind === 'evm') {
    const pk = meta?.kind === 'privateKey' ? (secret!.startsWith('0x') ? secret! : '0x' + secret!) : derived2!.evmPrivateKey;
    const provider = new ethers.JsonRpcProvider(evmProviderUrl(c), c.evmId);
    const wallet = new ethers.Wallet(pk, provider);
    const contract = new ethers.Contract(t.contract, ['function transfer(address to, uint256 value) returns (bool)'], wallet);
    const tx = Object.keys(feeOverrides).length ? await contract.transfer(to, ethers.parseUnits(amtStr, t.decimals), feeOverrides) : await contract.transfer(to, ethers.parseUnits(amtStr, t.decimals));
    return tx.hash;
  }
  if (c.kind === 'solana' || c.kind === 'solana-tw' || c.kind === 'solana-phantom') {
    const kp: Keypair = c.kind === 'solana-tw' ? Keypair.fromSeed(derived2!.solTWSeed32) : c.kind === 'solana-phantom' ? Keypair.fromSeed(derived2!.solPhantomSeed32) : meta?.kind === 'privateKey' ? importedSolKp! : Keypair.fromSeed(derived2!.solSeed32);
    const conn = new Connection(solanaRpcUrl(), 'confirmed');
    const mint = new PublicKey(t.contract); const owner = new PublicKey(to);
    const fromAta = getAssociatedTokenAddressSync(mint, kp.publicKey);
    const toAta = getAssociatedTokenAddressSync(mint, owner);
    const ixs = [];
    const toInfo = await conn.getAccountInfo(toAta);
    if (!toInfo) ixs.push(createAssociatedTokenAccountInstruction(kp.publicKey, toAta, owner, mint));
    const rawAmt = parseRawAmount(amtStr, t.decimals);
    if (rawAmt == null) throw new Error('Invalid amount.');
    ixs.push(createTransferCheckedInstruction(fromAta, mint, toAta, kp.publicKey, rawAmt, t.decimals));
    const tx = new Transaction().add(...ixs);
    const { blockhash } = await conn.getLatestBlockhash('confirmed'); tx.recentBlockhash = blockhash; tx.feePayer = kp.publicKey; tx.sign(kp);
    return await sendSolanaSigned(conn, tx.serialize(), bs58.encode(tx.signature!));
  }
  throw new Error('Token sending is not supported on ' + c.name + ' yet.');
}

// ---------- sign: message signing + sign-in requests (clear-signing) ----------
// Signing is exposed as an explicit tool with full-message review — there
// is no dApp browser yet (Wave 2), so nothing can ask this wallet to sign
// behind the user's back. Sign-in requests are pasted by the user, parsed
// field by field, and signed only on explicit confirmation.
function evmSigner(): { address: string; sign: (t: string) => Promise<string> } | null {
  let pk: string | null = null;
  if (meta?.kind === 'privateKey') { if (meta.chain !== 'solana') pk = secret!.startsWith('0x') ? secret! : '0x' + secret!; }
  else if (derived2) pk = derived2.evmPrivateKey;
  if (!pk) return null;
  const w = new ethers.Wallet(pk);
  return { address: w.address, sign: async (t: string) => w.signMessage(t) };
}
function solSigner(): { address: string; sign: (t: string) => Promise<string> } | null {
  let kp: Keypair | null = null;
  if (meta?.kind === 'privateKey') { if (meta.chain === 'solana') kp = importedSolKp; }
  else if (derived2) kp = Keypair.fromSeed(derived2.solSeed32);
  if (!kp) return null;
  const seed = kp.secretKey.slice(0, 32); const address = kp.publicKey.toBase58();
  return { address, sign: async (t: string) => bs58.encode(ed25519.sign(new TextEncoder().encode(t), seed)) };
}
let signFamily: 'evm' | 'solana' = 'evm';
let signDraftText = '';
let signParsed: ReturnType<typeof parseSignInMessage> = null;
function showSign(tab: 'msg' | 'siwe', err = '') {
  const evm = evmSigner(); const sol = solSigner();
  if (signFamily === 'evm' && !evm && sol) signFamily = 'solana';
  if (signFamily === 'solana' && !sol && evm) signFamily = 'evm';
  const signerRows = [
    evm ? `<div class="setRow"><span class="setLabel">Ethereum / EVM</span><button class="monoChip" data-copy="${esc(evm.address)}">${esc(shortAddr(evm.address))}</button></div>` : '',
    sol ? `<div class="setRow"><span class="setLabel">Solana</span><button class="monoChip" data-copy="${esc(sol.address)}">${esc(shortAddr(sol.address))}</button></div>` : '',
  ].join('');
  setView(`<main><button class="backBtn" id="bk" aria-label="Back"><i class="ri-arrow-left-s-line"></i></button><div class="largeTitle" style="padding-top:2px">Sign</div>
  <div style="padding:0 16px"><p class="small muted" style="line-height:1.55">Signing a message proves you control this account — it never moves funds and never reveals your key. Read every word before signing: a signature for a malicious message can be used against you. Syn Wallet will never ask you to sign anything.</p><div style="height:12px"></div>${err ? `<div class="err">${esc(err)}</div>` : ''}</div>
  <div class="setPanel"><div class="setH">Signing account</div><div class="setHSub">Active wallet · Account ${accountIdx() + 1}. Tap a chip to copy the address.</div>${signerRows || '<p class="small muted">No signing account is available for this wallet.</p>'}</div>
  <div style="padding:0 16px"><div class="seg" id="signSeg"><button data-t="msg" class="${tab === 'msg' ? 'on' : ''}" type="button">Sign message</button><button data-t="siwe" class="${tab === 'siwe' ? 'on' : ''}" type="button">Sign-in request</button></div></div>
  <div id="signBody" style="margin-top:12px"></div></main>`);
  ($('#bk') as HTMLElement).onclick = () => goBack({ route: 'settings' });
  V().querySelectorAll('[data-copy]').forEach(b => (b as HTMLElement).onclick = () => copyText((b as HTMLElement).dataset.copy!, b as HTMLElement));
  V().querySelectorAll('#signSeg button').forEach(b => (b as HTMLElement).onclick = () => showSign((b as HTMLElement).dataset.t as 'msg' | 'siwe'));
  const body = $('#signBody'); if (!body) return;
  if (tab === 'msg') renderSignMessage(body); else renderSignIn(body);
}
function sigResultHTML(sig: string): string {
  return `<div class="setH" style="margin-top:16px">Signature</div><div class="sigBox" id="sigVal">${esc(sig)}</div><button class="btnGhost" id="sigCopy" type="button" style="border-radius:999px"><i class="ri-file-copy-line"></i> Copy signature</button>`;
}
function renderSignMessage(body: HTMLElement) {
  const evm = evmSigner(); const sol = solSigner();
  const both = evm && sol;
  body.innerHTML = `<div class="card" style="position:relative"><h1 class="heroH" style="font-size:22px">Sign <span>message</span></h1><p class="heroSub">The full message is shown exactly as it will be signed.</p><div style="height:14px"></div>
  ${both ? `<div class="field"><label>Sign with</label><div class="seg" id="famSeg"><button data-f="evm" class="${signFamily === 'evm' ? 'on' : ''}" type="button">Ethereum / EVM</button><button data-f="solana" class="${signFamily === 'solana' ? 'on' : ''}" type="button">Solana</button></div></div>` : ''}
  <div class="field"><label>Message</label><div class="box"><textarea id="signMsg" placeholder="Type or paste the exact message…" autocomplete="off" spellcheck="false">${esc(signDraftText)}</textarea></div></div>
  <div id="blobWarn"></div><div id="signErr"></div>
  <button class="ctaWide" id="signGo" type="button">Sign message</button>
  <div id="signResult"></div></div>`;
  if (both) body.querySelectorAll('#famSeg button').forEach(b => (b as HTMLElement).onclick = () => { signFamily = (b as HTMLElement).dataset.f as 'evm' | 'solana'; renderSignMessage(body); });
  const ta = body.querySelector('#signMsg') as unknown as HTMLTextAreaElement;
  const warn = () => { const w = body.querySelector('#blobWarn'); if (w) w.innerHTML = looksLikeBlindBlob(ta.value) ? '<div class="warn">This looks like an unreadable blob (hex or base64 data), not a human-readable message. Signing data you cannot read is <b>blind signing</b> — only continue if you completely trust where it came from.</div>' : ''; };
  ta.addEventListener('input', () => { signDraftText = ta.value; warn(); });
  warn();
  (body.querySelector('#signGo') as HTMLButtonElement).onclick = async () => {
    const signer = signFamily === 'evm' ? evmSigner() : solSigner();
    const errBox = body.querySelector('#signErr'); const res = body.querySelector('#signResult');
    if (!signer) { if (errBox) errBox.innerHTML = '<div class="err">No account available to sign with.</div>'; return; }
    if (!ta.value) { if (errBox) errBox.innerHTML = '<div class="err">Enter a message first.</div>'; return; }
    const btn = body.querySelector('#signGo') as HTMLButtonElement; btnBusy(btn, 'Signing…');
    try {
      const sig = await signer.sign(ta.value);
      if (res) { res.innerHTML = sigResultHTML(sig); const cp = body.querySelector('#sigCopy') as HTMLElement | null; if (cp) cp.onclick = (e) => copyText(sig, e.currentTarget as HTMLElement); }
      if (errBox) errBox.innerHTML = '';
    } catch (e: any) { if (errBox) errBox.innerHTML = `<div class="err">Signing failed: ${esc(e?.message || String(e))}</div>`; }
    btn.disabled = false; btn.textContent = 'Sign message';
  };
}
function renderSignIn(body: HTMLElement) {
  body.innerHTML = `<div class="card" style="position:relative"><h1 class="heroH" style="font-size:22px">Sign-in <span>request</span></h1><p class="heroSub">Paste a sign-in message you were given (Sign-In With Ethereum / Solana). Syn parses every field for your review before anything is signed. This is the same flow dApps will use when WalletConnect arrives in Wave 2 — today, you bring the request yourself.</p><div style="height:14px"></div>
  <div class="field"><label>Sign-in message</label><div class="box"><textarea id="siweMsg" placeholder="example.com wants you to sign in with your…" autocomplete="off" autocapitalize="none" spellcheck="false"></textarea></div></div>
  <div id="siweErr"></div>
  <button class="ctaWide" id="siweReview" type="button">Review request</button>
  <div id="siweDetail"></div></div>`;
  const ta = body.querySelector('#siweMsg') as unknown as HTMLTextAreaElement;
  (body.querySelector('#siweReview') as HTMLButtonElement).onclick = () => {
    const errBox = body.querySelector('#siweErr'); const detail = body.querySelector('#siweDetail');
    const text = ta.value.trim();
    const parsed = parseSignInMessage(text);
    signParsed = parsed;
    if (!parsed) { if (errBox) errBox.innerHTML = '<div class="err">That does not parse as a Sign-In With Ethereum (EIP-4361) or Sign-In With Solana message. Nothing was signed.</div>'; if (detail) detail.innerHTML = ''; return; }
    if (errBox) errBox.innerHTML = '';
    const f = parsed.fields;
    const signer = parsed.family === 'evm' ? evmSigner() : solSigner();
    const timing = signInTimingProblem(f, Date.now());
    const addrMatch = signer ? (parsed.family === 'evm' ? signer.address.toLowerCase() === f.address.toLowerCase() : signer.address === f.address) : false;
    const row = (k: string, v: string) => `<div class="sumRow"><span class="sl">${esc(k)}</span><span class="sv" style="white-space:normal;word-break:break-word">${esc(v)}</span></div>`;
    if (detail) detail.innerHTML = `<div style="height:16px"></div><div class="setH">Review carefully</div>
    ${row('Sign in to (domain)', f.domain)}
    ${row('Network', parsed.family === 'evm' ? 'Ethereum / EVM' : 'Solana')}
    ${row('Your address', f.address)}
    ${f.statement ? `<div class="sumRow"><span class="sl">Statement</span></div><div class="sigBox" style="margin:6px 0 4px">${esc(f.statement)}</div>` : ''}
    ${row('URI', f.uri)}${row('Version', f.version)}${f.chainId != null ? row('Chain ID', String(f.chainId)) : ''}${row('Nonce', f.nonce)}${row('Issued at', f.issuedAt)}
    ${f.expirationTime ? row('Expires', f.expirationTime) : ''}${f.notBefore ? row('Not before', f.notBefore) : ''}${f.requestId ? row('Request ID', f.requestId) : ''}
    ${f.resources && f.resources.length ? row('Resources', f.resources.join('\n')) : ''}
    <div style="height:10px"></div>
    ${!signer ? '<div class="err">This wallet has no account on that network to sign with.</div>'
      : !addrMatch ? `<div class="err">This request is addressed to ${esc(f.address)}, but your active account is ${esc(signer.address)}. Signing it would not prove anything and could be a trick — signing is refused.</div>`
      : timing ? `<div class="err">${esc(timing)} Signing is refused.</div>`
      : `<div class="warn">You pasted this request yourself. Make sure the domain above is exactly the site you intend to sign in to — a signature made for one domain can be replayed there.</div><button class="ctaWide" id="siweSign" type="button">Sign in</button><div id="siweResult" style="margin-top:14px"></div>`}`;
    const sb = body.querySelector('#siweSign') as HTMLButtonElement | null;
    if (sb && signer) sb.onclick = async () => {
      btnBusy(sb, 'Signing…');
      try {
        const sig = await signer.sign(text);
        const res = body.querySelector('#siweResult');
        if (res) { res.innerHTML = sigResultHTML(sig) + '<p class="small muted" style="margin-top:10px;line-height:1.55">Give this signature to the site that sent the request. The message itself contains no secret — but treat the signature as proof of identity for that domain only.</p>'; const cp = body.querySelector('#sigCopy') as HTMLElement | null; if (cp) cp.onclick = (e) => copyText(sig, e.currentTarget as HTMLElement); }
      } catch (e: any) { const eb = body.querySelector('#siweErr'); if (eb) eb.innerHTML = `<div class="err">Signing failed: ${esc(e?.message || String(e))}</div>`; sb.disabled = false; sb.innerHTML = 'Sign in'; }
    };
  };
}

// ---------- token approvals viewer + revoke ----------
// Discovery comes from the GoPlus approval list (free API). Coverage is
// whatever GoPlus actually serves per chain and is labelled as such — a
// chain GoPlus does not cover is listed under "Not covered yet", never
// shown as an empty (zero-approval) result. Displayed amounts are re-read
// live from the chain before a revoke is offered. Solana has no GoPlus
// list, but SPL token-account delegates ARE readable on-chain, so those
// are listed and revocable directly.
function evmAddressOf(): string {
  if (!meta) return '';
  if (meta.kind === 'privateKey') return meta.chain === 'solana' ? '' : importedAddr;
  return derived2?.evmAddress || '';
}
function allowanceCallData(owner: string, spender: string): string {
  return '0xdd62ed3e' + owner.slice(2).toLowerCase().padStart(64, '0') + spender.slice(2).toLowerCase().padStart(64, '0');
}
async function readAllowance(c: Chain, token: string, owner: string, spender: string): Promise<bigint | null> {
  try { const res = await evmCall(c, 'eth_call', [{ to: token, data: allowanceCallData(owner, spender) }, 'latest']); return BigInt(res); } catch { return null; }
}
function showApprovals() {
  const evmAddr = evmAddressOf();
  const solChain = findChain('solana'); const solAddr = solChain ? addressFor(solChain) : '';
  const evmChains = visibleChains().filter(x => x.kind === 'evm');
  setView(`<main><button class="backBtn" id="bk" aria-label="Back"><i class="ri-arrow-left-s-line"></i></button><div class="largeTitle" style="padding-top:2px">Approvals</div>
  <div style="padding:0 16px"><p class="small muted" style="line-height:1.55">An approval lets a contract spend your tokens — including contracts you approved once and forgot. Revoking sets the allowance back to exactly zero; you pay only the network fee. Lists come from GoPlus and are verified against the chain before you revoke.</p><div style="height:12px"></div></div>
  ${evmAddr ? evmChains.map(c => `<div class="setPanel"><div class="setH">${esc(c.name)}</div><div id="appr-${c.id}"><p class="small muted" style="margin-top:6px">Checking with GoPlus…</p></div></div>`).join('') : '<div class="setPanel"><div class="setH">EVM approvals</div><p class="small muted" style="margin-top:6px">This wallet has no EVM account, so there are no ERC-20 approvals to review.</p></div>'}
  ${solAddr ? `<div class="setPanel"><div class="setH">Solana delegates</div><div class="setHSub">Read directly from your token accounts on-chain — no third-party list involved.</div><div id="appr-sol"><p class="small muted" style="margin-top:6px">Reading token accounts…</p></div></div>` : ''}
  <div id="apprSummary" style="padding:0 16px"></div></main>`);
  ($('#bk') as HTMLElement).onclick = () => goBack({ route: 'settings' });
  const covered: string[] = []; const notCovered: string[] = []; const failed: string[] = [];
  const paintSummary = () => { const s = $('#apprSummary'); if (s) s.innerHTML = `<p class="small muted" style="line-height:1.6">Coverage — checked by GoPlus: ${covered.length ? esc(covered.join(', ')) : 'none yet'}${notCovered.length ? `<br>Not covered by GoPlus yet: ${esc(notCovered.join(', '))} — approvals there are NOT shown, which is not the same as having none.` : ''}${failed.length ? `<br>Check failed (network/API error): ${esc(failed.join(', '))} — use Retry on that network.` : ''}</p>`; };
  const loadChain = async (c: Chain) => {
    const slot = document.getElementById('appr-' + c.id); if (!slot) return;
    const res = await gpApprovals(c.evmId!, evmAddr);
    if (!slot.isConnected) return;
    if (res.status === 'not-covered') { notCovered.push(c.name); slot.innerHTML = '<p class="small muted" style="margin-top:6px">Not covered by GoPlus yet — approvals on this network cannot be listed here. That does not mean you have none.</p>'; paintSummary(); return; }
    if (res.status === 'unavailable') { failed.push(c.name); slot.innerHTML = `<p class="small muted" style="margin-top:6px">The approval check failed for this network.</p><div style="height:8px"></div><button class="pillBtn" id="apprRetry-${c.id}" type="button">Retry</button>`; const rb = document.getElementById('apprRetry-' + c.id); if (rb) rb.onclick = () => { const i = failed.indexOf(c.name); if (i >= 0) failed.splice(i, 1); slot.innerHTML = '<p class="small muted" style="margin-top:6px">Checking with GoPlus…</p>'; void loadChain(c); }; paintSummary(); return; }
    covered.push(c.name); paintSummary();
    if (!res.rows.length) { slot.innerHTML = '<p class="small muted" style="margin-top:6px">No approvals found by GoPlus for your account on this network.</p>'; return; }
    slot.innerHTML = res.rows.map((r, i) => `<div class="setRow"><span style="min-width:0"><span class="setLabel">${esc(r.tokenSymbol || '?')} <span class="aSym">${esc(r.tokenName || '')}</span></span><div class="setDesc">Spender: ${r.spenderName ? esc(r.spenderName) + ' · ' : ''}${esc(r.spender.slice(0, 8))}…${esc(r.spender.slice(-6))}${r.approvedTime ? ' · approved ' + new Date(r.approvedTime * 1000).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }) : ''}</div>${r.spenderMalicious ? '<div class="setDesc" style="color:var(--red)">GoPlus flags this spender\'s behaviour as malicious.</div>' : r.spenderDoubt ? '<div class="setDesc" style="color:var(--amber)">GoPlus marks this spender as doubtful.</div>' : ''}<div class="setDesc" data-allow-note="${c.id}:${i}"></div></span><span style="text-align:right;flex:none;max-width:44%"><div class="sv" style="overflow-wrap:anywhere" data-allow="${c.id}:${i}">…</div><div style="height:6px"></div><button class="pillBtn danger" data-revoke="${c.id}:${i}" type="button">Revoke</button></span></div>`).join('');
    slot.querySelectorAll('[data-revoke]').forEach(b => (b as HTMLElement).onclick = () => {
      const [cid, ix] = ((b as HTMLElement).dataset.revoke || '').split(':'); const chain = findChain(cid); const r = res.rows[Number(ix)];
      if (!chain || !r) return;
      feeState = freshFeeState();
      go({ route: 'revoke', revoke: { family: 'evm', chainId: chain.id, tokenAddress: r.tokenAddress, tokenSymbol: r.tokenSymbol, tokenName: r.tokenName, decimals: r.decimals, spender: r.spender, spenderName: r.spenderName } }, b as HTMLElement);
    });
    // Verify each allowance live on-chain; a row whose live allowance is
    // already zero loses its Revoke button — GoPlus can lag the chain.
    for (let i = 0; i < res.rows.length; i++) {
      const r = res.rows[i];
      const live = await readAllowance(c, r.tokenAddress, evmAddr, r.spender);
      if (!slot.isConnected) return;
      const cell = slot.querySelector(`[data-allow="${c.id}:${i}"]`); const note = slot.querySelector(`[data-allow-note="${c.id}:${i}"]`); const btn = slot.querySelector(`[data-revoke="${c.id}:${i}"]`) as HTMLButtonElement | null;
      if (live === null) {
        if (cell) cell.textContent = isUnlimitedAmount(r.approvedAmount) ? 'Unlimited' : formatTokenAmount((() => { try { return BigInt(r.approvedAmount); } catch { return 0n; } })(), r.decimals) + ' ' + r.tokenSymbol;
        if (note) note.textContent = 'Amount per GoPlus — the live on-chain check failed, re-check on the revoke screen.';
        continue;
      }
      if (live === 0n) { if (cell) cell.textContent = '0'; if (note) note.textContent = 'Allowance is already zero on-chain.'; if (btn) { btn.disabled = true; btn.textContent = 'Set to zero'; btn.style.opacity = '.45'; } continue; }
      if (cell) { const unlim = live >= (1n << 255n); const huge = !unlim && live > (10n ** BigInt(Math.max(0, r.decimals))) * (10n ** 12n); cell.textContent = unlim ? 'Unlimited' : formatTokenAmount(live, r.decimals) + ' ' + r.tokenSymbol; if (unlim || huge) (cell as HTMLElement).style.color = 'var(--red)'; (cell as HTMLElement).dataset.huge = huge ? '1' : ''; }
      if (note) { const huge = (cell as HTMLElement | null)?.dataset.huge === '1'; note.textContent = 'Verified live on-chain just now.' + (huge ? ' This allowance is astronomically large — treat it like unlimited.' : ''); if (huge) (note as HTMLElement).style.color = 'var(--amber)'; }
    }
  };
  (async () => { for (const c of evmChains) { await loadChain(c); } })();
  if (solAddr) void loadSolDelegates(solAddr);
}
interface SolDelegate { mint: string; delegate: string; amount: string; decimals: number; account: string; program: string; }
async function loadSolDelegates(solAddr: string) {
  const slot = document.getElementById('appr-sol'); if (!slot) return;
  try {
    // Audit fix: Token-2022 accounts were never queried — their
    // delegates were invisible (and unrevocable) here. Both token
    // programs are read and merged; the program travels with the row
    // so the revoke instruction targets the right program.
    const TOKEN_2022 = 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb';
    const out: SolDelegate[] = [];
    for (const programId of ['TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA', TOKEN_2022]) {
      const v = await solanaRpcCall('getTokenAccountsByOwner', [solAddr, { programId }, { encoding: 'jsonParsed' }]);
      for (const a of (v?.value || [])) {
        const info = a?.account?.data?.parsed?.info;
        if (info?.delegate) out.push({ mint: String(info.mint || ''), delegate: String(info.delegate), amount: String(info.delegatedAmount?.uiAmountString ?? info.delegatedAmount?.uiAmount ?? '0'), decimals: Number(info.delegatedAmount?.decimals ?? info.tokenAmount?.decimals ?? 0), account: String(a.pubkey || ''), program: programId });
      }
    }
    if (!slot.isConnected) return;
    if (!out.length) { slot.innerHTML = '<p class="small muted" style="margin-top:6px">No token account delegates found for your main Solana account.</p>'; return; }
    const symOf = (mint: string) => BUILTIN_TOKENS.find(t => t.chainId === 'solana' && t.contract === mint)?.symbol || '';
    slot.innerHTML = out.map((d, i) => `<div class="setRow"><span style="min-width:0"><span class="setLabel">${esc(symOf(d.mint) || 'SPL token')} <span class="aSym">${esc(d.mint.slice(0, 8))}…</span></span><div class="setDesc">Delegate: ${esc(d.delegate.slice(0, 8))}…${esc(d.delegate.slice(-6))} · can spend up to the delegated amount</div></span><span style="text-align:right;flex:none"><div class="sv">${esc(d.amount)} ${esc(symOf(d.mint))}</div><div style="height:6px"></div><button class="pillBtn danger" data-solrevoke="${i}" type="button">Revoke</button></span></div>`).join('');
    slot.querySelectorAll('[data-solrevoke]').forEach(b => (b as HTMLElement).onclick = () => {
      const d = out[Number((b as HTMLElement).dataset.solrevoke)];
      go({ route: 'revoke', revoke: { family: 'solana', chainId: 'solana', tokenAddress: d.mint, tokenSymbol: symOf(d.mint) || 'SPL', tokenName: 'SPL token', decimals: d.decimals, spender: d.delegate, spenderName: '', tokenAccount: d.account, tokenProgram: d.program } }, b as HTMLElement);
    });
  } catch { if (slot.isConnected) slot.innerHTML = '<p class="small muted" style="margin-top:6px">Could not read your Solana token accounts right now.</p>'; }
}
function showRevokeConfirm(p: RevokePayload, err = '') {
  const c = findChain(p.chainId); if (!c) { go({ route: 'approvals' }); return; }
  const isEvm = p.family === 'evm';
  setView(`<main><button class="backBtn" id="bk" aria-label="Back"><i class="ri-arrow-left-s-line"></i></button>
  <div class="card" style="position:relative"><h1 class="heroH">Revoke <span>approval</span></h1><p class="heroSub" style="margin-top:2px">This sets the allowance to exactly zero</p><div style="height:8px"></div>${err ? `<div class="err">${esc(err)}</div>` : ''}
  <div class="sumRow"><span class="sl">Token</span><span class="sv">${esc(p.tokenName || p.tokenSymbol)} (${esc(p.tokenSymbol)})</span></div>
  <div class="sumRow"><span class="sl">Network</span><span class="sv">${esc(c.name)}</span></div>
  <div class="sumRow"><span class="sl">${isEvm ? 'Spender' : 'Delegate'}</span><span class="sv"><span class="monoChip" style="max-width:210px" data-full="${esc(p.spender)}">${esc(p.spender.slice(0, 10))}…${esc(p.spender.slice(-8))}</span></span></div>
  ${p.spenderName ? `<div class="sumRow"><span class="sl">Contract name</span><span class="sv">${esc(p.spenderName)}</span></div>` : ''}
  <div class="sumRow"><span class="sl">Current allowance</span><span class="sv" id="revAllow">${waveLoadHTML('sm')} Checking on-chain…</span></div>
  <div class="sumRow"><span class="sl">Network fee</span><span class="sv" id="revFee">${waveLoadHTML('sm')}</span></div>
  ${gasBoxHTML(c)}
  <p class="securityNote" style="margin:12px 0">${isEvm ? 'Revoking sends a real approve(spender, 0) transaction signed locally on this device. The spender will no longer be able to move this token from your account. This does not affect your balance.' : 'Revoking removes this delegate from your token account with a transaction signed locally on this device. The delegate will no longer be able to move those tokens. This does not affect your balance.'}</p>
  <button class="ctaWide" id="revokeBtn" type="button">Revoke approval</button><div style="height:10px"></div><button class="btnGhost" id="revCancel" type="button" style="border-radius:999px">Cancel</button></div></main>`);
  let gasLimitEst = 50000n;
  const updateRevFee = () => { const fc = $('#revFee'); if (!fc) return; if (!isEvm) { fc.textContent = '~0.000005 SOL'; return; } const txt = feeCostText(c, gasLimitEst); if (txt) fc.textContent = txt; else if (feeState.mode === 'custom') fc.textContent = 'Enter valid custom fees'; else fc.innerHTML = waveLoadHTML('sm'); };
  if (isEvm) {
    bindGasBox(c, () => gasLimitEst, updateRevFee);
    (async () => {
      const owner = evmAddressOf();
      const live = await readAllowance(c, p.tokenAddress, owner, p.spender);
      const cell = $('#revAllow');
      if (cell) cell.textContent = live === null ? 'Could not be read — check the explorer before revoking' : live === 0n ? 'Already zero on-chain — nothing to revoke' : live >= (1n << 255n) ? 'Unlimited' : formatTokenAmount(live, p.decimals) + ' ' + p.tokenSymbol;
      const btn = $('#revokeBtn') as HTMLButtonElement | null; if (btn && live === 0n) { btn.disabled = true; btn.textContent = 'Already revoked'; }
      try { const data = new ethers.Interface(['function approve(address spender, uint256 value) returns (bool)']).encodeFunctionData('approve', [p.spender, 0n]); const est = await evmCall(c, 'eth_estimateGas', [{ from: owner, to: p.tokenAddress, data }]); gasLimitEst = BigInt(est); updateRevFee(); } catch { /* keep the 50k display estimate */ }
    })();
  } else {
    (async () => {
      try {
        const v = await solanaRpcCall('getAccountInfo', [p.tokenAccount!, { encoding: 'jsonParsed' }]);
        const info = v?.value?.data?.parsed?.info;
        const cell = $('#revAllow');
        if (cell) cell.textContent = info?.delegate ? `${info.delegatedAmount?.uiAmountString ?? info.delegatedAmount?.uiAmount ?? '0'} ${p.tokenSymbol} delegated` : 'Delegate already removed on-chain';
        const btn = $('#revokeBtn') as HTMLButtonElement | null; if (btn && !info?.delegate) { btn.disabled = true; btn.textContent = 'Already revoked'; }
      } catch { const cell = $('#revAllow'); if (cell) cell.textContent = 'Could not be read — check the explorer before revoking'; }
    })();
  }
  updateRevFee();
  ($('#bk') as HTMLElement).onclick = () => goBack({ route: 'approvals' }); ($('#revCancel') as HTMLElement).onclick = () => goBack({ route: 'approvals' });
  ($('#revokeBtn') as HTMLButtonElement).onclick = async () => {
    const problem = customFeeProblem();
    if (problem) { showRevokeConfirm(p, problem); return; }
    const btn = $('#revokeBtn') as HTMLButtonElement; btnBusy(btn, 'Signing & broadcasting…');
    try {
      const overrides = isEvm ? (chosenFees(feeState, feeInfo)?.overrides || {}) : {};
      const hash = await doRevoke(p, overrides); recordLocalTx(c.id, hash, `Revoked ${p.tokenSymbol} approval`, { dir: 'approve', sym: p.tokenSymbol });
      celebrate(btn, () => {
        setView(receiptHTML({ title: 'Approval revoked', sub: `${p.tokenSymbol} · ${c.name}`, hash, doneLabel: 'Back to approvals' }));
        bindReceipt(hash, c.explorerTx, (el) => go({ route: 'approvals' }, el));
      });
    } catch (e: any) { showRevokeConfirm(p, 'Revoke failed: ' + (e?.shortMessage || e?.message || String(e))); }
  };
}
async function doRevoke(p: RevokePayload, feeOverrides: Record<string, bigint> = {}): Promise<string> {
  if (p.family === 'evm') {
    const c = findChain(p.chainId)!;
    const pk = meta?.kind === 'privateKey' ? (secret!.startsWith('0x') ? secret! : '0x' + secret!) : derived2!.evmPrivateKey;
    const provider = new ethers.JsonRpcProvider(evmProviderUrl(c), c.evmId);
    const wallet = new ethers.Wallet(pk, provider);
    const contract = new ethers.Contract(p.tokenAddress, ['function approve(address spender, uint256 value) returns (bool)'], wallet);
    const tx = Object.keys(feeOverrides).length ? await contract.approve(p.spender, 0n, feeOverrides) : await contract.approve(p.spender, 0n);
    return tx.hash;
  }
  const kp: Keypair = meta?.kind === 'privateKey' ? importedSolKp! : Keypair.fromSeed(derived2!.solSeed32);
  const conn = new Connection(solanaRpcUrl(), 'confirmed');
  const tx = new Transaction().add(createRevokeInstruction(new PublicKey(p.tokenAccount!), kp.publicKey, [], p.tokenProgram ? new PublicKey(p.tokenProgram) : undefined));
  const { blockhash } = await conn.getLatestBlockhash('confirmed'); tx.recentBlockhash = blockhash; tx.feePayer = kp.publicKey; tx.sign(kp);
  return await sendSolanaSigned(conn, tx.serialize(), bs58.encode(tx.signature!));
}

// ---------- Wave 2: feature config (operator-enabled services) ----------
// WalletConnect (Reown project ID) and MoonPay (publishable key) are the
// operator's own free credentials, served by /api/config from server
// environment variables. Empty = the feature stays honestly gated in
// the UI. These are publishable identifiers, never secret keys.
let featureCfg = { walletConnectProjectId: '', moonpayPublishableKey: '', polymarketBuilderConfigured: false, polymarketBuilderCode: '', polymarketBuilderAddress: '', twApiConfigured: false };
let featureCfgLoaded = false;
async function loadFeatureCfg(): Promise<void> {
  if (featureCfgLoaded) return;
  featureCfgLoaded = true;
  try {
    const r = await fetch('/api/config');
    if (r.ok) { const j = await r.json(); featureCfg = { walletConnectProjectId: String(j?.walletConnectProjectId || ''), moonpayPublishableKey: String(j?.moonpayPublishableKey || ''), polymarketBuilderConfigured: !!j?.polymarketBuilderConfigured, polymarketBuilderCode: String(j?.polymarketBuilderCode || ''), polymarketBuilderAddress: String(j?.polymarketBuilderAddress || ''), twApiConfigured: !!j?.twApiConfigured }; setTwEnabled(featureCfg.twApiConfigured); }
  } catch { /* stays gated */ }
}
// The Solana keypair for a Solana-family chain of the ACTIVE wallet.
function solanaKeypairFor(kind: ChainKind): Keypair | null {
  if (meta?.kind === 'privateKey') return meta.chain === 'solana' ? importedSolKp : null;
  if (!derived2) return null;
  if (kind === 'solana-tw') return Keypair.fromSeed(derived2.solTWSeed32);
  if (kind === 'solana-phantom') return Keypair.fromSeed(derived2.solPhantomSeed32);
  if (kind === 'solana') return Keypair.fromSeed(derived2.solSeed32);
  return null;
}
function evmPrivKey(): string | null {
  if (meta?.kind === 'privateKey') return meta.chain === 'solana' ? null : (secret!.startsWith('0x') ? secret! : '0x' + secret!);
  return derived2 ? derived2.evmPrivateKey : null;
}
function deserializeSolTx(bytes: Uint8Array): VersionedTransaction | Transaction {
  try { return VersionedTransaction.deserialize(bytes); } catch { return Transaction.from(bytes); }
}

// ---------- Wave 2: swaps (Jupiter for Solana, LI.FI for EVM/cross-chain) ----------
// ---------- shared picker sheet (Addition 11) ----------
// ONE bottom-sheet implementation — scaffold, search, ordering (the
// caller's), paste-an-address resolution, honest empty states —
// consumed by Swap, Send and Receive in three configurations. There
// are no forked copies: the modes differ only in the rows they pass
// and what a pick does.
export interface PickerRow { key: string; html: string; disabled?: boolean; searchText: string; net?: string }
interface PickerOpts {
  title: string;
  placeholder?: string;
  rows: () => PickerRow[];
  onPick: (key: string) => void;
  resolveAddress?: (addr: string) => Promise<PickerRow | null>;
  onResolvedPick?: (row: PickerRow) => void;
  emptyText?: (q: string) => string;
  footer?: string;
  // Network scoping: when `networks` is given, a chip rail renders
  // under the search box and the list shows only the selected
  // network's rows (each row carries its chain id in `net`). With
  // `allNetLabel` the rail starts with an All chip (id ''); without
  // it, a network is always selected (Receive's model).
  networks?: { id: string; label: string; iconHtml?: string }[];
  initialNet?: string;
  allNetLabel?: string;
}
interface PickerHandle { refresh: () => void; close: () => void; isOpen: () => boolean }
const pickerLooksLikeAddress = (s: string) => /^0x[0-9a-fA-F]{40}$/.test(s) || /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(s);
function openPickerSheet(opts: PickerOpts): PickerHandle {
  document.querySelectorAll('.pickerWrap').forEach(el => el.remove());
  const wrap = document.createElement('div');
  wrap.className = 'sheetWrap pickerWrap hidden';
  wrap.innerHTML = `<div class="sheetBk"></div>
    <div class="sheet" role="dialog" aria-label="${esc(opts.title)}">
      <div class="sheetGrabZone"><div class="sheetGrab"></div></div>
      <div class="sheetHead"><span class="sheetTitle">${esc(opts.title)}</span><button class="sheetX" type="button" aria-label="Close"><i class="ri-close-line"></i></button></div>
      <div class="sheetSearch"><i class="ri-search-line"></i><input placeholder="${esc(opts.placeholder || 'Search name or symbol, or paste an address')}" autocomplete="off" autocapitalize="none" spellcheck="false"><button class="sheetClear hidden" type="button" aria-label="Clear search"><i class="ri-close-circle-fill"></i></button></div>
      ${opts.networks && opts.networks.length ? '<div class="sheetNets" role="tablist" aria-label="Network"></div>' : ''}
      <div class="sheetList"></div>
      ${opts.footer ? `<div class="sheetFoot">${opts.footer}</div>` : ''}
    </div>`;
  document.body.appendChild(wrap);
  const listEl = wrap.querySelector('.sheetList') as HTMLElement;
  const netsEl = wrap.querySelector('.sheetNets') as HTMLElement | null;
  const input = wrap.querySelector('.sheetSearch input') as unknown as HTMLInputElement;
  const clearBtn = wrap.querySelector('.sheetClear') as HTMLElement;
  let query = ''; let resolved: PickerRow | null = null; let resolving = false; let seq = 0; let closed = false; let resDeb: any = null;
  let netSel = opts.initialNet ?? (opts.allNetLabel ? '' : (opts.networks?.[0]?.id ?? ''));
  const paintNets = () => {
    if (!netsEl || !opts.networks) return;
    const chips = [...(opts.allNetLabel ? [{ id: '', label: opts.allNetLabel, iconHtml: '' }] : []), ...opts.networks];
    netsEl.innerHTML = chips.map(n => `<button class="netChip sheetNet ${n.id === netSel ? 'on' : ''}" data-net="${esc(n.id)}" type="button" role="tab" aria-selected="${n.id === netSel}">${n.iconHtml || ''}<span>${esc(n.label)}</span></button>`).join('');
    netsEl.querySelectorAll('[data-net]').forEach(b => (b as HTMLElement).onclick = () => { netSel = (b as HTMLElement).dataset.net!; paintNets(); paint(); });
    const on = netsEl.querySelector('.sheetNet.on') as HTMLElement | null;
    if (on) netsEl.scrollTo({ left: Math.max(0, on.offsetLeft - 12) });
  };
  const rowBtn = (r: PickerRow, isResolved = false) => `<button class="sheetRow" data-pick="${esc(r.key)}" ${isResolved ? 'data-resolved="1"' : ''} type="button" ${r.disabled ? 'disabled' : ''}>${r.html}</button>`;
  const paint = () => {
    const q = query.trim().toLowerCase();
    const addrLike = pickerLooksLikeAddress(query.trim());
    let rows = opts.rows();
    if (opts.networks && netSel) rows = rows.filter(r => (r.net ?? '') === netSel);
    if (q && !addrLike) rows = rows.filter(r => r.searchText.includes(q));
    let html = '';
    if (resolved) html += '<div class="sheetGroupH">Found by address</div>' + rowBtn(resolved, true);
    else if (resolving) html += `<div class="sheetEmpty">${waveLoadHTML('sm')} Looking up that address on-chain…</div>`;
    else if (addrLike && opts.resolveAddress) html += '<div class="sheetEmpty">Token not found for that address</div>';
    if (rows.length) html += rows.map(r => rowBtn(r)).join('');
    else if (!resolved && !resolving && q && !addrLike) html += `<div class="sheetEmpty">${esc(opts.emptyText ? opts.emptyText(query.trim()) : `No matches for '${query.trim()}'`)}</div>`;
    listEl.innerHTML = html || '<div class="sheetEmpty">Nothing to show</div>';
    listEl.querySelectorAll('[data-pick]').forEach(b => (b as HTMLElement).onclick = () => {
      if ((b as HTMLButtonElement).disabled) return;
      if ((b as HTMLElement).dataset.resolved) { if (opts.onResolvedPick) opts.onResolvedPick(resolved!); else opts.onPick(resolved!.key); return; }
      opts.onPick((b as HTMLElement).dataset.pick!);
    });
  };
  const doResolve = async (addr: string) => {
    const my = ++seq; resolving = true; resolved = null; paint();
    let row: PickerRow | null = null;
    try { row = await opts.resolveAddress!(addr); } catch { row = null; }
    if (my !== seq || closed) return;
    resolved = row; resolving = false; paint();
  };
  input.addEventListener('input', () => {
    query = input.value;
    clearBtn.classList.toggle('hidden', !query);
    resolved = null; resolving = false; seq++;
    clearTimeout(resDeb);
    const addr = query.trim();
    if (opts.resolveAddress && pickerLooksLikeAddress(addr)) { paint(); resDeb = setTimeout(() => void doResolve(addr), 600); }
    else paint();
  });
  clearBtn.onclick = () => { input.value = ''; query = ''; resolved = null; seq++; clearBtn.classList.add('hidden'); paint(); input.focus(); };
  const close = () => { if (closed) return; closed = true; seq++; wrap.classList.remove('open'); setTimeout(() => wrap.remove(), 320); };
  (wrap.querySelector('.sheetBk') as HTMLElement).onclick = close;
  (wrap.querySelector('.sheetX') as HTMLElement).onclick = close;
  const grab = wrap.querySelector('.sheetGrabZone') as HTMLElement; const sheetEl = wrap.querySelector('.sheet') as HTMLElement;
  let sy = 0; let dy = 0;
  grab.addEventListener('touchstart', e => { sy = e.touches[0].clientY; dy = 0; sheetEl.style.transition = 'none'; }, { passive: true });
  grab.addEventListener('touchmove', e => { dy = Math.max(0, e.touches[0].clientY - sy); sheetEl.style.transform = `translateY(${dy}px)`; }, { passive: true });
  grab.addEventListener('touchend', () => { sheetEl.style.transition = ''; sheetEl.style.transform = ''; if (dy > 90) close(); dy = 0; }, { passive: true });
  paintNets();
  paint();
  wrap.classList.remove('hidden');
  requestAnimationFrame(() => requestAnimationFrame(() => wrap.classList.add('open')));
  setTimeout(() => { try { input.focus({ preventScroll: true }); } catch { /* headless */ } }, 340);
  return { refresh: () => { if (!closed) paint(); }, close, isOpen: () => !closed && wrap.isConnected };
}

// Address → token resolution for the picker configurations: reads the
// token's metadata on-chain (the Wave 1A custom-token machinery) on the
// enabled chains, best candidate first. Null = resolves to nothing.
async function resolveTokenAddress(addr: string): Promise<{ c: Chain; contract: string; meta: { name: string; symbol: string; decimals: number } } | null> {
  const isEvm = /^0x/.test(addr);
  const rank = (id: string) => { const i = DEFAULT_ENABLED.indexOf(id); return i < 0 ? 99 : i; };
  const candidates: Chain[] = isEvm
    ? CHAINS.filter(c => c.kind === 'evm' && enabledSet().has(c.id)).sort((a, b) => rank(a.id) - rank(b.id))
    : [findChain('solana')].filter((c): c is Chain => !!c);
  for (const c of candidates) {
    let meta: { name: string; symbol: string; decimals: number } | null = null;
    try { meta = await fetchTokenMeta(c, addr); } catch { meta = null; }
    if (meta && typeof meta.decimals === 'number' && (meta.symbol || !isEvm)) return { c, contract: addr, meta };
  }
  return null;
}
/** A resolved token becomes selectable: the known TokenDef if the
 * contract is already registered, else a new custom token (persisted). */
function ensureCustomToken(r: { c: Chain; contract: string; meta: { name: string; symbol: string; decimals: number } }): TokenDef {
  const known = findTokenByContract(r.c.id, r.contract);
  if (known) return known;
  const t: TokenDef = { id: 'ct-' + Date.now().toString(36), chainId: r.c.id, contract: r.contract, name: r.meta.name || r.meta.symbol || 'Unknown token', symbol: (r.meta.symbol || 'TOKEN').toUpperCase(), decimals: r.meta.decimals };
  config.tokens.push(t); saveConfig();
  void fetchTokenBalance(t).then(v => { tokenBalances.set(t.id, v); saveDataCache(); });
  return t;
}

interface SwapAsset extends PickerAsset { img: string }
function chainSwappable(c: Chain): boolean { return c.kind === 'evm' || c.kind === 'solana' || c.kind === 'solana-tw' || c.kind === 'solana-phantom'; }
function withAssetImg(a: PickerAsset): SwapAsset { return { ...a, img: a.contract === 'native' ? chainIconUrl(findChain(a.chainId)!) : tokenIconUrl(findToken(a.tokenId!)!) }; }
function swapAssets(): SwapAsset[] {
  // Set construction lives in lib/pickerassets (unit-tested): every
  // visible chain's native + every token hosted on it — built-ins and
  // custom tokens alike, de-duped by chain+contract. Every visible
  // chain's native asset is listed (the selector shows receive-only
  // networks' assets too — disabled on the pay side, no-route on the
  // receive side — instead of hiding them). TW-path token balances are
  // not tracked separately, so 'solana-tw' contributes its native only
  // and its stored tokens live under 'solana' (pickerChainId).
  return buildPickerAssets(visibleChains(), visibleTokens()).map(withAssetImg);
}
function assetSwappable(a: SwapAsset): boolean { const c = findChain(a.chainId); return !!c && chainSwappable(c); }
// Selector ordering: what the user HOLDS first (USD value desc), then
// the major routable assets (natives + the built-in stables), then the
// rest A–Z. Ordering is a sort over the complete set, never a filter.
function pickerUsdOf(a: PickerAsset): number { const b = swapAssetBalance(a as SwapAsset); const p = swapAssetPrice(a as SwapAsset); return b != null && p != null && b > 0 ? b * p : -1; }
function pickerChainRank(a: PickerAsset): number { const i = DEFAULT_ENABLED.indexOf(a.chainId); return i < 0 ? 99 : i; }
function sortedSwapAssets(): SwapAsset[] { return sortPickerAssets(swapAssets(), pickerUsdOf, pickerChainRank) as SwapAsset[]; }
// ---------- Send configuration of the shared picker (Addition 11) ----------
// Sendable = native assets of sendable chains + tokens on EVM/Solana
// chains. Same ordering discipline as Swap's: held first by USD value,
// then majors, then A–Z.
function sendableAssets(): SwapAsset[] { return filterSendableAssets(swapAssets(), id => findChain(id)?.kind, SENDABLE_KINDS) as SwapAsset[]; }
function sortedSendAssets(): SwapAsset[] { return sortPickerAssets(sendableAssets(), pickerUsdOf, pickerChainRank) as SwapAsset[]; }
function assetSheetRowInner(a: SwapAsset, selectedKey: string): string {
  const c = findChain(a.chainId);
  const b = swapAssetBalance(a); const p = swapAssetPrice(a); const st = swapAssetState(a);
  return `${iconHTML(a.img, a.symbol, a.name)}
    <span class="shTx"><span class="shName">${esc(a.name)} <span class="aSym">${esc(a.symbol)}</span></span><span class="shNet">${esc(c?.name || '')}</span></span>
    <span class="shRight">${b != null ? `<span class="shBal">${trimNum(b)} ${esc(a.symbol)}</span><span class="shUsd">${p != null ? fmtUsd(b * p) : ''}</span>` : `<span class="shUsd">${st === 'pending' ? 'Loading…' : ''}</span>`}</span>
    ${a.key === selectedKey ? '<span class="arrowChip grad"><i class="ri-check-line"></i></span>' : ''}`;
}
/** The picker's network rail: every chain that contributes at least
 * one row to the given set, in visible-chains order. A rail entry with
 * zero rows can never be produced — no dead networks. */
function pickerNetworks(assets: SwapAsset[]): { id: string; label: string; iconHtml: string }[] {
  const have = new Set(assets.map(a => a.chainId));
  return visibleChains().filter(c => have.has(c.id)).map(c => ({ id: c.id, label: c.name, iconHtml: coinIcon(c) }));
}
function openSendPicker(currentKey: string, onPick: (a: SwapAsset) => void, initialNet = ''): PickerHandle {
  let resolvedData: { c: Chain; contract: string; meta: { name: string; symbol: string; decimals: number } } | null = null;
  const handle = openPickerSheet({
    title: 'Select asset',
    networks: pickerNetworks(sendableAssets()),
    initialNet,
    allNetLabel: 'All networks',
    rows: () => sortedSendAssets().map(a => ({ key: a.key, net: a.chainId, searchText: (a.name + ' ' + a.symbol + ' ' + (findChain(a.chainId)?.name || '')).toLowerCase(), html: assetSheetRowInner(a, currentKey) })),
    onPick: (key) => { const a = sendableAssets().find(x => x.key === key); if (a) { handle.close(); onPick(a); } },
    resolveAddress: async (addr) => { const r = await resolveTokenAddress(addr); if (!r) return null; resolvedData = r; return { key: '__resolved', searchText: '', html: `${iconHTML('', r.meta.symbol || '?', r.meta.name)}<span class="shTx"><span class="shName">${esc(r.meta.name || 'Unknown token')} <span class="aSym">${esc(r.meta.symbol || '')}</span></span><span class="shNet">${esc(r.c.name)} · ${esc(addr.slice(0, 10))}…${esc(addr.slice(-6))}</span></span><span class="arrowChip"><i class="ri-arrow-right-line"></i></span>` }; },
    onResolvedPick: () => { if (!resolvedData) return; const t = ensureCustomToken(resolvedData); const a = sendableAssets().find(x => x.tokenId === t.id); handle.close(); if (a) onPick(a); },
    emptyText: (q) => `No tokens match '${q}'`,
  });
  return handle;
}

function findTokenByContract(chainId: string, contract: string): TokenDef | undefined {
  return [...BUILTIN_TOKENS, ...config.tokens].find(t => t.chainId === chainId && t.contract.toLowerCase() === contract.toLowerCase());
}
function swapAssetBalance(a: SwapAsset): number | null {
  if (a.contract === 'native') { const v = balances.get(a.chainId); return v === undefined ? null : v; }
  if (a.tokenId) { const v = tokenBalances.get(a.tokenId); return v === undefined ? null : v; }
  return null;
}
function isSolAsset(a: SwapAsset): boolean { const c = findChain(a.chainId); return !!c && (c.kind === 'solana' || c.kind === 'solana-tw' || c.kind === 'solana-phantom'); }
let swapFromKey = ''; let swapToKey = ''; let swapAmount = ''; let swapSlippageBps = 50;
// Addition 8: slippage control state. Custom mode is explicit (a custom
// value may coincide with a preset), and the custom text persists for
// the session across pair changes and flips — never silently reset.
let swapSlipCustomOn = false;
let swapSlipCustomText = '';
let swapQuote: SwapQuote | null = null; let swapQuoteErr = ''; let swapQuoteSig = ''; let swapSeq = 0; let swapTimer: any = null;
function presetSwapFrom(chainId: string, tokenId?: string) {
  const list = swapAssets();
  const hit = tokenId ? list.find(a => a.tokenId === tokenId) : list.find(a => a.chainId === chainId && a.contract === 'native');
  if (hit) { swapFromKey = hit.key; if (swapToKey === hit.key) swapToKey = ''; swapQuote = null; swapQuoteSig = ''; }
}
// Quote failure taxonomy — the user's next action differs per kind,
// so the UI never collapses them into one generic error:
//   noroute     — the pair is unsupported; pick a different pair.
//   noliquidity — amount too small / no liquidity at this size; try more.
//   provider    — network/provider error; the background re-quote retries.
type QuoteFailKind = 'noroute' | 'noliquidity' | 'provider';
function classifyQuoteError(e: any): QuoteFailKind {
  if (e?.qk) return e.qk as QuoteFailKind;
  const m = String(e?.message || '').toLowerCase();
  if (/no route|no routes|no available quotes|no quotes|route not found|could not find|not routable|no token accounts/.test(m)) return 'noroute';
  if (/too small|amount is too|minimum amount|insufficient liquidity|not enough liquidity|dust|less than the minimum/.test(m)) return 'noliquidity';
  return 'provider';
}
async function fetchSwapQuote(from: SwapAsset, to: SwapAsset, rawIn: string, bps: number): Promise<SwapQuote> {
  const fc = findChain(from.chainId)!; const tc = findChain(to.chainId)!;
  // A side on a receive-only / non-routable network can never produce a
  // quote through Syn's providers — answer NO ROUTE directly instead of
  // calling a provider with a chain it cannot settle.
  if (!chainSwappable(fc) || !chainSwappable(tc)) throw Object.assign(new Error('No route available for this pair'), { qk: 'noroute' as QuoteFailKind });
  if (isSolAsset(from) && isSolAsset(to)) {
    const j = await fetchJupiterQuote(from.contract === 'native' ? JUP_SOL_MINT : from.contract, to.contract === 'native' ? JUP_SOL_MINT : to.contract, rawIn, bps);
    const q = normalizeJupiterQuote(j, rawIn, from.decimals, to.decimals, bps);
    if (!q) throw new Error('Jupiter returned no route for this pair right now.');
    return q;
  }
  const j = await fetchLifiQuote({
    fromChain: isSolAsset(from) ? LIFI_SOLANA_CHAIN_ID : fc.evmId!,
    toChain: isSolAsset(to) ? LIFI_SOLANA_CHAIN_ID : tc.evmId!,
    fromToken: isSolAsset(from) ? (from.contract === 'native' ? LIFI_NATIVE_SOL : from.contract) : (from.contract === 'native' ? LIFI_NATIVE_EVM : from.contract),
    toToken: isSolAsset(to) ? (to.contract === 'native' ? LIFI_NATIVE_SOL : to.contract) : (to.contract === 'native' ? LIFI_NATIVE_EVM : to.contract),
    fromAmountRaw: rawIn,
    fromAddress: addressFor(fc),
    toAddress: addressFor(tc),
    slippage: bps / 10000,
  });
  const q = normalizeLifiQuote(j, from.decimals, to.decimals);
  if (!q) throw new Error('LI.FI returned no route for this pair right now.');
  return q;
}
function swapSignature(from: SwapAsset, to: SwapAsset, rawIn: string, bps: number): string { return `${from.key}>${to.key}:${rawIn}:${bps}`; }
// ---------- swap screen v3: compact card, atomic state, live re-quote,
// bottom-sheet selector with search, honest route failures ----------
// One card, two halves (You pay / You receive) divided by the flip
// button overlapping the seam. Selecting a coin, flipping, or a price
// tick repaints EVERY dependent field in the same frame from module
// state (no full-screen re-render, no field keeps a value from the
// previous pair), and quote requests are sequence-guarded: a response
// for anything but the latest (pair, amount, slippage) is discarded.
// Quote failures are classified (noroute / noliquidity / provider) and
// each lands on its own honest state — never a generic error, never a
// stale actionable quote.
let swapPicker: PickerHandle | null = null;   // the shared selector sheet, while open on Swap
let swapStale = false;   // a background re-quote failed — last good quote shown, marked stale, CTA off
let swapErrKind: QuoteFailKind | '' = '';
let lastQuoteAt = 0;     // last successful quote (drives tick re-quote debounce)
function swapAssetPrice(a: SwapAsset): number | null {
  if (a.contract === 'native') { const c = findChain(a.chainId); return c ? priceOf(c) : null; }
  if (a.tokenId) { const t = findToken(a.tokenId); return t ? tokenUsd(t) : null; }
  return null;
}
function swapAssetState(a: SwapAsset): LoadState {
  return a.contract === 'native' ? balStateOf(a.chainId) : a.tokenId ? tokStateOf(a.tokenId) : 'failed';
}
// Price-engine tick while the Swap screen is open: repaint balances /
// USD figures in place and re-quote in the background when the last
// quote is older than ~15s. Silent — no loader, no flash (the
// invisible-update rule); leaving the screen stops all of it.
function onSwapPricesTick() {
  if (currentRoute !== 'swap') return;
  const paint = (window as any).__synPaintSwap as undefined | (() => void);
  if (paint) paint();
  if (!swapAmount || !(parseFloat(swapAmount) > 0)) return;
  if (Date.now() - lastQuoteAt < 15000) return;
  const rq = (window as any).__synRequestSwapQuote as undefined | ((b?: boolean) => void);
  if (rq) rq(true);
}
function showSwap() {
  const list = swapAssets();
  if (!list.length) { setView(`<main><button class="backBtn" id="bk" aria-label="Back"><i class="ri-arrow-left-s-line"></i></button><div class="card"><h1 class="heroH">Swap</h1><p class="heroSub">No swappable networks are enabled. Enable Solana or an EVM network in Networks first.</p></div></main>`); ($('#bk') as HTMLElement).onclick = () => goBack({ route: 'wallet' }); return; }
  let from = list.find(a => a.key === swapFromKey) || list.find(a => (swapAssetBalance(a) ?? 0) > 0) || list.find(a => a.chainId === 'solana') || list[0];
  let to = list.find(a => a.key === swapToKey && a.key !== from.key) || list.find(a => a.chainId === from.chainId && a.symbol === 'USDC' && a.key !== from.key) || list.find(a => a.key !== from.key)!;
  swapFromKey = from.key; swapToKey = to.key;
  setView(`<main><button class="backBtn" id="bk" aria-label="Back"><i class="ri-arrow-left-s-line"></i></button>
  <div class="card swapCard"><button class="sheetX" id="xBtn" aria-label="Close"><i class="ri-close-line"></i></button>
    <div class="swapHead"><span class="swapTitle">Swap</span><span class="swapSub">Live quotes · signed on this device</span></div>
    <div class="swapHalf">
      <div class="swapLabRow"><span class="swapLab">You pay</span><button class="swapBal" id="fromBal" type="button"></button></div>
      <div class="swapRow"><button class="tokenPill" id="fromAssetBtn" type="button"></button><input class="swapAmtIn" id="swapAmt" inputmode="decimal" placeholder="0.0" autocomplete="off" value="${esc(swapAmount)}"></div>
      <div class="swapUsd" id="fromUsd"></div>
    </div>
    <div class="swapDiv"><button class="swapFlip" id="swapFlip" type="button" aria-label="Switch assets"><i class="ri-arrow-down-line"></i></button></div>
    <div class="swapHalf">
      <div class="swapLabRow"><span class="swapLab">You receive</span><span class="swapBal" id="toBal"></span></div>
      <div class="swapRow"><button class="tokenPill" id="toAssetBtn" type="button"></button><div class="swapAmtIn ro" id="swapOut">—</div></div>
      <div class="swapUsd" id="toUsd"></div>
    </div>
    <div id="quoteBox"></div>
    <div class="slipBox"><div class="swapLabRow"><span class="swapLab">Slippage tolerance</span><span class="slipEff" id="slipEff"></span></div>
    <div class="slipSeg" id="slipSeg"><button data-s="10" type="button">0.1%</button><button data-s="50" type="button">0.5%</button><button data-s="100" type="button">1.0%</button><button data-s="custom" type="button">Custom</button></div>
    <div class="slipSlot" id="slipSlot"></div></div>
    <div style="height:14px"></div>
    <button class="ctaWide" id="swapReview" disabled>Review swap</button>
  </div>
  <p class="securityNote" style="margin:12px 16px 0">Quotes are live from Jupiter (Solana) and LI.FI (EVM &amp; cross-chain) — route, minimum received and price impact are shown before you sign. Nothing is signed until the review screen.</p>
  </main>`);
  ($('#bk') as HTMLElement).onclick = () => goBack({ route: 'wallet' }); ($('#xBtn') as HTMLElement).onclick = () => goTab('wallet');
  clearInterval(swapTimer);
  swapTimer = setInterval(() => { if (currentRoute !== 'swap') { clearInterval(swapTimer); return; } if (swapAmount && parseFloat(swapAmount) > 0) void requestSwapQuote(true); }, 20000);
  const curFrom = () => swapAssets().find(a => a.key === swapFromKey)!;
  const curTo = () => swapAssets().find(a => a.key === swapToKey)!;
  const pillHTML = (a: SwapAsset) => `${iconHTML(a.img, a.symbol, a.name, { sm: true })}<span class="tpTx"><span class="tpSym">${esc(a.symbol)}</span><span class="tpChain">${esc(findChain(a.chainId)?.name || '')}</span></span><i class="ri-arrow-down-s-line"></i>`;
  const balHTML = (a: SwapAsset, max: boolean) => { const b = swapAssetBalance(a); const st = swapAssetState(a); return `<span>${b != null ? 'Balance: ' + trimNum(b) + ' ' + esc(a.symbol) : st === 'pending' ? 'Balance: Loading…' : 'Balance unavailable'}</span>${max ? '<span class="maxChip">MAX</span>' : ''}`; };
  const paintSwapUsd = () => {
    const f = curFrom(); const el = $('#fromUsd'); if (!el || !f) return;
    const amt = parseFloat(swapAmount); const fp = swapAssetPrice(f);
    el.textContent = amt > 0 && fp != null ? '≈ ' + fmtUsd(amt * fp) : '';
  };
  const paintQuote = () => {
    const box = $('#quoteBox'); const out = $('#swapOut'); const rb = $('#swapReview') as HTMLButtonElement | null; const toUsd = $('#toUsd');
    const f = curFrom(); const t = curTo(); if (!box || !f || !t) return;
    paintSwapUsd();
    const rawIn = parseRawAmount(swapAmount, f.decimals);
    const sig = rawIn ? swapSignature(f, t, rawIn.toString(), swapSlippageBps) : '';
    const blankOut = () => { if (out) out.textContent = '—'; if (toUsd) toUsd.textContent = ''; if (rb) rb.disabled = true; };
    if (swapErrKind === 'noroute') {
      box.innerHTML = `<div class="swapNoRoute"><i class="ri-route-line"></i><span>No route available for this pair</span></div>`;
      blankOut(); if (rb) rb.textContent = 'No route';
      return;
    }
    if (swapErrKind === 'noliquidity') {
      box.innerHTML = `<div class="swapNote warnTx">This amount is too small for the available routes — try a larger amount.</div>`;
      blankOut(); if (rb) rb.textContent = 'Review swap';
      return;
    }
    if (swapErrKind === 'provider') {
      box.innerHTML = `<div class="swapNote">Couldn't fetch a quote — retrying in the background.</div>`;
      blankOut(); if (rb) rb.textContent = 'Review swap';
      return;
    }
    if (swapQuoteErr) { box.innerHTML = `<div class="err" style="margin:12px 0 0">${esc(swapQuoteErr)}</div>`; blankOut(); if (rb) rb.textContent = 'Review swap'; return; }
    if (swapQuote && swapQuoteSig === sig) {
      const q = swapQuote;
      if (out) out.textContent = '≈ ' + trimNum(q.outHuman, q.outHuman < 1 ? 6 : 4);
      if (toUsd) { const tp = swapAssetPrice(t); toUsd.textContent = tp != null ? '≈ ' + fmtUsd(q.outHuman * tp) : ''; }
      const impact = q.priceImpactPct;
      box.innerHTML = `<div class="swapMeta">
      <div class="sumRow"><span class="sl">Rate</span><span class="sv">1 ${esc(f.symbol)} ≈ ${trimNum(q.rate, q.rate < 1 ? 6 : 4)} ${esc(t.symbol)}</span></div>
      <div class="sumRow"><span class="sl">Minimum received</span><span class="sv">${trimNum(q.minOutHuman, q.minOutHuman < 1 ? 6 : 4)} ${esc(t.symbol)}</span></div>
      <div class="sumRow"><span class="sl">Price impact</span><span class="sv" ${impact != null && impact > 5 ? 'style="color:var(--red)"' : impact != null && impact > 1 ? 'style="color:var(--amber)"' : ''}>${impact == null ? 'Unavailable' : '~' + impact.toFixed(2) + '%'}</span></div>
      <div class="sumRow"><span class="sl">Route</span><span class="sv" style="white-space:normal">${esc(q.routeLabel)}</span></div>
      ${q.feeLines.map(l => `<div class="sumRow"><span class="sl">Fees</span><span class="sv" style="white-space:normal">${esc(l)}</span></div>`).join('')}
      ${impact != null && impact > 15 ? '<div class="err" style="margin-top:10px">Price impact is over 15% — this trade would lose a large part of its value. Consider a smaller amount.</div>' : impact != null && impact > 5 ? '<div class="warn" style="margin-top:10px">High price impact — this trade moves the market price against you. Consider a smaller amount.</div>' : ''}
      ${swapStale ? '<div class="swapStale">Quote unavailable — showing the last quote. Check the amount or pair; a fresh quote is needed before you can review.</div>' : ''}
      </div>`;
      if (rb) { rb.disabled = swapStale; rb.textContent = 'Review swap'; }
      return;
    }
    box.innerHTML = rawIn ? `<p class="small muted" style="margin-top:12px">${waveLoadHTML()} Fetching a live quote…</p>` : '<p class="small muted" style="margin-top:12px">Enter an amount to get a live quote.</p>';
    blankOut(); if (rb) rb.textContent = 'Review swap';
  };
  (window as any).__synPaintSwapQuote = paintQuote;
  // Atomic repaint of every state-dependent field from module state —
  // pills, balances, USD lines, quote block, and the selector sheet if
  // it is open — in one frame.
  const paintSwapAll = (syncAmt: boolean) => {
    const f = curFrom(); const t = curTo(); if (!f || !t) return;
    const fb = $('#fromAssetBtn'); if (fb) fb.innerHTML = pillHTML(f);
    const tb = $('#toAssetBtn'); if (tb) tb.innerHTML = pillHTML(t);
    const fBal = $('#fromBal'); if (fBal) fBal.innerHTML = balHTML(f, true);
    const tBal = $('#toBal'); if (tBal) tBal.innerHTML = balHTML(t, false);
    if (swapPicker?.isOpen()) swapPicker.refresh();
    if (syncAmt) { const ai = $('#swapAmt') as unknown as HTMLInputElement | null; if (ai) ai.value = swapAmount; }
    paintSlip();
    paintQuote();
  };
  (window as any).__synPaintSwap = () => paintSwapAll(false);
  const invalidateQuote = () => { swapSeq++; }; // any in-flight response is now for stale input — discard on arrival
  const requestSwapQuote = async (background = false) => {
    const f = curFrom(); const t = curTo(); if (!f || !t) return;
    const rawIn = parseRawAmount(swapAmount, f.decimals);
    if (!rawIn) { swapQuote = null; swapQuoteErr = ''; swapErrKind = ''; swapStale = false; paintQuote(); return; }
    const sig = swapSignature(f, t, rawIn.toString(), swapSlippageBps);
    if (!background) { swapQuote = null; swapQuoteErr = ''; swapErrKind = ''; swapStale = false; paintQuote(); }
    const seq = ++swapSeq;
    try {
      const q = await fetchSwapQuote(f, t, rawIn.toString(), swapSlippageBps);
      if (seq !== swapSeq || currentRoute !== 'swap') return;
      swapQuote = q; swapQuoteSig = sig; swapQuoteErr = ''; swapErrKind = ''; swapStale = false; lastQuoteAt = Date.now();
    } catch (e: any) {
      if (seq !== swapSeq || currentRoute !== 'swap') return;
      const kind = classifyQuoteError(e);
      if (kind === 'noroute') { swapQuote = null; swapQuoteSig = ''; swapErrKind = 'noroute'; swapQuoteErr = ''; swapStale = false; }
      else if (kind === 'noliquidity') { swapQuote = null; swapQuoteSig = ''; swapErrKind = 'noliquidity'; swapQuoteErr = ''; swapStale = false; }
      else if (background && swapQuote && swapQuoteSig === sig) swapStale = true; // provider error: keep the last good numbers, marked stale, CTA off
      else { swapQuote = null; swapQuoteSig = ''; swapErrKind = 'provider'; swapQuoteErr = ''; swapStale = false; }
    }
    paintQuote();
  };
  (window as any).__synRequestSwapQuote = requestSwapQuote;
  let deb: any = null;
  const amtIn = $('#swapAmt') as unknown as HTMLInputElement;
  amtIn.addEventListener('input', () => { swapAmount = sanitizeAmt(amtIn.value, Math.min(8, curFrom().decimals)); amtIn.value = swapAmount; invalidateQuote(); paintSwapUsd(); clearTimeout(deb); deb = setTimeout(() => void requestSwapQuote(), 550); });
  const fBalBtn = $('#fromBal'); if (fBalBtn) fBalBtn.onclick = () => { const bal = swapAssetBalance(curFrom()); if (bal == null || bal <= 0) return; swapAmount = trimNum(bal, Math.min(8, curFrom().decimals)); amtIn.value = swapAmount; invalidateQuote(); void requestSwapQuote(); };
  const choose = (side: 'from' | 'to', key: string) => {
    // Picking the coin already on the other side auto-swaps the sides —
    // an identical pair is impossible.
    if (side === 'from') { if (key === swapToKey) swapToKey = swapFromKey; swapFromKey = key; }
    else { if (key === swapFromKey) swapFromKey = swapToKey; swapToKey = key; }
    swapQuote = null; swapQuoteErr = ''; swapErrKind = ''; swapStale = false;
    invalidateQuote();
    paintSwapAll(false);
    void requestSwapQuote();
  };
  // ---------- token selector: the SHARED picker sheet (Addition 11),
  // swap configuration. Same component Send and Receive use — this
  // block only supplies swap's rows, ordering and pick behaviour.
  let sheetSide: 'from' | 'to' = 'from';
  let sheetResolvedData: { c: Chain; contract: string; meta: { name: string; symbol: string; decimals: number } } | null = null;
  const sheetRowInner = (a: SwapAsset, side: 'from' | 'to'): string => {
    const c = findChain(a.chainId);
    const b = swapAssetBalance(a); const p = swapAssetPrice(a); const st = swapAssetState(a);
    const isSel = a.key === (side === 'from' ? swapFromKey : swapToKey);
    const isOther = a.key === (side === 'from' ? swapToKey : swapFromKey);
    const reason = !assetSwappable(a) ? (c && c.kind !== 'evm' && c.kind !== 'solana' && c.kind !== 'solana-tw' && c.kind !== 'solana-phantom' ? 'Receive-only network' : 'Swaps not supported on this network') : '';
    return `${iconHTML(a.img, a.symbol, a.name)}
      <span class="shTx"><span class="shName">${esc(a.name)} <span class="aSym">${esc(a.symbol)}</span></span><span class="shNet">${esc(c?.name || '')}${reason ? ' · ' + esc(reason) : ''}${isOther ? ' · On the other side — tap to swap sides' : ''}</span></span>
      <span class="shRight">${b != null ? `<span class="shBal">${trimNum(b)} ${esc(a.symbol)}</span><span class="shUsd">${p != null ? fmtUsd(b * p) : ''}</span>` : `<span class="shUsd">${st === 'pending' ? 'Loading…' : ''}</span>`}</span>
      ${isSel ? '<span class="arrowChip grad"><i class="ri-check-line"></i></span>' : ''}`;
  };
  const resolveSwapAddress = async (addr: string): Promise<PickerRow | null> => {
    const r = await resolveTokenAddress(addr);
    if (!r) return null;
    sheetResolvedData = r;
    return { key: '__resolved', searchText: '', html: `${iconHTML('', r.meta.symbol || '?', r.meta.name)}<span class="shTx"><span class="shName">${esc(r.meta.name || 'Unknown token')} <span class="aSym">${esc(r.meta.symbol || '')}</span></span><span class="shNet">${esc(r.c.name)} · ${esc(addr.slice(0, 10))}…${esc(addr.slice(-6))}</span></span><span class="arrowChip"><i class="ri-arrow-right-line"></i></span>` };
  };
  const selectResolved = () => {
    const r = sheetResolvedData; if (!r) return;
    const t = ensureCustomToken(r);
    const a = swapAssets().find(x => x.tokenId === t.id);
    sheetResolvedData = null;
    if (a) choose(sheetSide, a.key);
    swapPicker?.close();
  };
  const openSwapPicker = (side: 'from' | 'to') => {
    sheetSide = side; sheetResolvedData = null;
    swapPicker = openPickerSheet({
      title: 'Select token',
      networks: pickerNetworks(swapAssets()),
      allNetLabel: 'All networks',
      rows: () => sortedSwapAssets().map(a => ({ key: a.key, net: a.chainId, disabled: side === 'from' && !assetSwappable(a), searchText: (a.name + ' ' + a.symbol + ' ' + (findChain(a.chainId)?.name || '')).toLowerCase(), html: sheetRowInner(a, side) })),
      onPick: (key) => { choose(side, key); swapPicker?.close(); },
      resolveAddress: resolveSwapAddress,
      onResolvedPick: () => selectResolved(),
      emptyText: (q) => `No tokens match '${q}'`,
    });
  };
  const bindPill = (side: 'from' | 'to') => { const btn = $(side === 'from' ? '#fromAssetBtn' : '#toAssetBtn'); if (btn) btn.onclick = () => openSwapPicker(side); };
  bindPill('from'); bindPill('to');
  ($('#swapFlip') as HTMLElement).onclick = () => {
    // The previous receive estimate becomes the new pay amount (in the
    // new pay asset's decimals) and a fresh quote fires — amounts are
    // recomputed for the flipped pair, never mirrored as strings.
    const f = curFrom(); const t = curTo();
    const rawIn = parseRawAmount(swapAmount, f.decimals);
    const sig = rawIn ? swapSignature(f, t, rawIn.toString(), swapSlippageBps) : '';
    const carry = swapQuote && swapQuoteSig === sig ? trimNum(swapQuote.outHuman, Math.min(8, t.decimals)) : '';
    const k = swapFromKey; swapFromKey = swapToKey; swapToKey = k;
    if (carry) swapAmount = carry;
    swapQuote = null; swapQuoteErr = ''; swapErrKind = ''; swapStale = false;
    invalidateQuote();
    paintSwapAll(true);
    void requestSwapQuote();
  };
  // Addition 8: slippage segmented control. The slot under the segments
  // has a FIXED height, so switching segments or opening Custom never
  // shifts the layout. The slot is rebuilt only when the mode changes —
  // repaints while typing must not destroy the input or its caret.
  const seg = $('#slipSeg');
  const slipMsgFor = (pct: number | null, raw: string): { t: string; cls: string } => {
    if (raw.trim() === '' || pct == null || !(pct > 0)) return { t: 'Enter a value above 0% — the last applied slippage still stands.', cls: '' };
    if (pct > 50) return { t: "Slippage can't exceed 50% — the last applied slippage still stands.", cls: 'red' };
    if (pct > 3) return { t: 'High slippage — most swaps use 0.1–1%. You may receive much less than quoted.', cls: 'amber' };
    return { t: '', cls: '' };
  };
  const paintSlip = () => {
    if (!seg) return;
    seg.querySelectorAll('[data-s]').forEach(x => {
      const v = (x as HTMLElement).dataset.s!;
      x.classList.toggle('on', v === 'custom' ? swapSlipCustomOn : !swapSlipCustomOn && Number(v) === swapSlippageBps);
    });
    const eff = $('#slipEff'); if (eff) eff.textContent = trimNum(swapSlippageBps / 100, 2) + '% applied';
    const slot = $('#slipSlot'); if (!slot) return;
    const mode = swapSlipCustomOn ? 'custom' : 'preset';
    if (slot.dataset.mode !== mode) {
      slot.dataset.mode = mode;
      if (mode === 'preset') {
        slot.innerHTML = '<span class="slipHint">How much the price may move before the swap is cancelled instead of filled at a worse rate.</span>';
      } else {
        slot.innerHTML = `<div class="slipCustomRow"><input id="slipCustom" inputmode="decimal" placeholder="0.5" autocomplete="off" value="${esc(swapSlipCustomText)}"><span class="slipPctSign">%</span></div><div class="slipMsg" id="slipMsg"></div>`;
        const ci = slot.querySelector('#slipCustom') as unknown as HTMLInputElement;
        ci.addEventListener('input', () => {
          swapSlipCustomText = ci.value;
          const pct = parseFloat(ci.value.replace(',', '.'));
          const msg = slipMsgFor(isNaN(pct) ? null : pct, ci.value);
          const m = slot.querySelector('#slipMsg') as HTMLElement | null;
          if (m) { m.textContent = msg.t; m.className = 'slipMsg ' + msg.cls; }
          if (pct > 0 && pct <= 50) {
            const nb = Math.round(pct * 100);
            if (nb !== swapSlippageBps) { swapSlippageBps = nb; const e2 = $('#slipEff'); if (e2) e2.textContent = trimNum(nb / 100, 2) + '% applied'; invalidateQuote(); clearTimeout(deb); deb = setTimeout(() => void requestSwapQuote(), 550); }
          }
        });
        ci.addEventListener('blur', () => { if (swapSlipCustomText.trim() === '') { /* keep last applied */ } });
        const m0 = slipMsgFor(parseFloat(swapSlipCustomText.replace(',', '.')) || null, swapSlipCustomText);
        const mEl = slot.querySelector('#slipMsg') as HTMLElement | null;
        if (mEl && swapSlipCustomText.trim() !== '') { mEl.textContent = m0.t; mEl.className = 'slipMsg ' + m0.cls; }
      }
    }
  };
  if (seg) seg.querySelectorAll('[data-s]').forEach(b => (b as HTMLElement).onclick = () => {
    const v = (b as HTMLElement).dataset.s!;
    if (v === 'custom') {
      swapSlipCustomOn = true;
      if (swapSlipCustomText.trim() === '') swapSlipCustomText = trimNum(swapSlippageBps / 100, 2);
      paintSlip();
      const ci = $('#slipCustom') as unknown as HTMLInputElement | null; if (ci) { ci.focus(); ci.select(); }
    } else {
      swapSlipCustomOn = false;
      swapSlippageBps = Number(v);
      paintSlip();
      invalidateQuote(); void requestSwapQuote();
    }
  });
  paintSlip();
  ($('#swapReview') as HTMLButtonElement).onclick = () => {
    const f = curFrom(); const t = curTo(); if (!f || !t || !swapQuote || swapStale) return;
    const rawIn = parseRawAmount(swapAmount, f.decimals); if (!rawIn) return;
    const bal = swapAssetBalance(f);
    const amt = rawToHuman(rawIn, f.decimals);
    if (bal != null && amt > bal) { swapErrKind = ''; swapQuoteErr = 'Amount exceeds your ' + f.symbol + ' balance.'; paintQuote(); return; }
    go({ route: 'swapconfirm', swapConfirm: { quote: swapQuote, from: f, to: t, amountStr: swapAmount, rawIn: rawIn.toString(), slippageBps: swapSlippageBps } }, $('#swapReview') as HTMLElement);
  };
  paintSwapAll(false);
  if (swapAmount && parseFloat(swapAmount) > 0) void requestSwapQuote();
}
function showSwapConfirm(p: SwapConfirmPayload, err = '') {
  const fc = findChain(p.from.chainId)!; const tc = findChain(p.to.chainId)!;
  const q = p.quote;
  const crossChain = p.from.chainId !== p.to.chainId;
  const needsApproval = q.provider === 'lifi' && p.from.contract !== 'native' && fc.kind === 'evm' && !!q.approvalAddress;
  const impact = q.priceImpactPct;
  const fromBal = swapAssetBalance(p.from);
  const amtIn = rawToHuman(p.rawIn, p.from.decimals);
  setView(`<main><button class="backBtn" id="bk" aria-label="Back"><i class="ri-arrow-left-s-line"></i></button>
  <div class="card" style="position:relative"><h1 class="heroH">Review <span>swap</span></h1><p class="heroSub" style="margin-top:2px">Clear signing — exactly what will be signed</p><div style="height:8px"></div>${err ? `<div class="err">${esc(err)}</div>` : ''}
    <div class="sumAmt">${trimNum(amtIn, 8)} ${esc(p.from.symbol)} → ≈ ${trimNum(q.outHuman, q.outHuman < 1 ? 6 : 4)} ${esc(p.to.symbol)}</div>
    <div style="height:8px"></div>
    <div class="sumRow"><span class="sl">You pay</span><span class="sv">${trimNum(amtIn, 8)} ${esc(p.from.symbol)} · ${esc(fc.name)}</span></div>
    <div class="sumRow"><span class="sl">You receive (est.)</span><span class="sv">${trimNum(q.outHuman, q.outHuman < 1 ? 6 : 4)} ${esc(p.to.symbol)} · ${esc(tc.name)}</span></div>
    <div class="sumRow"><span class="sl">Minimum received</span><span class="sv">${trimNum(q.minOutHuman, q.minOutHuman < 1 ? 6 : 4)} ${esc(p.to.symbol)}</span></div>
    <div class="sumRow"><span class="sl">Rate</span><span class="sv">1 ${esc(p.from.symbol)} ≈ ${trimNum(q.rate, q.rate < 1 ? 6 : 4)} ${esc(p.to.symbol)}</span></div>
    <div class="sumRow"><span class="sl">Slippage</span><span class="sv">${(p.slippageBps / 100).toFixed(2).replace(/0+$/, '').replace(/\.$/, '.0')}%</span></div>
    <div class="sumRow"><span class="sl">Price impact</span><span class="sv" ${impact != null && impact > 5 ? 'style="color:var(--red)"' : impact != null && impact > 1 ? 'style="color:var(--amber)"' : ''}>${impact == null ? 'Unavailable' : '~' + impact.toFixed(2) + '%'}</span></div>
    <div class="sumRow"><span class="sl">Provider</span><span class="sv">${q.provider === 'jupiter' ? 'Jupiter' : 'LI.FI'}</span></div>
    <div class="sumRow"><span class="sl">Route</span><span class="sv" style="white-space:normal">${esc(q.routeLabel)}</span></div>
    ${q.feeLines.map(l => `<div class="sumRow"><span class="sl">Fees</span><span class="sv" style="white-space:normal">${esc(l)}</span></div>`).join('')}
    <div class="sumRow"><span class="sl">Received at</span><span class="sv"><span class="monoChip" style="max-width:210px" data-full="${esc(addressFor(tc))}">${esc(addressFor(tc).slice(0, 10))}…${esc(addressFor(tc).slice(-8))}</span></span></div>
    ${impact != null && impact > 15 ? '<div class="err" style="margin-top:12px">Price impact is over 15% — you would lose a large part of this trade\'s value to slippage. Strongly consider a smaller amount.</div>' : impact != null && impact > 5 ? '<div class="warn" style="margin-top:12px">High price impact (~' + impact.toFixed(1) + '%). You receive notably less than the spot value.</div>' : ''}
    ${p.from.contract === 'native' && fromBal != null && amtIn >= fromBal * 0.999 ? '<div class="warn" style="margin-top:12px">This uses essentially your whole ' + esc(p.from.symbol) + ' balance — network fees are also paid from it, so the swap may fail for fees. Leave a little behind.</div>' : ''}
    ${crossChain ? `<div class="warn" style="margin-top:12px">Cross-chain swap: after the source transaction confirms, the bridge delivers on ${esc(tc.name)}${q.etaSec ? ' — typically about ' + Math.max(1, Math.round(q.etaSec / 60)) + ' min' : ''}. Delivery is handled by the bridge protocol, not by Syn.</div>` : ''}
    <div style="margin-top:12px"><p class="small muted" style="margin-bottom:6px">Token you receive — risk check</p><div id="swapRiskSlot"><p class="small muted">${waveLoadHTML()} Checking token risk…</p></div></div>
    ${needsApproval ? `<div id="apprZone" style="margin-top:12px"><p class="small muted">${waveLoadHTML()} Checking the token allowance for the LI.FI spender…</p></div>` : ''}
    <p class="securityNote" style="margin:12px 0">The transaction is built by the provider from this quote and signed locally on this device — your key never leaves it. Quotes move: if the market shifts beyond your slippage, the swap reverts instead of filling worse than the minimum.</p>
    <button class="ctaWide" id="swapGo">Swap ${esc(p.from.symbol)} → ${esc(p.to.symbol)}</button><div style="height:10px"></div><button class="btnGhost" id="swapCancel" style="border-radius:999px">Cancel</button></div></main>`);
  ($('#bk') as HTMLElement).onclick = () => goBack({ route: 'swap' }); ($('#swapCancel') as HTMLElement).onclick = () => goBack({ route: 'swap' });
  { const slot = $('#swapRiskSlot'); if (slot) void (async () => { const seq = ++riskPaintSeq; const rep = await tokenRiskReport(p.to.contract, tc); if (slot.isConnected) slot.innerHTML = riskReportHTML(rep, 'token'); void appendTwRisk(slot, p.to.contract, tc, seq); })(); }
  let approvalOk = !needsApproval;
  if (needsApproval) {
    // Audit fix: while the allowance read is in flight the CTA was
    // tappable but silently dead. Disable it with an honest label.
    const gb0 = $('#swapGo') as HTMLButtonElement | null; if (gb0) { gb0.disabled = true; gb0.textContent = 'Checking allowance…'; }
    (async () => {
      const zone = $('#apprZone'); const goBtn = $('#swapGo') as HTMLButtonElement | null;
      const owner = evmAddressOf();
      const live = await readAllowance(fc, p.from.contract, owner, q.approvalAddress!);
      if (!zone || !zone.isConnected) return;
      const need = BigInt(p.rawIn);
      if (live !== null && live >= need) { approvalOk = true; zone.innerHTML = '<p class="small muted">Allowance already covers this swap — no approval transaction needed.</p>'; if (goBtn) { goBtn.disabled = false; goBtn.textContent = `Swap ${p.from.symbol} → ${p.to.symbol}`; } return; }
      if (goBtn) { goBtn.disabled = false; goBtn.textContent = `Approve ${p.from.symbol} first`; }
      zone.innerHTML = `<div class="warn" style="margin:0">${live === null ? 'The current allowance couldn’t be read, so treat this as unapproved. ' : ''}Step 1 of 2: LI.FI's contract (<span class="monoChip">${esc(q.approvalAddress!.slice(0, 10))}…${esc(q.approvalAddress!.slice(-6))}</span>) needs an allowance of exactly ${trimNum(amtIn, 8)} ${esc(p.from.symbol)} to route this swap. Approving is a separate on-chain transaction you sign; the swap follows after it confirms.</div>`;
      if (goBtn) goBtn.onclick = async () => {
        btnBusy(goBtn, 'Approving…');
        try {
          const pk = evmPrivKey()!; const provider = new ethers.JsonRpcProvider(evmProviderUrl(fc), fc.evmId); const wallet = new ethers.Wallet(pk, provider);
          const contract = new ethers.Contract(p.from.contract, ['function approve(address spender, uint256 value) returns (bool)'], wallet);
          const tx = await contract.approve(q.approvalAddress!, need);
          await tx.wait();
          renderRoute({ route: 'swapconfirm', swapConfirm: p });
        } catch (e: any) { showSwapConfirm(p, 'Approval failed: ' + (e?.shortMessage || e?.message || String(e))); }
      };
    })();
  }
  ($('#swapGo') as HTMLButtonElement).onclick = async () => {
    if (!approvalOk) return; // the approval handler owns the button until the allowance is in place
    const btn = $('#swapGo') as HTMLButtonElement; btnBusy(btn, 'Signing & broadcasting…');
    try {
      const hash = await doSwapExecute(p); recordLocalTx(p.from.chainId, hash, `Swap ${p.from.symbol} → ${p.to.symbol}`, { dir: 'swap', sym: p.from.symbol, amt: String(amtIn), img: p.from.img });
      if (p.from.contract === 'native') balances.delete(p.from.chainId); else if (p.from.tokenId) tokenBalances.delete(p.from.tokenId);
      if (p.to.contract === 'native') balances.delete(p.to.chainId); else if (p.to.tokenId) tokenBalances.delete(p.to.tokenId);
      celebrate(btn, () => {
        setView(receiptHTML({ title: 'Swap submitted', amount: `${trimNum(amtIn, 8)} ${p.from.symbol}`, sub: `→ ≈ ${trimNum(q.outHuman, q.outHuman < 1 ? 6 : 4)} ${p.to.symbol}${crossChain ? ' · This is the source-chain transaction. The bridge delivers on ' + tc.name + ' after it confirms — watch Activity on the destination network.' : ''}`, hash, extra: crossChain ? '<button class="btnGhost" id="swLifi" style="width:100%;margin-bottom:10px">Track on LI.FI explorer</button>' : '', doneLabel: 'Done' }));
        bindReceipt(hash, fc.explorerTx, (el) => goTab('wallet', el));
        const lf = $('#swLifi'); if (lf) lf.onclick = () => window.open('https://explorer.li.fi/tx/' + hash, '_blank');
      });
    } catch (e: any) {
      const eh = (e as any)?.hash || (e as any)?.transactionHash;
      if (typeof eh === 'string' && /^0x[0-9a-fA-F]{64}$/.test(eh)) { recordLocalTx(p.from.chainId, eh, `Swap ${p.from.symbol} -> ${p.to.symbol}`, { dir: 'swap', sym: p.from.symbol, amt: String(amtIn), img: p.from.img }); showSwapConfirm(p, 'The network may have accepted this swap already (check Activity before trying again).'); return; }
      showSwapConfirm(p, 'Swap failed: ' + (e?.shortMessage || e?.message || String(e)));
    }
  };
}
// Audit H-1 (2026-11-19): a built swap transaction is verified against
// the REVIEWED quote before anything signs it. Solana: the fee payer
// must be the user, and a simulation (with post-state reads of the
// user's own input/output token accounts) must show the input leaving
// by exactly the reviewed amount and the output arriving at no less
// than the reviewed minimum. Cross-chain LI.FI sources can only verify
// the input side on-chain — the output is the bridge's leg, and the
// review screen already says so. Any mismatch refuses the signature.
async function verifySolSwapTx(conn: Connection, tx: Transaction | VersionedTransaction, kp: Keypair, p: SwapConfirmPayload): Promise<void> {
  const owner = kp.publicKey.toBase58();
  const payer = tx instanceof VersionedTransaction ? tx.message.staticAccountKeys[0]?.toBase58() : (tx.feePayer?.toBase58() || tx.signatures[0]?.publicKey.toBase58());
  if (payer !== owner) throw new Error('Swap verification failed: the built transaction is paid for by a different account. Nothing was signed.');
  const inMint = p.from.contract === 'native' ? JUP_SOL_MINT : p.from.contract;
  const crossChain = p.from.chainId !== p.to.chainId;
  const outMint = p.to.contract === 'native' ? JUP_SOL_MINT : p.to.contract;
  const inAta = getAssociatedTokenAddressSync(new PublicKey(inMint), kp.publicKey);
  const outAta = crossChain ? inAta : getAssociatedTokenAddressSync(new PublicKey(outMint), kp.publicKey);
  const addrs = [...new Set([inAta.toBase58(), outAta.toBase58(), owner])];
  const amtOf = (r: any): string => { const a = r?.value?.data?.parsed?.info?.tokenAmount?.amount; return typeof a === 'string' && /^\d+$/.test(a) ? a : '0'; };
  const [preIn, preOut, preLamports] = await Promise.all([
    conn.getParsedAccountInfo(inAta).then(amtOf).catch(() => '0'),
    crossChain ? Promise.resolve('0') : conn.getParsedAccountInfo(outAta).then(amtOf).catch(() => '0'),
    conn.getBalance(kp.publicKey, 'confirmed').catch(() => 0),
  ]);
  const simRes: any = tx instanceof VersionedTransaction
    ? await conn.simulateTransaction(tx, { sigVerify: false, accounts: { encoding: 'jsonParsed', addresses: addrs } } as any)
    : await (conn as any).simulateTransaction(tx, [], addrs);
  const val = simRes?.value;
  if (!val) throw new Error('Swap verification failed: the built transaction could not be simulated. Nothing was signed.');
  const postByAddr = new Map<string, any>();
  (val.accounts || []).forEach((a: any, i: number) => postByAddr.set(addrs[i], a));
  const postAmt = (ata: string): string => { const amt = postByAddr.get(ata)?.data?.parsed?.info?.tokenAmount?.amount; return typeof amt === 'string' && /^\d+$/.test(amt) ? amt : '0'; };
  const postLamports = Number(postByAddr.get(owner)?.lamports ?? preLamports);
  const problem = solSwapVerdict({
    err: val.err,
    preTokenBalances: [
      { mint: inMint, owner, uiTokenAmount: { amount: preIn } },
      ...(crossChain ? [] : [{ mint: outMint, owner, uiTokenAmount: { amount: preOut } }]),
    ],
    postTokenBalances: [
      { mint: inMint, owner, uiTokenAmount: { amount: postAmt(inAta.toBase58()) } },
      ...(crossChain ? [] : [{ mint: outMint, owner, uiTokenAmount: { amount: postAmt(outAta.toBase58()) } }]),
    ],
    preBalances: [preLamports], postBalances: [postLamports],
  }, owner, inMint, outMint, p.rawIn, p.quote.minOutRaw, { inputOnly: crossChain });
  if (problem) throw new Error('Swap verification failed: ' + problem);
}
async function doSwapExecute(p: SwapConfirmPayload): Promise<string> {
  const fc = findChain(p.from.chainId)!;
  if (p.quote.provider === 'jupiter') {
    const kp = solanaKeypairFor(fc.kind); if (!kp) throw new Error('No Solana account available to sign.');
    const b64 = await fetchJupiterSwapTx(p.quote.raw, kp.publicKey.toBase58());
    const tx = deserializeSolTx(b64Bytes(b64));
    const conn = new Connection(solanaRpcUrl(), 'confirmed');
    await verifySolSwapTx(conn, tx, kp, p);
    if (tx instanceof VersionedTransaction) { tx.sign([kp]); return await sendSolanaSigned(conn, tx.serialize(), bs58.encode(tx.signatures[0])); }
    tx.sign(kp); return await sendSolanaSigned(conn, tx.serialize(), bs58.encode(tx.signature!));
  }
  const tr = p.quote.raw?.transactionRequest;
  if (!tr) throw new Error('The quote has no transaction to sign.');
  if (isSolAsset(p.from)) {
    const kp = solanaKeypairFor(fc.kind); if (!kp) throw new Error('No Solana account available to sign.');
    const tx = deserializeSolTx(b64Bytes(String(tr.data)));
    const conn = new Connection(solanaRpcUrl(), 'confirmed');
    await verifySolSwapTx(conn, tx, kp, p);
    if (tx instanceof VersionedTransaction) { tx.sign([kp]); return await sendSolanaSigned(conn, tx.serialize(), bs58.encode(tx.signatures[0])); }
    tx.sign(kp); return await sendSolanaSigned(conn, tx.serialize(), bs58.encode(tx.signature!));
  }
  // Audit H-1 (LI.FI EVM): the built transactionRequest must match the
  // reviewed quote — destination (the quote's own approval/router
  // address), chain, attached value, recipient and input token encoded
  // in the calldata, and no plain transfer/approve as the outer call.
  const tc = findChain(p.to.chainId)!;
  const problem = verifyLifiEvmTx(tr, {
    fromChainId: fc.evmId!,
    fromToken: p.from.contract === 'native' ? LIFI_NATIVE_EVM : p.from.contract,
    fromAmountRaw: p.rawIn,
    toAddress: addressFor(tc),
    approvalAddress: p.quote.approvalAddress,
  });
  if (problem) throw new Error('Swap verification failed: ' + problem);
  const pk = evmPrivKey(); if (!pk) throw new Error('No EVM account available to sign.');
  const provider = new ethers.JsonRpcProvider(evmProviderUrl(fc), fc.evmId);
  const wallet = new ethers.Wallet(pk, provider);
  const txReq: ethers.TransactionRequest = { to: tr.to, data: tr.data, value: BigInt(tr.value || '0') };
  if (tr.gasLimit) { try { txReq.gasLimit = BigInt(tr.gasLimit); } catch { /* provider fills it */ } }
  const tx = await wallet.sendTransaction(txReq);
  return tx.hash;
}

// ---------- Wave 2: Solana native staking ----------
// Standard stake-program transactions, built and signed locally and
// reviewed on the same clear-signing confirm as every other send. Stake
// accounts are read with getProgramAccounts (jsonParsed, with a raw-bytes
// fallback parser); activation state comes from getStakeActivation.
let stakeValidators: ValidatorInfo[] = [];
let stakeValidatorsAt = 0;
// Addition 7: validator identity enrichment from the validators.app
// public API (keyless, verified live). Names, avatar icons +
// skipped-slot rate only — anything the API doesn't serve stays
// absent, never invented.
let validatorInfo: Map<string, { name: string; skip: number | null; icon: string }> | null = null;
async function loadValidatorInfo(): Promise<void> {
  if (validatorInfo) return;
  try {
    // Via our own server: validators.app sends no CORS headers, so a
    // browser-direct read fails; /api/validators is a public-data
    // pass-through with an hour of server cache.
    const r = await fetch('/api/validators', { signal: AbortSignal.timeout(15000) });
    if (!r.ok) return;
    const arr = await r.json();
    if (!Array.isArray(arr)) return;
    const m = new Map<string, { name: string; skip: number | null; icon: string }>();
    for (const v of arr) {
      const vote = typeof v?.vote === 'string' ? v.vote : '';
      if (!vote) continue;
      const name = typeof v?.name === 'string' ? v.name.replace(/[\u{1F000}-\u{1FAFF}\u{2600}-\u{27BF}\u{FE0F}]/gu, '').trim() : '';
      const skip = typeof v?.skip === 'number' ? v.skip : null;
      const icon = typeof v?.icon === 'string' && v.icon.startsWith('https://') ? v.icon : '';
      m.set(vote, { name, skip, icon });
    }
    if (m.size) validatorInfo = m;
  } catch { /* enrichment is optional — rows keep pubkeys */ }
}
function validatorName(votePubkey: string): string {
  return validatorInfo?.get(votePubkey)?.name || '';
}
// Validator avatar in the coin/dApp tile pattern: the validator's own
// published icon over a monogram of its name (the pubkey's first
// letters when it has no name) — a missing or failed icon falls back
// to the monogram, never to a generic glyph.
function validatorAvatarHTML(votePubkey: string): string {
  const vi = validatorInfo?.get(votePubkey);
  const name = vi?.name || '';
  const words = name.split(/\s+/).filter(Boolean);
  const initials = (words.length > 1 ? words[0][0] + words[1][0] : name.slice(0, 2) || votePubkey.slice(0, 2)).toUpperCase();
  const img = vi?.icon && isSafeMediaUrl(vi.icon) ? `<img class="coinImg" src="${esc(vi.icon)}" alt="" loading="lazy">` : '';
  return `<span class="coinIc">${img}<span class="coinLetter">${esc(initials)}</span></span>`;
}
let stakeSelVoter = '';
let stakeListCache: { key: string; rows: { info: StakeAccountInfo; label: string; canDeactivate: boolean; canWithdraw: boolean }[] } | null = null;

// Returns null when BOTH read paths failed (RPC unreachable) so
// callers can show an honest error instead of caching "no accounts"
// for the whole session (audit fix).
async function fetchStakeAccounts(owner: string): Promise<{ info: StakeAccountInfo; label: string; canDeactivate: boolean; canWithdraw: boolean }[] | null> {
  let infos: StakeAccountInfo[] = [];
  let readOk = false;
  try {
    const res = await solanaRpcCall('getProgramAccounts', [STAKE_PROGRAM_ID, { encoding: 'jsonParsed', filters: [{ dataSize: 200 }, { memcmp: { offset: 44, bytes: owner } }] }]);
    readOk = true;
    for (const row of res ?? []) { const inf = parseStakeAccountParsed(row.pubkey, row.account?.lamports ?? 0, row.account?.data?.parsed); if (inf) infos.push(inf); }
  } catch { infos = []; }
  if (!infos.length) {
    try {
      const res = await solanaRpcCall('getProgramAccounts', [STAKE_PROGRAM_ID, { encoding: 'base64', filters: [{ dataSize: 200 }, { memcmp: { offset: 44, bytes: owner } }] }]);
      readOk = true;
      for (const row of res ?? []) { const raw = row.account?.data?.[0]; if (!raw) continue; const inf = parseStakeAccountBytes(row.pubkey, b64Bytes(raw), row.account?.lamports ?? 0); if (inf) infos.push(inf); }
    } catch { /* both read paths may have failed — readOk decides */ }
  }
  if (!readOk) return null;
  // Activation reads run in parallel — serially they cost one RPC
  // round trip per stake account, straight onto the screen's load.
  return Promise.all(infos.map(async (info) => {
    let act: any = null;
    try { act = await solanaRpcCall('getStakeActivation', [info.pubkey]); } catch { /* state unknown */ }
    return { info, ...stakeStateOf(info, act) };
  }));
}

/** Compact activated-stake figure for validator rows: 812K / 1.24M. */
function fmtStakeSol(v: number): string {
  if (v >= 1e6) return (v / 1e6).toFixed(2).replace(/\.?0+$/, '') + 'M';
  if (v >= 1e3) return (v / 1e3).toFixed(1).replace(/\.0$/, '') + 'K';
  return String(Math.round(v));
}
/** Short status word for a stake account row, from stakeStateOf's label. */
function stakeStatusShort(label: string): { t: string; warn: boolean } {
  if (label.startsWith('Active')) return { t: 'Active', warn: false };
  if (label.startsWith('Activating')) return { t: 'Activating', warn: true };
  if (label.startsWith('Deactivating')) return { t: 'Deactivating', warn: true };
  if (label.includes('ready to withdraw')) return { t: 'Ready to withdraw', warn: false };
  if (label.startsWith('Not delegated')) return { t: 'Not delegated', warn: true };
  if (label.startsWith('Inactive')) return { t: 'Inactive', warn: true };
  return { t: 'Delegated', warn: false };
}

function showStake(chainId: string) {
  const c = findChain(chainId) ?? findChain('solana')!;
  const owner = addressFor(c);
  const bal = balances.get(c.id);
  setView(`<main><button class="backBtn" id="bk" aria-label="Back"><i class="ri-arrow-left-s-line"></i></button>
  <h1 class="nftTitle">Stake SOL</h1>
  <p class="pageSub">Native Solana staking — your SOL stays in your own stake account, delegated to a validator. Unstaking takes an epoch or two to cool down.</p>
  <div class="setPanel"><div class="setH">Overview</div>
  <div class="sumRow"><span class="sl">Available</span><span class="sv" id="stkBal">${bal == null ? '…' : trimNum(bal, 6) + ' SOL'}</span></div>
  <div class="sumRow"><span class="sl">Staked</span><span class="sv" id="stkStaked">${stakeListCache && stakeListCache.key === accKey() + ':' + c.id ? trimNum(stakeListCache.rows.reduce((a, r) => a + r.info.delegatedLamports, 0) / 1e9, 6) + ' SOL' : '…'}</span></div>
  <div class="sumRow" id="stkRewardsRow" hidden><span class="sl">Rewards · last epoch</span><span class="sv" id="stkRewards"></span></div>
  <div class="sumRow" id="stkLidoRow" hidden><span class="sl">Liquid staking · Lido</span><span class="sv" id="stkLidoVal"></span></div>
  <div class="sumRow"><span class="sl">Network</span><span class="sv" style="display:inline-flex;align-items:center;gap:8px">${coinIcon(c)} ${esc(c.name)}</span></div>
  <div id="stkEpoch"></div></div>
  <div class="setPanel"><div class="setH">New stake</div>
    <div class="field" style="margin-top:10px"><label>Amount (SOL)</label><input id="stkAmt" class="inp mono" inputmode="decimal" placeholder="0.0"></div>
    <div class="field"><label>Validator — top by stake, or paste any vote pubkey</label><input id="stkSearch" class="inp mono" placeholder="Search or paste vote pubkey"></div>
    <div id="stkList">${waveLoadBlockHTML('Loading validators…', true)}</div>
    <div id="stkErr"></div>
    <button class="ctaWide" id="stkGo">Review stake</button>
  </div>
  <div class="setPanel"><div class="setH">Your stake accounts</div><div id="stkAccounts" style="margin-top:8px">${waveLoadBlockHTML('Loading…', true)}</div></div>
  <div class="setPanel"><div class="setH">About staking</div>
    <div class="sumRow"><span class="sl">How it works</span><span class="sv" style="text-align:right;max-width:62%;font-weight:500;line-height:1.5">Your SOL is delegated to a validator from a stake account you own. The network pays inflation rewards straight into that account.</span></div>
    <div class="sumRow"><span class="sl">Epochs</span><span class="sv" style="text-align:right;max-width:62%;font-weight:500;line-height:1.5">Solana runs in epochs of 432,000 slots — about 2 days. New stake warms up over an epoch or two; unstaking cools down the same way before you can withdraw.</span></div>
    <div class="sumRow"><span class="sl">Commission</span><span class="sv" style="text-align:right;max-width:62%;font-weight:500;line-height:1.5">The validator keeps that cut of your rewards. 0% means you keep them all; the stake itself is never touched by commission.</span></div>
    <div class="sumRow"><span class="sl">Risks</span><span class="sv" style="text-align:right;max-width:62%;font-weight:500;line-height:1.5">Solana has no slashing — delegated SOL can't be cut for validator misbehaviour. A validator that's often offline simply earns less. Delegation never hands over your keys; the SOL stays in your account.</span></div>
  </div></main>`);
  // Liquid staking line: the user's stETH (Lido), valued in SOL from
  // the live price store when both prices are available.
  const stethBal = tokenBalances.get('bt-eth-steth');
  if (stethBal != null && stethBal > 0) {
    const row = $('#stkLidoRow'); const val = $('#stkLidoVal');
    if (row && val) {
      const pu = prices?.['staked-ether']?.usd; const ps = prices?.['solana']?.usd;
      val.textContent = trimNum(stethBal, 6) + ' stETH' + (pu != null && ps != null && ps > 0 ? ' ≈ ' + trimNum(stethBal * pu / ps, 4) + ' SOL' : '');
      row.hidden = false;
    }
  }
  ($('#bk') as HTMLElement).onclick = () => goBack({ route: 'wallet' });
  const paintValidators = () => {
    const slot = $('#stkList'); if (!slot) return;
    const q = (($('#stkSearch') as HTMLInputElement | null)?.value ?? '').trim();
    const rows = stakeValidators.filter(v => !q || v.votePubkey.includes(q) || (validatorInfo?.get(v.votePubkey)?.name || '').toLowerCase().includes(q.toLowerCase())).slice(0, 12);
    if (!rows.length && q.length >= 32) { stakeSelVoter = q; slot.innerHTML = `<p class="small muted">Using pasted vote pubkey <span class="mono">${esc(q.slice(0, 10))}…${esc(q.slice(-6))}</span></p>`; return; }
    slot.innerHTML = rows.length ? rows.map(v => { const vi = validatorInfo?.get(v.votePubkey); const nm = vi?.name || ''; return `<button class="optRow vRow ${stakeSelVoter === v.votePubkey ? 'sel' : ''}" data-voter="${v.votePubkey}" style="margin-bottom:6px"><span class="optLeft">${validatorAvatarHTML(v.votePubkey)}<span class="optLabel">${nm ? esc(nm) : `<span class="mono">${esc(v.votePubkey.slice(0, 10))}…${esc(v.votePubkey.slice(-6))}</span>`}<div class="setDesc">${fmtStakeSol(v.activatedStakeSol)} SOL staked · ${v.commission}% commission${vi && vi.skip != null ? ' · ' + trimNum(vi.skip, 1) + '% skipped' : ''}${v.delinquent ? ' · <span style="color:var(--amber,#e8b23f);font-weight:600">delinquent</span>' : ''}</div></span></span>${stakeSelVoter === v.votePubkey ? '<span class="badge">Selected</span>' : '<span class="arrowChip"><i class="ri-arrow-right-line"></i></span>'}</button>`; }).join('') : '<p class="small muted">No validators match.</p>';
    slot.querySelectorAll('[data-voter]').forEach(b => (b as HTMLElement).onclick = () => { stakeSelVoter = (b as HTMLElement).dataset.voter!; paintValidators(); });
  };
  ($('#stkSearch') as HTMLInputElement).addEventListener('input', paintValidators);
  ($('#stkGo') as HTMLElement).onclick = () => {
    const err = $('#stkErr')!;
    // Audit L-3/H-4: the amount travels as an exact decimal string.
    const amtStr = sanitizeAmt((($('#stkAmt') as HTMLInputElement).value || '').replace(',', '.'), 9);
    const amt = parseFloat(amtStr);
    const voter = stakeSelVoter || (($('#stkSearch') as HTMLInputElement).value || '').trim();
    if (!(amt > 0) || parseRawAmount(amtStr, 9) == null) { err.innerHTML = '<div class="err">Enter an amount to stake.</div>'; return; }
    try { new PublicKey(voter); } catch { err.innerHTML = '<div class="err">Pick a validator from the list or paste a valid vote pubkey.</div>'; return; }
    const b = balances.get(c.id);
    if (b != null && amt + 0.00228288 + 0.00001 > b) { err.innerHTML = '<div class="err">Amount + stake-account rent (0.00228 SOL) + fee exceeds your available SOL.</div>'; return; }
    go({ route: 'stakeconfirm', stakeConfirm: { chainId: c.id, action: 'create', amtStr, voter } }, $('#stkGo') as HTMLElement);
  };
  // Cached validators paint immediately; the async block below
  // refreshes them invisibly when the cache is stale.
  if (stakeValidators.length) paintValidators();
  void (async () => {
    // Epoch strip: current epoch + progress through it (getEpochInfo).
    try {
      const ei: any = await solanaRpcCall('getEpochInfo', []);
      const el = $('#stkEpoch');
      if (el && ei && Number(ei.slotsInEpoch) > 0) {
        const pct = Math.min(100, Math.max(0, Math.round((Number(ei.slotIndex) / Number(ei.slotsInEpoch)) * 100)));
        el.innerHTML = `<div class="sumRow" style="border-bottom:none;padding-bottom:0"><span class="sl">Epoch</span><span class="sv">Epoch ${esc(String(ei.epoch))} · ~${pct}% through</span></div><div class="epochBar"><i style="width:${pct}%"></i></div>`;
      }
    } catch { /* strip stays empty */ }
  })();
  void (async () => {
    // Names + icons load IN PARALLEL from the start — they used to
    // wait behind the vote-accounts read, so rows first painted with
    // bare pubkeys and only re-painted once both had landed.
    void loadValidatorInfo().then(() => { paintValidators(); if (stakeListCache && stakeListCache.key === accKey() + ':' + c.id) paintStakeAccounts(stakeListCache.rows); saveDataCache(); });
    if (!stakeValidators.length || Date.now() - stakeValidatorsAt > 600_000) {
      // The server's trimmed endpoint first (top validators in one
      // small cached response); the raw getVoteAccounts read — every
      // vote account, megabytes — is only the fallback, and only
      // when there is no cached list to paint at all. A cached list
      // older than 10 minutes refreshes invisibly in place.
      let fresh: ValidatorInfo[] = [];
      try {
        const r = await fetch('/api/stake/validators', { signal: AbortSignal.timeout(20000) });
        if (r.ok) { const arr = await r.json(); if (Array.isArray(arr)) fresh = arr.filter((v: any) => v && typeof v.votePubkey === 'string'); }
      } catch { /* fall through to the direct read */ }
      if (!fresh.length && !stakeValidators.length) {
        try { const res = await solanaRpcCall('getVoteAccounts', []); fresh = sortValidators(res, 100); } catch { /* list stays as-is; paste path still works */ }
      }
      if (fresh.length) { stakeValidators = fresh; stakeValidatorsAt = Date.now(); saveDataCache(); }
    }
    if (!stakeSelVoter && stakeValidators.length) stakeSelVoter = stakeValidators[0].votePubkey;
    paintValidators();
    const b2 = balances.get(c.id); const el = $('#stkBal'); if (el && b2 != null) el.textContent = trimNum(b2, 6) + ' SOL';
  })();
  const paintStakeAccounts = (rows: { info: StakeAccountInfo; label: string; canDeactivate: boolean; canWithdraw: boolean }[]) => {
    const slot = $('#stkAccounts'); if (!slot) return;
    slot.innerHTML = rows.length ? rows.map((r, i) => { const st = stakeStatusShort(r.label); const vName = r.info.voter ? validatorName(r.info.voter) : ''; return `<div class="setRow"><span style="display:flex;gap:10px;align-items:center;min-width:0">${r.info.voter ? `<span class="vAvaSm">${validatorAvatarHTML(r.info.voter)}</span>` : ''}<span style="min-width:0"><span class="setLabel">${r.info.voter ? esc(vName || 'Validator ' + r.info.voter.slice(0, 8) + '…') : 'Not delegated'}</span><div class="setDesc">${((r.info.voter ? r.info.delegatedLamports : r.info.lamports) / 1e9).toFixed(6)} SOL · account <span class="mono">${esc(r.info.pubkey.slice(0, 8))}…</span>${r.info.activationEpoch ? ' · since epoch ' + esc(r.info.activationEpoch) : ''}</div></span></span><span style="display:flex;gap:6px;align-items:center"><span class="statusChip ${st.warn ? 'warn' : ''}">${esc(st.t)}</span>${r.canDeactivate ? `<button class="pillBtn" data-deact="${i}">Deactivate</button>` : ''}${r.canWithdraw ? `<button class="pillBtn" data-wd="${i}">Withdraw</button>` : ''}</span></div>`; }).join('') : '<p class="small muted">No stake accounts for this address yet.</p>';
    slot.querySelectorAll('[data-deact]').forEach(b => (b as HTMLElement).onclick = () => { const r = rows[Number((b as HTMLElement).dataset.deact)]; go({ route: 'stakeconfirm', stakeConfirm: { chainId: c.id, action: 'deactivate', stakePubkey: r.info.pubkey, stakeLamports: r.info.lamports } }, b as HTMLElement); });
    slot.querySelectorAll('[data-wd]').forEach(b => (b as HTMLElement).onclick = () => { const r = rows[Number((b as HTMLElement).dataset.wd)]; go({ route: 'stakeconfirm', stakeConfirm: { chainId: c.id, action: 'withdraw', stakePubkey: r.info.pubkey, stakeLamports: r.info.lamports } }, b as HTMLElement); });
  };
  void (async () => {
    const slot = $('#stkAccounts'); if (!slot) return;
    const key = accKey() + ':' + c.id;
    const rows = stakeListCache?.key === key ? stakeListCache.rows : await fetchStakeAccounts(owner);
    if (rows == null) {
      // RPC failure — NOT cached, and never shown as "no accounts".
      if (slot.isConnected) { slot.innerHTML = '<p class="small muted">Stake accounts couldn’t load — Solana didn’t answer. Reopen this screen to retry.</p>'; const se = $('#stkStaked'); if (se) se.textContent = 'Unavailable'; }
      return;
    }
    stakeListCache = { key, rows };
    if (!slot.isConnected) return;
    const stakedEl = $('#stkStaked');
    if (stakedEl) stakedEl.textContent = trimNum(rows.reduce((a, r) => a + r.info.delegatedLamports, 0) / 1e9, 6) + ' SOL';
    paintStakeAccounts(rows);
    // Rewards for the last completed epoch, straight from
    // getInflationReward — shown only when the chain answers for at
    // least one account; otherwise the row stays hidden (never guessed).
    const delegated = rows.filter(r => r.info.voter);
    if (delegated.length) {
      try {
        const ei: any = await solanaRpcCall('getEpochInfo', []);
        const epoch = Number(ei?.epoch);
        if (epoch > 0) {
          const rw: any = await solanaRpcCall('getInflationReward', [delegated.map(r => r.info.pubkey), { epoch: epoch - 1 }]);
          if (Array.isArray(rw) && rw.some((x: any) => x && Number(x.lamports) > 0)) {
            const total = rw.reduce((a: number, x: any) => a + Number(x?.lamports || 0), 0) / 1e9;
            const row = $('#stkRewardsRow'); const val = $('#stkRewards');
            if (row && val && total > 0) { val.textContent = '+' + trimNum(total, 6) + ' SOL'; row.hidden = false; }
          }
        }
      } catch { /* rewards row stays hidden */ }
    }
  })();
}

function showStakeConfirm(p: StakeConfirmPayload, err = '') {
  const c = findChain(p.chainId)!;
  const feeSol = p.action === 'create' ? 0.00001 : 0.000005;
  // Named validator when the identity data knows it — avatar + name,
  // with the vote account kept as its own clear-signing row. Unknown
  // validators keep the single combined row.
  const vName = p.voter ? validatorName(p.voter) : '';
  const voterRow = vName
    ? `<div class="sumRow"><span class="sl">Validator</span><span class="sv" style="display:inline-flex;align-items:center;gap:8px"><span class="vAvaSm">${validatorAvatarHTML(p.voter!)}</span>${esc(vName)}</span></div>
       <div class="sumRow"><span class="sl">Vote account</span><span class="sv"><span class="monoChip" style="max-width:210px" data-full="${esc((p.voter || ''))}">${esc((p.voter || '').slice(0, 10))}…${esc((p.voter || '').slice(-8))}</span></span></div>`
    : `<div class="sumRow"><span class="sl">Validator (vote account)</span><span class="sv"><span class="monoChip" style="max-width:210px" data-full="${esc((p.voter || ''))}">${esc((p.voter || '').slice(0, 10))}…${esc((p.voter || '').slice(-8))}</span></span></div>`;
  const rows = p.action === 'create'
    ? `<div class="sumAmt">${trimNum(parseFloat(p.amtStr || '0'), 8)} SOL</div>
       ${voterRow}
       <div class="sumRow"><span class="sl">Stake account rent</span><span class="sv">0.00228288 SOL</span></div>
       <div class="sumRow"><span class="sl">Network fee</span><span class="sv">~${feeSol} SOL</span></div>
       <div class="sumRow"><span class="sl">Total leaving wallet</span><span class="sv">${trimNum(parseFloat(p.amtStr || '0') + 0.00228288 + feeSol, 8)} SOL</span></div>
       <p class="securityNote" style="margin:12px 0">A new stake account is created in your name and delegated in the same transaction. The rent comes back when you withdraw after unstaking. Rewards accrue to the stake account automatically.</p>`
    : p.action === 'deactivate'
    ? `<div class="sumRow"><span class="sl">Stake account</span><span class="sv"><span class="monoChip" style="max-width:210px" data-full="${esc((p.stakePubkey || ''))}">${esc((p.stakePubkey || '').slice(0, 10))}…${esc((p.stakePubkey || '').slice(-8))}</span></span></div>
       <div class="sumRow"><span class="sl">Account balance</span><span class="sv">${((p.stakeLamports ?? 0) / 1e9).toFixed(6)} SOL</span></div>
       <div class="sumRow"><span class="sl">Network fee</span><span class="sv">~${feeSol} SOL</span></div>
       <p class="securityNote" style="margin:12px 0">Deactivation starts at the next epoch boundary. The stake then cools down (typically 2–4 days) before it can be withdrawn — nothing leaves the stake account with this transaction.</p>`
    : `<div class="sumRow"><span class="sl">Stake account</span><span class="sv"><span class="monoChip" style="max-width:210px" data-full="${esc((p.stakePubkey || ''))}">${esc((p.stakePubkey || '').slice(0, 10))}…${esc((p.stakePubkey || '').slice(-8))}</span></span></div>
       <div class="sumRow"><span class="sl">Returned to your wallet</span><span class="sv">${((p.stakeLamports ?? 0) / 1e9).toFixed(6)} SOL</span></div>
       <div class="sumRow"><span class="sl">Network fee</span><span class="sv">~${feeSol} SOL</span></div>
       <p class="securityNote" style="margin:12px 0">The full stake-account balance — stake, rewards and rent — returns to your wallet and the stake account is closed.</p>`;
  setView(`<main><button class="backBtn" id="bk" aria-label="Back"><i class="ri-arrow-left-s-line"></i></button>
  <div class="card"><h1 class="heroH">Review <span>${p.action === 'create' ? 'stake' : p.action}</span></h1><div style="height:8px"></div>${err ? `<div class="err">${esc(err)}</div>` : ''}
    <div class="sumRow"><span class="sl">Network</span><span class="sv" style="display:inline-flex;align-items:center;gap:8px">${coinIcon(c)} ${esc(c.name)}</span></div>
    ${rows}
    <button class="ctaWide" id="stkDo">${p.action === 'create' ? 'Stake SOL' : p.action === 'deactivate' ? 'Deactivate stake' : 'Withdraw SOL'}</button><div style="height:10px"></div><button class="btnGhost" id="stkCancel" style="border-radius:999px">Cancel</button></div></main>`);
  ($('#bk') as HTMLElement).onclick = () => goBack({ route: 'stake', chainId: c.id });
  ($('#stkCancel') as HTMLElement).onclick = () => goBack({ route: 'stake', chainId: c.id });
  ($('#stkDo') as HTMLElement).onclick = async () => {
    const btn = $('#stkDo') as HTMLButtonElement; btnBusy(btn, 'Signing & broadcasting…');
    try {
      const sig = await doStakeAction(p); recordLocalTx(c.id, sig, p.action === 'create' ? 'Staked SOL' : p.action === 'deactivate' ? 'Unstaking SOL' : 'Withdrew SOL', { dir: 'stake', sym: 'SOL', amt: p.action === 'create' ? p.amtStr : p.action === 'withdraw' ? String((p.stakeLamports ?? 0) / 1e9) : undefined });
      stakeListCache = null; balances.delete(c.id);
      celebrate(btn, () => {
        setView(receiptHTML({ title: `${p.action === 'create' ? 'Stake' : p.action === 'deactivate' ? 'Deactivation' : 'Withdrawal'} submitted`, sub: 'on Solana', hash: sig, doneLabel: 'Back to staking' }));
        bindReceipt(sig, c.explorerTx, (el) => go({ route: 'stake', chainId: c.id }, el));
      });
    } catch (e: any) { showStakeConfirm(p, 'Failed: ' + (e?.message || String(e))); }
  };
}

async function doStakeAction(p: StakeConfirmPayload): Promise<string> {
  const c = findChain(p.chainId)!;
  const kp = solanaKeypairFor(c.kind); if (!kp) throw new Error('No Solana account available to sign.');
  const conn = new Connection(solanaRpcUrl(), 'confirmed');
  let tx: Transaction;
  const signers: Keypair[] = [kp];
  if (p.action === 'create') {
    const stakeKp = Keypair.generate();
    // Audit L-3: no silent hard-coded rent fallback — if the network
    // can't state the rent-exempt minimum, the stake BLOCKS rather
    // than guessing an amount into a signed transaction.
    let rent: number;
    try { rent = await conn.getMinimumBalanceForRentExemption(StakeProgram.space); } catch { throw new Error('Could not read the stake-account rent from the network — nothing was sent. Try again.'); }
    const amtLamports = parseRawAmount(p.amtStr || '', 9);
    if (amtLamports == null) throw new Error('Invalid amount.');
    const lamports = Number(amtLamports + BigInt(rent));
    tx = new Transaction().add(
      StakeProgram.createAccount({ fromPubkey: kp.publicKey, stakePubkey: stakeKp.publicKey, authorized: new Authorized(kp.publicKey, kp.publicKey), lockup: new Lockup(0, 0, kp.publicKey), lamports }),
      StakeProgram.delegate({ stakePubkey: stakeKp.publicKey, authorizedPubkey: kp.publicKey, votePubkey: new PublicKey(p.voter!) }),
    );
    signers.push(stakeKp);
  } else if (p.action === 'deactivate') {
    tx = new Transaction().add(StakeProgram.deactivate({ stakePubkey: new PublicKey(p.stakePubkey!), authorizedPubkey: kp.publicKey }));
  } else {
    tx = new Transaction().add(StakeProgram.withdraw({ stakePubkey: new PublicKey(p.stakePubkey!), authorizedPubkey: kp.publicKey, toPubkey: kp.publicKey, lamports: p.stakeLamports! }));
  }
  const { blockhash } = await conn.getLatestBlockhash('confirmed'); tx.recentBlockhash = blockhash; tx.feePayer = kp.publicKey; tx.sign(...signers);
  return await sendSolanaSigned(conn, tx.serialize(), bs58.encode(tx.signature!));
}

// ---------- Wave 2: Lido liquid staking (Ethereum) ----------
// stETH contract verified on-chain from sober77 (name/symbol/code at
// 0xae7a…fE84). Stake = submit(referral) payable; stETH is rebasing, so
// the received amount is set by the protocol at execution (~1:1) — the
// confirm says exactly that instead of promising a figure.
const LIDO_STETH = '0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84';
function showLidoStake() {
  const c = findChain('ethereum')!;
  const bal = balances.get('ethereum');
  const steth = tokenBalances.get('bt-eth-steth');
  setView(`<main><button class="backBtn" id="bk" aria-label="Back"><i class="ri-arrow-left-s-line"></i></button>
  <div class="card"><h1 class="heroH">Stake with <span>Lido</span></h1><p class="heroSub" style="margin-top:2px">Liquid staking on Ethereum: deposit ETH, receive stETH. stETH rebases with staking rewards (Lido takes a protocol fee from the rewards, currently 10%).</p>
  <div style="height:10px"></div><div class="sumRow"><span class="sl">Available</span><span class="sv">${bal == null ? '…' : trimNum(bal, 6) + ' ETH'}</span></div>
  <div class="sumRow"><span class="sl">Your stETH</span><span class="sv">${steth == null ? '…' : trimNum(steth, 6) + ' stETH'}</span></div></div>
  <div class="setPanel"><div class="setH">New stake</div>
    <div class="field" style="margin-top:10px"><label>Amount (ETH)</label><input id="lidoAmt" class="inp mono" inputmode="decimal" placeholder="0.0"></div>
    <div id="lidoErr"></div>
    <button class="ctaWide" id="lidoGo">Review stake</button>
    <p class="securityNote" style="margin-top:12px">Unstaking stETH back to ETH goes through Lido's withdrawal queue (days, not instant) or a swap. This screen stakes only.</p>
  </div></main>`);
  ($('#bk') as HTMLElement).onclick = () => goBack({ route: 'wallet' });
  ($('#lidoGo') as HTMLElement).onclick = () => {
    const amtStr = sanitizeAmt((($('#lidoAmt') as HTMLInputElement).value || '').replace(',', '.'), 8);
    const amt = parseFloat(amtStr);
    const err = $('#lidoErr')!;
    if (!(amt > 0)) { err.innerHTML = '<div class="err">Enter an amount to stake.</div>'; return; }
    const b = balances.get('ethereum');
    if (b != null && amt >= b) { err.innerHTML = '<div class="err">Amount must leave ETH behind for the network fee.</div>'; return; }
    go({ route: 'lidoconfirm', lidoAmt: amtStr }, $('#lidoGo') as HTMLElement);
  };
}
function showLidoConfirm(amtStr: string, err = '') {
  const amt = parseFloat(amtStr) || 0; // display only — parseEther receives amtStr verbatim (audit H-4)
  const c = findChain('ethereum')!;
  setView(`<main><button class="backBtn" id="bk" aria-label="Back"><i class="ri-arrow-left-s-line"></i></button>
  <div class="card"><h1 class="heroH">Review <span>Lido stake</span></h1><div style="height:8px"></div>${err ? `<div class="err">${esc(err)}</div>` : ''}
    <div class="sumAmt">${trimNum(amt, 8)} ETH</div>
    <div class="sumRow"><span class="sl">You receive</span><span class="sv">≈ ${trimNum(amt, 8)} stETH</span></div>
    <p class="small muted" style="line-height:1.55">The exact stETH amount is set by the Lido protocol when the transaction executes (historically ~1:1). stETH then rebases upward as rewards accrue.</p>
    <div class="sumRow"><span class="sl">Contract</span><span class="sv"><button class="monoChip" id="lidoChip">${esc(shortAddr(LIDO_STETH))}</button></span></div>
    <div class="sumRow"><span class="sl">Network</span><span class="sv" style="display:inline-flex;align-items:center;gap:8px">${coinIcon(c)} Ethereum</span></div>
    ${gasBoxHTML(c)}
    <button class="ctaWide" id="lidoDo" style="margin-top:14px">Stake with Lido</button><div style="height:10px"></div><button class="btnGhost" id="lidoCancel" style="border-radius:999px">Cancel</button></div></main>`);
  let gasLimitEst = 160000n;
  const pk = evmPrivKey();
  if (pk) { void (async () => { try { const provider = new ethers.JsonRpcProvider(evmProviderUrl(c), c.evmId); const contract = new ethers.Contract(LIDO_STETH, ['function submit(address) payable returns (uint256)'], new ethers.Wallet(pk, provider)); gasLimitEst = await contract.submit.estimateGas(ethers.ZeroAddress, { value: ethers.parseEther(amtStr) }); } catch { /* default stands */ } })(); }
  bindGasBox(c, () => gasLimitEst, () => {});
  ($('#bk') as HTMLElement).onclick = () => goBack({ route: 'lido' });
  ($('#lidoCancel') as HTMLElement).onclick = () => goBack({ route: 'lido' });
  ($('#lidoChip') as HTMLElement).onclick = (e) => copyText(LIDO_STETH, e.currentTarget as HTMLElement);
  ($('#lidoDo') as HTMLElement).onclick = async () => {
    const btn = $('#lidoDo') as HTMLButtonElement; btnBusy(btn, 'Signing & broadcasting…');
    try {
      if (!pk) throw new Error('No EVM account available to sign.');
      if (feeState.mode !== 'auto' && !chosenFees(feeState, feeInfo)) throw new Error('Network fee data is unavailable, so your ' + feeState.mode + ' fee choice cannot be applied. Switch the fee back to Auto or try again — nothing was sent.');
      const provider = new ethers.JsonRpcProvider(evmProviderUrl(c), c.evmId);
      const wallet = new ethers.Wallet(pk, provider);
      const contract = new ethers.Contract(LIDO_STETH, ['function submit(address) payable returns (uint256)'], wallet);
      const ch = chosenFees(feeState, feeInfo);
      const tx = await contract.submit(ethers.ZeroAddress, { value: ethers.parseEther(amtStr), ...(ch ? ch.overrides : {}) }); recordLocalTx('ethereum', tx.hash, 'Staked ETH · Lido', { dir: 'stake', sym: 'ETH', amt: amtStr });
      balances.delete('ethereum'); tokenBalances.delete('bt-eth-steth');
      celebrate(btn, () => {
        setView(receiptHTML({ title: 'Lido stake submitted', sub: 'on Ethereum · Lido', hash: tx.hash, doneLabel: 'Done' }));
        bindReceipt(tx.hash, c.explorerTx, (el) => goTab('wallet', el));
      });
    } catch (e: any) { showLidoConfirm(amtStr, 'Stake failed: ' + (e?.shortMessage || e?.message || String(e))); }
  };
}

// ---------- Wave 2: NFT gallery ----------
// Solana: plain-RPC reads — token accounts (both token programs) whose
// amount is a whole unit, then Metaplex metadata PDAs and the metadata
// JSON, fetched client-side. Compressed NFTs (state-compression) do NOT
// appear via plain RPC and the screen says so. EVM: Blockscout's keyless
// indexer, only on chains that have one; other EVM chains show an honest
// unsupported note rather than a fake empty gallery.
let nftItems: NftItem[] | null = null;
let nftForKey = '';
let nftNotes: string[] = [];
// True when nftItems came from the disk cache at unlock: screens
// paint it instantly, and the first warm/open revalidates it once.
let nftStale = false;

// Set by fetchSolanaNfts when the 60-account metadata cap bites, so
// the gallery can say so instead of silently dropping the rest.
let solNftFoundCount = 0;
async function fetchSolanaNfts(c: Chain): Promise<NftItem[]> {
  const owner = addressFor(c);
  const found: { mint: string; amount: number; program: string }[] = [];
  for (const program of [TOKEN_PROGRAM_ID, TOKEN_2022_PROGRAM_ID]) {
    try {
      const res = await solanaRpcCall('getTokenAccountsByOwner', [owner, { programId: program }, { encoding: 'jsonParsed' }]);
      for (const row of res?.value ?? []) {
        const info = row.account?.data?.parsed?.info;
        const ta = info?.tokenAmount;
        if (info?.mint && ta && Number(ta.decimals) === 0 && Number(ta.amount) >= 1) found.push({ mint: info.mint, amount: Number(ta.amount), program });
      }
    } catch { /* program read failed — the other may still answer */ }
  }
  const items: NftItem[] = [];
  const metaProg = new PublicKey(METADATA_PROGRAM_ID);
  solNftFoundCount = found.length;
  const slice = found.slice(0, 60);
  if (slice.length) {
    const pdas = slice.map(f => PublicKey.findProgramAddressSync([new TextEncoder().encode('metadata'), metaProg.toBytes(), new PublicKey(f.mint).toBytes()], metaProg)[0].toBase58());
    let accounts: any[] = [];
    try { const res = await solanaRpcCall('getMultipleAccounts', [pdas, { encoding: 'base64' }]); accounts = res?.value ?? []; } catch { accounts = []; }
    for (let i = 0; i < slice.length; i++) {
      const f = slice[i];
      const raw = accounts[i]?.data?.[0];
      const meta = raw ? parseMetaplexMetadata(b64Bytes(raw)) : null;
      let fields = { name: '', image: '', collection: '', description: '' };
      let attrs: { k: string; v: string }[] = [];
      let rawImg = '';
      // Audit NEW MEDIUM (2026-11-19): the metadata URI is attacker-
      // controlled (anyone can airdrop an NFT pointing it anywhere).
      // Only https: URLs (or ipfs/ar rewrites to https gateways) are
      // ever fetched — never LAN/localhost/http/javascript: targets,
      // so airdrops can't fingerprint this device or probe its network.
      const metaUrl = meta?.uri ? safeMediaUrl(meta.uri) : '';
      if (metaUrl) {
        try {
          const ctl = new AbortController(); const to = setTimeout(() => ctl.abort(), 8000);
          const r = await fetch(metaUrl, { signal: ctl.signal }); clearTimeout(to);
          if (r.ok) { const j = await r.json(); fields = metadataJsonFields(j); attrs = metadataAttributes(j); rawImg = typeof j?.image === 'string' ? j.image : typeof j?.image_url === 'string' ? j.image_url : ''; }
        } catch { /* metadata JSON unreachable — mint-only entry */ }
      }
      const images = mediaCandidates(rawImg || fields.image);
      items.push({ key: `solana:${c.id}:${f.mint}:${f.mint}`, family: 'solana', chainId: c.id, contract: f.mint, tokenId: f.mint, name: fields.name || meta?.name || 'Unnamed NFT', collection: fields.collection || meta?.symbol || '', image: images[0] || safeMediaUrl(fields.image), images, description: fields.description || '', standard: 'SPL', amount: f.amount, tokenProgram: f.program, attributes: attrs });
    }
  }
  return items;
}

async function fetchEvmNfts(c: Chain): Promise<{ items: NftItem[]; supported: boolean }> {
  if (!c.blockscout) return { items: [], supported: false };
  const addr = addressFor(c);
  // Audit fix: follow Blockscout pagination (up to 3 pages) — page 1
  // alone silently dropped every NFT beyond it.
  let url = `${c.blockscout}/api/v2/addresses/${addr}/nft?type=ERC-721,ERC-1155`;
  const all: any[] = [];
  for (let page = 0; page < 3; page++) {
    const r = await fetch(url, { signal: AbortSignal.timeout(10000) });
    if (!r.ok) throw new Error('indexer ' + r.status);
    const j = await r.json();
    if (Array.isArray(j?.items)) all.push(...j.items);
    const np = j?.next_page_params;
    if (!np || typeof np !== 'object') break;
    const qs = Object.entries(np).map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`).join('&');
    url = `${c.blockscout}/api/v2/addresses/${addr}/nft?type=ERC-721,ERC-1155&${qs}`;
  }
  return { items: normalizeBlockscoutNfts({ items: all }, c.id), supported: true };
}

async function loadAllNfts(): Promise<void> {
  // Chains load CONCURRENTLY: one slow indexer must not stall the rest
  // (the Explore count on Home waits on this via the background warm).
  const per = await Promise.all(visibleChains().map(async (c): Promise<{ items: NftItem[]; note?: string }> => {
    if (c.kind === 'solana' || c.kind === 'solana-tw' || c.kind === 'solana-phantom') {
      try { const items = await fetchSolanaNfts(c); return solNftFoundCount > 60 ? { items, note: `${c.name}: ${solNftFoundCount} NFT token accounts found — showing the first 60.` } : { items }; } catch { return { items: [], note: `${c.name}: NFT read failed — pull to reopen this screen to retry.` }; }
    }
    if (c.kind === 'evm') {
      try {
        const r = await fetchEvmNfts(c);
        if (!r.supported) return { items: [], note: `${c.name}: no keyless NFT indexer covers this network yet, so its NFTs can't be listed.` };
        return { items: r.items };
      } catch { return { items: [], note: `${c.name}: NFT indexer unreachable right now.` }; }
    }
    return { items: [] };
  }));
  const items: NftItem[] = []; const notes: string[] = [];
  for (const r of per) { items.push(...r.items); if (r.note) notes.push(r.note); }
  nftItems = items; nftNotes = notes; nftForKey = accKey(); nftStale = false;
  saveDataCache();
}

function nftCardHTML(n: NftItem): string {
  const c = findChain(n.chainId);
  const initial = esc(((n.collection || n.name || '').match(/[A-Za-z0-9]/)?.[0] || 'N').toUpperCase());
  return `<button class="nftCard2" data-nft="${esc(n.key)}"><span class="nftThumb"><span class="nftPh"><i class="ri-image-line"></i><b>${initial}</b></span>${n.image ? `<img src="${esc(n.image)}" alt="" loading="lazy"${candsAttr(n.images)}>` : ''}<span class="nftChainBadge">${c ? coinIcon(c) : ''}${esc(c?.name ?? '')}</span></span><span class="nftName">${esc(n.name)}</span><span class="nftCol">${esc(n.collection || '')}</span></button>`;
}

// ---------- Collectibles promo card ----------
// The approved standalone card (~/workspace/syn-nft-card) under the
// Collectibles screen's left-aligned title (the old centred header
// card was removed at the user's order). Its live line is REAL: it
// rotates through the user's own first pieces — and is absent when
// the wallet holds none. The CTA opens Receive. The card renders
// SETTLED, always — no entrance animation: the staggered rise read
// to the user as the card "loading when the tab is clicked", even
// with its data already cached (frame proof, Wave 20 fix).
let nftPromoTimer: ReturnType<typeof setInterval> | null = null;
function nftPromoPieceHTML(n: NftItem, idx: number): string {
  const thumb = n.image ? `<img src="${esc(n.image)}" alt="" loading="lazy"${candsAttr(n.images)}>` : '';
  const bg = n.image ? '' : ` style="background-image:url(/assets/nft-tile-${(idx % 3) + 1}.jpg)"`;
  return `<span class="npThumb"${bg}>${thumb}</span><span class="npName">${esc(n.name)}</span><span class="npTag">${esc(n.collection || '')}</span>`;
}
function nftPromoHTML(vis: NftItem[]): string {
  const line = vis.length ? `<div class="npLive npRise" style="animation-delay:.27s"><span class="liveDotSm"></span><span class="npSwap" id="npSwap">${nftPromoPieceHTML(vis[0], 0)}</span></div>` : '';
  return `<div class="npCard${wavesFxOn() ? ' fxOn' : ''} settled">
    <svg class="npWm" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.1" aria-hidden="true"><rect x="2.5" y="3.5" width="19" height="17" rx="2.5"/><circle cx="8.6" cy="9.4" r="1.6"/><path d="M4 18.5l4.8-4.9 3.2 3.2 3.4-3.6 4.6 4.8"/></svg><span class="npGlass"></span>
    <div class="npTop npRise" style="animation-delay:.06s"><span class="npNew">NEW</span><span class="npKick">in your wallet</span></div>
    <div class="npHead npRise" style="animation-delay:.13s">Your <span class="npAcc">NFTs</span>, in your wallet</div>
    <p class="npCopy npRise" style="animation-delay:.2s">All your collectibles on Solana and Ethereum — view, track and keep them safe, right here in your wallet.</p>
    ${line}
    <div class="npFoot npRise" style="animation-delay:.34s"><button class="npCta" id="npReceive"><span class="npSheen"></span>Receive <span class="npAcc">NFTs</span><i class="ri-arrow-down-line"></i></button><span class="npStack" aria-hidden="true"><i style="background-image:url(/assets/nft-tile-1.jpg)"></i><i style="background-image:url(/assets/nft-tile-2.jpg)"></i><i style="background-image:url(/assets/nft-tile-3.jpg)"></i></span></div>
  </div>`;
}

function showNfts() {
  const hidden = new Set(config.hiddenNfts);
  const paint = () => {
    if (nftPromoTimer) { clearInterval(nftPromoTimer); nftPromoTimer = null; }
    const items = nftItems ?? [];
    const visAll = items.filter(n => !hidden.has(n.key));
    const hid = items.filter(n => hidden.has(n.key));
    // Addition 7: scam-airdrop quarantine. Flagged items leave the main
    // grid (and the Explore count) for a collapsed section below; the
    // user's own "not spam" choice overrides the heuristic.
    const okSet = new Set(config.spamOkNfts);
    const spam = visAll.filter(n => isSpamNft(n) && !okSet.has(n.key));
    const vis = visAll.filter(n => !isSpamNft(n) || okSet.has(n.key));
    // Group by collection: collections with several pieces get a header.
    const groups = new Map<string, NftItem[]>();
    for (const n of vis) { const k = n.collection || ''; if (!groups.has(k)) groups.set(k, []); groups.get(k)!.push(n); }
    const multi = [...groups.entries()].filter(([, v]) => v.length >= 2).sort((a, b) => b[1].length - a[1].length);
    const multiKeys = new Set(multi.map(([k]) => k));
    const singles = vis.filter(n => !multiKeys.has(n.collection || ''));
    const gallery = multi.map(([k, v]) => `<div class="nftGroupH">${esc(k)}</div><div class="nftGrid2">${v.map(nftCardHTML).join('')}</div>`).join('')
      + (singles.length ? `<div class="nftGrid2" ${multi.length ? 'style="margin-top:14px"' : ''}>${singles.map(nftCardHTML).join('')}</div>` : '');
    setView(`<main><button class="backBtn" id="bk" aria-label="Back"><i class="ri-arrow-left-s-line"></i></button>
    <div class="nftTitle">Collectibles</div>
    <p class="nftSub">${nftItems == null ? 'Reading your NFTs from the chains…' : vis.length + ' NFT' + (vis.length === 1 ? '' : 's') + ' found'}</p>
    ${nftPromoHTML(vis)}
    ${nftItems == null ? `<div class="card" style="margin-top:12px">${waveLoadBlockHTML('Loading…', true)}</div>` : vis.length ? gallery : `<div class="card" style="margin-top:12px"><div class="emptyState"><span class="tile"><i class="ri-image-2-line"></i></span><span class="et">No collectibles yet</span><span class="es">NFTs sent to your addresses will appear here.</span></div></div>`}
    ${nftItems != null && spam.length ? `<div class="setPanel"><button class="spamHead" id="spamToggle"><span><i class="ri-spam-2-line"></i>Possibly spam (${spam.length})</span><i class="ri-arrow-down-s-line"></i></button>
      <p class="securityNote" style="margin-top:8px">These can be scams — never visit links in NFT names, and never connect your wallet to a site one of them names.</p>
      <div id="spamGrid" hidden><div class="nftGrid2" style="padding:12px 0 4px">${spam.map(nftCardHTML).join('')}</div></div></div>` : ''}
    ${nftItems != null && nftNotes.length ? `<p class="covLine"><i class="ri-information-line"></i>Some networks can't be indexed yet<button class="covBtn" id="covDetails">Details</button></p>` : ''}
    ${hid.length ? `<div class="setPanel"><div class="setH">Hidden</div>${hid.map(n => `<div class="setRow"><span class="setLabel">${esc(n.name)}</span><button class="pillBtn" data-unhide="${esc(n.key)}">Unhide</button></div>`).join('')}</div>` : ''}
    </main>`);
    const recv = $('#npReceive') as unknown as HTMLElement | null;
    if (recv) recv.onclick = () => { const c = visibleChains()[0]; if (c) go({ route: 'receive', chainId: c.id }, recv); };
    if (vis.length > 1) {
      let npI = 0;
      nftPromoTimer = setInterval(() => {
        const sw = $('#npSwap');
        if (!sw || currentRoute !== 'nfts') { if (nftPromoTimer) { clearInterval(nftPromoTimer); nftPromoTimer = null; } return; }
        sw.classList.add('swapOut');
        setTimeout(() => {
          if (!sw.isConnected) return;
          npI = (npI + 1) % Math.min(vis.length, 3);
          sw.innerHTML = nftPromoPieceHTML(vis[npI], npI);
          sw.classList.add('swapIn'); sw.classList.remove('swapOut');
          requestAnimationFrame(() => requestAnimationFrame(() => sw.classList.remove('swapIn')));
        }, 460);
      }, 4600);
    }
    const spT = $('#spamToggle'); if (spT) spT.onclick = () => { const g = $('#spamGrid'); if (g) g.hidden = !g.hidden; };
    const cov = $('#covDetails'); if (cov) cov.onclick = () => openSheet('Coverage details', `<p class="noteP">Solana NFTs are read straight from the chain (token accounts + Metaplex metadata). <b>Compressed NFTs (cNFTs) don't appear</b> — plain RPC can't enumerate them. EVM NFTs come from Blockscout's keyless indexer where one exists.</p>${nftNotes.length ? nftNotes.map(t => `<p class="noteP">${esc(t)}</p>`).join('') : '<p class="noteP">Every visible network was read successfully.</p>'}`);
    ($('#bk') as HTMLElement).onclick = () => goBack({ route: 'wallet' });
    document.querySelectorAll('[data-nft]').forEach(b => (b as HTMLElement).onclick = () => go({ route: 'nft', nftKey: (b as HTMLElement).dataset.nft! }, b as HTMLElement));
    document.querySelectorAll('[data-unhide]').forEach(b => (b as HTMLElement).onclick = () => { config.hiddenNfts = config.hiddenNfts.filter(k => k !== (b as HTMLElement).dataset.unhide); saveConfig(); showNfts(); });
  };
  paint();
  if (nftItems == null || nftForKey !== accKey() || nftStale) void loadAllNfts().then(() => { if (currentRoute === 'nfts') paint(); });
}

function showNft(key: string) {
  const n = (nftItems ?? []).find(x => x.key === key);
  if (!n) { go({ route: 'nfts' }); return; }
  const c = findChain(n.chainId);
  setView(`<main><div style="display:flex;justify-content:space-between;align-items:flex-start;padding-right:20px"><button class="backBtn" id="bk" aria-label="Back"><i class="ri-arrow-left-s-line"></i></button>
  <span class="menuWrap"><button class="backBtn" id="nftMenuBtn" aria-label="More actions" style="margin-left:0;margin-right:0"><i class="ri-more-2-fill"></i></button>
  <span class="popMenu" id="nftMenu" hidden>${isSpamNft(n) && !config.spamOkNfts.includes(n.key) ? '<button id="nftNotSpam"><i class="ri-shield-check-line"></i>Not spam — show in gallery</button>' : ''}<button id="nftHide"><i class="ri-eye-off-line"></i>Hide</button><button id="nftReport" class="danger"><i class="ri-flag-line"></i>Report &amp; hide</button></span></span></div>
  <div style="padding:0 16px"><div class="nftHeroWrap"><span class="nftPh"><i class="ri-image-line"></i><b>${esc((n.collection || n.name || '?').trim().slice(0, 1).toUpperCase() || '?')}</b></span>${n.image ? `<img class="nftHero" src="${esc(n.image)}" alt="" style="margin:0;width:100%"${candsAttr(n.images)}>` : ''}</div></div>
  <div class="card"><h1 class="heroH" style="margin-top:2px">${esc(n.name)}</h1>
  ${n.collection ? `<p class="heroSub">${esc(n.collection)}</p>` : ''}
  ${n.description ? `<p class="small muted" style="line-height:1.55;margin-top:8px">${esc(n.description.slice(0, 400))}</p>` : ''}
  <div style="height:10px"></div>
  <div class="sumRow"><span class="sl">Network</span><span class="sv" style="display:inline-flex;align-items:center;gap:8px">${c ? coinIcon(c) : ''} ${esc(c?.name ?? n.chainId)}</span></div>
  <div class="sumRow"><span class="sl">Standard</span><span class="sv">${esc(n.standard)}</span></div>
  ${n.amount > 1 ? `<div class="sumRow"><span class="sl">Amount held</span><span class="sv">${n.amount}</span></div>` : ''}
  <div class="sumRow"><span class="sl">${n.family === 'solana' ? 'Mint address' : 'Token address'}</span><span class="sv"><button class="monoChip" id="nftChip">${esc(shortAddr(n.contract))}</button></span></div>
  ${n.family === 'evm' ? `<div class="sumRow"><span class="sl">Token ID</span><span class="sv mono">${esc(n.tokenId.length > 18 ? n.tokenId.slice(0, 16) + '…' : n.tokenId)}</span></div>` : ''}
  ${n.attributes && n.attributes.length ? `<div style="margin-top:14px"><div class="setH" style="margin-bottom:8px">Attributes</div><div class="attrChips">${n.attributes.map(a => `<span class="attrChip"><span>${esc(a.k)}</span>${esc(a.v)}</span>`).join('')}</div></div>` : ''}
  </div>
  <div class="setPanel"><div class="setH">Send this NFT</div>
    <div class="field" style="margin-top:10px"><label>Recipient address</label><input id="nftTo" class="inp mono" placeholder="${n.family === 'solana' ? 'Solana address' : '0x… address'}"></div>
    <div id="nftErr"></div>
    <button class="ctaWide" id="nftSend">Review transfer</button>
  </div></main>`);
  ($('#bk') as HTMLElement).onclick = () => goBack({ route: 'nfts' });
  ($('#nftChip') as HTMLElement).onclick = (e) => copyText(n.contract, e.currentTarget as HTMLElement);
  const menu = $('#nftMenu') as HTMLElement;
  ($('#nftMenuBtn') as HTMLElement).onclick = (e) => { e.stopPropagation(); menu.hidden = !menu.hidden; };
  document.addEventListener('click', function nftMenuAway(ev) { if (!menu.isConnected) { document.removeEventListener('click', nftMenuAway); return; } if (!(ev.target as HTMLElement).closest('.menuWrap')) menu.hidden = true; });
  ($('#nftHide') as HTMLElement).onclick = () => { if (!config.hiddenNfts.includes(n.key)) config.hiddenNfts.push(n.key); saveConfig(); go({ route: 'nfts' }); };
  ($('#nftReport') as HTMLElement).onclick = () => { if (!config.hiddenNfts.includes(n.key)) config.hiddenNfts.push(n.key); if (!config.reportedNfts.includes(n.key)) config.reportedNfts.push(n.key); saveConfig(); go({ route: 'nfts' }); };
  const nsBtn = $('#nftNotSpam'); if (nsBtn) nsBtn.onclick = () => { if (!config.spamOkNfts.includes(n.key)) config.spamOkNfts.push(n.key); saveConfig(); go({ route: 'nfts' }); };
  ($('#nftSend') as HTMLElement).onclick = () => {
    const to = (($('#nftTo') as HTMLInputElement).value || '').trim();
    const err = $('#nftErr')!;
    if (n.family === 'solana') { try { new PublicKey(to); } catch { err.innerHTML = '<div class="err">That is not a valid Solana address.</div>'; return; } }
    else if (!ethers.isAddress(to)) { err.innerHTML = '<div class="err">That is not a valid EVM address.</div>'; return; }
    go({ route: 'nftconfirm', nftConfirm: { nft: n, to } }, $('#nftSend') as HTMLElement);
  };
}

function showNftConfirm(n: NftItem, to: string, err = '') {
  const c = findChain(n.chainId)!;
  const isEvm = n.family === 'evm';
  setView(`<main><button class="backBtn" id="bk" aria-label="Back"><i class="ri-arrow-left-s-line"></i></button>
  <div class="card"><h1 class="heroH">Review <span>NFT transfer</span></h1><div style="height:8px"></div>${err ? `<div class="err">${esc(err)}</div>` : ''}
    ${n.image ? `<img class="nftHero" src="${esc(n.image)}" alt=""${candsAttr(n.images)}>` : ''}
    <div class="sumRow"><span class="sl">NFT</span><span class="sv">${esc(n.name)}</span></div>
    <div class="sumRow"><span class="sl">Network</span><span class="sv" style="display:inline-flex;align-items:center;gap:8px">${coinIcon(c)} ${esc(c.name)}</span></div>
    <div class="sumRow"><span class="sl">${n.family === 'solana' ? 'Mint' : 'Contract'}</span><span class="sv"><span class="monoChip" style="max-width:210px" data-full="${esc(n.contract)}">${esc(n.contract.slice(0, 10))}…${esc(n.contract.slice(-8))}</span></span></div>
    ${isEvm ? `<div class="sumRow"><span class="sl">Token ID</span><span class="sv mono">${esc(n.tokenId.length > 18 ? n.tokenId.slice(0, 16) + '…' : n.tokenId)}</span></div>` : ''}
    <div class="sumRow"><span class="sl">To</span><span class="sv"><span class="monoChip" style="max-width:210px" data-full="${esc(to)}">${esc(to.slice(0, 10))}…${esc(to.slice(-8))}</span></span></div>
    <div class="sumRow"><span class="sl">Amount</span><span class="sv">${n.family === 'solana' ? 1 : Math.min(n.amount, 1)} of ${n.amount}</span></div>
    ${gasBoxHTML(c)}
    <p class="securityNote" style="margin:12px 0">NFT transfers are permanent. Double-check the recipient — there is no undo.</p>
    <button class="ctaWide" id="nftDo">Transfer NFT</button><div style="height:10px"></div><button class="btnGhost" id="nftCancel" style="border-radius:999px">Cancel</button></div></main>`);
  let gasLimitEst = 100000n;
  if (isEvm) {
    const pk = evmPrivKey();
    if (pk) void (async () => { try { const provider = new ethers.JsonRpcProvider(evmProviderUrl(c), c.evmId); const w = new ethers.Wallet(pk, provider); const id = BigInt(n.tokenId); if (n.standard === 'ERC-1155') { const ct = new ethers.Contract(n.contract, ['function safeTransferFrom(address,address,uint256,uint256,bytes)'], w); gasLimitEst = await ct.safeTransferFrom.estimateGas(w.address, to, id, 1n, '0x'); } else { const ct = new ethers.Contract(n.contract, ['function transferFrom(address,address,uint256)'], w); gasLimitEst = await ct.transferFrom.estimateGas(w.address, to, id); } } catch { /* default stands */ } })();
    bindGasBox(c, () => gasLimitEst, () => {});
  }
  ($('#bk') as HTMLElement).onclick = () => goBack({ route: 'nft', nftKey: n.key });
  ($('#nftCancel') as HTMLElement).onclick = () => goBack({ route: 'nft', nftKey: n.key });
  ($('#nftDo') as HTMLElement).onclick = async () => {
    const btn = $('#nftDo') as HTMLButtonElement; btnBusy(btn, 'Signing & broadcasting…');
    try {
      const hash = await doNftTransfer(n, to); recordLocalTx(n.chainId, hash, 'Sent NFT', { dir: 'nft', cp: to, img: safeMediaUrl(n.image || '') || undefined });
      nftItems = null;
      celebrate(btn, () => {
        setView(receiptHTML({ title: 'NFT sent', sub: n.name || 'Collectible', hash, doneLabel: 'Back to Collectibles' }));
        bindReceipt(hash, c.explorerTx, (el) => go({ route: 'nfts' }, el));
      });
    } catch (e: any) { showNftConfirm(n, to, 'Transfer failed: ' + (e?.shortMessage || e?.message || String(e))); }
  };
}

async function doNftTransfer(n: NftItem, to: string): Promise<string> {
  const c = findChain(n.chainId)!;
  if (n.family === 'solana') {
    const kp = solanaKeypairFor(c.kind); if (!kp) throw new Error('No Solana account available to sign.');
    const program = new PublicKey(n.tokenProgram || TOKEN_PROGRAM_ID);
    const mint = new PublicKey(n.contract); const dest = new PublicKey(to);
    const conn = new Connection(solanaRpcUrl(), 'confirmed');
    const fromAta = getAssociatedTokenAddressSync(mint, kp.publicKey, false, program);
    const toAta = getAssociatedTokenAddressSync(mint, dest, false, program);
    const ixs = [];
    if (!(await conn.getAccountInfo(toAta))) ixs.push(createAssociatedTokenAccountInstruction(kp.publicKey, toAta, dest, mint, program));
    ixs.push(createTransferInstruction(fromAta, toAta, kp.publicKey, 1, [], program));
    const tx = new Transaction().add(...ixs);
    const { blockhash } = await conn.getLatestBlockhash('confirmed'); tx.recentBlockhash = blockhash; tx.feePayer = kp.publicKey; tx.sign(kp);
    return await sendSolanaSigned(conn, tx.serialize(), bs58.encode(tx.signature!));
  }
  const pk = evmPrivKey(); if (!pk) throw new Error('No EVM account available to sign.');
  const provider = new ethers.JsonRpcProvider(evmProviderUrl(c), c.evmId);
  const wallet = new ethers.Wallet(pk, provider);
  const ch = chosenFees(feeState, feeInfo);
  const ov = ch ? ch.overrides : {};
  const id = BigInt(n.tokenId);
  if (n.standard === 'ERC-1155') {
    const ct = new ethers.Contract(n.contract, ['function safeTransferFrom(address,address,uint256,uint256,bytes)'], wallet);
    const tx = await ct.safeTransferFrom(wallet.address, to, id, 1n, '0x', ov);
    return tx.hash;
  }
  const ct = new ethers.Contract(n.contract, ['function transferFrom(address,address,uint256)'], wallet);
  const tx = await ct.transferFrom(wallet.address, to, id, ov);
  return tx.hash;
}

// ---------- Wave 2: dApp discovery ----------
// The user's named dApps, with their real logos self-hosted under
// /assets/dapps/. They open EXTERNALLY in a new tab — there is no in-app
// browser; in-app signing arrives through WalletConnect (Connect screen).
const DAPPS: { name: string; url: string; logo: string; chains: string[]; cat: string; blurb: string }[] = [
  { name: 'Uniswap', url: 'https://app.uniswap.org', logo: '/assets/dapps/uniswap.ico', chains: ['Ethereum', 'Multi-chain'], cat: 'DEX', blurb: 'Decentralised exchange — swap tokens on Ethereum and L2s.' },
  { name: 'PancakeSwap', url: 'https://pancakeswap.finance', logo: '/assets/dapps/pancakeswap.ico', chains: ['BNB Chain', 'Multi-chain'], cat: 'DEX', blurb: 'The main DEX on BNB Chain — swaps, farms and pools.' },
  { name: 'Aave', url: 'https://app.aave.com', logo: '/assets/dapps/aave.ico', chains: ['Ethereum', 'Multi-chain'], cat: 'Lending', blurb: 'Lending protocol — supply assets and borrow against them.' },
  { name: 'OpenSea', url: 'https://opensea.io', logo: '/assets/dapps/opensea.png', chains: ['Ethereum', 'Multi-chain'], cat: 'NFT', blurb: 'NFT marketplace for buying and selling collectibles.' },
  { name: 'Compound', url: 'https://app.compound.finance', logo: '/assets/dapps/compound.png', chains: ['Ethereum'], cat: 'Lending', blurb: 'Lending protocol — earn interest and borrow on Ethereum.' },
  { name: '1inch', url: 'https://app.1inch.io', logo: '/assets/dapps/1inch.png', chains: ['Ethereum', 'Multi-chain'], cat: 'DEX', blurb: 'DEX aggregator that routes swaps across exchanges.' },
  { name: 'SushiSwap', url: 'https://www.sushi.com', logo: '/assets/dapps/sushiswap.png', chains: ['Ethereum', 'Multi-chain'], cat: 'DEX', blurb: 'Community DEX — swaps and liquidity pools on many chains.' },
  { name: 'Curve', url: 'https://curve.fi', logo: '/assets/dapps/curve.png', chains: ['Ethereum', 'Multi-chain'], cat: 'DEX', blurb: 'Exchange specialised in stablecoin and like-asset swaps.' },
  { name: 'Lido', url: 'https://stake.lido.fi', logo: '/assets/dapps/lido.png', chains: ['Ethereum'], cat: 'Liquid staking', blurb: 'Liquid staking — stake ETH and receive stETH.' },
  { name: 'Jupiter', url: 'https://jup.ag', logo: '/assets/dapps/jupiter.png', chains: ['Solana'], cat: 'DEX', blurb: 'Solana swap aggregator — the engine behind this wallet\'s Solana swaps.' },
  { name: 'Raydium', url: 'https://raydium.io', logo: '/assets/dapps/raydium.ico', chains: ['Solana'], cat: 'DEX', blurb: 'Solana DEX and liquidity platform.' },
  { name: 'Orca', url: 'https://www.orca.so', logo: '/assets/dapps/orca.ico', chains: ['Solana'], cat: 'DEX', blurb: 'Solana DEX with concentrated liquidity pools.' },
  { name: 'MakerDAO · Sky', url: 'https://app.sky.money', logo: '/assets/dapps/makerdao.ico', chains: ['Ethereum'], cat: 'Lending', blurb: 'MakerDAO\'s Sky app — DAI/USDS savings and borrowing.' },
  { name: 'Balancer', url: 'https://balancer.fi', logo: '/assets/dapps/balancer.png', chains: ['Ethereum', 'Multi-chain'], cat: 'DEX', blurb: 'DEX with weighted and boosted liquidity pools.' },
  { name: 'Aerodrome', url: 'https://aerodrome.finance', logo: '/assets/dapps/aerodrome.png', chains: ['Base'], cat: 'DEX', blurb: 'The central DEX and liquidity hub on Base.' },
  { name: 'Morpho', url: 'https://app.morpho.org', logo: '/assets/dapps/morpho.png', chains: ['Ethereum', 'Base'], cat: 'Lending', blurb: 'Lending protocol — curated vaults and isolated markets.' },
  { name: 'Kamino', url: 'https://app.kamino.finance', logo: '/assets/dapps/kamino.png', chains: ['Solana'], cat: 'Lending', blurb: 'Solana lending and automated liquidity vaults.' },
  { name: 'Rocket Pool', url: 'https://stake.rocketpool.net', logo: '/assets/dapps/rocketpool.png', chains: ['Ethereum'], cat: 'Liquid staking', blurb: 'Decentralised liquid staking — stake ETH, receive rETH.' },
  { name: 'Marinade', url: 'https://marinade.finance', logo: '/assets/dapps/marinade.png', chains: ['Solana'], cat: 'Liquid staking', blurb: 'Solana liquid staking — stake SOL, receive mSOL.' },
  { name: 'Magic Eden', url: 'https://magiceden.io', logo: '/assets/dapps/magiceden.png', chains: ['Solana', 'Multi-chain'], cat: 'NFT', blurb: 'NFT marketplace across Solana, Bitcoin and EVM chains.' },
  { name: 'Tensor', url: 'https://tensor.trade', logo: '/assets/dapps/tensor.png', chains: ['Solana'], cat: 'NFT', blurb: 'Pro NFT marketplace on Solana.' },
  { name: 'Stargate', url: 'https://stargate.finance', logo: '/assets/dapps/stargate.png', chains: ['Multi-chain'], cat: 'Bridge', blurb: 'Bridge native assets across chains on LayerZero.' },
  { name: 'Across', url: 'https://app.across.to', logo: '/assets/dapps/across.svg', chains: ['Ethereum', 'Multi-chain'], cat: 'Bridge', blurb: 'Fast, low-cost bridging between Ethereum L2s.' },
  { name: 'GMX', url: 'https://app.gmx.io', logo: '/assets/dapps/gmx.png', chains: ['Arbitrum', 'Avalanche'], cat: 'Perps', blurb: 'Perpetuals exchange — trade with leverage from liquidity pools.' },
  { name: 'Hyperliquid', url: 'https://app.hyperliquid.xyz', logo: '/assets/dapps/hyperliquid.png', chains: ['Hyperliquid'], cat: 'Perps', blurb: 'Perpetuals exchange on its own high-speed chain.' },
  { name: 'Drift', url: 'https://app.drift.trade', logo: '/assets/dapps/drift.png', chains: ['Solana'], cat: 'Perps', blurb: 'Solana perpetuals and spot exchange.' },
  { name: 'Yearn', url: 'https://yearn.fi', logo: '/assets/dapps/yearn.png', chains: ['Ethereum', 'Multi-chain'], cat: 'Yield', blurb: 'Yield vaults that auto-compound strategies.' },
  { name: 'Pendle', url: 'https://app.pendle.finance', logo: '/assets/dapps/pendle.png', chains: ['Ethereum', 'Multi-chain'], cat: 'Yield', blurb: 'Yield trading — split assets into principal and yield.' },
];
let discoverQuery = '';
let discoverCat = 'All';
function showDiscover() {
  const featured = ['Uniswap', 'Jupiter', 'Aave', 'Hyperliquid'].map(n => DAPPS.find(d => d.name === n)!).filter(Boolean);
  const cats = ['All', ...Array.from(new Set(DAPPS.map(d => d.cat)))];
  const openDapp = (d: typeof DAPPS[number]) => {
    let host = d.url; try { host = new URL(d.url).host; } catch { /* keep raw */ }
    const close = openSheet(d.name, `
      <span class="coinIc dappSheetIc"><img class="coinImg" src="${esc(d.logo)}" alt=""><span class="coinLetter">${esc(d.name.slice(0, 2).toUpperCase())}</span></span>
      <p class="noteP" style="font-size:14px;color:var(--hi)">${esc(d.blurb)}</p>
      <div class="sumRow"><span class="sl">Category</span><span class="sv">${esc(d.cat)}</span></div>
      <div class="sumRow"><span class="sl">Networks</span><span class="sv">${esc(d.chains.join(' · '))}</span></div>
      <div class="sumRow"><span class="sl">Official domain</span><span class="sv mono">${esc(host)}</span></div>
      <p class="noteP" style="margin-top:10px">Check the domain above matches before you connect or sign anything — fake dApp sites are the most common way wallets get drained.</p>
      <button class="ctaWide" id="dappOpen">Open ${esc(d.name)}</button>`);
    const ob = document.getElementById('dappOpen');
    if (ob) ob.onclick = () => { if (!/^https:\/\//i.test(d.url)) return; close(); window.open(d.url, '_blank'); };
  };
  const dappCard = (d: typeof DAPPS[number]) => `<button class="dappRow" data-dapp="${esc(d.name)}"><span class="coinIc"><img class="coinImg" src="${esc(d.logo)}" alt=""><span class="coinLetter">${esc(d.name.slice(0, 2).toUpperCase())}</span></span><span style="flex:1;min-width:0"><span class="dn">${esc(d.name)}</span><span class="db" style="display:block">${esc(d.blurb)}</span><span class="catChip">${esc(d.cat)}</span> <span class="db" style="display:inline">${esc(d.chains.join(' · '))}</span></span><span class="arrowChip"><i class="ri-arrow-right-up-line"></i></span></button>`;
  setView(`<main><button class="backBtn" id="bk" aria-label="Back"><i class="ri-arrow-left-s-line"></i></button>
  <div class="nftTitle">Discover</div>
  <p class="pageSub">Well-known Web3 apps, official domains only. Tap one to check its domain before opening — in-app signing arrives through WalletConnect.</p>
  <div class="searchField"><i class="ri-search-line"></i><input id="dappQ" type="text" placeholder="Search dApps or categories" value="${esc(discoverQuery)}" autocomplete="off"><button class="clr" id="dappClr" aria-label="Clear search"><i class="ri-close-line"></i></button></div>
  <div class="chipRail" id="dappCats">${cats.map(c => `<button class="chipPick ${discoverCat === c ? 'on' : ''}" data-cat="${esc(c)}" type="button">${esc(c)}</button>`).join('')}</div>
  <div id="dappFeat"><div class="nftGroupH" style="padding-top:10px">Featured</div><div class="featRow">${featured.map(d => `<button class="featCard" data-dapp="${esc(d.name)}"><span class="coinIc"><img class="coinImg" src="${esc(d.logo)}" alt=""><span class="coinLetter">${esc(d.name.slice(0, 2).toUpperCase())}</span></span><span class="fn">${esc(d.name)}</span><span class="catChip">${esc(d.cat)}</span></button>`).join('')}</div></div>
  <div class="nftGroupH">All dApps</div>
  <div id="dappList" style="margin-top:10px"></div></main>`);
  ($('#bk') as HTMLElement).onclick = () => goBack({ route: 'wallet' });
  const bindDapps = (scope: ParentNode) => scope.querySelectorAll('[data-dapp]').forEach(b => (b as HTMLElement).onclick = () => { const d = DAPPS.find(x => x.name === (b as HTMLElement).dataset.dapp); if (d) openDapp(d); });
  const paintList = () => {
    const q = discoverQuery.trim().toLowerCase();
    const rows = DAPPS.filter(d => (discoverCat === 'All' || d.cat === discoverCat) && (!q || d.name.toLowerCase().includes(q) || d.cat.toLowerCase().includes(q) || d.chains.some(x => x.toLowerCase().includes(q))));
    const list = $('#dappList'); if (!list) return;
    list.innerHTML = rows.length ? rows.map(dappCard).join('') : `<p class="small muted" style="padding:6px 16px">No dApps match '${esc(discoverQuery || discoverCat)}'</p>`;
    bindDapps(list);
    const feat = $('#dappFeat'); if (feat) feat.style.display = q || discoverCat !== 'All' ? 'none' : '';
    const clr = $('#dappClr'); if (clr) clr.classList.toggle('on', discoverQuery.length > 0);
  };
  paintList();
  bindDapps(document.getElementById('dappFeat')!);
  document.querySelectorAll('#dappCats [data-cat]').forEach(b => (b as HTMLElement).onclick = () => { discoverCat = (b as HTMLElement).dataset.cat!; document.querySelectorAll('#dappCats [data-cat]').forEach(x => x.classList.toggle('on', x === b)); railReveal(b as HTMLElement, true); paintList(); });
  const inp = $('#dappQ') as HTMLInputElement;
  inp.addEventListener('input', () => { discoverQuery = inp.value; paintList(); });
  ($('#dappClr') as HTMLElement).onclick = () => { discoverQuery = ''; inp.value = ''; paintList(); inp.focus(); };
}

// ---------- Wave 2: WalletConnect (honestly gated on a Reown project ID) ----------
// Full v2 flow — pairing by wc: URI, session proposal review, and session
// requests reviewed with the same clear-signing as the Sign tool — but it
// only exists when the operator configured WALLETCONNECT_PROJECT_ID on
// the server (a free Reown project ID; /api/config serves it). Without
// one, this screen explains exactly that and pairs nothing.
let wcProposal: any = null;
let wcRequest: any = null;
// Audit fix: proposals/requests used to be single slots — a second
// dApp event while one was open silently overwrote it, and the
// displaced dApp hung forever with no way to approve or reject it.
// Events now queue FIFO behind the one on screen; finishing the
// current one promotes the next.
const wcProposalQueue: any[] = [];
const wcRequestQueue: any[] = [];
function wcAdvanceProposal(): void { wcProposal = wcProposalQueue.shift() ?? null; }
function wcAdvanceRequest(): void { wcRequest = wcRequestQueue.shift() ?? null; }
let wcInitState: 'idle' | 'starting' | 'ready' | 'error' = 'idle';
// Audit fix: the pairing input's draft survives Connect rerenders
// (session events repaint the screen and used to wipe a half-pasted
// wc: URI).
let wcUriDraft = '';
let wcInitErr = '';

function wcAccounts(): WcAccounts {
  const sol = CHAINS.find(x => x.id === 'solana');
  return {
    evmAddress: evmAddressOf(),
    solAddress: sol ? addressFor(sol) : '',
    evmChainIds: visibleChains().filter(c => c.kind === 'evm' && c.evmId).map(c => c.evmId!),
  };
}

// WalletConnect start is never allowed to sit on "Starting…" forever:
// the SDK chunk download or SignClient.init can stall indefinitely on
// a bad connection (user report 2026-11-20: the Connect screen froze
// on "Starting WalletConnect…" with Pair disabled and no way out).
// ensureWc therefore races init against a UI timeout. The init itself
// keeps running in the background — if it lands late, the handlers
// below flip the screen to ready on their own; if it rejects, the
// error state offers Retry, and Reset (wipe the SDK's own storage,
// the other known wedge) after a timeout.
let wcAttempt = 0;
const WC_START_TIMEOUT_MS = 25000;
async function ensureWc(): Promise<boolean> {
  if (wcClientReady()) { wcInitState = 'ready'; return true; }
  await loadFeatureCfg();
  if (!featureCfg.walletConnectProjectId) return false;
  if (wcInitState === 'starting') return false;
  wcInitState = 'starting'; wcInitErr = '';
  const attempt = ++wcAttempt;
  const p = wcInit(featureCfg.walletConnectProjectId, {
    onProposal: (p: any) => { if (wcProposal) { wcProposalQueue.push(p); return; } wcProposal = p; if (currentRoute === 'connect') showConnect(); },
    onRequest: (e: any) => { if (wcRequest) { wcRequestQueue.push(e); return; } wcRequest = e; if (currentRoute === 'connect') showConnect(); else go({ route: 'connect' }); },
    onSessionDelete: () => { if (currentRoute === 'connect') showConnect(); },
  });
  p.then(
    () => { if (wcAttempt === attempt && wcInitState !== 'ready') { wcInitState = 'ready'; wcInitErr = ''; if (currentRoute === 'connect') showConnect(); } },
    (e: any) => { if (wcAttempt === attempt) { wcInitState = 'error'; wcInitErr = e?.message || String(e); if (currentRoute === 'connect') showConnect(); } },
  );
  const outcome = await Promise.race([
    p.then(() => 'ok' as const, () => 'err' as const),
    new Promise<'timeout'>(res => setTimeout(() => res('timeout'), WC_START_TIMEOUT_MS)),
  ]);
  if (outcome === 'timeout' && wcAttempt === attempt && wcInitState === 'starting') {
    wcInitState = 'error';
    wcInitErr = 'WalletConnect did not start within 25 seconds — the connection may be slow, or its relay is unreachable. It is still trying in the background; if it does not come up, tap Retry.';
    if (currentRoute === 'connect') showConnect();
  }
  return outcome === 'ok';
}

function wcPeerName(meta: any): string { return meta?.name || 'Unknown dApp'; }

// Audit NEW LOW 4: dApp-supplied fields are untyped — a peer can send
// an object where a string is expected, and String()/esc() on it used
// to crash the review itself (a fail-closed DoS of exactly the screen
// meant to protect the user). wcStr renders anything safely.
function wcStr(v: any): string {
  if (v == null) return '—';
  if (typeof v === 'string') return v;
  if (typeof v === 'number' || typeof v === 'bigint' || typeof v === 'boolean') return String(v);
  try { return JSON.stringify(v) ?? '—'; } catch { return '[unreadable value]'; }
}

function wcRequestReview(req: any): { kind: string; title: string; body: string } {
  const method: string = req?.params?.request?.method ?? '';
  const params = req?.params?.request?.params;
  const chainId: string = req?.params?.chainId ?? '';
  const kind = classifyRequest(method);
  if (kind === 'evm-send' || kind === 'evm-sign-tx') {
    const tx = parseWcEvmTx(params);
    if (!tx) return { kind, title: method, body: '<div class="err">This transaction request could not be parsed. Reject it.</div>' };
    const evmId = Number((chainId.split(':')[1] ?? '1'));
    const c = CHAINS.find(x => x.evmId === evmId);
    const eth = tx.value && tx.value !== '0x0' && tx.value !== '0' ? trimNum(Number(ethers.formatEther(BigInt(tx.value))), 8) : '0';
    // Decode the standard ERC-20/721 calls so the review names what the
    // call actually does — an unlimited approve must never hide inside
    // raw calldata behind a generic "contract call" warning.
    const dec = tx.data && tx.data !== '0x' ? decodeErc20Call(tx.data) : null;
    const tok = c ? findTokenByContract(c.id, tx.to) : undefined;
    const sym = tok ? tok.symbol : 'tokens';
    const chip = (a: string) => `<span class="monoChip" style="max-width:210px" data-full="${esc(a)}">${esc(a.slice(0, 10))}…${esc(a.slice(-8))}</span>`;
    const amtTxt = dec?.amount != null ? (tok ? `${formatTokenAmount(dec.amount, tok.decimals)} ${esc(tok.symbol)}` : `${dec.amount.toString()} base units (token unknown to this wallet — decimals not verified)`) : '';
    let callHtml = '';
    if (dec?.kind === 'approve') {
      const unlimited = (dec.amount ?? 0n) >= (1n << 128n);
      callHtml = `<div class="sumRow"><span class="sl">Call</span><span class="sv">Approve ${esc(sym)}</span></div>
      <div class="sumRow"><span class="sl">Spender</span><span class="sv">${chip(dec.spender!)}</span></div>
      <div class="sumRow"><span class="sl">Amount</span><span class="sv">${unlimited ? 'Unlimited' : amtTxt}</span></div>
      ${unlimited
        ? `<div class="err" style="margin-top:10px">UNLIMITED APPROVAL — this spender could move ALL of your ${esc(sym)} at any time, until you revoke it. Only approve if you fully trust this dApp; a limited approval is far safer.</div>`
        : `<div class="warn" style="margin-top:10px">This approval lets the spender move up to the amount above of your ${esc(sym)}. Only approve if you trust the dApp and expected this.</div>`}`;
    } else if (dec?.kind === 'transfer') {
      callHtml = `<div class="sumRow"><span class="sl">Call</span><span class="sv">Transfer ${esc(sym)}</span></div>
      <div class="sumRow"><span class="sl">Recipient</span><span class="sv">${chip(dec.to!)}</span></div>
      <div class="sumRow"><span class="sl">Amount</span><span class="sv">${amtTxt}</span></div>
      <div class="warn" style="margin-top:10px">This sends ${esc(sym)} out of your wallet to the recipient above. Verify both before approving.</div>`;
    } else if (dec?.kind === 'transferFrom') {
      callHtml = `<div class="sumRow"><span class="sl">Call</span><span class="sv">Transfer ${esc(sym)} (via allowance)</span></div>
      <div class="sumRow"><span class="sl">From</span><span class="sv">${chip(dec.from!)}</span></div>
      <div class="sumRow"><span class="sl">To</span><span class="sv">${chip(dec.to!)}</span></div>
      <div class="sumRow"><span class="sl">Amount</span><span class="sv">${amtTxt}</span></div>
      <div class="warn" style="margin-top:10px">This moves ${esc(sym)} using an existing allowance. Verify the sender, recipient and amount before approving.</div>`;
    } else if (dec?.kind === 'setApprovalForAll') {
      callHtml = `<div class="sumRow"><span class="sl">Call</span><span class="sv">${dec.approved ? 'Approve operator for ALL assets in a collection' : 'Revoke operator for a collection'}</span></div>
      <div class="sumRow"><span class="sl">Operator</span><span class="sv">${chip(dec.operator!)}</span></div>
      ${dec.approved
        ? `<div class="err" style="margin-top:10px">This gives the operator control over EVERY asset you hold in this contract's collection — a classic drainer request. Reject unless you know exactly why a marketplace needs it.</div>`
        : `<div class="warn" style="margin-top:10px">This revokes an operator's control over this collection. That is the safe direction, but verify the operator address.</div>`}`;
    } else if (tx.data && tx.data !== '0x') {
      callHtml = '<div class="warn" style="margin-top:10px">This is a contract call. The wallet cannot decode what this call does — only approve if you trust the dApp and expected this exact action.</div>';
    }
    return { kind, title: kind === 'evm-send' ? 'Send transaction' : 'Sign transaction', body: `
      <div class="sumRow"><span class="sl">Network</span><span class="sv">${esc(c?.name ?? ('Chain ' + evmId))}</span></div>
      <div class="sumRow"><span class="sl">To</span><span class="sv"><span class="monoChip" style="max-width:210px" data-full="${esc(tx.to)}">${esc(tx.to.slice(0, 10))}…${esc(tx.to.slice(-8))}</span></span></div>
      <div class="sumRow"><span class="sl">Value</span><span class="sv">${eth} ${esc(c?.symbol ?? 'ETH')}</span></div>
      <div class="sumRow"><span class="sl">Call data</span><span class="sv"><span class="monoChip" style="max-width:210px" data-full="${esc(tx.data)}" data-trunc="${esc(tx.data.length > 42 ? tx.data.slice(0, 42) + '…' : tx.data)}">${esc(tx.data.length > 42 ? tx.data.slice(0, 42) + '…' : tx.data)}</span></span></div>
      ${callHtml}` };
  }
  if (kind === 'sign-message') {
    const d = decodeWcSignMessage(method, params);
    return { kind, title: 'Sign message', body: `<div class="sumRow"><span class="sl">Method</span><span class="sv mono">${esc(method)}</span></div><div class="sumRow"><span class="sl">Account</span><span class="sv"><span class="monoChip" style="max-width:210px" data-full="${esc(d.address)}">${esc(d.address.slice(0, 10))}…${esc(d.address.slice(-8))}</span></span></div><p class="small" style="line-height:1.6;white-space:pre-wrap;word-break:break-word;margin-top:10px">${esc(d.text)}</p>${looksLikeBlindBlob(d.text) ? '<div class="warn" style="margin-top:10px">This message looks like an opaque blob, not readable text. Signing blobs you cannot read is how wallets get drained — reject unless you know exactly what it is.</div>' : ''}` };
  }
  if (kind === 'sign-typed') {
    let parsed: any = null;
    try { parsed = JSON.parse(Array.isArray(params) ? params[1] : params); } catch { /* below */ }
    if (!parsed) return { kind, title: method, body: '<div class="err">This typed-data request could not be parsed. Reject it.</div>' };
    // Audit H-5 + NEW LOW 4: the review now shows the COMPLETE typed
    // data being signed — domain (incl. chainId), the type table and
    // the full message, never a 2000-char truncation of an object
    // whose tail is signed sight-unseen. Peer fields go through
    // wcStr so a malformed (object-typed) field can't crash the review.
    const typeNames = parsed.types && typeof parsed.types === 'object' ? Object.keys(parsed.types).join(', ') : '—';
    return { kind, title: 'Sign typed data', body: `<div class="sumRow"><span class="sl">Domain</span><span class="sv">${esc(wcStr(parsed.domain?.name))}</span></div><div class="sumRow"><span class="sl">Domain chain</span><span class="sv">${esc(wcStr(parsed.domain?.chainId))}</span></div><div class="sumRow"><span class="sl">Verifying contract</span><span class="sv"><span class="monoChip" style="max-width:210px">${esc(wcStr(parsed.domain?.verifyingContract).slice(0, 10))}…</span></span></div><div class="sumRow"><span class="sl">Primary type</span><span class="sv mono">${esc(wcStr(parsed.primaryType))}</span></div><div class="sumRow"><span class="sl">Types</span><span class="sv mono" style="font-size:11px">${esc(typeNames)}</span></div><pre class="mono" style="white-space:pre-wrap;word-break:break-word;font-size:11px;line-height:1.5;margin-top:10px;max-height:260px;overflow:auto">${esc(JSON.stringify({ domain: parsed.domain ?? {}, message: parsed.message ?? {} }, null, 1))}</pre>` };
  }
  if (kind === 'sol-sign-tx' || kind === 'sol-sign-send' || kind === 'sol-sign-all') {
    const p0 = Array.isArray(params) ? params[0] : params;
    const list: string[] = kind === 'sol-sign-all' ? (p0?.transactions ?? []) : [p0?.transaction ?? ''];
    let count = 0; let okParse = true;
    for (const b64 of list) { try { const tx = deserializeSolTx(b64Bytes(b64)); count += tx instanceof VersionedTransaction ? tx.message.compiledInstructions.length : tx.instructions.length; } catch { okParse = false; } }
    if (!okParse) return { kind: 'unsupported', title: 'Sign transaction (Solana)', body: '<div class="err">At least one transaction in this request could not be parsed at all. Undecodable transactions are never signed — reject this request.</div>' };
    return { kind, title: kind === 'sol-sign-send' ? 'Sign & send transaction (Solana)' : 'Sign transaction (Solana)', body: `<div class="sumRow"><span class="sl">Transactions</span><span class="sv">${list.length}</span></div><div class="sumRow"><span class="sl">Instructions</span><span class="sv">${count}</span></div><div class="warn" style="margin-top:10px">Solana transactions from dApps can't be fully decoded here yet — you can see the shape, not every effect. Only approve transactions you initiated and expected.</div>` };
  }
  if (kind === 'sol-sign-message') {
    const p0 = Array.isArray(params) ? params[0] : params;
    let text = '';
    try { text = new TextDecoder().decode(bs58.decode(String(p0?.message ?? ''))); } catch { text = ''; }
    return { kind, title: 'Sign message (Solana)', body: `<p class="small" style="line-height:1.6;white-space:pre-wrap;word-break:break-word">${esc(text || '(undecodable message)')}</p>${looksLikeBlindBlob(text) ? '<div class="warn" style="margin-top:10px">This message looks like an opaque blob, not readable text — reject unless you know exactly what it is.</div>' : ''}` };
  }
  return { kind, title: method, body: '<div class="err">This wallet does not support this request method. Reject it.</div>' };
}

async function executeWcRequest(req: any): Promise<any> {
  const method: string = req?.params?.request?.method ?? '';
  const params = req?.params?.request?.params;
  const chainId: string = req?.params?.chainId ?? '';
  const kind = classifyRequest(method);
  if (kind === 'evm-send' || kind === 'evm-sign-tx') {
    const tx = parseWcEvmTx(params); if (!tx) throw new Error('Unparsable transaction.');
    const pk = evmPrivKey(); if (!pk) throw new Error('No EVM account available.');
    const evmId = Number((chainId.split(':')[1] ?? '1'));
    const c = CHAINS.find(x => x.evmId === evmId); if (!c) throw new Error('Unsupported chain ' + chainId);
    const provider = new ethers.JsonRpcProvider(evmProviderUrl(c), c.evmId);
    const wallet = new ethers.Wallet(pk, provider);
    // Audit H-5: a dApp must not be able to aim a request at an
    // account other than the one this session is connected with.
    if (tx.from && tx.from.toLowerCase() !== wallet.address.toLowerCase()) throw new Error('This request names a different sending account than the connected one — refused.');
    const reqTx: ethers.TransactionRequest = { to: tx.to, data: tx.data || '0x', value: BigInt(tx.value || '0') };
    if (tx.gas) { try { reqTx.gasLimit = BigInt(tx.gas); } catch { /* provider fills */ } }
    if (kind === 'evm-send') { const sent = await wallet.sendTransaction(reqTx); return sent.hash; }
    return await wallet.signTransaction(reqTx);
  }
  if (kind === 'sign-message') {
    const pk = evmPrivKey(); if (!pk) throw new Error('No EVM account available.');
    const wallet = new ethers.Wallet(pk);
    const d = decodeWcSignMessage(method, params);
    // Audit fix (same rule as the tx path, H-5): refuse to sign for an
    // account other than the connected/active one.
    if (d.address && d.address.toLowerCase() !== wallet.address.toLowerCase()) throw new Error('This request names a different account than the connected one — refused.');
    const bytes = d.raw.startsWith('0x') ? ethers.getBytes(d.raw) : new TextEncoder().encode(d.raw);
    return await wallet.signMessage(bytes);
  }
  if (kind === 'sign-typed') {
    const pk = evmPrivKey(); if (!pk) throw new Error('No EVM account available.');
    const wallet = new ethers.Wallet(pk);
    const namedAcct = Array.isArray(params) ? params[0] : '';
    if (typeof namedAcct === 'string' && /^0x[0-9a-fA-F]{40}$/.test(namedAcct) && namedAcct.toLowerCase() !== wallet.address.toLowerCase()) throw new Error('This request names a different account than the connected one — refused.');
    const parsed = JSON.parse(Array.isArray(params) ? params[1] : params);
    const types = { ...(parsed.types ?? {}) }; delete types.EIP712Domain;
    return await wallet.signTypedData(parsed.domain, types, parsed.message);
  }
  if (kind.startsWith('sol-')) {
    const kp = solanaKeypairFor('solana'); if (!kp) throw new Error('No Solana account available.');
    const p0 = Array.isArray(params) ? params[0] : params;
    if (kind === 'sol-sign-message') {
      const bytes = bs58.decode(String(p0?.message ?? ''));
      return { signature: bs58.encode(ed25519.sign(bytes, kp.secretKey.slice(0, 32))) };
    }
    const conn = new Connection(solanaRpcUrl(), 'confirmed');
    if (kind === 'sol-sign-all') {
      const out: string[] = [];
      for (const b64 of (p0?.transactions ?? [])) { const tx = deserializeSolTx(b64Bytes(b64)); if (tx instanceof VersionedTransaction) { tx.sign([kp]); out.push(bs58.encode(tx.serialize())); } else { tx.sign(kp); out.push(bs58.encode(tx.serialize())); } }
      return { transactions: out };
    }
    const tx = deserializeSolTx(b64Bytes(String(p0?.transaction ?? '')));
    if (tx instanceof VersionedTransaction) tx.sign([kp]); else tx.sign(kp);
    if (kind === 'sol-sign-send') { const sig = await conn.sendRawTransaction(tx.serialize(), { skipPreflight: false }); return { signature: sig }; }
    return { signature: bs58.encode(tx.serialize()) };
  }
  throw new Error('Unsupported method ' + method);
}

// ================= Invest (Addition 6) =================
// A market browser, not a second wallet: every figure is live from a
// named source (our market service for in-wallet assets, Hyperliquid's
// public API for perps/stocks/commodities/pre-IPO, GeckoTerminal for
// per-chain trending pools, DexScreener for bStocks' DEX prices).
// Buying always routes to a real path inside this app: the existing
// Swap for spot, native in-wallet Hyperliquid trading for perps
// (agent-wallet signing, see the trading section below). Data loads
// only when the tab is first opened — Home never pays for it.
interface HlAsset { name: string; idx: number; szDecimals: number; markPx: number; prevDayPx: number; change24h: number | null; dayNtlVlm: number; openInterest: number; funding: number; oraclePx: number; maxLeverage: number; }
interface HlDex { id: string; name: string; ord: number; ok?: boolean; assets: HlAsset[]; }
interface GtPool { name: string; symbol: string; address: string; pool: string; img?: string; priceUsd: number | null; change24h: number | null; volume24h: number | null; liquidityUsd: number | null; fdvUsd: number | null; }
interface BsStock { symbol: string; name: string; address: string; priceUsd: number | null; change24h: number | null; volume24h: number | null; liquidityUsd: number | null; fdvUsd: number | null; dexUrl: string | null; }
interface HlPosition { coin: string; dex: string; szi: number; entryPx: number; markPx: number; positionValue: number; unrealizedPnl: number; leverage: number | null; }
let investSection: 'crypto' | 'hl' | 'bstocks' | 'poly' = 'crypto';
let investNet = 'all';
let investCat: 'crypto' | 'stocks' | 'commodities' | 'preipo' | 'all' = 'crypto';
let investQuery = '';
let investPaintGen = 0; // bumped per paintInvestBody — stale painters bail
let hlData: { dexes: HlDex[] } | null = null;
let hlDataAt = 0;
let gtData = new Map<string, GtPool[]>();
let bsData: BsStock[] | null = null;
let hlAcct: { any: boolean; accountValue: number; unrealizedPnl: number; spotUsdc: number; positions: HlPosition[] } | null = null;
let hlAcctAt = 0;
// Audit fix: the account cache is keyed by wallet address — a cache
// entry from a previously active wallet must never render for another
// wallet, and a failed fetch must never render as a real $0.00 account.
let hlAcctAddr = '';
let hlAcctFailed = false;
let investHlSel: { dex: string; name: string } | null = null;
let investTokSel: { gtChain: string; pool: GtPool; bstock?: BsStock } | null = null;
const INVEST_NETS = [{ id: 'all', name: 'All' }, { id: 'solana', name: 'Solana' }, { id: 'ethereum', name: 'Ethereum' }, { id: 'bnb', name: 'BNB Chain' }, { id: 'base', name: 'Base' }, { id: 'hyperevm', name: 'HyperEVM' }];
const GT_TO_OUR_CHAIN: Record<string, string> = { solana: 'solana', ethereum: 'ethereum', bnb: 'bnb', base: 'base', hyperevm: 'evm-999' };
const HL_COMMODITIES = new Set(['GOLD', 'SILVER', 'COPPER', 'ALUMINIUM', 'PALLADIUM', 'PLATINUM', 'BRENTOIL', 'CL', 'OIL', 'WTI', 'USOIL', 'NATGAS', 'GAS', 'CORN', 'WHEAT', 'GOLDJM', 'SILVERJM']);
// Pre-IPO = markets on companies with no public listing yet (OpenAI,
// Anthropic, Unitree…), wherever they trade — io, para, or vntl if
// its markets are ever revived (all vntl markets were delisted at
// the 2026-11-20 audit; the category then honestly rests on io).
const HL_PREIPO = new Set(['OAI', 'ANTH', 'UNITREE', 'SPACEX', 'STRIPE']); // NOT 'XAI': the live main-dex XAI is the Xai Games token, not xAI — the company name loses to the real crypto asset
// Crypto index products on builder dexes (total-market / dominance
// / volatility indices) — crypto by subject, not equities.
const HL_CRYPTO_INDEX = new Set(['TOTAL2', 'OTHERS', 'BTCD', 'BVIV']);
// Category model (verified against the live perpDexs universes,
// 2026-11-20): per-dex defaults from each venue's premise, with the
// named asset overrides above applied first. xyz = equities venue
// (its indices/FX ride along in Stocks), para/io = equities venues
// with pre-IPO exceptions, km/mkts/hyna = crypto venues, main = crypto.
const HL_DEX_DEFAULT: Record<string, 'crypto' | 'stocks' | 'preipo'> = { '': 'crypto', hyna: 'crypto', km: 'crypto', mkts: 'crypto', abcd: 'crypto', xyz: 'stocks', flx: 'stocks', para: 'stocks', io: 'stocks', vntl: 'preipo', cash: 'stocks' };
function hlBaseName(full: string): string { return full.includes(':') ? full.split(':')[1] : full; }
function hlCategory(dexId: string, fullName: string, cryptoSyms: Set<string>): 'crypto' | 'stocks' | 'commodities' | 'preipo' {
  const base = hlBaseName(fullName);
  if (HL_COMMODITIES.has(base)) return 'commodities';
  if (HL_PREIPO.has(base)) return 'preipo';
  if (HL_CRYPTO_INDEX.has(base)) return 'crypto';
  if (cryptoSyms.has(base)) return 'crypto';
  return HL_DEX_DEFAULT[dexId] || 'stocks';
}
// In-flight dedup on the section loaders: the background warm and a
// section opened mid-warm share ONE fetch instead of racing two.
let hlInflight: Promise<{ dexes: HlDex[] } | null> | null = null;
async function loadHlMarkets(): Promise<{ dexes: HlDex[] } | null> {
  if (hlData && Date.now() - hlDataAt < 20000) return hlData;
  if (hlInflight) return hlInflight;
  hlInflight = (async () => {
    try { const r = await fetch('/api/hl/markets'); if (!r.ok) return hlData; const j = await r.json();
      // A fully-degraded snapshot (every dex failed upstream) never
      // replaces good data the user is already looking at — the
      // next refresh tick retries instead.
      const total = (d: { dexes: HlDex[] } | null): number => (d?.dexes || []).reduce((s, x) => s + x.assets.length, 0);
      if (hlData && total(j) === 0 && total(hlData) > 0) return hlData;
      hlData = j; hlDataAt = Date.now(); return hlData; } catch { return hlData; } finally { hlInflight = null; }
  })();
  return hlInflight;
}
const gtInflight = new Map<string, Promise<GtPool[]>>();
async function loadGt(chain: string): Promise<GtPool[]> {
  const hit = gtData.get(chain); if (hit) return hit;
  const flying = gtInflight.get(chain); if (flying) return flying;
  const p = (async () => {
    try { const r = await fetch('/api/gt/trending/' + chain); if (!r.ok) return []; const j = await r.json(); const pools: GtPool[] = j.pools || []; gtData.set(chain, pools); return pools; } catch { return []; } finally { gtInflight.delete(chain); }
  })();
  gtInflight.set(chain, p);
  return p;
}
// Token symbol -> underlying ticker: strip the bStocks "B" suffix,
// with the one mechanical exception — FWDIB is Forward Industries,
// listed as FORD (stripping would invent a nonexistent "FWDI").
const BS_UNDERLYING_EXC: Record<string, string> = { FWDIB: 'FORD' };
function bsUnderlying(sym: string): string { return BS_UNDERLYING_EXC[sym] || sym.replace(/B$/, ''); }
let bsInflight: Promise<BsStock[]> | null = null;
async function loadBstocks(): Promise<BsStock[]> {
  if (bsData) return bsData;
  if (bsInflight) return bsInflight;
  bsInflight = (async () => {
    try { const r = await fetch('/api/bstocks'); if (!r.ok) return []; const j = await r.json(); const stocks: BsStock[] = j.stocks || []; bsData = stocks; return stocks; } catch { return []; } finally { bsInflight = null; }
  })();
  return bsInflight;
}
function chgPill(ch: number | null): string { return ch == null ? '' : `<span class="chgPill ${ch >= 0 ? 'pos' : 'neg'}">${ch >= 0 ? '+' : ''}${ch.toFixed(2)}%</span>`; }
// ---------- Invest → Predictions promo card ----------
// Announcement card at the top of the Invest tab, directly below the
// "Invest" title, for the Predictions launch — the design the user
// approved as a standalone (~/workspace/syn-promo): NEW chip + "in
// Invest", Polymarket-blue "Predictions" with a shimmer, logo lockup
// on the CTA row, mark watermark, and NO close button (his order —
// the card is not dismissible; the dismissal key was bumped to v2 at
// his order so a dismissal of the OLD card no longer hides this one). Idle
// animation is gated by wavesFxOn (.fxOn), like the Explore fx. The
// live line is one real trending market from the same Gamma feed the
// Prediction section uses; its slot has a fixed height whether or
// not the feed answers, so the card's geometry never changes when
// the line fills in.
const PROMO_POLY_KEY = 'syn-wallet-promo-predictions-v2';
let promoPolyCache: { q: string; pct: number; at: number } | null = null;
// The card renders SETTLED, always — no entrance animation. The
// staggered rise read to the user as the card "loading when the tab
// is clicked" (frame proof: content sat at opacity 0 for ~0.9s on
// first open even with its data already cached). Its live line
// paints from cache at any age (stale-while-revalidate); a skeleton
// shows only when no market has ever been fetched on this device.
let promoShownKey = '';
function promoPolyDismissed(): boolean { try { return localStorage.getItem(PROMO_POLY_KEY) === '1'; } catch { return false; } }
function promoLiveHTML(c: { q: string; pct: number }): string {
  return `<span class="liveDotSm"></span><span class="promoLiveQ">${esc(c.q)}</span><span class="promoLivePct">Yes ${polyPct(c.pct)}</span>`;
}
async function fillPromoPolyLive() {
  // Fresh cache: just make sure the slot shows it (no fetch, no pop).
  if (promoPolyCache && Date.now() - promoPolyCache.at < 120000) {
    const el = $('#promoPolyLive');
    if (el && currentRoute === 'invest' && promoShownKey !== promoPolyCache.q + '|' + promoPolyCache.pct) {
      el.innerHTML = promoLiveHTML(promoPolyCache);
      promoShownKey = promoPolyCache.q + '|' + promoPolyCache.pct;
    }
    return;
  }
  try {
    // Reuse the browse cache when the user already opened Predictions.
    let evs = polyListMem.get('tag:trending');
    if (!evs || !evs.length) evs = await gammaEvents({ limit: 8 });
    const e = (evs || []).find(x => x.markets[0] && x.markets[0].outcomes.length === 2 && x.markets[0].prices[0] != null);
    if (!e) return;
    const m = e.markets[0];
    promoPolyCache = { q: m.question, pct: m.prices[0] ?? 0, at: Date.now() };
    saveDataCache();
    const el = $('#promoPolyLive'); if (!el || currentRoute !== 'invest') return;
    const key = promoPolyCache.q + '|' + promoPolyCache.pct;
    if (promoShownKey === key) return;
    const wasSkeleton = !!el.querySelector('.promoLiveSkel');
    el.innerHTML = promoLiveHTML(promoPolyCache);
    promoShownKey = key;
    if (wasSkeleton) el.classList.add('pop');
  } catch { /* feed unavailable — the static card stands on its own */ }
}
function paintInvestPromo() {
  const slot = $('#invPromo'); if (!slot) return;
  if (promoPolyDismissed()) { slot.innerHTML = ''; return; }
  const live = promoPolyCache;
  if (live) promoShownKey = live.q + '|' + live.pct;
  slot.innerHTML = `<div class="promoCard${wavesFxOn() ? ' fxOn' : ''} settled" id="promoPolyCard" role="button" tabindex="0" aria-label="Explore Predictions">
    <img class="promoMark" src="/assets/polymarket-mark.png" alt=""><span class="promoGlass"></span>
    <div class="promoTop pRise" style="animation-delay:.06s"><span class="promoNew">NEW</span><span class="promoKick">in Invest</span></div>
    <div class="promoHead pRise" style="animation-delay:.13s"><span class="promoBlue">Predictions</span> are live</div>
    <p class="promoCopy pRise" style="animation-delay:.2s">Trade Polymarket markets — politics, sports, crypto and more — with live streaming prices, right from your wallet.</p>
    <div class="promoLive pRise" id="promoPolyLive" style="animation-delay:.27s">${live ? promoLiveHTML(live) : '<span class="promoLiveSkel"></span>'}</div>
    <div class="promoFoot pRise" style="animation-delay:.34s"><span class="promoCta"><span class="promoSheen"></span>Explore <span class="promoBlue">Predictions</span><i class="ri-arrow-right-line"></i></span><img class="promoLock" src="/assets/polymarket-lockup.png" alt="Polymarket"></div>
  </div>`;
  const card = $('#promoPolyCard') as unknown as HTMLElement | null; if (!card) return;
  card.onclick = () => {
    if (investSection === 'poly') { window.scrollTo({ top: 0, behavior: prefersReducedMotion() ? 'auto' : 'smooth' }); return; }
    investSection = 'poly'; showInvest();
  };
  void fillPromoPolyLive();
}
function showInvest() {
  setView(`<main><div class="ltWrap"><div class="largeTitle">Invest</div></div>
  <div id="invPromo"></div>
  <div class="chipRail" id="invSections">
    <button class="netChip${investSection === 'crypto' ? ' on' : ''}" data-sec="crypto"><i class="ri-coins-line"></i><span>Crypto</span></button>
    <button class="netChip${investSection === 'poly' ? ' on' : ''}" data-sec="poly"><i class="ri-line-chart-line"></i><span>Prediction</span></button>
    <button class="netChip${investSection === 'hl' ? ' on' : ''}" data-sec="hl"><i class="ri-line-chart-line"></i><span>Hyperliquid</span></button>
    <button class="netChip${investSection === 'bstocks' ? ' on' : ''}" data-sec="bstocks"><i class="ri-building-line"></i><span>bStocks</span></button>
  </div>
  <div class="sheetSearch" style="margin:2px 16px 10px"><i class="ri-search-line"></i><input id="invSearch" placeholder="Search markets" autocomplete="off" autocapitalize="none" spellcheck="false" value="${esc(investQuery)}"></div>
  <div id="invBody"></div></main>`);
  V().querySelectorAll('[data-sec]').forEach(b => (b as HTMLElement).onclick = () => { investSection = (b as HTMLElement).dataset.sec as typeof investSection; showInvest(); });
  const si = $('#invSearch') as unknown as HTMLInputElement;
  si.addEventListener('input', () => { investQuery = si.value; paintInvestBody(); });
  paintInvestBody();
  paintInvestPromo();
}
function paintInvestBody() {
  // Audit fix: every keystroke repaints — bump the paint generation
  // so a slower, older painter can never overwrite a newer one.
  investPaintGen++;
  const body = $('#invBody'); if (!body || currentRoute !== 'invest') return;
  if (investSection === 'crypto') void paintInvestCrypto(body);
  else if (investSection === 'hl') void paintInvestHl(body);
  else if (investSection === 'poly') void paintInvestPoly(body);
  else void paintInvestBstocks(body);
  // Each painter sets its sub-rail markup synchronously (before its
  // first await), so the rail exists by now: wire its fades and make
  // sure the selected pill starts fully in view.
  initRails(body);
}
// The one Hyperliquid account fetch (30s cache, keyed by master
// address) — used by the Settings Hyperliquid account screen and
// the market trade zone. (The account card that used to sit on
// Invest was removed at the user's order 2026-11-20; the account
// lives in Settings now.)
async function loadHlAcct(addr: string): Promise<void> {
  // Audit fix: a different active wallet invalidates the cached account.
  if (hlAcctAddr !== addr) { hlAcct = null; hlAcctAt = 0; hlAcctFailed = false; }
  if (!hlAcct || Date.now() - hlAcctAt > 30000) {
    try { const r = await fetch('/api/hl/account/' + addr); if (r.ok) { hlAcct = await r.json(); hlAcctAt = Date.now(); hlAcctAddr = addr; hlAcctFailed = false; } else if (!hlAcct) hlAcctFailed = true; } catch { if (!hlAcct) hlAcctFailed = true; }
  }
}
// ---------- Settings: Your Hyperliquid account (user order 2026-11-20) ----------
// The Hyperliquid account — value, P&L, spot, open
// positions — plus the account's identity: master address, trading
// key address and its approval state, deposit and markets actions.
// Read-only except two explicit actions (Set up trading key, Close
// position); the data comes from the shared loadHlAcct cache.
let hlAcctSetupErr = '';
function showHlAccount() {
  const addr = hlMasterAddr();
  setView(`<main><button class="backBtn" id="bk" aria-label="Back"><i class="ri-arrow-left-s-line"></i></button><div class="largeTitle" style="padding-top:2px">Hyperliquid account</div>
  <div id="setHlAcct" style="padding:0 16px"></div></main>`);
  ($('#bk') as HTMLElement).onclick = () => goBack({ route: 'settings' });
  void paintSettingsHlAccount(addr);
}
async function paintSettingsHlAccount(addr: string) {
  const slot = $('#setHlAcct'); if (!slot) return;
  if (!addr) {
    slot.innerHTML = `<div class="gGroup"><div class="gCard"><div class="sRow stat"><span class="sTx"><span class="sLbl">No EVM account</span><div class="sSub">This wallet was imported from a Solana key, so it has no Hyperliquid account — Hyperliquid accounts are EVM addresses.</div></span></div></div></div>`;
    return;
  }
  if (!hlAcct || hlAcctAddr !== addr) slot.innerHTML = `<div class="gGroup"><div class="gCard" style="min-height:132px"><div style="padding:6px 2px">${waveLoadBlockHTML()}</div></div></div>`;
  await loadHlAcct(addr);
  if (currentRoute !== 'hlaccount') return;
  const host = $('#setHlAcct'); if (!host) return;
  const a = hlAcct;
  const rec = activeWallet()?.hlAgent;
  const agentAddr = rec ? new ethers.Wallet(rec.key).address : '';
  const agentReady = hlAgentApprovedFor(addr);
  let acctCard: string;
  if (!a && hlAcctFailed) {
    acctCard = `<div class="gGroup"><div class="gHead">Balance</div><div class="gCard">
    <div class="sRow stat"><span class="sTx"><span class="sLbl">Account unavailable</span><div class="sSub">Hyperliquid didn't answer — your funds are unaffected. Reopen this screen to retry.</div></span><span class="sVal strong muted">Unavailable</span></div>
    </div></div>`;
  } else if (!a) { return; }
  else {
    const posRows = (a.positions || []).map((p, ix) => `<div class="sRow stat"><span class="sTx"><span class="sLbl">${esc(hlBaseName(p.coin))} ${p.szi > 0 ? 'Long' : 'Short'} ${p.leverage ? p.leverage + '×' : ''}</span><div class="sSub">${esc(Math.abs(p.szi).toString())} @ entry ${fmtPrice(p.entryPx)} · mark ${fmtPrice(p.markPx)}${p.dex ? ' · ' + esc(p.dex) : ''}</div></span><span class="sVal strong ${p.unrealizedPnl >= 0 ? 'pos' : 'neg'}">${p.unrealizedPnl >= 0 ? '+' : '−'}${fmtUsd(Math.abs(p.unrealizedPnl))}</span>${agentReady ? `<button class="hlMiniBtn" data-hlclose="${ix}">Close</button>` : ''}</div>`).join('');
    acctCard = `<div class="gGroup"><div class="gHead">Balance</div><div class="gCard">
    <div class="sRow stat"><span class="sTx"><span class="sLbl">Account value</span><div class="sSub">Across all Hyperliquid dexes</div></span><span class="sVal strong">${fmtUsd(a.accountValue || 0)}</span></div>
    <div class="sRow stat"><span class="sTx"><span class="sLbl">Unrealised P&amp;L</span></span><span class="sVal strong ${(a.unrealizedPnl || 0) >= 0 ? 'pos' : 'neg'}">${(a.unrealizedPnl || 0) >= 0 ? '+' : '−'}${fmtUsd(Math.abs(a.unrealizedPnl || 0))}</span></div>
    ${a.spotUsdc > 0 ? `<div class="sRow stat"><span class="sTx"><span class="sLbl">Spot USDC</span></span><span class="sVal strong">${fmtUsd(a.spotUsdc)}</span></div>` : ''}
    ${posRows}
    </div></div>`;
  }
  const identity = `<div class="gGroup"><div class="gHead">Addresses</div><div class="gCard">
    <div class="sRow stat"><span class="sTx"><span class="sLbl">Master account</span><div class="sSub">Your wallet's EVM address — deposits are credited here</div></span></div>
    <div style="padding:0 14px 12px"><span class="monoChip" data-full="${esc(addr)}">${esc(shortAddr(addr))}</span></div>
    <div class="sRow stat"><span class="sTx"><span class="sLbl">Trading key</span><div class="sSub">${rec ? 'Generated on this device and stored only in your encrypted vault. It can trade but never withdraw.' : 'Not set up yet — it is created on this device the first time you place a trade, or when you set it up here.'}</div></span><span class="sVal strong ${agentReady ? 'pos' : 'muted'}">${rec ? (agentReady ? 'Approved' : 'Not approved') : 'Not set up'}</span></div>
    ${rec ? `<div style="padding:0 14px 12px"><span class="monoChip" data-full="${esc(agentAddr)}">${esc(shortAddr(agentAddr))}</span></div>` : ''}
    ${hlAcctSetupErr ? `<div style="padding:0 14px 12px"><p class="small" style="color:var(--red)">${esc(hlAcctSetupErr)}</p></div>` : ''}
    ${!agentReady ? `<div class="sRow stat"><span class="sTx"><span class="sLbl">Set up trading key</span><div class="sSub">Signs a Hyperliquid approval with your master key. Needs a funded account — Hyperliquid only registers accounts that have deposited.</div></span><button class="hlMiniBtn" id="setHlAgent">Set up</button></div>` : ''}
  </div></div>`;
  host.innerHTML = acctCard + identity + `<div class="gGroup"><div class="gHead">Actions</div><div class="gCard">
    <div class="sRow stat"><span class="sTx"><span class="sLbl">Deposit USDC</span><div class="sSub">From Arbitrum — credited to this address</div></span><button class="hlMiniBtn" id="setHlDeposit">Deposit</button></div>
    <button class="sRow" id="setHlMarkets" type="button"><span class="sTx"><span class="sLbl">Open markets</span><div class="sSub">Trade perpetuals in the Invest tab</div></span><i class="ri-arrow-right-s-line sChev"></i></button>
  </div><div class="gFoot">Live from Hyperliquid's public API for your wallet address. Trading is built into Syn Wallet — orders are signed on this device by your wallet's trading key, which can trade but never withdraw.</div></div>`;
  const dep = $('#setHlDeposit'); if (dep) dep.onclick = () => openHlDeposit();
  const mk = $('#setHlMarkets'); if (mk) mk.onclick = () => goTab('invest');
  const ag = $('#setHlAgent'); if (ag) ag.onclick = async () => {
    const btn = ag as HTMLButtonElement; btn.disabled = true; btn.textContent = 'Setting up…';
    try { await hlEnsureAgentKey(); hlAcctSetupErr = ''; hlAcctAt = 0; }
    catch (e) { hlAcctSetupErr = e instanceof Error ? e.message : 'The trading key could not be set up.'; }
    if (currentRoute === 'hlaccount') void paintSettingsHlAccount(addr);
  };
  host.querySelectorAll('[data-hlclose]').forEach(b => (b as HTMLElement).onclick = () => { const p = (a?.positions || [])[Number((b as HTMLElement).dataset.hlclose)]; if (p) void hlClosePositionFlow(p.coin, p.dex, b as HTMLElement); });
}
async function paintInvestCrypto(body: HTMLElement) {
  const gen = investPaintGen;
  const q = investQuery.trim().toLowerCase();
  const nets = investNet === 'all' ? INVEST_NETS.slice(1) : INVEST_NETS.filter(n => n.id === investNet);
  const chips = `<div class="chipRail">${INVEST_NETS.map(n => `<button class="netChip${investNet === n.id ? ' on' : ''}" data-net="${n.id}"><span>${n.name}</span></button>`).join('')}</div>`;
  // In-wallet assets for the selected networks (real balances + prices).
  const ourIds = new Set(nets.map(n => GT_TO_OUR_CHAIN[n.id]));
  const inWallet: string[] = [];
  for (const c of visibleChains().filter(c => ourIds.has(c.id))) {
    const p = priceOf(c); const b = balances.get(c.id);
    if (q && !(c.name + ' ' + c.symbol).toLowerCase().includes(q)) continue;
    inWallet.push(`<button class="aRow" data-asset="${c.id}">${coinIcon(c)}<span class="aMid"><span class="aName">${esc(c.symbol)} <span class="aSym">${esc(c.name)}</span></span><span class="aSub"><span>${p != null ? fmtPrice(p) : 'Price unavailable'}</span> ${chgPill(changeOf(c))}</span></span><span class="aRight"><span class="amt">${b != null && p != null ? fmtUsd(b * p) : '—'}</span><span class="usd">${b == null ? '' : fmtCrypto(b, c.symbol)}</span></span><i class="ri-arrow-right-s-line aChev"></i></button>`);
  }
  for (const t of visibleTokens().filter(t => ourIds.has(t.chainId))) {
    const tp = tokenUsd(t); const tb = tokenBalances.get(t.id);
    if (q && !(t.name + ' ' + t.symbol).toLowerCase().includes(q)) continue;
    inWallet.push(`<button class="aRow" data-token2="${t.id}">${tokenIcon(t)}<span class="aMid"><span class="aName">${esc(t.symbol)} <span class="aSym">${esc(findChain(t.chainId)?.name || '')}</span></span><span class="aSub"><span>${tp != null ? fmtPrice(tp) : 'Price unavailable'}</span></span></span><span class="aRight"><span class="amt">${tb != null && tp != null ? fmtUsd(tb * tp) : '—'}</span><span class="usd">${tb == null ? '' : fmtCrypto(tb, t.symbol)}</span></span><i class="ri-arrow-right-s-line aChev"></i></button>`);
  }
  body.innerHTML = `${chips}
    ${inWallet.length ? `<div class="secHead" style="padding:4px 16px 6px"><span class="secTitle">In your wallet</span></div><div class="iosList homeList" style="margin:0 16px">${inWallet.join('')}</div>` : ''}
    <div class="secHead" style="padding:14px 16px 6px"><span class="secTitle">Trending ${investNet === 'all' ? 'markets' : 'on ' + (INVEST_NETS.find(n => n.id === investNet)?.name || '')}</span><span class="small muted">GeckoTerminal</span></div>
    <div id="invTrend"><div style="padding:6px 16px">${waveLoadBlockHTML()}</div></div>`;
  body.querySelectorAll('[data-net]').forEach(b => (b as HTMLElement).onclick = () => { investNet = (b as HTMLElement).dataset.net!; showInvest(); });
  body.querySelectorAll('[data-asset]').forEach(b => (b as HTMLElement).onclick = () => go({ route: 'asset', chainId: (b as HTMLElement).dataset.asset! }, b as HTMLElement));
  body.querySelectorAll('[data-token2]').forEach(b => (b as HTMLElement).onclick = () => go({ route: 'token', tokenId: (b as HTMLElement).dataset.token2! }, b as HTMLElement));
  const pools: { net: string; pool: GtPool }[] = [];
  for (const n of nets) for (const p of await loadGt(n.id)) pools.push({ net: n.id, pool: p });
  if (gen !== investPaintGen) return; // a newer keystroke repaint superseded this one
  const slot = $('#invTrend'); if (!slot || currentRoute !== 'invest' || investSection !== 'crypto') return;
  const seen = new Set<string>();
  const rows = pools.filter(({ pool }) => { const k = pool.address.toLowerCase(); if (seen.has(k)) return false; seen.add(k); return !q || (pool.name + ' ' + pool.symbol).toLowerCase().includes(q); })
    .sort((a, b) => (b.pool.volume24h || 0) - (a.pool.volume24h || 0)).slice(0, 40);
  slot.innerHTML = rows.length ? `<div class="iosList homeList" style="margin:0 16px">${rows.map(({ net, pool }) => `<button class="aRow" data-gt="${net}:${esc(pool.pool)}">${iconHTML(pool.img && isSafeMediaUrl(pool.img) ? pool.img : '', pool.symbol, pool.name, { sm: true })}<span class="aMid"><span class="aName">${esc(pool.symbol)} <span class="aSym">${esc(pool.name)}</span></span><span class="aSub"><span>${pool.priceUsd != null ? fmtUsd(pool.priceUsd, pool.priceUsd < 1 ? 6 : 2) : '—'}</span> ${chgPill(pool.change24h)}</span></span><span class="aRight"><span class="amt">${pool.volume24h != null ? fmtMcap(pool.volume24h) : '—'}</span><span class="usd">24h volume</span></span><i class="ri-arrow-right-s-line aChev"></i></button>`).join('')}</div>` : '<p class="small muted secEmpty">No trending markets loaded for this network right now.</p>';
  slot.querySelectorAll('[data-gt]').forEach(b => (b as HTMLElement).onclick = () => { const [net, poolAddr] = ((b as HTMLElement).dataset.gt || '').split(':'); const hit = pools.find(x => x.net === net && x.pool.pool === poolAddr); if (hit) { investTokSel = { gtChain: net, pool: hit.pool }; go({ route: 'investtoken' }, b as HTMLElement); } });
}
let hlListTimer: ReturnType<typeof setInterval> | null = null;
function hlRowList(data: { dexes: HlDex[] }): { dex: HlDex; a: HlAsset; cat: string }[] {
  const main = data.dexes.find(d => d.id === '');
  const cryptoSyms = new Set((main?.assets || []).map(a => a.name));
  const all: { dex: HlDex; a: HlAsset; cat: string }[] = [];
  for (const dex of data.dexes) for (const a of dex.assets) all.push({ dex, a, cat: hlCategory(dex.id, a.name, cryptoSyms) });
  return all;
}
async function paintInvestHl(body: HTMLElement) {
  const gen = investPaintGen;
  const cats = [{ id: 'crypto', name: 'Crypto perps' }, { id: 'stocks', name: 'Stocks' }, { id: 'commodities', name: 'Commodities' }, { id: 'preipo', name: 'Pre-IPO' }, { id: 'all', name: 'All markets' }] as const;
  body.innerHTML = `<div class="chipRail">${cats.map(c => `<button class="netChip${investCat === c.id ? ' on' : ''}" data-cat="${c.id}"><span>${c.name}</span></button>`).join('')}</div><div id="invHlList"><div style="padding:6px 16px">${waveLoadBlockHTML()}</div></div>`;
  body.querySelectorAll('[data-cat]').forEach(b => (b as HTMLElement).onclick = () => { investCat = (b as HTMLElement).dataset.cat as typeof investCat; paintInvestBody(); });
  if (hlListTimer) { clearInterval(hlListTimer); hlListTimer = null; }
  const paintList = (data: { dexes: HlDex[] } | null) => {
    const slot = $('#invHlList'); if (!slot || currentRoute !== 'invest' || investSection !== 'hl') return;
    if (!data) { slot.innerHTML = '<p class="small muted secEmpty">Hyperliquid markets are unavailable right now — pull back in a moment.</p>'; return; }
    const q = investQuery.trim().toLowerCase();
    const all = hlRowList(data);
    // Search is GLOBAL across categories and dexes (the category
    // rail scopes browsing, never searching). Lists are COMPLETE —
    // no volume cap; the count line says exactly how many markets
    // are live, and a dex that failed to load is named, not hidden.
    const rows = all.filter(r => (q ? (r.a.name.toLowerCase().includes(q) || hlBaseName(r.a.name).toLowerCase().includes(q) || r.dex.name.toLowerCase().includes(q)) : (investCat === 'all' || r.cat === investCat))).sort((x, y) => y.a.dayNtlVlm - x.a.dayNtlVlm);
    const failed = data.dexes.filter(d => d.ok === false);
    const foot = `<p class="small muted" style="padding:8px 16px">${q ? `Search results across all categories` : investCat === 'all' ? 'All live markets' : cats.find(c => c.id === investCat)?.name} · ${rows.length} of ${all.length} live markets · Source: Hyperliquid${failed.length ? ` · ${failed.map(d => esc(d.name)).join(', ')} unavailable right now` : ''}</p>`;
    slot.innerHTML = rows.length ? `<div class="iosList homeList" style="margin:0 16px">${rows.map(({ dex, a, cat }) => `<button class="aRow" data-hl="${esc(dex.id)}:${esc(a.name)}">${cat === 'commodities' ? commodityIcon(hlBaseName(a.name), a.name, { sm: true }) : cat === 'stocks' ? stockIcon(hlBaseName(a.name), a.name, { sm: true }) : underlyingIcon(hlBaseName(a.name), a.name, { sm: true })}<span class="aMid"><span class="aName">${esc(hlBaseName(a.name))} <span class="aSym">${dex.id ? esc(dex.name) : 'Hyperliquid'}</span></span><span class="aSub"><span>${fmtPrice(a.markPx)}</span> ${chgPill(a.change24h)}</span></span><span class="aRight"><span class="amt">${fmtMcap(a.dayNtlVlm)}</span><span class="usd">24h volume</span></span><i class="ri-arrow-right-s-line aChev"></i></button>`).join('')}</div>${foot}` : `<p class="small muted secEmpty">${q ? `No live market matches '${esc(investQuery.trim())}'.` : 'No live markets in this category right now.'}</p>${foot}`;
    slot.querySelectorAll('[data-hl]').forEach(b => (b as HTMLElement).onclick = () => { const v = (b as HTMLElement).dataset.hl || ''; const ix = v.indexOf(':'); investHlSel = { dex: v.slice(0, ix), name: v.slice(ix + 1) }; go({ route: 'hlmarket' }, b as HTMLElement); });
  };
  const hlData0 = await loadHlMarkets();
  if (gen !== investPaintGen) return; // superseded — don't paint or arm a second timer
  paintList(hlData0);
  // Live refresh while the section is open: values swap in place on
  // the same cadence as the server cache; no loader, no re-layout
  // beyond the rows themselves. Stops the moment the user leaves.
  hlListTimer = setInterval(async () => {
    if (currentRoute !== 'invest' || investSection !== 'hl' || !document.getElementById('invHlList')) { if (hlListTimer) { clearInterval(hlListTimer); hlListTimer = null; } return; }
    if (document.hidden) return;
    hlDataAt = 0; // bypass the client cache so the tick really refreshes
    const data = await loadHlMarkets();
    if (data) paintList(data);
  }, 25000);
}
async function paintInvestBstocks(body: HTMLElement) {
  body.innerHTML = `<div style="padding:0 16px"><div class="warn" style="font-size:13px;line-height:1.55">bStocks are Binance's tokenized U.S. stocks &amp; ETFs (issued by BTECH Holdings, 1:1 backed) — plain BNB Chain tokens that trade on PancakeSwap around the clock. Prices below are the live DEX prices (DexScreener) and can differ slightly from Binance's. Tokenized securities: not available to U.S. persons; eligibility is yours to check.</div></div><div id="invBsList"><div style="padding:10px 16px">${waveLoadBlockHTML()}</div></div>`;
  const stocks = await loadBstocks();
  const slot = $('#invBsList'); if (!slot || currentRoute !== 'invest' || investSection !== 'bstocks') return;
  const q = investQuery.trim().toLowerCase();
  const rows = stocks.filter(s => !q || (s.name + ' ' + s.symbol).toLowerCase().includes(q));
  slot.innerHTML = rows.length ? `<div class="iosList homeList" style="margin:10px 16px 0">${rows.map(s => `<button class="aRow" data-bs="${s.symbol}">${stockIcon(bsUnderlying(s.symbol), s.name, { sm: true })}<span class="aMid"><span class="aName">${esc(bsUnderlying(s.symbol))} <span class="aSym">${esc(s.name.replace(' (bStocks Tokenized Stock)', '').replace(' (bStocks Tokenized ETF)', ''))} · bStock</span></span><span class="aSub"><span>${s.priceUsd != null ? fmtPrice(s.priceUsd) : 'No DEX pair yet'}</span> ${chgPill(s.change24h)}</span></span><span class="aRight"><span class="amt">${s.volume24h != null ? fmtMcap(s.volume24h) : '—'}</span><span class="usd">24h volume</span></span><i class="ri-arrow-right-s-line aChev"></i></button>`).join('')}</div>` : '<p class="small muted secEmpty">No bStocks markets loaded right now.</p>';
  slot.querySelectorAll('[data-bs]').forEach(b => (b as HTMLElement).onclick = () => { const s = stocks.find(x => x.symbol === (b as HTMLElement).dataset.bs); if (s) { investTokSel = { gtChain: 'bnb', pool: { name: s.name, symbol: s.symbol, address: s.address, pool: '', priceUsd: s.priceUsd, change24h: s.change24h, volume24h: s.volume24h, liquidityUsd: s.liquidityUsd, fdvUsd: s.fdvUsd }, bstock: s }; go({ route: 'investtoken' }, b as HTMLElement); } });
}
// ---------- Invest → Prediction (Polymarket) ----------
// Discovery + live data + trading on Polymarket, built on the
// Builder architecture: orders carry Syn's builder attribution via
// remote signing (our server holds the builder secret; see
// lib/polymarket.ts). The seven uimaxx registry designs are ported
// natively: category-nav → the pill category rail; mini-market-card
// → binary market cards with the semicircle gauge; match-card →
// sports matchup cards; prediction-market-card → multi-outcome
// event cards; live-ticker-chart + depth-book + quick-trade-panel
// → the market detail screen.
const POLY_CATS: { id: string; label: string; icon?: string }[] = [
  { id: 'trending', label: 'Trending', icon: 'ri-fire-line' },
  { id: 'updown', label: 'Up or Down', icon: 'ri-time-line' },
  { id: 'politics', label: 'Politics' },
  { id: 'sports', label: 'Sports' },
  { id: 'crypto', label: 'Crypto' },
  { id: 'business', label: 'Business' },
  { id: 'culture', label: 'Culture' },
  { id: 'tech', label: 'Tech' },
  { id: 'weather', label: 'Weather' },
  { id: 'esports', label: 'Esports' },
];
let polyCat = 'trending';
let polySel: { market: PolyMarket; eventTitle: string; outcomeIx: number; updown?: { asset: string; tfSecs: number } } | null = null;
let polyUpTf = 300; // Up or Down timeframe, seconds (5m default)
let polyUdTimer: ReturnType<typeof setInterval> | null = null;
let polyCreds: ClobCreds | null = null; // memory only, re-derived per session
let polyListUnsubs: (() => void)[] = [];
let polyDetailUnsubs: (() => void)[] = [];
// Last successfully loaded browse lists, per view key (category or
// search), plus the most recent list rendered anywhere in the tab. A
// failed refresh falls back to these with a stale note instead of
// replacing the tab with an unreachable message.
const polyListMem = new Map<string, PolyEvent[]>();
let polyLastRendered: PolyEvent[] | null = null;
function polyListCleanup() { for (const u of polyListUnsubs) { try { u(); } catch { /* already gone */ } } polyListUnsubs = []; if (polyUdTimer) { clearInterval(polyUdTimer); polyUdTimer = null; } }
function polyDetailCleanup() { for (const u of polyDetailUnsubs) { try { u(); } catch { /* already gone */ } } polyDetailUnsubs = []; }
const polyPct = (p: number): string => p <= 0 ? '0%' : p >= 1 ? '100%' : (p * 100).toFixed(p < 0.1 ? 1 : 0) + '%';
const polyPctNum = (p: number): string => polyPct(p).replace(/%$/, '');
const polyCents = (p: number): string => (p * 100).toFixed(p > 0 && p < 0.1 ? 1 : 0) + '¢';
const polyEnd = (iso: string): string => { const t = Date.parse(iso); if (!Number.isFinite(t)) return ''; const d = new Date(t); return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' }) + (d.getFullYear() !== new Date().getFullYear() ? ' ' + d.getFullYear() : ''); };

function polyGaugeSVG(p: number, stroke = 'var(--silver)'): string {
  const arc = 59.69; const filled = Math.max(0, Math.min(1, p)) * arc;
  return `<svg viewBox="0 0 48 26" fill="none" aria-hidden="true" class="polyGauge"><path d="M5 24A19 19 0 0 1 43 24" stroke="var(--fill06)" stroke-width="4" stroke-linecap="round"/><path d="M5 24A19 19 0 0 1 43 24" stroke="${stroke}" stroke-width="4" stroke-linecap="round" stroke-dasharray="${filled.toFixed(1)} ${arc}"/></svg>`;
}
const isUpDown = (m: PolyMarket): boolean => m.outcomes.length === 2 && /^up$/i.test(m.outcomes[0] || '') && /^down$/i.test(m.outcomes[1] || '');
// The mini-market-card's orb button pair, natively: a gradient orb
// slot with a trend glyph on the first side, a flat slot on the
// second, prices inside the labels. Used wherever a binary market's
// outcomes are literally Up/Down.
function polyOrbPills(m: PolyMarket): string {
  return `<div class="polyPills">${m.outcomes.map((o, ix) => `<button class="orbBtn fillAction strokeLit${ix === 1 ? ' dim' : ''}" data-poly-go="${esc(m.conditionId)}:${ix}"><span class="orbSlot${ix === 0 ? ' orbBg' : ''}"><i class="${ix === 0 ? 'ri-arrow-right-up-line' : 'ri-arrow-right-down-line'}"></i></span><span class="orbLbl">${esc(o)} ${polyCents(m.prices[ix] ?? (ix === 0 ? 0 : 1 - (m.prices[0] ?? 0)))}</span></button>`).join('')}</div>`;
}
// ---- Mini market card (Up or Down browse cards) ----
// The standalone mini-market-card component, ported exactly: orb
// badge, underlined title, semicircle gauge, floating tips, orb
// buttons, LIVE footer. The tips are REAL recent trades for the
// market (Data API v2 via /api/poly/trades): the notional of each
// recent trade ≥ $1, coloured by which outcome the money moved
// toward; slots without a real trade stay empty.
const UD_COIN_LOGOS: Record<string, string> = { btc: '/assets/coins/bitcoin.png', eth: '/assets/coins/ethereum.png', sol: '/assets/coins/solana.png', xrp: '/assets/coins/xrp.png' };
const MMC_TIP_DELAYS = [0, -1300, -600, -2500, -1900, -3100];
const MMC_TIP_OP = ['o70', 'o70', 'o80', 'o50', 'o50', 'o80'];
const MMC_TREND_UP = '<svg viewBox="0 0 256 256" fill="currentColor" style="color:#fff"><path d="M232,56v64a8,8,0,0,1-16,0V75.31l-82.34,82.35a8,8,0,0,1-11.31,0L76.69,112,28.34,160.34a8,8,0,0,1-11.31-11.31l54-54a8,8,0,0,1,11.31,0L128,140.69,192.69,76H168a8,8,0,0,1,0-16h56A8,8,0,0,1,232,56Z"/></svg>';
const MMC_TREND_DOWN = '<svg viewBox="0 0 256 256" fill="currentColor" style="color:rgba(245,245,245,.7)"><path d="M232,200a8,8,0,0,1-8,8H168a8,8,0,0,1,0-16h24.69L128,127.31,82.34,172.69a8,8,0,0,1-11.31,0l-54-54A8,8,0,0,1,28.34,107.66L76.69,156l39.65-39.66a8,8,0,0,1,11.31,0L216,204.69V180a8,8,0,0,1,16,0Z"/></svg>';
const MMC_BOOKMARK = '<svg viewBox="0 0 256 256"><path d="M192,40V216l-64-39.48L64,216V40a8,8,0,0,1,8-8h112A8,8,0,0,1,192,40Z" fill="none" stroke="currentColor" stroke-width="16"/></svg>';
function mmcCardHTML(e: PolyEvent, m: PolyMarket, title: string, letter: string): string {
  const p = m.prices[0] ?? 0;
  const p1 = m.prices[1] ?? (1 - p);
  const endMs = Date.parse(m.endDate || e.endDate);
  const asset = parseUpDownSlug(m.slug)?.asset || '';
  const logo = UD_COIN_LOGOS[asset] || '';
  const badge = `${esc(letter || '?')}${logo ? `<img class="coinImg mmcBadgeImg" src="${logo}" alt="">` : ''}`;
  return `<div class="polyCard mmcCard strokeLit" data-polym="${esc(m.conditionId)}" data-mmc-cond="${esc(m.conditionId)}" role="button" tabindex="0">
    <div class="mmcHeader"><span class="mmcBadge">${badge}</span><h3 class="mmcTitle">${esc(title)}</h3><div class="mmcGauge"><svg viewBox="0 0 48 26" fill="none" aria-hidden="true"><path d="M5 24A19 19 0 0 1 43 24" stroke="#1c1c1c" stroke-width="4" stroke-linecap="round"/><path d="M5 24A19 19 0 0 1 43 24" stroke="#34d399" stroke-width="4" stroke-linecap="round" stroke-dasharray="${(p * 59.69).toFixed(2)} 59.69"/></svg><div class="mmcGaugePct" data-poly-price="${esc(m.tokenIds[0] || '')}">${polyPct(p)}</div><div class="mmcGaugeLbl">${esc(m.outcomes[0] || 'Up')}</div></div></div>
    <div class="mmcTipsTop"><span data-tip="0"></span><span data-tip="1"></span></div>
    <div class="mmcBets"><button class="mmcOrb mmcInteractive strokeLit" data-poly-go="${esc(m.conditionId)}:0"><span class="mmcSlot mmcOrbTilt">${MMC_TREND_UP}</span><span class="mmcLbl">${esc(m.outcomes[0] || 'Up')} <span data-poly-cents="${esc(m.tokenIds[0] || '')}">${polyCents(p)}</span></span></button><button class="mmcOrb mmcInteractive mmcMuted strokeLit" data-poly-go="${esc(m.conditionId)}:1"><span class="mmcSlot mmcFlat">${MMC_TREND_DOWN}</span><span class="mmcLbl">${esc(m.outcomes[1] || 'Down')} <span data-poly-cents="${esc(m.tokenIds[1] || '')}">${polyCents(p1)}</span></span></button></div>
    <div class="mmcTipsBottom"><span class="mmcTipGroup"><span data-tip="2"></span><span data-tip="3"></span></span><span class="mmcTipGroup"><span data-tip="4"></span><span data-tip="5"></span></span></div>
    <div class="mmcFoot"><div class="mmcLive"><span class="mmcDot"></span><b>LIVE</b><span>· Polymarket · <span data-ud-end="${endMs}">Ends in ${fmtUdCountdown(endMs - Date.now())}</span></span></div><button class="mmcBookmark mmcInteractive" data-mmc-bookmark aria-label="Bookmark market">${MMC_BOOKMARK}</button></div>
  </div>`;
}
function paintMmcTips(root: HTMLElement) {
  root.querySelectorAll('[data-mmc-cond]').forEach(card => {
    const cond = (card as HTMLElement).dataset.mmcCond || '';
    if (!cond || (card as HTMLElement).dataset.tipsDone) return;
    (card as HTMLElement).dataset.tipsDone = '1';
    void polyTrades(cond, 25).then(trades => {
      if (!document.body.contains(card)) return;
      const tips = trades.map(t => ({ usd: t.size * t.price, up: (t.side === 'BUY') === (t.outcomeIx === 0) })).filter(t => t.usd >= 1).slice(0, 6);
      tips.forEach((t, i) => {
        const s = card.querySelector(`[data-tip="${i}"]`) as HTMLElement | null;
        if (!s) return;
        s.className = `mmcTip miniMarketTip ${t.up ? 'pos' : 'neg'} ${MMC_TIP_OP[i]}`;
        s.style.animationDelay = MMC_TIP_DELAYS[i] + 'ms';
        s.textContent = '+ $' + Math.round(t.usd);
      });
    }).catch(() => { /* tips are ambient — absence is fine */ });
  });
}
// ---- Prediction bookmarks ----
// Device-local like everything else in the wallet: a set of market
// condition ids in localStorage. Every bookmark button on every card
// (browse, Up or Down, search, appended pages) and on the market
// detail reads and writes this one store, so a market shows the same
// state everywhere and it survives reloads.
const POLY_BM_KEY = 'syn-wallet-poly-bookmarks';
let polyBmSet: Set<string> | null = null;
function polyBookmarks(): Set<string> {
  if (!polyBmSet) {
    try { polyBmSet = new Set(JSON.parse(localStorage.getItem(POLY_BM_KEY) || '[]')); } catch { polyBmSet = new Set(); }
  }
  return polyBmSet;
}
function polyBmToggle(cond: string): boolean {
  const s = polyBookmarks();
  const on = !s.has(cond);
  if (on) s.add(cond); else s.delete(cond);
  try { localStorage.setItem(POLY_BM_KEY, JSON.stringify([...s])); } catch { /* storage unavailable — state still holds for this session */ }
  return on;
}
function polyBmPaint(root: ParentNode) {
  root.querySelectorAll('[data-mmc-bookmark]').forEach(b => {
    const card = (b as HTMLElement).closest('[data-polym]');
    const cond = card ? (card as HTMLElement).dataset.polym || '' : '';
    const on = !!cond && polyBookmarks().has(cond);
    (b as HTMLElement).classList.toggle('on', on);
    (b as HTMLElement).setAttribute('aria-pressed', String(on));
  });
}
function wireMmcBookmarks(root: HTMLElement) {
  root.querySelectorAll('[data-mmc-bookmark]').forEach(b => (b as HTMLElement).onclick = (ev) => {
    ev.stopPropagation();
    const card = (b as HTMLElement).closest('[data-polym]');
    const cond = card ? (card as HTMLElement).dataset.polym || '' : '';
    if (!cond) return;
    polyBmToggle(cond);
    polyBmPaint(document);
  });
  polyBmPaint(root);
}
function bncCardHTML(e: PolyEvent, m: PolyMarket): string {
  // The finalized standalone binary card (Satoshi card): same final
  // language as the event card — orb tile + underlined title, the
  // orb-button pair instead of pills, quiet footer. NO gauge, NO
  // floating tips, NO LIVE tag. First outcome gets the orb-tilt slot,
  // second stays muted; prices live in the labels (data-poly-cents
  // keeps the first one ticking live).
  const p = m.prices[0] ?? 0;
  const p1 = m.prices[1] ?? (1 - p);
  const letter = (m.question || e.title || '?').trim().charAt(0).toUpperCase();
  const badge = `${esc(letter)}${e.image && isSafeMediaUrl(e.image) ? `<img class="coinImg evcBadgeImg" src="${esc(e.image)}" alt="">` : ''}`;
  return `<div class="polyCard evcCard strokeLit" data-polym="${esc(m.conditionId)}" role="button" tabindex="0">
    <div class="evcHead"><span class="evcBadge">${badge}</span><h3 class="evcTitle">${esc(m.question)}</h3></div>
    <div class="mmcBets"><button class="mmcOrb mmcInteractive strokeLit" data-poly-go="${esc(m.conditionId)}:0"><span class="mmcSlot mmcOrbTilt">${MMC_TREND_UP}</span><span class="mmcLbl">${esc(m.outcomes[0] || 'Yes')} <span data-poly-cents="${esc(m.tokenIds[0] || '')}">${polyCents(p)}</span></span></button><button class="mmcOrb mmcInteractive mmcMuted strokeLit" data-poly-go="${esc(m.conditionId)}:1"><span class="mmcSlot mmcFlat">${MMC_TREND_DOWN}</span><span class="mmcLbl">${esc(m.outcomes[1] || 'No')} <span data-poly-cents="${esc(m.tokenIds[1] || '')}">${polyCents(p1)}</span></span></button></div>
    <div class="evcFoot"><span class="evcMeta">Polymarket · ${fmtMcap(m.volume)} Vol. · Ends ${polyEnd(m.endDate || e.endDate)}</span><button class="evcBookmark" data-mmc-bookmark aria-label="Bookmark market">${MMC_BOOKMARK}</button></div>
  </div>`;
}
function polyMiniCard(e: PolyEvent, m: PolyMarket): string {
  if (isUpDown(m)) return mmcCardHTML(e, m, m.question, (e.title || '?').trim().charAt(0).toUpperCase());
  return bncCardHTML(e, m);
}
function polyMatchCard(e: PolyEvent, m: PolyMarket): string {
  const [t1, t2] = e.title.split(/\s+vs\.?\s+/i);
  const row = (ix: number, name: string) => `<div class="polyTeamRow"><span class="polyTeamIc">${esc((name || '?').trim().slice(0, 2).toUpperCase())}</span><span class="polyTeamName">${esc(name || m.outcomes[ix] || '')}</span><span class="polyTeamPct" data-poly-price="${esc(m.tokenIds[ix] || '')}">${polyPct(m.prices[ix] ?? 0)}</span></div>`;
  return `<div class="polyCard" data-polym="${esc(m.conditionId)}" role="button" tabindex="0">
    ${row(0, t1)}${row(1, t2)}
    <div class="polyPills"><button class="polyPill yes" data-poly-go="${esc(m.conditionId)}:0">${esc(t1 || m.outcomes[0] || '')}</button><button class="polyPill no" data-poly-go="${esc(m.conditionId)}:1">${esc(t2 || m.outcomes[1] || '')}</button></div>
    <div class="polyCardFoot"><span class="polyLiveTag"><span class="liveDotSm"></span>Sports</span><span>${fmtMcap(m.volume)} Vol.</span><span>Ends ${polyEnd(m.endDate || e.endDate)}</span><button class="evcBookmark" data-mmc-bookmark aria-label="Bookmark market">${MMC_BOOKMARK}</button></div>
  </div>`;
}
function polyEventCard(e: PolyEvent): string {
  // The finalized standalone event card (mini-market language, per
  // Penta's edit of the Trail Blazers vs. Knicks card): fill-panel +
  // stroke-lit, orb tile with the event's real image, underlined
  // title, silver-bar outcome rows, quiet footer. NO gauge, NO
  // floating tips, NO LIVE tag on this card type.
  const rows = e.markets.slice().sort((a, b) => (b.prices[0] ?? 0) - (a.prices[0] ?? 0)).slice(0, 4).map(m => {
    const p = m.prices[0] ?? 0;
    return `<button class="evcRow" data-poly-go="${esc(m.conditionId)}:0"><span class="evcLbl">${esc(m.outcomes[0] && m.outcomes[0] !== 'Yes' ? m.question : (m.question.replace(/^Will\s+/i, '').slice(0, 44)))}</span><span class="evcBar"><span style="width:${Math.round(p * 100)}%"></span></span><span class="evcPct" data-poly-price="${esc(m.tokenIds[0] || '')}">${polyPct(p)}</span></button>`;
  }).join('');
  const letter = (e.title || '?').trim().charAt(0).toUpperCase();
  const badge = `${esc(letter)}${e.image && isSafeMediaUrl(e.image) ? `<img class="coinImg evcBadgeImg" src="${esc(e.image)}" alt="">` : ''}`;
  return `<div class="polyCard evcCard strokeLit" data-polym="${esc(e.markets[0]?.conditionId || '')}" role="button" tabindex="0">
    <div class="evcHead"><span class="evcBadge">${badge}</span><h3 class="evcTitle">${esc(e.title)}</h3></div>
    <div class="evcRows">${rows}</div>
    <div class="evcFoot"><span class="evcMeta">Polymarket · ${fmtMcap(e.volume)} Vol. · ${e.markets.length} markets · Ends ${polyEnd(e.endDate)}</span><button class="evcBookmark" data-mmc-bookmark aria-label="Bookmark market">${MMC_BOOKMARK}</button></div>
  </div>`;
}
function polyCardFor(e: PolyEvent): string {
  const m = e.markets[0];
  if (!m) return '';
  const isMatch = (polyCat === 'sports' || e.tags.includes('sports')) && /\s+vs\.?\s+/i.test(e.title) && m.outcomes.length === 2 && !/^yes$/i.test(m.outcomes[0] || '');
  if (e.markets.length === 1 && m.outcomes.length === 2) return isMatch ? polyMatchCard(e, m) : polyMiniCard(e, m);
  return polyEventCard(e);
}

// ---- Up or Down cards ----
// One card per asset for the CURRENT window of the chosen timeframe.
// The foot carries a live countdown (data-ud-end, ticked by the
// section's 1s timer); when a window rolls, the section reloads
// itself with the next window's markets.
function fmtUdCountdown(ms: number): string {
  const s = Math.max(0, Math.ceil(ms / 1000));
  return Math.floor(s / 60) + ':' + String(s % 60).padStart(2, '0');
}
// ---- Live ticker card (Up or Down detail) ----
// The card is the standalone live-ticker component, ported exactly:
// same layout, same values, Polymarket branding beside the
// countdown. Its numbers are REAL: Price To Beat, Current Price and
// the chart line all come from the Chainlink stream these markets
// resolve on, relayed by the server (/api/poly/chainlink) — never
// the demo's synthetic series.
function ltFmtSpot(v: number): string {
  if (v >= 100) return '$' + v.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
  if (v >= 1) return '$' + v.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 4 });
  return '$' + v.toPrecision(4);
}
function ltWindowLine(startMs: number, endMs: number): string {
  const tz = 'America/New_York';
  const md = new Intl.DateTimeFormat('en-US', { timeZone: tz, month: 'long', day: 'numeric' }).format(new Date(startMs));
  const parts = (t: number) => new Intl.DateTimeFormat('en-US', { timeZone: tz, hour: 'numeric', minute: '2-digit', hour12: true }).formatToParts(new Date(t));
  const hm = (t: number, mer: boolean) => { const p = parts(t); const g = (k: string) => p.find(x => x.type === k)?.value || ''; return mer ? `${g('hour')}:${g('minute')}${g('dayPeriod')}` : `${g('hour')}:${g('minute')}`; };
  const sameMer = parts(startMs).find(x => x.type === 'dayPeriod')?.value === parts(endMs).find(x => x.type === 'dayPeriod')?.value;
  return `${md}, ${hm(startMs, !sameMer)}-${hm(endMs, true)} ET`;
}
function ltCardHTML(eventTitle: string, tfSecs: number, startMs: number, endMs: number, asset = ''): string {
  const tfLabel = tfSecs === 300 ? '5m' : tfSecs === 900 ? '15m' : '1h';
  const title = (eventTitle || '').split(' - ')[0] + ' ' + tfLabel;
  const logo = UD_COIN_LOGOS[asset] || '';
  return `<div class="ltCard">
    <div class="ltHeader">
      <span class="ltLogo">${logo ? `<img class="ltLogoImg" src="${logo}" alt="">` : '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 2 4.5 12.2 12 16.6l7.5-4.4L12 2Z"/><path d="M12 22.2 4.5 13.7 12 18.1l7.5-4.4L12 22.2Z" opacity=".72"/></svg>'}</span>
      <div class="ltTitle"><h3>${esc(title)}</h3>
        <div class="ltSub"><span>${esc(ltWindowLine(startMs, endMs))}</span><svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M12 11v5"/><path d="M12 8h.01"/></svg></div>
      </div>
      <div class="ltActions">
        <button class="ltIconBtn" id="ltEmbed" type="button" aria-label="Copy embed code"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="m8 8-4.5 4L8 16M16 8l4.5 4L16 16"/></svg></button>
        <button class="ltIconBtn" id="ltCopy" type="button" aria-label="Copy link"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M14 5h5v5"/><path d="M19 5l-7.5 7.5"/><path d="M19 13.5V19a1.5 1.5 0 0 1-1.5 1.5h-12A1.5 1.5 0 0 1 4 19V7a1.5 1.5 0 0 1 1.5-1.5H11"/></svg></button>
        <button class="ltIconBtn" id="ltBookmark" type="button" aria-label="Bookmark" aria-pressed="false"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M7 4.5h10V20l-5-3.6L7 20Z"/></svg></button>
      </div>
    </div>
    <div class="ltStats">
      <div><div class="ltLabel">Price To Beat</div><div class="ltBig" id="ltBeat">—</div></div>
      <div class="ltDivider"><div class="ltLabel blue"><span>Current Price</span><span class="ltDelta" id="ltDeltaWrap"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 5.5 19 18H5Z"/></svg><span id="ltDelta">—</span></span></div><div class="ltBig indigo" id="ltCur">—</div></div>
      <div class="ltRight">
        <div class="ltCount"><div class="ltCell"><div class="ltNum" id="ltMins">--</div><div class="ltUnit">Mins</div></div><div class="ltCell"><div class="ltNum" id="ltSecs">--</div><div class="ltUnit">Secs</div></div></div>
        <span class="ltBrand"><img src="/assets/polymarket-logo.png" alt="" aria-hidden="true">Polymarket</span>
      </div>
    </div>
    <svg class="ltChart" id="ltSvg" viewBox="0 0 640 260" preserveAspectRatio="none" role="img" aria-label="Live price chart"></svg>
    <div class="ltMarkers"><div class="ltVals"><span class="ltVal" id="ltDeltaChip">—</span><span class="ltVal" id="ltDeltaPct">—</span></div><span class="ltTarget">Target<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m6 9 6 6 6-6"/></svg></span></div>
    <div class="ltFooter"><span class="ltSource">Source: polymarket.com</span><div class="ltTimes" id="ltTimes"></div></div>
  </div>`;
}
// ---- Quick trade panel (Up or Down detail) ----
// The standalone quick-trade component, ported exactly: indigo
// diamond tile, muted market title, coloured side label, underline
// tabs, the 1-Tap / Confirm each / Limit select menu, aurora-orb
// side buttons with live cent labels, $5/$25/$100 presets with live
// win lines, and the Terms footer. Execution is the wallet's real
// Polymarket flow: 1-Tap places through the same build/validate/
// sign/post path as the review sheet (direct mode), Confirm each
// and Limit go through the review sheet; the pUSD/session gates
// apply unchanged.
const QT_TREND_UP = 'M232,104a8,8,0,0,1-8,8H184a8,8,0,0,1,0-16h28.7L134.3,101.4a8,8,0,0,1-11.3,0L88,66.3,51.3,103a8,8,0,0,1-11.3-11.3l48-48a8,8,0,0,1,11.3,0l35,35L205.4,8H176a8,8,0,0,1,0-16h48a8,8,0,0,1,8,8Z';
const QT_TREND_DN = 'M232,152a8,8,0,0,1-8,8H184a8,8,0,0,1,0-16h28.7l-78.4,5.4a8,8,0,0,1-11.3,0L88,189.7,51.3,153A8,8,0,0,1,40,141.7l48-48a8,8,0,0,1,11.3,0l35,35L205.4,248H176a8,8,0,0,1,0-16h48a8,8,0,0,1,8,8Z';
function qtPanelHTML(sel: { eventTitle: string; outcomeIx: number }, m: PolyMarket): string {
  const title = (sel.eventTitle || '').split(' - ')[0];
  const side0 = m.outcomes[sel.outcomeIx] || '';
  return `<div class="qtPanel qtStrokeLit qtFillPanel" role="region" aria-label="Quick trade panel">
    <div class="qtHead">
      <span class="qtLogo" aria-hidden="true"><svg viewBox="0 0 24 24" fill="#fff"><path d="M12 2.8 17.2 11.5 12 14.62 6.8 11.5 12 2.8Z"/><path d="M6.8 13.36 12 16.48 17.2 13.36 12 20.9 6.8 13.36Z"/></svg></span>
      <div><div class="qtSub">${esc(title)}</div><div class="qtSide${side0 === 'Down' ? ' down' : ''}" id="qtSideLabel">${esc(side0)}</div></div>
    </div>
    <div class="qtTabs" role="tablist" aria-label="Order type">
      <button class="qtTab qtInteractive" role="tab" aria-selected="true" data-tside="BUY">Buy</button>
      <button class="qtTab qtInteractive" role="tab" aria-selected="false" data-tside="SELL">Sell</button>
      <div class="qtSelect" id="qtSelect">
        <button class="qtTrigger qtInteractive" aria-haspopup="listbox" aria-expanded="false" id="qtTrigger"><span id="qtModeValue">1-Tap</span><svg viewBox="0 0 256 256" fill="currentColor"><path d="M213.66,101.66l-80,80a8,8,0,0,1-11.32,0l-80-80A8,8,0,0,1,48,88H208a8,8,0,0,1,5.66,13.66Z"/></svg></button>
        <div class="qtMenu qtFillPanel" role="listbox" id="qtMenu">${['1-Tap', 'Confirm each', 'Limit'].map((md, i) => `<button role="option" aria-selected="${i === 0}" data-qtmode="${md}"><span>${md}</span><svg viewBox="0 0 256 256" fill="currentColor"><path d="M229.66,77.66l-128,128a8,8,0,0,1-11.32,0l-56-56a8,8,0,0,1,11.32-11.32L96,188.69,218.34,66.34a8,8,0,0,1,11.32,11.32Z"/></svg></button>`).join('')}</div>
      </div>
    </div>
    <div class="qtSides" role="group" aria-label="Direction">${m.outcomes.map((o, ix) => `<button class="qtOrb qtStrokeLit qtFillAction qtInteractive${ix === sel.outcomeIx ? ' selected' : ''}" data-out="${ix}"><span class="qtOrbIc"><svg viewBox="0 0 256 256" fill="currentColor"><path d="${ix === 0 ? QT_TREND_UP : QT_TREND_DN}"${ix === 0 ? ' transform="translate(0,24)"' : ' transform="scale(1,-1) translate(0,-232)"'}"/></svg></span><span class="qtLbl">${esc(o)} <b data-poly-pill="${esc(m.tokenIds[ix] || '')}">${polyCents(m.prices[ix] ?? 0)}</b></span></button>`).join('')}</div>
    <div class="qtLabel" id="qtActionLabel">One-tap buy</div>
    <div class="qtPresets">${[5, 25, 100].map(a => `<button class="qtPreset qtHoverRaise qtInteractive" data-qtpreset="${a}" aria-pressed="false"><span class="qtAmt">$${a}</span><span class="qtWin" data-qtline="${a}">win <b data-win="${a}">—</b></span></button>`).join('')}</div>
    <button class="qtSellAll qtInteractive" id="qtSellAll" style="display:none">Sell all shares</button>
    <div id="polyLimitRow" style="display:none;margin-top:12px"><label class="polyFldLbl">Limit price (¢)</label><input id="polyLimitPx" class="polyIn" inputmode="decimal" placeholder="50"></div>
    <div class="small muted" id="polyHoldLine" style="margin-top:10px"></div>
    <div id="polyGateBox"><div style="padding:6px 0">${waveLoadBlockHTML()}</div></div>
    <div class="err" id="polyTradeErr" style="display:none"></div>
    <p class="qtStatus" id="qtStatus" aria-live="polite"></p>
    <p class="qtTerms">By trading, you agree to the <a href="https://polymarket.com/terms" target="_blank" rel="noopener">Terms of Use</a>.</p>
  </div>`;
}
function polyUpDownCard(e: PolyEvent, m: PolyMarket, assetName: string, symbol: string, tfLabel: string): string {
  return mmcCardHTML(e, m, `${symbol} Up or Down ${tfLabel}`, (symbol || '?').charAt(0).toUpperCase());
}

// Addition 10: positions design — money count-up (first paint per
// account only; the promo card's lesson: replaying on every tab switch
// reads as reloading) and the position icon: the market's REAL image,
// with a letter tile in a title-hashed colour if the image is missing
// or fails to load, so a row never renders broken or empty.
let polyPosSeenKey = '';
function polyCountUp(el: HTMLElement) {
  const target = parseFloat(el.dataset.pcount || ''); if (!Number.isFinite(target)) return;
  const kind = el.dataset.pkind;
  const fmt = (v: number): string => kind === 'pnl' ? (v < 0 ? '−' : '+') + fmtUsd(Math.abs(v)) : fmtUsd(v);
  if (!wavesFxOn()) { el.textContent = fmt(target); return; }
  const t0 = performance.now(); const dur = 950;
  const step = (t: number) => { const k = Math.min(1, (t - t0) / dur); const e = 1 - Math.pow(1 - k, 3); el.textContent = fmt(target * e); if (k < 1) requestAnimationFrame(step); };
  setTimeout(() => requestAnimationFrame(step), 400);
}
const POLY_TILE_COLORS = ['#D97757', '#F7931A', '#542583', '#2F5CFF', '#0E7C5B', '#8A5A2B', '#375A7F', '#7A3B69'];
function polyTileFor(title: string): { letter: string; color: string } {
  let h = 0; for (const ch of title) h = (h * 31 + ch.charCodeAt(0)) >>> 0;
  return { letter: (title || '?').trim().charAt(0).toUpperCase() || '?', color: POLY_TILE_COLORS[h % POLY_TILE_COLORS.length] };
}
function polyPosIconHTML(p: PolyPosition): string {
  // The letter sits UNDER the image (the app's dapp-row pattern): the
  // global error handler removes a broken .coinImg, revealing it.
  const t = polyTileFor(p.title);
  if (!p.icon) return `<span class="polyEvIc polyTile" style="background:${t.color}">${esc(t.letter)}</span>`;
  if (!isSafeMediaUrl(p.icon)) return `<span class="polyEvIc polyTile" style="background:${t.color}">${esc(t.letter)}</span>`;
  return `<span class="polyEvIc polyTile" style="background:${t.color}">${esc(t.letter)}<img class="coinImg" src="${esc(p.icon)}" alt=""></span>`;
}

let polySearchTimer: ReturnType<typeof setTimeout> | null = null;
async function paintInvestPoly(body: HTMLElement) {
  polyListCleanup();
  body.innerHTML = `
    <div class="polyCats" role="tablist">${POLY_CATS.map(c => `<button class="polyCat${polyCat === c.id ? ' on' : ''}" data-cat="${c.id}">${c.icon ? `<i class="${c.icon}"></i>` : ''}<span>${c.label}</span></button>`).join('')}</div>
    <div id="polyPositions"></div>
    <div id="polyNote"></div>
    <div id="polyList"><div style="padding:6px 16px">${waveLoadBlockHTML()}</div></div>
    <p class="small muted" style="padding:10px 16px;line-height:1.55">Live from Polymarket (Gamma + CLOB). Prices stream over the app's relayed WebSocket — the same market channel Polymarket's own site uses. Trading is attributed to Syn as a builder; your keys never leave this device.</p>`;
  body.querySelectorAll('[data-cat]').forEach(b => (b as HTMLElement).onclick = () => { polyCat = (b as HTMLElement).dataset.cat!; paintInvestBody(); });
  // His positions (public Data API read for his Polygon address).
  const addr = evmAddressOf();
  if (addr) void polyPositions(addr).then(ps => {
    const slot = $('#polyPositions'); if (!slot || currentRoute !== 'invest' || investSection !== 'poly') return;
    if (!ps.length) { slot.innerHTML = ''; return; }
    const total = ps.reduce((s, p) => s + p.currentValue, 0);
    const net = ps.reduce((s, p) => s + p.cashPnl, 0);
    const first = polyPosSeenKey !== addr; polyPosSeenKey = addr;
    const fx = first && wavesFxOn();
    slot.classList.toggle('fxOn', fx);
    const cnt = (v: number, kind: string): string => first ? ` data-pcount="${v}" data-pkind="${kind}"` : '';
    slot.innerHTML = `<div class="secHead" style="padding:2px 16px 6px"><span class="secTitle">Your positions</span><span class="polyPosTot"><span class="polyPosTotal"${cnt(total, 'usd')}>${fmtUsd(total)}</span><span class="polyPosNet ${net >= 0 ? 'pos' : 'neg'}"${cnt(net, 'pnl')}>${net >= 0 ? '+' : '−'}${fmtUsd(Math.abs(net))}</span></span></div>
      <div style="padding:0 16px;display:flex;flex-direction:column;gap:8px">${ps.slice(0, 50).map((p, i) => `<div class="polyPosRow" style="--i:${i}" role="button" tabindex="0" data-poly-pos="${esc(p.conditionId)}:${esc(p.asset)}"><span class="polySheen" aria-hidden="true"></span>${polyPosIconHTML(p)}<span class="polyPosTx"><span class="polyPosT">${esc(p.title)}</span><span class="polyPosS">${esc(p.outcome)} · ${trimNum(p.size, 2)} shares @ ${polyCents(p.avgPrice)}</span></span><span class="polyPosVal"><span${cnt(p.currentValue, 'usd')}>${fmtUsd(p.currentValue)}</span><span class="${p.cashPnl >= 0 ? 'pos' : 'neg'}"${cnt(p.cashPnl, 'pnl')}>${p.cashPnl >= 0 ? '+' : '−'}${fmtUsd(Math.abs(p.cashPnl))}</span></span></div>`).join('')}</div>${ps.length > 50 ? `<p class="small muted" style="padding:8px 16px 0">Showing 50 of ${ps.length} positions — the totals above include all of them.</p>` : ''}`;
    if (first) slot.querySelectorAll('[data-pcount]').forEach(el => polyCountUp(el as HTMLElement));
    // Audit fix: position rows were dead — no market id, no wiring.
    // A tap now opens that market's detail (outcome side = the
    // position's own token), like every other market card.
    let posBusy = false;
    const openPos = async (row: HTMLElement) => {
      if (posBusy) return;
      const [cond, asset] = (row.dataset.polyPos || '').split(':');
      if (!cond) return;
      posBusy = true;
      try {
        const m = await gammaMarketByCondition(cond);
        if (!m) return;
        const ix = Math.max(0, m.tokenIds.indexOf(asset));
        polySel = { market: m, eventTitle: m.question, outcomeIx: ix };
        go({ route: 'polymarket' }, row);
      } catch { /* stay on the list — the row can be tapped again */ }
      finally { posBusy = false; }
    };
    slot.querySelectorAll('[data-poly-pos]').forEach(row => {
      const el = row as HTMLElement;
      el.onclick = () => void openPos(el);
      el.onkeydown = (e: KeyboardEvent) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); void openPos(el); } };
    });
  }).catch(() => {
    // Audit fix: a failed positions read must not look identical to
    // holding nothing — say so in the slot instead of leaving it blank.
    const slot = $('#polyPositions'); if (!slot || currentRoute !== 'invest' || investSection !== 'poly') return;
    if (!slot.innerHTML) slot.innerHTML = '<p class="small muted" style="padding:2px 16px 6px">Your positions couldn’t load right now — reopen this tab to retry.</p>';
  });
  const paintUpDown = async (refresh = false) => {
    polyListCleanup();
    const slot = $('#polyList'); if (!slot || currentRoute !== 'invest' || investSection !== 'poly') return;
    const note = $('#polyNote'); if (note) note.innerHTML = '';
    const chips = `<div class="polyCats" style="padding-top:2px">${UPDOWN_TFS.map(t => `<button class="polyCat${t.secs === polyUpTf ? ' on' : ''}" data-udtf="${t.secs}"><span>${t.id}</span></button>`).join('')}</div>`;
    const wireChips = () => slot.querySelectorAll('[data-udtf]').forEach(b => (b as HTMLElement).onclick = () => { polyUpTf = Number((b as HTMLElement).dataset.udtf) || 300; void paintUpDown(); });
    // Audit fix (invisible updates): a window-rollover refresh must
    // not blank the live cards behind a loading block — keep the
    // current cards on screen and swap them when the new window's
    // data lands. The loader is only for the first paint / chip taps.
    if (!(refresh && slot.querySelector('.polyGrid'))) {
      slot.innerHTML = chips + `<div style="padding:6px 16px">${waveLoadBlockHTML('Loading…', true)}</div>`;
      wireChips();
    }
    const tf = UPDOWN_TFS.find(t => t.secs === polyUpTf) || UPDOWN_TFS[0];
    const evs = await Promise.all(UPDOWN_ASSETS.map(a => gammaEventBySlug(upDownSlug(a.slug, polyUpTf)).catch(() => null)));
    if (!document.body.contains(slot) || currentRoute !== 'invest' || investSection !== 'poly' || polyCat !== 'updown') return;
    const pairs = UPDOWN_ASSETS.map((a, i) => ({ a, e: evs[i] })).filter(x => x.e && x.e.markets.length);
    if (!pairs.length) { slot.innerHTML = chips + '<p class="small muted secEmpty">Up or Down markets are unavailable right now.</p>'; wireChips(); return; }
    slot.innerHTML = chips + `<div class="polyGrid">${pairs.map(({ a, e }) => polyUpDownCard(e!, e!.markets[0], a.name, a.symbol, tf.id)).join('')}</div>`;
    wireChips();
    const byCond = new Map<string, { e: PolyEvent; m: PolyMarket; asset: string }>();
    for (const { a, e } of pairs) for (const m of e!.markets) byCond.set(m.conditionId, { e: e!, m, asset: a.slug });
    const open = (cond: string, ix: number, el: HTMLElement) => { const hit = byCond.get(cond); if (hit) { polySel = { market: hit.m, eventTitle: hit.e.title, outcomeIx: ix, updown: { asset: hit.asset, tfSecs: polyUpTf } }; go({ route: 'polymarket' }, el); } };
    slot.querySelectorAll('[data-poly-go]').forEach(b => (b as HTMLElement).onclick = (ev) => { ev.stopPropagation(); const [cond, ix] = ((b as HTMLElement).dataset.polyGo || '').split(':'); open(cond, Number(ix) || 0, b as HTMLElement); });
    slot.querySelectorAll('[data-polym]').forEach(card => (card as HTMLElement).onclick = () => open((card as HTMLElement).dataset.polym!, 0, card as HTMLElement));
    wireMmcBookmarks(slot);
    paintMmcTips(slot);
    for (const { e } of pairs) { const m = e!.markets[0]; if (m?.tokenIds[0]) polyListUnsubs.push(polyFeed.subscribe(m.tokenIds[0], () => {
      const q2 = polyFeed.quotes.get(m.tokenIds[0]); if (!q2) return;
      const mid = q2.bestBid > 0 && q2.bestAsk > 0 ? (q2.bestBid + q2.bestAsk) / 2 : q2.lastTrade;
      if (!mid) return;
      slot.querySelectorAll(`[data-poly-price="${m.tokenIds[0]}"]`).forEach(el => { el.textContent = polyPct(mid); });
      slot.querySelectorAll(`[data-poly-cents="${m.tokenIds[0]}"]`).forEach(el => { el.textContent = polyCents(mid); });
      if (m.tokenIds[1]) slot.querySelectorAll(`[data-poly-cents="${m.tokenIds[1]}"]`).forEach(el => { el.textContent = polyCents(1 - mid); });
    })); }
    let rolling = false;
    polyUdTimer = setInterval(() => {
      if (!document.body.contains(slot)) { if (polyUdTimer) { clearInterval(polyUdTimer); polyUdTimer = null; } return; }
      const now = Date.now();
      let rolled = false;
      slot.querySelectorAll('[data-ud-end]').forEach(el => { const end = Number((el as HTMLElement).dataset.udEnd); const left = end - now; (el as HTMLElement).textContent = left > 0 ? 'Ends in ' + fmtUdCountdown(left) : 'Ending…'; if (left <= 0) rolled = true; });
      if (rolled && !rolling) { rolling = true; void paintUpDown(true); }
    }, 1000);
  };
  const load = async () => {
    const slot = $('#polyList'); if (!slot || currentRoute !== 'invest' || investSection !== 'poly') return;
    const note = $('#polyNote');
    const q = investQuery.trim();
    if (polyCat === 'updown' && q.length < 2) { await paintUpDown(); return; }
    const key = q.length >= 2 ? 'q:' + q.toLowerCase() : 'tag:' + polyCat;
    const PAGE = 100; // Gamma's max page — categories hold far more than the old single page of 24.
    const render = (events: PolyEvent[]) => {
      polyLastRendered = events;
      const all = [...events];
      slot.innerHTML = `<div class="polyGrid">${events.map(polyCardFor).join('')}</div>`;
      // (Re)binds every card in the grid from the accumulated list —
      // onclick assignment is idempotent, so Show more can re-run it
      // after appending a page.
      const wireCards = () => {
        const byCond = new Map<string, { e: PolyEvent; m: PolyMarket }>();
        for (const e of all) for (const m of e.markets) byCond.set(m.conditionId, { e, m });
        slot.querySelectorAll('[data-poly-go]').forEach(b => (b as HTMLElement).onclick = (ev) => { ev.stopPropagation(); const [cond, ix] = ((b as HTMLElement).dataset.polyGo || '').split(':'); const hit = byCond.get(cond); if (hit) { polySel = { market: hit.m, eventTitle: hit.e.title, outcomeIx: Number(ix) || 0 }; go({ route: 'polymarket' }, b as HTMLElement); } });
        slot.querySelectorAll('[data-polym]').forEach(card => (card as HTMLElement).onclick = () => { const hit = byCond.get((card as HTMLElement).dataset.polym!); if (hit) { polySel = { market: hit.m, eventTitle: hit.e.title, outcomeIx: 0 }; go({ route: 'polymarket' }, card as HTMLElement); } });
        wireMmcBookmarks(slot);
        paintMmcTips(slot);
      };
      wireCards();
      // Show more: categories page through Gamma at 100 a page until
      // a short page says the list is exhausted.
      if (q.length < 2 && events.length >= PAGE) {
        const wrap = document.createElement('div');
        wrap.className = 'polyMoreWrap';
        wrap.innerHTML = '<button class="btnGhost polyMoreBtn" type="button">Show more markets</button>';
        slot.appendChild(wrap);
        const btn = wrap.querySelector('button') as HTMLButtonElement;
        const shownIds = new Set(all.map(e => e.id));
        let offset = PAGE;
        let busy = false;
        btn.onclick = async () => {
          if (busy) return;
          busy = true;
          btn.textContent = 'Loading…';
          try {
            const pageEvts = await gammaEvents({ tag: polyCat === 'trending' ? undefined : polyCat, limit: PAGE, offset });
            offset += PAGE;
            const fresh = pageEvts.filter(e => !shownIds.has(e.id));
            if (fresh.length) {
              for (const e of fresh) { shownIds.add(e.id); all.push(e); }
              const grid = slot.querySelector('.polyGrid');
              if (grid) grid.insertAdjacentHTML('beforeend', fresh.map(polyCardFor).join(''));
              polyLastRendered = all;
              polyListMem.set(key, all);
              wireCards();
            }
            if (pageEvts.length < PAGE || !fresh.length) { wrap.remove(); return; }
            btn.textContent = 'Show more markets';
          } catch { btn.textContent = 'Couldn’t load more — tap to retry'; }
          busy = false;
        };
      }
      if (slot.querySelector('[data-ud-end]')) {
        polyUdTimer = setInterval(() => {
          if (!document.body.contains(slot)) { if (polyUdTimer) { clearInterval(polyUdTimer); polyUdTimer = null; } return; }
          const now = Date.now();
          slot.querySelectorAll('[data-ud-end]').forEach(el => { const end = Number((el as HTMLElement).dataset.udEnd); const left = end - now; (el as HTMLElement).textContent = left > 0 ? 'Ends in ' + fmtUdCountdown(left) : 'Ending…'; });
        }, 1000);
      }
      // Live % ticks for the visible binary markets (bounded, silent).
      const watch: string[] = [];
      for (const e of events) { const m = e.markets[0]; if (m && m.outcomes.length === 2 && m.tokenIds[0]) watch.push(m.tokenIds[0]); if (watch.length >= 10) break; }
      for (const tid of watch) polyListUnsubs.push(polyFeed.subscribe(tid, () => {
        const q2 = polyFeed.quotes.get(tid); if (!q2) return;
        const mid = q2.bestBid > 0 && q2.bestAsk > 0 ? (q2.bestBid + q2.bestAsk) / 2 : q2.lastTrade;
        if (!mid) return;
        slot.querySelectorAll(`[data-poly-price="${tid}"]`).forEach(el => { el.textContent = polyPct(mid); });
        slot.querySelectorAll(`[data-poly-cents="${tid}"]`).forEach(el => { el.textContent = polyCents(mid); });
      }));
    };
    try {
      let events = await gammaEvents(q.length >= 2 ? { search: q } : { tag: polyCat === 'trending' ? undefined : polyCat, limit: PAGE });
      if (!document.body.contains(slot)) return;
      // The live Bitcoin Up or Down window leads the popular list.
      if (polyCat === 'trending' && q.length < 2) {
        try {
          const pin = await gammaEventBySlug(upDownSlug('btc', 300));
          if (pin && pin.markets.length) events = [pin, ...events.filter(e => e.id !== pin.id)];
        } catch { /* the pin is a bonus, never a blocker */ }
        if (!document.body.contains(slot)) return;
      }
      if (!events.length) {
        if (note) note.innerHTML = '';
        slot.innerHTML = q.length >= 2
          ? '<p class="small muted secEmpty">No live markets match that search.</p>'
          : '<p class="small muted secEmpty">No live markets in this category right now.</p>';
        return;
      }
      polyListMem.set(key, events);
      if (note) note.innerHTML = '';
      render(events);
    } catch {
      if (!document.body.contains(slot)) return;
      // Failure doctrine: never blank good content behind a dead-end
      // message. A cached list for this view wins; content already on
      // screen stays with a scoped note; the unreachable state is only
      // for a first-ever load with nothing to show, and it can retry.
      const cached = polyListMem.get(key);
      if (cached && cached.length) {
        render(cached);
        if (note) note.innerHTML = '<p class="polyStaleNote">Couldn’t refresh — showing the last markets loaded for this view.</p>';
        return;
      }
      if (polyLastRendered && polyLastRendered.length) {
        // The section repaint on typing wipes the visible list before
        // the fetch resolves, so "keep the previous results" has to
        // restore them from memory, not from the DOM.
        render(polyLastRendered);
        if (note) note.innerHTML = `<p class="polyStaleNote">${q.length >= 2 ? 'Search failed — showing the previous results.' : 'Couldn’t refresh — showing the previous results.'}</p>`;
        return;
      }
      if (slot.querySelector('.polyCard')) {
        if (note) note.innerHTML = `<p class="polyStaleNote">${q.length >= 2 ? 'Search failed — showing the previous results.' : 'Couldn’t refresh — showing the previous results.'}</p>`;
        return;
      }
      slot.innerHTML = `<div class="secEmpty" style="text-align:center"><p class="small muted" style="margin-bottom:12px">Polymarket is unreachable right now — check back in a moment.</p><button class="btnGhost" id="polyRetry" style="border-radius:999px">Retry</button></div>`;
      const rb = $('#polyRetry'); if (rb) rb.onclick = () => { slot.innerHTML = `<div style="padding:6px 16px">${waveLoadBlockHTML()}</div>`; void load(); };
    }
  };
  if (investQuery.trim().length >= 2) { if (polySearchTimer) clearTimeout(polySearchTimer); polySearchTimer = setTimeout(() => void load(), 350); }
  else void load();
}

// ---------- Polymarket market detail: live chart + book + trade ----------
interface PolyGate { state: 'checking' | 'needs-connect' | 'no-collateral' | 'needs-wrap' | 'needs-approval' | 'ready' | 'error'; pusd: number | null; usdcE: number | null; usdcNative: number | null; msg: string }
// Audit fix: the gate cache is keyed by wallet + exchange type. The
// allowance lives on a market-specific exchange (standard vs Neg-Risk),
// so an unkeyed cache let one market inherit another's "ready".
let polyGateCache: { at: number; gate: PolyGate; key: string } | null = null;
let polyTrade = { side: 'BUY' as 'BUY' | 'SELL', mode: 'market' as 'market' | 'limit', amount: '25', shares: '', limitCents: '' };
let polySeries: { t: number; p: number }[] = [];
let polySeriesToken = '';
let polyMyPos: PolyPosition | null = null;

async function polyErc20Bal(token: string, owner: string): Promise<number | null> {
  const c = findChain('polygon'); if (!c) return null;
  try { const res = await evmCall(c, 'eth_call', [{ to: token, data: '0x70a08231' + owner.slice(2).toLowerCase().padStart(64, '0') }, 'latest']); return Number(BigInt(res)) / 1e6; } catch { return null; }
}
async function evalPolyGate(m: PolyMarket, force = false): Promise<PolyGate> {
  const key = evmAddressOf() + ':' + (m.negRisk ? 'nr' : 'std');
  if (!force && polyGateCache && polyGateCache.key === key && Date.now() - polyGateCache.at < 20000) return polyGateCache.gate;
  const done = (gate: PolyGate): PolyGate => { polyGateCache = { at: Date.now(), gate, key }; return gate; };
  await loadFeatureCfg();
  // Builder identity (CLOB V2): attribution comes from the builder
  // CODE written into the signed order — configured on this
  // deployment — so it never blocks trading. The builder API
  // key/secret/passphrase gate only the gasless RELAYER path
  // (Builder-authenticated submissions); they are named where that
  // path is offered, not as a blanket trading block.
  const attr = featureCfg.polymarketBuilderCode
    ? ' Orders from this app carry Syn’s builder code in the signed order (attribution on).'
    : ' Builder attribution is off on this deployment (no builder code configured on the server).';
  if (!evmPrivKey()) return done({ state: 'error', pusd: null, usdcE: null, usdcNative: null, msg: 'This wallet has no EVM key (Solana-only), so it can’t trade on Polymarket.' });
  if (!polyCreds) return done({ state: 'needs-connect', pusd: null, usdcE: null, usdcNative: null, msg: 'Connect trading once per session: your wallet signs a Polymarket login message (EIP-712) and derives its CLOB API credentials on this device. Nothing is stored.' + attr });
  const addr = evmAddressOf();
  const [pusd, usdcE, usdcNative] = await Promise.all([polyErc20Bal(PUSD, addr), polyErc20Bal(USDC_E, addr), polyErc20Bal(USDC_NATIVE, addr)]);
  // Audit fix: unverifiable reads must fail CLOSED. Previously a null
  // balance/allowance (Polygon RPC down) fell through to "ready".
  if (pusd == null) return done({ state: 'error', pusd, usdcE, usdcNative, msg: 'Couldn’t verify your pUSD balance — Polygon didn’t answer. Trading stays paused until this check passes; reopen the market to retry.' });
  if (pusd <= 0) {
    if (usdcE != null && usdcE > 0) return done({ state: 'needs-wrap', pusd, usdcE, usdcNative, msg: `You hold ${fmtUsd(usdcE)} of USDC.e, but Polymarket’s CLOB V2 settles in pUSD. Wrap USDC.e into pUSD 1:1 before trading — deposit at polymarket.com (it converts automatically) or use the Collateral Onramp contract on Polygon.` });
    return done({ state: 'no-collateral', pusd, usdcE, usdcNative, msg: `No pUSD on Polygon in this wallet${usdcNative && usdcNative > 0 ? ` — you hold ${fmtUsd(usdcNative)} of native USDC, which isn’t the trading collateral either` : ''}. Fund this address (${shortAddr(addr)}) with pUSD, or deposit at polymarket.com (deposits are converted to pUSD automatically), before trading.` });
  }
  const c = findChain('polygon');
  const allowance = c ? await readAllowance(c, PUSD, addr, m.negRisk ? NEG_RISK_EXCHANGE_V2 : CTF_EXCHANGE_V2) : null;
  if (allowance == null) return done({ state: 'error', pusd, usdcE, usdcNative, msg: 'Couldn’t verify the exchange allowance — Polygon didn’t answer. Trading stays paused until this check passes; reopen the market to retry.' });
  if (allowance < 1000000n) return done({ state: 'needs-approval', pusd, usdcE, usdcNative, msg: `One approval is needed: let the Polymarket ${m.negRisk ? 'Neg-Risk ' : ''}exchange contract (V2) spend your pUSD. This is a standard ERC-20 approval from your wallet (gas in POL)${featureCfg.polymarketBuilderConfigured ? ', or gasless via the builder relayer — its Builder API credentials are configured on the server' : '. The gasless relayer path stays off until the operator adds the Builder API key / secret / passphrase (polymarket.com → Settings → Builders) to the server; the direct approval works without them'}.` });
  return done({ state: 'ready', pusd, usdcE, usdcNative, msg: (pusd != null ? `Trading ready · ${fmtUsd(pusd)} pUSD available` : 'Trading ready') + attr });
}

// The order book is ONE coherent surface, built once per outcome as a
// fixed skeleton (column header, ASKS caption, 7 ask slots, the spread
// divider, BIDS caption, 7 bid slots — every row a fixed height) and
// then painted IN PLACE: streamed updates change only text and depth-
// fill widths, never the DOM structure, so no row can shift. Depth is
// the cumulative total as a subtle right-anchored fill inside the row
// (no pills, no gaps, no floating bars); totals are cumulative from
// the best price through the row, matching the column header's math.
const POLY_BOOK_LEVELS = 7;
function polyBookSkeletonHTML(): string {
  const row = (side: 'ask' | 'bid', i: number) => `<div class="polyBookRow ${side}" data-brow="${side}${i}"><span class="polyBookFill"></span><span class="pbPx">—</span><span class="pbSh">—</span><span class="pbTot">—</span></div>`;
  let asks = ''; let bids = '';
  for (let i = 0; i < POLY_BOOK_LEVELS; i++) { asks += row('ask', i); bids += row('bid', i); }
  return `<div class="polyBook"><div class="polyBookCols"><span>Price</span><span>Shares</span><span>Total</span></div><div class="polyBookCap">Asks</div>${asks}<div class="polyBookSpread"><span class="pbSpLbl">Spread</span><span class="pbSpVal">—</span><span class="pbMid"></span></div><div class="polyBookCap">Bids</div>${bids}</div>`;
}
function polyBookPaint(root: HTMLElement, book: Book | undefined, key: string) {
  if (!book || (!book.bids.length && !book.asks.length)) {
    if (root.dataset.bk !== 'empty') { root.innerHTML = '<p class="small muted secEmpty">No order book for this outcome right now.</p>'; root.dataset.bk = 'empty'; }
    return;
  }
  if (root.dataset.bk !== key) { root.innerHTML = polyBookSkeletonHTML(); root.dataset.bk = key; }
  const asks = book.asks.slice().sort((a, b) => a.price - b.price).slice(0, POLY_BOOK_LEVELS);
  const bids = book.bids.slice().sort((a, b) => b.price - a.price).slice(0, POLY_BOOK_LEVELS);
  let cum = 0; const askRows = asks.map(l => { cum += l.price * l.size; return { ...l, total: cum }; });
  cum = 0; const bidRows = bids.map(l => { cum += l.price * l.size; return { ...l, total: cum }; });
  const maxT = Math.max(askRows[askRows.length - 1]?.total || 0, bidRows[bidRows.length - 1]?.total || 0, 0.01);
  const paintRow = (el: HTMLElement | null, l: { price: number; size: number; total: number } | undefined) => {
    if (!el) return;
    const fill = el.firstElementChild as HTMLElement;
    const px = el.children[1] as HTMLElement; const sh = el.children[2] as HTMLElement; const tot = el.children[3] as HTMLElement;
    if (!l) { el.classList.add('void'); fill.style.width = '0%'; px.textContent = '—'; sh.textContent = '—'; tot.textContent = '—'; return; }
    el.classList.remove('void');
    fill.style.width = Math.min(100, (l.total / maxT) * 100).toFixed(1) + '%';
    px.textContent = polyCents(l.price); sh.textContent = trimNum(l.size, 2); tot.textContent = fmtUsd(l.total);
  };
  // Asks display worst-first (descending) so the best ask sits directly
  // above the spread; slot i shows askRows[LEVELS-1-i] when it exists.
  for (let i = 0; i < POLY_BOOK_LEVELS; i++) paintRow(root.querySelector(`[data-brow="ask${i}"]`), askRows[POLY_BOOK_LEVELS - 1 - i]);
  for (let i = 0; i < POLY_BOOK_LEVELS; i++) paintRow(root.querySelector(`[data-brow="bid${i}"]`), bidRows[i]);
  const sp = root.querySelector('.polyBookSpread');
  if (sp) {
    const bestAsk = asks[0]?.price; const bestBid = bids[0]?.price;
    (sp.children[1] as HTMLElement).textContent = bestAsk != null && bestBid != null ? polyCents(bestAsk - bestBid) : '—';
    (sp.children[2] as HTMLElement).textContent = bestAsk != null && bestBid != null ? 'Mid ' + polyCents((bestAsk + bestBid) / 2) : '';
  }
}

function drawPolyChart() {
  const cv = document.querySelector('#polyChart') as unknown as HTMLCanvasElement | null;
  if (!cv || !polySeries.length) return;
  const dpr = Math.min(2, window.devicePixelRatio || 1);
  const w = cv.clientWidth; const h = 150;
  if (cv.width !== Math.round(w * dpr)) { cv.width = Math.round(w * dpr); cv.height = Math.round(h * dpr); }
  const ctx = cv.getContext('2d'); if (!ctx) return;
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0); ctx.clearRect(0, 0, w, h);
  const pts = polySeries.slice(-400);
  let min = Math.min(...pts.map(p => p.p)); let max = Math.max(...pts.map(p => p.p));
  if (max - min < 0.04) { const mid = (max + min) / 2; min = Math.max(0, mid - 0.02); max = Math.min(1, mid + 0.02); }
  const pad = (max - min) * 0.15; min = Math.max(0, min - pad); max = Math.min(1, max + pad);
  // Right gutter: the plot (line, fill, now-dot and its halo) lives in
  // [4, plotW-4]; the axis labels live entirely inside the gutter, so
  // a label can never sit on the stroke or the dot.
  const gutter = 36; const plotW = Math.max(40, w - gutter);
  const X = (i: number) => (i / Math.max(1, pts.length - 1)) * (plotW - 8) + 4;
  const Y = (v: number) => 10 + (1 - (v - min) / (max - min)) * (h - 24);
  ctx.strokeStyle = 'rgba(199,208,218,.10)'; ctx.fillStyle = 'rgba(147,169,192,.75)'; ctx.font = '9px Allo, sans-serif'; ctx.lineWidth = 1;
  for (let g = 0; g <= 3; g++) { const v = min + ((max - min) * g) / 3; const y = Y(v); ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(plotW, y); ctx.stroke(); ctx.fillText(polyPct(v), plotW + 6, y - 3); }
  // The break-even line (the live-ticker-chart's dashed target,
  // translated): 50% is where the market flips sides.
  if (min < 0.5 && max > 0.5) { const y = Y(0.5); ctx.save(); ctx.setLineDash([4, 4]); ctx.strokeStyle = 'rgba(199,208,218,.45)'; ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(plotW, y); ctx.stroke(); ctx.restore(); }
  const grad = ctx.createLinearGradient(0, 0, 0, h); grad.addColorStop(0, 'rgba(199,208,218,.20)'); grad.addColorStop(1, 'rgba(199,208,218,0)');
  ctx.beginPath(); pts.forEach((p, i) => { const x = X(i); const y = Y(p.p); i ? ctx.lineTo(x, y) : ctx.moveTo(x, y); });
  ctx.strokeStyle = '#d7dee8'; ctx.lineWidth = 1.6; ctx.stroke();
  ctx.lineTo(X(pts.length - 1), h); ctx.lineTo(X(0), h); ctx.closePath(); ctx.fillStyle = grad; ctx.fill();
  const lx = X(pts.length - 1); const ly = Y(pts[pts.length - 1].p);
  ctx.beginPath(); ctx.arc(lx, ly, 6, 0, Math.PI * 2); ctx.fillStyle = 'rgba(215,222,232,.18)'; ctx.fill();
  ctx.beginPath(); ctx.arc(lx, ly, 3, 0, Math.PI * 2); ctx.fillStyle = '#eef2f7'; ctx.fill();
}

function showPolyMarket() {
  const sel = polySel; if (!sel) { goTab('invest'); return; }
  const m = sel.market;
  const ud = sel.updown ?? parseUpDownSlug(m.slug) ?? undefined;
  polyTrade = { side: 'BUY', mode: 'market', amount: '25', shares: '', limitCents: '' };
  polyMyPos = null;
  const pillsHTML = `<div class="polyOutPills" id="polyOutPills">${m.outcomes.length === 2 ? m.outcomes.map((o, ix) => `<button class="orbBtn fillAction strokeLit${ix === sel.outcomeIx ? ' on' : ''}" data-out="${ix}"><span class="orbSlot"><i class="${isUpDown(m) ? (ix === 0 ? 'ri-arrow-right-up-line' : 'ri-arrow-right-down-line') : (ix === 0 ? 'ri-check-line' : 'ri-close-line')}"></i></span><span class="orbLbl">${esc(o)}</span><b class="orbCents" data-poly-pill="${esc(m.tokenIds[ix] || '')}">${polyCents(m.prices[ix] ?? 0)}</b></button>`).join('') : m.outcomes.map((o, ix) => `<button class="polyOutPill${ix === sel.outcomeIx ? ' on' : ''}" data-out="${ix}"><span>${esc(o)}</span><b data-poly-pill="${esc(m.tokenIds[ix] || '')}">${polyCents(m.prices[ix] ?? 0)}</b></button>`).join('')}</div>`;
  setView(`<main class="polyMain"><button class="backBtn" id="bk" aria-label="Back"><i class="ri-arrow-left-s-line"></i></button>
  ${ud ? `<div style="padding:6px 16px 0">${ltCardHTML(sel.eventTitle, ud.tfSecs, Date.parse(m.endDate) - ud.tfSecs * 1000, Date.parse(m.endDate), ud.asset)}</div>` : `<div style="padding:2px 16px 0"><div class="polyDetQ">${esc(m.question)}</div>
  <div class="polyDetMeta"><span>${fmtMcap(m.volume)} Vol.</span><span class="polyMetaSep">·</span><span>Ends ${polyEnd(m.endDate)}</span><span class="polyMetaSep">·</span><span class="polyLiveState" id="polyLiveState"><span class="liveDotSm off"></span>Connecting</span></div></div>`}
  ${ud ? '' : pillsHTML}
  ${ud ? '' : `<div class="polyPriceBlock"><span class="polyBigWrap"><span class="polyBigPrice" id="polyBigPrice">${polyPctNum(m.prices[sel.outcomeIx] ?? 0)}</span><span class="polyBigPct">%</span></span><span class="polyChanceLine">chance · <span id="polyLastTrade">${m.lastTrade ? 'last ' + polyCents(m.lastTrade) : ''}</span></span></div>
  <div class="polyChartWrap fillPanel strokeLit"><canvas id="polyChart"></canvas><div class="polyChartEmpty" id="polyChartEmpty">${waveLoadBlockHTML('Loading…', true)}</div></div>`}
  <div class="gGroup"><div class="gHead">Order book · <span id="polyBookOutcome">${esc(m.outcomes[sel.outcomeIx] || '')}</span></div><div class="gCard polyBookCard"><div id="polyBook">${waveLoadBlockHTML('Loading…', true)}</div></div></div>
  ${ud ? `<div style="padding:14px 16px 0">${qtPanelHTML(sel, m)}</div>` : `  <div class="gGroup"><div class="gHead">Trade</div><div class="gCard polyPanel" style="padding:14px">
    <div class="polySideTabs"><button data-tside="BUY" class="on">Buy</button><button data-tside="SELL">Sell</button><span class="polyModeSeg"><button data-tmode="market" class="on">Market</button><button data-tmode="limit">Limit</button></span></div>
    <div id="polyLimitRow" style="display:none"><label class="polyFldLbl">Limit price (¢)</label><input id="polyLimitPx" class="polyIn" inputmode="decimal" placeholder="50"></div>
    <div id="polyBuyAmt"><label class="polyFldLbl">Amount (pUSD)</label><div class="polyAmtWrap"><input id="polyAmt" class="polyIn" inputmode="decimal" value="25"></div><div class="polyPresetGrid">${[5, 25, 100].map(a => `<button class="polyPreset" data-preset="${a}"><span class="ppAmt">$${a}</span><span class="ppWin">win <b data-win="${a}">—</b></span></button>`).join('')}</div></div>
    <div id="polySellAmt" style="display:none"><label class="polyFldLbl">Shares</label><div class="polyAmtWrap"><input id="polyShares" class="polyIn" inputmode="decimal" placeholder="0"><button class="polyMaxBtn" id="polyMax" style="display:none">Sell all</button></div><div class="small muted" id="polyHoldLine"></div></div>
    <div class="polyEst" id="polyEst"></div>
    <div id="polyGateBox"><div style="padding:6px 0">${waveLoadBlockHTML()}</div></div>
    <div class="err" id="polyTradeErr" style="display:none"></div>
    <button class="ctaWide" id="polyReview" disabled>Review order</button>
    <p class="small muted" style="line-height:1.55;margin-top:10px">Orders are signed by this wallet and sent to Polymarket’s CLOB${''} — Syn never custodies funds. Market buys fill at the walked book price (FOK); limit orders rest on the book (GTC).</p>
  </div></div>`}
  ${ud ? '<div id="polyHistBox"></div>' : ''}<div id="polyPosBox"></div><div id="polyOrdersBox"></div></main>`);
  ($('#bk') as HTMLElement).onclick = () => goBack({ route: 'invest' });
  // Live ticker card (Up or Down only): Chainlink beat/current/series
  // from the server relay, painted in place. Copy/embed copy the real
  // Polymarket event link; bookmark toggles its state, as in the
  // standalone component.
  let ltData: { beat: number | null; current: number | null; samples: [number, number][] } | null = null;
  const ltStart = Date.parse(m.endDate) - (ud ? ud.tfSecs * 1000 : 0);
  const ltEnd = Date.parse(m.endDate);
  const ltPaint = () => {
    if (!ud) return;
    const s = Math.max(0, Math.ceil((ltEnd - Date.now()) / 1000));
    const mn = $('#ltMins'); if (mn) mn.textContent = String(Math.floor(s / 60)).padStart(2, '0');
    const sc = $('#ltSecs'); if (sc) sc.textContent = String(s % 60).padStart(2, '0');
    const d = ltData;
    const beatEl = $('#ltBeat'); if (beatEl) beatEl.textContent = d && d.beat != null ? ltFmtSpot(d.beat) : '—';
    const curEl = $('#ltCur'); if (curEl) curEl.textContent = d && d.current != null ? ltFmtSpot(d.current) : '—';
    const hasDelta = !!(d && d.beat != null && d.current != null && d.beat > 0);
    const dv = hasDelta ? (d!.current as number) - (d!.beat as number) : 0;
    const dTxt = hasDelta ? (dv < 0 ? '− ' : '+ ') + '$' + Math.abs(dv).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 }) : '—';
    const dEl = $('#ltDelta'); if (dEl) dEl.textContent = dTxt;
    const dWrap = $('#ltDeltaWrap'); if (dWrap) dWrap.className = 'ltDelta' + (hasDelta ? (dv < 0 ? ' neg' : ' pos') : '');
    const chip = $('#ltDeltaChip'); if (chip) { chip.textContent = dTxt; chip.className = 'ltVal' + (hasDelta ? (dv < 0 ? ' neg' : ' pos') : ''); }
    const pct = $('#ltDeltaPct');
    if (pct) { const pv = hasDelta ? (dv / (d!.beat as number)) * 100 : 0; pct.textContent = hasDelta ? (pv < 0 ? '−' : '+') + Math.abs(pv).toFixed(Math.abs(pv) < 0.01 && pv !== 0 ? 3 : 2) + '%' : '—'; pct.className = 'ltVal' + (hasDelta ? (dv < 0 ? ' neg' : ' pos') : ''); }
    const times = $('#ltTimes');
    if (times && !times.childElementCount) {
      const f = (t: number) => new Date(t).toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit' });
      const tgt = '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="8.5"/><circle cx="12" cy="12" r="4.5"/><circle cx="12" cy="12" r="1" fill="currentColor"/></svg>';
      times.innerHTML = [0, 1, 2, 3, 4].map(i => `<span class="${i % 2 ? 'alt' : ''}">${i === 4 ? tgt + 'Target ' : ''}${f(ltStart + (ltEnd - ltStart) * i / 4)}</span>`).join('');
    }
    const svg = document.getElementById('ltSvg');
    if (svg && d && d.samples.length) {
      const vals = d.samples.map(p => p[1]);
      if (d.beat != null) vals.push(d.beat);
      if (d.current != null) vals.push(d.current);
      let lo = Math.min(...vals), hi = Math.max(...vals);
      const pad = (hi - lo) * 0.14 || hi * 0.001 || 1;
      lo -= pad; hi += pad;
      const X = (t: number) => ((t - ltStart) / (ltEnd - ltStart)) * 556;
      const Y = (v: number) => 24 + (1 - (v - lo) / (hi - lo)) * 212;
      let g = '';
      for (let i = 0; i < 5; i++) { const v = hi - (hi - lo) * i / 4; const y = 24 + 212 * i / 4; g += `<line x1="0" y1="${y.toFixed(1)}" x2="556" y2="${y.toFixed(1)}" stroke="rgba(148,163,184,.14)"/><text x="564" y="${(y + 4).toFixed(1)}" font-size="11" fill="#8b94a3">${ltFmtSpot(v)}</text>`; }
      if (d.beat != null) { const y = Y(d.beat); g += `<line x1="0" y1="${y.toFixed(1)}" x2="556" y2="${y.toFixed(1)}" stroke="#6d7cff" stroke-width="1" stroke-dasharray="4 4" opacity=".85"/>`; }
      g += `<polyline points="${d.samples.map(p => `${X(p[0]).toFixed(1)},${Y(p[1]).toFixed(1)}`).join(' ')}" fill="none" stroke="#6d7cff" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>`;
      const last = d.samples[d.samples.length - 1];
      g += `<g><circle class="ltPulse" cx="${X(last[0]).toFixed(1)}" cy="${Y(last[1]).toFixed(1)}" r="11" fill="rgba(109,124,255,.18)"/><circle cx="${X(last[0]).toFixed(1)}" cy="${Y(last[1]).toFixed(1)}" r="5" fill="#6d7cff" stroke="#fff" stroke-width="2"/></g>`;
      svg.innerHTML = g;
    }
  };
  const ltFetch = async () => {
    if (!ud) return;
    try {
      const r = await fetch(`/api/poly/chainlink?symbol=${encodeURIComponent(ud.asset)}&start=${Math.floor(ltStart / 1000)}&end=${Math.floor(ltEnd / 1000)}`, { cache: 'no-store' });
      if (r.ok) { ltData = await r.json(); ltPaint(); }
    } catch { /* keep the last paint */ }
  };
  if (ud) {
    const evUrl = 'https://polymarket.com/event/' + (m.slug || '');
    const cp = $('#ltCopy'); if (cp) cp.onclick = (e) => { void copyText(evUrl, e.currentTarget as HTMLElement); };
    const em = $('#ltEmbed'); if (em) em.onclick = (e) => { void copyText(`<iframe src="${evUrl}" width="400" height="200" frameborder="0"></iframe>`, e.currentTarget as HTMLElement); };
    const bm = $('#ltBookmark'); if (bm) {
      const paintBm = () => { const on = polyBookmarks().has(m.conditionId); bm.classList.toggle('on', on); bm.setAttribute('aria-pressed', String(on)); };
      paintBm();
      bm.onclick = () => { polyBmToggle(m.conditionId); paintBm(); };
    }
    ltPaint();
  }
  const tokenOf = (ix: number) => m.tokenIds[ix] || '';
  let selected = sel.outcomeIx;
  let qtMode: 'tap' | 'confirm' | 'limit' = 'tap';
  let bookTimer: ReturnType<typeof setTimeout> | null = null;
  let chartQueued = false;

  const curBook = (): Book | undefined => polyFeed.books.get(tokenOf(selected));
  const curPrice = (): number => {
    const q = polyFeed.quotes.get(tokenOf(selected));
    const bk = curBook();
    if (polyTrade.side === 'BUY') return bk?.asks[0]?.price ?? q?.bestAsk ?? m.prices[selected] ?? 0;
    return bk?.bids[0]?.price ?? q?.bestBid ?? m.prices[selected] ?? 0;
  };
  const paintBook = () => { const s = $('#polyBook'); if (s && currentRoute === 'polymarket') polyBookPaint(s, curBook(), tokenOf(selected)); const bo = $('#polyBookOutcome'); if (bo) bo.textContent = m.outcomes[selected] || ''; };
  // Preset tiles carry the live "win" for their amount at the
  // current book (the quick-trade-panel design) — recomputed wherever
  // paintEst runs: feed ticks, book seeds, side/mode/input changes.
  const paintPresets = () => {
    // Quick-trade tiles on the sell side quote share counts instead
    // of win amounts: the $ tile means "sell $X worth", converted at
    // the current bid (or the limit price) and capped at holdings.
    if (ud) {
      document.querySelectorAll('[data-qtline]').forEach(line => {
        const amt = parseFloat((line as HTMLElement).dataset.qtline || '0');
        if (polyTrade.side === 'SELL') {
          const bk2 = curBook(); const bid = bk2?.bids[0]?.price ?? 0;
          const held = polyMyPos && polyMyPos.asset === tokenOf(selected) ? polyMyPos.size : 0;
          const ref = polyTrade.mode === 'limit' ? (parseFloat(polyTrade.limitCents) || 0) / 100 : bid;
          const n = ref > 0 ? Math.min(held, amt / ref) : 0;
          (line as HTMLElement).textContent = held > 0 && n > 0 ? `≈ ${trimNum(n, 1)} shares` : '— shares';
        } else if (!line.querySelector('[data-win]')) {
          line.innerHTML = `win <b data-win="${amt}">—</b>`;
        }
      });
    }
    document.querySelectorAll('[data-win]').forEach(el => {
      const amt = parseFloat((el as HTMLElement).dataset.win || '0');
      let txt = '—';
      try {
        const bk = curBook();
        if (bk && amt > 0) {
          let price = 0;
          if (polyTrade.mode === 'market') { if (bk.asks.length) price = walkPrice(bk.asks.slice().sort((a, b) => b.price - a.price), 'BUY', amt, 'FOK'); }
          else price = (parseFloat(polyTrade.limitCents) || 0) / 100;
          if (price > 0 && price < 1) txt = fmtUsd(amt / price);
        }
      } catch { /* not enough liquidity for that size */ }
      (el as HTMLElement).textContent = txt;
    });
  };
  const paintEst = () => {
    paintPresets();
    const el = $('#polyEst'); if (!el) return;
    const bk = curBook();
    const err = (t: string) => { el.innerHTML = `<span class="muted">${t}</span>`; };
    try {
      if (polyTrade.side === 'BUY') {
        const amt = parseFloat(polyTrade.amount) || 0;
        if (amt <= 0) return err('Enter an amount.');
        let price: number;
        if (polyTrade.mode === 'market') { if (!bk?.asks.length) return err('No asks to fill against right now.'); price = walkPrice(bk.asks.slice().sort((a, b) => b.price - a.price), 'BUY', amt, 'FOK'); }
        else { price = (parseFloat(polyTrade.limitCents) || 0) / 100; if (price <= 0 || price >= 1) return err('Set a limit price between 1¢ and 99¢.'); }
        const shares = amt / price;
        el.innerHTML = `<span>Est. <b>${trimNum(shares, 2)} shares</b> @ ${polyCents(price)}</span><span>To win <b>${fmtUsd(shares)}</b> (+${fmtUsd(shares - amt)})</span>`;
      } else {
        const sh = parseFloat(polyTrade.shares) || 0;
        if (sh <= 0) return err('Enter shares to sell.');
        let price: number;
        if (polyTrade.mode === 'market') { if (!bk?.bids.length) return err('No bids to fill against right now.'); price = walkPrice(bk.bids.slice().sort((a, b) => a.price - b.price), 'SELL', sh, 'FOK'); }
        else { price = (parseFloat(polyTrade.limitCents) || 0) / 100; if (price <= 0 || price >= 1) return err('Set a limit price between 1¢ and 99¢.'); }
        el.innerHTML = `<span>Sell <b>${trimNum(sh, 2)} shares</b> @ ${polyCents(price)}</span><span>Receive <b>${fmtUsd(sh * price)}</b></span>`;
      }
    } catch { err('Not enough liquidity for that size.'); }
  };
  const paintPills = () => {
    document.querySelectorAll('[data-poly-pill]').forEach(el => {
      const tid = (el as HTMLElement).dataset.polyPill!; const q = polyFeed.quotes.get(tid); const bk = polyFeed.books.get(tid);
      const mid = q && q.bestBid > 0 && q.bestAsk > 0 ? (q.bestBid + q.bestAsk) / 2 : bk?.bids[0] && bk?.asks[0] ? (bk.bids[0].price + bk.asks[0].price) / 2 : q?.lastTrade;
      if (mid) el.textContent = polyCents(mid);
    });
    const q = polyFeed.quotes.get(tokenOf(selected)); const bk = curBook();
    const mid = q && q.bestBid > 0 && q.bestAsk > 0 ? (q.bestBid + q.bestAsk) / 2 : bk?.bids[0] && bk?.asks[0] ? (bk.bids[0].price + bk.asks[0].price) / 2 : q?.lastTrade || 0;
    const bp = $('#polyBigPrice'); if (bp && mid) bp.textContent = polyPctNum(mid);
    const lt = $('#polyLastTrade'); if (lt && q?.lastTrade) lt.textContent = 'last ' + polyCents(q.lastTrade);
    const sl = $('#qtSideLabel');
    if (sl) { sl.textContent = m.outcomes[selected] || ''; sl.classList.toggle('down', (m.outcomes[selected] || '') === 'Down'); }
    document.querySelectorAll('.qtOrb').forEach(x => x.classList.toggle('selected', Number((x as HTMLElement).dataset.out) === selected));
  };
  const queueChart = () => { if (chartQueued) return; chartQueued = true; requestAnimationFrame(() => { chartQueued = false; drawPolyChart(); }); };
  const appendPoint = () => {
    const q = polyFeed.quotes.get(tokenOf(selected));
    const mid = q && q.bestBid > 0 && q.bestAsk > 0 ? (q.bestBid + q.bestAsk) / 2 : q?.lastTrade || 0;
    if (!mid) return;
    const now = Date.now();
    const last = polySeries[polySeries.length - 1];
    if (last && now - last.t < 900 && Math.abs(last.p - mid) < 1e-9) return;
    polySeries.push({ t: now, p: mid });
    if (polySeries.length > 900) polySeries = polySeries.slice(-900);
    queueChart();
  };
  const onFeedEvent = (tid: string) => () => {
    if (currentRoute !== 'polymarket') return;
    paintPills();
    if (tid === tokenOf(selected)) {
      appendPoint();
      if (bookTimer) clearTimeout(bookTimer);
      bookTimer = setTimeout(() => { paintBook(); paintEst(); }, 250);
    }
  };
  const seedToken = async (ix: number) => {
    const tid = tokenOf(ix); if (!tid) return;
    try { const bk = await clobBook(tid); polyFeed.books.set(tid, bk); if (ix === selected) { paintBook(); paintEst(); } } catch { /* book stays as the feed leaves it */ }
    if (ix === selected) {
      try {
        const hist = await clobHistory(tid, '1d', 5);
        if (ix === selected && tokenOf(selected) === tid) {
          polySeries = hist; polySeriesToken = tid;
          const ce = $('#polyChartEmpty'); if (ce) ce.style.display = hist.length ? 'none' : 'block';
          if (!hist.length && ce) ce.innerHTML = '<p class="small muted secEmpty">No price history for this outcome yet — the live line starts with the stream.</p>';
          drawPolyChart();
        }
      } catch { const ce = $('#polyChartEmpty'); if (ce) ce.innerHTML = '<p class="small muted secEmpty">Price history unavailable — the live line starts with the stream.</p>'; }
    }
  };
  // Subscriptions: both outcome tokens for the panel's whole life on
  // this screen; renderRoute's polyDetailCleanup releases them (and
  // the feed socket closes when the last subscription goes).
  for (let ix = 0; ix < m.tokenIds.length; ix++) { const tid = tokenOf(ix); if (tid) polyDetailUnsubs.push(polyFeed.subscribe(tid, onFeedEvent(tid))); }
  polyDetailUnsubs.push(polyFeed.onStatus(s => { const el = $('#polyLiveState'); if (el) el.innerHTML = s === 'live' ? '<span class="liveDotSm"></span>Live' : s === 'connecting' ? '<span class="liveDotSm off"></span>Connecting' : '<span class="liveDotSm off"></span>Offline'; }));
  // Steady repaint: win lines, estimates and pill prices track the
  // latest book even when the stream is quiet between trades.
  const estIv = setInterval(() => { if (currentRoute === 'polymarket') { paintPills(); paintEst(); } }, 2000);
  polyDetailUnsubs.push(() => clearInterval(estIv));
  void seedToken(selected);
  if (tokenOf(1 - selected)) void clobBook(tokenOf(1 - selected)).then(bk => polyFeed.books.set(tokenOf(1 - selected), bk)).catch(() => { /* seeded by the stream */ });
  // Up or Down rollover: the window ends minutes after it opens, so
  // the detail counts down and, at the boundary, swaps itself to the
  // current window's market (same outcome side kept) instead of
  // leaving the user trading a dead book. The next window's event
  // exists on Gamma before the current one ends; if a fetch races
  // it, the tick retries.
  if (ud) {
    let rolling = false;
    let ltTicks = 0;
    void ltFetch();
    const iv = setInterval(async () => {
      if (currentRoute !== 'polymarket') { clearInterval(iv); return; }
      const left = Date.parse(m.endDate) - Date.now();
      ltTicks++;
      ltPaint();
      if (ltTicks % 2 === 0) void ltFetch();
      if (left <= 0 && !rolling) {
        rolling = true;
        try {
          const next = await gammaEventBySlug(upDownSlug(ud.asset, ud.tfSecs));
          const nm = next?.markets[0];
          if (next && nm && nm.conditionId !== m.conditionId) {
            polySel = { market: nm, eventTitle: next.title, outcomeIx: selected, updown: ud };
            clearInterval(iv);
            polyDetailCleanup();
            showPolyMarket();
            return;
          }
        } catch { /* retry on the next tick */ }
        rolling = false;
      }
    }, 1000);
    polyDetailUnsubs.push(() => clearInterval(iv));
  }
  // His positions in this market (public read), painted per selected
  // outcome. Audit fix: the match is EXACTLY the selected outcome's
  // token — the old fallback to any position in the condition let the
  // sell panel (and Max) use the opposite outcome's shares — and the
  // box is repainted on every outcome switch, not just first load.
  let myPosList: PolyPosition[] = [];
  const paintPolyPos = () => {
    polyMyPos = myPosList.find(p => p.conditionId === m.conditionId && p.asset === tokenOf(selected)) || null;
    const box = $('#polyPosBox'); if (!box || currentRoute !== 'polymarket') return;
    const mb = $('#polyMax') as HTMLElement | null;
    const sa = $('#qtSellAll') as HTMLElement | null;
    if (!polyMyPos) { box.innerHTML = ''; const hl0 = $('#polyHoldLine'); if (hl0) hl0.textContent = ''; if (mb) mb.style.display = 'none'; if (sa) sa.style.display = 'none'; return; }
    const p = polyMyPos;
    box.innerHTML = `<div class="gGroup"><div class="gHead">Your position</div><div class="gCard"><div class="sRow stat"><span class="sTx"><span class="sLbl">${esc(p.outcome)} · ${trimNum(p.size, 2)} shares</span><div class="sSub">Avg ${polyCents(p.avgPrice)} · now ${polyCents(p.curPrice)}</div></span><span class="sVal strong">${fmtUsd(p.currentValue)} <span class="${p.cashPnl >= 0 ? 'pos' : 'neg'}">(${p.cashPnl >= 0 ? '+' : '−'}${fmtUsd(Math.abs(p.cashPnl)).slice(1)})</span></span></div></div></div>`;
    const hl = $('#polyHoldLine'); if (hl) hl.textContent = `You hold ${trimNum(p.size, 2)} ${p.outcome} shares`;
    if (mb) mb.style.display = 'inline-block';
    if (sa) { sa.style.display = polyTrade.side === 'SELL' ? 'block' : 'none'; sa.textContent = `Sell all · ${trimNum(p.size, 2)} shares`; }
  };
  // Outcome switching reseeds chart + book for the newly selected token.
  document.querySelectorAll('[data-out]').forEach(b => (b as HTMLElement).onclick = () => {
    selected = Number((b as HTMLElement).dataset.out); sel.outcomeIx = selected;
    document.querySelectorAll('[data-out]').forEach(x => x.classList.toggle('on', Number((x as HTMLElement).dataset.out) === selected));
    polySeries = []; polySeriesToken = '';
    paintBook(); paintPills(); paintEst(); paintPolyPos();
    void seedToken(selected);
  });
  // Trade panel wiring.
  const syncPanel = () => {
    document.querySelectorAll('[data-tside]').forEach(x => { x.classList.toggle('on', (x as HTMLElement).dataset.tside === polyTrade.side); if (x.classList.contains('qtTab')) x.setAttribute('aria-selected', String((x as HTMLElement).dataset.tside === polyTrade.side)); });
    document.querySelectorAll('[data-tmode]').forEach(x => x.classList.toggle('on', (x as HTMLElement).dataset.tmode === polyTrade.mode));
    const lr = $('#polyLimitRow'); if (lr) lr.style.display = polyTrade.mode === 'limit' ? 'block' : 'none';
    const ba = $('#polyBuyAmt'); if (ba) ba.style.display = polyTrade.side === 'BUY' ? 'block' : 'none';
    const sa = $('#polySellAmt'); if (sa) sa.style.display = polyTrade.side === 'SELL' ? 'block' : 'none';
    const al = $('#qtActionLabel');
    if (al) al.textContent = qtMode === 'tap' ? `One-tap ${polyTrade.side.toLowerCase()}` : `${polyTrade.side === 'BUY' ? 'Buy' : 'Sell'} · ${qtMode === 'limit' ? 'Limit' : 'Confirm each'}`;
    const sa2 = $('#qtSellAll'); if (sa2) sa2.style.display = polyTrade.side === 'SELL' && polyMyPos && polyMyPos.asset === tokenOf(selected) ? 'block' : 'none';
    paintEst();
  };
  document.querySelectorAll('[data-tside]').forEach(b => (b as HTMLElement).onclick = () => { polyTrade.side = (b as HTMLElement).dataset.tside as 'BUY' | 'SELL'; syncPanel(); });
  document.querySelectorAll('[data-tmode]').forEach(b => (b as HTMLElement).onclick = () => { polyTrade.mode = (b as HTMLElement).dataset.tmode as 'market' | 'limit'; syncPanel(); });
  document.querySelectorAll('[data-preset]').forEach(b => (b as HTMLElement).onclick = () => { polyTrade.amount = (b as HTMLElement).dataset.preset!; const ai = $('#polyAmt') as unknown as HTMLInputElement | null; if (ai) ai.value = polyTrade.amount; paintEst(); });
  const amtIn = $('#polyAmt') as unknown as HTMLInputElement | null; if (amtIn) amtIn.addEventListener('input', e => { polyTrade.amount = (e.target as HTMLInputElement).value; paintEst(); });
  const shIn = $('#polyShares') as unknown as HTMLInputElement | null; if (shIn) shIn.addEventListener('input', e => { polyTrade.shares = (e.target as HTMLInputElement).value; paintEst(); });
  const lpIn = $('#polyLimitPx') as unknown as HTMLInputElement | null; if (lpIn) lpIn.addEventListener('input', e => { polyTrade.limitCents = (e.target as HTMLInputElement).value; paintEst(); });
  const maxBtn = $('#polyMax') as HTMLElement | null;
  if (maxBtn) maxBtn.onclick = () => { if (polyMyPos) { polyTrade.shares = String(Math.floor(polyMyPos.size * 100) / 100); const si = $('#polyShares') as unknown as HTMLInputElement | null; if (si) si.value = polyTrade.shares; paintEst(); } };
  // Quick trade panel wiring (Up or Down only): the select menu
  // picks the execution mode; preset taps act on it — 1-Tap places
  // through the same order path as the review sheet's confirm,
  // Confirm each / Limit open the review sheet.
  let qtStatusTimer: ReturnType<typeof setTimeout> | undefined;
  const qtStatus = (html: string, sticky = false) => {
    const st = $('#qtStatus'); if (!st) return;
    st.innerHTML = html; st.classList.add('show');
    if (qtStatusTimer) clearTimeout(qtStatusTimer);
    if (!sticky) qtStatusTimer = setTimeout(() => st.classList.remove('show'), 3600);
  };
  if (ud) {
    const selBox = $('#qtSelect'); const trig = $('#qtTrigger');
    const closeQtMenu = () => { if (selBox) selBox.classList.remove('open'); if (trig) trig.setAttribute('aria-expanded', 'false'); };
    if (trig && selBox) trig.onclick = (e) => { e.stopPropagation(); const open = selBox.classList.toggle('open'); trig.setAttribute('aria-expanded', String(open)); };
    document.querySelectorAll('[data-qtmode]').forEach(b => (b as HTMLElement).onclick = () => {
      const md = (b as HTMLElement).dataset.qtmode!;
      qtMode = md === 'Limit' ? 'limit' : md === 'Confirm each' ? 'confirm' : 'tap';
      polyTrade.mode = qtMode === 'limit' ? 'limit' : 'market';
      const mv = $('#qtModeValue'); if (mv) mv.textContent = md;
      document.querySelectorAll('[data-qtmode]').forEach(x => x.setAttribute('aria-selected', String(x === b)));
      closeQtMenu(); syncPanel();
    });
    const onDocDown = (e: Event) => { if (selBox && !selBox.contains(e.target as Node)) closeQtMenu(); };
    const onDocKey = (e: KeyboardEvent) => { if (e.key === 'Escape') closeQtMenu(); };
    document.addEventListener('mousedown', onDocDown);
    document.addEventListener('keydown', onDocKey);
    polyDetailUnsubs.push(() => { document.removeEventListener('mousedown', onDocDown); document.removeEventListener('keydown', onDocKey); });
    document.querySelectorAll('[data-qtpreset]').forEach(b => (b as HTMLElement).onclick = () => {
      const amt = parseFloat((b as HTMLElement).dataset.qtpreset || '0');
      document.querySelectorAll('[data-qtpreset]').forEach(x => x.setAttribute('aria-pressed', 'false'));
      b.setAttribute('aria-pressed', 'true');
      if (polyTrade.side === 'BUY') { polyTrade.amount = String(amt); }
      else {
        const bk = curBook();
        const ref = polyTrade.mode === 'limit' ? (parseFloat(polyTrade.limitCents) || 0) / 100 : (bk?.bids[0]?.price ?? 0);
        const held = polyMyPos && polyMyPos.asset === tokenOf(selected) ? polyMyPos.size : 0;
        if (held <= 0) { qtStatus(`You don't hold any ${esc(m.outcomes[selected] || '')} shares to sell.`); return; }
        if (ref <= 0) { qtStatus(polyTrade.mode === 'limit' ? 'Set a limit price first.' : 'No bids to sell into right now.'); return; }
        const sh = Math.min(held, amt / ref);
        polyTrade.shares = String(Math.floor(sh * 100) / 100);
        if (sh < amt / ref - 1e-9) qtStatus(`Capped at your ${trimNum(held, 2)} shares — selling ${trimNum(sh, 2)}.`);
      }
      paintEst();
      if (qtMode === 'tap') { qtStatus('Posting…', true); void polyReviewOrder(m, () => selected, curBook, paintGate, { direct: true, onStatus: (t) => qtStatus(t) }); }
      else if (qtMode === 'limit' && !((parseFloat(polyTrade.limitCents) || 0) > 0)) { qtStatus('Set a limit price first, then tap a preset to review.'); const lp = $('#polyLimitPx'); if (lp) lp.focus(); }
      else { void polyReviewOrder(m, () => selected, curBook, paintGate); }
    });
    const saBtn = $('#qtSellAll') as HTMLElement | null;
    if (saBtn) saBtn.onclick = () => {
      const held = polyMyPos && polyMyPos.asset === tokenOf(selected) ? polyMyPos.size : 0;
      if (held <= 0) { qtStatus(`You don't hold any ${esc(m.outcomes[selected] || '')} shares to sell.`); return; }
      polyTrade.shares = String(Math.floor(held * 100) / 100);
      paintEst();
      if (qtMode === 'tap') { qtStatus('Posting…', true); void polyReviewOrder(m, () => selected, curBook, paintGate, { direct: true, onStatus: (t) => qtStatus(t) }); }
      else if (qtMode === 'limit' && !((parseFloat(polyTrade.limitCents) || 0) > 0)) { qtStatus('Set a limit price first, then tap Sell all to review.'); const lp = $('#polyLimitPx'); if (lp) lp.focus(); }
      else { void polyReviewOrder(m, () => selected, curBook, paintGate); }
    };
  }
  // His positions in this market (public read) — painted per outcome
  // by paintPolyPos (defined above, also runs on outcome switches).
  const addr = evmAddressOf();
  if (addr) void polyPositions(addr).then(ps => { myPosList = ps; paintPolyPos(); }).catch(() => { /* read-only — absence is fine */ });
  // Recent windows: the last five windows for this asset + timeframe,
  // with how each resolved (Gamma's closed markets settle at 1/0).
  if (ud) {
    void (async () => {
      const box = $('#polyHistBox'); if (!box) return;
      const endMs = Date.parse(m.endDate); const startMs = endMs - ud.tfSecs * 1000;
      const hm = (t: number) => new Intl.DateTimeFormat('en-US', { timeZone: 'America/New_York', hour: 'numeric', minute: '2-digit', hour12: true }).format(new Date(t));
      const dy = (t: number) => new Intl.DateTimeFormat('en-US', { timeZone: 'America/New_York', month: 'short', day: 'numeric' }).format(new Date(t));
      const evs = await Promise.all([1, 2, 3, 4, 5].map(k => gammaEventBySlug(upDownSlug(ud.asset, ud.tfSecs, startMs - k * ud.tfSecs * 1000)).catch(() => null)));
      // Each window's real Chainlink move (beat → final tick in the
      // window) from the server's stream buffer; absent when the
      // buffer doesn't reach that far back — the row then carries
      // the result only.
      const cls = await Promise.all([1, 2, 3, 4, 5].map(async k => {
        const wStart = startMs - k * ud.tfSecs * 1000; const wEnd = wStart + ud.tfSecs * 1000;
        try {
          const r = await fetch(`/api/poly/chainlink?symbol=${encodeURIComponent(ud.asset)}&start=${Math.floor(wStart / 1000)}&end=${Math.floor(wEnd / 1000)}`, { cache: 'no-store' });
          const j = await r.json();
          const samples = Array.isArray(j?.samples) ? j.samples : [];
          return { beat: j?.beat != null ? Number(j.beat) : null, fin: samples.length ? Number(samples[samples.length - 1][1]) : null };
        } catch { return { beat: null, fin: null }; }
      }));
      if (!document.body.contains(box) || currentRoute !== 'polymarket') return;
      let upWins = 0, downWins = 0;
      const rows = evs.map((ev, i) => {
        const wStart = startMs - (i + 1) * ud.tfSecs * 1000; const wEnd = wStart + ud.tfSecs * 1000;
        const pm = ev?.markets[0];
        const cl = cls[i];
        let pill: string;
        if (!pm) pill = '<span class="histPill wait">—</span>';
        else if (pm.closed) {
          const winIx = pm.prices[0] >= pm.prices[1] ? 0 : 1;
          const wname = pm.outcomes[winIx] || '';
          if (wname === 'Down') downWins++; else upWins++;
          pill = `<span class="histPill ${wname === 'Down' ? 'down' : 'up'}">${esc(wname)} won</span>`;
        } else pill = '<span class="histPill wait">Settling…</span>';
        let move = '';
        let sub = dy(wStart);
        if (cl.beat != null && cl.fin != null && cl.beat > 0) {
          const pct = (cl.fin - cl.beat) / cl.beat * 100;
          move = `<span class="histMove ${pct >= 0 ? 'pos' : 'neg'}">${pct >= 0 ? '+' : '−'}${Math.abs(pct).toFixed(2)}%</span>`;
          sub += ` · ${ltFmtSpot(cl.beat)} → ${ltFmtSpot(cl.fin)}`;
        }
        return `<div class="sRow stat"><span class="sTx"><span class="sLbl">${hm(wStart)} – ${hm(wEnd)} ET</span><div class="sSub">${sub}</div></span><span class="histRight">${move}${pill}</span></div>`;
      }).join('');
      const sum = upWins + downWins > 0 ? ` · Up ${upWins} / Down ${downWins}` : '';
      box.innerHTML = `<div class="gGroup"><div class="gHead">Recent windows${sum}</div><div class="gCard">${rows}</div></div>`;
    })();
  }
  // Open orders on this market (L2 read; needs session credentials).
  // Audit fix: resting limit orders were invisible and uncancellable
  // anywhere in the app after the "Order posted" sheet closed.
  const paintPolyOrders = async () => {
    const box = $('#polyOrdersBox'); if (!box || currentRoute !== 'polymarket') return;
    if (!polyCreds) { box.innerHTML = ''; return; }
    const addr3 = evmAddressOf(); if (!addr3) { box.innerHTML = ''; return; }
    let orders: PolyOpenOrder[];
    try { orders = await getOpenOrders(polyCreds, addr3, m.conditionId); } catch { return; /* a failed read leaves the last paint */ }
    if (!document.body.contains(box) || currentRoute !== 'polymarket') return;
    if (!orders.length) { box.innerHTML = ''; return; }
    box.innerHTML = `<div class="gGroup"><div class="gHead">Open orders</div><div class="gCard">${orders.map((o, ix) => { const left = Math.max(0, o.originalSize - o.sizeMatched); return `<div class="sRow stat"><span class="sTx"><span class="sLbl">${esc(o.side)} ${esc(o.outcome)} · ${trimNum(left, 2)} left</span><div class="sSub">@ ${polyCents(o.price)} · ${trimNum(o.originalSize, 2)} shares${o.sizeMatched > 0 ? ` · ${trimNum(o.sizeMatched, 2)} filled` : ''}</div></span><button class="hlMiniBtn" data-polycancel="${ix}">Cancel</button></div>`; }).join('')}</div><div class="gFoot">Resting orders on Polymarket’s CLOB for this market. Cancelling releases the committed funds or shares.</div></div>`;
    box.querySelectorAll('[data-polycancel]').forEach(b => (b as HTMLElement).onclick = async () => {
      const o = orders[Number((b as HTMLElement).dataset.polycancel)]; if (!o || !polyCreds) return;
      const btn = b as HTMLButtonElement; btn.disabled = true; btn.textContent = '…';
      try {
        const ok = await cancelPolyOrder(polyCreds, evmAddressOf(), o.id);
        if (!ok) throw new Error('the CLOB did not confirm the cancel');
        void paintPolyOrders();
      } catch (e) {
        btn.disabled = false; btn.textContent = 'Cancel';
        const er = $('#polyTradeErr'); if (er) { er.style.display = 'block'; er.textContent = 'Cancel failed: ' + (e instanceof Error ? e.message : String(e)); }
      }
    });
  };
  // Gate + review.
  const paintGate = async (force = false) => {
    const box = $('#polyGateBox'); if (!box || currentRoute !== 'polymarket') return;
    void paintPolyOrders();
    const gate = await evalPolyGate(m, force);
    if (!document.body.contains(box)) return;
    const review = $('#polyReview') as unknown as HTMLButtonElement | null;
    if (gate.state === 'ready') { box.innerHTML = `<div class="polyGateOk"><i class="ri-shield-check-line"></i><span>${esc(gate.msg)}</span></div>`; if (review) review.disabled = false; return; }
    if (review) review.disabled = true;
    // Gate notice card: presentation lives here, in plain language —
    // evalPolyGate's state/data are untouched, only how they read.
    // (gate.msg still feeds the review-order error line verbatim.)
    const v = ((): { icon: string; headline: string; copy: string; foot?: string; cta?: { id: string; label: string } } => {
      const attr = featureCfg.polymarketBuilderCode ? 'Orders carry Syn’s builder code, so trades are attributed to Syn.' : 'Builder attribution is off on this deployment.';
      switch (gate.state) {
        case 'needs-connect': return { icon: 'ri-key-2-line', headline: 'Connect trading', copy: 'Sign once per session to trade. Your keys stay on this device — nothing is stored.', foot: attr, cta: { id: 'polyConnect', label: 'Connect trading' } };
        case 'needs-wrap': return { icon: 'ri-exchange-line', headline: 'Convert to pUSD', copy: `You hold ${fmtUsd(gate.usdcE ?? 0)} of USDC.e, but trading settles in pUSD. The two swap 1:1.`, foot: 'Deposit at polymarket.com and it converts for you, or use the Collateral Onramp on Polygon.' };
        case 'no-collateral': return { icon: 'ri-wallet-3-line', headline: 'Add pUSD to trade', copy: `Trading settles in pUSD on Polygon, and this wallet has none yet.${gate.usdcNative && gate.usdcNative > 0 ? ` Your ${fmtUsd(gate.usdcNative)} of regular USDC isn’t the trading token.` : ''}`, foot: `Fund ${shortAddr(evmAddressOf())} with pUSD, or deposit at polymarket.com — deposits become pUSD automatically.` };
        case 'needs-approval': return { icon: 'ri-shield-line', headline: 'Approve pUSD', copy: `One approval lets the Polymarket${m.negRisk ? ' Neg-Risk' : ''} exchange spend your pUSD when you place orders. The approval amount is unlimited — the standard setup for this exchange, so you approve once instead of per order. You can revoke it any time from the token's Approvals screen. Gas is paid in POL.`, foot: featureCfg.polymarketBuilderConfigured ? 'You can also approve gas-free via the builder relayer.' : 'A gas-free relayer option unlocks once builder keys are added to the server.', cta: { id: 'polyApprove', label: 'Approve pUSD' } };
        default: return { icon: 'ri-information-line', headline: 'Trading unavailable', copy: gate.msg };
      }
    })();
    box.innerHTML = `<div class="polyGateCard"><div class="polyGateHead"><span class="polyGateMed"><i class="${v.icon}"></i></span><span class="polyGateTitle">${esc(v.headline)}</span></div><p class="polyGateCopy">${esc(v.copy)}</p>${v.foot ? `<p class="polyGateFoot">${esc(v.foot)}</p>` : ''}${v.cta ? `<button class="polyGateCta" id="${v.cta.id}">${esc(v.cta.label)}</button>` : ''}</div>`;
    const conn = $('#polyConnect'); if (conn) conn.onclick = async () => {
      btnBusy(conn as HTMLButtonElement, 'Signing…');
      try { const pk = evmPrivKey(); if (!pk) throw new Error('no EVM key'); polyCreds = await deriveClobCreds(new ethers.Wallet(pk)); polyGateCache = null; void paintGate(true); }
      catch (e) { const er = $('#polyTradeErr'); if (er) { er.style.display = 'block'; er.textContent = 'Could not derive Polymarket credentials: ' + (e instanceof Error ? e.message : String(e)); } (conn as HTMLButtonElement).disabled = false; conn.textContent = 'Connect trading'; }
    };
    const appr = $('#polyApprove'); if (appr) appr.onclick = async () => {
      btnBusy(appr as HTMLButtonElement, 'Approving…');
      try {
        const pk = evmPrivKey(); const c = findChain('polygon'); if (!pk || !c) throw new Error('wallet unavailable');
        const provider = new ethers.JsonRpcProvider(evmProviderUrl(c), c.evmId);
        const contract = new ethers.Contract(PUSD, ['function approve(address spender, uint256 value) returns (bool)'], new ethers.Wallet(pk, provider));
        const tx = await contract.approve(m.negRisk ? NEG_RISK_EXCHANGE_V2 : CTF_EXCHANGE_V2, ethers.MaxUint256);
        await tx.wait();
        polyGateCache = null; void paintGate(true);
      } catch (e) { const er = $('#polyTradeErr'); if (er) { er.style.display = 'block'; er.textContent = 'Approval failed: ' + (e instanceof Error ? e.message : String(e)); } (appr as HTMLButtonElement).disabled = false; appr.textContent = 'Approve pUSD'; }
    };
  };
  void paintGate();
  const reviewBtn = $('#polyReview') as unknown as HTMLButtonElement | null;
  if (reviewBtn) reviewBtn.onclick = () => void polyReviewOrder(m, () => selected, curBook, paintGate);
  syncPanel();
}

async function polyReviewOrder(m: PolyMarket, getSelected: () => number, curBook: () => Book | undefined, paintGate: (f?: boolean) => Promise<void>, opts?: { direct?: boolean; onStatus?: (html: string) => void }) {
  const selected = getSelected();
  const tid = m.tokenIds[selected]; if (!tid) return;
  const errBox = $('#polyTradeErr');
  const fail = (t: string) => { if (errBox) { errBox.style.display = 'block'; errBox.textContent = t; } if (opts?.direct) opts.onStatus?.(esc(t)); };
  if (errBox) errBox.style.display = 'none';
  const gate = await evalPolyGate(m);
  if (gate.state !== 'ready' || !polyCreds) { fail('Trading is not ready: ' + gate.msg); return; }
  const bk = curBook();
  const cfg = roundConfigFor(m.tickSize);
  let price = 0; let rawMaker = 0; let rawTaker = 0; let orderType: 'GTC' | 'FOK' = 'GTC';
  try {
    if (polyTrade.mode === 'market') {
      orderType = 'FOK';
      if (polyTrade.side === 'BUY') { const amt = parseFloat(polyTrade.amount) || 0; if (!bk?.asks.length) return fail('No asks to fill against right now.'); price = walkPrice(bk.asks.slice().sort((a, b) => b.price - a.price), 'BUY', amt, 'FOK'); ({ rawMakerAmt: rawMaker, rawTakerAmt: rawTaker } = marketRawAmounts('BUY', amt, price, cfg)); }
      else { const sh = parseFloat(polyTrade.shares) || 0; if (!bk?.bids.length) return fail('No bids to fill against right now.'); price = walkPrice(bk.bids.slice().sort((a, b) => a.price - b.price), 'SELL', sh, 'FOK'); ({ rawMakerAmt: rawMaker, rawTakerAmt: rawTaker } = marketRawAmounts('SELL', sh, price, cfg)); }
    } else {
      price = (parseFloat(polyTrade.limitCents) || 0) / 100;
      if (price <= 0 || price >= 1) return fail('Set a limit price between 1¢ and 99¢.');
      if (polyTrade.side === 'BUY') { const amt = parseFloat(polyTrade.amount) || 0; ({ rawMakerAmt: rawMaker, rawTakerAmt: rawTaker } = limitRawAmounts('BUY', amt / price, price, cfg)); }
      else { const sh = parseFloat(polyTrade.shares) || 0; ({ rawMakerAmt: rawMaker, rawTakerAmt: rawTaker } = limitRawAmounts('SELL', sh, price, cfg)); }
    }
  } catch { return fail('Not enough liquidity for that size.'); }
  const shares = polyTrade.side === 'BUY' ? rawTaker : rawMaker;
  const total = polyTrade.side === 'BUY' ? rawMaker : rawTaker;
  if (!(shares > 0) || !(total > 0)) return fail('Enter an amount first.');
  if (shares < m.minSize) return fail(`Below Polymarket’s minimum order size for this market (${m.minSize} shares).`);
  const outcome = m.outcomes[selected] || '';
  // Audit fix: validate affordability/holdings BEFORE anything is
  // signed — previously a too-big buy or an unheld sell only failed
  // after posting to the CLOB.
  if (polyTrade.side === 'BUY' && gate.pusd != null && total > gate.pusd) return fail(`This order costs ${fmtUsd(total)} but you hold ${fmtUsd(gate.pusd)} pUSD. Lower the amount or add pUSD first.`);
  if (polyTrade.side === 'SELL') {
    const addr2 = evmAddressOf();
    if (addr2) {
      try {
        const ps = await polyPositions(addr2);
        const mine = ps.find(p => p.asset === tid);
        if (!mine) return fail(`You don't hold any ${outcome} shares to sell.`);
        if (shares > mine.size + 1e-9) return fail(`You hold ${trimNum(mine.size, 2)} ${outcome} shares — you can't sell ${trimNum(shares, 2)}.`);
      } catch { /* the read failed — the CLOB still enforces holdings; don't block on it */ }
    }
  }
  // One sign+post implementation for both the review sheet's
  // confirm and the quick-trade panel's 1-Tap mode (direct): the
  // order is built, validated and affordability-checked above;
  // this is the only place it is signed and sent.
  const doPost = async (reportErr: (t: string) => void): Promise<Awaited<ReturnType<typeof postOrder>> | null> => {
    try {
      const pk = evmPrivKey(); if (!pk || !polyCreds) throw new Error('wallet locked');
      const wallet = new ethers.Wallet(pk);
      const signed = await buildSignedOrder(wallet, { tokenId: tid, side: polyTrade.side, rawMakerAmt: rawMaker, rawTakerAmt: rawTaker, negRisk: m.negRisk, builderCode: featureCfg.polymarketBuilderCode || undefined });
      if (!verifyOrderSignature(signed, m.negRisk)) throw new Error('local signature check failed — order not sent');
      const res = await postOrder(wallet, polyCreds, signed, orderType);
      if (!res.ok) { reportErr(res.error || 'The CLOB rejected the order.'); return null; }
      polyGateCache = null; void paintGate(true);
      return res;
    } catch (e) { reportErr('Could not post the order: ' + (e instanceof Error ? e.message : String(e))); return null; }
  };
  if (opts?.direct) {
    const res = await doPost(t => opts.onStatus?.(esc(t)));
    if (res) opts.onStatus?.(`<b>${polyTrade.side} ${esc(outcome)}</b> — ${trimNum(shares, 2)} shares @ ${polyCents(price)} · ${esc(res.status || 'accepted')}`);
    return;
  }
  const close = openSheet('Review order', `<div class="detCard" style="margin:0">
    <div class="detRow"><span class="detLbl">Market</span><span class="detVal" style="text-align:right;max-width:62%">${esc(m.question)}</span></div>
    <div class="detRow"><span class="detLbl">Outcome</span><span class="detVal">${esc(outcome)}</span></div>
    <div class="detRow"><span class="detLbl">Side</span><span class="detVal">${polyTrade.side} · ${polyTrade.mode === 'market' ? 'Market (FOK)' : 'Limit (GTC)'}</span></div>
    <div class="detRow"><span class="detLbl">Price</span><span class="detVal">${polyCents(price)} per share</span></div>
    <div class="detRow"><span class="detLbl">Shares</span><span class="detVal">${trimNum(shares, 2)}</span></div>
    <div class="detRow"><span class="detLbl">${polyTrade.side === 'BUY' ? 'You pay' : 'You receive (est.)'}</span><span class="detVal">${fmtUsd(total)} pUSD</span></div>
    ${polyTrade.side === 'BUY' ? `<div class="detRow"><span class="detLbl">Payout if right</span><span class="detVal">${fmtUsd(shares)}</span></div>` : ''}
    <div class="detRow"><span class="detLbl">Exchange</span><span class="detVal">${m.negRisk ? 'Polymarket Neg-Risk Exchange V2' : 'Polymarket CTF Exchange V2'} · Polygon</span></div>
    <div class="detRow"><span class="detLbl">Builder</span><span class="detVal">${featureCfg.polymarketBuilderCode ? `Syn Wallet — code ${featureCfg.polymarketBuilderCode.slice(0, 10)}… in the signed order` : 'None (no builder code configured)'}</span></div>
  </div>
  <p class="small muted" style="line-height:1.55;margin:12px 0">The order is EIP-712 signed by your wallet on this device and posted to Polymarket’s CLOB with your own API credentials. Review every field — a matched order settles on-chain and cannot be undone by Syn.</p>
  <div class="err" id="polyPostErr" style="display:none"></div>
  <button class="ctaWide" id="polyConfirm">Confirm ${polyTrade.side.toLowerCase()}</button>
  <div style="height:8px"></div><button class="btnGhost" id="polyCancel" style="border-radius:999px">Cancel</button>`);
  ($('#polyCancel') as HTMLElement).onclick = () => close();
  ($('#polyConfirm') as HTMLElement).onclick = async () => {
    const btn = $('#polyConfirm') as unknown as HTMLButtonElement; btnBusy(btn, 'Posting…');
    const res = await doPost(t => { const pe = $('#polyPostErr'); if (pe) { pe.style.display = 'block'; pe.textContent = t; } });
    if (!res) { btn.disabled = false; btn.textContent = 'Confirm ' + polyTrade.side.toLowerCase(); return; }
    close();
    const done = openSheet('Order posted', `<div class="detCard" style="margin:0">
      <div class="detRow"><span class="detLbl">Status</span><span class="detVal">${esc(res.status || 'accepted')}</span></div>
      <div class="detRow"><span class="detLbl">Order ID</span><span class="detVal" style="max-width:62%;overflow:hidden;text-overflow:ellipsis">${esc(res.orderId || '—')}</span></div>
      <div class="detRow"><span class="detLbl">Order</span><span class="detVal">${polyTrade.side} ${trimNum(shares, 2)} ${esc(outcome)} @ ${polyCents(price)}</span></div>
    </div><div style="height:12px"></div><button class="ctaWide" id="polyDone">Done</button>`);
    ($('#polyDone') as HTMLElement).onclick = () => done();
  };
}

// ================= Hyperliquid trading (in-wallet) =================
// Trading lives entirely inside Syn Wallet. The user's Hyperliquid
// account is their wallet's own EVM address. A dedicated agent
// (API) wallet is generated in the browser, stored ONLY inside the
// encrypted vault (WalletEntry.hlAgent), and approved once by the
// master key via Hyperliquid's approveAgent action. The agent key
// signs orders/cancels/leverage on-device; it can trade but can
// never withdraw. The server only relays signed payloads.
interface HlPosFull { coin: string; dex: string; szi: number; entryPx: number; positionValue: number; unrealizedPnl: number; liquidationPx: number | null; leverage: number; marginUsed: number; }
interface HlOrderFull { coin: string; dex: string; oid: number; side: string; limitPx: number; sz: number; origSz: number; reduceOnly: boolean; isTrigger: boolean; triggerPx: number; }
function hlOrderFullFromApi(o: any, dexId: string): HlOrderFull {
  return { coin: String(o.coin || ''), dex: dexId, oid: Number(o.oid || 0), side: String(o.side || ''), limitPx: parseFloat(o.limitPx || '0'), sz: parseFloat(o.sz || '0'), origSz: parseFloat(o.origSz || o.sz || '0'), reduceOnly: !!o.reduceOnly, isTrigger: !!o.isTrigger, triggerPx: parseFloat(o.triggerPx || '0') };
}
function hlMasterAddr(): string { const c = findChain('ethereum'); return c ? addressFor(c) : ''; }
function hlAgentApprovedFor(addr: string): boolean {
  const rec = activeWallet()?.hlAgent;
  return !!rec && rec.approved.includes(addr.toLowerCase());
}
// Ensure an agent key exists (generating + persisting it inside the
// encrypted vault on first use) and is approved for the master
// address. Returns the agent private key. Throws with the exchange's
// own message when approval is rejected (e.g. account not funded —
// Hyperliquid only registers accounts that have deposited).
let hlAgentEnsuring: Promise<string> | null = null;
function hlEnsureAgentKey(): Promise<string> {
  if (hlAgentEnsuring) return hlAgentEnsuring;
  hlAgentEnsuring = (async () => {
    const w = activeWallet(); if (!w) throw new Error('Wallet is locked.');
    const master = hlMasterAddr(); if (!master) throw new Error('No EVM account in this wallet.');
    if (!w.hlAgent) {
      const fresh = ethers.Wallet.createRandom();
      w.hlAgent = { key: fresh.privateKey, approved: [] };
      await persistPayload();
    }
    const rec = w.hlAgent;
    const agentAddr = new ethers.Wallet(rec.key).address;
    if (!rec.approved.includes(master.toLowerCase())) {
      const pk = evmPrivKey(); if (!pk) throw new Error('This wallet has no EVM key to approve trading with.');
      await hlApproveAgent(pk, agentAddr, 'Syn Wallet');
      rec.approved.push(master.toLowerCase());
      await persistPayload();
    }
    return rec.key;
  })();
  void hlAgentEnsuring.catch(() => { }).finally(() => { hlAgentEnsuring = null; });
  return hlAgentEnsuring;
}
function hlResolveAsset(coin: string, dexId: string): { dex: HlDex; asset: HlAsset; assetId: number } | null {
  const dex = hlData?.dexes.find(d => d.id === dexId); if (!dex) return null;
  const asset = dex.assets.find(x => x.name === coin); if (!asset) return null;
  return { dex, asset, assetId: hlAssetId(dex.ord ?? 0, asset.idx ?? 0) };
}
// Market price for order construction: prefer the freshest snapshot
// in hlData, falling back to the figure the caller already shows.
function hlMarkOf(coin: string, dexId: string, fallback: number): number {
  return hlResolveAsset(coin, dexId)?.asset.markPx || fallback;
}
async function hlClosePositionFlow(coin: string, dexId: string, btn?: HTMLElement) {
  if (btn) btn.textContent = '…';
  try {
    await loadHlMarkets();
    const r = hlResolveAsset(coin, dexId); if (!r) throw new Error('Market not found in the latest snapshot.');
    const user = hlMasterAddr();
    const st = await hlInfo(dexId ? { type: 'clearinghouseState', user, dex: dexId } : { type: 'clearinghouseState', user });
    const pos = (st?.assetPositions || []).map((p: any) => p.position).find((p: any) => p.coin === coin && parseFloat(p.szi || '0') !== 0);
    if (!pos) throw new Error('No open position on this market.');
    const szi = parseFloat(pos.szi); const mark = hlMarkOf(coin, dexId, Math.abs(szi) > 0 ? parseFloat(pos.positionValue || '0') / Math.abs(szi) : 0);
    const close = openSheet('Close position', `<div class="detCard" style="margin:0">
      <div class="detRow"><span class="detLbl">Market</span><span class="detVal">${esc(hlBaseName(coin))}${dexId ? ' · ' + esc(dexId) : ''}</span></div>
      <div class="detRow"><span class="detLbl">Position</span><span class="detVal">${szi > 0 ? 'Long' : 'Short'} ${trimNum(Math.abs(szi), 4)} @ entry ${fmtUsd(parseFloat(pos.entryPx || '0'))}</span></div>
      <div class="detRow"><span class="detLbl">Close at</span><span class="detVal">Market (reduce-only)</span></div>
      <div class="detRow"><span class="detLbl">Unrealised P&amp;L</span><span class="detVal">${fmtUsd(parseFloat(pos.unrealizedPnl || '0'))}</span></div>
    </div><div class="err" id="hlCloseErr" style="display:none"></div><div class="small muted" id="hlCloseStatus" style="margin-top:10px"></div><div style="height:12px"></div><button class="ctaWide" id="hlCloseGo">Close position</button>`);
    ($('#hlCloseGo') as HTMLElement).onclick = async () => {
      const goBtn = $('#hlCloseGo') as HTMLButtonElement; const st2 = $('#hlCloseStatus'); const er = $('#hlCloseErr');
      goBtn.disabled = true;
      try {
        if (st2) st2.textContent = 'Preparing your trading key…';
        const agentKey = await hlEnsureAgentKey();
        if (st2) st2.textContent = 'Signing and sending the close…';
        const px = hlRoundPrice(mark * (szi > 0 ? 0.95 : 1.05), r.asset.szDecimals);
        const wire = hlOrderWire({ asset: r.assetId, isBuy: szi < 0, px, sz: hlRoundSize(Math.abs(szi), r.asset.szDecimals, 'round'), reduceOnly: true, tif: 'Ioc' });
        const res = await hlPostL1(agentKey, hlOrderAction([wire]));
        const lines = hlOrderStatusLines(res);
        if (st2) st2.innerHTML = lines.map(esc).join('<br>');
        // Audit fix: a per-order rejection must not end in a "Done"
        // button — the dismiss action is labelled honestly.
        const hasErr = (res?.response?.data?.statuses || []).some((s: any) => !!s?.error);
        goBtn.textContent = hasErr ? 'Close' : 'Done'; goBtn.disabled = false;
        goBtn.onclick = () => { close(); hlAcctAt = 0; if (currentRoute === 'hlmarket') void hlRefreshTradeZone(); };
        hlAcctAt = 0;
      } catch (e) {
        if (er) { er.style.display = 'block'; er.textContent = e instanceof Error ? e.message : String(e); }
        goBtn.disabled = false;
      }
    };
  } catch (e) {
    if (btn) btn.textContent = 'Close';
    const er2 = openSheet('Close position', `<p class="small" style="line-height:1.55">${esc(e instanceof Error ? e.message : String(e))}</p><div style="height:12px"></div><button class="ctaWide" id="hlCloseOk">OK</button>`);
    ($('#hlCloseOk') as HTMLElement).onclick = () => er2();
  }
}
async function hlCancelOrderFlow(o: HlOrderFull, btn?: HTMLElement) {
  if (btn) btn.textContent = '…';
  try {
    await loadHlMarkets();
    const r = hlResolveAsset(o.coin, o.dex); if (!r) throw new Error('Market not found in the latest snapshot.');
    const agentKey = await hlEnsureAgentKey();
    await hlPostL1(agentKey, hlCancelAction([{ a: r.assetId, o: o.oid }]));
    hlAcctAt = 0;
    
    if (currentRoute === 'hlmarket') void hlRefreshTradeZone();
  } catch (e) {
    if (btn) btn.textContent = 'Cancel';
    const er2 = openSheet('Cancel order', `<p class="small" style="line-height:1.55">${esc(e instanceof Error ? e.message : String(e))}</p><div style="height:12px"></div><button class="ctaWide" id="hlCancelOk">OK</button>`);
    ($('#hlCancelOk') as HTMLElement).onclick = () => er2();
  }
}
// ---- Deposit: Arbitrum native USDC -> Bridge2 -> this address ----
function openHlDeposit() {
  const arb = findChain('arbitrum');
  const user = hlMasterAddr();
  const close = openSheet('Deposit to Hyperliquid', `<div id="hlDepBody">${waveLoadBlockHTML('Loading balances…', true)}</div>`);
  void (async () => {
    const body = document.getElementById('hlDepBody'); if (!body) return;
    try {
      if (!arb || !user) throw new Error('Arbitrum is not available in this wallet.');
      const provider = new ethers.JsonRpcProvider(evmProviderUrl(arb));
      const usdc = new ethers.Contract(HL_ARBITRUM_USDC, ['function balanceOf(address) view returns (uint256)'], provider);
      const [usdcBal, ethBal, spot] = await Promise.all([
        usdc.balanceOf(user).then((v: bigint) => Number(v) / 1e6).catch(() => null),
        provider.getBalance(user).then((v: bigint) => Number(v) / 1e18).catch(() => null),
        hlInfo({ type: 'spotClearinghouseState', user }).catch(() => null),
      ]);
      const hlUsdc = parseFloat((spot?.balances || []).find((b: any) => b.coin === 'USDC')?.total || '0');
      if (!document.getElementById('hlDepBody')) return;
      body.innerHTML = `<div class="detCard" style="margin:0">
        <div class="detRow"><span class="detLbl">USDC on Arbitrum</span><span class="detVal">${usdcBal == null ? 'Unavailable' : fmtUsd(usdcBal)}</span></div>
        <div class="detRow"><span class="detLbl">ETH on Arbitrum (gas)</span><span class="detVal">${ethBal == null ? 'Unavailable' : trimNum(ethBal, 5) + ' ETH'}</span></div>
        <div class="detRow"><span class="detLbl">USDC on Hyperliquid</span><span class="detVal" id="hlDepHlBal">${fmtUsd(hlUsdc)}</span></div>
        <div class="detRow"><span class="detLbl">Bridge</span><span class="detVal" style="max-width:62%;overflow:hidden;text-overflow:ellipsis">${HL_BRIDGE_ADDRESS}</span></div>
      </div>
      <label class="polyFldLbl" style="margin-top:14px">Amount (USDC)</label>
      <div class="polyAmtWrap"><input id="hlDepAmt" class="polyIn" inputmode="decimal" placeholder="25"><button class="polyMaxBtn" id="hlDepMax">Max</button></div>
      <p class="small muted" style="line-height:1.55;margin-top:10px">Deposits send <b>native USDC on Arbitrum</b> to Hyperliquid's bridge and are credited to this same address, usually within a minute. <b>Minimum ${HL_MIN_DEPOSIT_USDC} USDC — smaller deposits are not credited and are lost.</b> Only native USDC works; bridged USDC.e is not recognised.</p>
      <div class="err" id="hlDepErr" style="display:none"></div>
      <div class="small muted" id="hlDepStatus" style="margin-top:8px"></div>
      <div style="height:12px"></div><button class="ctaWide" id="hlDepGo">Review deposit</button>`;
      const amtIn = $('#hlDepAmt') as unknown as HTMLInputElement;
      ($('#hlDepMax') as HTMLElement).onclick = () => { if (usdcBal != null) { amtIn.value = String(Math.floor(usdcBal * 100) / 100); } };
      ($('#hlDepGo') as HTMLElement).onclick = async () => {
        const err = $('#hlDepErr'); const status = $('#hlDepStatus'); const goBtn = $('#hlDepGo') as HTMLButtonElement;
        const showErr = (t: string) => { if (err) { err.style.display = 'block'; err.textContent = t; } };
        if (err) err.style.display = 'none';
        const amt = parseFloat(amtIn.value);
        if (!(amt >= HL_MIN_DEPOSIT_USDC)) return showErr(`Enter at least ${HL_MIN_DEPOSIT_USDC} USDC — smaller deposits are lost, so the wallet will not send one.`);
        if (usdcBal != null && amt > usdcBal) return showErr('That is more USDC than this address holds on Arbitrum.');
        if (ethBal != null && ethBal <= 0) return showErr('You need a little ETH on Arbitrum to pay gas for the deposit.');
        const pk = evmPrivKey(); if (!pk) { showErr('This wallet has no EVM key.'); return; }
        goBtn.disabled = true;
        try {
          if (status) status.textContent = 'Sending USDC to the bridge…';
          const signer = new ethers.Wallet(pk, new ethers.JsonRpcProvider(evmProviderUrl(arb)));
          const contract = new ethers.Contract(HL_ARBITRUM_USDC, ['function transfer(address to, uint256 value) returns (bool)'], signer);
          const tx = await contract.transfer(HL_BRIDGE_ADDRESS, ethers.parseUnits(amt.toFixed(6), 6));
          if (status) status.innerHTML = `Sent — transaction ${esc(String(tx.hash).slice(0, 10))}… Waiting for the bridge to credit your Hyperliquid account (usually under a minute).`;
          await tx.wait();
          const before = hlUsdc;
          for (let i = 0; i < 12; i++) {
            await new Promise(r => setTimeout(r, 10000));
            try { const s2 = await hlInfo({ type: 'spotClearinghouseState', user }); const now = parseFloat((s2?.balances || []).find((b: any) => b.coin === 'USDC')?.total || '0'); const el = document.getElementById('hlDepHlBal'); if (el) el.textContent = fmtUsd(now); if (now >= before + amt - 0.01) { if (status) status.textContent = `Credited — your Hyperliquid balance now shows ${fmtUsd(now)}.`; break; } } catch { /* keep waiting */ }
            if (i === 11 && status) status.textContent = 'The transfer is confirmed on Arbitrum. Crediting is taking longer than usual — your Hyperliquid balance will update shortly; nothing else is needed.';
          }
          goBtn.textContent = 'Done'; goBtn.disabled = false; goBtn.onclick = () => { close(); hlAcctAt = 0; if (currentRoute === 'hlmarket') void hlRefreshTradeZone(); };
          hlAcctAt = 0;
        } catch (e) {
          showErr(e instanceof Error ? e.message : String(e));
          goBtn.disabled = false;
        }
      };
    } catch (e) {
      body.innerHTML = `<p class="small" style="line-height:1.55">${esc(e instanceof Error ? e.message : String(e))}</p>`;
    }
  })();
}
// ---- Perp detail trade zone ----
interface HlTradeForm { side: 'long' | 'short'; mode: 'market' | 'limit'; size: string; unit: 'usd' | 'coin'; limitPx: string; leverage: number; tp: string; sl: string; }
let hlForm: HlTradeForm = { side: 'long', mode: 'market', size: '', unit: 'usd', limitPx: '', leverage: 1, tp: '', sl: '' };
const hlLevKnown = new Map<string, number>();
let hlZonePos: HlPosFull | null = null;
let hlZoneOrders: HlOrderFull[] = [];
let hlZoneAvail: number | null = null;
// Audit fix: zone state is keyed to the market on screen. Without the
// key, opening market B painted market A's position/orders/available
// margin (with a live Close button) until B's fetch landed — and
// forever if B's fetch failed.
let hlZoneKey = '';
let hlZoneTimer: ReturnType<typeof setInterval> | null = null;
async function hlLoadZoneState(dexId: string, coin: string): Promise<void> {
  const user = hlMasterAddr(); if (!user) return;
  const key = dexId + ':' + coin;
  const [st, os] = await Promise.all([
    hlInfo(dexId ? { type: 'clearinghouseState', user, dex: dexId } : { type: 'clearinghouseState', user }).catch(() => null),
    hlInfo(dexId ? { type: 'frontendOpenOrders', user, dex: dexId } : { type: 'frontendOpenOrders', user }).catch(() => null),
  ]);
  if (hlZoneKey !== key) return; // a different market is on screen now
  if (st) {
    hlZoneAvail = parseFloat(st.withdrawable || '0');
    const pos = (st.assetPositions || []).map((p: any) => p.position).find((p: any) => p.coin === coin && parseFloat(p.szi || '0') !== 0);
    hlZonePos = pos ? { coin, dex: dexId, szi: parseFloat(pos.szi), entryPx: parseFloat(pos.entryPx || '0'), positionValue: parseFloat(pos.positionValue || '0'), unrealizedPnl: parseFloat(pos.unrealizedPnl || '0'), liquidationPx: pos.liquidationPx != null ? parseFloat(pos.liquidationPx) : null, leverage: Number(pos.leverage?.value || 1), marginUsed: parseFloat(pos.marginUsed || '0') } : null;
    if (hlZonePos) hlLevKnown.set(coin, hlZonePos.leverage);
  }
  if (Array.isArray(os)) hlZoneOrders = os.map((o: any) => hlOrderFullFromApi(o, dexId)).filter(o => o.coin === coin);
}
async function hlRefreshTradeZone(): Promise<void> {
  const sel = investHlSel; if (!sel || currentRoute !== 'hlmarket') return;
  const dex = hlData?.dexes.find(d => d.id === sel.dex); const a = dex?.assets.find(x => x.name === sel.name);
  if (!dex || !a) return;
  await hlLoadZoneState(sel.dex, sel.name).catch(() => { /* keep last state */ });
  paintHlPosBox(sel.dex);
  paintHlGateLine();
  paintHlEst(a);
}
function paintHlGateLine() {
  const gate = document.getElementById('hltGate'); if (!gate) return;
  const user = hlMasterAddr();
  if (!evmPrivKey()) { gate.innerHTML = `<div class="polyGateCard"><div class="polyGateHead"><span class="polyGateMed"><i class="ri-key-2-line"></i></span><span class="polyGateTitle">Trading unavailable</span></div><p class="polyGateCopy">This wallet was imported from a non-EVM key, so it has no Hyperliquid account. Import or create an EVM wallet to trade perps.</p></div>`; return; }
  if (hlAgentApprovedFor(user)) { gate.innerHTML = ''; return; }
  gate.innerHTML = `<div class="polyGateCard"><div class="polyGateHead"><span class="polyGateMed"><i class="ri-key-2-line"></i></span><span class="polyGateTitle">Enable trading</span></div><p class="polyGateCopy">Syn Wallet creates a trading key that lives only in your encrypted vault. Your wallet signs a one-time approval; after that the trading key signs orders on this device. It can trade but can never withdraw.</p><p class="polyGateFoot">Your Hyperliquid account is this wallet's own address. It activates with your first deposit (minimum ${HL_MIN_DEPOSIT_USDC} USDC).</p><button class="polyGateCta" id="hltEnable">Enable trading</button></div>`;
  ($('#hltEnable') as HTMLElement).onclick = async () => {
    const btn = $('#hltEnable') as HTMLButtonElement; btn.disabled = true; btn.textContent = 'Approving…';
    try { await hlEnsureAgentKey(); paintHlGateLine(); }
    catch (e) { btn.disabled = false; btn.textContent = 'Enable trading'; const er = document.getElementById('hltErr'); if (er) { er.style.display = 'block'; er.textContent = e instanceof Error ? e.message : String(e); } }
  };
}
function paintHlPosBox(dexId: string) {
  const box = document.getElementById('hltPosBox'); if (!box) return;
  const p = hlZonePos;
  const posHtml = p ? `<div class="gGroup"><div class="gHead">Your position</div><div class="gCard">
    <div class="sRow stat"><span class="sTx"><span class="sLbl">${p.szi > 0 ? 'Long' : 'Short'} ${trimNum(Math.abs(p.szi), 4)} ${esc(hlBaseName(p.coin))} · ${p.leverage}×</span><div class="sSub">Entry ${fmtPrice(p.entryPx)} · margin ${fmtUsd(p.marginUsed)}${p.liquidationPx ? ' · liq ' + fmtPrice(p.liquidationPx) : ''}</div></span><span class="sVal strong ${p.unrealizedPnl >= 0 ? 'pos' : 'neg'}">${p.unrealizedPnl >= 0 ? '+' : '−'}${fmtUsd(Math.abs(p.unrealizedPnl))}</span><button class="hlMiniBtn" id="hltClose">Close</button></div>
  </div></div>` : '';
  const ordHtml = hlZoneOrders.length ? `<div class="gGroup"><div class="gHead">Open orders</div><div class="gCard">
    ${hlZoneOrders.map((o, ix) => `<div class="sRow stat"><span class="sTx"><span class="sLbl">${o.side === 'B' ? 'Buy' : 'Sell'} ${trimNum(o.sz, 4)}${o.isTrigger ? ' · trigger' : ''}</span><div class="sSub">@ ${fmtPrice(o.isTrigger ? o.triggerPx : o.limitPx)} · order ${o.oid}</div></span><button class="hlMiniBtn" data-hltcancel="${ix}">Cancel</button></div>`).join('')}
  </div></div>` : '';
  box.innerHTML = posHtml + ordHtml;
  const cb = document.getElementById('hltClose'); if (cb && p) cb.onclick = () => void hlClosePositionFlow(p.coin, dexId, cb);
  box.querySelectorAll('[data-hltcancel]').forEach(b => (b as HTMLElement).onclick = () => { const o = hlZoneOrders[Number((b as HTMLElement).dataset.hltcancel)]; if (o) void hlCancelOrderFlow(o, b as HTMLElement); });
}
function hlFormNumbers(a: HlAsset): { px: number; szCoin: number; notional: number } | null {
  const px = hlForm.mode === 'market' ? a.markPx : parseFloat(hlForm.limitPx);
  const raw = parseFloat(hlForm.size);
  if (!(px > 0) || !(raw > 0)) return null;
  const szCoin = hlForm.unit === 'usd' ? raw / px : raw;
  return { px, szCoin, notional: szCoin * px };
}
function paintHlEst(a: HlAsset) {
  const el = document.getElementById('hltEst'); if (!el) return;
  const avail = document.getElementById('hltAvail');
  if (avail) avail.textContent = hlZoneAvail == null ? '' : `Available on ${a.name.includes(':') ? 'this dex' : 'Hyperliquid'}: ${fmtUsd(hlZoneAvail)} · cross margin`;
  const n = hlFormNumbers(a);
  if (!n) { el.innerHTML = '<span class="muted">Enter a size to see the order summary.</span>'; const rb0 = document.getElementById('hltReview') as HTMLButtonElement | null; if (rb0) rb0.disabled = true; return; }
  const isLong = hlForm.side === 'long';
  const liq = hlEstLiqPx(n.px, isLong, hlForm.leverage, a.maxLeverage);
  el.innerHTML = `<span>${isLong ? 'Long' : 'Short'} <b>${trimNum(n.szCoin, 4)} ${esc(hlBaseName(a.name))}</b></span><span>Notional <b>${fmtUsd(n.notional)}</b> · margin <b>${fmtUsd(n.notional / hlForm.leverage)}</b></span><span>Est. liquidation <b>${fmtPrice(liq)}</b></span>`;
  const rb = document.getElementById('hltReview') as HTMLButtonElement | null; if (rb) rb.disabled = false;
}
function paintHlTradeZone(dex: HlDex, a: HlAsset) {
  const host = document.getElementById('hlTradeZone'); if (!host) return;
  const coin = a.name;
  // New market on screen: drop the previous market's zone state before
  // anything paints, so its position/orders can never appear here.
  const zkey = dex.id + ':' + coin;
  if (hlZoneKey !== zkey) { hlZoneKey = zkey; hlZonePos = null; hlZoneOrders = []; hlZoneAvail = null; }
  if (!hlLevKnown.has(coin) && hlZonePos) hlLevKnown.set(coin, hlZonePos.leverage);
  hlForm = { side: 'long', mode: 'market', size: '', unit: 'usd', limitPx: '', leverage: hlLevKnown.get(coin) || Math.min(10, a.maxLeverage), tp: '', sl: '' };
  const levChoices = [...new Set([1, 2, 3, 5, 10, 15, 20, 25, 40, 50].filter(v => v <= a.maxLeverage).concat([a.maxLeverage]))].sort((x, y) => x - y);
  if (!levChoices.includes(hlForm.leverage)) hlForm.leverage = levChoices[levChoices.length - 1] || 1;
  host.innerHTML = `
  <div class="gGroup"><div class="gHead">Trade</div><div class="gCard polyPanel" style="padding:14px">
    <div id="hltGate"></div>
    <div class="polySideTabs"><button data-hlside="long" class="on">Long</button><button data-hlside="short">Short</button><span class="polyModeSeg"><button data-hlmode="market" class="on">Market</button><button data-hlmode="limit">Limit</button></span></div>
    <div id="hltLimitRow" style="display:none"><label class="polyFldLbl">Limit price (USD)</label><input id="hltLimitPx" class="polyIn" inputmode="decimal" placeholder="${trimNum(a.markPx, 2)}"></div>
    <label class="polyFldLbl">Leverage · cross margin</label>
    <div class="chipRail" id="hltLevRail" style="padding:0 0 4px">${levChoices.map(v => `<button class="netChip${v === hlForm.leverage ? ' on' : ''}" data-hllev="${v}"><span>${v}×</span></button>`).join('')}</div>
    <label class="polyFldLbl">Size</label>
    <div class="polyAmtWrap"><input id="hltSize" class="polyIn" inputmode="decimal" placeholder="0"><button class="polyMaxBtn" id="hltUnit">USD</button></div>
    <div style="display:flex;gap:10px">
      <span style="flex:1"><label class="polyFldLbl">Take profit (optional)</label><input id="hltTp" class="polyIn" inputmode="decimal" placeholder="Price"></span>
      <span style="flex:1"><label class="polyFldLbl">Stop loss (optional)</label><input id="hltSl" class="polyIn" inputmode="decimal" placeholder="Price"></span>
    </div>
    <div class="polyEst" id="hltEst"></div>
    <div class="small muted" id="hltAvail" style="margin-top:6px"></div>
    <div class="err" id="hltErr" style="display:none"></div>
    <button class="ctaWide" id="hltReview" disabled>Review order</button>
    <p class="small muted" style="line-height:1.55;margin-top:10px">Orders are signed on this device by your wallet's trading key and relayed to Hyperliquid — Syn never custodies funds and the key cannot withdraw. Minimum order value ${fmtUsd(HL_MIN_ORDER_USD)}.${dex.id ? ' This is a HIP-3 builder dex: it keeps its own margin balance, separate from the main dex.' : ''}</p>
  </div></div>
  <div id="hltPosBox"></div>
  <div class="gGroup"><div class="gHead">Deposit</div><div class="gCard">
    <div class="sRow stat"><span class="sTx"><span class="sLbl">USDC on Hyperliquid</span><div class="sSub">Deposits arrive from Arbitrum in about a minute</div></span><button class="hlMiniBtn" id="hltDeposit">Deposit</button></div>
  </div><div class="gFoot">Minimum deposit ${HL_MIN_DEPOSIT_USDC} USDC — smaller deposits are not credited and are lost.</div></div>`;
  paintHlGateLine();
  paintHlPosBox(dex.id);
  paintHlEst(a);
  ($('#hltDeposit') as HTMLElement).onclick = () => openHlDeposit();
  host.querySelectorAll('[data-hlside]').forEach(b => (b as HTMLElement).onclick = () => { hlForm.side = (b as HTMLElement).dataset.hlside as 'long' | 'short'; host.querySelectorAll('[data-hlside]').forEach(x => x.classList.toggle('on', x === b)); paintHlEst(a); });
  host.querySelectorAll('[data-hlmode]').forEach(b => (b as HTMLElement).onclick = () => { hlForm.mode = (b as HTMLElement).dataset.hlmode as 'market' | 'limit'; host.querySelectorAll('[data-hlmode]').forEach(x => x.classList.toggle('on', x === b)); const lr = document.getElementById('hltLimitRow'); if (lr) lr.style.display = hlForm.mode === 'limit' ? 'block' : 'none'; paintHlEst(a); });
  host.querySelectorAll('[data-hllev]').forEach(b => (b as HTMLElement).onclick = () => { hlForm.leverage = Number((b as HTMLElement).dataset.hllev); hlLevKnown.set(coin, hlForm.leverage); host.querySelectorAll('[data-hllev]').forEach(x => x.classList.toggle('on', x === b)); paintHlEst(a); });
  const sizeIn = $('#hltSize') as unknown as HTMLInputElement;
  sizeIn.addEventListener('input', () => { hlForm.size = sizeIn.value; paintHlEst(a); });
  ($('#hltUnit') as HTMLElement).onclick = () => { hlForm.unit = hlForm.unit === 'usd' ? 'coin' : 'usd'; ($('#hltUnit') as HTMLElement).textContent = hlForm.unit === 'usd' ? 'USD' : hlBaseName(coin); paintHlEst(a); };
  const lpIn = $('#hltLimitPx') as unknown as HTMLInputElement;
  lpIn.addEventListener('input', () => { hlForm.limitPx = lpIn.value; paintHlEst(a); });
  const tpIn = $('#hltTp') as unknown as HTMLInputElement; tpIn.addEventListener('input', () => { hlForm.tp = tpIn.value; });
  const slIn = $('#hltSl') as unknown as HTMLInputElement; slIn.addEventListener('input', () => { hlForm.sl = slIn.value; });
  ($('#hltReview') as HTMLElement).onclick = () => openHlReview(dex, a);
  void hlLoadZoneState(dex.id, coin).then(() => { paintHlPosBox(dex.id); paintHlEst(a); }).catch(() => { /* state stays as painted */ });
  if (hlZoneTimer) clearInterval(hlZoneTimer);
  hlZoneTimer = setInterval(() => { if (currentRoute !== 'hlmarket' || document.hidden) { if (currentRoute !== 'hlmarket' && hlZoneTimer) { clearInterval(hlZoneTimer); hlZoneTimer = null; } return; } void hlRefreshTradeZone(); }, 25000);
}
function openHlReview(dex: HlDex, a: HlAsset) {
  const err = (t: string) => { const er = document.getElementById('hltErr'); if (er) { er.style.display = 'block'; er.textContent = t; } };
  const erEl = document.getElementById('hltErr'); if (erEl) erEl.style.display = 'none';
  const n = hlFormNumbers(a); if (!n) return err('Enter a size first.');
  const isLong = hlForm.side === 'long';
  const isBuy = isLong;
  const px = hlForm.mode === 'market' ? hlRoundPrice(a.markPx * (isBuy ? 1.05 : 0.95), a.szDecimals) : hlRoundPrice(parseFloat(hlForm.limitPx), a.szDecimals);
  if (!(px > 0)) return err('Set a valid limit price.');
  const sz = hlRoundSize(n.szCoin, a.szDecimals, hlForm.unit === 'usd' ? 'down' : 'round');
  if (!(sz > 0)) return err('Size is below this market’s minimum precision.');
  const notional = sz * (hlForm.mode === 'market' ? a.markPx : px);
  if (notional < HL_MIN_ORDER_USD) return err(`Hyperliquid requires a minimum order value of ${fmtUsd(HL_MIN_ORDER_USD)} — this order is ${fmtUsd(notional)}.`);
  if (hlZoneAvail != null && notional / hlForm.leverage > hlZoneAvail && !hlZonePos) return err(`Margin needed (${fmtUsd(notional / hlForm.leverage)}) exceeds the ${fmtUsd(hlZoneAvail)} available on this dex.`);
  const tp = parseFloat(hlForm.tp); const sl = parseFloat(hlForm.sl);
  if (hlForm.tp && !(tp > 0)) return err('Take profit price is not valid.');
  if (hlForm.sl && !(sl > 0)) return err('Stop loss price is not valid.');
  if (tp > 0 && ((isLong && tp <= n.px) || (!isLong && tp >= n.px))) return err('Take profit must be beyond the entry price.');
  if (sl > 0 && ((isLong && sl >= n.px) || (!isLong && sl <= n.px))) return err('Stop loss must be on the other side of the entry price.');
  const liq = hlEstLiqPx(hlForm.mode === 'market' ? a.markPx : px, isLong, hlForm.leverage, a.maxLeverage);
  const r = hlResolveAsset(a.name, dex.id); if (!r) return err('Market not found in the latest snapshot.');
  const close = openSheet('Review order', `<div class="detCard" style="margin:0">
    <div class="detRow"><span class="detLbl">Market</span><span class="detVal">${esc(hlBaseName(a.name))} perpetual${dex.id ? ' · ' + esc(dex.name) : ''}</span></div>
    <div class="detRow"><span class="detLbl">Side</span><span class="detVal">${isLong ? 'Long' : 'Short'} · ${hlForm.mode === 'market' ? 'Market' : 'Limit'}</span></div>
    <div class="detRow"><span class="detLbl">Size</span><span class="detVal">${trimNum(sz, Math.max(4, a.szDecimals))} ${esc(hlBaseName(a.name))}</span></div>
    <div class="detRow"><span class="detLbl">Price</span><span class="detVal">${hlForm.mode === 'market' ? 'Market (~' + fmtPrice(a.markPx) + ' · limit ' + fmtPrice(px) + ')' : fmtPrice(px)}</span></div>
    <div class="detRow"><span class="detLbl">Notional</span><span class="detVal">${fmtUsd(notional)}</span></div>
    <div class="detRow"><span class="detLbl">Leverage</span><span class="detVal">${hlForm.leverage}× · cross</span></div>
    <div class="detRow"><span class="detLbl">Margin required</span><span class="detVal">${fmtUsd(notional / hlForm.leverage)}</span></div>
    <div class="detRow"><span class="detLbl">Est. liquidation</span><span class="detVal">${fmtPrice(liq)}</span></div>
    ${tp > 0 ? `<div class="detRow"><span class="detLbl">Take profit</span><span class="detVal">${fmtPrice(hlRoundPrice(tp, a.szDecimals))}</span></div>` : ''}
    ${sl > 0 ? `<div class="detRow"><span class="detLbl">Stop loss</span><span class="detVal">${fmtPrice(hlRoundPrice(sl, a.szDecimals))}</span></div>` : ''}
  </div><div class="err" id="hlRevErr" style="display:none"></div><div class="small muted" id="hlRevStatus" style="margin-top:10px"></div><div style="height:12px"></div><button class="ctaWide" id="hlRevGo">${isLong ? 'Place long' : 'Place short'}</button>`);
  ($('#hlRevGo') as HTMLElement).onclick = async () => {
    const goBtn = $('#hlRevGo') as HTMLButtonElement; const status = $('#hlRevStatus'); const er2 = $('#hlRevErr');
    goBtn.disabled = true;
    const fail = (t: string) => { if (er2) { er2.style.display = 'block'; er2.textContent = t; } goBtn.disabled = false; };
    try {
      if (status) status.textContent = 'Preparing your trading key…';
      const agentKey = await hlEnsureAgentKey();
      if (hlLevKnown.get(a.name) !== hlForm.leverage || !hlZonePos) {
        if (status) status.textContent = `Setting leverage to ${hlForm.leverage}×…`;
        await hlPostL1(agentKey, hlUpdateLeverageAction(r.assetId, true, hlForm.leverage));
        hlLevKnown.set(a.name, hlForm.leverage);
      }
      if (status) status.textContent = 'Signing and placing the order…';
      const orders: HlOrderWire[] = [hlOrderWire({ asset: r.assetId, isBuy, px, sz, reduceOnly: false, tif: hlForm.mode === 'market' ? 'Ioc' : 'Gtc' })];
      if (tp > 0) orders.push(hlOrderWire({ asset: r.assetId, isBuy: !isBuy, px: hlRoundPrice(tp, a.szDecimals), sz, reduceOnly: true, trigger: { isMarket: true, triggerPx: hlRoundPrice(tp, a.szDecimals), tpsl: 'tp' } }));
      if (sl > 0) orders.push(hlOrderWire({ asset: r.assetId, isBuy: !isBuy, px: hlRoundPrice(sl, a.szDecimals), sz, reduceOnly: true, trigger: { isMarket: true, triggerPx: hlRoundPrice(sl, a.szDecimals), tpsl: 'sl' } }));
      const res = await hlPostL1(agentKey, hlOrderAction(orders, orders.length > 1 ? 'positionTpsl' : 'na'));
      const lines = hlOrderStatusLines(res);
      if (status) status.innerHTML = lines.map(esc).join('<br>');
      const hasErr = (res?.response?.data?.statuses || []).some((s: any) => !!s?.error);
      goBtn.textContent = hasErr ? 'Close' : 'Done'; goBtn.disabled = false;
      goBtn.onclick = () => { close(); hlAcctAt = 0; void hlRefreshTradeZone(); };
      hlAcctAt = 0;
    } catch (e) { fail(e instanceof Error ? e.message : String(e)); }
  };
}

let hlDetailTimer: ReturnType<typeof setInterval> | null = null;
async function fetchHlCandles(coin: string, interval: string, hours: number): Promise<{ time: number; open: number; high: number; low: number; close: number; volume: number }[]> {
  try { const r = await fetch(`/api/hl/candles?coin=${encodeURIComponent(coin)}&interval=${interval}&hours=${hours}`); if (!r.ok) return []; const j = await r.json(); return Array.isArray(j?.candles) ? j.candles : []; } catch { return []; }
}
function showHlMarket() {
  const sel = investHlSel; if (!sel) { goTab('invest'); return; }
  if (hlDetailTimer) { clearInterval(hlDetailTimer); hlDetailTimer = null; }
  type HlPeriod = { value: string; label: string; name: string; unit: 'hour' | 'day'; candles: { time: number; open: number; high: number; low: number; close: number; volume: number }[] };
  let candlePeriods: HlPeriod[] = [];
  const paintStats = () => {
    const dex = hlData?.dexes.find(d => d.id === sel.dex); const a = dex?.assets.find(x => x.name === sel.name);
    if (!dex || !a) return;
    const set = (id: string, txt: string) => { const el = document.getElementById(id); if (el) el.textContent = txt; };
    set('hlMark', fmtPrice(a.markPx));
    const chg = document.getElementById('hlChg'); if (chg) chg.innerHTML = chgPill(a.change24h);
    set('hlOracle', fmtPrice(a.oraclePx));
    set('hlFunding', (a.funding >= 0 ? '+' : '') + (a.funding * 100).toFixed(4) + '% / hr');
    set('hlOi', `${trimNum(a.openInterest, 2)} ${esc(hlBaseName(a.name))} · ${fmtMcap(a.openInterest * a.markPx)}`);
    set('hlVol', fmtMcap(a.dayNtlVlm));
    set('hlPrev', fmtPrice(a.prevDayPx));
  };
  const render = () => {
    const dex = hlData?.dexes.find(d => d.id === sel.dex); const a = dex?.assets.find(x => x.name === sel.name);
    if (!dex || !a) { setView(`<main><button class="backBtn" id="bk" aria-label="Back"><i class="ri-arrow-left-s-line"></i></button><div class="largeTitle" style="padding-top:2px">${esc(hlBaseName(sel.name))}</div><p class="small muted" style="padding:0 16px">This market is not in the latest Hyperliquid snapshot.</p></main>`); ($('#bk') as HTMLElement).onclick = () => goBack({ route: 'invest' }); return; }
    const cat = hlCategory(sel.dex, a.name, new Set((hlData?.dexes.find(d => d.id === '')?.assets || []).map(x => x.name)));
    setView(`<main><button class="backBtn" id="bk" aria-label="Back"><i class="ri-arrow-left-s-line"></i></button>
    <div class="dHead"><div class="dIdRow">${cat === 'commodities' ? commodityIcon(hlBaseName(a.name), a.name, { sm: true }) : cat === 'stocks' ? stockIcon(hlBaseName(a.name), a.name, { sm: true }) : underlyingIcon(hlBaseName(a.name), a.name, { sm: true })}<div class="dIdTx"><div class="dName">${esc(hlBaseName(a.name))}</div><div class="dSym">Perpetual · ${esc(dex.name)}${sel.dex ? ' (HIP-3)' : ''}</div></div><span class="liveDot">LIVE</span></div>
    <div class="dPriceBlock"><div class="dEyebrow">MARK PRICE</div><div class="dPriceRow"><span class="dPriceVal" id="hlMark">${fmtPrice(a.markPx)}</span><span id="hlChg">${chgPill(a.change24h)}</span></div></div></div>
    <div class="chartBox" id="hlChartBox" style="margin:2px 16px 0"><div class="chartEmpty">${waveLoadHTML()} Loading live chart…</div></div>
    <div class="gGroup"><div class="gHead">Market</div><div class="gCard flushHair">
      <div class="sRow stat"><span class="sTx"><span class="sLbl">Oracle price</span></span><span class="sVal strong" id="hlOracle">${fmtPrice(a.oraclePx)}</span></div>
      <div class="sRow stat"><span class="sTx"><span class="sLbl">Funding rate</span></span><span class="sVal strong" id="hlFunding">${(a.funding >= 0 ? '+' : '') + (a.funding * 100).toFixed(4)}% / hr</span></div>
      <div class="sRow stat"><span class="sTx"><span class="sLbl">Open interest</span></span><span class="sVal strong" id="hlOi">${trimNum(a.openInterest, 2)} ${esc(hlBaseName(a.name))} · ${fmtMcap(a.openInterest * a.markPx)}</span></div>
      <div class="sRow stat"><span class="sTx"><span class="sLbl">24h volume</span></span><span class="sVal strong" id="hlVol">${fmtMcap(a.dayNtlVlm)}</span></div>
      <div class="sRow stat"><span class="sTx"><span class="sLbl">Previous day price</span></span><span class="sVal strong" id="hlPrev">${fmtPrice(a.prevDayPx)}</span></div>
      <div class="sRow stat"><span class="sTx"><span class="sLbl">Max leverage</span></span><span class="sVal strong">${a.maxLeverage}×</span></div>
      <div class="sRow stat"><span class="sTx"><span class="sLbl">Venue</span></span><span class="sVal strong">Hyperliquid${sel.dex ? ' · ' + esc(dex.name) : ''}</span></div>
    </div><div class="gFoot">Live data from Hyperliquid's public API, refreshed while this screen is open. Source: Hyperliquid.</div></div>
    <div id="hlTradeZone"></div></main>`);
    ($('#bk') as HTMLElement).onclick = () => goBack({ route: 'invest' });
    paintHlTradeZone(dex, a);
    // Chart: HL candles through our proxy — 1D (hourly) + 1W (4h).
    // Mounted once; refresh ticks update it in place.
    void (async () => {
      const [d1, w1] = await Promise.all([fetchHlCandles(sel.name, '1h', 24), fetchHlCandles(sel.name, '4h', 168)]);
      const host = document.getElementById('hlChartBox'); if (!host || currentRoute !== 'hlmarket') return;
      candlePeriods = ([
        { value: 'day', label: '1D', name: 'Past day', unit: 'hour', candles: d1 },
        { value: 'week', label: '1W', name: 'Past week', unit: 'day', candles: w1 },
      ] as HlPeriod[]).filter(p => p.candles.length > 1);
      if (!candlePeriods.length) { host.innerHTML = '<div class="chartEmpty">Live chart unavailable right now. The prices above are still live.</div>'; return; }
      chartHandle = mountPriceChart(host, { periods: candlePeriods, selected: 'day' });
    })();
    // Invisible live refresh of price + stats + chart while open.
    if (hlDetailTimer) clearInterval(hlDetailTimer);
    hlDetailTimer = setInterval(async () => {
      if (currentRoute !== 'hlmarket' || document.hidden) { if (currentRoute !== 'hlmarket' && hlDetailTimer) { clearInterval(hlDetailTimer); hlDetailTimer = null; } return; }
      hlDataAt = 0;
      const data = await loadHlMarkets(); if (!data) return;
      paintStats();
      if (chartHandle && candlePeriods.length) {
        const [d1, w1] = await Promise.all([fetchHlCandles(sel.name, '1h', 24), fetchHlCandles(sel.name, '4h', 168)]);
        candlePeriods = ([
          { value: 'day', label: '1D', name: 'Past day', unit: 'hour', candles: d1 },
          { value: 'week', label: '1W', name: 'Past week', unit: 'day', candles: w1 },
        ] as HlPeriod[]).filter(p => p.candles.length > 1);
        if (candlePeriods.length && document.getElementById('hlChartBox')) chartHandle.update(candlePeriods);
      }
    }, 30000);
  };
  if (hlData) render(); else { setView(`<main><div style="padding:40px 16px">${waveLoadBlockHTML()}</div></main>`); void loadHlMarkets().then(render); }
}
function presetSwapBuy(chainId: string, tokenId: string): boolean {
  const list = swapAssets();
  const to = list.find(a => a.tokenId === tokenId); if (!to) return false;
  const from = list.find(a => a.chainId === chainId && a.symbol === 'USDC' && a.contract !== 'native') || list.find(a => a.chainId === chainId && a.contract === 'native');
  if (!from || from.key === to.key) return false;
  swapFromKey = from.key; swapToKey = to.key; swapQuote = null; swapQuoteSig = '';
  return true;
}
function showInvestToken() {
  const sel = investTokSel; if (!sel) { goTab('invest'); return; }
  const p = sel.pool; const bs = sel.bstock;
  const ourChainId = GT_TO_OUR_CHAIN[sel.gtChain] || '';
  const chain = findChain(ourChainId);
  const enabled = !!chain && enabledSet().has(ourChainId);
  const existing = chain ? [...BUILTIN_TOKENS, ...config.tokens].find(t => t.chainId === ourChainId && t.contract.toLowerCase() === p.address.toLowerCase()) : undefined;
  setView(`<main><button class="backBtn" id="bk" aria-label="Back"><i class="ri-arrow-left-s-line"></i></button>
  <div class="dHead"><div class="dIdRow">${bs ? stockIcon(bsUnderlying(p.symbol), p.name, { sm: true }) : iconHTML(p.img && isSafeMediaUrl(p.img) ? p.img : '', p.symbol, p.name, { sm: true })}<div class="dIdTx"><div class="dName">${esc(p.name)}</div><div class="dSym">${esc(p.symbol)} · ${esc(chain?.name || sel.gtChain)}${bs ? ' · bStock' : ''}</div></div><span class="liveDot">LIVE</span></div>
  <div class="dPriceBlock"><div class="dEyebrow">PRICE</div><div class="dPriceRow"><span class="dPriceVal">${p.priceUsd != null ? fmtUsd(p.priceUsd, p.priceUsd < 1 ? 6 : 2) : '—'}</span><span>${chgPill(p.change24h)}</span></div></div></div>
  <div class="gGroup"><div class="gHead">Market</div><div class="gCard flushHair">
    <div class="sRow stat"><span class="sTx"><span class="sLbl">24h volume</span></span><span class="sVal strong">${p.volume24h != null ? fmtMcap(p.volume24h) : '—'}</span></div>
    <div class="sRow stat"><span class="sTx"><span class="sLbl">Liquidity</span></span><span class="sVal strong">${p.liquidityUsd != null ? fmtMcap(p.liquidityUsd) : '—'}</span></div>
    <div class="sRow stat"><span class="sTx"><span class="sLbl">Fully diluted value</span></span><span class="sVal strong">${p.fdvUsd != null ? fmtMcap(p.fdvUsd) : '—'}</span></div>
    <div class="sRow stat"><span class="sTx"><span class="sLbl">${chain?.kind === 'solana' ? 'Mint' : 'Contract'}</span><div class="sSub">Tap the chip to copy</div></span><button class="monoChip" id="itContract">${esc(shortAddr(p.address))}</button></div>
    ${bs ? '<div class="sRow stat"><span class="sTx"><span class="sLbl">On Binance</span></span><button class="monoChip" id="itBinance">binance.com <i class="ri-arrow-right-up-line"></i></button></div>' : ''}
  </div><div class="gFoot">Prices from ${bs ? 'DexScreener (PancakeSwap pool)' : 'GeckoTerminal'}. Always check the contract before buying — same-ticker copycats exist.</div></div>
  <div style="padding:0 16px"><div id="itBuyErr"></div>
  ${existing ? `<button class="ctaWide" id="itBuy">Buy ${esc(p.symbol)}</button><div style="height:10px"></div><button class="btnGhost" id="itView" style="border-radius:999px">View in wallet</button>` : enabled ? `<button class="ctaWide" id="itBuy">Add token &amp; buy</button><p class="small muted" style="line-height:1.55;margin-top:10px">Adds this exact contract to your wallet on ${esc(chain!.name)}, then opens Swap with it pre-selected as what you're buying.</p>` : `<button class="ctaWide" disabled style="opacity:.45">Buy unavailable</button><p class="small muted" style="line-height:1.55;margin-top:10px">${chain ? `Enable ${esc(chain.name)} in Settings → Networks to hold and buy this token.` : 'This network is not a wallet network yet.'}</p>`}
  </div></main>`);
  ($('#bk') as HTMLElement).onclick = () => goBack({ route: 'invest' });
  ($('#itContract') as HTMLElement).onclick = (e) => copyText(p.address, e.currentTarget as HTMLElement);
  const bn = $('#itBinance'); if (bn) bn.onclick = () => window.open('https://www.binance.com', '_blank');
  const vw = $('#itView'); if (vw && existing) vw.onclick = () => go({ route: 'token', tokenId: existing.id }, vw);
  const buy = $('#itBuy') as HTMLButtonElement | null;
  if (buy) buy.onclick = async () => {
    const err = (msg: string) => { const s = $('#itBuyErr'); if (s) s.innerHTML = `<div class="err" style="margin-bottom:10px">${esc(msg)}</div>`; };
    if (!chain) { err('Network unavailable.'); return; }
    let tokenId = existing?.id;
    if (!tokenId) {
      btnBusy(buy, 'Reading contract…');
      const meta = await fetchTokenMeta(chain, p.address).catch(() => null);
      if (!meta) { err('That contract did not answer like a token on ' + chain.name + ' — nothing was added.'); buy.disabled = false; buy.textContent = 'Add token & buy'; return; }
      const t: TokenDef = { id: 'ct-' + Date.now().toString(36), chainId: ourChainId, contract: p.address, name: meta.name || p.name, symbol: meta.symbol || p.symbol, decimals: meta.decimals };
      config.tokens.push(t); saveConfig(); tokenId = t.id;
      void fetchTokenBalance(t).then(v => { tokenBalances.set(t.id, v); saveDataCache(); });
    }
    if (!presetSwapBuy(ourChainId, tokenId)) { err('Swap cannot route to this token from ' + chain.name + ' yet.'); return; }
    go({ route: 'swap' }, buy);
  };
}

function showConnect(err = '') {
  void loadFeatureCfg();
  if (wcClientReady() && wcInitState !== 'ready') wcInitState = 'ready';
  const pid = featureCfg.walletConnectProjectId;
  if (!pid) {
    setView(`<main><button class="backBtn" id="bk" aria-label="Back"><i class="ri-arrow-left-s-line"></i></button>
    <div class="nftTitle">WalletConnect</div>
    <p class="wcSub">Connect this wallet to a dApp — every request is reviewed here before anything is signed.</p>
    <div style="height:14px"></div>
    <div class="setPanel"><div class="setH">Pair a dApp</div>
    <div class="warn" style="margin:10px 0 0">WalletConnect needs a <b>free Reown project ID</b> before it can pair. Create one at <b>cloud.reown.com</b>, then set it on the server as the <span class="mono">WALLETCONNECT_PROJECT_ID</span> environment variable and restart the service. The full connect flow is built and waiting — nothing is faked in the meantime.</div>
    <div style="height:12px"></div><button class="ctaWide" disabled style="opacity:.45">Connect a dApp</button>
    <p class="securityNote" style="margin-top:12px">A project ID is a public identifier, not a secret key — it never touches your funds or your seed.</p></div>
    <div class="setPanel"><div class="setH">Sessions</div><div class="emptyState" style="padding:22px 16px 14px"><span class="tile"><i class="ri-link-unlink-line"></i></span><span class="et" style="font-size:15px">No active sessions</span><span class="es">dApps you connect will appear here.</span></div></div></main>`);
    ($('#bk') as HTMLElement).onclick = () => goBack({ route: 'wallet' });
    return;
  }
  if (wcInitState === 'idle') void ensureWc();
  const sessions = wcClientReady() ? wcSessions() : [];
  const prop = wcProposal;
  let propHTML = '';
  if (prop) {
    const meta = prop.params?.proposer?.metadata;
    const built = buildNamespaces(prop, wcAccounts());
    propHTML = `<div class="setPanel"><div class="setH">Connection request</div>
      <div class="setRow"><span class="setLabel">${esc(wcPeerName(meta))}</span><span class="sv small muted">${esc(meta?.url ?? '')}</span></div>
      ${built.problems.length ? `<div class="err">This dApp asks for something this wallet can't serve:<br>${built.problems.map(esc).join('<br>')}</div>` : `<p class="small muted" style="line-height:1.55">It will see your public addresses on: ${esc(Object.keys(built.namespaces).map(k => k === 'solana' ? 'Solana' : 'EVM chains ' + (built.namespaces.eip155?.chains ?? []).map((x: string) => x.split(':')[1]).join(', ')).join(' · '))}. It can never move funds without a request you review and approve here.</p>
      ${Object.values(built.granted.required).some(g => g.methods.length) ? `<div class="sumRow"><span class="sl">Required methods</span><span class="sv mono" style="font-size:11px;text-align:right">${esc(Object.values(built.granted.required).map(g => g.methods.join(', ')).filter(Boolean).join(' · '))}</span></div>` : ''}
      ${Object.values(built.granted.optional).some(g => g.methods.length) ? `<div class="sumRow"><span class="sl">Optional methods</span><span class="sv mono" style="font-size:11px;text-align:right">${esc(Object.values(built.granted.optional).map(g => g.methods.join(', ')).filter(Boolean).join(' · '))}</span></div>` : ''}
      ${built.granted.refusedMethods.length ? `<p class="small" style="color:var(--amber,#e8b23f);line-height:1.5;margin-top:6px">Not granted — this wallet never shares: ${esc(built.granted.refusedMethods.join(', '))}.</p>` : ''}`}
      <div style="display:flex;gap:8px;margin-top:10px"><button class="ctaWide" id="wcApproveBtn" ${built.problems.length ? 'disabled style="opacity:.45;flex:1"' : 'style="flex:1"'}>Approve</button><button class="btnGhost" id="wcRejectBtn" style="flex:1;border-radius:999px">Reject</button></div></div>`;
  }
  let reqHTML = '';
  if (wcRequest) {
    const review = wcRequestReview(wcRequest);
    const sess = sessions.find((s: any) => s.topic === wcRequest.topic);
    reqHTML = `<div class="setPanel"><div class="setH">${esc(review.title)}</div>
      <p class="small muted">Requested by ${esc(wcPeerName(sess?.peer?.metadata))}</p>
      ${review.body}
      <div id="wcReqErr"></div>
      <div style="display:flex;gap:8px;margin-top:12px"><button class="ctaWide" id="wcReqOk" style="flex:1" ${review.kind === 'unsupported' ? 'disabled' : ''}>Approve &amp; sign</button><button class="btnGhost" id="wcReqNo" style="flex:1;border-radius:999px">Reject</button></div></div>`;
  }
  setView(`<main><button class="backBtn" id="bk" aria-label="Back"><i class="ri-arrow-left-s-line"></i></button>
  <div class="nftTitle">WalletConnect</div>
  <p class="wcSub">${wcInitState === 'ready' ? 'Pair with a dApp by pasting its wc: pairing code, then review every request here before it is signed.' : wcInitState === 'error' ? 'WalletConnect failed to start.' : `${waveLoadHTML()} Starting WalletConnect…`}</p>
  ${wcInitState === 'error' ? `<div class="err" style="margin:10px 16px 12px">${esc(wcInitErr)}</div>
  <div style="display:flex;gap:8px;padding:0 16px 4px"><button class="ctaWide" id="wcRetryBtn" style="flex:1">Retry</button><button class="btnGhost" id="wcResetBtn" style="flex:1;border-radius:999px">Reset WalletConnect data</button></div>` : ''}
  ${err ? `<div class="err" style="margin:10px 16px 12px">${esc(err)}</div>` : ''}
  <div style="height:14px"></div>
  ${propHTML}${reqHTML}
  <div class="setPanel"><div class="setH">Pair a dApp</div>
    <div class="field" style="margin-top:10px"><label>Pairing code (wc:…)</label><input id="wcUri" class="inp mono" placeholder="wc:…" value="${esc(wcUriDraft)}"></div>
    <div id="wcPairErr"></div>
    <button class="ctaWide" id="wcPairBtn" ${wcInitState !== 'ready' ? 'disabled style="opacity:.45"' : ''}>Pair</button>
  </div>
  <div class="setPanel"><div class="setH">Sessions</div>
    ${sessions.length ? sessions.map((s: any) => {
      const meta = s.peer?.metadata ?? {};
      const icon = Array.isArray(meta.icons) && meta.icons[0] ? String(meta.icons[0]) : '';
      const chainNames: string[] = [];
      for (const [ns, v] of Object.entries<any>(s.namespaces ?? {})) {
        if (ns === 'solana') chainNames.push('Solana');
        else for (const ch of (v?.chains ?? [])) { const id = Number(String(ch).split(':')[1]); const cc = CHAINS.find(x => x.evmId === id); chainNames.push(cc ? cc.name : 'Chain ' + id); }
      }
      const exp = Number(s.expiry) > 0 ? new Date(Number(s.expiry) * 1000).toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: 'numeric' }) : '';
      return `<div class="wcSess">${isSafeMediaUrl(icon) ? `<span class="wcIcWrap"><span class="wcIc"><i class="ri-global-line"></i></span><img class="coinImg" src="${esc(icon)}" alt=""></span>` : '<span class="wcIc"><i class="ri-global-line"></i></span>'}<span style="flex:1;min-width:0"><span class="wn">${esc(wcPeerName(meta))}</span><span class="wd" style="display:block">${esc(meta.url ?? '')}</span><span class="wd" style="display:block">${esc(chainNames.slice(0, 4).join(' · ') || 'No chains')}${chainNames.length > 4 ? ' +' + (chainNames.length - 4) : ''}${exp ? ' · Expires ' + esc(exp) : ''}</span></span><button class="pillBtn danger" data-disc="${esc(s.topic)}">Disconnect</button></div>`;
    }).join('') : '<div class="emptyState" style="padding:22px 16px 14px"><span class="tile"><i class="ri-link-unlink-line"></i></span><span class="et" style="font-size:15px">No active sessions</span><span class="es">dApps you connect will appear here.</span></div>'}
  </div></main>`);
  ($('#bk') as HTMLElement).onclick = () => goBack({ route: 'wallet' });
  const wcRt = $('#wcRetryBtn'); if (wcRt) wcRt.onclick = () => { wcInitState = 'idle'; showConnect(); };
  const wcRs = $('#wcResetBtn'); if (wcRs) wcRs.onclick = async () => { btnBusy(wcRs as HTMLButtonElement, 'Resetting…'); try { await wcWipeStorage(); } catch { /* best effort */ } wcInitState = 'idle'; showConnect(); };
  const wcUriEl = $('#wcUri') as unknown as HTMLInputElement | null;
  if (wcUriEl) wcUriEl.addEventListener('input', () => { wcUriDraft = wcUriEl.value; });
  const pairBtn = $('#wcPairBtn');
  if (pairBtn) pairBtn.onclick = async () => {
    const uri = (($('#wcUri') as HTMLInputElement).value || '').trim();
    const e = $('#wcPairErr')!;
    if (!uri.startsWith('wc:')) { e.innerHTML = '<div class="err">Paste the full wc: pairing code from the dApp.</div>'; return; }
    const pb = pairBtn as HTMLButtonElement; btnBusy(pb, 'Pairing…');
    try { await wcPair(uri); wcUriDraft = ''; const wu = $('#wcUri') as unknown as HTMLInputElement | null; if (wu) wu.value = ''; e.innerHTML = `<p class="small muted">${waveLoadHTML()} Pairing sent — waiting for the dApp to respond with a session request.</p>`; }
    catch (ex: any) { e.innerHTML = `<div class="err">Pairing failed: ${esc(ex?.message || String(ex))}</div>`; }
    if (pb.isConnected) { pb.disabled = false; pb.innerHTML = 'Pair'; }
  };
  if (prop) {
    const ab = $('#wcApproveBtn'); if (ab) ab.onclick = async () => { try { const built = buildNamespaces(prop, wcAccounts()); await wcApprove(prop.id, built.namespaces); wcAdvanceProposal(); showConnect(); } catch (ex: any) { showConnect('Approve failed: ' + (ex?.message || String(ex))); } };
    const rb = $('#wcRejectBtn'); if (rb) rb.onclick = async () => { try { await wcReject(prop.id); } catch { /* already gone */ } wcAdvanceProposal(); showConnect(); };
  }
  if (wcRequest) {
    const req = wcRequest;
    const ok = $('#wcReqOk'); if (ok) ok.onclick = async () => {
      const btn = ok as HTMLButtonElement; btnBusy(btn, 'Signing…');
      try { const result = await executeWcRequest(req); await wcRespond(req.topic, req.id, result); wcAdvanceRequest(); showConnect(); }
      catch (ex: any) { const e = $('#wcReqErr'); if (e) e.innerHTML = `<div class="err">${esc(ex?.message || String(ex))}</div>`; btn.disabled = false; btn.textContent = 'Approve & sign'; }
    };
    const no = $('#wcReqNo'); if (no) no.onclick = async () => { try { await wcRejectRequest(req.topic, req.id); } catch { /* already gone */ } wcAdvanceRequest(); showConnect(); };
  }
  document.querySelectorAll('[data-disc]').forEach(b => (b as HTMLElement).onclick = async () => { try { await wcDisconnect((b as HTMLElement).dataset.disc!); } catch { /* already gone */ } showConnect(); });
}

// ---------- Wave 2: buy / sell (MoonPay, honestly gated) ----------
// Hosted ramp behind the operator's own MoonPay publishable key
// (MOONPAY_PUBLISHABLE_KEY on the server). MoonPay handles cards, KYC
// and payout on its own hosted pages — Syn never sees card data. No key
// configured = the screen says exactly that; nothing is faked.
let buyMode: 'buy' | 'sell' = 'buy';
let buyAsset = 'eth';
const BUY_ASSETS: { code: string; label: string; chainId: string }[] = [
  { code: 'btc', label: 'Bitcoin (BTC)', chainId: 'bitcoin' },
  { code: 'eth', label: 'Ethereum (ETH)', chainId: 'ethereum' },
  { code: 'sol', label: 'Solana (SOL)', chainId: 'solana' },
  { code: 'usdc_eth', label: 'USD Coin (USDC · Ethereum)', chainId: 'ethereum' },
];
function showBuy(err = '') {
  void loadFeatureCfg();
  const key = featureCfg.moonpayPublishableKey;
  const asset = BUY_ASSETS.find(a => a.code === buyAsset) ?? BUY_ASSETS[1];
  const chain = findChain(asset.chainId);
  const addr = chain ? addressFor(chain) : '';
  setView(`<main><button class="backBtn" id="bk" aria-label="Back"><i class="ri-arrow-left-s-line"></i></button>
  <div class="card"><h1 class="heroH">${buyMode === 'buy' ? 'Buy' : 'Sell'} <span>crypto</span></h1><p class="heroSub" style="margin-top:2px">Provided by MoonPay on its own hosted pages — card payments, identity checks and payouts are MoonPay's; Syn never touches your card data.</p>
  ${err ? `<div class="err" style="margin-top:10px">${esc(err)}</div>` : ''}</div>
  <div class="seg" id="buySeg" style="margin:12px 16px 4px"><button data-m="buy" class="${buyMode === 'buy' ? 'on' : ''}" type="button">Buy</button><button data-m="sell" class="${buyMode === 'sell' ? 'on' : ''}" type="button">Sell</button></div>
  <div class="setPanel"><div class="setH">${buyMode === 'buy' ? 'You receive' : 'You sell'}</div>
    <div style="display:flex;flex-wrap:wrap;gap:8px;margin-top:10px">${BUY_ASSETS.map(a => `<button class="pillBtn ${a.code === buyAsset ? '' : 'ghost'}" data-asset="${a.code}">${esc(a.label)}</button>`).join('')}</div>
    <div class="field" style="margin-top:12px"><label>${buyMode === 'buy' ? 'You pay (USD)' : 'Amount (' + esc(asset.label) + ')'}</label><input id="buyAmt" class="inp mono" inputmode="decimal" placeholder="${buyMode === 'buy' ? '100' : '0.1'}"></div>
    ${buyMode === 'buy' ? `<div class="sumRow"><span class="sl">Delivered to</span><span class="sv"><span class="monoChip" style="max-width:210px">${esc(addr.slice(0, 10))}…${esc(addr.slice(-6))}</span></span></div>` : ''}
    ${key ? `<button class="ctaWide" id="buyGo">Continue to MoonPay</button>` : `<div class="warn" style="margin:0">Buy &amp; sell needs a <b>MoonPay account key</b> before it can run. The operator adds a publishable key from <b>dashboard.moonpay.com</b> as the <span class="mono">MOONPAY_PUBLISHABLE_KEY</span> server environment variable — the full flow is built and waiting.</div><div style="height:12px"></div><button class="ctaWide" disabled style="opacity:.45">Continue to MoonPay</button>`}
  </div></main>`);
  ($('#bk') as HTMLElement).onclick = () => goBack({ route: 'wallet' });
  document.querySelectorAll('#buySeg [data-m]').forEach(b => (b as HTMLElement).onclick = () => { buyMode = (b as HTMLElement).dataset.m as 'buy' | 'sell'; showBuy(); });
  document.querySelectorAll('[data-asset]').forEach(b => (b as HTMLElement).onclick = () => { buyAsset = (b as HTMLElement).dataset.asset!; showBuy(); });
  const go2 = $('#buyGo');
  if (go2) go2.onclick = () => {
    const amt = (($('#buyAmt') as HTMLInputElement).value || '').trim();
    if (!amt || !(parseFloat(amt) > 0)) { showBuy('Enter an amount first.'); return; }
    const q = new URLSearchParams({ apiKey: key, theme: 'dark' });
    let url: string;
    if (buyMode === 'buy') { q.set('currencyCode', asset.code); q.set('walletAddress', addr); q.set('baseCurrencyCode', 'usd'); q.set('baseCurrencyAmount', amt); url = 'https://buy.moonpay.com?' + q.toString(); }
    else { q.set('baseCurrencyCode', asset.code); q.set('baseCurrencyAmount', amt); q.set('quoteCurrencyCode', 'usd'); q.set('refundWalletAddress', addr); url = 'https://sell.moonpay.com?' + q.toString(); }
    window.open(url, '_blank');
  };
}

// ---------- encrypted backup file ----------
function exportBackup() {
  const blob = getVault(); if (!blob) return;
  const d = new Date(); const stamp = `${d.getFullYear()}${String(d.getMonth() + 1).padStart(2, '0')}${String(d.getDate()).padStart(2, '0')}`;
  // Audit M-5: the passkey PRF wrap of the password is device-bound
  // credential material — it is NEVER exported. The restoring device
  // re-enables passkey unlock itself.
  const file = { app: 'syn-wallet', kind: 'syn-wallet-backup', v: 2, createdAt: Date.now(), vault: blob, config: { ...config, passkey: null } };
  const url = URL.createObjectURL(new Blob([JSON.stringify(file, null, 2)], { type: 'application/json' }));
  const a = document.createElement('a'); a.href = url; a.download = `syn-wallet-backup-${stamp}.json`; document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 4000);
}
function pickBackupFile(onErr: (msg: string) => void) {
  const inp = document.createElement('input'); inp.type = 'file'; inp.accept = '.json,application/json';
  inp.onchange = async () => {
    const f = inp.files?.[0]; if (!f) return;
    try {
      const j = JSON.parse(await f.text());
      if (!j || j.kind !== 'syn-wallet-backup' || !j.vault || j.vault.v !== 1 || typeof j.vault.ct !== 'string' || typeof j.vault.iv !== 'string' || typeof j.vault.salt !== 'string') throw new Error('bad file');
      // Audit H-3 (2026-11-19): tear the live session down BEFORE the
      // imported vault lands. The old flow wrote the new vault while
      // the previous wallet stayed decrypted in memory — the next
      // persistPayload() then overwrote the import with the OLD wallet.
      clearSessionSecrets();
      // Audit M-6: the previous wallet's financial history (local tx
      // records, portfolio snapshots, caches, counterparties) and its
      // throttle counters do not survive onto the imported wallet.
      for (const k of [DATA_CACHE_KEY, LOCALTX_KEY, SNAPS_KEY, OHLC_CACHE_KEY, COUNTERPARTY_KEY]) { try { localStorage.removeItem(k); } catch { /* ignore */ } }
      clearAuthFailures('unlock'); clearAuthFailures('reveal');
      localStorage.setItem(VAULT_KEY, JSON.stringify(j.vault));
      localStorage.removeItem(META_KEY);
      if (j.config && typeof j.config === 'object') {
        // Audit M-5 / NEW MEDIUM: imported config passes through
        // loadConfig's sanitisers (networks, RPC overrides, tokens,
        // explorer prefixes all re-validated), and a file's passkey
        // wrap is never adopted — it belongs to another device.
        localStorage.setItem(CONFIG_KEY, JSON.stringify({ ...j.config, passkey: null })); loadConfig();
      } else {
        localStorage.removeItem(CONFIG_KEY); loadConfig();
      }
      shellMounted = false; navStack = []; navIdx = -1; currentRoute = '';
      showUnlock('Backup restored. Enter the password that was set when the backup was made.');
    } catch { onErr('That file is not a valid Syn Wallet backup.'); }
  };
  inp.click();
}

// ---------- passkey unlock (WebAuthn PRF wraps a copy of the password) ----------
function b64urlEncode(data: ArrayBuffer | Uint8Array): string { const b = data instanceof Uint8Array ? data : new Uint8Array(data); let s = ''; for (const x of b) s += String.fromCharCode(x); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
function b64urlDecode(s: string): Uint8Array { const t = s.replace(/-/g, '+').replace(/_/g, '/'); const pad = t + '='.repeat((4 - (t.length % 4)) % 4); const bin = atob(pad); const out = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i); return out; }
async function passkeyPrfAvailable(): Promise<boolean> {
  try { return !!window.PublicKeyCredential && !!(await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()); } catch { return false; }
}
async function prfGet(credId: Uint8Array, salt: Uint8Array): Promise<Uint8Array | null> {
  try {
    const a = await navigator.credentials.get({ publicKey: { challenge: crypto.getRandomValues(new Uint8Array(32)), rpId: location.hostname, allowCredentials: [{ type: 'public-key', id: credId as BufferSource }], userVerification: 'required', extensions: { prf: { eval: { first: salt as BufferSource } } } as any } }) as PublicKeyCredential | null;
    const first = (a?.getClientExtensionResults() as any)?.prf?.results?.first;
    return first ? new Uint8Array(first) : null;
  } catch { return null; }
}
async function enablePasskey(): Promise<string | null> {
  if (!appPassword) return 'Unlock the wallet first.';
  if (!window.PublicKeyCredential) return 'Not supported on this device/browser.';
  const salt = crypto.getRandomValues(new Uint8Array(32));
  try {
    const cred = await navigator.credentials.create({ publicKey: { challenge: crypto.getRandomValues(new Uint8Array(32)), rp: { name: 'Syn Wallet', id: location.hostname }, user: { id: crypto.getRandomValues(new Uint8Array(16)), name: 'syn-wallet', displayName: 'Syn Wallet' }, pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }], authenticatorSelection: { authenticatorAttachment: 'platform', userVerification: 'required', residentKey: 'required' }, extensions: { prf: { eval: { first: salt as BufferSource } } } as any } }) as PublicKeyCredential | null;
    if (!cred) return 'Passkey creation was cancelled.';
    let prf = (cred.getClientExtensionResults() as any)?.prf?.results?.first as ArrayBuffer | undefined;
    let prfBytes: Uint8Array | null = prf ? new Uint8Array(prf) : null;
    if (!prfBytes) prfBytes = await prfGet(new Uint8Array(cred.rawId), salt);
    if (!prfBytes) return 'This device/browser does not support passkey encryption (PRF), so passkey unlock stays off. Your password is unaffected.';
    const wrap = await wrapWithRawKey(appPassword, prfBytes);
    config.passkey = { credId: b64urlEncode(cred.rawId), salt: b64urlEncode(salt), wrap }; saveConfig();
    return null;
  } catch (e: any) { return 'Passkey setup failed on this device/browser: ' + (e?.message || 'unsupported'); }
}
async function tryPasskeyUnlock(): Promise<string | null> {
  const pk = config.passkey; if (!pk) return 'Passkey unlock is not set up on this device.';
  // Audit M-3: the passkey path respects — and feeds — the same
  // persisted failure throttle as the password path (it used to bypass
  // throttling entirely).
  const waitLeft = authWaitRemaining('unlock');
  if (waitLeft > 0) return `Too many failed attempts — wait ${Math.ceil(waitLeft / 1000)}s and try again.`;
  const prf = await prfGet(b64urlDecode(pk.credId), b64urlDecode(pk.salt));
  if (!prf) return 'Passkey unlock was cancelled or is unavailable here.';
  let pw: string;
  try { pw = await unwrapWithRawKey(pk.wrap, prf); } catch { noteAuthFailure('unlock'); return 'That passkey does not match this vault — use your password.'; }
  const ok = await unlockWithPassword(pw);
  if (!ok) noteAuthFailure('unlock');
  return ok ? null : 'The passkey no longer matches this vault (password changed?). Use your password, then re-enable passkey unlock in Settings.';
}


// ---------- no service worker (owner's order) ----------
// Syn Wallet has NO service worker, exactly like the other Syn projects:
// the server is the single source of truth, index.html and every
// non-hashed asset are served no-cache, and a fresh index always names
// the current hashed bundles — so no client can ever sit on a stale
// version again. (The old v1–v7 workers + build-mismatch update pill
// existed only to fight that staleness; /sw.js is now a self-destructing
// kill-switch that purges their caches and unregisters itself.)
// One-time boot mop-up for anything a fresh-loaded page still finds
// registered: unregister + delete all caches, fire-and-forget. It never
// blocks boot and never reloads the page.
function purgeLegacyServiceWorker() {
  if (!('serviceWorker' in navigator)) return;
  void (async () => {
    try { const reg = await navigator.serviceWorker.getRegistration(); if (reg) await reg.unregister(); } catch { /* best-effort */ }
    try { const ks = await caches.keys(); await Promise.all(ks.map(k => caches.delete(k))); } catch { /* best-effort */ }
  })();
}

// ---------- boot ----------
// Hardened after the 2026-11-19 eternal-splash incident: every step
// is isolated so a failure degrades that step instead of killing the
// Self-update: when a new build ships while the app sits open (the
// common case on a phone), the next return to the tab reloads it
// once, so what's on screen is always the current release. The
// check compares /api/health's build stamp against the one seen at
// boot; it never interrupts typing or an open sheet — it simply
// retries on the next return.
let bootedBuild = '';
let lastUpdateCheck = 0;
async function fetchBuildStamp(): Promise<string> {
  try { const r = await fetch('/api/health', { cache: 'no-store' }); const j = await r.json(); return String(j?.build || ''); } catch { return ''; }
}
async function checkForUpdate() {
  const now = Date.now();
  if (!bootedBuild || now - lastUpdateCheck < 60000) return;
  lastUpdateCheck = now;
  const b = await fetchBuildStamp();
  if (!b || b === bootedBuild) return;
  const ae = document.activeElement;
  const typing = !!ae && (ae.tagName === 'INPUT' || ae.tagName === 'TEXTAREA');
  if (typing || document.querySelector('.sheetWrap, .sheet, .modalOverlay')) return;
  location.reload();
}
void fetchBuildStamp().then(b => { bootedBuild = b; });
(window as any).__synCheckUpdate = checkForUpdate;
document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'visible') void checkForUpdate(); });
window.addEventListener('focus', () => { void checkForUpdate(); });

// boot, the current step is published on window.__synBootStep, and
// window.__synBooted is set the moment the first screen renders.
// /boot-watchdog.js (loaded before this bundle) watches those flags:
// if the bundle never runs at all it re-injects it cache-busted, and
// if boot stalls it replaces the splash with an error state — the
// splash is never the final state of a failed load again.
(async () => {
  const w = window as any;
  w.__synBootStarted = true;
  const step = (name: string) => { w.__synBootStep = name; };
  const guard = (name: string, fn: () => void) => {
    step(name);
    try { fn(); } catch (e) { console.warn('[boot] step failed:', name, e); w.__synBootError = name; }
  };
  guard('config', () => loadConfig());
  void loadFeatureCfg();
  guard('cache', () => loadDataCache());
  guard('service worker', () => purgeLegacyServiceWorker());
  // The splash lifts as soon as the first screen can compose — the
  // only wait is for the (preloaded) font to be usable, capped so a
  // slow font can never hold the boot hostage. No blind delay.
  step('fonts');
  try { await Promise.race([document.fonts.ready, new Promise(r => setTimeout(r, 300))]); } catch { /* fonts never block boot */ }
  step('first screen');
  try {
    document.getElementById('splash')?.remove();
    if (getVault()) showUnlock(); else showOnboarding();
    w.__synBooted = true;
  } catch (e) {
    // First render failed: leave __synBooted unset so the watchdog
    // names this step in its error state instead of the user staring
    // at an eternal splash or a blank page.
    console.warn('[boot] first screen failed:', e);
    w.__synBootError = 'first screen';
    document.getElementById('splash')?.remove();
  }
})();
