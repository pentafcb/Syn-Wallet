// WalletConnect v2 (Reown) — Wave 2, GATED ON A PROJECT ID.
// @walletconnect/sign-client cannot initialise without a project ID,
// and a project ID is the operator's own free Reown credential — it is
// never hardcoded. The server exposes it at /api/config from the
// WALLETCONNECT_PROJECT_ID environment variable; with no ID configured
// the Connect screen explains exactly that and pairing stays disabled.
// When an ID exists, the full flow below runs: pair by URI, review the
// session proposal, approve/reject, then every session request is
// routed through the wallet's clear-signing screens in main.ts — this
// module never signs anything itself.
//
// The pure helpers (namespace building, request classification,
// parameter decoding) are unit-tested; the SDK is loaded lazily via
// dynamic import so it never weighs down the main bundle.

export const WC_SOLANA_CHAIN = 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp';
export const WC_EVM_METHODS = ['eth_sendTransaction', 'eth_signTransaction', 'personal_sign', 'eth_sign', 'eth_signTypedData', 'eth_signTypedData_v4'];
export const WC_SOL_METHODS = ['solana_signTransaction', 'solana_signAndSendTransaction', 'solana_signMessage', 'solana_signAllTransactions'];
export const WC_EVENTS = ['accountsChanged', 'chainChanged'];
// Audit H-5 (2026-11-19): methods this wallet will ever GRANT. eth_sign
// is deliberately absent — it signs an opaque hash with no prefix
// separation and the app's own clean note already refuses unprefixed
// eth_sign; a dApp asking for it gets every other requested method and
// a visible note, never the grant.
const WC_EVM_GRANTABLE = WC_EVM_METHODS.filter(m => m !== 'eth_sign');
const WC_SOL_GRANTABLE = [...WC_SOL_METHODS];

export interface WcAccounts { evmAddress: string; solAddress: string; evmChainIds: number[]; }

/**
 * Build session namespaces from a proposal. Only chains/accounts this
 * wallet can actually serve are granted; anything required but
 * unsupported is reported in `problems` so the UI can refuse honestly
 * instead of approving a session it cannot honour.
 */
export interface WcGrantSummary { required: Record<string, { chains: string[]; methods: string[] }>; optional: Record<string, { chains: string[]; methods: string[] }>; refusedMethods: string[]; }
export function buildNamespaces(proposal: any, acc: WcAccounts): { namespaces: Record<string, any>; problems: string[]; granted: WcGrantSummary } {
  const params = proposal?.params || {};
  const required = params.requiredNamespaces || {};
  const optional = params.optionalNamespaces || {};
  // Audit H-5: required and optional stay distinguishable end to end —
  // the approval sheet shows both, and nothing optional is silently
  // merged into the required grant.
  const merge = (src: any) => {
    const out: Record<string, { chains: string[]; methods: string[]; events: string[] }> = {};
    if (!src || typeof src !== 'object') return out;
    for (const [k, v] of Object.entries<any>(src)) {
      if (!out[k]) out[k] = { chains: [], methods: [], events: [] };
      for (const c of (v?.chains || [])) if (!out[k].chains.includes(c)) out[k].chains.push(c);
      for (const m of (v?.methods || [])) if (!out[k].methods.includes(m)) out[k].methods.push(m);
      for (const e of (v?.events || [])) if (!out[k].events.includes(e)) out[k].events.push(e);
    }
    return out;
  };
  const reqSpec = merge(required);
  const optSpec = merge(optional);
  const namespaces: Record<string, any> = {};
  const problems: string[] = [];
  const granted: WcGrantSummary = { required: {}, optional: {}, refusedMethods: [] };
  const keys = [...new Set([...Object.keys(reqSpec), ...Object.keys(optSpec)])];
  for (const key of keys) {
    const isRequired = key in reqSpec;
    const grantable = key === 'eip155' ? WC_EVM_GRANTABLE : key === 'solana' ? WC_SOL_GRANTABLE : null;
    // EXACT grant (audit H-5): only methods the dApp actually asked for,
    // intersected with what this wallet will ever grant. An unspecified
    // method list grants NOTHING — never the full hard-coded list.
    const pickMethods = (spec: { methods: string[] } | undefined): string[] => {
      if (!spec || !grantable) return [];
      const out: string[] = [];
      for (const m of spec.methods) {
        if (grantable.includes(m)) { if (!out.includes(m)) out.push(m); }
        else if (!granted.refusedMethods.includes(m)) granted.refusedMethods.push(m);
      }
      return out;
    };
    const pickChains = (spec: { chains: string[] } | undefined): string[] => {
      if (!spec) return [];
      if (key === 'eip155') return spec.chains.filter(c => acc.evmChainIds.includes(Number(c.split(':')[1])));
      if (key === 'solana') return spec.chains.filter(c => c === WC_SOLANA_CHAIN);
      return [];
    };
    const reqChains = pickChains(reqSpec[key]);
    const optChains = pickChains(optSpec[key]).filter(c => !reqChains.includes(c));
    const reqMethods = pickMethods(reqSpec[key]);
    const optMethods = pickMethods(optSpec[key]).filter(m => !reqMethods.includes(m));
    if (key === 'eip155') {
      if (!acc.evmAddress) { if (isRequired) problems.push('This wallet has no EVM account for the requested Ethereum session.'); continue; }
      if (!reqChains.length && !optChains.length) { if (isRequired) problems.push('None of the requested EVM networks are enabled in this wallet.'); continue; }
      const chains = [...reqChains, ...optChains];
      const events = [...(reqSpec[key]?.events || []), ...(optSpec[key]?.events || [])].filter(e => WC_EVENTS.includes(e));
      namespaces.eip155 = {
        accounts: chains.map(c => `${c}:${acc.evmAddress}`),
        chains,
        methods: [...reqMethods, ...optMethods],
        events: events.length ? [...new Set(events)] : WC_EVENTS,
      };
      granted.required.eip155 = { chains: reqChains, methods: reqMethods };
      granted.optional.eip155 = { chains: optChains, methods: optMethods };
    } else if (key === 'solana') {
      if (!acc.solAddress) { if (isRequired) problems.push('This wallet has no Solana account for the requested session.'); continue; }
      if (!reqChains.length && !optChains.length) { if (isRequired) problems.push('Only Solana mainnet sessions are supported.'); continue; }
      const chains = [...reqChains, ...optChains];
      const events = [...(reqSpec[key]?.events || []), ...(optSpec[key]?.events || [])].filter(e => WC_EVENTS.includes(e));
      namespaces.solana = {
        accounts: chains.map(c => `${c}:${acc.solAddress}`),
        chains,
        methods: [...reqMethods, ...optMethods],
        events: events.length ? [...new Set(events)] : WC_EVENTS,
      };
      granted.required.solana = { chains: reqChains, methods: reqMethods };
      granted.optional.solana = { chains: optChains, methods: optMethods };
    } else if (isRequired) {
      problems.push(`Unsupported session namespace requested: ${key}`);
    }
  }
  if (!Object.keys(namespaces).length && !problems.length) problems.push('The proposal asks for nothing this wallet can serve.');
  return { namespaces, problems, granted };
}

export type WcRequestKind = 'evm-send' | 'evm-sign-tx' | 'sign-message' | 'sign-typed' | 'sol-sign-tx' | 'sol-sign-send' | 'sol-sign-message' | 'sol-sign-all' | 'unsupported';
export function classifyRequest(method: string): WcRequestKind {
  switch (method) {
    case 'eth_sendTransaction': return 'evm-send';
    case 'eth_signTransaction': return 'evm-sign-tx';
    case 'personal_sign': case 'eth_sign': return 'sign-message';
    case 'eth_signTypedData': case 'eth_signTypedData_v4': return 'sign-typed';
    case 'solana_signTransaction': return 'sol-sign-tx';
    case 'solana_signAndSendTransaction': return 'sol-sign-send';
    case 'solana_signMessage': return 'sol-sign-message';
    case 'solana_signAllTransactions': return 'sol-sign-all';
    default: return 'unsupported';
  }
}

export interface WcEvmTx { from: string; to: string; value: string; data: string; gas: string; }
export function parseWcEvmTx(params: any): WcEvmTx | null {
  const t = Array.isArray(params) ? params[0] : null;
  if (!t || typeof t !== 'object') return null;
  const s = (v: any) => (typeof v === 'string' ? v : '');
  return { from: s(t.from), to: s(t.to), value: s(t.value) || '0x0', data: s(t.data) || '0x', gas: s(t.gas) || s(t.gasLimit) };
}

export interface DecodedErc20Call {
  kind: 'approve' | 'transfer' | 'transferFrom' | 'setApprovalForAll';
  spender?: string; to?: string; from?: string; operator?: string;
  amount?: bigint; approved?: boolean;
}
/**
 * Decode the ERC-20 / ERC-721 calls a dApp most commonly asks a wallet
 * to sign, so the review screen can show exactly what the call does
 * instead of raw calldata. Anything else (or malformed data) returns
 * null and the review falls back to its generic contract-call warning.
 * Addresses are returned lowercase; amounts as raw base-unit bigints.
 */
export function decodeErc20Call(data: string): DecodedErc20Call | null {
  if (typeof data !== 'string') return null;
  const h = data.replace(/^0x/, '');
  if (!/^[0-9a-fA-F]+$/.test(h) || h.length < 8) return null;
  const sel = h.slice(0, 8).toLowerCase();
  const word = (i: number): string | null => {
    const w = h.slice(8 + i * 64, 8 + (i + 1) * 64);
    return w.length === 64 ? w : null;
  };
  const addr = (i: number): string | null => {
    const w = word(i); if (!w) return null;
    return '0x' + w.slice(24).toLowerCase();
  };
  const uint = (i: number): bigint | null => {
    const w = word(i); if (!w) return null;
    try { return BigInt('0x' + w); } catch { return null; }
  };
  if (sel === '095ea7b3') { // approve(address spender, uint256 amount)
    const spender = addr(0); const amount = uint(1);
    if (!spender || amount === null) return null;
    return { kind: 'approve', spender, amount };
  }
  if (sel === 'a9059cbb') { // transfer(address to, uint256 amount)
    const to = addr(0); const amount = uint(1);
    if (!to || amount === null) return null;
    return { kind: 'transfer', to, amount };
  }
  if (sel === '23b872dd') { // transferFrom(address from, address to, uint256 amount)
    const from = addr(0); const to = addr(1); const amount = uint(2);
    if (!from || !to || amount === null) return null;
    return { kind: 'transferFrom', from, to, amount };
  }
  if (sel === 'a22cb465') { // setApprovalForAll(address operator, bool approved)
    const operator = addr(0); const flag = uint(1);
    if (!operator || flag === null) return null;
    return { kind: 'setApprovalForAll', operator, approved: flag !== 0n };
  }
  return null;
}

function hexToUtf8(hex: string): string | null {
  try {
    const h = hex.replace(/^0x/, '');
    if (!/^[0-9a-fA-F]*$/.test(h) || h.length % 2) return null;
    const bytes = new Uint8Array(h.length / 2);
    for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    return text;
  } catch { return null; }
}
/** Decode a personal_sign / eth_sign payload into displayable text. */
export function decodeWcSignMessage(method: string, params: any): { text: string; raw: string; address: string } {
  const arr = Array.isArray(params) ? params : [];
  // personal_sign: [message, address]; eth_sign: [address, message]
  const message = method === 'eth_sign' ? arr[1] : arr[0];
  const address = method === 'eth_sign' ? arr[0] : arr[1];
  const raw = typeof message === 'string' ? message : '';
  const text = raw.startsWith('0x') ? (hexToUtf8(raw) ?? raw) : raw;
  return { text, raw, address: typeof address === 'string' ? address : '' };
}

// ---------- SDK wrapper (browser only; loaded on demand) ----------
export interface WcHandlers {
  onProposal: (proposal: any) => void;
  onRequest: (event: any) => void;
  onSessionDelete?: () => void;
}
let client: any = null;
let initPromise: Promise<any> | null = null;
export function wcClientReady(): boolean { return !!client; }
export function wcInit(projectId: string, handlers: WcHandlers): Promise<any> {
  if (client) return Promise.resolve(client);
  // One init at a time, shared by every caller. The dynamic import and
  // SignClient.init can both stall indefinitely on a bad connection
  // (a chunk download that never finishes, a wedged SDK storage read) —
  // the promise then simply never settles, and the UI layer owns the
  // timeout + retry UX. Memoising the in-flight promise means a retry
  // never starts a second, competing init; a REJECTED init clears the
  // memo so the next call genuinely tries again.
  if (initPromise) return initPromise;
  initPromise = (async () => {
    const { SignClient } = await import('@walletconnect/sign-client');
    const c = await SignClient.init({
      projectId,
      // The SDK ships a telemetry/event client (pulse.walletconnect.org).
      // It stays off unless enabled in this SDK version, and we pin it
      // OFF explicitly: this wallet sends no analytics or telemetry.
      telemetryEnabled: false,
      metadata: { name: 'Syn Wallet', description: 'Syn Wallet — non-custodial multi-chain wallet', url: location.origin, icons: [location.origin + '/assets/logo.png'] },
    });
    c.on('session_proposal', handlers.onProposal);
    c.on('session_request', handlers.onRequest);
    if (handlers.onSessionDelete) c.on('session_delete', handlers.onSessionDelete);
    client = c;
    return c;
  })();
  initPromise.catch(() => { initPromise = null; });
  return initPromise;
}
// Audit fix: the lazy @walletconnect/utils import in the reject /
// disconnect paths had no timeout — on a stalled chunk download the
// review sheet hung forever on Reject/Disconnect. Race it; callers
// treat these as best-effort and surface the timeout as a failure.
const WC_UTILS_TIMEOUT_MS = 15000;
async function wcUtils(): Promise<any> {
  return Promise.race([
    import('@walletconnect/utils'),
    new Promise((_, rej) => setTimeout(() => rej(new Error('WalletConnect utilities did not load in time.')), WC_UTILS_TIMEOUT_MS)),
  ]);
}
export async function wcPair(uri: string): Promise<void> {
  if (!client) throw new Error('WalletConnect is not initialised.');
  await client.pair({ uri });
}
export async function wcApprove(id: number, namespaces: Record<string, any>): Promise<void> {
  if (!client) throw new Error('WalletConnect is not initialised.');
  await client.approve({ id, namespaces });
}
export async function wcReject(id: number): Promise<void> {
  if (!client) return;
  const { getSdkError } = await wcUtils();
  await client.reject({ id, reason: getSdkError('USER_REJECTED') });
}
export async function wcRespond(topic: string, id: number, result: any): Promise<void> {
  if (!client) throw new Error('WalletConnect is not initialised.');
  await client.respond({ topic, response: { id, result, jsonrpc: '2.0' } });
}
export async function wcRejectRequest(topic: string, id: number): Promise<void> {
  if (!client) return;
  const { getSdkError } = await wcUtils();
  await client.respond({ topic, response: { id, error: getSdkError('USER_REJECTED'), jsonrpc: '2.0' } });
}
export function wcSessions(): any[] {
  try { return client ? client.session.getAll() : []; } catch { return []; }
}
export async function wcDisconnect(topic: string): Promise<void> {
  if (!client) return;
  const { getSdkError } = await wcUtils();
  await client.disconnect({ topic, reason: getSdkError('USER_DISCONNECTED') });
}

/**
 * Audit M-10 (2026-11-19): the SDK keeps its own storage (localStorage
 * `wc@2:*` keys + the `walletconnect.db` IndexedDB) OUTSIDE the vault.
 * On wallet wipe that storage must go too: disconnect every session,
 * drop every wc@2 key and delete the database. On plain lock the
 * sessions intentionally survive (same as every major wallet — a
 * locked wallet keeps its pairings; the keys that could USE them stay
 * inside the encrypted vault), which is the documented residual.
 */
export async function wcWipeStorage(): Promise<void> {
  try {
    for (const s of wcSessions()) { try { await wcDisconnect(s.topic); } catch { /* best effort */ } }
  } catch { /* best effort */ }
  try {
    for (const store of [localStorage, sessionStorage]) {
      const keys: string[] = [];
      for (let i = 0; i < store.length; i++) { const k = store.key(i); if (k && k.startsWith('wc@2:')) keys.push(k); }
      keys.forEach(k => store.removeItem(k));
    }
  } catch { /* storage unavailable */ }
  try {
    await new Promise<void>(resolve => {
      const req = indexedDB.deleteDatabase('walletconnect.db');
      req.onsuccess = () => resolve(); req.onerror = () => resolve(); req.onblocked = () => resolve();
      setTimeout(resolve, 1500);
    });
  } catch { /* no IndexedDB */ }
}
