// Audit fix pass 2026-11-19 — regression tests for the audit findings
// whose fixes live in pure library code. Each block names the finding
// it would have caught.
import assert from 'node:assert';
import { validateCustomNetwork, sanitizeTokenText, isValidTronAddress } from '../client/lib/netvalidate.js';
import { isSafeMediaUrl, safeMediaUrl, mediaCandidates } from '../client/lib/nfts.js';
import { buildNamespaces, type WcAccounts } from '../client/lib/walletconnect.js';
import { parseRawAmount, verifyLifiEvmTx, solSwapVerdict } from '../client/lib/swap.js';
import { iconHTML } from '../client/lib/icons.js';
import { MIN_PASSWORD_LENGTH, encryptVault, decryptVault } from '../client/lib/wallet.js';

// ---------- NEW HIGH / NEW MEDIUM: token + network text sanitisation ----------
assert.equal(sanitizeTokenText('<script>alert(1)</script>', 'symbol'), null, 'markup symbol must be rejected');
assert.equal(sanitizeTokenText('USDC', 'symbol'), 'USDC');
assert.equal(sanitizeTokenText('Way Too Long Symbol', 'symbol'), null, 'symbol over 12 chars rejected');
assert.equal(sanitizeTokenText('Evil<b>Token', 'name'), 'EvilbToken', 'angle brackets stripped from names');
assert.equal(sanitizeTokenText('Normal Token', 'name'), 'Normal Token');
assert.equal(sanitizeTokenText(42, 'name'), null, 'non-string rejected');
assert.equal(validateCustomNetwork({ name: 'Bad<Chain>', rpc: 'https://rpc.example', chainId: 1, symbol: 'ETH', explorer: '' }, 1), 'Network name: letters, numbers and spaces only (max 32 characters).');
assert.equal(validateCustomNetwork({ name: 'x'.repeat(33), rpc: 'https://rpc.example', chainId: 1, symbol: 'ETH', explorer: '' }, 1), 'Network name: letters, numbers and spaces only (max 32 characters).');
assert.equal(validateCustomNetwork({ name: 'Good Chain', rpc: 'https://rpc.example', chainId: 1, symbol: 'ETH', explorer: '' }, 1), null);
assert.equal(validateCustomNetwork({ name: 'Good Chain', rpc: 'http://rpc.example', chainId: 1, symbol: 'ETH', explorer: '' }, 1), 'RPC URL must start with https://');
console.log('AUDIT: text sanitisation PASSED');

// ---------- M-7: TRON Base58Check ----------
assert.equal(isValidTronAddress('TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t'), true, 'USDT contract address is a valid TRON address');
assert.equal(isValidTronAddress('TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6u'), false, 'one-char typo breaks the checksum');
assert.equal(isValidTronAddress('0x52908400098527886E0F7030069857D2E4169EE7'), false, 'EVM address is not a TRON address');
assert.equal(isValidTronAddress(''), false);
console.log('AUDIT: tron checksum PASSED');

// ---------- H-6 class / NEW MEDIUM: media URL allowlist ----------
assert.equal(isSafeMediaUrl('https://cdn.example/x.png'), true);
assert.equal(isSafeMediaUrl('http://cdn.example/x.png'), false, 'plain http media refused');
assert.equal(isSafeMediaUrl('javascript:alert(1)'), false);
assert.equal(isSafeMediaUrl('data:text/html;base64,PHNjcmlwdD4='), false);
assert.equal(isSafeMediaUrl('data:image/svg+xml;base64,PHN2Zz4='), false, 'SVG data URLs are script-capable — refused');
assert.equal(isSafeMediaUrl('data:image/png;base64,iVBORw0KGgo='), true, 'raster data URLs allowed');
assert.equal(isSafeMediaUrl('https://user:pass@cdn.example/x.png'), false, 'embedded credentials refused');
assert.equal(isSafeMediaUrl('https://cdn.example/a|b.png'), false, 'pipe refused (candidate-list separator)');
assert.equal(isSafeMediaUrl('ipfs://QmXyz/art.png'), false, 'raw ipfs: URIs are not themselves loadable — they must be rewritten first');
assert.ok(safeMediaUrl('ipfs://QmXyz/art.png').startsWith('https://'), 'safeMediaUrl rewrites ipfs to an https gateway');
assert.deepEqual(mediaCandidates('javascript:alert(1)'), []);
assert.deepEqual(mediaCandidates('http://192.168.1.1/x.png'), [], 'LAN http refused');
console.log('AUDIT: media allowlist PASSED');

// ---------- H-5: WalletConnect exact grant ----------
const acc: WcAccounts = { evmAddress: '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266', solAddress: 'oeYf6Kc3xYhzrYq8Zc5v8Zc5v8Zc5v8Zc5v8Zc5v8Zc5v8Z', evmChainIds: [1, 137] };
const noMethods = buildNamespaces({ params: { requiredNamespaces: { eip155: { chains: ['eip155:1'], methods: [], events: [] } } } }, acc);
assert.deepEqual(noMethods.namespaces.eip155?.methods ?? [], [], 'a proposal naming NO methods must be granted NO methods (was: the full hard-coded list)');
const withSign = buildNamespaces({ params: { requiredNamespaces: { eip155: { chains: ['eip155:1'], methods: ['eth_sendTransaction', 'eth_sign'], events: [] } } } }, acc);
assert.deepEqual(withSign.namespaces.eip155.methods, ['eth_sendTransaction'], 'eth_sign is never granted');
assert.ok(withSign.granted.refusedMethods.includes('eth_sign'), 'refused methods are surfaced for the approval sheet');
const optSplit = buildNamespaces({ params: {
  requiredNamespaces: { eip155: { chains: ['eip155:1'], methods: ['personal_sign'], events: [] } },
  optionalNamespaces: { eip155: { chains: ['eip155:137'], methods: ['eth_sendTransaction'], events: [] } },
} }, acc);
assert.deepEqual(optSplit.granted.required.eip155.methods, ['personal_sign']);
assert.deepEqual(optSplit.granted.optional.eip155.methods, ['eth_sendTransaction'], 'optional stays labelled optional, not merged into required');
console.log('AUDIT: wc exact grant PASSED');

// ---------- H-4: exact amount parsing ----------
assert.equal(parseRawAmount('0.97277447', 18), 972774470000000000n);
assert.equal(parseRawAmount('1', 6), 1000000n);
assert.equal(parseRawAmount('0.000000001', 9), 1n);
assert.equal(parseRawAmount('1.0000000001', 9), null, 'more precision than the token has is refused, not rounded');
assert.equal(parseRawAmount('-1', 9), null);
assert.equal(parseRawAmount('1e3', 9), null, 'exponent notation refused');
assert.equal(parseRawAmount('', 9), null);
console.log('AUDIT: exact amounts PASSED');

// ---------- H-1: LI.FI built-tx verification ----------
const RECIP = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';
const TOKEN = '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48';
const ROUTER = '0x1231DEB6f5749EF6cE6943a275A1D3E7486F4EaE';
const exp = { fromChainId: 1, fromToken: TOKEN, fromAmountRaw: '1000000', toAddress: RECIP, approvalAddress: ROUTER };
const goodData = '0x12345678' + '000000000000000000000000' + TOKEN.slice(2).toLowerCase() + '000000000000000000000000' + RECIP.slice(2).toLowerCase();
assert.equal(verifyLifiEvmTx({ to: ROUTER, chainId: 1, value: '0', data: goodData }, exp), null, 'a faithful built tx verifies');
assert.ok(verifyLifiEvmTx({ to: '0x000000000000000000000000000000000000dEaD', chainId: 1, value: '0', data: goodData }, exp), 'wrong destination refused');
assert.ok(verifyLifiEvmTx({ to: ROUTER, chainId: 137, value: '0', data: goodData }, exp), 'wrong chain refused');
assert.ok(verifyLifiEvmTx({ to: ROUTER, chainId: 1, value: '5', data: goodData }, exp), 'native value attached to a token swap refused');
assert.ok(verifyLifiEvmTx({ to: ROUTER, chainId: 1, value: '0', data: '0xa9059cbb' + goodData.slice(10) }, exp), 'bare transfer selector refused');
const expNative = { fromChainId: 1, fromToken: '0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE', fromAmountRaw: '1000', toAddress: RECIP, approvalAddress: ROUTER };
assert.ok(verifyLifiEvmTx({ to: ROUTER, chainId: 1, value: '999', data: goodData }, expNative), 'native amount mismatch refused');
assert.equal(verifyLifiEvmTx({ to: ROUTER, chainId: 1, value: '1000', data: goodData }, expNative), null);
console.log('AUDIT: lifi tx verification PASSED');

// ---------- H-1: Solana swap simulation verdict ----------
const OWNER = 'Owner1111111111111111111111111111111111111';
const IN = 'InMint111111111111111111111111111111111111';
const OUT = 'OutMint11111111111111111111111111111111111';
const bal = (mint: string, amount: string) => ({ mint, owner: OWNER, uiTokenAmount: { amount } });
assert.equal(solSwapVerdict({ preTokenBalances: [bal(IN, '5000'), bal(OUT, '0')], postTokenBalances: [bal(IN, '4000'), bal(OUT, '900')] }, OWNER, IN, OUT, '1000', '900'), null, 'exact-in and min-out met');
assert.ok(solSwapVerdict({ preTokenBalances: [bal(IN, '5000')], postTokenBalances: [bal(IN, '4500')] }, OWNER, IN, OUT, '1000', '0'), 'input delta must equal the reviewed amount exactly');
assert.ok(solSwapVerdict({ preTokenBalances: [bal(IN, '5000'), bal(OUT, '0')], postTokenBalances: [bal(IN, '4000'), bal(OUT, '800')] }, OWNER, IN, OUT, '1000', '900'), 'output below the reviewed minimum refused');
assert.ok(solSwapVerdict({ err: { InstructionError: [0, 'x'] } }, OWNER, IN, OUT, '1000', '0'), 'simulation error refused');
console.log('AUDIT: solana swap verdict PASSED');

// ---------- NEW LOW 3: icon URL escaping/validation ----------
assert.ok(!iconHTML('https://x.example/a.png" onerror="alert(1)', 'ETH', 'Ethereum').includes('onerror'), 'icon URL cannot break out of the src attribute');
assert.ok(iconHTML('/assets/coins/eth.png', 'ETH', 'Ethereum').includes('/assets/coins/eth.png'), 'same-origin icon paths still render');
console.log('AUDIT: icon escaping PASSED');

// ---------- M-4: new-password length floor ----------
// The audit recommended a 12-character minimum for new passwords.
// The user explicitly overrode that on 2026-11-19 ("Keep the 8
// character passwords"), so this test pins the floor at 8 — the
// override is deliberate, not a regression. The floor lives in the
// lib constant the set-password screen enforces; the vault layer
// itself never had a length check, so existing passwords of any
// length still unlock, and an 8-character password round-trips.
assert.equal(MIN_PASSWORD_LENGTH, 8, 'user override of M-4: new-password floor is 8, not the audit-recommended 12');
const pwBlob = await encryptVault('{"v":2,"wallets":[]}', '12345678');
assert.equal(await decryptVault(pwBlob, '12345678'), '{"v":2,"wallets":[]}', 'an 8-character password encrypts and decrypts the vault');
console.log('AUDIT: password floor (M-4, user override to 8) PASSED');

console.log('ALL AUDIT TESTS PASSED');
