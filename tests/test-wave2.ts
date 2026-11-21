import assert from 'node:assert';
import { ethers } from 'ethers';
import bs58 from 'bs58';
import { parseRawAmount, rawToHuman, fmtRaw, minOutFromBps, normalizeJupiterQuote, normalizeLifiQuote, LIFI_SOLANA_CHAIN_ID } from '../client/lib/swap.js';
import { parseStakeAccountBytes, parseStakeAccountParsed, sortValidators, stakeStateOf, U64_MAX, type StakeAccountInfo } from '../client/lib/stake.js';
import { rewriteMediaUrl, parseMetaplexMetadata, metadataJsonFields, normalizeBlockscoutNfts, mediaCandidates, isSpamNft } from '../client/lib/nfts.js';
import { buildNamespaces, classifyRequest, parseWcEvmTx, decodeWcSignMessage, type WcAccounts } from '../client/lib/walletconnect.js';

// ---------- swap amount math (exact, no float drift) ----------
assert.equal(parseRawAmount('1.5', 9), 1500000000n);
assert.equal(parseRawAmount('0.000000001', 9), 1n);
assert.equal(parseRawAmount('12', 6), 12000000n);
assert.equal(parseRawAmount('1.0000000001', 9), null, 'too many decimals must be rejected, not rounded');
assert.equal(parseRawAmount('abc', 9), null);
assert.equal(parseRawAmount('', 9), null);
assert.equal(parseRawAmount('-1', 9), null);
assert.equal(rawToHuman('1500000000', 9), 1.5);
assert.equal(fmtRaw('1234567', 6), '1.234567');
assert.equal(minOutFromBps('1000000', 50), '995000', '0.5% slippage floor');
assert.equal(minOutFromBps('1000000', 100), '990000');
console.log('SWAP AMOUNT MATH PASSED');

// ---------- Jupiter quote normalization (fixture shaped like the live
// lite-api response verified from sober77; priceImpactPct is a FRACTION) ----------
const jupFixture = {
  inputMint: 'So11111111111111111111111111111111111111112',
  inAmount: '1000000000',
  outputMint: 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v',
  outAmount: '74520000',
  otherAmountThreshold: '74147400',
  swapMode: 'ExactIn',
  slippageBps: 50,
  priceImpactPct: '0.00010689558640247576',
  routePlan: [{ swapInfo: { label: 'Orca' } }, { swapInfo: { label: 'Meteora' } }],
  swapUsdValue: '74.52',
};
const jq = normalizeJupiterQuote(jupFixture, '1000000000', 9, 6, 50)!;
assert.ok(jq, 'jupiter fixture must normalize');
assert.equal(jq.provider, 'jupiter');
assert.equal(jq.outHuman, 74.52);
assert.equal(jq.minOutRaw, '74147400', 'provider threshold wins when present');
assert.ok(Math.abs((jq.priceImpactPct ?? -1) - 0.010689558640247576) < 1e-12, 'fraction impact x100 -> percent');
assert.equal(jq.routeLabel, 'Orca → Meteora');
assert.equal(normalizeJupiterQuote({ outAmount: 'x' }, '1', 9, 6, 50), null, 'garbage quote rejected');
assert.equal(normalizeJupiterQuote(null, '1', 9, 6, 50), null);
console.log('JUPITER NORMALIZATION PASSED');

// ---------- LI.FI quote normalization (fixture shaped like the live
// li.quest response verified from sober77) ----------
const lifiFixture = {
  tool: 'sushiswap',
  toolDetails: { name: 'SushiSwap Aggregator' },
  estimate: {
    fromAmount: '1000000000000000000',
    toAmount: '1791440000',
    toAmountMin: '1782482800',
    fromAmountUSD: '1797.33',
    toAmountUSD: '1791.44',
    approvalAddress: '0x111111125421ca6dc452d289314280a0f8842a65',
    executionDuration: 30,
    feeCosts: [{ name: 'LI.FI fee', amount: '1797000000000000', amountUSD: '3.23', token: { symbol: 'ETH', decimals: 18 } }],
    gasCosts: [{ amount: '420000000000000', amountUSD: '0.75', token: { symbol: 'ETH', decimals: 18 } }],
  },
  includedSteps: [{ tool: 'sushiswap', toolDetails: { name: 'SushiSwap Aggregator' } }],
  transactionRequest: { to: '0x111111125421ca6dc452d289314280a0f8842a65', data: '0x1234', value: '1000000000000000000', chainId: 1 },
};
const lq = normalizeLifiQuote(lifiFixture, 18, 6)!;
assert.ok(lq, 'lifi fixture must normalize');
assert.equal(lq.provider, 'lifi');
assert.equal(lq.outHuman, 1791.44);
assert.equal(lq.minOutRaw, '1782482800');
assert.ok(lq.priceImpactPct !== null && lq.priceImpactPct > 0.3 && lq.priceImpactPct < 0.35, 'impact derived from USD estimates');
assert.equal(lq.approvalAddress, '0x111111125421ca6dc452d289314280a0f8842a65');
assert.equal(lq.etaSec, 30);
assert.ok(lq.feeLines.some(l => l.includes('LI.FI fee')), 'fee lines carry provider fees');
assert.ok(lq.feeLines.some(l => l.includes('Network fee')), 'fee lines carry gas');
assert.equal(LIFI_SOLANA_CHAIN_ID, 1151111081099710);
assert.equal(normalizeLifiQuote({ estimate: { toAmount: 'NaN' } }, 18, 6), null);
console.log('LIFI NORMALIZATION PASSED');

// ---------- Solana stake account parsing ----------
// Synthetic 200-byte delegated stake account, built to the documented
// layout: disc u32 @0, voter @124, stake u64 @156, activation @164,
// deactivation @172 (u64 max = not deactivating).
function stakeBytes(opts: { disc: number; voter?: Uint8Array; stake?: bigint; act?: bigint; deact?: bigint }): Uint8Array {
  const b = new Uint8Array(200);
  const dv = new DataView(b.buffer);
  dv.setUint32(0, opts.disc, true);
  if (opts.voter) b.set(opts.voter, 124);
  const put = (off: number, v: bigint) => { let x = v; for (let i = 0; i < 8; i++) { b[off + i] = Number(x & 255n); x >>= 8n; } };
  if (opts.stake !== undefined) put(156, opts.stake);
  if (opts.act !== undefined) put(164, opts.act);
  if (opts.deact !== undefined) put(172, opts.deact);
  return b;
}
const voterBytes = bs58.decode('Vote111111111111111111111111111111111111111');
const delegated = parseStakeAccountBytes('StakeAcct111', stakeBytes({ disc: 2, voter: voterBytes, stake: 5000000000n, act: 700n, deact: BigInt(U64_MAX) }), 5002282880)!;
assert.ok(delegated);
assert.equal(delegated.voter, 'Vote111111111111111111111111111111111111111');
assert.equal(delegated.delegatedLamports, 5000000000);
assert.equal(delegated.activationEpoch, '700');
assert.equal(delegated.deactivationEpoch, null, 'u64 max deactivation = not deactivating');
const deactivating = parseStakeAccountBytes('S2', stakeBytes({ disc: 2, voter: voterBytes, stake: 100n, act: 1n, deact: 800n }), 200)!;
assert.equal(deactivating.deactivationEpoch, '800');
const initialized = parseStakeAccountBytes('S3', stakeBytes({ disc: 1 }), 2282880)!;
assert.equal(initialized.voter, null);
assert.equal(parseStakeAccountBytes('S4', stakeBytes({ disc: 9 }), 0), null, 'unknown discriminant rejected');
assert.equal(parseStakeAccountBytes('S5', new Uint8Array(100), 0), null, 'short buffer rejected');
// jsonParsed form
const parsed = parseStakeAccountParsed('S6', 5002282880, { info: { stake: { delegation: { voter: 'Vote111111111111111111111111111111111111111', stake: '5000000000', activationEpoch: '700', deactivationEpoch: '18446744073709551615' } } } })!;
assert.equal(parsed.delegatedLamports, 5000000000);
assert.equal(parsed.deactivationEpoch, null);
assert.equal(parseStakeAccountParsed('S7', 0, null), null);
// validators + state
const vals = sortValidators({ current: [{ votePubkey: 'V1', nodePubkey: 'N1', activatedStake: '2000000000000', commission: 5 }, { votePubkey: 'V2', nodePubkey: 'N2', activatedStake: '9000000000000', commission: 0 }], delinquent: [{ votePubkey: 'V3', nodePubkey: 'N3', activatedStake: '1000000000000', commission: 100 }] }, 25);
assert.deepEqual(vals.map(v => v.votePubkey), ['V2', 'V1', 'V3'], 'stake-desc order');
assert.equal(vals[0].activatedStakeSol, 9000);
assert.equal(vals[2].delinquent, true);
const base: StakeAccountInfo = { pubkey: 'S', lamports: 1, voter: 'V', delegatedLamports: 1, activationEpoch: '1', deactivationEpoch: null };
assert.deepEqual(stakeStateOf(base, { state: 'active', active: 1, inactive: 0 }), { label: 'Active — earning rewards', canDeactivate: true, canWithdraw: false });
assert.equal(stakeStateOf({ ...base, deactivationEpoch: '9' }, { state: 'inactive', active: 0, inactive: 1 }).canWithdraw, true);
assert.equal(stakeStateOf({ ...base, voter: null }, null).canWithdraw, true);
console.log('STAKE PARSING PASSED');

// ---------- Metaplex metadata + Blockscout NFTs ----------
function borshStr(s: string): number[] { const bytes = [...Buffer.from(s, 'utf8')]; const len = bytes.length; return [len & 255, (len >> 8) & 255, (len >> 16) & 255, (len >> 24) & 255, ...bytes]; }
const metaBuf = new Uint8Array([
  4, // key = MetadataV1
  ...new Array(32).fill(7), // update authority
  ...new Array(32).fill(9), // mint
  ...borshStr('Cool Cat #1'),
  ...borshStr('COOL'),
  ...borshStr('ipfs://bafycoolcat/metadata.json'),
  ...new Array(64).fill(0), // padding the parser must tolerate
]);
const meta = parseMetaplexMetadata(metaBuf)!;
assert.ok(meta);
assert.equal(meta.name, 'Cool Cat #1');
assert.equal(meta.symbol, 'COOL');
assert.equal(meta.uri, 'ipfs://bafycoolcat/metadata.json');
assert.equal(parseMetaplexMetadata(new Uint8Array(10)), null, 'short buffer rejected');
assert.equal(rewriteMediaUrl('ipfs://bafyX/1.png'), 'https://ipfs.io/ipfs/bafyX/1.png');
assert.equal(rewriteMediaUrl('ar://abc123'), 'https://arweave.net/abc123');
assert.equal(rewriteMediaUrl('https://cdn.example.com/x.png'), 'https://cdn.example.com/x.png');
assert.equal(rewriteMediaUrl(''), '');
const fields = metadataJsonFields({ name: 'Json Name', image: 'ipfs://imghash', collection: { name: 'The Collection' }, description: 'A cat.' });
assert.equal(fields.collection, 'The Collection');
assert.equal(fields.image, 'https://ipfs.io/ipfs/imghash', 'metadataJsonFields rewrites ipfs:// to the gateway');
const evmNfts = normalizeBlockscoutNfts({ items: [
  { id: '42', image_url: 'https://img.example/42.png', metadata: { name: 'Token Forty-Two', description: 'd' }, token: { address_hash: '0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D', name: 'Bored Ape Yacht Club', type: 'ERC-721' }, token_type: 'ERC-721', value: '1' },
  { id: '7', image_url: null, metadata: null, token: { address: '0x1234567890abcdef1234567890abcdef12345678', name: 'Semi', type: 'ERC-1155' }, token_type: 'ERC-1155', value: '3' },
] }, 'ethereum');
assert.equal(evmNfts.length, 2);
assert.equal(evmNfts[0].key, 'evm:ethereum:0xbc4ca0eda7647a8ab7c2061c2e118a18a936f13d:42', 'keys carry the lowercased contract');
assert.equal(evmNfts[0].collection, 'Bored Ape Yacht Club');
assert.equal(evmNfts[1].amount, 3);
assert.equal(evmNfts[1].standard, 'ERC-1155');
// ---------- Addition 7: media candidates + spam heuristic ----------
assert.deepEqual(mediaCandidates('ipfs://QmXyz123/art.png'), ['https://ipfs.io/ipfs/QmXyz123/art.png', 'https://cloudflare-ipfs.com/ipfs/QmXyz123/art.png', 'https://dweb.link/ipfs/QmXyz123/art.png']);
assert.deepEqual(mediaCandidates('https://gateway.pinata.cloud/ipfs/QmXyz123'), ['https://ipfs.io/ipfs/QmXyz123', 'https://cloudflare-ipfs.com/ipfs/QmXyz123', 'https://dweb.link/ipfs/QmXyz123'], 'gateway URLs normalise to the candidate set');
assert.deepEqual(mediaCandidates('ar://abc123'), ['https://arweave.net/abc123']);
assert.deepEqual(mediaCandidates('data:image/svg+xml;base64,PHN2Zz4='), [], 'audit 2026-11-19: data: SVG is script-capable and no longer an allowed media URL');
assert.deepEqual(mediaCandidates('https://cdn.example/x.png'), ['https://cdn.example/x.png']);
assert.deepEqual(mediaCandidates(''), []);
assert.equal(isSpamNft({ name: '🎁10ETH Reward at eeth.lat', collection: '' }), true, 'the user\'s Polygon scam NFT is flagged');
assert.equal(isSpamNft({ name: 'UNI Airdrop Pass', collection: '$UNI AIRDROP' }), true, 'the user\'s Base scam NFT is flagged');
assert.equal(isSpamNft({ name: 'Visit claim-portal.xyz to mint', collection: '' }), true);
assert.equal(isSpamNft({ name: 'Bored Ape #4213', collection: 'Bored Ape Yacht Club' }), false);
assert.equal(isSpamNft({ name: 'Mad Lads #1024', collection: 'Mad Lads' }), false);
assert.equal(isSpamNft({ name: 'Okay Bear #55', collection: 'Okay Bears' }), false);
console.log('NFT PARSING PASSED');

// ---------- WalletConnect namespaces + request classification ----------
const acc: WcAccounts = { evmAddress: '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266', solAddress: 'oeYf6Kc3xYhzrYq8Zc5v8Zc5v8Zc5v8Zc5v8Zc5v8Z', evmChainIds: [1, 137] };
const proposal = { params: { requiredNamespaces: {
  eip155: { chains: ['eip155:1', 'eip155:56'], methods: ['eth_sendTransaction', 'personal_sign'], events: ['accountsChanged'] },
  solana: { chains: ['solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp'], methods: ['solana_signMessage'], events: [] },
} } };
const built = buildNamespaces(proposal, acc);
assert.deepEqual(built.problems, [], 'supported chains subset must not be a problem');
assert.deepEqual(built.namespaces.eip155.chains, ['eip155:1'], 'only enabled chains are granted (56 was requested, not enabled)');
assert.ok(built.namespaces.eip155.accounts[0].endsWith(acc.evmAddress));
assert.deepEqual(built.namespaces.solana.chains, ['solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp']);
const badProposal = { params: { requiredNamespaces: { cosmos: { chains: ['cosmoshub-4'], methods: [], events: [] } } } };
assert.ok(buildNamespaces(badProposal, acc).problems.length > 0, 'unsupported REQUIRED namespace must be reported, not silently granted');
assert.equal(classifyRequest('eth_sendTransaction'), 'evm-send');
assert.equal(classifyRequest('eth_signTransaction'), 'evm-sign-tx');
assert.equal(classifyRequest('personal_sign'), 'sign-message');
assert.equal(classifyRequest('eth_signTypedData_v4'), 'sign-typed');
assert.equal(classifyRequest('solana_signTransaction'), 'sol-sign-tx');
assert.equal(classifyRequest('solana_signAndSendTransaction'), 'sol-sign-send');
assert.equal(classifyRequest('solana_signMessage'), 'sol-sign-message');
assert.equal(classifyRequest('wallet_watchAsset'), 'unsupported');
const wcTx = parseWcEvmTx([{ from: '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266', to: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8', value: '0xde0b6b3a7640000', data: '0x' }])!;
assert.equal(wcTx.value, '0xde0b6b3a7640000');
const creationTx = parseWcEvmTx([{ data: '0x6080' }])!;
assert.equal(creationTx.to, '', 'a missing destination is a contract creation — parsed as such, reviewed via its call data');
assert.equal(creationTx.value, '0x0', 'missing value defaults to zero');
const helloHex = '0x' + Buffer.from('Hello Syn', 'utf8').toString('hex');
const dec = decodeWcSignMessage('personal_sign', [helloHex, acc.evmAddress]);
assert.equal(dec.text, 'Hello Syn');
assert.equal(dec.address, acc.evmAddress);
const dec2 = decodeWcSignMessage('eth_sign', [acc.evmAddress, helloHex]);
assert.equal(dec2.text, 'Hello Syn', 'eth_sign param order is [address, message]');
console.log('WALLETCONNECT LOGIC PASSED');

// ---------- Lido submit calldata (offline, ethers Interface) ----------
const lidoIface = new ethers.Interface(['function submit(address _referral) payable returns (uint256)']);
const data = lidoIface.encodeFunctionData('submit', [ethers.ZeroAddress]);
assert.ok(data.startsWith('0xa1903eab'), 'submit(address) selector must be a1903eab');
assert.equal(data.length, 2 + 8 + 64, 'selector + one 32-byte word');
console.log('LIDO CALLDATA PASSED');

console.log('ALL WAVE 2 TESTS PASSED');
