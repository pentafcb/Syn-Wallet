import assert from 'node:assert';
import { PublicKey } from '@solana/web3.js';
import { nameKindOf, looksLikeNameAttempt, snsDomainKey, snsOwnerFromAccountData, snsParentFromAccountData, snsReverseKey, snsNameFromReverseData, snsFavouriteKey, snsFavouriteNameAccount, SNS_ROOT } from '../client/lib/names.js';
import { buildSignInMessage, parseSignInMessage, signInTimingProblem, looksLikeBlindBlob, type SignInFields } from '../client/lib/signing.js';
import { computePresets, computeLegacyPresets, parseGwei, formatGwei, validateCustomFees, effectiveGasPriceWei } from '../client/lib/fees.js';
import { extractTokenRisks, extractAddressRisks, normalizeApprovals, isUnlimitedAmount, formatTokenAmount } from '../client/lib/goplus.js';

// ---------- name classification ----------
assert.equal(nameKindOf('vitalik.eth'), 'ens');
assert.equal(nameKindOf('sub.vitalik.eth'), 'ens');
assert.equal(nameKindOf('bonfida.sol'), 'sns');
assert.equal(nameKindOf('sub.bonfida.sol'), 'sns');
assert.equal(nameKindOf('  Toly.SOL '), 'sns');
assert.equal(nameKindOf('name.bnb'), null, '.bnb must NOT be treated as resolvable');
assert.equal(nameKindOf('name.arb'), null);
assert.equal(nameKindOf('0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045'), null);
assert.equal(nameKindOf('.eth'), null);
assert.equal(looksLikeNameAttempt('something.bnb'), true, 'unsupported suffix still counts as a name attempt (hard-block path)');
assert.equal(looksLikeNameAttempt('vitalik.eth'), true);
assert.equal(looksLikeNameAttempt('0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045'), false);
console.log('NAME CLASSIFICATION PASSED');

// ---------- SNS derivation (live-verified against the Bonfida SDK) ----------
assert.equal(snsDomainKey('bonfida.sol').toBase58(), 'Crf8hzfthWGbGbLTVCiqRqV5MVnbpHB1L9KQMd6gsinb', 'bonfida.sol domain key');
assert.equal(snsDomainKey('toly.sol').toBase58(), 'FX1APjKbFu6M8GKb3dGXcZLXjxX4fGaYwvHqb5Vaee8q', 'toly.sol domain key');
// Owner/parent parsing from a synthetic NameRegistryState account buffer
const ownerPk = new PublicKey('Fw1ETanDZafof7xEULsnq9UY6o71Tpds89tNwPkWLb1v');
const acct = new Uint8Array(96);
acct.set(new PublicKey(SNS_ROOT).toBuffer(), 0);
acct.set(ownerPk.toBuffer(), 32);
assert.equal(snsOwnerFromAccountData(acct), 'Fw1ETanDZafof7xEULsnq9UY6o71Tpds89tNwPkWLb1v');
assert.equal(snsParentFromAccountData(acct), SNS_ROOT);
assert.equal(snsOwnerFromAccountData(new Uint8Array(10)), null);
// Reverse key + reverse record parsing
assert.equal(snsReverseKey(new PublicKey('Crf8hzfthWGbGbLTVCiqRqV5MVnbpHB1L9KQMd6gsinb')).toBase58(), 'DqgmWxe2PPrfy45Ja3UPyFGwcbRzkRuwXt3NyxjX8krg', 'bonfida reverse key');
const revData = new Uint8Array(96 + 4 + 7);
const nm = new TextEncoder().encode('bonfida');
revData[96] = 7; revData.set(nm, 100);
assert.equal(snsNameFromReverseData(revData), 'bonfida');
assert.equal(snsNameFromReverseData(new Uint8Array(50)), null);
// Favourite-domain PDA + payload parsing
assert.equal(snsFavouriteKey(new PublicKey('86xCnPeV69n6t3DnyGvkKobf9FdN2H9oiVDdaMpo2MMY')).toBase58(), 'DHbyrHbWpwjjCDQ8JEZdB2Q3cVQ8A4gT9o37nZUT3GoZ', 'favourite PDA for toly');
const favData = new Uint8Array(33); favData[0] = 1; favData.set(new PublicKey('FX1APjKbFu6M8GKb3dGXcZLXjxX4fGaYwvHqb5Vaee8q').toBuffer(), 1);
assert.equal(snsFavouriteNameAccount(favData), 'FX1APjKbFu6M8GKb3dGXcZLXjxX4fGaYwvHqb5Vaee8q');
console.log('SNS DERIVATION + PARSING PASSED');

// ---------- SIWE / Solana sign-in build + parse round-trips ----------
const siweFields: SignInFields = {
  domain: 'app.example.com', address: '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045',
  statement: 'Sign in to Example App.\nSecond line of the statement.', uri: 'https://app.example.com/login', version: '1',
  chainId: 1, nonce: 'abc123XYZ', issuedAt: '2026-11-18T10:00:00.000Z', expirationTime: '2026-11-18T11:00:00.000Z',
  requestId: 'req-42', resources: ['https://app.example.com/tos', 'ipfs://QmExample'],
};
const siweText = buildSignInMessage('evm', siweFields);
const parsed = parseSignInMessage(siweText);
assert.ok(parsed && parsed.family === 'evm', 'SIWE parses');
assert.deepEqual(parsed!.fields, siweFields, 'SIWE round-trip preserves every field');
assert.equal(buildSignInMessage('evm', parsed!.fields), siweText, 'SIWE rebuild is byte-identical');
const minimal: SignInFields = { domain: 'd.app', address: '0x0000000000000000000000000000000000000001', uri: 'https://d.app', version: '1', chainId: 137, nonce: 'n1', issuedAt: '2026-01-01T00:00:00Z' };
const pMin = parseSignInMessage(buildSignInMessage('evm', minimal));
assert.ok(pMin && pMin.fields.statement === undefined && pMin.fields.chainId === 137, 'minimal SIWE parses');
const solFields: SignInFields = { domain: 'sol.example', address: '86xCnPeV69n6t3DnyGvkKobf9FdN2H9oiVDdaMpo2MMY', statement: 'Welcome.', uri: 'https://sol.example/auth', version: '1', nonce: 'zz9', issuedAt: '2026-11-18T10:00:00.000Z' };
const solText = buildSignInMessage('solana', solFields);
const pSol = parseSignInMessage(solText);
assert.ok(pSol && pSol.family === 'solana' && pSol.fields.address === solFields.address, 'Solana sign-in parses');
assert.equal(buildSignInMessage('solana', pSol!.fields), solText, 'Solana rebuild is byte-identical');
// Rejections: garbage, wrong family address, missing nonce
assert.equal(parseSignInMessage('please sign this random text'), null);
assert.equal(parseSignInMessage(siweText.replace('Nonce: abc123XYZ', 'X-Nonce: abc123XYZ')), null, 'missing nonce rejected');
assert.equal(parseSignInMessage(siweText.replace(siweFields.address, 'not-an-address')), null, 'bad address rejected');
assert.equal(parseSignInMessage(solText.replace('Solana account:', 'Ethereum account:')), null, 'family/address mismatch rejected');
// Timing checks
assert.equal(signInTimingProblem(siweFields, Date.parse('2026-11-18T10:30:00.000Z')), null);
assert.ok(signInTimingProblem(siweFields, Date.parse('2026-11-18T12:00:00.000Z'))?.includes('expired'));
// Blind-blob detection
assert.equal(looksLikeBlindBlob('0x' + 'ab'.repeat(40)), true);
assert.equal(looksLikeBlindBlob('SGVsbG8gd29ybGQgdGhpcyBpcyBhIGxvbmcgYmFzZTY0IGJsb2IgdGV4dCBmb3IgdGVzdGluZw=='), true);
assert.equal(looksLikeBlindBlob('Please sign this message to prove you own this wallet. Nonce: 1234'), false);
assert.equal(looksLikeBlindBlob('gm'), false);
console.log('SIGN-IN BUILD/PARSE + BLOB DETECTION PASSED');

// ---------- fee maths ----------
const G = 1000000000n;
assert.equal(parseGwei('12.5'), 12500000000n);
assert.equal(parseGwei('0.000000001'), 1n);
assert.equal(parseGwei('1.0000000001'), null, 'too many decimals');
assert.equal(parseGwei('-3'), null);
assert.equal(parseGwei('abc'), null);
assert.equal(formatGwei(12500000000n), '12.5');
assert.equal(formatGwei(1n), '0.000000001');
assert.equal(formatGwei(30n * G), '30');
const presets = computePresets(30n * G, 2n * G);
assert.equal(presets.slow.maxPriorityFeePerGas, 1600000000n, 'slow = 0.8x priority');
assert.equal(presets.slow.maxFeePerGas, 34600000000n, 'slow maxFee = 1.1x base + prio');
assert.equal(presets.market.maxPriorityFeePerGas, 2n * G);
assert.equal(presets.market.maxFeePerGas, 62n * G, 'market maxFee = 2x base + prio');
assert.equal(presets.fast.maxPriorityFeePerGas, 3n * G);
assert.equal(presets.fast.maxFeePerGas, 78n * G, 'fast maxFee = 2.5x base + prio');
const legacy = computeLegacyPresets(20n * G);
assert.equal(legacy.slow, 18n * G); assert.equal(legacy.market, 20n * G); assert.equal(legacy.fast, 25n * G);
assert.equal(effectiveGasPriceWei(presets.market, 30n * G), 32n * G, 'effective = base + priority when below maxFee');
assert.equal(effectiveGasPriceWei({ maxFeePerGas: 31n * G, maxPriorityFeePerGas: 2n * G }, 30n * G), 31n * G, 'effective capped by maxFee');
// validation
assert.ok(validateCustomFees('10', '12', 30n * G).error?.includes('higher'), 'priority > maxFee is an error');
assert.ok(validateCustomFees('x', '1', null).error, 'garbage is an error');
assert.ok(validateCustomFees('20', '1', 30n * G).warning?.includes('below the current base fee'), 'below-base warns');
assert.ok(validateCustomFees('2000', '1', 30n * G).warning?.includes('unusually high'), 'absurd max fee warns');
assert.deepEqual(validateCustomFees('80', '2', 30n * G), {}, 'sane custom fees pass clean');
console.log('FEE MATHS + VALIDATION PASSED');

// ---------- GoPlus extraction / normalization (real captured fixtures) ----------
// USDT on Ethereum, captured live 2026-11-18 (fields trimmed, values exact)
const usdt = { is_honeypot: '0', buy_tax: '0', sell_tax: '0', cannot_buy: '0', cannot_sell_all: null, is_mintable: '1', can_take_back_ownership: '0', hidden_owner: '0', is_open_source: '1', is_proxy: '0', is_blacklisted: '1', transfer_pausable: '1', slippage_modifiable: '1', personal_slippage_modifiable: '0', trading_cooldown: '0', anti_whale_modifiable: '0' };
const usdtRisk = extractTokenRisks(usdt);
assert.equal(usdtRisk.warnings.length, 0, 'USDT fixture yields no strong warnings');
assert.ok(usdtRisk.notes.some(n => n.includes('mint new tokens')));
assert.ok(usdtRisk.notes.some(n => n.includes('blacklist')));
assert.ok(usdtRisk.notes.some(n => n.includes('pause transfers')));
const scam = extractTokenRisks({ is_honeypot: '1', sell_tax: '0.99', buy_tax: '0.05', is_open_source: '0', hidden_owner: '1' });
assert.ok(scam.warnings.some(w => w.includes('honeypot')));
assert.ok(scam.warnings.some(w => w.includes('Sell tax') && w.includes('99%')), 'sell tax fraction renders as 99%');
assert.ok(scam.notes.some(w => w.includes('Buy tax') && w.includes('5%')), 'small buy tax is a note, not a warning');
assert.ok(scam.warnings.some(w => w.includes('not public')));
const addrRisk = extractAddressRisks({ sanctioned: '1', phishing_activities: '0', number_of_malicious_contracts_created: '2', contract_address: '1' });
assert.ok(addrRisk.some(x => x.includes('sanctions')));
assert.ok(addrRisk.some(x => x.includes('2 malicious contracts')));
assert.equal(extractAddressRisks({ sanctioned: '0', phishing_activities: '0' }).length, 0);
// Approvals fixture: real GoPlus v2 response for a Binance hot wallet (SLP approval), captured 2026-11-18
const gpFixture = [{ token_address: '0xcc8fa225d80b9c7d42f96e9570156c65d6caaa25', token_name: 'Smooth Love Potion', token_symbol: 'SLP', decimals: 0, malicious_address: 0, approved_list: [{ approved_contract: '0x64192819ac13ef72bf6b5ae239ac672b43a9af08', approved_amount: '4000', approved_time: 1659344446, address_info: { contract_name: 'TransparentUpgradeableProxyV2', is_contract: 1, malicious_behavior: [], doubt_list: 0 } }] }];
const rows = normalizeApprovals(gpFixture);
assert.equal(rows.length, 1);
assert.equal(rows[0].tokenSymbol, 'SLP');
assert.equal(rows[0].spender, '0x64192819ac13ef72bf6b5ae239ac672b43a9af08');
assert.equal(rows[0].spenderName, 'TransparentUpgradeableProxyV2');
assert.equal(rows[0].approvedAmount, '4000');
assert.equal(rows[0].spenderMalicious, false);
assert.equal(normalizeApprovals(null).length, 0);
assert.equal(normalizeApprovals([]).length, 0);
// Allowance formatting / unlimited detection
assert.equal(isUnlimitedAmount('-1'), true, 'GoPlus -1 means unlimited');
assert.equal(isUnlimitedAmount((2n ** 256n - 1n).toString()), true, 'uint256 max is unlimited');
assert.equal(isUnlimitedAmount('4000'), false);
assert.equal(isUnlimitedAmount(''), false);
assert.equal(formatTokenAmount(4000n, 0), '4,000');
assert.equal(formatTokenAmount(1500000n, 6), '1.5');
assert.equal(formatTokenAmount(123456789n, 6), '123.456789');
assert.equal(formatTokenAmount(0n, 18), '0');
assert.ok(formatTokenAmount(340282366920938463463374607431768211455n, 18).startsWith('≈3.40e+'), 'huge finite allowances collapse to exponent form');
console.log('GOPLUS EXTRACTION + ALLOWANCE FORMATTING PASSED');
console.log('ALL WAVE 1B TESTS PASSED');
