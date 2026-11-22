// GoPlus security API (free keyless tier) — token risk, address risk and
// the ERC-20 approval list. Verified live from sober77 on 2026-11-18:
//   token_security/{chain}        code 1 on EVM chains (1, 10, ...)
//   address_security/{addr}       code 1 for EVM chains; Solana -> code 5000
//   v2/token_approval_security    code 1 on chains 1, 56, 137, 42161, 8453;
//                                 code 2018 ("main chain does not exist")
//                                 on 10, 43114, 250, 324, 59144, 100, ...
//   Solana token security         no working keyless endpoint (404/5000) —
//                                 mint/freeze authority is read on-chain
//                                 instead (extractSolMintRisks below)
// Every failure degrades to an honest "unavailable / not covered" state —
// the UI never presents an unchecked item as checked, and never uses the
// word "safe" as a verdict.

export interface RiskReport { status: 'ok' | 'unavailable'; warnings: string[]; notes: string[]; reason?: string; source?: string; }
const GP1 = 'https://api.gopluslabs.io/api/v1';
const GP2 = 'https://api.gopluslabs.io/api/v2';

async function gpFetch(url: string): Promise<any | null> {
  try {
    const r = await fetch(url, { signal: AbortSignal.timeout(12000) });
    if (!r.ok) return null;
    return await r.json();
  } catch { return null; }
}
const is1 = (v: any) => v === '1' || v === 1;

// ---- token risk ----
export function extractTokenRisks(r: any): { warnings: string[]; notes: string[] } {
  const warnings: string[] = []; const notes: string[] = [];
  if (!r || typeof r !== 'object') return { warnings, notes };
  if (is1(r.is_honeypot)) warnings.push('Flagged as a honeypot — buyers may be unable to sell this token.');
  if (is1(r.cannot_buy)) warnings.push('Buying is currently blocked by the token contract.');
  if (is1(r.cannot_sell_all)) warnings.push('Holders cannot sell their full balance.');
  const taxPct = (v: any): number | null => { const n = Number(v); if (!Number.isFinite(n) || n <= 0) return null; return n <= 1 ? n * 100 : n; };
  const bt = taxPct(r.buy_tax); const st = taxPct(r.sell_tax);
  if (bt !== null) (bt >= 10 ? warnings : notes).push(`Buy tax reported by GoPlus: ${bt.toFixed(bt % 1 ? 1 : 0)}%`);
  if (st !== null) (st >= 10 ? warnings : notes).push(`Sell tax reported by GoPlus: ${st.toFixed(st % 1 ? 1 : 0)}%`);
  if (is1(r.hidden_owner)) warnings.push('The contract has a hidden owner.');
  if (is1(r.can_take_back_ownership)) warnings.push('Ownership of the contract can be taken back by its deployer.');
  if (r.is_open_source === '0' || r.is_open_source === 0) warnings.push('Contract source code is not public — its behaviour cannot be reviewed.');
  if (is1(r.is_mintable)) notes.push('The issuer can mint new tokens, increasing supply.');
  if (is1(r.is_blacklisted)) notes.push('The issuer can blacklist addresses, freezing their tokens.');
  if (is1(r.transfer_pausable)) notes.push('The issuer can pause transfers.');
  if (is1(r.is_proxy)) notes.push('Proxy contract — its logic can be upgraded by its owner.');
  if (is1(r.slippage_modifiable) || is1(r.personal_slippage_modifiable)) notes.push('Trading slippage rules can be changed by the issuer.');
  if (is1(r.trading_cooldown)) notes.push('A trading cooldown applies after buying.');
  if (is1(r.anti_whale_modifiable)) notes.push('Anti-whale limits can be changed by the issuer.');
  return { warnings, notes };
}
export async function gpTokenRisk(evmId: number, contract: string): Promise<RiskReport> {
  const j = await gpFetch(`${GP1}/token_security/${evmId}?contract_addresses=${contract}`);
  if (!j || j.code !== 1) return { status: 'unavailable', warnings: [], notes: [], reason: 'GoPlus does not cover this network on its free API.' };
  const r = j.result?.[contract.toLowerCase()];
  if (!r) return { status: 'unavailable', warnings: [], notes: [], reason: 'GoPlus has no data for this contract.' };
  const { warnings, notes } = extractTokenRisks(r);
  return { status: 'ok', warnings, notes };
}

// ---- Solana mint risk (on-chain, no third party) ----
// GoPlus serves no SPL token security on its free keyless API, but the
// two signals that matter for a Solana token — mint authority and
// freeze authority — live in the mint account itself. SPL Token mint
// layout (82-byte base, identical for the classic Token program and
// Token-2022's base mint):
//    0..4   mintAuthority COption tag (u32 LE; 0 = none, 1 = some)
//    4..36  mintAuthority pubkey (when tag = 1)
//   36..44  supply (u64 LE)
//   44      decimals
//   45      isInitialized (0/1)
//   46..50  freezeAuthority COption tag
//   50..82  freezeAuthority pubkey (when tag = 1)
// Returns null when the bytes are not a parseable initialized mint, so
// the UI can degrade to an honest "unavailable" instead of guessing.
export function extractSolMintRisks(data: Uint8Array): { warnings: string[]; notes: string[] } | null {
  if (!data || data.length < 82) return null;
  if (data[45] !== 1) return null;
  const tag = (o: number) => data[o] | (data[o + 1] << 8) | (data[o + 2] << 16) | (data[o + 3] << 24);
  const mintTag = tag(0); const freezeTag = tag(46);
  if ((mintTag !== 0 && mintTag !== 1) || (freezeTag !== 0 && freezeTag !== 1)) return null;
  const warnings: string[] = []; const notes: string[] = [];
  if (freezeTag === 1) warnings.push('Freeze authority is active — the issuer can freeze token accounts, including yours.');
  else notes.push('Freeze authority is revoked — the issuer cannot freeze your token account.');
  if (mintTag === 1) notes.push('Mint authority is active — the issuer can create new supply, diluting holders.');
  else notes.push('Mint authority is revoked — the issuer cannot increase the supply.');
  return { warnings, notes };
}

// ---- address risk ----
const ADDRESS_FLAG_LABELS: [string, string][] = [
  ['sanctioned', 'On a sanctions list'],
  ['phishing_activities', 'Linked to phishing activity'],
  ['stealing_attack', 'Linked to theft attacks'],
  ['honeypot_related_address', 'Linked to honeypot contracts'],
  ['money_laundering', 'Linked to money laundering'],
  ['cybercrime', 'Linked to cybercrime'],
  ['financial_crime', 'Linked to financial crime'],
  ['darkweb_transactions', 'Linked to darkweb transactions'],
  ['blackmail_activities', 'Linked to blackmail activity'],
  ['mixer', 'Linked to mixing services'],
  ['fake_kyc', 'Fake-KYC flag'],
  ['blacklist_doubt', 'Blacklist-doubt flag'],
  ['gas_abuse', 'Gas-abuse flag'],
  ['malicious_mining_activities', 'Linked to malicious mining'],
  ['fake_token', 'Has created fake tokens'],
];
export function extractAddressRisks(r: any): string[] {
  if (!r || typeof r !== 'object') return [];
  const out: string[] = [];
  for (const [k, label] of ADDRESS_FLAG_LABELS) if (is1(r[k])) out.push(label);
  const n = Number(r.number_of_malicious_contracts_created);
  if (Number.isFinite(n) && n > 0) out.push(`Has created ${n} malicious contract${n === 1 ? '' : 's'}`);
  return out;
}
export async function gpAddressRisk(address: string, chainId: string): Promise<RiskReport> {
  const j = await gpFetch(`${GP1}/address_security/${address}?chain_id=${encodeURIComponent(chainId)}`);
  if (!j || j.code !== 1 || !j.result) return { status: 'unavailable', warnings: [], notes: [], reason: 'Address risk check unavailable (GoPlus).' };
  return { status: 'ok', warnings: extractAddressRisks(j.result), notes: [] };
}

// ---- ERC-20 approval list ----
export interface ApprovalRow {
  tokenAddress: string; tokenName: string; tokenSymbol: string; decimals: number;
  spender: string; spenderName: string; spenderMalicious: boolean; spenderDoubt: boolean;
  approvedAmount: string; // raw string from GoPlus ("-1" = unlimited there)
  approvedTime: number;
}
export function normalizeApprovals(result: any): ApprovalRow[] {
  const rows: ApprovalRow[] = [];
  if (!Array.isArray(result)) return rows;
  for (const t of result) {
    for (const a of (t?.approved_list || [])) {
      rows.push({
        tokenAddress: String(t.token_address || ''),
        tokenName: String(t.token_name || ''),
        tokenSymbol: String(t.token_symbol || ''),
        decimals: Number.isFinite(Number(t.decimals)) ? Number(t.decimals) : 18,
        spender: String(a.approved_contract || ''),
        spenderName: String(a.address_info?.contract_name || ''),
        spenderMalicious: Array.isArray(a.address_info?.malicious_behavior) && a.address_info.malicious_behavior.length > 0,
        spenderDoubt: is1(a.address_info?.doubt_list) || Number(a.address_info?.doubt_list) > 0,
        approvedAmount: String(a.approved_amount ?? ''),
        approvedTime: Number(a.approved_time || 0),
      });
    }
  }
  return rows;
}
export type ApprovalsResult = { status: 'ok'; rows: ApprovalRow[] } | { status: 'not-covered' } | { status: 'unavailable' };
export async function gpApprovals(evmId: number, owner: string): Promise<ApprovalsResult> {
  const j = await gpFetch(`${GP2}/token_approval_security/${evmId}?addresses=${owner}`);
  if (!j) return { status: 'unavailable' };
  if (j.code === 2018 || j.code === 2022) return { status: 'not-covered' };
  if (j.code !== 1) return { status: 'unavailable' };
  return { status: 'ok', rows: normalizeApprovals(j.result) };
}

// ---- amount formatting (allowances) ----
// GoPlus reports "-1" for unlimited approvals. On-chain, unlimited is
// conventionally 2^256-1 (or anything >= 2^255) — treat both as unlimited.
export function isUnlimitedAmount(raw: string): boolean {
  if (raw.trim() === '-1') return true;
  try { return BigInt(raw) >= (1n << 255n); } catch { return false; }
}
export function formatTokenAmount(raw: bigint, decimals: number): string {
  if (raw < 0n) return '0';
  const d = Math.max(0, Math.min(36, decimals));
  const base = 10n ** BigInt(d);
  const ip = raw / base; const fp = raw % base;
  // Astronomically large finite allowances collapse to exponent form so a
  // 30-digit number can never blow out the layout; they are flagged in the
  // UI as effectively unlimited.
  if (ip >= 10n ** 16n) return '≈' + (Number(raw) / 10 ** d).toExponential(2);
  let out = ip.toLocaleString('en-US');
  if (fp > 0n && d > 0) {
    const fs = fp.toString().padStart(d, '0').slice(0, 6).replace(/0+$/, '');
    if (fs) out += '.' + fs;
  }
  return out;
}
