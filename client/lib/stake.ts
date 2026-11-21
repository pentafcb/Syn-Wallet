// Solana native staking helpers (Wave 2). Stake accounts are read with
// getProgramAccounts on the Stake program, filtered by the withdraw
// authority (memcmp offset 44 in the account layout). The RPC's
// jsonParsed encoding is used when present; a binary parser for the
// documented 200-byte layout is kept as fallback and unit-tested.
//
// Layout (all little-endian): u32 state discriminant (0 uninitialized,
// 1 initialized, 2 delegated) | meta.rentExemptReserve u64 @4 |
// authorized.staker @12 | authorized.withdrawer @44 | lockup @76..124 |
// delegation.voter @124 | delegation.stake u64 @156 |
// delegation.activationEpoch u64 @164 | delegation.deactivationEpoch
// u64 @172 (u64 max = not deactivating) | warmupCooldownRate f64 @180 |
// creditsObserved u64 @188.
import { base58 } from '@scure/base';

export const STAKE_PROGRAM_ID = 'Stake11111111111111111111111111111111111111';
export const U64_MAX = '18446744073709551615';

export interface StakeAccountInfo {
  pubkey: string;
  lamports: number;
  /** vote pubkey the stake is delegated to; null when not delegated */
  voter: string | null;
  /** delegated (activating/active) stake in lamports */
  delegatedLamports: number;
  activationEpoch: string | null;
  /** epoch at which deactivation was signalled; null = not deactivating */
  deactivationEpoch: string | null;
}

function u64le(b: Uint8Array, off: number): string {
  let v = 0n;
  for (let i = 7; i >= 0; i--) v = v * 256n + BigInt(b[off + i]);
  return v.toString();
}

/** Parse one stake account from its raw 200-byte layout. */
export function parseStakeAccountBytes(pubkey: string, data: Uint8Array, lamports: number): StakeAccountInfo | null {
  if (!data || data.length < 200) return null;
  const disc = data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24);
  if (disc === 1) return { pubkey, lamports, voter: null, delegatedLamports: 0, activationEpoch: null, deactivationEpoch: null };
  if (disc !== 2) return null;
  const voter = base58.encode(data.slice(124, 156));
  const deact = u64le(data, 172);
  return {
    pubkey, lamports, voter,
    delegatedLamports: Number(u64le(data, 156)),
    activationEpoch: u64le(data, 164),
    deactivationEpoch: deact === U64_MAX ? null : deact,
  };
}

/** Parse the jsonParsed form of a stake account (RPC parsed encoding). */
export function parseStakeAccountParsed(pubkey: string, lamports: number, parsed: any): StakeAccountInfo | null {
  const info = parsed?.info;
  if (!info || typeof info !== 'object') return null;
  const del = info?.stake?.delegation;
  if (!del || typeof del.voter !== 'string') {
    return { pubkey, lamports, voter: null, delegatedLamports: 0, activationEpoch: null, deactivationEpoch: null };
  }
  const deact = del.deactivationEpoch != null ? String(del.deactivationEpoch) : null;
  return {
    pubkey, lamports,
    voter: del.voter,
    delegatedLamports: Number(del.stake || 0),
    activationEpoch: del.activationEpoch != null ? String(del.activationEpoch) : null,
    deactivationEpoch: deact === U64_MAX ? null : deact,
  };
}

export interface ValidatorInfo {
  votePubkey: string;
  nodePubkey: string;
  activatedStakeSol: number;
  commission: number;
  delinquent: boolean;
}

/** getVoteAccounts result -> display rows, biggest stake first. */
export function sortValidators(result: any, limit = 25): ValidatorInfo[] {
  const rows: ValidatorInfo[] = [];
  const push = (list: any, delinquent: boolean) => {
    for (const v of (Array.isArray(list) ? list : [])) {
      if (!v?.votePubkey) continue;
      rows.push({ votePubkey: String(v.votePubkey), nodePubkey: String(v.nodePubkey || ''), activatedStakeSol: Number(v.activatedStake || 0) / 1e9, commission: Number(v.commission || 0), delinquent });
    }
  };
  push(result?.current, false);
  push(result?.delinquent, true);
  rows.sort((a, b) => b.activatedStakeSol - a.activatedStakeSol);
  return rows.slice(0, limit);
}

/** Display state for one stake account, from getStakeActivation output. */
export function stakeStateOf(info: StakeAccountInfo, activation: { state?: string; active?: number; inactive?: number } | null): { label: string; canDeactivate: boolean; canWithdraw: boolean } {
  if (!info.voter) return { label: 'Not delegated', canDeactivate: false, canWithdraw: true };
  if (info.deactivationEpoch != null) {
    if (activation && activation.state === 'inactive') return { label: 'Deactivated — ready to withdraw', canDeactivate: false, canWithdraw: true };
    return { label: 'Deactivating (cooldown until the epoch ends)', canDeactivate: false, canWithdraw: false };
  }
  const st = activation?.state;
  if (st === 'active') return { label: 'Active — earning rewards', canDeactivate: true, canWithdraw: false };
  if (st === 'activating') return { label: 'Activating (warming up)', canDeactivate: true, canWithdraw: false };
  if (st === 'inactive') return { label: 'Inactive', canDeactivate: true, canWithdraw: false };
  return { label: 'Delegated', canDeactivate: true, canWithdraw: false };
}
