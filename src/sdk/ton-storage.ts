import { beginCell, Cell } from '@ton/core';

export interface TonVerifierStateInitPolicy {
  appDomainHash: string;
  issuerKeyHash: string;
  maxTokenAgeSec: number;
  requirePremium: boolean;
}

function parseUint256(value: string, name: string): bigint {
  if (!/^[0-9]+$/.test(value)) throw new Error(`${name} must be a decimal integer`);
  const parsed = BigInt(value);
  if (parsed <= 0n || parsed >= 2n ** 256n) throw new Error(`${name} must be in 1..2^256-1`);
  return parsed;
}

/** Serialize the immutable policy expected in the TON contract's StateInit data. */
export function buildTonVerifierStateInitData(policy: TonVerifierStateInitPolicy): Cell {
  if (!Number.isSafeInteger(policy.maxTokenAgeSec) || policy.maxTokenAgeSec <= 0 || policy.maxTokenAgeSec > 0xffff_ffff) {
    throw new Error('maxTokenAgeSec must be an integer in 1..2^32-1');
  }
  return beginCell()
    .storeUint(parseUint256(policy.appDomainHash, 'appDomainHash'), 256)
    .storeUint(parseUint256(policy.issuerKeyHash, 'issuerKeyHash'), 256)
    .storeUint(policy.maxTokenAgeSec, 32)
    .storeUint(policy.requirePremium ? 1 : 0, 8)
    .storeUint(0, 64)
    .storeBit(0) // empty HashmapE usedNullifiers
    .endCell();
}
