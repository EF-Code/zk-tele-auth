import { Address, beginCell, Cell } from '@ton/core';
import { toBasechainAddressLimbs } from './ton-address-binding.js';

export interface TonVerifierStateInitPolicy {
  appDomainHash: string;
  issuerKeyHash: string;
  maxTokenAgeSec: number;
  requirePremium: boolean;
}

export interface PrivaLaunchpadStateInitPolicy {
  appDomainHash: string;
  issuerKeyHash: string;
  launchIdHash: string;
  maxTokenAgeSec: number;
  requirePremium: boolean;
  maxAuthorizationTtlSec: number;
  pricePerUnitNano: bigint | number | string;
  perIdentityCap: bigint | number | string;
  inventory: bigint | number | string;
}

function parseUint256(value: string, name: string): bigint {
  if (!/^[0-9]+$/.test(value)) throw new Error(`${name} must be a decimal integer`);
  const parsed = BigInt(value);
  if (parsed <= 0n || parsed >= 2n ** 256n) throw new Error(`${name} must be in 1..2^256-1`);
  return parsed;
}

function parseUint64(value: bigint | number | string, name: string): bigint {
  const stringValue = typeof value === 'bigint' ? value.toString() : String(value);
  if (!/^(0|[1-9][0-9]*)$/.test(stringValue)) throw new Error(`${name} must be a canonical unsigned integer`);
  const parsed = BigInt(stringValue);
  if (parsed < 0n || parsed >= 2n ** 64n) throw new Error(`${name} must fit in uint64`);
  return parsed;
}

function parseCoins(value: bigint | number | string): bigint {
  const parsed = parseUint64(value, 'pricePerUnitNano');
  if (parsed === 0n) throw new Error('pricePerUnitNano must be positive');
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

/**
 * Serialize the immutable Priva launchpad policy.  The first cell is kept
 * small enough for a single StateInit data cell; accounting dictionaries live
 * in a deterministic reference with the same order as the Tolk struct.
 */
export function buildPrivaLaunchpadStateInitData(policy: PrivaLaunchpadStateInitPolicy): Cell {
  const appDomainHash = parseUint256(policy.appDomainHash, 'appDomainHash');
  const issuerKeyHash = parseUint256(policy.issuerKeyHash, 'issuerKeyHash');
  const launchIdHash = parseUint256(policy.launchIdHash, 'launchIdHash');
  if (!Number.isSafeInteger(policy.maxTokenAgeSec) || policy.maxTokenAgeSec <= 0 || policy.maxTokenAgeSec > 0xffff_ffff) {
    throw new Error('maxTokenAgeSec must be an integer in 1..2^32-1');
  }
  if (!Number.isSafeInteger(policy.maxAuthorizationTtlSec) || policy.maxAuthorizationTtlSec <= 0 || policy.maxAuthorizationTtlSec > 0xffff_ffff) {
    throw new Error('maxAuthorizationTtlSec must be an integer in 1..2^32-1');
  }
  const price = parseCoins(policy.pricePerUnitNano);
  const cap = parseUint64(policy.perIdentityCap, 'perIdentityCap');
  const inventory = parseUint64(policy.inventory, 'inventory');
  if (cap === 0n || inventory === 0n) throw new Error('perIdentityCap and inventory must be positive');
  if (cap > 1_000_000n || inventory > 1_000_000n) throw new Error('perIdentityCap and inventory are bounded to 1,000,000 for storage economics');
  const accounting = beginCell()
    .storeCoins(price)
    .storeUint(cap, 64)
    .storeUint(inventory, 64)
    .storeUint(0, 64)
    .storeCoins(0)
    .storeBit(0)
    .storeBit(0)
    .storeBit(0)
    .endCell();
  return beginCell()
    .storeUint(appDomainHash, 256)
    .storeUint(issuerKeyHash, 256)
    .storeUint(launchIdHash, 256)
    .storeUint(policy.maxTokenAgeSec, 32)
    .storeUint(policy.requirePremium ? 1 : 0, 8)
    .storeUint(policy.maxAuthorizationTtlSec, 32)
    .storeRef(accounting)
    .endCell();
}

export interface PrivaLaunchpadPurchaseBody {
  queryId: bigint | number | string;
  quantity: bigint | number | string;
  recipient: Address | string;
  proof: Cell;
  pubInputs: Cell;
}

/** Serialize the untagged launchpad purchase envelope consumed by Tolk. */
export function buildPrivaLaunchpadPurchaseBody(request: PrivaLaunchpadPurchaseBody): Cell {
  const queryId = parseUint64(request.queryId, 'queryId');
  const quantity = parseUint64(request.quantity, 'quantity');
  if (quantity === 0n) throw new Error('quantity must be positive');
  const recipient = typeof request.recipient === 'string' ? Address.parse(request.recipient) : request.recipient;
  if (recipient.workChain !== 0) throw new Error('Priva launchpad accepts basechain recipients only');
  if (!(request.proof instanceof Cell) || !(request.pubInputs instanceof Cell)) throw new Error('proof and pubInputs must be TON cells');
  return beginCell()
    .storeUint(queryId, 64)
    .storeUint(quantity, 64)
    .storeAddress(recipient)
    .storeRef(request.proof)
    .storeRef(request.pubInputs)
    .endCell();
}

/** Return the exact field limbs used by the Priva circuit for a recipient. */
export function privaRecipientLimbs(recipient: Address | string): { addressHi: string; addressLo: string } {
  return toBasechainAddressLimbs(recipient);
}
