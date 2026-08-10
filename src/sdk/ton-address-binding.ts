import { Address } from '@ton/core';

const LIMB_BITS = 128n;
const LIMB_MASK = (1n << LIMB_BITS) - 1n;

/** The two field-safe limbs used by priva_purchase_auth/v2 for a TON account ID. */
export interface TonBasechainAddressLimbs {
  addressHi: string;
  addressLo: string;
}

/**
 * Parse a user-facing TON address into the canonical account-ID limbs that
 * the purchase circuit and launchpad compare. Only workchain 0 is accepted:
 * this is an explicit v2 launchpad policy, not an implicit address conversion.
 */
export function toBasechainAddressLimbs(address: string | Address): TonBasechainAddressLimbs {
  const parsed = typeof address === 'string' ? Address.parse(address) : address;
  if (parsed.workChain !== 0) throw new Error('Priva purchase authorization supports basechain addresses only');
  const accountId = BigInt(`0x${parsed.hash.toString('hex')}`);
  return {
    addressHi: (accountId >> LIMB_BITS).toString(),
    addressLo: (accountId & LIMB_MASK).toString(),
  };
}
