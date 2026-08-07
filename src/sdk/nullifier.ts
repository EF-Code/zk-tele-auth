import { CryptoUtils, PoseidonUtils } from './crypto-utils.js';

/**
 * Nullifier derivation, kept in lockstep with `circuits/hasher.circom`
 * (`PoseidonNullifier`).
 *
 *     nullifierHash = Poseidon(userId, appDomainHash, issuerSecret)
 *
 * The userId stays private inside the circuit; only the nullifier is ever
 * revealed. Mixing appDomainHash into the hash guarantees the same Telegram
 * account yields a different nullifier per dApp. The stable issuer secret keeps
 * the value deterministic while preventing public user-id enumeration.
 */
export class NullifierDeriver {
  /**
   * Domain commitment fed to the circuit as the public `appDomainHash`.
   * A Poseidon fold of the 256-bit SHA-256 digest of the normalized domain.
   */
  static async hashAppDomain(appDomain: string): Promise<string> {
    const normalized = appDomain.toLowerCase().trim();
    return PoseidonUtils.fieldElementFromHex(CryptoUtils.sha256(normalized));
  }

  /**
   * Derive the anonymous nullifier for (user, domain, issuer secret).
   * @returns decimal string field element (matches circuit public signal [0])
   */
  static async deriveNullifier(
    userId: number | string,
    appDomain: string,
    issuerSecret: string
  ): Promise<string> {
    const appDomainHash = BigInt(await NullifierDeriver.hashAppDomain(appDomain));
    return PoseidonUtils.hash([BigInt(userId), appDomainHash, BigInt(issuerSecret)]);
  }

  /** Public commitment pinned by every verifier for an authorized gateway. */
  static async deriveIssuerKeyHash(issuerSecret: string): Promise<string> {
    const secret = BigInt(issuerSecret);
    if (secret <= 0n) throw new Error('issuer secret must be a positive field element');
    return PoseidonUtils.hash([secret]);
  }
}
