import { CryptoUtils, PoseidonUtils } from './crypto-utils.js';

/**
 * Nullifier derivation, kept in lockstep with `circuits/hasher.circom`
 * (`PoseidonNullifier`).
 *
 *     nullifierHash = Poseidon(userId, appDomainHash, salt)
 *
 * The userId stays private inside the circuit; only the nullifier is ever
 * revealed. Mixing appDomainHash into the hash guarantees the same Telegram
 * account yields a *different* nullifier per dApp, so a user cannot be
 * correlated across applications (unlinkability) and cannot be double-counted
 * within one dApp (Sybil resistance).
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
   * Derive the anonymous nullifier for (user, domain, salt).
   * @returns decimal string field element (matches circuit public signal [0])
   */
  static async deriveNullifier(
    userId: number | string,
    appDomain: string,
    salt: string
  ): Promise<string> {
    const appDomainHash = BigInt(await NullifierDeriver.hashAppDomain(appDomain));
    return PoseidonUtils.hash([BigInt(userId), appDomainHash, BigInt(salt)]);
  }
}
