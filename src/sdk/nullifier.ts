import { crypto } from './crypto-utils.js';

export class NullifierDeriver {
  /**
   * Derive a deterministic anonymous nullifier hash from userId and appDomain
   * @param userId Telegram numeric User ID
   * @param appDomain Target Web3 dApp domain (e.g. "mydapp.io")
   * @param salt Optional secret salt
   * @returns 64-character hex string representing nullifier hash
   */
  static deriveNullifier(userId: number, appDomain: string, salt: string = 'zk-tele-auth-v1'): string {
    const raw = `${userId}:${appDomain.toLowerCase().trim()}:${salt}`;
    return crypto.sha256(raw);
  }

  /**
   * Derive domain hash for circuit public signals
   * @param appDomain
   * @returns BigInt string representation
   */
  static hashAppDomain(appDomain: string): string {
    const hex = crypto.sha256(appDomain.toLowerCase().trim());
    return BigInt('0x' + hex.substring(0, 16)).toString();
  }
}
