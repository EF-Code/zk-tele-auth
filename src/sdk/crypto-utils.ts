import * as cryptoNode from 'crypto';
import { poseidonHash, fieldElementFromHex } from './poseidon.js';

/**
 * Node-oriented crypto helpers used by the SDK. These mirror the HMAC scheme
 * Telegram uses to authenticate WebApp initData (see initdata-parser).
 */
export class CryptoUtils {
  static sha256(data: string | Buffer): string {
    return cryptoNode.createHash('sha256').update(data).digest('hex');
  }

  static hmacSha256(key: string | Buffer, data: string): Buffer {
    return cryptoNode.createHmac('sha256', key).update(data).digest();
  }

  static hmacSha256Hex(key: string | Buffer, data: string): string {
    return cryptoNode.createHmac('sha256', key).update(data).digest('hex');
  }

  /**
   * Generate a cryptographically random salt as a decimal field element
   * (< 2^224) safe for the BLS12-381 scalar field.
   */
  static randomSalt(): string {
    const bytes = cryptoNode.randomBytes(28);
    return BigInt('0x' + bytes.toString('hex')).toString();
  }
}

/**
 * Poseidon hashing helpers over the BLS12-381 scalar field, kept in sync with
 * the circom circuits in ./circuits.
 */
export const PoseidonUtils = {
  /** Poseidon over the BLS12-381 scalar field. */
  hash: poseidonHash,
  /** Canonical field element from a hex digest (used for domain hashing). */
  fieldElementFromHex,
};

export const crypto = CryptoUtils;