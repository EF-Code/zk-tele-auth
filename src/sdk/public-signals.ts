import { ZkAuthProofPayload } from './types.js';

export const TELEGRAM_AUTH_PUBLIC_SIGNALS = [
  'nullifierHash',
  'isVerified',
  'appDomainHash',
  'currentTimestamp',
  'maxTokenAgeSec',
  'isPremiumRequired',
  'issuerKeyHash',
] as const;

export type TelegramAuthPublicSignal = (typeof TELEGRAM_AUTH_PUBLIC_SIGNALS)[number];

export interface ParsedPublicSignals {
  nullifierHash: string;
  isVerified: boolean;
  appDomainHash: string;
  currentTimestamp: number;
  maxTokenAgeSec: number;
  isPremiumRequired: boolean;
  issuerKeyHash: string;
}

function parseSafeInteger(value: string, name: string): number {
  if (!/^(0|[1-9][0-9]*)$/.test(value)) {
    throw new Error(`${name} must be a canonical non-negative integer`);
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) throw new Error(`${name} exceeds JavaScript safe-integer range`);
  return parsed;
}

function parseBoolean(value: string, name: string): boolean {
  if (value !== '0' && value !== '1') throw new Error(`${name} must be 0 or 1`);
  return value === '1';
}

/**
 * Parse the telegram_auth public signals into named fields.
 * The circuit exposes signals in a fixed order (outputs first, then public
 * inputs, as emitted by circom/snarkjs).
 */
export function parseTelegramAuthPublicSignals(publicSignals: string[]): ParsedPublicSignals {
  if (!Array.isArray(publicSignals) || publicSignals.length !== TELEGRAM_AUTH_PUBLIC_SIGNALS.length) {
    throw new Error(
      `expected ${TELEGRAM_AUTH_PUBLIC_SIGNALS.length} public signals, got ${publicSignals?.length}`
    );
  }
  return {
    nullifierHash: publicSignals[0],
    isVerified: parseBoolean(publicSignals[1], 'isVerified'),
    appDomainHash: publicSignals[2],
    currentTimestamp: parseSafeInteger(publicSignals[3], 'currentTimestamp'),
    maxTokenAgeSec: parseSafeInteger(publicSignals[4], 'maxTokenAgeSec'),
    isPremiumRequired: parseBoolean(publicSignals[5], 'isPremiumRequired'),
    issuerKeyHash: publicSignals[6],
  };
}

export function assertFreshTimestamp(timestamp: number, maxTokenAgeSec: number, skewSec = 300): void {
  if (!Number.isSafeInteger(timestamp) || timestamp < 0) throw new Error('invalid proof timestamp');
  if (!Number.isSafeInteger(maxTokenAgeSec) || maxTokenAgeSec <= 0) throw new Error('invalid token age policy');
  if (!Number.isSafeInteger(skewSec) || skewSec < 0) throw new Error('invalid clock skew policy');
  const now = Math.floor(Date.now() / 1000);
  if (timestamp > now + skewSec) {
    throw new Error('proof timestamp is in the future (clock skew or replay attempt)');
  }
  if (now - timestamp > maxTokenAgeSec) {
    throw new Error('proof expired');
  }
}

/**
 * Build a normalized payload from a raw snarkjs proof result.
 */
export function buildPayload(
  proof: ZkAuthProofPayload['proof'],
  publicSignals: string[]
): ZkAuthProofPayload {
  const parsed = parseTelegramAuthPublicSignals(publicSignals);
  return {
    proof,
    publicSignals,
    nullifierHash: parsed.nullifierHash,
    appDomainHash: parsed.appDomainHash,
    timestamp: parsed.currentTimestamp,
    maxTokenAgeSec: parsed.maxTokenAgeSec,
    isPremiumRequired: parsed.isPremiumRequired,
    issuerKeyHash: parsed.issuerKeyHash,
    isVerified: parsed.isVerified,
  };
}
