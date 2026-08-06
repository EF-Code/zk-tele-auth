import { ZkAuthProofPayload } from './types.js';

export const TELEGRAM_AUTH_PUBLIC_SIGNALS = [
  'nullifierHash',
  'isVerified',
  'appDomainHash',
  'currentTimestamp',
  'maxTokenAgeSec',
  'isPremiumRequired',
] as const;

export type TelegramAuthPublicSignal = (typeof TELEGRAM_AUTH_PUBLIC_SIGNALS)[number];

export interface ParsedPublicSignals {
  nullifierHash: string;
  isVerified: boolean;
  appDomainHash: string;
  currentTimestamp: number;
  maxTokenAgeSec: number;
  isPremiumRequired: boolean;
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
    isVerified: publicSignals[1] === '1',
    appDomainHash: publicSignals[2],
    currentTimestamp: Number(publicSignals[3]),
    maxTokenAgeSec: Number(publicSignals[4]),
    isPremiumRequired: publicSignals[5] === '1',
  };
}

export function assertFreshTimestamp(timestamp: number, maxTokenAgeSec: number, skewSec = 300): void {
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
    isVerified: parsed.isVerified,
  };
}
