import * as snarkjs from 'snarkjs';
import { loadVerificationKey } from './artifacts.js';
import { NullifierDeriver } from './nullifier.js';
import { parseTelegramAuthPublicSignals, assertFreshTimestamp } from './public-signals.js';
import {
  ProofArtifactOptions,
  VerificationResult,
  ZkAuthProofPayload,
  ZkAuthVerificationPolicy,
} from './types.js';
import { assertFieldElement } from './poseidon.js';

const DEFAULT_SKEW_SEC = 300;

/**
 * Verify a real Groth16 proof for the telegram_auth circuit.
 *
 * Checks, in order:
 *  1. public signals match the independently configured relying-party policy,
 *  2. the proof timestamp is fresh, and
 *  3. the SNARK pairing equation is valid.
 */
export class ZkAuthProofVerifier {
  static async verifyProof(
    payload: ZkAuthProofPayload,
    policy: ZkAuthVerificationPolicy,
    opts: ProofArtifactOptions = {}
  ): Promise<VerificationResult> {
    const fail = (error: string): VerificationResult => ({
      isValid: false,
      nullifierHash: '',
      error,
    });

    if (!payload || !payload.proof || !Array.isArray(payload.publicSignals)) {
      return fail('malformed proof payload');
    }

    let parsed;
    try {
      parsed = parseTelegramAuthPublicSignals(payload.publicSignals);
    } catch (err) {
      return fail(err instanceof Error ? err.message : String(err));
    }

    // Reject policy mismatches before spending time on the pairing check.
    if (!parsed.isVerified) {
      return fail('circuit gate isVerified != 1');
    }

    if (!policy || typeof policy !== 'object') return fail('verification policy is required');
    if (!policy.expectedAppDomain?.trim()) return fail('expected app domain is required');
    if (!/^[0-9]+$/.test(policy.expectedIssuerKeyHash || '')) return fail('expected issuer key hash is required');
    try {
      assertFieldElement(BigInt(policy.expectedIssuerKeyHash), 'expectedIssuerKeyHash');
    } catch (err) {
      return fail(err instanceof Error ? err.message : String(err));
    }
    if (!Number.isSafeInteger(policy.maxTokenAgeSec) || policy.maxTokenAgeSec <= 0) {
      return fail('invalid verifier maxTokenAgeSec policy');
    }

    const expectedDomainHash = await NullifierDeriver.hashAppDomain(policy.expectedAppDomain);
    if (parsed.appDomainHash !== expectedDomainHash) {
      return fail('appDomainHash does not match expected app domain');
    }

    if (parsed.issuerKeyHash !== policy.expectedIssuerKeyHash) {
      return fail('issuerKeyHash does not match authorized issuer');
    }
    if (parsed.maxTokenAgeSec !== policy.maxTokenAgeSec) {
      return fail('maxTokenAgeSec does not match verifier policy');
    }
    if (parsed.isPremiumRequired !== policy.requirePremium) {
      return fail('isPremiumRequired does not match verifier policy');
    }

    // Freshness uses the verifier-pinned policy, never a prover-selected age.
    try {
      assertFreshTimestamp(
        parsed.currentTimestamp,
        policy.maxTokenAgeSec,
        policy.clockSkewSec ?? DEFAULT_SKEW_SEC
      );
    } catch (err) {
      return fail(err instanceof Error ? err.message : String(err));
    }

    let ok: boolean;
    try {
      const verificationKey = await loadVerificationKey('telegram_auth', opts);
      ok = await snarkjs.groth16.verify(verificationKey, payload.publicSignals, payload.proof);
    } catch (err) {
      return fail(`groth16 verification error: ${err instanceof Error ? err.message : String(err)}`);
    }
    if (!ok) return fail('groth16 verification failed');

    return {
      isValid: true,
      nullifierHash: parsed.nullifierHash,
      appDomainHash: parsed.appDomainHash,
      issuerKeyHash: parsed.issuerKeyHash,
    };
  }
}
