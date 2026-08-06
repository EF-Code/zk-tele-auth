import * as snarkjs from 'snarkjs';
import { loadVerificationKey } from './artifacts.js';
import { NullifierDeriver } from './nullifier.js';
import { parseTelegramAuthPublicSignals, assertFreshTimestamp } from './public-signals.js';
import { ProofArtifactOptions, VerificationResult, ZkAuthProofPayload } from './types.js';

const DEFAULT_SKEW_SEC = 300;

/**
 * Verify a real Groth16 proof for the telegram_auth circuit.
 *
 * Checks, in order:
 *  1. the SNARK pairing equation (groth16.verify),
 *  2. the public gate signal isVerified == 1,
 *  3. appDomainHash in the proof matches the expected app domain,
 *  4. the proof timestamp is fresh (not stale, not forged in the future).
 */
export class ZkAuthProofVerifier {
  static async verifyProof(
    payload: ZkAuthProofPayload,
    expectedAppDomain: string,
    opts: ProofArtifactOptions = {}
  ): Promise<VerificationResult> {
    const fail = (error: string): VerificationResult => ({
      isValid: false,
      nullifierHash: payload?.nullifierHash ?? '',
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

    // 1. Real pairing check
    const verificationKey = await loadVerificationKey('telegram_auth', opts);
    const ok = await snarkjs.groth16.verify(
      verificationKey,
      payload.publicSignals,
      payload.proof
    );
    if (!ok) {
      return fail('groth16 verification failed');
    }

    // 2. Circuit gate must be satisfied
    if (!parsed.isVerified) {
      return fail('circuit gate isVerified != 1');
    }

    // 3. Domain binding
    const expectedDomainHash = await NullifierDeriver.hashAppDomain(expectedAppDomain);
    if (parsed.appDomainHash !== expectedDomainHash) {
      return fail('appDomainHash does not match expected app domain');
    }

    // 4. Freshness
    try {
      assertFreshTimestamp(parsed.currentTimestamp, parsed.maxTokenAgeSec, DEFAULT_SKEW_SEC);
    } catch (err) {
      return fail(err instanceof Error ? err.message : String(err));
    }

    return {
      isValid: true,
      nullifierHash: parsed.nullifierHash,
      appDomainHash: parsed.appDomainHash,
    };
  }
}
