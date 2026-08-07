import * as snarkjs from 'snarkjs';
import { loadVerificationKey, resolveArtifacts } from './artifacts.js';
import {
  MembershipProofInputs,
  MembershipProofPayload,
  ProofArtifactOptions,
  VerificationResult,
} from './types.js';

const MEMBERSHIP_DEPTH = 12;

/** Generate a depth-12 private-leaf Merkle membership proof. */
export async function generateMembershipProof(
  inputs: MembershipProofInputs,
  opts: ProofArtifactOptions = {}
): Promise<MembershipProofPayload> {
  if (inputs.pathElements.length !== MEMBERSHIP_DEPTH || inputs.pathIndices.length !== MEMBERSHIP_DEPTH) {
    throw new Error(`membership path must contain exactly ${MEMBERSHIP_DEPTH} levels`);
  }
  const pathIndices = inputs.pathIndices.map((value) => String(value));
  if (pathIndices.some((value) => value !== '0' && value !== '1')) {
    throw new Error('membership path indices must be 0 or 1');
  }

  const { wasm, zkey } = await resolveArtifacts('membership', opts);
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    {
      leaf: inputs.leaf,
      root: inputs.root,
      pathElements: inputs.pathElements,
      pathIndices,
    },
    wasm,
    zkey
  );
  if (publicSignals.length !== 2 || publicSignals[0] !== '1') {
    throw new Error('membership circuit did not produce an affirmative proof');
  }
  return { proof, publicSignals, isMember: true, root: publicSignals[1] };
}

/** Verify both the Groth16 proof and the relying party's expected Merkle root. */
export async function verifyMembershipProof(
  payload: MembershipProofPayload,
  expectedRoot: string,
  opts: ProofArtifactOptions = {}
): Promise<VerificationResult> {
  const fail = (error: string): VerificationResult => ({ isValid: false, nullifierHash: '', error });
  if (!payload?.proof || !Array.isArray(payload.publicSignals) || payload.publicSignals.length !== 2) {
    return fail('malformed membership proof payload');
  }
  if (payload.publicSignals[0] !== '1') return fail('membership gate is not satisfied');
  if (payload.publicSignals[1] !== expectedRoot) return fail('membership root does not match verifier policy');
  try {
    const verificationKey = await loadVerificationKey('membership', opts);
    const ok = await snarkjs.groth16.verify(verificationKey, payload.publicSignals, payload.proof);
    return ok ? { isValid: true, nullifierHash: '' } : fail('membership Groth16 verification failed');
  } catch (err) {
    return fail(`membership verification error: ${err instanceof Error ? err.message : String(err)}`);
  }
}
