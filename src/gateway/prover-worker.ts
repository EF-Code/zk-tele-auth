import { ZkAuthProofGenerator } from '../sdk/proof-generator.js';
import { PrivaPurchaseAuthProofGenerator } from '../sdk/priva-purchase.js';
import { ProofArtifactOptions, PrivaPurchaseAuthInputs, PrivaPurchaseAuthProofPayload, ZkAuthProofInputs, ZkAuthProofPayload } from '../sdk/types.js';

type AuthenticateJob = { jobId: number; kind: 'authenticate'; inputs: ZkAuthProofInputs; artifactOpts: ProofArtifactOptions };
type PrivaJob = { jobId: number; kind: 'priva'; inputs: PrivaPurchaseAuthInputs };
type Job = AuthenticateJob | PrivaJob;

process.on('message', async (job: Job) => {
  try {
    const result: ZkAuthProofPayload | PrivaPurchaseAuthProofPayload = job.kind === 'authenticate'
      ? await ZkAuthProofGenerator.generateProof(job.inputs, job.artifactOpts)
      : await PrivaPurchaseAuthProofGenerator.generateProof(job.inputs);
    process.send?.({ jobId: job.jobId, ok: true, result });
  } catch (error) {
    // Error messages are intentionally generic at the process boundary. The
    // gateway owns the client-facing error policy and never forwards secrets.
    process.send?.({
      jobId: job.jobId,
      ok: false,
      error: error instanceof Error ? error.message : 'proof generation failed',
    });
  }
});
