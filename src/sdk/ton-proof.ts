import { Address, Cell } from '@ton/core';
import { proofToMessageCell } from 'export-ton-verifier';
import { Groth16Proof } from './types.js';
import { assertFieldElement } from './poseidon.js';

export const TON_GROTH16_VERIFY_OPCODE = 993839639;
export const TON_VERIFIER_MIN_VALUE_NANO = 50_000_000n;

function validateProof(proof: Groth16Proof): void {
  if (!proof || proof.protocol !== 'groth16' || proof.curve !== 'bls12381') throw new Error('proof must be a BLS12-381 Groth16 proof');
  if (!Array.isArray(proof.pi_a) || proof.pi_a.length !== 3 || !Array.isArray(proof.pi_c) || proof.pi_c.length !== 3 || !Array.isArray(proof.pi_b) || proof.pi_b.length !== 3 || proof.pi_b.some((pair) => !Array.isArray(pair) || pair.length !== 2)) {
    throw new Error('proof coordinates have an invalid Groth16 shape');
  }
}

function validateSignals(publicSignals: string[]): void {
  if (!Array.isArray(publicSignals) || publicSignals.length === 0 || publicSignals.length > 255) throw new Error('publicSignals must contain 1..255 values');
  for (const [index, value] of publicSignals.entries()) {
    if (typeof value !== 'string' || !/^(0|[1-9][0-9]*)$/.test(value)) throw new Error(`publicSignals[${index}] must be a canonical decimal field element`);
    assertFieldElement(BigInt(value), `publicSignals[${index}]`);
  }
}

/** Encode a verified BLS12-381 Groth16 proof for the generated Tolk verifier. */
export async function buildTonGroth16VerifierMessage(input: { proof: Groth16Proof; publicSignals: string[] }): Promise<Cell> {
  validateProof(input.proof);
  validateSignals(input.publicSignals);
  const cell = await proofToMessageCell({ proof: input.proof as unknown as Record<string, unknown>, publicSignals: input.publicSignals, protocol: 'groth16', lang: 'tolk' });
  const parsed = cell.beginParse();
  if (parsed.loadUint(32) !== TON_GROTH16_VERIFY_OPCODE) throw new Error('encoded TON verifier opcode mismatch');
  return cell;
}

export interface TonConnectVerificationRequest {
  verifierAddress: Address | string;
  proof: Groth16Proof;
  publicSignals: string[];
  /** Unix timestamp after which TonConnect should reject the request. */
  validUntil?: number;
  /** Attached TON value in nanograms; the verifier minimum is 0.05 TON. */
  valueNano?: bigint | string | number;
}

/** Build a TonConnect-compatible generic verifier transaction without broadcasting it. */
export async function buildTonVerifierTonConnectTransaction(request: TonConnectVerificationRequest): Promise<{ validUntil: number; messages: Array<{ address: string; amount: string; payload: string }> }> {
  const address = typeof request.verifierAddress === 'string' ? Address.parse(request.verifierAddress) : request.verifierAddress;
  const value = typeof request.valueNano === 'bigint' ? request.valueNano : BigInt(String(request.valueNano ?? TON_VERIFIER_MIN_VALUE_NANO));
  if (value < TON_VERIFIER_MIN_VALUE_NANO) throw new Error('valueNano must be at least 50000000');
  const validUntil = request.validUntil ?? Math.floor(Date.now() / 1000) + 300;
  if (!Number.isSafeInteger(validUntil) || validUntil <= Math.floor(Date.now() / 1000)) throw new Error('validUntil must be a future Unix timestamp');
  const body = await buildTonGroth16VerifierMessage({ proof: request.proof, publicSignals: request.publicSignals });
  return {
    validUntil,
    messages: [{ address: address.toString(), amount: value.toString(), payload: body.toBoc().toString('base64') }],
  };
}
