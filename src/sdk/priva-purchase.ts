import * as snarkjs from 'snarkjs';
import { loadVerificationKey, resolveArtifacts } from './artifacts.js';
import { NullifierDeriver } from './nullifier.js';
import { assertFreshTimestamp } from './public-signals.js';
import { assertFieldElement } from './poseidon.js';
import {
  PrivaPurchaseAuthInputs,
  PrivaPurchaseAuthProofPayload,
  PrivaPurchaseAuthVerificationPolicy,
  VerificationResult,
} from './types.js';

export const PRIVA_PURCHASE_AUTH_PUBLIC_SIGNALS = [
  'identityNullifier', 'actionNullifier', 'isAuthorized', 'appDomainHash',
  'currentTimestamp', 'maxTokenAgeSec', 'isPremiumRequired', 'issuerKeyHash',
  'launchIdHash', 'launchpadAddressHash', 'operation', 'recipientHash',
  'clientNonce', 'expiryEpoch', 'circuitVersion',
] as const;

const BUY_OPERATION = 1;
const CIRCUIT_VERSION = 1;
const MAX_UINT32 = 0xffff_ffff;

function parseField(value: string, name: string): string {
  if (!/^(0|[1-9][0-9]*)$/.test(value)) throw new Error(`${name} must be a canonical field element`);
  assertFieldElement(BigInt(value), name);
  return value;
}

function parseUInt(value: string, name: string): number {
  if (!/^(0|[1-9][0-9]*)$/.test(value)) throw new Error(`${name} must be a canonical non-negative integer`);
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) throw new Error(`${name} exceeds JavaScript safe-integer range`);
  return parsed;
}

function parseBit(value: string, name: string): boolean {
  if (value !== '0' && value !== '1') throw new Error(`${name} must be 0 or 1`);
  return value === '1';
}

export function parsePrivaPurchaseAuthPublicSignals(publicSignals: string[]): Omit<PrivaPurchaseAuthProofPayload, 'proof' | 'publicSignals'> {
  if (!Array.isArray(publicSignals) || publicSignals.length !== PRIVA_PURCHASE_AUTH_PUBLIC_SIGNALS.length) {
    throw new Error(`expected ${PRIVA_PURCHASE_AUTH_PUBLIC_SIGNALS.length} public signals, got ${publicSignals?.length}`);
  }
  return {
    identityNullifier: parseField(publicSignals[0], 'identityNullifier'),
    actionNullifier: parseField(publicSignals[1], 'actionNullifier'),
    isAuthorized: parseBit(publicSignals[2], 'isAuthorized'),
    appDomainHash: parseField(publicSignals[3], 'appDomainHash'),
    timestamp: parseUInt(publicSignals[4], 'currentTimestamp'),
    maxTokenAgeSec: parseUInt(publicSignals[5], 'maxTokenAgeSec'),
    isPremiumRequired: parseBit(publicSignals[6], 'isPremiumRequired'),
    issuerKeyHash: parseField(publicSignals[7], 'issuerKeyHash'),
    launchIdHash: parseField(publicSignals[8], 'launchIdHash'),
    launchpadAddressHash: parseField(publicSignals[9], 'launchpadAddressHash'),
    operation: parseUInt(publicSignals[10], 'operation'),
    recipientHash: parseField(publicSignals[11], 'recipientHash'),
    clientNonce: parseField(publicSignals[12], 'clientNonce'),
    expiryEpoch: parseUInt(publicSignals[13], 'expiryEpoch'),
    circuitVersion: parseUInt(publicSignals[14], 'circuitVersion'),
  };
}

export class PrivaPurchaseAuthProofGenerator {
  static async generateProof(inputs: PrivaPurchaseAuthInputs): Promise<PrivaPurchaseAuthProofPayload> {
    const now = inputs.currentTimestamp;
    const version = inputs.circuitVersion ?? CIRCUIT_VERSION;
    if (!/^[1-9][0-9]*$/.test(String(inputs.userId))) throw new Error('userId must be a positive integer');
    if (!/^[1-9][0-9]*$/.test(inputs.issuerSecret)) throw new Error('issuerSecret must be a positive decimal field element');
    if (!inputs.appDomain.trim()) throw new Error('appDomain must not be empty');
    if (!Number.isSafeInteger(now) || now < 0) throw new Error('currentTimestamp must be a non-negative safe integer');
    if (!Number.isSafeInteger(inputs.authDate) || inputs.authDate < 0) throw new Error('authDate must be a non-negative safe integer');
    if (!Number.isSafeInteger(inputs.maxTokenAgeSec) || !inputs.maxTokenAgeSec || inputs.maxTokenAgeSec > MAX_UINT32) throw new Error('maxTokenAgeSec must be in 1..2^32-1');
    if (!Number.isSafeInteger(inputs.expiryEpoch) || inputs.expiryEpoch < now) throw new Error('expiryEpoch must be a safe integer not before currentTimestamp');
    if (version !== CIRCUIT_VERSION) throw new Error(`unsupported Priva circuit version: ${version}`);

    const appDomainHash = await NullifierDeriver.hashAppDomain(inputs.appDomain);
    const issuerKeyHash = await NullifierDeriver.deriveIssuerKeyHash(inputs.issuerSecret);
    const { wasm, zkey } = await resolveArtifacts('priva_purchase_auth');
    const { proof, publicSignals } = await snarkjs.groth16.fullProve({
      appDomainHash,
      currentTimestamp: String(now),
      maxTokenAgeSec: String(inputs.maxTokenAgeSec),
      isPremiumRequired: inputs.isPremiumRequired ? '1' : '0',
      issuerKeyHash,
      launchIdHash: parseField(inputs.launchIdHash, 'launchIdHash'),
      launchpadAddressHash: parseField(inputs.launchpadAddressHash, 'launchpadAddressHash'),
      operation: String(BUY_OPERATION),
      recipientHash: parseField(inputs.recipientHash, 'recipientHash'),
      clientNonce: parseField(inputs.clientNonce, 'clientNonce'),
      expiryEpoch: String(inputs.expiryEpoch),
      circuitVersion: String(version),
      userId: String(inputs.userId),
      authDate: String(inputs.authDate),
      isPremium: inputs.isPremium ? '1' : '0',
      issuerSecret: inputs.issuerSecret,
    }, wasm, zkey);
    const parsed = parsePrivaPurchaseAuthPublicSignals(publicSignals);
    return { proof, publicSignals, ...parsed };
  }
}

export class PrivaPurchaseAuthProofVerifier {
  static async verifyProof(payload: PrivaPurchaseAuthProofPayload, policy: PrivaPurchaseAuthVerificationPolicy): Promise<VerificationResult> {
    const fail = (error: string): VerificationResult => ({ isValid: false, nullifierHash: '', error });
    let parsed;
    try { parsed = parsePrivaPurchaseAuthPublicSignals(payload?.publicSignals); }
    catch (error) { return fail(error instanceof Error ? error.message : String(error)); }
    if (!parsed.isAuthorized) return fail('circuit gate isAuthorized != 1');
    try {
      if (parsed.appDomainHash !== await NullifierDeriver.hashAppDomain(policy.expectedAppDomain)) return fail('appDomainHash does not match expected app domain');
      if (parsed.issuerKeyHash !== parseField(policy.expectedIssuerKeyHash, 'expectedIssuerKeyHash')) return fail('issuerKeyHash does not match authorized issuer');
      if (parsed.launchIdHash !== parseField(policy.expectedLaunchIdHash, 'expectedLaunchIdHash')) return fail('launchIdHash does not match policy');
      if (parsed.launchpadAddressHash !== parseField(policy.expectedLaunchpadAddressHash, 'expectedLaunchpadAddressHash')) return fail('launchpadAddressHash does not match policy');
      if (parsed.recipientHash !== parseField(policy.expectedRecipientHash, 'expectedRecipientHash')) return fail('recipientHash does not match policy');
      if (parsed.maxTokenAgeSec !== policy.maxTokenAgeSec || parsed.isPremiumRequired !== policy.requirePremium) return fail('credential policy does not match verifier policy');
      if (parsed.operation !== BUY_OPERATION) return fail('operation is not BUY');
      if (parsed.circuitVersion !== (policy.expectedCircuitVersion ?? CIRCUIT_VERSION)) return fail('circuitVersion does not match policy');
      if (!Number.isSafeInteger(policy.maxAuthorizationTtlSec) || policy.maxAuthorizationTtlSec <= 0) return fail('invalid maximum authorization TTL');
      if (parsed.expiryEpoch < parsed.timestamp || parsed.expiryEpoch - parsed.timestamp > policy.maxAuthorizationTtlSec) return fail('expiryEpoch exceeds verifier policy');
      assertFreshTimestamp(parsed.timestamp, policy.maxTokenAgeSec);
    } catch (error) { return fail(error instanceof Error ? error.message : String(error)); }
    try {
      const verificationKey = await loadVerificationKey('priva_purchase_auth');
      if (!await snarkjs.groth16.verify(verificationKey, payload.publicSignals, payload.proof)) return fail('groth16 verification failed');
    } catch (error) { return fail(`groth16 verification error: ${error instanceof Error ? error.message : String(error)}`); }
    return { isValid: true, nullifierHash: parsed.identityNullifier, appDomainHash: parsed.appDomainHash, issuerKeyHash: parsed.issuerKeyHash };
  }
}
