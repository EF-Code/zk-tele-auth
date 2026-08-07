import * as snarkjs from 'snarkjs';
import { NullifierDeriver } from './nullifier.js';
import { resolveArtifacts } from './artifacts.js';
import { buildPayload } from './public-signals.js';
import { ProofArtifactOptions, ZkAuthProofInputs, ZkAuthProofPayload } from './types.js';
import { assertFieldElement } from './poseidon.js';

const DEFAULT_MAX_TOKEN_AGE_SEC = 24 * 60 * 60; // 24h
const MAX_UINT32 = 0xffff_ffff;

function assertUnsignedSafeInteger(value: number, name: string): void {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error(`${name} must be a non-negative safe integer`);
}

/**
 * Generate a real Groth16 proof for the telegram_auth circuit.
 *
 * The gateway (which holds the bot token) authenticates the Telegram initData
 * off-circuit and then calls this to produce the zero-knowledge proof that a
 * dApp or TON smart contract can verify without learning the userId.
 *
 * Circuit input names must match the circom template exactly; values are
 * provided as decimal strings.
 */
export class ZkAuthProofGenerator {
  static async generateProof(
    inputs: ZkAuthProofInputs,
    opts: ProofArtifactOptions = {}
  ): Promise<ZkAuthProofPayload> {
    const {
      userId,
      authDate,
      isPremium,
      appDomain,
      currentTimestamp,
      maxTokenAgeSec = DEFAULT_MAX_TOKEN_AGE_SEC,
      isPremiumRequired = false,
      issuerSecret,
    } = inputs;

    const userIdString = String(userId);
    if (!/^[1-9][0-9]*$/.test(userIdString)) throw new Error('userId must be a positive integer');
    if (!/^[1-9][0-9]*$/.test(issuerSecret)) {
      throw new Error('issuerSecret must be a positive decimal field element');
    }
    assertFieldElement(BigInt(userIdString), 'userId');
    assertFieldElement(BigInt(issuerSecret), 'issuerSecret');
    if (!appDomain.trim()) throw new Error('appDomain must not be empty');
    assertUnsignedSafeInteger(authDate, 'authDate');
    assertUnsignedSafeInteger(currentTimestamp, 'currentTimestamp');
    if (!Number.isSafeInteger(maxTokenAgeSec) || maxTokenAgeSec <= 0 || maxTokenAgeSec > MAX_UINT32) {
      throw new Error('maxTokenAgeSec must be an integer in 1..2^32-1');
    }

    const appDomainHash = await NullifierDeriver.hashAppDomain(appDomain);
    const issuerKeyHash = await NullifierDeriver.deriveIssuerKeyHash(issuerSecret);

    const circuitInput = {
      appDomainHash,
      currentTimestamp: String(currentTimestamp),
      maxTokenAgeSec: String(maxTokenAgeSec),
      isPremiumRequired: isPremiumRequired ? '1' : '0',
      issuerKeyHash,
      userId: userIdString,
      authDate: String(authDate),
      isPremium: isPremium ? '1' : '0',
      issuerSecret,
    };

    const { wasm, zkey } = await resolveArtifacts('telegram_auth', opts);
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(circuitInput, wasm, zkey);

    return buildPayload(proof, publicSignals);
  }
}
