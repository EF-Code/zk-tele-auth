import * as snarkjs from 'snarkjs';
import { NullifierDeriver } from './nullifier.js';
import { CryptoUtils } from './crypto-utils.js';
import { resolveArtifacts } from './artifacts.js';
import { buildPayload } from './public-signals.js';
import { ProofArtifactOptions, ZkAuthProofInputs, ZkAuthProofPayload } from './types.js';

const DEFAULT_MAX_TOKEN_AGE_SEC = 24 * 60 * 60; // 24h

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
      salt = CryptoUtils.randomSalt(),
    } = inputs;

    const appDomainHash = await NullifierDeriver.hashAppDomain(appDomain);

    const circuitInput = {
      appDomainHash,
      currentTimestamp: String(currentTimestamp),
      maxTokenAgeSec: String(maxTokenAgeSec),
      isPremiumRequired: isPremiumRequired ? '1' : '0',
      userId: String(userId),
      authDate: String(authDate),
      isPremium: isPremium ? '1' : '0',
      salt,
    };

    const { wasm, zkey } = await resolveArtifacts('telegram_auth', opts);
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(circuitInput, wasm, zkey);

    return buildPayload(proof, publicSignals);
  }
}
