import { InitDataParser } from '../sdk/initdata-parser.js';
import { ZkAuthProofGenerator } from '../sdk/proof-generator.js';
import { ZkAuthProofVerifier } from '../sdk/proof-verifier.js';

export class ZkTeleAuthGateway {
  private botToken: string;
  private appDomain: string;

  constructor(botToken: string, appDomain: string) {
    this.botToken = botToken;
    this.appDomain = appDomain;
  }

  /**
   * Handle incoming MiniApp authentication request and generate ZK Proof
   * @param rawInitData Raw initData string from Telegram MiniApp
   * @returns Proof payload
   */
  async handleAuthenticate(rawInitData: string) {
    // 1. Validate signature using bot token
    const isValidSig = InitDataParser.validateSignature(rawInitData, this.botToken);
    if (!isValidSig) {
      throw new Error('Invalid Telegram initData HMAC signature');
    }

    // 2. Parse user data
    const { user, raw } = InitDataParser.parse(rawInitData);

    // 3. Generate ZK Proof on client / gateway
    const proofPayload = await ZkAuthProofGenerator.generateProof({
      userId: user.id,
      authDate: raw.auth_date,
      isPremium: Boolean(user.is_premium),
      appDomain: this.appDomain,
      currentTimestamp: Math.floor(Date.now() / 1000)
    });

    // 4. Verify proof locally
    const verification = await ZkAuthProofVerifier.verifyProof(proofPayload, this.appDomain);
    if (!verification.isValid) {
      throw new Error(`Proof verification failed: ${verification.error}`);
    }

    return {
      success: true,
      nullifierHash: proofPayload.nullifierHash,
      proofPayload
    };
  }
}
