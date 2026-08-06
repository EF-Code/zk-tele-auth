import * as http from 'http';
import { InitDataParser } from '../sdk/initdata-parser.js';
import { ZkAuthProofGenerator } from '../sdk/proof-generator.js';
import { ZkAuthProofVerifier } from '../sdk/proof-verifier.js';
import { ProofArtifactOptions, ZkAuthProofPayload } from '../sdk/types.js';

/**
 * ZkTeleAuthGateway
 *
 * Server-side prover that authenticates Telegram MiniApp initData against the
 * bot token (HMAC-SHA256) and then emits a real Groth16 proof for the
 * telegram_auth circuit. Because the HMAC secret (the bot token) can never be
 * shipped inside a circuit, the gateway is the trusted prover: only a session
 * that passed Telegram signature validation is ever turned into a proof.
 *
 * The proof itself is verified locally before being returned, so callers
 * receive a proof that already satisfies the full public-signal checks.
 */
export class ZkTeleAuthGateway {
  private botToken: string;
  private appDomain: string;
  private maxTokenAgeSec: number;
  private artifactOpts: ProofArtifactOptions;

  constructor(botToken: string, appDomain: string, maxTokenAgeSec = 24 * 60 * 60, artifactOpts: ProofArtifactOptions = {}) {
    this.botToken = botToken;
    this.appDomain = appDomain;
    this.maxTokenAgeSec = maxTokenAgeSec;
    this.artifactOpts = artifactOpts;
  }

  /**
   * Authenticate a raw Telegram initData query string and produce a proof.
   * @throws when the HMAC signature is invalid or proof generation fails.
   */
  async handleAuthenticate(rawInitData: string): Promise<{
    success: true;
    nullifierHash: string;
    proofPayload: ZkAuthProofPayload;
  }> {
    if (!rawInitData || typeof rawInitData !== 'string') {
      throw new Error('empty initData payload');
    }

    const isValidSig = InitDataParser.validateSignature(rawInitData, this.botToken);
    if (!isValidSig) {
      throw new Error('Invalid Telegram initData HMAC signature');
    }

    const { user, raw } = InitDataParser.parse(rawInitData);
    if (!user.id) {
      throw new Error('initData carries no Telegram user id');
    }

    const proofPayload = await ZkAuthProofGenerator.generateProof(
      {
        userId: user.id,
        authDate: raw.auth_date,
        isPremium: Boolean(user.is_premium),
        appDomain: this.appDomain,
        currentTimestamp: Math.floor(Date.now() / 1000),
        maxTokenAgeSec: this.maxTokenAgeSec,
      },
      this.artifactOpts
    );

    const verification = await ZkAuthProofVerifier.verifyProof(
      proofPayload,
      this.appDomain,
      this.artifactOpts
    );
    if (!verification.isValid) {
      throw new Error(`self-check verification failed: ${verification.error}`);
    }

    return {
      success: true,
      nullifierHash: proofPayload.nullifierHash,
      proofPayload,
    };
  }

  /**
   * Minimal zero-dependency HTTP server exposing POST /authenticate.
   * Body: { "initData": "query_id=...&user=...&hash=..." }
   */
  createServer(): http.Server {
    return http.createServer(async (req, res) => {
      res.setHeader('Access-Control-Allow-Origin', '*');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
      res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
      if (req.method === 'OPTIONS') {
        res.writeHead(204);
        res.end();
        return;
      }

      if (req.method !== 'POST' || req.url !== '/authenticate') {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'not found' }));
        return;
      }

      let body = '';
      req.on('data', (chunk) => (body += chunk));
      req.on('end', async () => {
        try {
          const parsed = JSON.parse(body || '{}');
          const initData = parsed.initData;
          if (typeof initData !== 'string') {
            throw new Error('body must include a string "initData" field');
          }
          const result = await this.handleAuthenticate(initData);
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify(result));
        } catch (err) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: err instanceof Error ? err.message : String(err) }));
        }
      });
    });
  }
}
