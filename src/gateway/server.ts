import * as http from 'http';
import { InitDataParser } from '../sdk/initdata-parser.js';
import { ZkAuthProofGenerator } from '../sdk/proof-generator.js';
import { ZkAuthProofVerifier } from '../sdk/proof-verifier.js';
import { PrivaPurchaseAuthProofGenerator, PrivaPurchaseAuthProofVerifier } from '../sdk/priva-purchase.js';
import { ProofArtifactOptions, PrivaPurchaseAuthProofPayload, ZkAuthProofPayload } from '../sdk/types.js';
import { NullifierDeriver } from '../sdk/nullifier.js';
import { assertFieldElement } from '../sdk/poseidon.js';

export interface ZkTeleAuthGatewayOptions {
  botToken: string;
  /** Stable private field element. Store this in a secret manager; never expose it to clients. */
  issuerSecret: string;
  appDomain: string;
  maxTokenAgeSec?: number;
  requirePremium?: boolean;
  corsOrigin?: string;
  maxBodyBytes?: number;
  maxConcurrentProofs?: number;
  artifactOpts?: ProofArtifactOptions;
}

const DEFAULT_MAX_TOKEN_AGE_SEC = 24 * 60 * 60;
const DEFAULT_MAX_BODY_BYTES = 64 * 1024;
const DEFAULT_MAX_CONCURRENT_PROOFS = 2;
const CLOCK_SKEW_SEC = 300;

export interface PrivaPurchaseAuthorizationRequest {
  launchIdHash: string;
  launchpadAddressHi: string;
  launchpadAddressLo: string;
  recipientAddressHi: string;
  recipientAddressLo: string;
  clientNonce: string;
  expiryEpoch: number;
  operation: 'BUY';
  circuitVersion?: number;
}

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
  private issuerSecret: string;
  private issuerKeyHash: Promise<string>;
  private appDomain: string;
  private maxTokenAgeSec: number;
  private requirePremium: boolean;
  private corsOrigin?: string;
  private maxBodyBytes: number;
  private maxConcurrentProofs: number;
  private activeProofs = 0;
  private artifactOpts: ProofArtifactOptions;

  constructor(options: ZkTeleAuthGatewayOptions) {
    if (!options.botToken) throw new Error('botToken is required');
    if (!options.appDomain?.trim()) throw new Error('appDomain is required');
    if (!/^[1-9][0-9]*$/.test(options.issuerSecret || '')) {
      throw new Error('issuerSecret must be a positive decimal field element');
    }
    assertFieldElement(BigInt(options.issuerSecret), 'issuerSecret');
    this.botToken = options.botToken;
    this.issuerSecret = options.issuerSecret;
    this.issuerKeyHash = NullifierDeriver.deriveIssuerKeyHash(options.issuerSecret);
    this.appDomain = options.appDomain;
    this.maxTokenAgeSec = options.maxTokenAgeSec ?? DEFAULT_MAX_TOKEN_AGE_SEC;
    this.requirePremium = options.requirePremium ?? false;
    this.corsOrigin = options.corsOrigin;
    this.maxBodyBytes = options.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES;
    this.maxConcurrentProofs = options.maxConcurrentProofs ?? DEFAULT_MAX_CONCURRENT_PROOFS;
    this.artifactOpts = options.artifactOpts ?? {};
    if (!Number.isSafeInteger(this.maxTokenAgeSec) || this.maxTokenAgeSec <= 0 || this.maxTokenAgeSec > 0xffff_ffff) {
      throw new Error('maxTokenAgeSec must be an integer in 1..2^32-1');
    }
    if (!Number.isSafeInteger(this.maxBodyBytes) || this.maxBodyBytes <= 0) {
      throw new Error('maxBodyBytes must be a positive integer');
    }
    if (!Number.isSafeInteger(this.maxConcurrentProofs) || this.maxConcurrentProofs <= 0) {
      throw new Error('maxConcurrentProofs must be a positive integer');
    }
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
    if (!Number.isSafeInteger(user.id) || user.id <= 0) {
      throw new Error('initData carries no Telegram user id');
    }

    const now = Math.floor(Date.now() / 1000);
    if (!Number.isSafeInteger(raw.auth_date) || raw.auth_date <= 0) {
      throw new Error('initData carries an invalid auth_date');
    }
    if (raw.auth_date > now + CLOCK_SKEW_SEC) throw new Error('initData auth_date is in the future');
    if (now - raw.auth_date > this.maxTokenAgeSec) throw new Error('Telegram initData expired');
    if (this.activeProofs >= this.maxConcurrentProofs) throw new Error('prover busy; retry later');

    this.activeProofs += 1;
    try {
      const issuerKeyHash = await this.issuerKeyHash;

      const proofPayload = await ZkAuthProofGenerator.generateProof(
        {
          userId: user.id,
          authDate: raw.auth_date,
          isPremium: Boolean(user.is_premium),
          appDomain: this.appDomain,
          currentTimestamp: now,
          maxTokenAgeSec: this.maxTokenAgeSec,
          isPremiumRequired: this.requirePremium,
          issuerSecret: this.issuerSecret,
        },
        this.artifactOpts
      );

      const verification = await ZkAuthProofVerifier.verifyProof(
        proofPayload,
        {
          expectedAppDomain: this.appDomain,
          expectedIssuerKeyHash: issuerKeyHash,
          maxTokenAgeSec: this.maxTokenAgeSec,
          requirePremium: this.requirePremium,
        },
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
    } finally {
      this.activeProofs -= 1;
    }
  }

  /**
   * Produce a Priva-bound proof after validating the Telegram session and every
   * public action field. The gateway cannot substitute a launch or recipient:
   * the proof verifier pins those fields again before settlement.
   */
  async handlePrivaPurchaseAuthorization(
    rawInitData: string,
    request: PrivaPurchaseAuthorizationRequest
  ): Promise<{
    success: true;
    identityNullifier: string;
    actionNullifier: string;
    proofPayload: PrivaPurchaseAuthProofPayload;
  }> {
    if (!rawInitData || typeof rawInitData !== 'string') throw new Error('empty initData payload');
    if (!request || request.operation !== 'BUY') throw new Error('only BUY authorizations are supported');
    for (const [name, value] of Object.entries({
      launchIdHash: request.launchIdHash,
      launchpadAddressHi: request.launchpadAddressHi,
      launchpadAddressLo: request.launchpadAddressLo,
      recipientAddressHi: request.recipientAddressHi,
      recipientAddressLo: request.recipientAddressLo,
      clientNonce: request.clientNonce,
    })) {
      if (typeof value !== 'string' || !/^(0|[1-9][0-9]*)$/.test(value)) {
        throw new Error(`${name} must be a canonical field element`);
      }
      assertFieldElement(BigInt(value), name);
    }
    if (!Number.isSafeInteger(request.expiryEpoch)) throw new Error('expiryEpoch must be a safe integer');
    if (request.circuitVersion !== undefined && request.circuitVersion !== 1) throw new Error('unsupported Priva circuit version');

    const isValidSig = InitDataParser.validateSignature(rawInitData, this.botToken);
    if (!isValidSig) throw new Error('Invalid Telegram initData HMAC signature');
    const { user, raw } = InitDataParser.parse(rawInitData);
    if (!Number.isSafeInteger(user.id) || user.id <= 0) throw new Error('initData carries no Telegram user id');
    const now = Math.floor(Date.now() / 1000);
    if (!Number.isSafeInteger(raw.auth_date) || raw.auth_date <= 0) throw new Error('initData carries an invalid auth_date');
    if (raw.auth_date > now + CLOCK_SKEW_SEC) throw new Error('initData auth_date is in the future');
    if (now - raw.auth_date > this.maxTokenAgeSec) throw new Error('Telegram initData expired');
    if (request.expiryEpoch < now || request.expiryEpoch - now > this.maxTokenAgeSec) {
      throw new Error('expiryEpoch is outside the gateway authorization window');
    }
    if (this.activeProofs >= this.maxConcurrentProofs) throw new Error('prover busy; retry later');

    this.activeProofs += 1;
    try {
      const issuerKeyHash = await this.issuerKeyHash;
      const proofPayload = await PrivaPurchaseAuthProofGenerator.generateProof({
        userId: user.id,
        authDate: raw.auth_date,
        isPremium: Boolean(user.is_premium),
        appDomain: this.appDomain,
        currentTimestamp: now,
        maxTokenAgeSec: this.maxTokenAgeSec,
        isPremiumRequired: this.requirePremium,
        issuerSecret: this.issuerSecret,
        launchIdHash: request.launchIdHash,
        launchpadAddressHi: request.launchpadAddressHi,
        launchpadAddressLo: request.launchpadAddressLo,
        recipientAddressHi: request.recipientAddressHi,
        recipientAddressLo: request.recipientAddressLo,
        clientNonce: request.clientNonce,
        expiryEpoch: request.expiryEpoch,
        circuitVersion: 1,
      });
      const verification = await PrivaPurchaseAuthProofVerifier.verifyProof(proofPayload, {
        expectedAppDomain: this.appDomain,
        expectedIssuerKeyHash: issuerKeyHash,
        maxTokenAgeSec: this.maxTokenAgeSec,
        requirePremium: this.requirePremium,
        expectedLaunchIdHash: request.launchIdHash,
        expectedLaunchpadAddressHi: request.launchpadAddressHi,
        expectedLaunchpadAddressLo: request.launchpadAddressLo,
        expectedRecipientAddressHi: request.recipientAddressHi,
        expectedRecipientAddressLo: request.recipientAddressLo,
        maxAuthorizationTtlSec: this.maxTokenAgeSec,
        expectedCircuitVersion: 1,
      });
      if (!verification.isValid) throw new Error(`self-check verification failed: ${verification.error}`);
      return {
        success: true,
        identityNullifier: proofPayload.identityNullifier,
        actionNullifier: proofPayload.actionNullifier,
        proofPayload,
      };
    } finally {
      this.activeProofs -= 1;
    }
  }

  /**
   * Minimal zero-dependency HTTP server exposing POST /authenticate.
   * Body: { "initData": "query_id=...&user=...&hash=..." }
   */
  createServer(): http.Server {
    return http.createServer(async (req, res) => {
      if (this.corsOrigin) res.setHeader('Access-Control-Allow-Origin', this.corsOrigin);
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
      res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
      if (req.method === 'OPTIONS') {
        res.writeHead(204);
        res.end();
        return;
      }

      if (req.method !== 'POST' || (req.url !== '/authenticate' && req.url !== '/v1/purchase-authorizations')) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'not found' }));
        return;
      }

      let body = '';
      let bodyBytes = 0;
      let bodyRejected = false;
      req.on('data', (chunk: Buffer) => {
        if (bodyRejected) return;
        bodyBytes += chunk.length;
        if (bodyBytes > this.maxBodyBytes) {
          bodyRejected = true;
          res.writeHead(413, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'request body too large' }));
          return;
        }
        body += chunk.toString('utf8');
      });
      req.on('end', async () => {
        if (bodyRejected) return;
        try {
          const parsed = JSON.parse(body || '{}');
          const initData = parsed.initData;
          if (typeof initData !== 'string') {
            throw new Error('body must include a string "initData" field');
          }
          const result = req.url === '/v1/purchase-authorizations'
            ? await this.handlePrivaPurchaseAuthorization(initData, parsed)
            : await this.handleAuthenticate(initData);
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify(result));
        } catch (err) {
          const message = err instanceof Error ? err.message : String(err);
          const status = message.startsWith('prover busy') ? 429 : 400;
          res.writeHead(status, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: message }));
        }
      });
    });
  }
}
