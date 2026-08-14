import * as http from 'http';
import * as crypto from 'node:crypto';
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
  requestTimeoutMs?: number;
  headersTimeoutMs?: number;
  keepAliveTimeoutMs?: number;
  maxQueueDepth?: number;
  exposeHttpErrors?: boolean;
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
  private requestTimeoutMs: number;
  private headersTimeoutMs: number;
  private keepAliveTimeoutMs: number;
  private maxQueueDepth: number;
  private exposeHttpErrors: boolean;
  private activeProofs = 0;
  private queuedProofs = 0;
  private proofSlotWaiters: Array<() => void> = [];
  private requestCount = 0;
  private rejectedRequestCount = 0;
  private completedRequestCount = 0;
  private failedRequestCount = 0;
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
    this.requestTimeoutMs = options.requestTimeoutMs ?? 30_000;
    this.headersTimeoutMs = options.headersTimeoutMs ?? 10_000;
    this.keepAliveTimeoutMs = options.keepAliveTimeoutMs ?? 5_000;
    this.maxQueueDepth = options.maxQueueDepth ?? 0;
    this.exposeHttpErrors = options.exposeHttpErrors ?? false;
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
    for (const [name, value] of [
      ['requestTimeoutMs', this.requestTimeoutMs],
      ['headersTimeoutMs', this.headersTimeoutMs],
      ['keepAliveTimeoutMs', this.keepAliveTimeoutMs],
    ] as const) {
      if (!Number.isSafeInteger(value) || value < 1000) throw new Error(`${name} must be an integer >= 1000`);
    }
    if (!Number.isSafeInteger(this.maxQueueDepth) || this.maxQueueDepth < 0) throw new Error('maxQueueDepth must be a non-negative integer');
  }

  private async acquireProofSlot(): Promise<void> {
    if (this.activeProofs < this.maxConcurrentProofs) {
      this.activeProofs += 1;
      return;
    }
    if (this.queuedProofs >= this.maxQueueDepth) throw new Error('prover busy; retry later');
    this.queuedProofs += 1;
    await new Promise<void>((resolve) => this.proofSlotWaiters.push(resolve));
    this.queuedProofs -= 1;
    this.activeProofs += 1;
  }

  private releaseProofSlot(): void {
    this.activeProofs -= 1;
    const next = this.proofSlotWaiters.shift();
    if (next) next();
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
    await this.acquireProofSlot();
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
      this.releaseProofSlot();
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
    await this.acquireProofSlot();
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
      this.releaseProofSlot();
    }
  }

  /**
   * Minimal zero-dependency HTTP server exposing POST /authenticate.
   * Body: { "initData": "query_id=...&user=...&hash=..." }
   */
  createServer(): http.Server {
    const server = http.createServer(async (req, res) => {
      const requestId = crypto.randomUUID();
      this.requestCount += 1;
      res.setHeader('X-Request-Id', requestId);
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader('Cache-Control', 'no-store');
      if (this.corsOrigin) res.setHeader('Access-Control-Allow-Origin', this.corsOrigin);
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
      res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
      const pathname = (() => {
        try { return new URL(req.url || '/', 'http://localhost').pathname; }
        catch { return ''; }
      })();
      if (req.method === 'GET' && pathname === '/livez') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'ok' }));
        return;
      }
      if (req.method === 'GET' && pathname === '/readyz') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'ready', activeProofs: this.activeProofs, queuedProofs: this.queuedProofs, maxConcurrentProofs: this.maxConcurrentProofs }));
        return;
      }
      if (req.method === 'GET' && pathname === '/metrics') {
        res.writeHead(200, { 'Content-Type': 'text/plain; version=0.0.4; charset=utf-8' });
        res.end([
          `zk_tele_auth_requests_total ${this.requestCount}`,
          `zk_tele_auth_requests_completed_total ${this.completedRequestCount}`,
          `zk_tele_auth_requests_failed_total ${this.failedRequestCount}`,
          `zk_tele_auth_requests_rejected_total ${this.rejectedRequestCount}`,
          `zk_tele_auth_active_proofs ${this.activeProofs}`,
        ].join('\n') + '\n');
        return;
      }
      if (req.method === 'OPTIONS' && (pathname === '/authenticate' || pathname === '/v1/purchase-authorizations')) {
        res.writeHead(204);
        res.end();
        return;
      }

      if (req.method !== 'POST' || (pathname !== '/authenticate' && pathname !== '/v1/purchase-authorizations')) {
        this.rejectedRequestCount += 1;
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'not found', code: 'NOT_FOUND' }));
        return;
      }
      const contentType = String(req.headers['content-type'] || '').split(';', 1)[0].trim().toLowerCase();
      if (contentType !== 'application/json') {
        this.rejectedRequestCount += 1;
        res.writeHead(415, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'content type must be application/json', code: 'UNSUPPORTED_MEDIA_TYPE' }));
        return;
      }
      if (this.activeProofs + this.queuedProofs >= this.maxConcurrentProofs + this.maxQueueDepth) {
        this.rejectedRequestCount += 1;
        res.writeHead(429, { 'Content-Type': 'application/json', 'Retry-After': '1' });
        res.end(JSON.stringify({ error: 'prover busy; retry later', code: 'PROVER_BUSY' }));
        return;
      }

      let body = '';
      let bodyBytes = 0;
      let bodyRejected = false;
      let ended = false;
      const rejectBody = (status: number, error: string, code: string) => {
        if (ended) return;
        ended = true;
        this.rejectedRequestCount += 1;
        res.writeHead(status, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error, code }));
      };
      req.on('data', (chunk: Buffer) => {
        if (bodyRejected || ended) return;
        bodyBytes += chunk.length;
        if (bodyBytes > this.maxBodyBytes) {
          bodyRejected = true;
          rejectBody(413, 'request body too large', 'BODY_TOO_LARGE');
          return;
        }
        body += chunk.toString('utf8');
      });
      req.on('aborted', () => { bodyRejected = true; });
      req.on('error', () => { bodyRejected = true; rejectBody(400, 'request stream failed', 'REQUEST_STREAM_FAILED'); });
      req.on('end', async () => {
        if (bodyRejected || ended) return;
        try {
          const parsed = JSON.parse(body || '{}');
          const initData = parsed.initData;
          if (typeof initData !== 'string') {
            throw new Error('body must include a string "initData" field');
          }
          const result = pathname === '/v1/purchase-authorizations'
            ? await this.handlePrivaPurchaseAuthorization(initData, parsed)
            : await this.handleAuthenticate(initData);
          this.completedRequestCount += 1;
          ended = true;
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify(result));
        } catch (err) {
          const message = err instanceof Error ? err.message : String(err);
          const status = message.startsWith('prover busy') ? 429 : 400;
          this.failedRequestCount += 1;
          ended = true;
          res.writeHead(status, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            error: this.exposeHttpErrors ? message : 'request rejected',
            code: status === 429 ? 'PROVER_BUSY' : 'REQUEST_REJECTED',
            requestId,
          }));
        }
      });
    });
    server.requestTimeout = this.requestTimeoutMs;
    server.headersTimeout = this.headersTimeoutMs;
    server.keepAliveTimeout = this.keepAliveTimeoutMs;
    return server;
  }
}
