import * as http from 'http';
import * as crypto from 'node:crypto';
import { InitDataParser } from '../sdk/initdata-parser.js';
import { ZkAuthProofVerifier } from '../sdk/proof-verifier.js';
import { PrivaPurchaseAuthProofVerifier } from '../sdk/priva-purchase.js';
import { ProofArtifactOptions, PrivaPurchaseAuthProofPayload, ZkAuthProofPayload } from '../sdk/types.js';
import { NullifierDeriver } from '../sdk/nullifier.js';
import { assertFieldElement } from '../sdk/poseidon.js';
import { ProverExecutor, ProverPool } from './prover-pool.js';

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
  proofTimeoutMs?: number;
  expectedIssuerKeyHash?: string;
  maxAuthorizationTtlSec?: number;
  /** Priva is experimental and disabled unless explicitly enabled. */
  enableExperimentalPriva?: boolean;
  exposeHttpErrors?: boolean;
  artifactOpts?: ProofArtifactOptions;
  /** Inject a bounded pool in tests or a platform-specific worker supervisor. */
  proverPool?: ProverExecutor;
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
  private proofTimeoutMs: number;
  private expectedIssuerKeyHash?: string;
  private maxAuthorizationTtlSec: number;
  private enableExperimentalPriva: boolean;
  private exposeHttpErrors: boolean;
  private activeProofs = 0;
  private queuedProofs = 0;
  private proofSlotWaiters: Array<() => void> = [];
  private requestCount = 0;
  private rejectedRequestCount = 0;
  private completedRequestCount = 0;
  private failedRequestCount = 0;
  private artifactOpts: ProofArtifactOptions;
  private proverPool: ProverExecutor;
  private accepting = true;
  private ready = false;
  private inFlightRequests = 0;
  private drainWaiters: Array<() => void> = [];

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
    this.proofTimeoutMs = options.proofTimeoutMs ?? 30_000;
    this.expectedIssuerKeyHash = options.expectedIssuerKeyHash;
    this.maxAuthorizationTtlSec = options.maxAuthorizationTtlSec ?? this.maxTokenAgeSec;
    this.enableExperimentalPriva = options.enableExperimentalPriva ?? false;
    this.exposeHttpErrors = options.exposeHttpErrors ?? false;
    this.artifactOpts = options.artifactOpts ?? {};
    this.proverPool = options.proverPool ?? new ProverPool({
      maxWorkers: this.maxConcurrentProofs,
      // The gateway admission queue owns HTTP overload accounting. Once a
      // request has acquired a slot, its worker job is dispatched immediately.
      maxQueueDepth: 0,
      jobTimeoutMs: this.proofTimeoutMs,
    });
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
    if (!Number.isSafeInteger(this.proofTimeoutMs) || this.proofTimeoutMs < 1000) throw new Error('proofTimeoutMs must be an integer >= 1000');
    if (!Number.isSafeInteger(this.maxAuthorizationTtlSec) || this.maxAuthorizationTtlSec <= 0 || this.maxAuthorizationTtlSec > this.maxTokenAgeSec) throw new Error('maxAuthorizationTtlSec must be in 1..maxTokenAgeSec');
    if (this.expectedIssuerKeyHash !== undefined) {
      assertFieldElement(BigInt(this.expectedIssuerKeyHash), 'expectedIssuerKeyHash');
    }
  }

  /** Validate the independently configured issuer commitment before readiness. */
  async verifyStartupPolicy(): Promise<void> {
    const derived = await this.issuerKeyHash;
    if (this.expectedIssuerKeyHash !== undefined && derived !== this.expectedIssuerKeyHash) {
      throw new Error('configured issuer commitment does not match issuerSecret');
    }
  }

  markReady(): void { this.ready = true; }
  markNotReady(): void { this.ready = false; }
  stopAccepting(): void {
    this.accepting = false;
    if (this.inFlightRequests === 0) this.resolveDrainWaiters();
  }
  async close(): Promise<void> {
    await this.proverPool.close();
  }
  async drain(timeoutMs = this.requestTimeoutMs): Promise<boolean> {
    if (this.inFlightRequests === 0) return true;
    return new Promise<boolean>((resolve) => {
      const timer = setTimeout(() => resolve(false), timeoutMs);
      this.drainWaiters.push(() => { clearTimeout(timer); resolve(true); });
    });
  }
  private resolveDrainWaiters(): void {
    const waiters = this.drainWaiters.splice(0);
    for (const waiter of waiters) waiter();
  }
  readiness(): { ready: boolean; activeProofs: number; queuedProofs: number; maxConcurrentProofs: number } {
    return { ready: this.ready, activeProofs: this.activeProofs, queuedProofs: this.queuedProofs, maxConcurrentProofs: this.maxConcurrentProofs };
  }

  private async withProofTimeout<T>(work: Promise<T>): Promise<T> {
    let timer: NodeJS.Timeout | undefined;
    try {
      return await Promise.race([
        work,
        new Promise<T>((_, reject) => { timer = setTimeout(() => reject(new Error('proof generation timed out')), this.proofTimeoutMs); }),
      ]);
    } finally {
      if (timer) clearTimeout(timer);
    }
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

      const proofPayload = await this.withProofTimeout(this.proverPool.run({
        kind: 'authenticate',
        inputs: {
          userId: user.id,
          authDate: raw.auth_date,
          isPremium: Boolean(user.is_premium),
          appDomain: this.appDomain,
          currentTimestamp: now,
          maxTokenAgeSec: this.maxTokenAgeSec,
          isPremiumRequired: this.requirePremium,
          issuerSecret: this.issuerSecret,
        },
        artifactOpts: this.artifactOpts,
      }));

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
    if (request.expiryEpoch < now || request.expiryEpoch - now > this.maxAuthorizationTtlSec) {
      throw new Error('expiryEpoch is outside the gateway authorization window');
    }
    await this.acquireProofSlot();
    try {
      const issuerKeyHash = await this.issuerKeyHash;
      const proofPayload = await this.withProofTimeout(this.proverPool.run({
        kind: 'priva',
        inputs: {
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
        },
      }));
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
        maxAuthorizationTtlSec: this.maxAuthorizationTtlSec,
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
      if (!this.accepting) {
        res.writeHead(503, { 'Content-Type': 'application/json', 'Retry-After': '1' });
        res.end(JSON.stringify({ error: 'server is draining', code: 'SERVER_DRAINING' }));
        return;
      }
      const requestId = crypto.randomUUID();
      this.requestCount += 1;
      this.inFlightRequests += 1;
      const finishRequest = () => {
        this.inFlightRequests -= 1;
        if (!this.accepting && this.inFlightRequests === 0) this.resolveDrainWaiters();
      };
      res.once('finish', finishRequest);
      res.once('close', () => { if (!res.writableFinished) finishRequest(); });
      res.setHeader('X-Request-Id', requestId);
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader('Cache-Control', 'no-store');
      if (this.corsOrigin) {
        res.setHeader('Access-Control-Allow-Origin', this.corsOrigin);
        res.setHeader('Vary', 'Origin');
      }
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
        const status = this.readiness();
        res.writeHead(status.ready ? 200 : 503, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: status.ready ? 'ready' : 'not_ready', ...status }));
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
      const isLegacyAuthentication = pathname === '/authenticate';
      const isAuthentication = pathname === '/v1/authentications' || isLegacyAuthentication;
      const isExperimentalPriva = pathname === '/v1/purchase-authorizations';
      if (isLegacyAuthentication) res.setHeader('Deprecation', 'true');
      if (req.method === 'OPTIONS' && (isAuthentication || (isExperimentalPriva && this.enableExperimentalPriva))) {
        const origin = String(req.headers.origin || '');
        if (this.corsOrigin && origin !== this.corsOrigin) {
          res.writeHead(403, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'origin is not allowed', code: 'CORS_ORIGIN_DENIED' }));
          return;
        }
        res.writeHead(204);
        res.end();
        return;
      }

      if (req.method !== 'POST' || (!isAuthentication && !(isExperimentalPriva && this.enableExperimentalPriva))) {
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
      const origin = String(req.headers.origin || '');
      if (this.corsOrigin && origin && origin !== this.corsOrigin) {
        this.rejectedRequestCount += 1;
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'origin is not allowed', code: 'CORS_ORIGIN_DENIED', requestId }));
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
          const parsed = parseRequestJson(body || '{}');
          validateRequestSchema(pathname, parsed, this.enableExperimentalPriva);
          const initData = parsed.initData;
          if (typeof initData !== 'string') {
            throw new Error('body must include a string "initData" field');
          }
          const result = isExperimentalPriva
            ? await this.handlePrivaPurchaseAuthorization(initData, parsed as unknown as PrivaPurchaseAuthorizationRequest)
            : await this.handleAuthenticate(initData);
          this.completedRequestCount += 1;
          ended = true;
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify(result));
        } catch (err) {
          const message = err instanceof Error ? err.message : String(err);
          const status = message.startsWith('prover busy') ? 429 : message.includes('timed out') ? 504 : message.startsWith('Invalid Telegram') ? 401 : 422;
          this.failedRequestCount += 1;
          ended = true;
          res.writeHead(status, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            error: this.exposeHttpErrors ? message : 'request rejected',
            code: status === 429 ? 'PROVER_BUSY' : status === 504 ? 'PROOF_TIMEOUT' : status === 401 ? 'TELEGRAM_AUTH_REJECTED' : 'REQUEST_REJECTED',
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

function parseRequestJson(text: string): Record<string, unknown> {
  const value = JSON.parse(text);
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('request body must be a JSON object');
  // JSON.parse accepts duplicate keys with last-write-wins semantics.  Reject
  // duplicate semantic keys before parsing so an intermediary cannot sign one
  // value while the gateway consumes another.
  const keys: string[] = [];
  let inString = false;
  let escaped = false;
  let expectingKey = false;
  let key = '';
  for (let i = 0; i < text.length; i += 1) {
    const char = text[i];
    if (inString) {
      if (escaped) escaped = false;
      else if (char === '\\') escaped = true;
      else if (char === '"') { inString = false; if (expectingKey) { key = JSON.parse(`"${key}"`); if (keys.includes(key)) throw new Error('duplicate JSON field'); keys.push(key); expectingKey = false; } }
      else if (expectingKey) key += char;
      continue;
    }
    if (char === '"') { inString = true; key = ''; const prefix = text.slice(0, i).trimEnd(); expectingKey = prefix.endsWith('{') || prefix.endsWith(','); }
  }
  return value as Record<string, unknown>;
}

function validateRequestSchema(pathname: string, parsed: Record<string, unknown>, enableExperimentalPriva: boolean): void {
  const isPriva = pathname === '/v1/purchase-authorizations';
  if (isPriva && !enableExperimentalPriva) throw new Error('experimental Priva route is disabled');
  const allowed = !isPriva
    ? new Set(['schemaVersion', 'initData'])
    : new Set(['schemaVersion', 'initData', 'launchIdHash', 'launchpadAddressHi', 'launchpadAddressLo', 'recipientAddressHi', 'recipientAddressLo', 'clientNonce', 'expiryEpoch', 'operation', 'circuitVersion']);
  for (const key of Object.keys(parsed)) if (!allowed.has(key)) throw new Error(`unknown request field: ${key}`);
  if (parsed.schemaVersion !== undefined && parsed.schemaVersion !== 1) throw new Error('unsupported request schema version');
  if (typeof parsed.initData !== 'string' || parsed.initData.length === 0 || parsed.initData.length > 32 * 1024) throw new Error('initData must be a bounded non-empty string');
  if (isPriva) {
    for (const key of ['launchIdHash', 'launchpadAddressHi', 'launchpadAddressLo', 'recipientAddressHi', 'recipientAddressLo', 'clientNonce']) {
      if (typeof parsed[key] !== 'string' || !/^(0|[1-9][0-9]*)$/.test(parsed[key] as string)) throw new Error(`${key} must be a canonical decimal field`);
    }
    if (parsed.operation !== 'BUY') throw new Error('operation must be BUY');
    if (!Number.isSafeInteger(parsed.expiryEpoch) || (parsed.expiryEpoch as number) < 0) throw new Error('expiryEpoch must be a safe integer');
    if (parsed.circuitVersion !== undefined && parsed.circuitVersion !== 1) throw new Error('unsupported circuit version');
  }
}
