import {
  AuthenticateRequest,
  AuthenticateResponse,
  FetchLike,
  GatewayErrorBody,
  GatewayHealthResponse,
  ZkTeleAuthClientOptions,
} from './types.js';

const DEFAULT_TIMEOUT_MS = 30_000;

function normalizeBaseUrl(value: string): string {
  if (typeof value !== 'string' || value.trim() === '') throw new Error('baseUrl is required');
  let parsed: URL;
  try { parsed = new URL(value); } catch { throw new Error('baseUrl must be an absolute URL'); }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') throw new Error('baseUrl must use http or https');
  parsed.hash = '';
  parsed.search = '';
  return parsed.toString().replace(/\/+$/, '');
}

function assertProofPayload(value: unknown): asserts value is AuthenticateResponse {
  if (!value || typeof value !== 'object' || (value as { success?: unknown }).success !== true) {
    throw new Error('gateway returned an invalid authentication response');
  }
  const response = value as Partial<AuthenticateResponse>;
  if (typeof response.nullifierHash !== 'string' || !Array.isArray(response.proofPayload?.publicSignals)) {
    throw new Error('gateway returned an invalid proof payload');
  }
}

function parseRetryAfter(value: string | null): number | undefined {
  if (!value || !/^[0-9]+$/.test(value)) return undefined;
  const seconds = Number(value);
  return Number.isSafeInteger(seconds) ? seconds : undefined;
}

export class GatewayClientError extends Error {
  readonly status: number;
  readonly code: string;
  readonly requestId?: string;
  readonly retryAfterSec?: number;

  constructor(status: number, body: GatewayErrorBody, retryAfterSec?: number) {
    super(body.error || `gateway request failed with HTTP ${status}`);
    this.name = 'GatewayClientError';
    this.status = status;
    this.code = body.code || 'REQUEST_FAILED';
    this.requestId = body.requestId;
    this.retryAfterSec = retryAfterSec;
  }
}

/** Browser-safe typed client for the stable authentication gateway API. */
export class ZkTeleAuthClient {
  private readonly baseUrl: string;
  private readonly fetchImpl: FetchLike;
  private readonly timeoutMs: number;
  private readonly headers: Record<string, string>;

  constructor(options: ZkTeleAuthClientOptions) {
    this.baseUrl = normalizeBaseUrl(options.baseUrl);
    this.fetchImpl = options.fetch || globalThis.fetch?.bind(globalThis);
    if (!this.fetchImpl) throw new Error('a fetch implementation is required');
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    if (!Number.isSafeInteger(this.timeoutMs) || this.timeoutMs < 100 || this.timeoutMs > 300_000) {
      throw new Error('timeoutMs must be an integer in 100..300000');
    }
    this.headers = { ...options.headers };
  }

  async authenticate(request: AuthenticateRequest, signal?: AbortSignal): Promise<AuthenticateResponse> {
    if (!request || typeof request.initData !== 'string' || request.initData.length === 0) {
      throw new Error('initData must be a non-empty string');
    }
    if (request.initData.length > 32 * 1024) throw new Error('initData exceeds the gateway limit');
    const response = await this.request('/v1/authentications', {
      method: 'POST',
      body: JSON.stringify({ schemaVersion: 1, initData: request.initData }),
      signal,
    });
    assertProofPayload(response);
    return response;
  }

  async liveness(signal?: AbortSignal): Promise<GatewayHealthResponse> {
    return this.request('/livez', { method: 'GET', signal }) as Promise<GatewayHealthResponse>;
  }

  async readiness(signal?: AbortSignal): Promise<GatewayHealthResponse> {
    return this.request('/readyz', { method: 'GET', signal }) as Promise<GatewayHealthResponse>;
  }

  private async request(path: string, init: RequestInit): Promise<unknown> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    const externalSignal = init.signal;
    let abortExternal: (() => void) | undefined;
    if (externalSignal) {
      if (externalSignal.aborted) controller.abort();
      else {
        abortExternal = () => controller.abort();
        externalSignal.addEventListener('abort', abortExternal, { once: true });
      }
    }
    try {
      const response = await this.fetchImpl(`${this.baseUrl}${path}`, {
        ...init,
        signal: controller.signal,
        headers: {
          Accept: 'application/json',
          ...this.headers,
          ...(init.body ? { 'Content-Type': 'application/json' } : {}),
        },
      });
      const body = await response.json().catch(() => ({})) as unknown;
      if (!response.ok) {
        const errorBody = body && typeof body === 'object' ? body as GatewayErrorBody : {};
        throw new GatewayClientError(response.status, errorBody, parseRetryAfter(response.headers.get('retry-after')));
      }
      return body;
    } catch (error) {
      if (error instanceof GatewayClientError) throw error;
      if (controller.signal.aborted) throw new Error('gateway request timed out or was aborted');
      throw error;
    } finally {
      clearTimeout(timer);
      if (abortExternal && externalSignal) externalSignal.removeEventListener('abort', abortExternal);
    }
  }
}
