/** Minimal fetch surface so the client works in browsers, workers, and tests. */
export type FetchLike = (input: string | URL, init?: RequestInit) => Promise<Response>;

export interface ZkTeleAuthClientOptions {
  /** Gateway origin, for example `https://auth.example`. */
  baseUrl: string;
  /** Injectable fetch implementation for tests or a non-browser runtime. */
  fetch?: FetchLike;
  /** Abort the request after this many milliseconds. Defaults to 30 seconds. */
  timeoutMs?: number;
  /** Additional non-sensitive request headers. */
  headers?: Record<string, string>;
}

export interface AuthenticateRequest {
  initData: string;
}

export interface GatewayProofPayload {
  proof: {
    pi_a: string[];
    pi_b: string[][];
    pi_c: string[];
    protocol: string;
    curve: string;
  };
  publicSignals: string[];
  [key: string]: unknown;
}

export interface AuthenticateResponse {
  success: true;
  nullifierHash: string;
  proofPayload: GatewayProofPayload;
}

export interface GatewayErrorBody {
  error?: string;
  code?: string;
  requestId?: string;
}

export interface GatewayHealthResponse {
  status: 'ok' | 'ready' | 'not_ready';
  activeProofs?: number;
  queuedProofs?: number;
  maxConcurrentProofs?: number;
}
