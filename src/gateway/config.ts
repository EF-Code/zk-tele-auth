import { ZkTeleAuthGatewayOptions } from './server.js';

export interface GatewayRuntimeConfig extends ZkTeleAuthGatewayOptions {
  host: string;
  port: number;
  requestTimeoutMs: number;
  headersTimeoutMs: number;
  keepAliveTimeoutMs: number;
  proofTimeoutMs: number;
  maxQueueDepth: number;
  environment: 'development' | 'test' | 'staging' | 'production';
  allowDevelopmentArtifacts: boolean;
  expectedIssuerKeyHash?: string;
  maxAuthorizationTtlSec: number;
  enableExperimentalPriva: boolean;
}

function required(env: NodeJS.ProcessEnv, name: string): string {
  const value = env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function integer(env: NodeJS.ProcessEnv, name: string, fallback: number, min: number, max: number): number {
  const raw = env[name] ?? String(fallback);
  if (!/^[0-9]+$/.test(raw)) throw new Error(`${name} must be a non-negative integer`);
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < min || value > max) throw new Error(`${name} must be in ${min}..${max}`);
  return value;
}

function boolean(env: NodeJS.ProcessEnv, name: string, fallback: boolean): boolean {
  const raw = env[name];
  if (raw === undefined) return fallback;
  if (raw === '1' || raw === 'true') return true;
  if (raw === '0' || raw === 'false') return false;
  throw new Error(`${name} must be true/false or 1/0`);
}

function environment(env: NodeJS.ProcessEnv): GatewayRuntimeConfig['environment'] {
  const value = env.NODE_ENV || 'development';
  if (value !== 'development' && value !== 'test' && value !== 'staging' && value !== 'production') {
    throw new Error('NODE_ENV must be development, test, staging, or production');
  }
  return value;
}

function optionalField(value: string | undefined, name: string): string | undefined {
  if (value === undefined) return undefined;
  if (!/^[0-9]+$/.test(value)) throw new Error(`${name} must be a decimal field element`);
  return value;
}

function validCorsOrigin(value: string, currentEnvironment: GatewayRuntimeConfig['environment']): boolean {
  if (value === '*') return false;
  if (/^https:\/\/[^\s/]+(?:\/[^\s]*)?$/.test(value)) return true;
  return currentEnvironment !== 'production' && /^http:\/\/(?:localhost|127\.0\.0\.1)(?::[0-9]{1,5})?$/.test(value);
}

/** Parse production gateway configuration without logging any secret values. */
export function loadGatewayConfig(env: NodeJS.ProcessEnv = process.env): GatewayRuntimeConfig {
  const currentEnvironment = environment(env);
  const allowDevelopmentArtifacts = boolean(env, 'ZK_TELE_AUTH_ALLOW_DEVELOPMENT_ARTIFACTS', currentEnvironment !== 'production');
  if (currentEnvironment === 'production' && allowDevelopmentArtifacts) {
    throw new Error('development artifacts cannot be enabled in production');
  }
  const maxTokenAgeSec = integer(env, 'ZK_TELE_AUTH_MAX_TOKEN_AGE_SEC', 3600, 1, 0xffff_ffff);
  const maxAuthorizationTtlSec = integer(env, 'ZK_TELE_AUTH_MAX_AUTHORIZATION_TTL_SEC', maxTokenAgeSec, 1, maxTokenAgeSec);
  const expectedIssuerKeyHash = optionalField(env.ZK_TELE_AUTH_ISSUER_KEY_HASH, 'ZK_TELE_AUTH_ISSUER_KEY_HASH');
  if (currentEnvironment === 'production' && !expectedIssuerKeyHash) {
    throw new Error('ZK_TELE_AUTH_ISSUER_KEY_HASH is required in production');
  }
  const corsOrigin = required(env, 'ZK_TELE_AUTH_CORS_ORIGIN');
  if (!validCorsOrigin(corsOrigin, currentEnvironment)) {
    throw new Error('ZK_TELE_AUTH_CORS_ORIGIN must be one explicit HTTPS origin (or local HTTP in non-production)');
  }
  const enableExperimentalPriva = boolean(env, 'ZK_TELE_AUTH_ENABLE_EXPERIMENTAL_PRIVA', false);
  if (currentEnvironment === 'production' && enableExperimentalPriva) {
    throw new Error('experimental Priva route cannot be enabled in production');
  }
  return {
    botToken: required(env, 'TELEGRAM_BOT_TOKEN'),
    issuerSecret: required(env, 'ZK_TELE_AUTH_ISSUER_SECRET'),
    appDomain: required(env, 'ZK_TELE_AUTH_APP_DOMAIN'),
    maxTokenAgeSec,
    requirePremium: boolean(env, 'ZK_TELE_AUTH_REQUIRE_PREMIUM', false),
    corsOrigin,
    maxBodyBytes: integer(env, 'ZK_TELE_AUTH_MAX_BODY_BYTES', 64 * 1024, 1024, 1024 * 1024),
    maxConcurrentProofs: integer(env, 'ZK_TELE_AUTH_MAX_CONCURRENT_PROOFS', 2, 1, 64),
    host: env.ZK_TELE_AUTH_HOST || '127.0.0.1',
    port: integer(env, 'PORT', 8080, 1, 65535),
    requestTimeoutMs: integer(env, 'ZK_TELE_AUTH_REQUEST_TIMEOUT_MS', 30_000, 1000, 300_000),
    headersTimeoutMs: integer(env, 'ZK_TELE_AUTH_HEADERS_TIMEOUT_MS', 10_000, 1000, 120_000),
    keepAliveTimeoutMs: integer(env, 'ZK_TELE_AUTH_KEEP_ALIVE_TIMEOUT_MS', 5000, 1000, 120_000),
    proofTimeoutMs: integer(env, 'ZK_TELE_AUTH_PROOF_TIMEOUT_MS', 20_000, 1000, 300_000),
    maxQueueDepth: integer(env, 'ZK_TELE_AUTH_MAX_QUEUE_DEPTH', 8, 0, 1024),
    environment: currentEnvironment,
    allowDevelopmentArtifacts,
    expectedIssuerKeyHash,
    maxAuthorizationTtlSec,
    enableExperimentalPriva,
  };
}
