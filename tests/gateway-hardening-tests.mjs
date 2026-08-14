import assert from 'node:assert/strict';
import http from 'node:http';
import { ZkTeleAuthGateway } from '../dist/gateway/server.js';
import { loadGatewayConfig } from '../dist/gateway/config.js';
import { assertArtifactReadiness } from '../dist/gateway/artifact-readiness.js';
import { structuredLog } from '../dist/gateway/secrets.js';

function configEnv(overrides = {}) {
  return {
    NODE_ENV: 'staging',
    TELEGRAM_BOT_TOKEN: '123456789:token',
    ZK_TELE_AUTH_ISSUER_SECRET: '123456789',
    ZK_TELE_AUTH_APP_DOMAIN: 'dapp.example',
    ZK_TELE_AUTH_CORS_ORIGIN: 'https://dapp.example',
    ...overrides,
  };
}

async function listen(server) {
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  assert.equal(typeof address, 'object');
  return `http://127.0.0.1:${address.port}`;
}

const parsed = loadGatewayConfig(configEnv());
assert.equal(parsed.environment, 'staging');
assert.equal(parsed.allowDevelopmentArtifacts, true);
assert.throws(() => loadGatewayConfig(configEnv({ NODE_ENV: 'production', ZK_TELE_AUTH_ALLOW_DEVELOPMENT_ARTIFACTS: '1' })), /development artifacts/);
assert.throws(() => loadGatewayConfig(configEnv({ ZK_TELE_AUTH_CORS_ORIGIN: '*' })), /explicit HTTPS origin/);
assert.equal(assertArtifactReadiness({ allowDevelopmentArtifacts: true }).status, 'development-only');
assert.throws(() => assertArtifactReadiness({ allowDevelopmentArtifacts: false }), /development proving artifacts/);
const mismatchedGateway = new ZkTeleAuthGateway({
  botToken: '123456789:token',
  issuerSecret: '123456789',
  appDomain: 'dapp.example',
  expectedIssuerKeyHash: '1',
});
await assert.rejects(() => mismatchedGateway.verifyStartupPolicy(), /issuer commitment/);
const redacted = structuredLog('test', { issuerKeyHash: '123456789', proof: 'proof-material', nested: { nonce: '1234', count: 2 } });
assert.doesNotMatch(redacted, /123456789|proof-material/);
assert.match(redacted, /REDACTED/);

const gateway = new ZkTeleAuthGateway({
  botToken: '123456789:token',
  issuerSecret: '123456789',
  appDomain: 'dapp.example',
  corsOrigin: 'https://dapp.example',
});
await gateway.verifyStartupPolicy();
gateway.markReady();
const server = gateway.createServer();
const base = await listen(server);
try {
  const live = await fetch(`${base}/livez`);
  assert.equal(live.status, 200);
  assert.equal((await live.json()).status, 'ok');

  const ready = await fetch(`${base}/readyz`);
  assert.equal(ready.status, 200);
  assert.equal((await ready.json()).status, 'ready');

  const metrics = await fetch(`${base}/metrics`);
  assert.equal(metrics.status, 200);
  assert.match(await metrics.text(), /zk_tele_auth_requests_total/);

  const wrongType = await fetch(`${base}/authenticate`, {
    method: 'POST',
    body: JSON.stringify({ initData: 'not-valid' }),
  });
  assert.equal(wrongType.status, 415);
  assert.equal((await wrongType.json()).code, 'UNSUPPORTED_MEDIA_TYPE');

  const notFound = await fetch(`${base}/does-not-exist`);
  assert.equal(notFound.status, 404);
  assert.equal((await notFound.json()).code, 'NOT_FOUND');

  const unknownField = await fetch(`${base}/authenticate`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', origin: 'https://dapp.example' },
    body: JSON.stringify({ initData: 'not-valid', extra: true }),
  });
  assert.equal(unknownField.status, 422);
  assert.equal((await unknownField.json()).code, 'REQUEST_REJECTED');

  const duplicateField = await fetch(`${base}/authenticate`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', origin: 'https://dapp.example' },
    body: '{"initData":"not-valid","initData":"also-not-valid"}',
  });
  assert.equal(duplicateField.status, 422);
  assert.equal((await duplicateField.json()).code, 'REQUEST_REJECTED');

  const deniedCors = await fetch(`${base}/authenticate`, {
    method: 'OPTIONS',
    headers: { origin: 'https://attacker.example', 'access-control-request-method': 'POST' },
  });
  assert.equal(deniedCors.status, 403);

  gateway.markNotReady();
  const notReady = await fetch(`${base}/readyz`);
  assert.equal(notReady.status, 503);
  gateway.markReady();
} finally {
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}

console.log('gateway hardening tests: passed');
