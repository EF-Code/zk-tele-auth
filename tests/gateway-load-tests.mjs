import assert from 'node:assert/strict';
import { ZkTeleAuthGateway } from '../dist/gateway/server.js';

const gateway = new ZkTeleAuthGateway({
  botToken: '123456789:load-test',
  issuerSecret: '123456789',
  appDomain: 'load-test.example',
  maxConcurrentProofs: 1,
  maxQueueDepth: 2,
});
const server = gateway.createServer();
await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
const address = server.address();
const base = `http://127.0.0.1:${address.port}`;
gateway.markReady();
try {
  const started = performance.now();
  const responses = await Promise.all(Array.from({ length: 100 }, () => fetch(`${base}/livez`)));
  const elapsedMs = performance.now() - started;
  assert.ok(responses.every((response) => response.status === 200));
  const metrics = await (await fetch(`${base}/metrics`)).text();
  assert.match(metrics, /zk_tele_auth_requests_total/);
  assert.match(metrics, /zk_tele_auth_proof_timeouts_total/);
  assert.doesNotMatch(metrics, /request_id|initData|user_id|label=/i);
  console.log(JSON.stringify({ test: 'gateway-liveness-under-concurrency', requests: responses.length, elapsedMs: Math.round(elapsedMs) }));
} finally {
  gateway.markNotReady();
  gateway.stopAccepting();
  await gateway.close();
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}
