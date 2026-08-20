import assert from 'node:assert/strict';
import { GatewayClientError, ZkTeleAuthClient } from '../dist/client/index.js';

function response(status, body, headers = {}) {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: new Headers(headers),
    async json() { return body; },
  };
}

let requests = [];
const fetchMock = async (url, init) => {
  requests.push({ url, init });
  return response(200, {
    success: true,
    nullifierHash: '123',
    proofPayload: { publicSignals: ['1'], proof: {} },
  });
};

const client = new ZkTeleAuthClient({ baseUrl: 'https://auth.example///', fetch: fetchMock, timeoutMs: 1000 });
const result = await client.authenticate({ initData: 'signed-init-data' });
assert.equal(result.success, true);
assert.equal(requests[0].url, 'https://auth.example/v1/authentications');
assert.equal(requests[0].init.method, 'POST');
assert.equal(JSON.parse(requests[0].init.body).schemaVersion, 1);
assert.equal(requests[0].init.headers['Content-Type'], 'application/json');

const errorClient = new ZkTeleAuthClient({
  baseUrl: 'https://auth.example',
  fetch: async () => response(429, { error: 'busy', code: 'PROVER_BUSY', requestId: 'req-1' }, { 'retry-after': '2' }),
});
await assert.rejects(
  errorClient.authenticate({ initData: 'signed-init-data' }),
  (error) => error instanceof GatewayClientError && error.status === 429 && error.code === 'PROVER_BUSY' && error.retryAfterSec === 2,
);

assert.throws(() => new ZkTeleAuthClient({ baseUrl: 'javascript:alert(1)', fetch: fetchMock }), /http or https/);
await assert.rejects(client.authenticate({ initData: '' }), /non-empty/);
console.log('browser client tests: passed');
