import assert from 'node:assert/strict';
import { CryptoUtils } from '../dist/sdk/index.js';
import { ZkTeleAuthGateway } from '../dist/gateway/server.js';

function signedInitData(botToken, authDate) {
  const params = new URLSearchParams({
    query_id: 'AAHdF6IQAAAAAN0XohDhrOrc',
    user: JSON.stringify({ id: 987654321, is_premium: false }),
    auth_date: String(authDate),
  });
  const dataCheck = [...params.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([key, value]) => `${key}=${value}`).join('\n');
  const secretKey = CryptoUtils.hmacSha256('WebAppData', botToken);
  params.set('hash', CryptoUtils.hmacSha256Hex(secretKey, dataCheck));
  return params.toString();
}

class BlockingPool {
  closed = false;
  rejects = [];

  run() {
    if (this.closed) return Promise.reject(new Error('pool closed'));
    return new Promise((_, reject) => this.rejects.push(reject));
  }

  async close() {
    this.closed = true;
    for (const reject of this.rejects.splice(0)) reject(new Error('pool closed'));
  }
}

const pool = new BlockingPool();
const gateway = new ZkTeleAuthGateway({
  botToken: '123456789:token',
  issuerSecret: '123456789',
  appDomain: 'dapp.example',
  maxConcurrentProofs: 1,
  maxQueueDepth: 1,
  proverPool: pool,
});
const server = gateway.createServer();
await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
const address = server.address();
const base = `http://127.0.0.1:${address.port}`;
const body = JSON.stringify({ initData: signedInitData('123456789:token', Math.floor(Date.now() / 1000)) });
const first = fetch(`${base}/v1/authentications`, { method: 'POST', headers: { 'content-type': 'application/json' }, body });
const second = fetch(`${base}/v1/authentications`, { method: 'POST', headers: { 'content-type': 'application/json' }, body });
await new Promise((resolve) => setTimeout(resolve, 100));
const live = await fetch(`${base}/livez`);
assert.equal(live.status, 200);
assert.equal((await live.json()).status, 'ok');
gateway.stopAccepting();
await gateway.close();
await Promise.allSettled([first, second]);
await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
console.log('gateway worker isolation and saturation tests: passed');
