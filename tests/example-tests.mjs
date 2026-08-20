import assert from 'node:assert/strict';
import { CryptoUtils, NullifierDeriver, ZkAuthProofVerifier } from '../dist/sdk/index.js';
import { spawn } from 'node:child_process';

const child = spawn(process.execPath, ['examples/telegram-mini-app/server.mjs'], {
  cwd: process.cwd(),
  env: {
    ...process.env,
    NODE_ENV: 'development',
    TELEGRAM_BOT_TOKEN: '123456789:example-token',
    ZK_TELE_AUTH_ISSUER_SECRET: '123456789',
    ZK_TELE_AUTH_APP_DOMAIN: 'telegram-mini-app.local',
    ZK_TELE_AUTH_CORS_ORIGIN: 'http://127.0.0.1:3000',
    ZK_TELE_AUTH_ALLOW_DEVELOPMENT_ARTIFACTS: '1',
    ZK_TELE_AUTH_HOST: '127.0.0.1',
    PORT: '18080',
  },
  stdio: ['ignore', 'pipe', 'pipe'],
});
let output = '';
child.stdout.on('data', (chunk) => { output += chunk.toString(); });
child.stderr.on('data', (chunk) => { output += chunk.toString(); });
try {
  const deadline = Date.now() + 10_000;
  while (!output.includes('Mini App example') && Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 50));
  assert.match(output, /Mini App example/);
  const live = await fetch('http://127.0.0.1:18080/livez');
  assert.equal(live.status, 200);
  const authDate = Math.floor(Date.now() / 1000);
  const params = new URLSearchParams({
    query_id: 'AAHdF6IQAAAAAN0XohDhrOrc',
    user: JSON.stringify({ id: 987654321, is_premium: false }),
    auth_date: String(authDate),
  });
  const dataCheck = [...params.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([key, value]) => `${key}=${value}`).join('\n');
  const secretKey = CryptoUtils.hmacSha256('WebAppData', '123456789:example-token');
  params.set('hash', CryptoUtils.hmacSha256Hex(secretKey, dataCheck));
  const authentication = await fetch('http://127.0.0.1:18080/v1/authentications', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ schemaVersion: 1, initData: params.toString() }),
  });
  assert.equal(authentication.status, 200);
  const authenticationBody = await authentication.json();
  const issuerKeyHash = await NullifierDeriver.deriveIssuerKeyHash('123456789');
  const verification = await ZkAuthProofVerifier.verifyProof(authenticationBody.proofPayload, {
    expectedAppDomain: 'telegram-mini-app.local',
    expectedIssuerKeyHash: issuerKeyHash,
    maxTokenAgeSec: 3600,
    requirePremium: false,
  });
  assert.equal(verification.isValid, true);
  const tampered = structuredClone(authenticationBody.proofPayload);
  tampered.publicSignals[0] = '1';
  const rejected = await ZkAuthProofVerifier.verifyProof(tampered, {
    expectedAppDomain: 'telegram-mini-app.local',
    expectedIssuerKeyHash: issuerKeyHash,
    maxTokenAgeSec: 3600,
    requirePremium: false,
  });
  assert.equal(rejected.isValid, false);
  const page = await fetch('http://127.0.0.1:3000/');
  assert.equal(page.status, 200);
  assert.match(await page.text(), /Telegram authentication example/);
  const client = await fetch('http://127.0.0.1:3000/client.js');
  assert.equal(client.status, 200);
  assert.match(await client.text(), /ZkTeleAuthClient/);
  console.log('Telegram Mini App example tests: passed');
} finally {
  child.kill('SIGTERM');
  if (child.exitCode === null && child.signalCode === null) {
    await Promise.race([
      new Promise((resolve) => child.once('exit', resolve)),
      new Promise((resolve) => setTimeout(resolve, 2_000)),
    ]);
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
  }
}

process.exit(0);
