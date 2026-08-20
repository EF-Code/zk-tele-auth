import assert from 'node:assert/strict';
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
  const page = await fetch('http://127.0.0.1:3000/');
  assert.equal(page.status, 200);
  assert.match(await page.text(), /Telegram authentication example/);
  const client = await fetch('http://127.0.0.1:3000/client.js');
  assert.equal(client.status, 200);
  assert.match(await client.text(), /ZkTeleAuthClient/);
  console.log('Telegram Mini App example tests: passed');
} finally {
  child.kill('SIGTERM');
  await new Promise((resolve) => child.once('exit', resolve));
}
