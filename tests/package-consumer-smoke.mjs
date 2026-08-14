import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

const root = process.cwd();
const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'zk-tele-auth-consumer-'));
let tarball;
try {
  const packedJson = JSON.parse(execFileSync('npm', ['pack', '--json', '--ignore-scripts'], { cwd: root, encoding: 'utf8' }));
  const packed = packedJson['zk-tele-auth'] || packedJson[0];
  if (!packed?.filename) throw new Error('npm pack did not return a package filename');
  tarball = path.join(root, packed.filename);
  execFileSync('npm', ['init', '-y'], { cwd: temp, stdio: 'ignore' });
  execFileSync('npm', ['install', '--ignore-scripts', '--no-audit', '--no-fund', tarball], { cwd: temp, stdio: 'pipe' });
  const sdk = await import(path.join(temp, 'node_modules', 'zk-tele-auth', 'dist', 'sdk', 'index.js'));
  const gateway = await import(path.join(temp, 'node_modules', 'zk-tele-auth', 'dist', 'gateway', 'server.js'));
  assert.equal(typeof sdk.ZkAuthProofVerifier.verifyProof, 'function');
  assert.equal(typeof gateway.ZkTeleAuthGateway, 'function');
  console.log('package consumer smoke test: passed');
} finally {
  if (tarball) fs.rmSync(tarball, { force: true });
  fs.rmSync(temp, { recursive: true, force: true });
}
