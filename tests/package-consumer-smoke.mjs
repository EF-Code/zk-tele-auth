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
  const consumer = path.join(temp, 'consumer.mjs');
  fs.writeFileSync(consumer, [
    "import * as sdk from 'zk-tele-auth';",
    "import * as gateway from 'zk-tele-auth/gateway';",
    "console.log('consumer imports: loaded');",
    "if (typeof sdk.ZkAuthProofVerifier?.verifyProof !== 'function') throw new Error('SDK export missing');",
    "if (typeof sdk.buildPrivaLaunchpadStateInitData !== 'function') throw new Error('TON export missing');",
    "if (typeof gateway.ZkTeleAuthGateway !== 'function') throw new Error('gateway export missing');",
    "const now = Math.floor(Date.now() / 1000);",
    "const issuerSecret = '123456789';",
    "console.time('consumer proof');",
    "const proof = await sdk.ZkAuthProofGenerator.generateProof({ userId: '123456789', authDate: now, isPremium: false, appDomain: 'consumer.example', currentTimestamp: now, maxTokenAgeSec: 3600, issuerSecret });",
    "console.timeEnd('consumer proof');",
    "const issuerKeyHash = await sdk.NullifierDeriver.deriveIssuerKeyHash(issuerSecret);",
    "const result = await sdk.ZkAuthProofVerifier.verifyProof(proof, { expectedAppDomain: 'consumer.example', expectedIssuerKeyHash: issuerKeyHash, maxTokenAgeSec: 3600, requirePremium: false });",
    "if (!result.isValid) throw new Error(result.error || 'installed-package proof verification failed');",
    "process.exit(0);",
  ].join('\n'));
  execFileSync(process.execPath, [consumer], { cwd: temp, stdio: 'pipe' });
  const packageRoot = path.join(temp, 'node_modules', 'zk-tele-auth');
  assert.equal(fs.existsSync(path.join(packageRoot, 'circuits')), false);
  assert.equal(fs.existsSync(path.join(packageRoot, 'artifacts', 'priva_purchase_auth', 'priva_purchase_auth.r1cs')), false);
  console.log('package consumer smoke test: passed');
} finally {
  if (tarball) fs.rmSync(tarball, { force: true });
  fs.rmSync(temp, { recursive: true, force: true });
}
