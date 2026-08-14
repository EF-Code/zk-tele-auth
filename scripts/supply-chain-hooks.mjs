#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const outputDir = path.join(root, 'build', 'supply-chain');
fs.mkdirSync(outputDir, { recursive: true });
const packageLock = path.join(root, 'package-lock.json');
const sbom = {
  bomFormat: 'CycloneDX',
  specVersion: '1.5',
  serialNumber: `urn:uuid:${crypto.randomUUID()}`,
  metadata: { timestamp: new Date().toISOString(), component: { type: 'application', name: 'zk-tele-auth', version: JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8')).version } },
  components: Object.entries(JSON.parse(fs.readFileSync(packageLock, 'utf8')).packages || {}).filter(([key]) => key.startsWith('node_modules/')).map(([key, value]) => ({ type: 'library', name: key.slice('node_modules/'.length), version: value.version })),
};
const sbomPath = path.join(outputDir, 'sbom.cdx.json');
fs.writeFileSync(sbomPath, `${JSON.stringify(sbom, null, 2)}\n`);
console.log(`SBOM: ${path.relative(root, sbomPath)}`);
for (const [tool, args] of [['syft', ['.', '-o', 'cyclonedx-json']], ['trivy', ['fs', '--exit-code', '1', '--severity', 'HIGH,CRITICAL', '.']]]) {
  const probe = spawnSync(tool, ['--version'], { cwd: root, encoding: 'utf8' });
  if (probe.status !== 0) {
    console.log(`${tool}: unavailable (CI/install hook required before release)`);
    continue;
  }
  const run = spawnSync(tool, args, { cwd: root, encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 });
  fs.writeFileSync(path.join(outputDir, `${tool}.log`), `${run.stdout || ''}${run.stderr || ''}`);
  if (run.status !== 0) process.exitCode = 1;
}
if (process.env.RELEASE_IMAGE && process.env.COSIGN_SIGN === '1') {
  const cosign = spawnSync('cosign', ['sign', '--yes', process.env.RELEASE_IMAGE], { cwd: root, encoding: 'utf8' });
  fs.writeFileSync(path.join(outputDir, 'cosign.log'), `${cosign.stdout || ''}${cosign.stderr || ''}`);
  if (cosign.status !== 0) process.exitCode = 1;
} else {
  console.log('cosign: signing hook not invoked (set RELEASE_IMAGE and COSIGN_SIGN=1 in a protected release environment)');
}
