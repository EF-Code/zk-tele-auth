#!/usr/bin/env node
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

const root = process.cwd();
let tarball;
try {
  const raw = execFileSync('npm', ['pack', '--json', '--ignore-scripts'], { cwd: root, encoding: 'utf8' });
  const metadata = JSON.parse(raw);
  const packageInfo = Array.isArray(metadata) ? metadata[0] : (metadata?.filename ? metadata : metadata?.['zk-tele-auth']);
  assert.ok(packageInfo?.filename, 'npm pack did not report a filename');
  tarball = path.resolve(root, packageInfo.filename);
  assert.ok(packageInfo.size <= 10 * 1024 * 1024, `compressed package exceeds 10 MiB (${packageInfo.size})`);
  assert.ok(packageInfo.unpackedSize <= 20 * 1024 * 1024, `unpacked package exceeds 20 MiB (${packageInfo.unpackedSize})`);
  const files = new Set((packageInfo.files || []).map((entry) => entry.path));
  for (const required of [
    'package.json', 'README.md', 'LICENSE', 'THIRD_PARTY_NOTICES.md',
    'dist/sdk/index.js', 'dist/sdk/index.d.ts', 'dist/client/index.js',
    'dist/gateway/server.js', 'artifacts/manifest.json',
  ]) assert.ok(files.has(required), `required package file missing: ${required}`);
  for (const forbidden of ['FULL_DEPLOYMENT_LUNA_MAX_HANDOFF.md', '.env', 'node_modules/', 'tests/']) {
    assert.equal([...files].some((file) => file === forbidden || file.startsWith(forbidden)), false, `review/local material packed: ${forbidden}`);
  }
  const content = [...files].join('\n');
  assert.doesNotMatch(content, /github_pat_|gh[pousr]_[A-Za-z0-9]{20,}|BEGIN (?:RSA|EC|OPENSSH|PRIVATE) KEY/);
  console.log(JSON.stringify({ package: packageInfo.id, compressedBytes: packageInfo.size, unpackedBytes: packageInfo.unpackedSize, fileCount: files.size }));
} finally {
  if (tarball) fs.rmSync(tarball, { force: true });
}
