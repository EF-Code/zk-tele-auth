#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { sha256File } from './lib/attestation.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const reportPath = path.resolve(root, process.env.RELEASE_PREFLIGHT_OUT || 'build/release-preflight.json');
const startedAt = new Date().toISOString();
const gates = [];

function add(id, status, message, evidence = []) {
  gates.push({ id, status, message, evidence });
}

function readJson(relativePath) {
  const absolutePath = path.join(root, relativePath);
  if (!fs.existsSync(absolutePath)) throw new Error(`missing ${relativePath}`);
  return JSON.parse(fs.readFileSync(absolutePath, 'utf8'));
}

function command(id, args, required = true, blockedExitCode = null) {
  const result = spawnSync(args[0], args.slice(1), {
    cwd: root,
    encoding: 'utf8',
    env: { ...process.env, CI: '1' },
    maxBuffer: 8 * 1024 * 1024,
  });
  const output = `${result.stdout || ''}${result.stderr || ''}`.trim();
  const evidencePath = path.join('build', 'release-preflight', `${id}.log`);
  fs.mkdirSync(path.join(root, 'build', 'release-preflight'), { recursive: true });
  fs.writeFileSync(path.join(root, evidencePath), output ? `${output}\n` : '(no output)\n');
  if (result.status === 0) add(id, 'pass', `${args.join(' ')} passed`, [evidencePath]);
  else if (blockedExitCode !== null && result.status === blockedExitCode) add(id, 'blocked', `${args.join(' ')} is blocked pending external evidence`, [evidencePath]);
  else add(id, required ? 'fail' : 'blocked', `${args.join(' ')} exited ${result.status ?? 'unknown'}`, [evidencePath]);
  return result.status === 0;
}

function gitOutput(args) {
  const result = spawnSync('git', args, { cwd: root, encoding: 'utf8' });
  return result.status === 0 ? result.stdout.trim() : '';
}

function inspectProfile() {
  try {
    const profile = readJson('docs/production/deployment-profile.json');
    const serialized = JSON.stringify(profile);
    const required = [
      'network', 'reviewedCommit', 'applicationDomain', 'appDomainHash', 'issuerKeyHash',
      'maxTokenAgeSec', 'maxAuthorizationTtlSec', 'launchpadAddress',
      'launchId', 'launchIdHash', 'pricePerUnitNano', 'perIdentityCap', 'inventory',
      'operatorApprovalReference',
    ];
    const missing = required.filter((key) => profile[key] === '' || profile[key] === 0 || String(profile[key]) === '0' || String(profile[key]).includes('PENDING'));
    const policyMismatch = profile.acceptedAsset !== 'native-ton' || profile.refundPolicy !== 'accounted-credit-pending-reviewed-withdrawal-adapter';
    if (profile.status !== 'approved' || missing.length || policyMismatch || serialized.includes('PENDING_')) {
      add('operator_profile', 'blocked', `operator deployment profile is incomplete (${missing.join(', ') || 'status/evidence placeholders remain'})`, ['docs/production/deployment-profile.json', 'docs/production/OPERATOR_INPUTS.md']);
    } else {
      add('operator_profile', 'pass', 'operator deployment profile is complete', ['docs/production/deployment-profile.json']);
    }
  } catch (error) {
    add('operator_profile', 'fail', error instanceof Error ? error.message : String(error));
  }
}

function inspectProductionEvidence() {
  try {
    const profile = readJson('docs/production/deployment-profile.json');
    const manifest = readJson('artifacts/manifest.json');
    const required = Array.isArray(profile.requiredCircuits) ? profile.requiredCircuits : [];
    if (manifest.status !== 'production-approved' || required.some((name) => manifest.circuits?.[name]?.status !== 'production-approved')) {
      add('production_artifacts', 'blocked', 'production ceremony/artifact approval is absent or not approved', ['artifacts/manifest.json', 'config/attestation-trust.json']);
    } else {
      add('production_artifacts', 'pass', 'production artifact manifest is approved', ['artifacts/manifest.json']);
    }
    const attestationPath = path.join(root, 'artifacts', 'production-attestation.json');
    if (!fs.existsSync(attestationPath)) {
      add('signed_attestation', 'blocked', 'signed production artifact attestation is absent', ['artifacts/production-attestation.json']);
    } else {
      const check = spawnSync(process.execPath, [path.join(root, 'scripts', 'check-production-attestation.mjs')], { cwd: root, encoding: 'utf8' });
      const evidencePath = 'build/release-preflight/production-attestation.log';
      fs.mkdirSync(path.join(root, 'build', 'release-preflight'), { recursive: true });
      fs.writeFileSync(path.join(root, evidencePath), `${check.stdout || ''}${check.stderr || ''}`);
      add('signed_attestation', check.status === 0 ? 'pass' : 'blocked', check.status === 0 ? 'production attestation verified' : 'production attestation could not be verified', [evidencePath]);
    }
  } catch (error) {
    add('production_evidence', 'fail', error instanceof Error ? error.message : String(error));
  }
}

function inspectExternalRecords() {
  const review = path.join(root, 'docs', 'production', 'independent-review.json');
  const testnet = path.join(root, 'deployments', 'testnet', 'manifest.json');
  let profile;
  let manifest;
  try {
    profile = readJson('docs/production/deployment-profile.json');
    manifest = readJson('artifacts/manifest.json');
  } catch (error) {
    add('external_records', 'fail', error instanceof Error ? error.message : String(error));
    return;
  }
  if (!fs.existsSync(review)) {
    add('independent_review', 'blocked', 'independent review record is absent', ['docs/production/independent-review.json']);
  } else {
    try {
      const record = JSON.parse(fs.readFileSync(review, 'utf8'));
      if (record.status !== 'approved' || record.commit !== profile.reviewedCommit || record.artifactManifestDigest !== sha256File(path.join(root, 'artifacts', 'manifest.json'), fs) || record.findingsClosed !== true) {
        add('independent_review', 'fail', 'independent review record is malformed, mismatched, or has open findings', ['docs/production/independent-review.json']);
      } else add('independent_review', 'pass', 'independent review record matches the release commit and artifact manifest', ['docs/production/independent-review.json']);
    } catch (error) {
      add('independent_review', 'fail', `cannot parse independent review record: ${error instanceof Error ? error.message : String(error)}`, ['docs/production/independent-review.json']);
    }
  }
  if (!fs.existsSync(testnet)) {
    add('testnet_evidence', 'blocked', 'testnet deployment evidence is absent', ['deployments/testnet/manifest.json']);
  } else {
    try {
      const record = JSON.parse(fs.readFileSync(testnet, 'utf8'));
      if (record.schemaVersion !== 1 || record.network !== 'testnet' || record.status !== 'verified' || record.sourceCommit !== profile.reviewedCommit || record.artifactManifestDigest !== sha256File(path.join(root, 'artifacts', 'manifest.json'), fs) || record.activeState !== 'active' || !/^[0-9]+$/.test(String(record.balanceNano)) || !/^[0-9]+$/.test(String(record.storageMarginNano)) || !record.transaction?.hash || !record.transaction?.lt || !Array.isArray(record.providers) || record.providers.length < 2 || record.canary?.validProofAccepted !== true || record.canary?.invalidPolicyRejected !== true || record.canary?.replayRejected !== true) {
        add('testnet_evidence', 'fail', 'testnet manifest is malformed, mismatched, or lacks canary/replay evidence', ['deployments/testnet/manifest.json']);
      } else add('testnet_evidence', 'pass', 'testnet manifest matches the release and records canary/replay evidence', ['deployments/testnet/manifest.json']);
    } catch (error) {
      add('testnet_evidence', 'fail', `cannot parse testnet manifest: ${error instanceof Error ? error.message : String(error)}`, ['deployments/testnet/manifest.json']);
    }
  }
  if (profile.network === 'mainnet') {
    if (typeof profile.mainnetApprovalReference !== 'string' || !profile.mainnetApprovalReference || profile.mainnetApprovalReference.includes('PENDING')) add('mainnet_approval', 'blocked', 'mainnet approval is an explicit operator/multisig action and is never inferred by CI', ['docs/production/OPERATOR_INPUTS.md']);
    else add('mainnet_approval', 'pass', 'mainnet approval reference is present in the operator profile', ['docs/production/deployment-profile.json']);
  }
  else add('mainnet_approval', 'not-applicable', 'deployment profile targets testnet/staging; mainnet approval is not yet in scope', ['docs/production/deployment-profile.json']);
  command('priva_launchpad_composition', ['npm', 'run', 'check:priva-composition'], true, 3);
}

function inspectSecrets() {
  const patterns = [
    /github_pat_[A-Za-z0-9_]{20,}/,
    /\bgh[pousr]_[A-Za-z0-9]{20,}/,
    /-----BEGIN (?:RSA|EC|OPENSSH|PRIVATE) KEY-----/,
  ];
  const result = spawnSync('git', ['grep', '-I', '-n', '-E', patterns.map((pattern) => pattern.source).join('|'), '--'], { cwd: root, encoding: 'utf8' });
  if (result.status === 0 && result.stdout.trim()) add('tracked_secret_scan', 'fail', 'secret-like material matched tracked files');
  else add('tracked_secret_scan', 'pass', 'no supported secret signatures found in tracked files');
}

function inspectRuntime() {
  const nodeMajor = Number(process.versions.node.split('.')[0]);
  const npm = spawnSync('npm', ['--version'], { cwd: root, encoding: 'utf8' });
  const npmMajor = Number(String(npm.stdout || '').trim().split('.')[0]);
  const lockfile = path.join(root, 'package-lock.json');
  let lockVersion;
  try { lockVersion = JSON.parse(fs.readFileSync(lockfile, 'utf8')).lockfileVersion; } catch { lockVersion = undefined; }
  if (!Number.isInteger(nodeMajor) || nodeMajor < 20 || nodeMajor >= 27 || !Number.isInteger(npmMajor) || npmMajor < 10 || lockVersion !== 3) {
    add('runtime_versions', 'fail', `unsupported runtime/toolchain (node ${process.versions.node}, npm ${String(npm.stdout || '').trim()}, lockfileVersion ${lockVersion ?? 'missing'})`, ['package.json', 'package-lock.json']);
  } else {
    add('runtime_versions', 'pass', `node ${process.versions.node}, npm ${String(npm.stdout).trim()}, lockfileVersion 3`, ['package.json', 'package-lock.json']);
  }
}

function inspectPackedSecrets() {
  const packed = spawnSync('npm', ['pack', '--json', '--ignore-scripts'], { cwd: root, encoding: 'utf8', maxBuffer: 2 * 1024 * 1024 });
  if (packed.status !== 0) {
    add('packed_secret_scan', 'fail', 'npm pack failed while checking release contents');
    return;
  }
  let tarball;
  try {
    const metadata = JSON.parse(packed.stdout);
    const packageMetadata = Array.isArray(metadata)
      ? metadata[0]
      : (metadata?.filename ? metadata : Object.values(metadata ?? {})[0]);
    const filename = packageMetadata?.filename;
    if (!filename) throw new Error('npm pack did not report a tarball');
    tarball = path.join(root, filename);
    const data = zlib.gunzipSync(fs.readFileSync(tarball));
    const suspicious = [/github_pat_[A-Za-z0-9_]{20,}/, /\bgh[pousr]_[A-Za-z0-9]{20,}/, /-----BEGIN (?:RSA|EC|OPENSSH|PRIVATE) KEY-----/].some((pattern) => pattern.test(data.toString('utf8')));
    add('packed_secret_scan', suspicious ? 'fail' : 'pass', suspicious ? 'secret-like material matched npm package contents' : 'no supported secret signatures found in npm package contents');
  } catch (error) {
    add('packed_secret_scan', 'fail', error instanceof Error ? error.message : String(error));
  } finally {
    if (tarball) fs.rmSync(tarball, { force: true });
  }
}

try {
  fs.mkdirSync(path.dirname(reportPath), { recursive: true });
  const head = gitOutput(['rev-parse', 'HEAD']);
  const status = gitOutput(['status', '--porcelain']);
  add('source_revision', head ? 'pass' : 'fail', head ? `release candidate ${head}` : 'unable to resolve Git revision');
  add('clean_worktree', status ? 'fail' : 'pass', status ? 'worktree has uncommitted changes' : 'worktree is clean');
  inspectProfile();
  inspectRuntime();
  inspectSecrets();
  command('build', ['npm', 'run', 'build']);
  command('tests', ['npm', 'test']);
  command('manifest', ['npm', 'run', 'artifacts:manifest:check']);
  command('development_artifacts', ['npm', 'run', 'artifacts:verify:dev']);
  command('ton_compilation', ['npm', 'run', 'compile:ton']);
  command('package_consumer', ['npm', 'run', 'package:consumer-smoke']);
  command('deployment_tooling', [process.execPath, '--check', path.join(root, 'scripts', 'deploy-ton.mjs')]);
  command('audit', ['npm', 'audit', '--audit-level=high']);
  const dockerfilePath = path.join(root, 'Dockerfile');
  if (fs.existsSync(dockerfilePath) && /@sha256:[0-9a-f]{64}/i.test(fs.readFileSync(dockerfilePath, 'utf8'))) {
    add('container_definition', 'pass', 'Dockerfile exists and pins its base image by digest', ['Dockerfile', '.dockerignore']);
  } else {
    add('container_definition', 'fail', 'Dockerfile is missing or its base image is not digest-pinned', ['Dockerfile']);
  }
  inspectProductionEvidence();
  inspectExternalRecords();
  inspectPackedSecrets();
  const report = {
    schemaVersion: 1,
    type: 'zk-tele-auth-release-preflight',
    startedAt,
    finishedAt: new Date().toISOString(),
    commit: head,
    reportSha256: null,
    gates,
  };
  fs.writeFileSync(reportPath, `${JSON.stringify(report, null, 2)}\n`);
  const digest = sha256File(reportPath, fs);
  report.reportSha256 = digest;
  fs.writeFileSync(reportPath, `${JSON.stringify(report, null, 2)}\n`);
  const failed = gates.filter((gate) => gate.status === 'fail');
  const blocked = gates.filter((gate) => gate.status === 'blocked');
  console.log(`release preflight: ${gates.filter((gate) => gate.status === 'pass').length} pass, ${failed.length} fail, ${blocked.length} blocked`);
  for (const gate of gates) console.log(`[${gate.status}] ${gate.id}: ${gate.message}`);
  console.log(`report: ${path.relative(root, reportPath)}`);
  if (failed.length || blocked.length) process.exitCode = 1;
} catch (error) {
  console.error(`ERROR: release preflight failed: ${error instanceof Error ? error.message : String(error)}`);
  process.exitCode = 1;
}
