#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { sha256File } from './lib/attestation.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const manifestPath = path.join(root, 'artifacts', 'manifest.json');
const write = process.argv.includes('--write');

const circuits = {
  telegram_auth: {
    source: 'circuits/telegram_auth.circom',
    files: [
      'artifacts/telegram_auth/telegram_auth.r1cs',
      'artifacts/telegram_auth/telegram_auth.wasm',
      'artifacts/telegram_auth/telegram_auth_final.zkey',
      'artifacts/telegram_auth/telegram_auth_vkey.json',
      'artifacts/telegram_auth/telegram_auth.json',
      'contracts/zk_tele_auth_verifier.tolk',
    ],
  },
  priva_purchase_auth: {
    source: 'circuits/priva_purchase_auth.circom',
    files: [
      'artifacts/priva_purchase_auth/priva_purchase_auth.r1cs',
      'artifacts/priva_purchase_auth/priva_purchase_auth.wasm',
      'artifacts/priva_purchase_auth/priva_purchase_auth_final.zkey',
      'artifacts/priva_purchase_auth/priva_purchase_auth_vkey.json',
      'artifacts/priva_purchase_auth/priva_purchase_auth.json',
      'contracts/priva_purchase_auth_verifier.tolk',
      'contracts/priva_purchase_auth_verifier_wrapper.tolk',
      'contracts/priva_purchase_launchpad.tolk',
    ],
  },
  membership: {
    source: 'circuits/membership.circom',
    files: [
      'artifacts/membership/membership.r1cs',
      'artifacts/membership/membership.wasm',
      'artifacts/membership/membership_final.zkey',
      'artifacts/membership/membership_vkey.json',
      'artifacts/membership/membership.json',
    ],
  },
};

function fail(message) {
  console.error(`ERROR: ${message}`);
  process.exitCode = 1;
}

function buildManifest() {
  const manifest = {
    schemaVersion: 2,
    type: 'zk-tele-auth-artifact-manifest',
    status: 'development-only',
    generatedBy: 'scripts/check-artifact-manifest.mjs',
    toolchain: {
      circom: '2.1.6',
      snarkjs: '0.7.6',
      tolk: '1.4.2',
      exporter: '3.0.2',
      node: '>=20 <27',
    },
    circuits: {},
  };
  for (const [name, config] of Object.entries(circuits)) {
    const files = [config.source, ...config.files];
    const hashes = {};
    for (const relativePath of files) {
      const absolutePath = path.join(root, relativePath);
      if (!fs.existsSync(absolutePath)) throw new Error(`missing artifact-manifest file: ${relativePath}`);
      hashes[relativePath] = sha256File(absolutePath, fs);
    }
    const metadataPath = path.join(root, `artifacts/${name}/${name}.json`);
    const metadata = JSON.parse(fs.readFileSync(metadataPath, 'utf8'));
    const runtimeFiles = Object.fromEntries(Object.entries(hashes).filter(([relativePath]) => /\.(?:wasm|zkey)$|_vkey\.json$/.test(relativePath)));
    manifest.circuits[name] = {
      status: 'development-only',
      circuitVersion: 1,
      curve: metadata.prime === 'bls12381' ? 'BLS12-381' : metadata.prime,
      constraints: metadata.constraints,
      publicSignals: metadata.publicInputs,
      files: hashes,
      runtimeFiles,
    };
  }
  return manifest;
}

try {
  const expected = buildManifest();
  if (write) {
    fs.writeFileSync(manifestPath, `${JSON.stringify(expected, null, 2)}\n`);
    console.log(`wrote ${path.relative(root, manifestPath)}`);
  } else if (!fs.existsSync(manifestPath)) {
    fail(`missing ${path.relative(root, manifestPath)}; run npm run artifacts:manifest:write`);
  } else {
    const actual = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
    if (JSON.stringify(actual) !== JSON.stringify(expected)) {
      const mismatches = [];
      for (const [circuit, config] of Object.entries(expected.circuits)) {
        for (const [relativePath, expectedHash] of Object.entries(config.files)) {
          const actualHash = actual.circuits?.[circuit]?.files?.[relativePath];
          if (actualHash !== expectedHash) mismatches.push(`${relativePath}: manifest=${actualHash || '<missing>'}, current=${expectedHash}`);
        }
        if (actual.circuits?.[circuit]?.status !== config.status) mismatches.push(`${circuit}: status=${actual.circuits?.[circuit]?.status || '<missing>'}, current=${config.status}`);
      }
      if (actual.status !== expected.status) mismatches.push(`manifest status=${actual.status || '<missing>'}, current=${expected.status}`);
      fail(`artifact manifest is stale or has been edited outside the generator${mismatches.length ? ` (${mismatches.slice(0, 8).join('; ')})` : ''}`);
    } else {
      console.log('✓ artifact manifest matches all source and generated files');
    }
  }
} catch (error) {
  fail(error instanceof Error ? error.message : String(error));
}
