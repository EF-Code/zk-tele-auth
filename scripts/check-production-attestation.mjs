#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalJson, verifyAttestationSignature, sha256File } from './lib/attestation.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const profilePath = path.join(root, 'docs', 'production', 'deployment-profile.json');
const manifestPath = path.join(root, 'artifacts', 'manifest.json');
const trustPath = path.join(root, 'config', 'attestation-trust.json');
const attestationPath = path.join(root, 'artifacts', 'production-attestation.json');

function fail(message) {
  console.error(`ERROR: ${message}`);
  process.exitCode = 1;
}

try {
  for (const [file, label] of [[profilePath, 'deployment profile'], [manifestPath, 'artifact manifest'], [trustPath, 'attestation trust policy'], [attestationPath, 'production attestation']]) {
    if (!fs.existsSync(file)) throw new Error(`missing ${label}: ${path.relative(root, file)}`);
  }
  const profile = JSON.parse(fs.readFileSync(profilePath, 'utf8'));
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  const trust = JSON.parse(fs.readFileSync(trustPath, 'utf8'));
  const attestation = JSON.parse(fs.readFileSync(attestationPath, 'utf8'));
  if (profile.schemaVersion !== 1 || !Array.isArray(profile.requiredCircuits) || profile.requiredCircuits.length === 0) {
    throw new Error('deployment profile must name at least one required circuit');
  }
  if (manifest.status !== 'production-approved') throw new Error('artifact manifest is not production-approved');
  verifyAttestationSignature(attestation, trust);
  if (attestation.network !== profile.network) throw new Error('attestation network does not match deployment profile');
  if (attestation.commit !== profile.reviewedCommit) throw new Error('attestation commit does not match deployment profile');
  if (attestation.manifestDigest !== sha256File(manifestPath, fs)) throw new Error('attestation does not bind the artifact manifest digest');
  for (const circuit of profile.requiredCircuits) {
    if (!manifest.circuits?.[circuit]) throw new Error(`required circuit is absent from manifest: ${circuit}`);
    if (manifest.circuits[circuit].status !== 'production-approved') throw new Error(`circuit is not production-approved: ${circuit}`);
    const expected = manifest.circuits[circuit].files;
    const actual = attestation.circuits?.[circuit]?.files;
    if (canonicalJson(expected) !== canonicalJson(actual)) throw new Error(`attestation hashes do not match manifest: ${circuit}`);
  }
  console.log('✓ cryptographically verified production artifact attestation');
} catch (error) {
  fail(error instanceof Error ? error.message : String(error));
}
