#!/usr/bin/env node
/**
 * Verify that the checked-in Priva proving artifacts and composed contract have not changed without
 * updating their provenance record. `--production` additionally fails closed
 * unless a separately supplied, reviewed production attestation is present.
 */
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const provenancePath = path.join(root, 'artifacts', 'priva_purchase_auth', 'provenance.json');
const production = process.argv.includes('--production');

function fail(message) {
  console.error(`ERROR: ${message}`);
  process.exitCode = 1;
}

function sha256(file) {
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

if (!fs.existsSync(provenancePath)) {
  fail(`missing Priva artifact provenance: ${provenancePath}`);
} else {
  const provenance = JSON.parse(fs.readFileSync(provenancePath, 'utf8'));
  if (provenance.schemaVersion !== 1 || provenance.circuit !== 'priva_purchase_auth') {
    fail('unsupported Priva artifact provenance schema');
  } else if (!provenance.artifacts || typeof provenance.artifacts !== 'object') {
    fail('Priva artifact provenance has no artifact hashes');
  } else {
    for (const [relativePath, expectedHash] of Object.entries(provenance.artifacts)) {
      const file = path.join(root, relativePath);
      if (!fs.existsSync(file)) {
        fail(`provenance-tracked artifact is missing: ${relativePath}`);
        continue;
      }
      const actualHash = sha256(file);
      if (actualHash !== expectedHash) fail(`artifact hash mismatch: ${relativePath}`);
    }

    if (process.exitCode) {
      // Keep the output focused on the integrity failure.
    } else if (!production) {
      console.log(`✓ Priva artifact provenance verified (${provenance.status})`);
    } else {
      const attestationPath = path.join(root, 'artifacts', 'priva_purchase_auth', 'production-attestation.json');
      if (provenance.status !== 'production' || !fs.existsSync(attestationPath)) {
        fail('Priva proof artifacts are not production-approved: a reviewed production ceremony, signed artifact attestation, and independent audit are required');
      } else {
        const attestation = JSON.parse(fs.readFileSync(attestationPath, 'utf8'));
        if (attestation.schemaVersion !== 1 || attestation.circuit !== provenance.circuit || attestation.status !== 'production-approved') {
          fail('invalid Priva production attestation');
        } else if (JSON.stringify(attestation.artifacts) !== JSON.stringify(provenance.artifacts)) {
          fail('production attestation hashes do not match the deployed Priva artifact set');
        } else {
          console.log('✓ Priva proof artifacts have a production attestation');
        }
      }
    }
  }
}
