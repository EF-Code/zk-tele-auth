#!/usr/bin/env node
/**
 * Verify artifact hashes and exported verification keys for any manifest
 * lifecycle status. Development-only verification remains available through
 * verify-development-artifacts.mjs; release preflight uses this status-neutral
 * integrity check so an approved manifest is not rejected merely because it is
 * no longer a development manifest.
 */
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import * as snarkjs from 'snarkjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const manifestPath = path.join(root, 'artifacts', 'manifest.json');
const allowedStatuses = new Set(['development-only', 'production-pending-attestation', 'production-approved', 'revoked']);
const hash = (file) => crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
const canonical = (value) => {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
};

if (!fs.existsSync(manifestPath)) throw new Error('artifact manifest is missing');
const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
if (manifest.schemaVersion !== 2 || manifest.type !== 'zk-tele-auth-artifact-manifest') throw new Error('unsupported artifact manifest schema');
if (!allowedStatuses.has(manifest.status)) throw new Error(`unsupported artifact manifest status: ${manifest.status}`);

for (const [circuit, entry] of Object.entries(manifest.circuits || {})) {
  if (!allowedStatuses.has(entry.status)) throw new Error(`unsupported artifact status: ${circuit}=${entry.status}`);
  for (const [relativePath, expected] of Object.entries(entry.files || {})) {
    const file = path.resolve(root, relativePath);
    if (!file.startsWith(`${root}${path.sep}`) || !fs.existsSync(file)) throw new Error(`missing ${relativePath}`);
    if (hash(file) !== expected) throw new Error(`hash mismatch: ${relativePath}`);
  }
  for (const [relativePath, expected] of Object.entries(entry.runtimeFiles || {})) {
    if (entry.files?.[relativePath] !== expected) throw new Error(`runtime file is not bound to the full manifest: ${relativePath}`);
  }
  const vkeyPath = path.join(root, 'artifacts', circuit, `${circuit}_vkey.json`);
  const zkeyPath = path.join(root, 'artifacts', circuit, `${circuit}_final.zkey`);
  if (fs.existsSync(vkeyPath) && fs.existsSync(zkeyPath)) {
    const exported = await snarkjs.zKey.exportVerificationKey(zkeyPath);
    const committed = JSON.parse(fs.readFileSync(vkeyPath, 'utf8'));
    if (canonical(exported) !== canonical(committed)) throw new Error(`verification key drift: ${circuit}`);
  }
}

console.log(`✓ artifact hashes and exported verification keys verified (${manifest.status}; ${Object.keys(manifest.circuits || {}).length} circuits)`);
process.exit(0);
