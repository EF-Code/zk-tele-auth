#!/usr/bin/env node
/**
 * Import externally generated artifacts only after an operator supplies a
 * verified transcript hash.  This command never creates ceremony material,
 * never copies a ptau into Git, and never marks artifacts production-approved;
 * a signed attestation and independent review are separate gates.
 */
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import * as snarkjs from 'snarkjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
function canonicalJson(value) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('non-finite verification-key value');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  throw new Error('unsupported verification-key value');
}
const arg = (name) => {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : undefined;
};
const sourceDir = arg('--source-dir');
const ptau = arg('--ptau');
const expectedPtauHash = arg('--expected-ptau-sha256');
const commit = arg('--commit');
const network = arg('--network');
const importFiles = process.argv.includes('--import');
if (!sourceDir || !ptau || !expectedPtauHash || !commit || !network) throw new Error('--source-dir, --ptau, --expected-ptau-sha256, --commit, and --network are required');
if (!/^[0-9a-f]{64}$/i.test(expectedPtauHash)) throw new Error('--expected-ptau-sha256 must be a 64-character hex digest');
if (!/^[0-9a-f]{40}$/i.test(commit)) throw new Error('--commit must be a full Git commit');
if (!['testnet', 'mainnet'].includes(network)) throw new Error('--network must be testnet or mainnet');
const absoluteSource = path.resolve(sourceDir);
const absolutePtau = path.resolve(ptau);
if (!fs.existsSync(absolutePtau)) throw new Error('phase-one transcript is missing');
const ptauHash = crypto.createHash('sha256').update(fs.readFileSync(absolutePtau)).digest('hex');
if (ptauHash !== expectedPtauHash.toLowerCase()) throw new Error('phase-one transcript digest does not match the independently reviewed expected hash');
const circuits = ['telegram_auth', 'priva_purchase_auth', 'membership'];
const copied = [];
for (const circuit of circuits) {
  const source = path.join(absoluteSource, circuit);
  const target = path.join(root, 'artifacts', circuit);
  const required = [
    `${circuit}.r1cs`, `${circuit}.wasm`, `${circuit}_final.zkey`, `${circuit}_vkey.json`,
  ];
  for (const filename of required) if (!fs.existsSync(path.join(source, filename))) throw new Error(`missing externally supplied ${circuit}/${filename}`);
  // Cryptographically bind the final zkey to the supplied phase-one file and
  // exact R1CS before any repository file is changed.
  const verified = await snarkjs.zKey.verify(absolutePtau, path.join(source, `${circuit}.r1cs`), path.join(source, `${circuit}_final.zkey`));
  if (!verified) throw new Error(`snarkjs zkey verification failed: ${circuit}`);
  const exportedVkey = await snarkjs.zKey.exportVerificationKey(path.join(source, `${circuit}_final.zkey`));
  const suppliedVkey = JSON.parse(fs.readFileSync(path.join(source, `${circuit}_vkey.json`), 'utf8'));
  if (canonicalJson(exportedVkey) !== canonicalJson(suppliedVkey)) {
    throw new Error(`supplied verification key does not match final zkey: ${circuit}`);
  }
  if (importFiles) {
    fs.mkdirSync(target, { recursive: true });
    for (const filename of required) {
      fs.copyFileSync(path.join(source, filename), path.join(target, filename));
      copied.push(path.join('artifacts', circuit, filename));
    }
  }
}
const report = {
  schemaVersion: 1,
  type: 'zk-tele-auth-production-artifact-import',
  status: importFiles ? 'imported-pending-attestation' : 'verified-no-write',
  network,
  reviewedCommit: commit,
  phaseOneTranscriptSha256: ptauHash,
  circuits,
  copied,
  verifiedAt: new Date().toISOString(),
};
console.log(JSON.stringify(report, null, 2));
process.exit(0);
