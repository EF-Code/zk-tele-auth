#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { sha256File } from './lib/attestation.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const manifestArgIndex = process.argv.indexOf('--manifest');
const manifestRelative = manifestArgIndex >= 0 ? process.argv[manifestArgIndex + 1] : '';
if (!manifestRelative) throw new Error('--manifest <path> is required');
const manifestPath = path.resolve(root, manifestRelative);
if (!manifestPath.startsWith(`${root}${path.sep}`)) throw new Error('deployment manifest must be inside the repository');
if (!fs.existsSync(manifestPath)) throw new Error(`missing deployment manifest: ${manifestRelative}`);
const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
const required = ['schemaVersion', 'network', 'sourceCommit', 'artifactManifestDigest', 'contract', 'address', 'codeHash', 'dataHash', 'verifiedAt'];
for (const key of required) if (manifest[key] === undefined || manifest[key] === '') throw new Error(`deployment manifest missing ${key}`);
if (manifest.schemaVersion !== 1 || !['testnet', 'mainnet'].includes(manifest.network)) throw new Error('invalid deployment manifest schema/network');
if (!/^[0-9a-f]{40}$/.test(manifest.sourceCommit) || !/^[0-9a-f]{64}$/i.test(manifest.artifactManifestDigest)) throw new Error('invalid deployment manifest digest format');
if (!/^[-_A-Za-z0-9:]+$/.test(manifest.address)) throw new Error('invalid deployment address format');
const artifactManifestPath = path.join(root, 'artifacts', 'manifest.json');
if (!fs.existsSync(artifactManifestPath)) throw new Error('artifact manifest is missing');
if (sha256File(artifactManifestPath, fs) !== manifest.artifactManifestDigest) throw new Error('deployment manifest artifact digest mismatch');
console.log(JSON.stringify({
  status: 'locally-consistent',
  network: manifest.network,
  contract: manifest.contract,
  address: manifest.address,
  artifactManifestDigest: manifest.artifactManifestDigest,
  liveChainVerification: 'not-performed',
}, null, 2));

