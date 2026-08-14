#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { Cell, contractAddress } from '@ton/core';
import { runTolkCompiler } from '@ton/tolk-js';
import { buildTonVerifierStateInitData } from '../dist/sdk/ton-storage.js';
import { sha256File } from './lib/attestation.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const args = new Set(process.argv.slice(2));
const value = (name, fallback) => {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : fallback;
};
const network = value('--network', 'testnet');
const contract = value('--contract', 'generic-verifier');
const workchain = Number(value('--workchain', '0'));
const live = args.has('--live');
const confirmedMainnet = args.has('--confirm-mainnet');
if (network !== 'testnet' && network !== 'mainnet') throw new Error('--network must be testnet or mainnet');
if (contract !== 'generic-verifier') throw new Error('only generic-verifier dry-run tooling is implemented; Priva launchpad composition is not yet approved');
if (!Number.isInteger(workchain) || workchain < -128 || workchain > 127) throw new Error('--workchain must be an integer in -128..127');
if (network === 'mainnet' && !confirmedMainnet) throw new Error('mainnet requires --confirm-mainnet and remains operator-controlled');
if (live) throw new Error('live network mutation is not implemented; use --dry-run and an approved multisig adapter');

const profile = JSON.parse(fs.readFileSync(path.join(root, 'docs/production/deployment-profile.json'), 'utf8'));
const required = ['applicationDomain', 'issuerKeyHash', 'maxTokenAgeSec', 'requirePremium'];
for (const key of required) {
  if (profile[key] === '' || profile[key] === 0 || String(profile[key]).includes('PENDING')) throw new Error(`operator profile is incomplete: ${key}`);
}
const compilation = await runTolkCompiler({
  entrypointFileName: 'contracts/zk_tele_auth_verifier.tolk',
  fsReadCallback: (requestedPath) => fs.readFileSync(path.resolve(root, requestedPath), 'utf8'),
});
if (compilation.status === 'error') throw new Error(compilation.message);
const code = Cell.fromBoc(Buffer.from(compilation.codeBoc64, 'base64'))[0];
const data = buildTonVerifierStateInitData({
  appDomainHash: String(profile.appDomainHash || (() => { throw new Error('operator profile requires appDomainHash'); })()),
  issuerKeyHash: String(profile.issuerKeyHash),
  maxTokenAgeSec: Number(profile.maxTokenAgeSec),
  requirePremium: Boolean(profile.requirePremium),
});
const address = contractAddress(workchain, { code, data });
const manifestPath = path.join(root, 'artifacts', 'manifest.json');
const summary = {
  schemaVersion: 1,
  mode: 'dry-run',
  network,
  contract,
  workchain,
  sourceCommit: spawnSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).stdout.trim(),
  artifactManifestDigest: sha256File(manifestPath, fs),
  codeHash: code.hash().toString('hex'),
  dataHash: data.hash().toString('hex'),
  address: address.toString(),
  policy: {
    appDomainHash: String(profile.appDomainHash),
    issuerKeyHash: String(profile.issuerKeyHash),
    maxTokenAgeSec: Number(profile.maxTokenAgeSec),
    requirePremium: Boolean(profile.requirePremium),
  },
  liveMutation: false,
};
console.log(JSON.stringify(summary, null, 2));

