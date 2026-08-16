#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { Cell, contractAddress } from '@ton/core';
import { runTolkCompiler } from '@ton/tolk-js';
import { buildPrivaLaunchpadStateInitData, buildTonVerifierStateInitData } from '../dist/sdk/ton-storage.js';
import { sha256File } from './lib/attestation.mjs';
import { validateDeploymentProfile } from './lib/deployment-profile.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const value = (name, fallback) => {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : fallback;
};
const args = new Set(process.argv.slice(2));
const network = value('--network', 'testnet');
const contract = value('--contract', 'generic-verifier');
const workchain = Number(value('--workchain', '0'));
const dryRun = args.has('--dry-run');
const live = args.has('--live');
const confirmedMainnet = args.has('--confirm-mainnet');
if (!['testnet', 'mainnet'].includes(network)) throw new Error('--network must be testnet or mainnet');
if (!['generic-verifier', 'priva-launchpad'].includes(contract)) throw new Error('--contract must be generic-verifier or priva-launchpad');
if (!Number.isInteger(workchain) || workchain < -128 || workchain > 127) throw new Error('--workchain must be an integer in -128..127');
if (!dryRun && !live) throw new Error('deployment mode must be explicit: pass --dry-run or --live');
if (live) throw new Error('live network mutation is not implemented; use an approved multisig adapter after this deterministic dry-run');
if (network === 'mainnet' && !confirmedMainnet) throw new Error('mainnet dry-runs require --confirm-mainnet and remain operator-controlled');

const profile = JSON.parse(fs.readFileSync(path.join(root, 'docs/production/deployment-profile.json'), 'utf8'));
const sourceCommit = spawnSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).stdout.trim();
const profileValidation = validateDeploymentProfile(profile, { candidateCommit: sourceCommit, requirePriva: contract === 'priva-launchpad' });
if (profileValidation.invalid.length) throw new Error(`operator profile is invalid: ${profileValidation.invalid.join(', ')}`);
if (profileValidation.missing.length) throw new Error(`operator profile is incomplete: ${profileValidation.missing.join(', ')}`);
if (profile.network !== network) throw new Error(`operator profile network ${profile.network} does not match --network ${network}`);

const entrypointFileName = contract === 'generic-verifier' ? 'contracts/zk_tele_auth_verifier.tolk' : 'contracts/priva_purchase_launchpad.tolk';
const compilation = await runTolkCompiler({
  entrypointFileName,
  fsReadCallback: (requestedPath) => fs.readFileSync(path.resolve(root, requestedPath), 'utf8'),
});
if (compilation.status === 'error') throw new Error(compilation.message);
const code = Cell.fromBoc(Buffer.from(compilation.codeBoc64, 'base64'))[0];
const data = contract === 'generic-verifier'
  ? buildTonVerifierStateInitData({
    appDomainHash: String(profile.appDomainHash),
    issuerKeyHash: String(profile.issuerKeyHash),
    maxTokenAgeSec: Number(profile.maxTokenAgeSec),
    requirePremium: Boolean(profile.requirePremium),
  })
  : buildPrivaLaunchpadStateInitData({
    appDomainHash: String(profile.appDomainHash),
    issuerKeyHash: String(profile.issuerKeyHash),
    launchIdHash: String(profile.launchIdHash),
    maxTokenAgeSec: Number(profile.maxTokenAgeSec),
    requirePremium: Boolean(profile.requirePremium),
    maxAuthorizationTtlSec: Number(profile.maxAuthorizationTtlSec),
    pricePerUnitNano: String(profile.pricePerUnitNano),
    perIdentityCap: String(profile.perIdentityCap),
    inventory: String(profile.inventory),
  });
const address = contractAddress(workchain, { code, data });
const manifestPath = path.join(root, 'artifacts', 'manifest.json');
const expectedFundingNano = contract === 'generic-verifier' ? 50_000_000n : 100_000_000n + BigInt(String(profile.pricePerUnitNano));
const summary = {
  schemaVersion: 1,
  mode: 'dry-run',
  network,
  contract,
  workchain,
  sourceCommit,
  artifactManifestDigest: sha256File(manifestPath, fs),
  codeHash: code.hash().toString('hex'),
  dataHash: data.hash().toString('hex'),
  address: address.toString(),
  policy: contract === 'generic-verifier' ? {
    appDomainHash: String(profile.appDomainHash),
    applicationDomain: String(profile.applicationDomain),
    issuerKeyHash: String(profile.issuerKeyHash),
    maxTokenAgeSec: Number(profile.maxTokenAgeSec),
    requirePremium: Boolean(profile.requirePremium),
  } : {
    appDomainHash: String(profile.appDomainHash),
    applicationDomain: String(profile.applicationDomain),
    issuerKeyHash: String(profile.issuerKeyHash),
    launchIdHash: String(profile.launchIdHash),
    maxTokenAgeSec: Number(profile.maxTokenAgeSec),
    requirePremium: Boolean(profile.requirePremium),
    maxAuthorizationTtlSec: Number(profile.maxAuthorizationTtlSec),
    pricePerUnitNano: String(profile.pricePerUnitNano),
    perIdentityCap: String(profile.perIdentityCap),
    inventory: String(profile.inventory),
  },
  expectedFundingNano: expectedFundingNano.toString(),
  feeCeilingNano: (expectedFundingNano + 200_000_000n).toString(),
  operatorApprovalReference: profile.operatorApprovalReference || 'PENDING_OPERATOR_INPUT',
  liveMutation: false,
};
console.log(JSON.stringify(summary, null, 2));
