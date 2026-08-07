import * as assert from 'node:assert';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { beginCell, Cell, contractAddress, toNano } from '@ton/core';
import { Blockchain } from '@ton/sandbox';
import { runTolkCompiler } from '@ton/tolk-js';
import { proofToMessageCell } from 'export-ton-verifier';
import {
  NullifierDeriver,
  ZkAuthProofGenerator,
  buildTonVerifierStateInitData,
} from '../dist/sdk/index.js';

const root = process.cwd();
const DOMAIN = 'dapp.zk-tele-auth.io';
const ISSUER_SECRET = '1892374981273498127349812734981273498';
const ATTACKER_SECRET = '9823749812734981273498127349812734981';
const MAX_AGE = 3600;

class VerifierContract {
  constructor(code, data) {
    this.init = { code, data };
    this.address = contractAddress(0, this.init);
  }

  async send(provider, via, body) {
    await provider.internal(via, { value: toNano('0.1'), body });
  }

  async getVerifiedCount(provider) {
    const result = await provider.get('verifiedCount', []);
    return result.stack.readBigNumber();
  }
}

function hasExitCode(result, exitCode) {
  return result.transactions.some((transaction) =>
    transaction.description.type === 'generic' &&
    transaction.description.computePhase.type === 'vm' &&
    transaction.description.computePhase.exitCode === exitCode
  );
}

async function proofBody(issuerSecret, now) {
  const payload = await ZkAuthProofGenerator.generateProof({
    userId: 424242,
    authDate: now - 5,
    isPremium: true,
    appDomain: DOMAIN,
    currentTimestamp: now,
    maxTokenAgeSec: MAX_AGE,
    isPremiumRequired: true,
    issuerSecret,
  });
  return proofToMessageCell({
    proof: payload.proof,
    publicSignals: payload.publicSignals,
    protocol: 'groth16',
    lang: 'tolk',
  });
}

async function run() {
  console.log('\nTON sandbox security tests\n');
  const compilation = await runTolkCompiler({
    entrypointFileName: 'contracts/zk_tele_auth_verifier.tolk',
    fsReadCallback: (requestedPath) => fs.readFileSync(path.resolve(root, requestedPath), 'utf8'),
  });
  if (compilation.status === 'error') throw new Error(compilation.message);
  const code = Cell.fromBoc(Buffer.from(compilation.codeBoc64, 'base64'))[0];

  const issuerKeyHash = await NullifierDeriver.deriveIssuerKeyHash(ISSUER_SECRET);
  const appDomainHash = await NullifierDeriver.hashAppDomain(DOMAIN);
  const data = buildTonVerifierStateInitData({
    appDomainHash,
    issuerKeyHash,
    maxTokenAgeSec: MAX_AGE,
    requirePremium: true,
  });

  const blockchain = await Blockchain.create();
  const now = Math.floor(Date.now() / 1000);
  blockchain.now = now;
  const sender = await blockchain.treasury('zk-tele-auth-test-sender');
  const contract = blockchain.openContract(new VerifierContract(code, data));
  await contract.send(sender.getSender(), beginCell().endCell());
  assert.strictEqual(await contract.getVerifiedCount(), 0n);

  const validBody = await proofBody(ISSUER_SECRET, now);
  const accepted = await contract.send(sender.getSender(), validBody);
  assert.ok(hasExitCode(accepted, 0));
  assert.strictEqual(await contract.getVerifiedCount(), 1n);
  console.log('  ✓ real issuer-bound proof accepted and persisted');

  const replay = await contract.send(sender.getSender(), validBody);
  assert.ok(hasExitCode(replay, 265));
  assert.strictEqual(await contract.getVerifiedCount(), 1n);
  console.log('  ✓ stable-nullifier replay rejected with exit 265');

  const attackerBody = await proofBody(ATTACKER_SECRET, now);
  const wrongIssuer = await contract.send(sender.getSender(), attackerBody);
  assert.ok(hasExitCode(wrongIssuer, 267));
  assert.strictEqual(await contract.getVerifiedCount(), 1n);
  console.log('  ✓ cryptographically valid proof from wrong issuer rejected with exit 267');

  const unconfigured = blockchain.openContract(new VerifierContract(code, beginCell().endCell()));
  await unconfigured.send(sender.getSender(), beginCell().endCell());
  const missingPolicy = await unconfigured.send(sender.getSender(), validBody);
  assert.ok(hasExitCode(missingPolicy, 266));
  console.log('  ✓ empty StateInit cannot accept proofs (exit 266)');
}

run().catch((error) => {
  console.error(error);
  process.exit(1);
});
