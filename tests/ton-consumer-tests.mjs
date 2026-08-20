import assert from 'node:assert/strict';
import { Address, Cell } from '@ton/core';
import { ZkAuthProofGenerator } from '../dist/sdk/index.js';
import {
  TON_GROTH16_VERIFY_OPCODE,
  TON_VERIFIER_MIN_VALUE_NANO,
  buildTonGroth16VerifierMessage,
  buildTonVerifierTonConnectTransaction,
} from '../dist/sdk/ton.js';

const now = Math.floor(Date.now() / 1000);
const proofPayload = await ZkAuthProofGenerator.generateProof({
  userId: '987654321',
  authDate: now,
  isPremium: false,
  appDomain: 'consumer.example',
  currentTimestamp: now,
  maxTokenAgeSec: 3600,
  issuerSecret: '123456789',
});

const body = await buildTonGroth16VerifierMessage(proofPayload);
assert.ok(body instanceof Cell);
assert.equal(body.beginParse().loadUint(32), TON_GROTH16_VERIFY_OPCODE);

const transaction = await buildTonVerifierTonConnectTransaction({
  verifierAddress: 'EQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAM9c',
  proof: proofPayload.proof,
  publicSignals: proofPayload.publicSignals,
  validUntil: now + 300,
});
assert.equal(transaction.messages.length, 1);
assert.equal(transaction.messages[0].amount, TON_VERIFIER_MIN_VALUE_NANO.toString());
assert.equal(Address.parse(transaction.messages[0].address).workChain, 0);
assert.ok(transaction.messages[0].payload.length > 0);
await assert.rejects(buildTonGroth16VerifierMessage({ proof: { ...proofPayload.proof, curve: 'bn128' }, publicSignals: proofPayload.publicSignals }), /BLS12-381/);
console.log('TON consumer transaction tests: passed');
