import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { beginCell, Cell, contractAddress, toNano } from '@ton/core';
import { Blockchain } from '@ton/sandbox';
import { runTolkCompiler } from '@ton/tolk-js';
import { proofToMessageCell } from 'export-ton-verifier';
import {
  NullifierDeriver,
  PrivaPurchaseAuthProofGenerator,
  buildPrivaLaunchpadPurchaseBody,
  buildPrivaLaunchpadStateInitData,
  toBasechainAddressLimbs,
} from '../dist/sdk/index.js';

const root = process.cwd();
const DOMAIN = 'launchpad.zk-tele-auth.io';
const ISSUER_SECRET = '1892374981273498127349812734981273498';
const MAX_AGE = 3600;
const PRICE = toNano('1');

class LaunchpadContract {
  constructor(code, data) {
    this.init = { code, data };
    this.address = contractAddress(0, this.init);
  }

  async send(provider, via, body, value = toNano('2')) {
    return provider.internal(via, { value, body });
  }

  async getPolicy(provider) {
    const { stack } = await provider.get('launchPolicy', []);
    return {
      appDomainHash: stack.readBigNumber(),
      issuerKeyHash: stack.readBigNumber(),
      launchIdHash: stack.readBigNumber(),
      maxTokenAgeSec: stack.readBigNumber(),
      requirePremium: stack.readBigNumber(),
      maxAuthorizationTtlSec: stack.readBigNumber(),
      pricePerUnit: stack.readBigNumber(),
      perIdentityCap: stack.readBigNumber(),
      inventory: stack.readBigNumber(),
      sold: stack.readBigNumber(),
    };
  }

  async getIdentityPurchased(provider, identity) {
    const { stack } = await provider.get('identityPurchased', [{ type: 'int', value: BigInt(identity) }]);
    return stack.readBigNumber();
  }

  async getUsedAction(provider, action) {
    const { stack } = await provider.get('usedAction', [{ type: 'int', value: BigInt(action) }]);
    return stack.readBigNumber();
  }

  async getUsedQuery(provider, queryId) {
    const { stack } = await provider.get('usedQuery', [{ type: 'int', value: BigInt(queryId) }]);
    return stack.readBigNumber();
  }

  async getRefundCredit(provider, recipientHash) {
    const { stack } = await provider.get('refundCredit', [{ type: 'int', value: BigInt(recipientHash) }]);
    return stack.readBigNumber();
  }
}

function hasExitCode(result, exitCode) {
  return result.transactions.some((transaction) =>
    transaction.description.type === 'generic' &&
    transaction.description.computePhase.type === 'vm' &&
    transaction.description.computePhase.exitCode === exitCode
  );
}

function splitProofMessage(message) {
  const slice = message.beginParse();
  assert.equal(slice.loadUint(32), 993839639);
  return { proof: slice.loadRef(), pubInputs: slice.loadRef() };
}

async function makeProof({ codeAddress, launchIdHash, recipient, userId = 424242, clientNonce = '1', expiryEpoch, now, appDomain = DOMAIN, issuerSecret = ISSUER_SECRET, isPremium = true, isPremiumRequired = true, currentTimestamp = now, maxTokenAgeSec = MAX_AGE }) {
  const limbs = toBasechainAddressLimbs(codeAddress);
  const recipientLimbs = toBasechainAddressLimbs(recipient);
  const payload = await PrivaPurchaseAuthProofGenerator.generateProof({
    userId,
    authDate: currentTimestamp - 5,
    isPremium,
    appDomain,
    currentTimestamp,
    maxTokenAgeSec,
    isPremiumRequired,
    issuerSecret,
    launchIdHash,
    launchpadAddressHi: limbs.addressHi,
    launchpadAddressLo: limbs.addressLo,
    recipientAddressHi: recipientLimbs.addressHi,
    recipientAddressLo: recipientLimbs.addressLo,
    clientNonce,
    expiryEpoch,
    circuitVersion: 1,
  });
  const envelope = await proofToMessageCell({
    proof: payload.proof,
    publicSignals: payload.publicSignals,
    protocol: 'groth16',
    lang: 'tolk',
  });
  const cells = splitProofMessage(envelope);
  return { payload, body: buildPrivaLaunchpadPurchaseBody({ queryId: clientNonce, quantity: 1, recipient, ...cells }) };
}

async function bodyFromPayload(payload, { recipient, queryId, quantity = 1 }) {
  const envelope = await proofToMessageCell({
    proof: payload.proof,
    publicSignals: payload.publicSignals,
    protocol: 'groth16',
    lang: 'tolk',
  });
  return buildPrivaLaunchpadPurchaseBody({ queryId, quantity, recipient, ...splitProofMessage(envelope) });
}

function mutatedPayload(payload, changes) {
  const publicSignals = [...payload.publicSignals];
  for (const [index, value] of Object.entries(changes)) publicSignals[Number(index)] = String(value);
  return { ...payload, publicSignals };
}

async function compile() {
  const result = await runTolkCompiler({
    entrypointFileName: 'contracts/priva_purchase_launchpad.tolk',
    fsReadCallback: (requestedPath) => fs.readFileSync(path.resolve(root, requestedPath), 'utf8'),
  });
  if (result.status === 'error') throw new Error(result.message);
  return Cell.fromBoc(Buffer.from(result.codeBoc64, 'base64'))[0];
}

async function run() {
  console.log('\nPriva launchpad composition tests\n');
  const code = await compile();
  const issuerKeyHash = await NullifierDeriver.deriveIssuerKeyHash(ISSUER_SECRET);
  const appDomainHash = await NullifierDeriver.hashAppDomain(DOMAIN);
  const launchIdHash = '777';
  const data = buildPrivaLaunchpadStateInitData({
    appDomainHash,
    issuerKeyHash,
    launchIdHash,
    maxTokenAgeSec: MAX_AGE,
    requirePremium: true,
    maxAuthorizationTtlSec: 600,
    pricePerUnitNano: PRICE,
    perIdentityCap: 2,
    inventory: 4,
  });

  const blockchain = await Blockchain.create();
  const now = Math.floor(Date.now() / 1000);
  blockchain.now = now;
  const buyer = await blockchain.treasury('priva-launchpad-buyer');
  const otherBuyer = await blockchain.treasury('priva-launchpad-other-buyer');
  const contract = blockchain.openContract(new LaunchpadContract(code, data));
  await contract.send(buyer.getSender(), beginCell().endCell(), toNano('0.2'));
  const policy = await contract.getPolicy();
  assert.equal(policy.pricePerUnit, PRICE);
  assert.equal(policy.inventory, 4n);
  assert.equal(policy.sold, 0n);
  console.log('  ✓ immutable launch policy and accounting state deserialize');

  const first = await makeProof({
    codeAddress: contract.address,
    launchIdHash,
    recipient: buyer.address,
    clientNonce: '1',
    expiryEpoch: now + 300,
    now,
  });
  const accepted = await contract.send(buyer.getSender(), first.body, toNano('2.25'));
  assert.ok(hasExitCode(accepted, 0));
  let after = await contract.getPolicy();
  assert.equal(after.sold, 1n);
  assert.equal(after.inventory, 3n);
  assert.equal(await contract.getIdentityPurchased(first.payload.identityNullifier), 1n);
  assert.equal(await contract.getUsedAction(first.payload.actionNullifier), 1n);
  assert.equal(await contract.getUsedQuery(1), 1n);
  const buyerHash = BigInt(`0x${buyer.address.hash.toString('hex')}`);
  assert.equal(await contract.getRefundCredit(buyerHash), toNano('1.2'));
  console.log('  ✓ valid proof, recipient binding, payment, inventory, and accounted refund credit succeed');

  const replay = await contract.send(buyer.getSender(), first.body, toNano('2'));
  assert.ok(hasExitCode(replay, 276));
  after = await contract.getPolicy();
  assert.equal(after.sold, 1n);
  assert.equal(await contract.getIdentityPurchased(first.payload.identityNullifier), 1n);
  console.log('  ✓ exact action replay fails without state drift');

  const second = await makeProof({
    codeAddress: contract.address,
    launchIdHash,
    recipient: buyer.address,
    clientNonce: '2',
    expiryEpoch: now + 300,
    now,
  });
  const secondAccepted = await contract.send(buyer.getSender(), second.body, toNano('2'));
  assert.ok(hasExitCode(secondAccepted, 0));
  assert.equal(await contract.getIdentityPurchased(first.payload.identityNullifier), 2n);

  const duplicateQuery = await contract.send(
    buyer.getSender(),
    await bodyFromPayload(second.payload, { queryId: '1', recipient: buyer.address }),
    toNano('2'),
  );
  assert.ok(hasExitCode(duplicateQuery, 276));
  assert.equal(await contract.getUsedQuery(1), 1n);
  assert.equal(await contract.getIdentityPurchased(first.payload.identityNullifier), 2n);
  console.log('  ✓ duplicate query IDs fail closed even with a fresh action authorization');
  const third = await makeProof({
    codeAddress: contract.address,
    launchIdHash,
    recipient: buyer.address,
    clientNonce: '3',
    expiryEpoch: now + 300,
    now,
  });
  const cap = await contract.send(buyer.getSender(), third.body, toNano('2'));
  assert.ok(hasExitCode(cap, 277));
  assert.equal(await contract.getIdentityPurchased(first.payload.identityNullifier), 2n);
  console.log('  ✓ changing clientNonce cannot bypass the cumulative identity cap');

  const other = await makeProof({
    codeAddress: contract.address,
    launchIdHash,
    recipient: otherBuyer.address,
    userId: 989898,
    clientNonce: '4',
    expiryEpoch: now + 300,
    now,
  });
  const otherAccepted = await contract.send(otherBuyer.getSender(), other.body, toNano('2'));
  assert.ok(hasExitCode(otherAccepted, 0));
  assert.equal(await contract.getIdentityPurchased(other.payload.identityNullifier), 1n);
  console.log('  ✓ a different identity receives an independent cap');

  const wrongRecipient = await makeProof({
    codeAddress: contract.address,
    launchIdHash,
    recipient: buyer.address,
    clientNonce: '5',
    expiryEpoch: now + 300,
    now,
  });
  const wrongRecipientBody = await bodyFromPayload(wrongRecipient.payload, { queryId: '5', recipient: otherBuyer.address });
  const redirected = await contract.send(buyer.getSender(), wrongRecipientBody, toNano('2'));
  assert.ok(hasExitCode(redirected, 272));
  console.log('  ✓ duplicated recipient fields cannot redirect the actual credited sender');

  const wrongLaunchPayload = mutatedPayload(first.payload, { 8: '778' });
  const wrongLaunchResult = await contract.send(buyer.getSender(), await bodyFromPayload(wrongLaunchPayload, { queryId: '6', recipient: buyer.address }), toNano('2'));
  assert.ok(hasExitCode(wrongLaunchResult, 270));
  console.log('  ✓ cross-launch authorization fails before state mutation');

  const wrongIssuerPayload = mutatedPayload(first.payload, { 7: '1' });
  const wrongIssuerResult = await contract.send(buyer.getSender(), await bodyFromPayload(wrongIssuerPayload, { queryId: '8', recipient: buyer.address }), toNano('2'));
  assert.ok(hasExitCode(wrongIssuerResult, 269));
  const wrongDomainPayload = mutatedPayload(first.payload, { 3: '1' });
  const wrongDomainResult = await contract.send(buyer.getSender(), await bodyFromPayload(wrongDomainPayload, { queryId: '9', recipient: buyer.address }), toNano('2'));
  assert.ok(hasExitCode(wrongDomainResult, 268));
  const wrongLaunchpadPayload = mutatedPayload(first.payload, { 9: '0', 10: '0' });
  const wrongLaunchpadResult = await contract.send(buyer.getSender(), await bodyFromPayload(wrongLaunchpadPayload, { queryId: '10', recipient: buyer.address }), toNano('2'));
  assert.ok(hasExitCode(wrongLaunchpadResult, 271));
  console.log('  ✓ issuer, domain, and executing-address bindings fail closed');

  const wrongPremiumPayload = mutatedPayload(first.payload, { 6: '0' });
  const wrongPremiumResult = await contract.send(buyer.getSender(), await bodyFromPayload(wrongPremiumPayload, { queryId: '11', recipient: buyer.address }), toNano('2'));
  assert.ok(hasExitCode(wrongPremiumResult, 274));
  const wrongFreshnessPayload = mutatedPayload(first.payload, { 5: MAX_AGE - 1 });
  const wrongFreshnessResult = await contract.send(buyer.getSender(), await bodyFromPayload(wrongFreshnessPayload, { queryId: '17', recipient: buyer.address }), toNano('2'));
  assert.ok(hasExitCode(wrongFreshnessResult, 274));
  const staleExpiryPayload = mutatedPayload(first.payload, { 15: now - 1 });
  const staleExpiryResult = await contract.send(buyer.getSender(), await bodyFromPayload(staleExpiryPayload, { queryId: '12', recipient: buyer.address }), toNano('2'));
  assert.ok(hasExitCode(staleExpiryResult, 275));
  const futureTimestampPayload = mutatedPayload(first.payload, { 4: now + 301, 15: now + 600 });
  const futureTimestampResult = await contract.send(buyer.getSender(), await bodyFromPayload(futureTimestampPayload, { queryId: '13', recipient: buyer.address }), toNano('2'));
  assert.ok(hasExitCode(futureTimestampResult, 275));
  console.log('  ✓ Premium and chain-time expiry/future boundaries fail closed');

  const wrongOperationPayload = { ...first.payload, publicSignals: [...first.payload.publicSignals] };
  wrongOperationPayload.publicSignals[11] = '2';
  const wrongOperationResult = await contract.send(buyer.getSender(), await bodyFromPayload(wrongOperationPayload, { queryId: '14', recipient: buyer.address }), toNano('2'));
  assert.ok(hasExitCode(wrongOperationResult, 273));
  const wrongVersionPayload = { ...first.payload, publicSignals: [...first.payload.publicSignals] };
  wrongVersionPayload.publicSignals[16] = '2';
  const wrongVersionResult = await contract.send(buyer.getSender(), await bodyFromPayload(wrongVersionPayload, { queryId: '15', recipient: buyer.address }), toNano('2'));
  assert.ok(hasExitCode(wrongVersionResult, 274));
  console.log('  ✓ operation and circuit-version substitutions are rejected before pairing');

  const insufficient = await contract.send(buyer.getSender(), await bodyFromPayload(first.payload, { queryId: '7', recipient: buyer.address }), toNano('1.01'));
  assert.ok(hasExitCode(insufficient, 279));
  assert.equal((await contract.getPolicy()).sold, 3n);
  console.log('  ✓ insufficient attached value fails closed without consuming inventory');

  const malformedProofBody = await bodyFromPayload(first.payload, { queryId: '16', recipient: buyer.address });
  const malformedProofSlice = malformedProofBody.beginParse();
  malformedProofSlice.loadUint(64);
  malformedProofSlice.loadUint(64);
  malformedProofSlice.loadAddress();
  malformedProofSlice.loadRef();
  const malformedProof = beginCell()
    .storeUint('16', 64)
    .storeUint(1, 64)
    .storeAddress(buyer.address)
    .storeRef(beginCell().endCell())
    .storeRef(malformedProofSlice.loadRef())
    .endCell();
  const malformedProofResult = await contract.send(buyer.getSender(), malformedProof, toNano('2'));
  assert.ok(hasExitCode(malformedProofResult, 258) || hasExitCode(malformedProofResult, 9));
  assert.equal((await contract.getPolicy()).sold, 3n);
  console.log('  ✓ malformed proof cells fail before any accounting mutation');

  const malformed = await contract.send(buyer.getSender(), beginCell().storeUint(1, 64).endCell(), toNano('2'));
  assert.ok(hasExitCode(malformed, 282) || hasExitCode(malformed, 9) || hasExitCode(malformed, 63));
  assert.equal((await contract.getPolicy()).sold, 3n);
  console.log('  ✓ malformed/truncated purchase envelopes cannot mutate state');
}

run().catch((error) => {
  console.error(error);
  process.exit(1);
});
