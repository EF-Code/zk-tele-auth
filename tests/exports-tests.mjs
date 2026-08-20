import assert from 'node:assert/strict';

const stable = await import('../dist/sdk/index.js');
const ton = await import('../dist/sdk/ton.js');
const client = await import('../dist/client/index.js');
const experimental = await import('../dist/sdk/experimental/priva.js');

assert.equal(typeof stable.ZkAuthProofGenerator, 'function');
assert.equal(typeof stable.ZkAuthProofVerifier, 'function');
assert.equal(typeof ton.buildTonVerifierTonConnectTransaction, 'function');
assert.equal(typeof client.ZkTeleAuthClient, 'function');
assert.equal(typeof experimental.PrivaPurchaseAuthProofGenerator, 'function');
for (const name of Object.keys(stable)) {
  assert.equal(name.startsWith('Priva'), false, `stable root leaked experimental export ${name}`);
  assert.equal(name.includes('Launchpad'), false, `stable root leaked launchpad export ${name}`);
}

console.log('package export boundary tests: passed');
