import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { canonicalJson, signedAttestationPayload, verifyAttestationSignature } from '../scripts/lib/attestation.mjs';

const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const spki = publicKey.export({ format: 'der', type: 'spki' });
const rawPublic = spki.subarray(-32).toString('base64');
const payload = {
  schemaVersion: 1,
  type: 'zk-tele-auth-artifact-attestation',
  status: 'production-approved',
  network: 'testnet',
  expiresAt: '2099-01-01T00:00:00.000Z',
  keyId: 'test-reviewer',
  commit: 'a'.repeat(40),
  manifestDigest: 'b'.repeat(64),
  circuits: { telegram_auth: { files: { 'circuits/telegram_auth.circom': 'c'.repeat(64) } } },
};
const signature = crypto.sign(null, Buffer.from(canonicalJson(payload)), privateKey).toString('base64');
const attestation = { ...payload, signature };
assert.equal(verifyAttestationSignature(attestation, { schemaVersion: 1, keys: [{ keyId: 'test-reviewer', publicKey: rawPublic }] }), true);
assert.throws(() => verifyAttestationSignature({ ...attestation, commit: 'd'.repeat(40) }, { schemaVersion: 1, keys: [{ keyId: 'test-reviewer', publicKey: rawPublic }] }), /signature verification failed/);
assert.equal(typeof canonicalJson(signedAttestationPayload(attestation)), 'string');
console.log('attestation signature tests: passed');
