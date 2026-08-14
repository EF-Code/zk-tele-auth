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
  createdAt: '2026-01-01T00:00:00.000Z',
  reviewReference: 'review-2026-001',
  keyId: 'test-reviewer',
  commit: 'a'.repeat(40),
  manifestDigest: 'b'.repeat(64),
  circuits: { telegram_auth: { files: { 'circuits/telegram_auth.circom': 'c'.repeat(64) } } },
};
const signature = crypto.sign(null, Buffer.from(canonicalJson(payload)), privateKey).toString('base64');
const attestation = { ...payload, signature };
const trust = { schemaVersion: 1, type: 'zk-tele-auth-attestation-trust-policy', keys: [{ keyId: 'test-reviewer', identity: 'test reviewer', publicKey: rawPublic, allowedNetworks: ['testnet'], validFrom: '2025-01-01T00:00:00.000Z', validUntil: '2100-01-01T00:00:00.000Z' }] };
assert.equal(verifyAttestationSignature(attestation, trust), true);
assert.throws(() => verifyAttestationSignature({ ...attestation, commit: 'd'.repeat(40) }, trust), /signature verification failed/);
assert.throws(() => verifyAttestationSignature(attestation, { ...trust, keys: [{ ...trust.keys[0], allowedNetworks: ['mainnet'] }] }), /network is not allowed/);
const futurePayload = { ...payload, createdAt: '2098-01-01T00:00:00.000Z' };
const futureAttestation = { ...futurePayload, signature: crypto.sign(null, Buffer.from(canonicalJson(futurePayload)), privateKey).toString('base64') };
assert.throws(() => verifyAttestationSignature(futureAttestation, trust), /createdAt is in the future/);
assert.equal(typeof canonicalJson(signedAttestationPayload(attestation)), 'string');
console.log('attestation signature tests: passed');
