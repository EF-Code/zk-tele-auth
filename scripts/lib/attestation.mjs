import crypto from 'node:crypto';

/**
 * Canonical JSON used for release attestations. Object keys are sorted and
 * insignificant whitespace is removed; arrays retain their declared order.
 * The format is intentionally small so it can be reproduced by non-Node
 * release tooling.
 */
export function canonicalJson(value) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('attestation contains a non-finite number');
    return JSON.stringify(value);
  }
  if (typeof value === 'bigint') throw new Error('attestation cannot contain bigint values');
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  throw new Error(`unsupported attestation value type: ${typeof value}`);
}

export function signedAttestationPayload(attestation) {
  if (!attestation || typeof attestation !== 'object' || Array.isArray(attestation)) {
    throw new Error('attestation must be an object');
  }
  const payload = structuredClone(attestation);
  delete payload.signature;
  return payload;
}

function ed25519PublicKey(rawBase64) {
  const raw = Buffer.from(rawBase64, 'base64');
  if (raw.length !== 32) throw new Error('Ed25519 public keys must contain exactly 32 bytes');
  // SubjectPublicKeyInfo prefix for an Ed25519 public key.
  const spkiPrefix = Buffer.from('302a300506032b6570032100', 'hex');
  return crypto.createPublicKey({ key: Buffer.concat([spkiPrefix, raw]), format: 'der', type: 'spki' });
}

export function verifyAttestationSignature(attestation, trustedKeys) {
  if (attestation?.schemaVersion !== 1) throw new Error('unsupported attestation schema');
  if (attestation?.type !== 'zk-tele-auth-artifact-attestation') throw new Error('unsupported attestation type');
  if (attestation?.status !== 'production-approved') throw new Error('attestation is not production-approved');
  if (typeof attestation.keyId !== 'string' || !attestation.keyId) throw new Error('attestation keyId is required');
  if (typeof attestation.signature !== 'string' || !attestation.signature) throw new Error('attestation signature is required');
  const trusted = trustedKeys?.keys?.find((key) => key?.keyId === attestation.keyId);
  if (!trusted || trusted.revoked === true) throw new Error(`attestation signer is not trusted: ${attestation.keyId}`);
  if (trustedKeys?.schemaVersion !== 1 || trustedKeys?.type !== 'zk-tele-auth-attestation-trust-policy') throw new Error('unsupported attestation trust policy');
  if (typeof trusted.identity !== 'string' || trusted.identity.length < 3) throw new Error('trusted attestation signer identity is required');
  if (!Array.isArray(trusted.allowedNetworks) || trusted.allowedNetworks.length === 0 || !trusted.allowedNetworks.includes(attestation.network)) throw new Error('attestation network is not allowed for signer');
  if (typeof trusted.validFrom !== 'string' || Number.isNaN(Date.parse(trusted.validFrom)) || typeof trusted.validUntil !== 'string' || Number.isNaN(Date.parse(trusted.validUntil))) throw new Error('trusted attestation key validity window is malformed');
  const createdAt = Date.parse(String(attestation.createdAt || ''));
  if (Number.isNaN(createdAt) || createdAt < Date.parse(trusted.validFrom) || createdAt > Date.parse(trusted.validUntil)) throw new Error('attestation createdAt is outside signer validity window');
  if (createdAt > Date.now() + 300_000) throw new Error('attestation createdAt is in the future');
  if (typeof attestation.commit !== 'string' || !/^[0-9a-f]{40}$/i.test(attestation.commit)) throw new Error('attestation commit is malformed');
  if (typeof attestation.manifestDigest !== 'string' || !/^[0-9a-f]{64}$/i.test(attestation.manifestDigest)) throw new Error('attestation manifest digest is malformed');
  if (typeof attestation.reviewReference !== 'string' || !attestation.reviewReference || attestation.reviewReference.includes('PENDING')) throw new Error('attestation review reference is required');
  if (typeof trusted.publicKey !== 'string') throw new Error('trusted attestation key has no public key');
  const signature = Buffer.from(attestation.signature, 'base64');
  if (signature.length !== 64) throw new Error('Ed25519 signatures must contain exactly 64 bytes');
  const publicKey = ed25519PublicKey(trusted.publicKey);
  const valid = crypto.verify(null, Buffer.from(canonicalJson(signedAttestationPayload(attestation))), publicKey, signature);
  if (!valid) throw new Error('attestation signature verification failed');
  if (typeof attestation.expiresAt !== 'string' || Number.isNaN(Date.parse(attestation.expiresAt))) throw new Error('attestation expiresAt is required');
  if (Date.parse(attestation.expiresAt) <= Date.now()) throw new Error('attestation has expired');
  if (Date.parse(attestation.expiresAt) > Date.parse(trusted.validUntil)) throw new Error('attestation expires after signer validity');
  return true;
}

export function sha256File(file, fs) {
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}
