import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';

function canonicalJson(value: unknown): string {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('non-finite attestation number');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (typeof value === 'object' && value !== null) {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson((value as Record<string, unknown>)[key])}`).join(',')}}`;
  }
  throw new Error('unsupported attestation value');
}

function sha256(file: string): string {
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

function publicKey(rawBase64: string): crypto.KeyObject {
  const raw = Buffer.from(rawBase64, 'base64');
  if (raw.length !== 32) throw new Error('trusted Ed25519 key must be 32 bytes');
  return crypto.createPublicKey({
    key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), raw]),
    format: 'der',
    type: 'spki',
  });
}

function signaturePayload(attestation: Record<string, unknown>): Record<string, unknown> {
  const payload = structuredClone(attestation);
  delete payload.signature;
  return payload;
}

/**
 * Production gateways refuse development artifacts unless an explicit
 * non-production override is enabled. The release preflight remains the
 * authoritative release gate; this check prevents a misconfigured server from
 * advertising readiness with a development proving key.
 */
export function assertArtifactReadiness(options: {
  artifactsDir?: string;
  allowDevelopmentArtifacts: boolean;
  requiredCircuits?: string[];
}): { status: 'development-only' | 'production-approved'; manifestDigest?: string } {
  const artifactsDir = options.artifactsDir || path.resolve(process.cwd(), 'artifacts');
  const manifestPath = path.join(artifactsDir, 'manifest.json');
  if (!fs.existsSync(manifestPath)) throw new Error(`missing artifact manifest: ${manifestPath}`);
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8')) as Record<string, any>;
  if (manifest.schemaVersion !== 2 || manifest.type !== 'zk-tele-auth-artifact-manifest') throw new Error('artifact manifest schema is invalid');
  const circuits = options.requiredCircuits || ['telegram_auth'];
  const manifestDigest = sha256(manifestPath);
  if (manifest.status === 'development-only') {
    if (!options.allowDevelopmentArtifacts) throw new Error('development proving artifacts are not allowed');
    return { status: 'development-only', manifestDigest };
  }
  if (manifest.status !== 'production-approved') throw new Error('artifact manifest has an unsupported status');
  const attestationPath = path.join(artifactsDir, 'production-attestation.json');
  const trustPath = path.resolve(process.cwd(), 'config', 'attestation-trust.json');
  if (!fs.existsSync(attestationPath) || !fs.existsSync(trustPath)) throw new Error('production attestation or trust policy is missing');
  const attestation = JSON.parse(fs.readFileSync(attestationPath, 'utf8')) as Record<string, any>;
  const trust = JSON.parse(fs.readFileSync(trustPath, 'utf8')) as Record<string, any>;
  const trusted = trust.keys?.find((key: any) => key.keyId === attestation.keyId);
  if (!trusted || trusted.revoked === true) throw new Error('production attestation signer is not trusted');
  if (trust.schemaVersion !== 1 || trust.type !== 'zk-tele-auth-attestation-trust-policy') throw new Error('attestation trust policy schema is invalid');
  if (typeof trusted.identity !== 'string' || !Array.isArray(trusted.allowedNetworks) || !trusted.allowedNetworks.includes(attestation.network)) throw new Error('production attestation signer identity/network is not approved');
  if (typeof trusted.validFrom !== 'string' || typeof trusted.validUntil !== 'string' || Date.parse(trusted.validFrom) > Date.parse(String(attestation.createdAt || '')) || Date.parse(String(attestation.createdAt || '')) > Date.parse(trusted.validUntil)) throw new Error('production attestation is outside signer validity window');
  if (Date.parse(String(attestation.createdAt || '')) > Date.now() + 300_000) throw new Error('production attestation createdAt is in the future');
  if (!/^[0-9a-f]{40}$/i.test(String(attestation.commit || '')) || !/^[0-9a-f]{64}$/i.test(String(attestation.manifestDigest || ''))) throw new Error('production attestation commit/digest is malformed');
  if (typeof attestation.reviewReference !== 'string' || !attestation.reviewReference || attestation.reviewReference.includes('PENDING')) throw new Error('production attestation review reference is missing');
  if (attestation.schemaVersion !== 1 || attestation.type !== 'zk-tele-auth-artifact-attestation' || attestation.status !== 'production-approved') throw new Error('production attestation metadata is invalid');
  if (typeof attestation.expiresAt !== 'string' || Date.parse(attestation.expiresAt) <= Date.now()) throw new Error('production attestation is expired or missing expiresAt');
  const signature = Buffer.from(String(attestation.signature || ''), 'base64');
  if (signature.length !== 64 || !crypto.verify(null, Buffer.from(canonicalJson(signaturePayload(attestation))), publicKey(trusted.publicKey), signature)) {
    throw new Error('production attestation signature is invalid');
  }
  if (attestation.manifestDigest !== sha256(manifestPath)) throw new Error('production attestation manifest digest mismatch');
  for (const circuit of circuits) {
    if (manifest.circuits?.[circuit]?.status !== 'production-approved') throw new Error(`circuit is not production-approved: ${circuit}`);
    const manifestFiles = manifest.circuits[circuit].files;
    const attestedFiles = attestation.circuits?.[circuit]?.files;
    if (!manifestFiles || !attestedFiles || canonicalJson(manifestFiles) !== canonicalJson(attestedFiles)) throw new Error(`production attestation file hashes mismatch: ${circuit}`);
    const runtimeFiles = manifest.circuits[circuit].runtimeFiles || manifestFiles;
    for (const [relativePath, expected] of Object.entries(runtimeFiles)) {
      const file = path.resolve(process.cwd(), relativePath);
      if (!file.startsWith(`${path.resolve(process.cwd())}${path.sep}`) || !fs.existsSync(file)) throw new Error(`attested artifact is missing: ${relativePath}`);
      if (sha256(file) !== expected) throw new Error(`attested artifact hash mismatch: ${relativePath}`);
    }
  }
  return { status: 'production-approved', manifestDigest: attestation.manifestDigest };
}
