import * as assert from 'node:assert';
import * as crypto from 'node:crypto';
import * as snarkjs from 'snarkjs';
import {
  BLS12_381_SCALAR_FIELD,
  CryptoUtils,
  buildTonVerifierStateInitData,
  InitDataParser,
  NullifierDeriver,
  PrivaPurchaseAuthProofGenerator,
  PrivaPurchaseAuthProofVerifier,
  ZkAuthProofGenerator,
  ZkAuthProofVerifier,
  generateMembershipProof,
  poseidonHash,
  resolveArtifacts,
  verifyMembershipProof,
} from '../dist/sdk/index.js';
import { ZkTeleAuthGateway } from '../dist/gateway/server.js';
import { poseidon2 } from 'poseidon-bls12381';

let passed = 0;
let failed = 0;

function test(name, fn) {
  return Promise.resolve()
    .then(fn)
    .then(() => {
      passed++;
      console.log(`  ✓ ${name}`);
    })
    .catch((err) => {
      failed++;
      console.error(`  ✗ ${name}\n    ${err.message}`);
    });
}

function signedInitData(botToken, user, authDate) {
  const params = new URLSearchParams();
  params.set('query_id', 'AAHdF6IQAAAAAN0XohDhrOrc');
  params.set('user', JSON.stringify(user));
  params.set('auth_date', String(authDate));
  const dataCheck = [...params.entries()]
    .map(([key, value]) => `${key}=${value}`)
    .sort()
    .join('\n');
  const secretKey = CryptoUtils.hmacSha256('WebAppData', botToken);
  params.set('hash', CryptoUtils.hmacSha256Hex(secretKey, dataCheck));
  return params.toString();
}

async function run() {
  console.log('zk-tele-auth security regression tests\n');

  const now = Math.floor(Date.now() / 1000);
  const DOMAIN = 'dapp.zk-tele-auth.io';
  const ISSUER_SECRET = '1892374981273498127349812734981273498';
  const OTHER_ISSUER_SECRET = '9823749812734981273498127349812734981';
  const ISSUER_KEY_HASH = await NullifierDeriver.deriveIssuerKeyHash(ISSUER_SECRET);
  const MAX_AGE = 24 * 60 * 60;
  const policy = (overrides = {}) => ({
    expectedAppDomain: DOMAIN,
    expectedIssuerKeyHash: ISSUER_KEY_HASH,
    maxTokenAgeSec: MAX_AGE,
    requirePremium: true,
    ...overrides,
  });
  const proofInputs = (overrides = {}) => ({
    userId: 987654321,
    authDate: now - 300,
    isPremium: true,
    appDomain: DOMAIN,
    currentTimestamp: now,
    maxTokenAgeSec: MAX_AGE,
    isPremiumRequired: true,
    issuerSecret: ISSUER_SECRET,
    ...overrides,
  });
  const privaInputs = (overrides = {}) => ({
    ...proofInputs(),
    launchIdHash: '101',
    launchpadAddressHash: '202',
    recipientHash: '303',
    clientNonce: '404',
    expiryEpoch: now + 300,
    circuitVersion: 1,
    ...overrides,
  });
  const privaPolicy = (overrides = {}) => ({
    ...policy(),
    expectedLaunchIdHash: '101',
    expectedLaunchpadAddressHash: '202',
    expectedRecipientHash: '303',
    maxAuthorizationTtlSec: 300,
    expectedCircuitVersion: 1,
    ...overrides,
  });

  await test('nullifier is stable for an issuer/user/domain tuple', async () => {
    const a = await NullifierDeriver.deriveNullifier(987654321, DOMAIN, ISSUER_SECRET);
    const b = await NullifierDeriver.deriveNullifier(987654321, DOMAIN, ISSUER_SECRET);
    assert.strictEqual(a, b);
  });

  await test('nullifier changes across domains', async () => {
    const a = await NullifierDeriver.deriveNullifier(987654321, DOMAIN, ISSUER_SECRET);
    const b = await NullifierDeriver.deriveNullifier(987654321, 'other.example', ISSUER_SECRET);
    assert.notStrictEqual(a, b);
  });

  await test('nullifier changes across issuers', async () => {
    const a = await NullifierDeriver.deriveNullifier(987654321, DOMAIN, ISSUER_SECRET);
    const b = await NullifierDeriver.deriveNullifier(987654321, DOMAIN, OTHER_ISSUER_SECRET);
    assert.notStrictEqual(a, b);
  });

  await test('issuer commitment changes with the private issuer secret', async () => {
    const other = await NullifierDeriver.deriveIssuerKeyHash(OTHER_ISSUER_SECRET);
    assert.notStrictEqual(ISSUER_KEY_HASH, other);
  });

  await test('domain hashing is canonical', async () => {
    assert.strictEqual(
      await NullifierDeriver.hashAppDomain('  DApp.ZK-Tele-Auth.IO '),
      await NullifierDeriver.hashAppDomain(DOMAIN)
    );
  });

  await test('Poseidon-2 matches the pinned BLS12-381 reference vector', () => {
    assert.strictEqual(
      poseidonHash([1n, 2n]),
      '28821147804331559602169231704816259064962739503761913593647409715501647586810'
    );
  });

  await test('initData parsing extracts user and auth_date', () => {
    const query = signedInitData('123:token', { id: 987654321, is_premium: true }, now);
    const { raw, user } = InitDataParser.parse(query);
    assert.strictEqual(raw.auth_date, now);
    assert.strictEqual(user.id, 987654321);
    assert.strictEqual(user.is_premium, true);
  });

  await test('constant-time initData validation accepts valid HMAC and rejects tampering', () => {
    const botToken = '123456789:AAHdF6IQAAAAAN0XohDhrOrc';
    const query = signedInitData(botToken, { id: 987654321, is_premium: true }, now);
    assert.strictEqual(InitDataParser.validateSignature(query, botToken), true);
    assert.strictEqual(InitDataParser.validateSignature(query.replace('987654321', '987654322'), botToken), false);
    assert.strictEqual(InitDataParser.validateSignature(`${query.slice(0, -1)}z`, botToken), false);
  });

  await test('random issuer secrets are valid positive decimal field elements', () => {
    const secret = CryptoUtils.randomFieldSecret();
    assert.match(secret, /^[1-9][0-9]*$/);
    assert.ok(BigInt(secret) < 2n ** 254n);
  });

  let acceptedPayload;
  await test('authorized issuer generates a real Groth16 Premium proof', async () => {
    acceptedPayload = await ZkAuthProofGenerator.generateProof(proofInputs());
    assert.strictEqual(acceptedPayload.publicSignals.length, 7);
    assert.strictEqual(acceptedPayload.issuerKeyHash, ISSUER_KEY_HASH);
    assert.strictEqual(acceptedPayload.isPremiumRequired, true);
    assert.strictEqual(acceptedPayload.isVerified, true);
  });

  await test('verifier accepts proof only under pinned issuer and policy', async () => {
    const result = await ZkAuthProofVerifier.verifyProof(acceptedPayload, policy());
    assert.strictEqual(result.isValid, true);
    assert.strictEqual(result.issuerKeyHash, ISSUER_KEY_HASH);
  });

  await test('proof from an unauthorized issuer is rejected', async () => {
    const attackerProof = await ZkAuthProofGenerator.generateProof(
      proofInputs({ issuerSecret: OTHER_ISSUER_SECRET, userId: 42 })
    );
    const result = await ZkAuthProofVerifier.verifyProof(attackerProof, policy());
    assert.strictEqual(result.isValid, false);
    assert.match(result.error, /issuerKeyHash/);
  });

  await test('same account receives the same nullifier across fresh proofs', async () => {
    const second = await ZkAuthProofGenerator.generateProof(proofInputs({ currentTimestamp: now + 1 }));
    assert.strictEqual(acceptedPayload.nullifierHash, second.nullifierHash);
  });

  await test('wrong app domain is rejected', async () => {
    const result = await ZkAuthProofVerifier.verifyProof(
      acceptedPayload,
      policy({ expectedAppDomain: 'attacker.example' })
    );
    assert.strictEqual(result.isValid, false);
    assert.match(result.error, /appDomainHash/);
  });

  await test('prover-selected age policy is rejected', async () => {
    const proof = await ZkAuthProofGenerator.generateProof(
      proofInputs({ maxTokenAgeSec: 2 * MAX_AGE })
    );
    const result = await ZkAuthProofVerifier.verifyProof(proof, policy());
    assert.strictEqual(result.isValid, false);
    assert.match(result.error, /maxTokenAgeSec/);
  });

  await test('Premium policy downgrade is rejected', async () => {
    const proof = await ZkAuthProofGenerator.generateProof(
      proofInputs({ isPremiumRequired: false })
    );
    const result = await ZkAuthProofVerifier.verifyProof(proof, policy());
    assert.strictEqual(result.isValid, false);
    assert.match(result.error, /isPremiumRequired/);
  });

  await test('non-Premium witness cannot satisfy a Premium-required proof', async () => {
    await assert.rejects(
      ZkAuthProofGenerator.generateProof(proofInputs({ userId: 12345, isPremium: false })),
      /Assert Failed/
    );
  });

  await test('stale proof is rejected using verifier-pinned age', async () => {
    const staleNow = now - 48 * 60 * 60;
    const proof = await ZkAuthProofGenerator.generateProof(
      proofInputs({ authDate: staleNow - 300, currentTimestamp: staleNow })
    );
    const result = await ZkAuthProofVerifier.verifyProof(proof, policy());
    assert.strictEqual(result.isValid, false);
    assert.match(result.error, /expired/);
  });

  await test('tampered Groth16 proof is rejected without throwing', async () => {
    const tampered = structuredClone(acceptedPayload);
    tampered.proof.pi_a[0] = '0xdeadbeef';
    const result = await ZkAuthProofVerifier.verifyProof(tampered, policy());
    assert.strictEqual(result.isValid, false);
  });

  await test('gateway validates signed initData and emits issuer-bound proof', async () => {
    const botToken = '123456789:AAHdF6IQAAAAAN0XohDhrOrc';
    const gateway = new ZkTeleAuthGateway({
      botToken,
      issuerSecret: ISSUER_SECRET,
      appDomain: DOMAIN,
      maxTokenAgeSec: MAX_AGE,
      requirePremium: true,
    });
    const query = signedInitData(botToken, { id: 778899, is_premium: true }, now);
    const result = await gateway.handleAuthenticate(query);
    assert.strictEqual(result.success, true);
    assert.strictEqual(result.proofPayload.issuerKeyHash, ISSUER_KEY_HASH);
  });

  await test('gateway rejects expired initData before proving', async () => {
    const botToken = '123456789:AAHdF6IQAAAAAN0XohDhrOrc';
    const gateway = new ZkTeleAuthGateway({
      botToken,
      issuerSecret: ISSUER_SECRET,
      appDomain: DOMAIN,
      maxTokenAgeSec: 60,
    });
    const query = signedInitData(botToken, { id: 778899 }, now - 61);
    await assert.rejects(gateway.handleAuthenticate(query), /expired/);
  });

  await test('gateway emits a Priva-bound purchase authorization', async () => {
    const botToken = '123456789:AAHdF6IQAAAAAN0XohDhrOrc';
    const gateway = new ZkTeleAuthGateway({ botToken, issuerSecret: ISSUER_SECRET, appDomain: DOMAIN });
    const query = signedInitData(botToken, { id: 778900 }, now);
    const result = await gateway.handlePrivaPurchaseAuthorization(query, {
      launchIdHash: '101', launchpadAddressHash: '202', recipientHash: '303',
      clientNonce: '404', expiryEpoch: now + 60, operation: 'BUY', circuitVersion: 1,
    });
    assert.strictEqual(result.success, true);
    assert.strictEqual(result.proofPayload.recipientHash, '303');
  });

  await test('gateway rejects a Priva authorization with a non-BUY operation', async () => {
    const botToken = '123456789:AAHdF6IQAAAAAN0XohDhrOrc';
    const gateway = new ZkTeleAuthGateway({ botToken, issuerSecret: ISSUER_SECRET, appDomain: DOMAIN });
    const query = signedInitData(botToken, { id: 778901 }, now);
    await assert.rejects(
      gateway.handlePrivaPurchaseAuthorization(query, {
        launchIdHash: '101', launchpadAddressHash: '202', recipientHash: '303',
        clientNonce: '404', expiryEpoch: now + 60, operation: 'SELL',
      }),
      /only BUY/
    );
  });

  let privaPayload;
  await test('Priva purchase proof binds a stable identity and one-time action', async () => {
    privaPayload = await PrivaPurchaseAuthProofGenerator.generateProof(privaInputs());
    assert.strictEqual(privaPayload.publicSignals.length, 15);
    assert.strictEqual(privaPayload.isAuthorized, true);
    assert.strictEqual(privaPayload.launchIdHash, '101');
    assert.strictEqual(privaPayload.recipientHash, '303');
    assert.strictEqual(privaPayload.operation, 1);
  });

  await test('Priva verifier accepts only the exact pinned action policy', async () => {
    const result = await PrivaPurchaseAuthProofVerifier.verifyProof(privaPayload, privaPolicy());
    assert.strictEqual(result.isValid, true);
    assert.strictEqual(result.nullifierHash, privaPayload.identityNullifier);
  });

  await test('Priva action nonce changes action nullifier but not identity nullifier', async () => {
    const next = await PrivaPurchaseAuthProofGenerator.generateProof(privaInputs({ clientNonce: '405' }));
    assert.strictEqual(next.identityNullifier, privaPayload.identityNullifier);
    assert.notStrictEqual(next.actionNullifier, privaPayload.actionNullifier);
  });

  await test('Priva verifier rejects a recipient-redirection policy mismatch', async () => {
    const result = await PrivaPurchaseAuthProofVerifier.verifyProof(
      privaPayload,
      privaPolicy({ expectedRecipientHash: '304' })
    );
    assert.strictEqual(result.isValid, false);
    assert.match(result.error, /recipientHash/);
  });

  await test('Priva verifier rejects a cross-launch policy mismatch', async () => {
    const result = await PrivaPurchaseAuthProofVerifier.verifyProof(
      privaPayload,
      privaPolicy({ expectedLaunchIdHash: '102' })
    );
    assert.strictEqual(result.isValid, false);
    assert.match(result.error, /launchIdHash/);
  });

  await test('Priva circuit rejects an expired authorization witness', async () => {
    await assert.rejects(
      PrivaPurchaseAuthProofGenerator.generateProof(privaInputs({ expiryEpoch: now - 1 })),
      /expiryEpoch/
    );
  });

  await test('TON StateInit data commits domain, issuer and verifier policy', async () => {
    const appDomainHash = await NullifierDeriver.hashAppDomain(DOMAIN);
    const data = buildTonVerifierStateInitData({
      appDomainHash,
      issuerKeyHash: ISSUER_KEY_HASH,
      maxTokenAgeSec: MAX_AGE,
      requirePremium: true,
    }).beginParse();
    assert.strictEqual(data.loadUintBig(256).toString(), appDomainHash);
    assert.strictEqual(data.loadUintBig(256).toString(), ISSUER_KEY_HASH);
    assert.strictEqual(data.loadUint(32), MAX_AGE);
    assert.strictEqual(data.loadUint(8), 1);
    assert.strictEqual(data.loadUintBig(64), 0n);
    assert.strictEqual(data.loadBit(), false);
    data.endParse();
  });

  const DEPTH = 12;
  async function buildPath(leaf, pathIndices) {
    const pathElements = [];
    let current = BigInt(leaf);
    for (let i = 0; i < DEPTH; i++) {
      const sibling = crypto.randomBytes(8).readBigUInt64LE() + 1n;
      pathElements.push(sibling.toString());
      current = pathIndices[i] === 1 ? poseidon2([sibling, current]) : poseidon2([current, sibling]);
    }
    return { root: current.toString(), pathElements };
  }

  await test('membership proof keeps leaf private and pins the expected root', async () => {
    const leaf = poseidonHash([987654321n, BigInt(ISSUER_SECRET)]);
    const pathIndices = Array.from({ length: DEPTH }, (_, index) => (index + 1) % 2);
    const { root, pathElements } = await buildPath(leaf, pathIndices);
    const proof = await generateMembershipProof({ leaf, root, pathElements, pathIndices });
    assert.deepStrictEqual(proof.publicSignals, ['1', root]);
    assert.ok(!proof.publicSignals.includes(leaf));
    assert.strictEqual((await verifyMembershipProof(proof, root)).isValid, true);
    assert.strictEqual((await verifyMembershipProof(proof, String(BigInt(root) + 1n))).isValid, false);
  });

  await test('wrong membership root is unsatisfiable rather than a valid negative proof', async () => {
    const leaf = poseidonHash([111n, BigInt(ISSUER_SECRET)]);
    const pathIndices = Array.from({ length: DEPTH }, () => 0);
    const { root, pathElements } = await buildPath(leaf, pathIndices);
    await assert.rejects(
      generateMembershipProof({
        leaf,
        root: String(BigInt(root) + 1n),
        pathElements,
        pathIndices,
      }),
      /Assert Failed/
    );
  });

  await test('membership circuit itself rejects non-binary path selectors', async () => {
    const modulo = (value) => {
      const reduced = value % BLS12_381_SCALAR_FIELD;
      return reduced < 0n ? reduced + BLS12_381_SCALAR_FIELD : reduced;
    };
    const leaf = 123456n;
    const pathIndices = [2n, ...Array.from({ length: DEPTH - 1 }, () => 0n)];
    const pathElements = Array.from({ length: DEPTH }, (_, index) => BigInt(index + 900));
    let current = leaf;
    for (let i = 0; i < DEPTH; i++) {
      const selector = pathIndices[i];
      const sibling = pathElements[i];
      const left = modulo(current + (sibling - current) * selector);
      const right = modulo(sibling + (current - sibling) * selector);
      current = poseidon2([left, right]);
    }
    const { wasm, zkey } = await resolveArtifacts('membership');
    await assert.rejects(
      snarkjs.groth16.fullProve(
        {
          leaf: leaf.toString(),
          root: current.toString(),
          pathElements: pathElements.map(String),
          pathIndices: pathIndices.map(String),
        },
        wasm,
        zkey
      ),
      /Assert Failed/
    );
  });

  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed === 0 ? 0 : 1);
}

run().catch((err) => {
  console.error(err);
  process.exit(1);
});
