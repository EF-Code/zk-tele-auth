import * as assert from 'node:assert';
import * as crypto from 'node:crypto';
import * as snarkjs from 'snarkjs';
import { poseidon2 } from 'poseidon-bls12381';
import {
  NullifierDeriver,
  CryptoUtils,
  InitDataParser,
  ZkAuthProofGenerator,
  ZkAuthProofVerifier,
  resolveArtifacts,
  loadVerificationKey,
  poseidonHash,
} from '../dist/sdk/index.js';

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

function sha256(s) {
  return crypto.createHash('sha256').update(s).digest('hex');
}

async function run() {
  console.log('zk-tele-auth unit tests\n');

  await test('nullifier is deterministic for (user, domain, salt)', async () => {
    const a = await NullifierDeriver.deriveNullifier(987654321, 'dapp.io', '123456789');
    const b = await NullifierDeriver.deriveNullifier(987654321, 'dapp.io', '123456789');
    assert.strictEqual(a, b);
  });

  await test('nullifier changes across domains (unlinkability)', async () => {
    const a = await NullifierDeriver.deriveNullifier(987654321, 'dapp.io', '123456789');
    const b = await NullifierDeriver.deriveNullifier(987654321, 'other.io', '123456789');
    assert.notStrictEqual(a, b);
  });

  await test('nullifier changes across salts', async () => {
    const a = await NullifierDeriver.deriveNullifier(987654321, 'dapp.io', '123456789');
    const b = await NullifierDeriver.deriveNullifier(987654321, 'dapp.io', '987654321');
    assert.notStrictEqual(a, b);
  });

  await test('domain hashing is canonical', async () => {
    const a = await NullifierDeriver.hashAppDomain('  MyDapp.IO ');
    const b = await NullifierDeriver.hashAppDomain('mydapp.io');
    assert.strictEqual(a, b);
  });

  await test('BLS12-381 Poseidon-2 matches the reference circuit constant', () => {
    assert.strictEqual(poseidonHash([1n, 2n]), '28821147804331559602169231704816259064962739503761913593647409715501647586810');
  });

  await test('BLS12-381 Poseidon output stays inside the scalar field', () => {
    const out = poseidonHash([12345678901234567890n, 42n, 7n]);
    const Fr = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001n;
    assert.ok(BigInt(out) < Fr);
  });

  await test('initData parse extracts user and auth_date', () => {
    const q = 'auth_date=1620000000&query_id=AAHdF6IQAAAAAN0XohDhrOrc&user=%7B%22id%22%3A987654321%2C%22is_premium%22%3Atrue%7D&hash=abc';
    const { user, raw } = InitDataParser.parse(q);
    assert.strictEqual(user.id, 987654321);
    assert.strictEqual(user.is_premium, true);
    assert.strictEqual(raw.auth_date, 1620000000);
  });

  await test('initData HMAC validation accepts a correctly signed payload', () => {
    const botToken = '123456789:AAHdF6IQAAAAAN0XohDhrOrc';
    const params = new URLSearchParams();
    params.set('query_id', 'AAHdF6IQAAAAAN0XohDhrOrc');
    params.set('user', JSON.stringify({ id: 987654321, is_premium: true }));
    params.set('auth_date', '1620000000');

    const dataCheck = [...params.entries()]
      .map(([k, v]) => `${k}=${v}`)
      .sort()
      .join('\n');
    const secretKey = CryptoUtils.hmacSha256('WebAppData', botToken);
    const hash = CryptoUtils.hmacSha256Hex(secretKey, dataCheck);
    params.set('hash', hash);

    assert.strictEqual(InitDataParser.validateSignature(params.toString(), botToken), true);
  });

  await test('initData HMAC validation rejects a tampered payload', () => {
    const botToken = '123456789:AAHdF6IQAAAAAN0XohDhrOrc';
    const q = 'query_id=AAHdF6IQAAAAAN0XohDhrOrc&auth_date=1620000000&user=%7B%22id%22%3A987654321%7D&hash=deadbeef';
    assert.strictEqual(InitDataParser.validateSignature(q, botToken), false);
  });

  await test('random salt is a valid field-sized decimal string', () => {
    const s = CryptoUtils.randomSalt();
    assert.ok(/^[0-9]+$/.test(s));
    assert.ok(BigInt(s) < 2n ** 254n);
  });

  // ---- real proof tests (require artifacts; run `npm run setup:circuits`) ----

  const now = Math.floor(Date.now() / 1000);
  const DOMAIN = 'dapp.zk-tele-auth.io';

  await test('generate a real Groth16 proof for a premium user', async () => {
    const payload = await ZkAuthProofGenerator.generateProof({
      userId: 987654321,
      authDate: now - 300,
      isPremium: true,
      appDomain: DOMAIN,
      currentTimestamp: now,
    });
    assert.ok(payload.proof.pi_a.length === 3);
    assert.ok(payload.publicSignals.length === 6);
    assert.strictEqual(payload.isVerified, true);
    assert.strictEqual(payload.maxTokenAgeSec, 24 * 60 * 60);
  });

  await test('verify the generated proof locally (pairing check)', async () => {
    const payload = await ZkAuthProofGenerator.generateProof({
      userId: 987654321,
      authDate: now - 300,
      isPremium: true,
      appDomain: DOMAIN,
      currentTimestamp: now,
    });
    const result = await ZkAuthProofVerifier.verifyProof(payload, DOMAIN);
    assert.strictEqual(result.isValid, true);
    assert.strictEqual(result.nullifierHash, payload.nullifierHash);
  });

  await test('proof fails for the wrong app domain', async () => {
    const payload = await ZkAuthProofGenerator.generateProof({
      userId: 987654321,
      authDate: now - 300,
      isPremium: true,
      appDomain: DOMAIN,
      currentTimestamp: now,
    });
    const result = await ZkAuthProofVerifier.verifyProof(payload, 'attacker.example');
    assert.strictEqual(result.isValid, false);
    assert.match(result.error, /appDomainHash/);
  });

  await test('proof fails when the SNARK is tampered', async () => {
    const payload = await ZkAuthProofGenerator.generateProof({
      userId: 987654321,
      authDate: now - 300,
      isPremium: true,
      appDomain: DOMAIN,
      currentTimestamp: now,
    });
    payload.proof.pi_a[0] = '0xdeadbeef';
    const result = await ZkAuthProofVerifier.verifyProof(payload, DOMAIN);
    assert.strictEqual(result.isValid, false);
  });

  await test('proof fails when stale (outside maxTokenAgeSec)', async () => {
    const staleNow = now - 48 * 60 * 60;
    const payload = await ZkAuthProofGenerator.generateProof({
      userId: 987654321,
      authDate: staleNow - 300,
      isPremium: true,
      appDomain: DOMAIN,
      currentTimestamp: staleNow,
      maxTokenAgeSec: 24 * 60 * 60,
    });
    const result = await ZkAuthProofVerifier.verifyProof(payload, DOMAIN);
    assert.strictEqual(result.isValid, false);
    assert.match(result.error, /expired|future|skew/);
  });

  await test('proof honors the premium requirement (non-premium user rejected)', async () => {
    await assert.rejects(
      ZkAuthProofGenerator.generateProof({
        userId: 12345,
        authDate: now - 300,
        isPremium: false,
        appDomain: DOMAIN,
        currentTimestamp: now,
        isPremiumRequired: true,
      }),
      /Assert Failed/
    );
  });

  await test('circuit nullifier matches SDK Poseidon derivation', async () => {
    const salt = CryptoUtils.randomSalt();
    const payload = await ZkAuthProofGenerator.generateProof({
      userId: 555666777,
      authDate: now - 300,
      isPremium: true,
      appDomain: DOMAIN,
      currentTimestamp: now,
      salt,
    });
    const expected = await NullifierDeriver.deriveNullifier(555666777, DOMAIN, salt);
    assert.strictEqual(payload.nullifierHash, expected);
  });

  // ---- Merkle membership proof (real circuit `membership`, depth 12) ----

  const DEPTH = 12;

  async function buildPath(leaf, pathIndices) {
    const pathElements = [];
    let cur = leaf;
    for (let i = 0; i < DEPTH; i++) {
      const el = crypto.randomBytes(32).readBigUInt64LE() + 1n;
      pathElements.push(el);
      cur = pathIndices[i] === 1n ? poseidon2([el, cur]) : poseidon2([cur, el]);
    }
    return { root: cur, pathElements };
  }

  const loadMembershipVkey = () => loadVerificationKey('membership');

  await test('generate and verify a real Merkle membership proof', async () => {
    const leaf = poseidonHash([987654321n, 1n]);
    const pathIndices = Array.from({ length: DEPTH }, (_, i) => BigInt((i + 7) % 2));
    const { root, pathElements } = await buildPath(leaf, pathIndices);

    const circuitInput = {
      leaf: leaf.toString(),
      root: root.toString(),
      pathElements: pathElements.map(String),
      pathIndices: pathIndices.map(String),
    };

    const { wasm, zkey } = await resolveArtifacts('membership');
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(circuitInput, wasm, zkey);
    const vkey = await loadMembershipVkey();

    assert.strictEqual(publicSignals[0], '1'); // isMember gate
    assert.strictEqual(publicSignals[1], leaf.toString());
    assert.strictEqual(publicSignals[2], root.toString());
    const ok = await snarkjs.groth16.verify(vkey, publicSignals, proof);
    assert.strictEqual(ok, true);
  });

  await test('membership proof with a wrong root yields isMember=0', async () => {
    const leaf = poseidonHash([987654321n, 1n]);
    const pathIndices = Array.from({ length: DEPTH }, () => 0n);
    const { root, pathElements } = await buildPath(leaf, pathIndices);
    const evilRoot = (BigInt(root) + 1n).toString();
    const circuitInput = {
      leaf: leaf.toString(),
      root: evilRoot,
      pathElements: pathElements.map(String),
      pathIndices: pathIndices.map(String),
    };
    const { wasm, zkey } = await resolveArtifacts('membership');
    const vkey = await loadMembershipVkey();
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(circuitInput, wasm, zkey);
    assert.strictEqual(publicSignals[0], '0'); // isMember gate is 0 even though proof verifies
    const ok = await snarkjs.groth16.verify(vkey, publicSignals, proof);
    assert.strictEqual(ok, true);
  });

  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed === 0 ? 0 : 1);
}

run().catch((err) => {
  console.error(err);
  process.exit(1);
});
