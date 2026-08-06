#!/usr/bin/env node
/*
 * Real Groth16 trusted setup for zk-tele-auth circuits.
 *
 * Pipeline per circuit:
 *   1. compile        circom <name>.circom -> r1cs / wasm / sym
 *   2. phase 1        powersOfTau (bn128) + contribute + preparePhase2
 *   3. phase 2        groth16 setup (newZKey) + deterministic beacon finalize
 *   4. export         verification_key.json
 *
 * The produced artifacts are mirrored into ./artifacts so that the SDK, tests
 * and the TON verifier generation can consume them without re-running setup.
 *
 * NOTE: the powersOfTau is generated locally with a fixed beacon. This is a
 * self-hosted, reproducible setup suitable for development and testing. For a
 * production deployment you MUST reuse a public ceremony ptau and discard the
 * toxic waste (see README "Trusted setup" section).
 *
 * Env:
 *   CIRCOM        path to the circom binary (default: resolved from PATH)
 *   ZK_TAU_POWER  explicit powers-of-tau size (default: computed, min 14)
 *   ZK_TAU_ENTROPY  entropy used for the phase-1 contribution (default dev)
 */
const snarkjs = require('snarkjs');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { execFileSync } = require('child_process');
const crypto = require('crypto');

const root = path.resolve(__dirname, '..');
const buildDir = path.join(root, 'build', 'circuits');
const ptauDir = path.join(root, 'build', 'ptau');
const artifactsDir = path.join(root, 'artifacts');

const CIRCUITS = [
  { name: 'telegram_auth', prime: 'bls12381', power: 14 },
  { name: 'membership', prime: 'bls12381', power: 14 },
];

const DEFAULT_ENTROPY = 'zk-tele-auth v1 local dev setup';

const logger = {
  log: (msg) => console.log(`[setup] ${msg}`),
  info: (msg) => console.log(`[setup] ${msg}`),
  error: (msg) => console.error(`[setup] ERROR ${msg}`),
  warn: (msg) => console.warn(`[setup] WARN ${msg}`),
  debug: () => {},
};

function findCircom() {
  const env = process.env.CIRCOM;
  if (env && fs.existsSync(env)) return env;
  for (const dir of process.env.PATH.split(path.delimiter)) {
    const candidate = path.join(dir, 'circom');
    if (fs.existsSync(candidate)) return candidate;
  }
  const home = path.join(os.homedir(), '.local', 'bin', 'circom');
  if (fs.existsSync(home)) return home;
  throw new Error(
    'circom binary not found. Install it (https://github.com/iden3/circom) or set the CIRCOM env var.'
  );
}

function ensureDir(p) {
  fs.mkdirSync(p, { recursive: true });
}

function compileCircuit(circomBin, circuit) {
  const outDir = path.join(buildDir, circuit.name);
  ensureDir(outDir);
  logger.log(`compiling ${circuit.name}.circom ...`);
  execFileSync(
    circomBin,
    [path.join(root, 'circuits', `${circuit.name}.circom`), '--prime', 'bls12381', '-o', outDir, '--r1cs', '--wasm', '--sym'],
    { stdio: ['ignore', 'inherit', 'inherit'] }
  );
  const r1cs = path.join(outDir, `${circuit.name}.r1cs`);
  return snarkjs.r1cs.info(r1cs, logger).then((info) => {
    logger.log(
      `${circuit.name}: ${info.nConstraints} constraints, ${info.nPubInputs} pub inputs, ${info.nPrvInputs} priv inputs`
    );
    return { circuit, r1cs, wasm: path.join(outDir, `${circuit.name}_js`, `${circuit.name}.wasm`), info };
  });
}

async function ensurePtau(power, prime) {
  const name = `pot_${prime}_${power}.ptau`;
  const ptau = path.join(ptauDir, name);
  if (fs.existsSync(ptau)) {
    logger.log(`reusing existing ptau: ${name}`);
    return ptau;
  }
  ensureDir(ptauDir);
  logger.log(`creating powersOfTau (${prime}, power=${power}) ...`);
  const curve = await snarkjs.curves.getCurveFromName(prime);
  const phase1a = path.join(ptauDir, `pot_${prime}_${power}_0000.ptau`);
  const phase1b = path.join(ptauDir, `pot_${prime}_${power}_0001.ptau`);
  await snarkjs.powersOfTau.newAccumulator(curve, power, phase1a, logger);
  const entropy = process.env.ZK_TAU_ENTROPY || DEFAULT_ENTROPY;
  await snarkjs.powersOfTau.contribute(phase1a, phase1b, 'zk-tele-auth phase1', entropy, logger);
  await snarkjs.powersOfTau.preparePhase2(phase1b, ptau, logger);
  fs.unlinkSync(phase1a);
  fs.unlinkSync(phase1b);
  logger.log(`ptau ready: ${name} (${(fs.statSync(ptau).size / 1024 / 1024).toFixed(2)} MB)`);
  return ptau;
}

async function setupCircuit(circuitDef, ptau) {
  const circuit = circuitDef.name;
  const srcDir = path.join(buildDir, circuit);
  const r1cs = path.join(srcDir, `${circuit}.r1cs`);
  const wasm = path.join(srcDir, `${circuit}_js`, `${circuit}.wasm`);

  const zkey = path.join(srcDir, `${circuit}_final.zkey`);
  if (fs.existsSync(zkey) && process.env.ZK_TAU_REUSE === '1') {
    logger.log(`reusing existing zkey for ${circuit}`);
  } else {
    const zkeyInit = path.join(srcDir, `${circuit}_init.zkey`);
    logger.log(`groth16 setup for ${circuit} ...`);
    await snarkjs.zKey.newZKey(r1cs, ptau, zkeyInit, logger);
    const beaconHash = crypto
      .createHash('blake2b512')
      .update(process.env.ZK_TAU_ENTROPY || DEFAULT_ENTROPY)
      .digest('hex')
      .slice(0, 64);
    logger.log(`finalizing ${circuit} with deterministic beacon ...`);
    await snarkjs.zKey.beacon(zkeyInit, zkey, 'zk-tele-auth beacon', beaconHash, 10, logger);
    fs.unlinkSync(zkeyInit);
  }

  const vkey = await snarkjs.zKey.exportVerificationKey(zkey, logger);

  // Mirror committed artifacts
  const mirror = path.join(artifactsDir, circuit);
  ensureDir(mirror);
  fs.copyFileSync(r1cs, path.join(mirror, `${circuit}.r1cs`));
  fs.copyFileSync(wasm, path.join(mirror, `${circuit}.wasm`));
  fs.copyFileSync(zkey, path.join(mirror, `${circuit}_final.zkey`));
  fs.writeFileSync(path.join(mirror, `${circuit}_vkey.json`), JSON.stringify(vkey, null, 2));

  const manifest = {
    name: circuit,
    power: circuitDef.power,
    prime: circuitDef.prime,
    constraints: (await snarkjs.r1cs.info(r1cs)).nConstraints,
    publicInputs: Object.keys(vkey.IC).length - 1,
    vkeySha256: crypto.createHash('sha256').update(JSON.stringify(vkey)).digest('hex'),
    artifacts: {
      r1cs: `${circuit}.r1cs`,
      wasm: `${circuit}.wasm`,
      zkey: `${circuit}_final.zkey`,
      vkey: `${circuit}_vkey.json`,
    },
  };
  fs.writeFileSync(path.join(mirror, `${circuit}.json`), JSON.stringify(manifest, null, 2));
  logger.log(
    `${circuit} ready: zkey ${(fs.statSync(zkey).size / 1024).toFixed(0)} KB, wasm ${(fs.statSync(wasm).size / 1024).toFixed(0)} KB`
  );
}

async function main() {
  const circomBin = findCircom();
  logger.log(`using circom: ${circomBin}`);

  ensureDir(buildDir);
  ensureDir(ptauDir);

  // Wipe previous per-circuit outputs so stale artifacts from another prime or
  // an older circuit revision can never leak into ./artifacts. Set
  // ZK_TAU_REUSE=1 to keep and skip re-running phase 2.
  if (process.env.ZK_TAU_REUSE !== '1') {
    for (const circuitDef of CIRCUITS) {
      fs.rmSync(path.join(buildDir, circuitDef.name), { recursive: true, force: true });
    }
  }

  const compiled = [];
  for (const circuitDef of CIRCUITS) {
    compiled.push(await compileCircuit(circomBin, circuitDef));
  }

  const maxConstraints = Math.max(...compiled.map((c) => c.info.nConstraints));
  const requiredPower = Math.max(14, Math.ceil(Math.log2(maxConstraints)) + 1);
  const power = Number(process.env.ZK_TAU_POWER || requiredPower);
  if (power < requiredPower) {
    throw new Error(`ZK_TAU_POWER=${power} is too small; need at least ${requiredPower}`);
  }

  const ptau = await ensurePtau(power, 'bls12381');

  for (const circuitDef of CIRCUITS) {
    circuitDef.power = power;
    await setupCircuit(circuitDef, ptau);
  }

  logger.log('done. artifacts written to ./artifacts');
  process.exit(0);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
