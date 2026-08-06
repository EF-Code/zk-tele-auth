import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';
import { ProofArtifactOptions } from './types.js';

const here = path.dirname(fileURLToPath(import.meta.url));

/**
 * Project-relative artifacts root: `<repo>/artifacts`.
 * Resolved from this module at `<repo>/dist/sdk/artifacts.js` (two levels up).
 * Overridable via the ZK_TELE_AUTH_ARTIFACTS_DIR env var or explicit options.
 */
function defaultArtifactsDir(): string {
  return (
    process.env.ZK_TELE_AUTH_ARTIFACTS_DIR ||
    path.resolve(here, '..', '..', 'artifacts')
  );
}

function assertFile(file: string, what: string) {
  if (!fs.existsSync(file)) {
    throw new Error(`[zk-tele-auth] missing ${what} artifact: ${file}. Run: npm run setup:circuits`);
  }
}

export interface ResolvedArtifacts {
  dir: string;
  r1cs: string;
  wasm: string;
  zkey: string;
  vkeyPath: string;
}

/**
 * Resolve the circuit artifacts (r1cs/wasm/zkey/vkey) for a named circuit.
 * Absolute paths in `opts` take precedence; otherwise the directory layout is
 * `<artifactsDir>/<circuit>/{name.r1cs, name.wasm, name_final.zkey, name_vkey.json}`.
 */
export async function resolveArtifacts(
  circuit: string,
  opts: ProofArtifactOptions = {}
): Promise<ResolvedArtifacts> {
  const dir = opts.artifactsDir || defaultArtifactsDir();
  const r1cs = path.join(dir, circuit, `${circuit}.r1cs`);
  const wasm = opts.wasmPath || path.join(dir, circuit, `${circuit}.wasm`);
  const zkey = opts.zkeyPath || path.join(dir, circuit, `${circuit}_final.zkey`);
  const vkeyPath = path.join(dir, circuit, `${circuit}_vkey.json`);

  if (!opts.verificationKey) assertFile(vkeyPath, 'verification key');
  if (!opts.wasmPath) assertFile(wasm, 'wasm witness');
  if (!opts.zkeyPath) assertFile(zkey, 'proving key');

  return { dir, r1cs, wasm, zkey, vkeyPath };
}

export async function loadVerificationKey(
  circuit: string,
  opts: ProofArtifactOptions = {}
): Promise<object> {
  if (opts.verificationKey) return opts.verificationKey;
  const { vkeyPath } = await resolveArtifacts(circuit, opts);
  return JSON.parse(fs.readFileSync(vkeyPath, 'utf-8'));
}
