import { buildPoseidon, buildPoseidonWasm } from 'circomlibjs';
import { Scalar } from 'ffjavascript';

let cached: Promise<ReturnType<typeof buildPoseidon>> | null = null;

/**
 * Lazily build (and cache) a Poseidon hash instance over the BN254 scalar
 * field, using the exact same constants and round structure as circomlib's
 * `poseidon.circom` (t = nInputs + 1, 8 full + R_P partial rounds).
 *
 * The circuit side computes the same values, which the test suite asserts by
 * comparing JS-derived nullifiers against circuit public signals.
 */
export async function getPoseidon() {
  if (!cached) {
    cached = buildPoseidonWasm ? buildPoseidonWasm() : buildPoseidon();
    // warm up so the first hash call does not pay the init cost
    await cached;
  }
  return cached;
}

export interface Poseidon {
  (inputs: (bigint | number | string)[]): bigint;
  F: {
    toString(x: bigint): string;
    fromObject?(): unknown;
    e?: unknown;
  };
}

/**
 * Poseidon hash over BN254 scalar field.
 * @param inputs field elements (auto-reduced to the scalar field)
 * @returns decimal string of the hash output
 */
export async function poseidonHash(inputs: (bigint | number | string)[]): Promise<string> {
  const poseidon = await getPoseidon();
  const values = inputs.map((v) => BigInt(v));
  for (const v of values) {
    if (v < 0n) throw new Error('poseidon inputs must be non-negative');
  }
  const out = poseidon(values);
  return Scalar.toString(out, 10);
}

/**
 * Derive a canonical field element for a message from its hex digest.
 * Splits the hex into two chunks that fit comfortably inside the 254-bit
 * scalar field (248 bits + 8 bits), then folds them with one Poseidon call.
 */
export async function fieldElementFromHex(hex: string): Promise<string> {
  const clean = hex.replace(/^0x/, '');
  if (clean.length !== 64) throw new Error(`expected 64 hex chars, got ${clean.length}`);
  const lo = BigInt('0x' + clean.slice(0, 62));
  const hi = BigInt('0x' + clean.slice(62, 64));
  return poseidonHash([lo, hi]);
}
