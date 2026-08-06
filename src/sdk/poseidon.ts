import * as blsPoseidon from 'poseidon-bls12381';

/**
 * Poseidon hash over the BLS12-381 scalar field (255-bit Fr), using the
 * official reference constants (128-bit security) from jmagan's
 * `poseidon-bls12381` package.
 *
 * The circom side is `Poseidon255(nInputs)` from `poseidon-bls12381-circom`,
 * which uses the exact same constants and round structure, so JS-derived
 * hashes are identical to circuit outputs over `--prime bls12381`.
 */
export function poseidon(inputs: (bigint | number | string)[]): bigint {
  const arity = inputs.length;
  if (arity < 1 || arity > 16) {
    throw new Error(`poseidon supports 1..16 inputs, got ${arity}`);
  }
  const values = inputs.map((v) => BigInt(v));
  for (const v of values) {
    if (v < 0n) throw new Error('poseidon inputs must be non-negative');
  }
  const fn = (blsPoseidon as unknown as Record<string, (i: bigint[]) => bigint>)[`poseidon${arity}`];
  return fn(values);
}

/**
 * Poseidon hash over the BLS12-381 scalar field.
 * @param inputs field elements (auto-reduced to the scalar field)
 * @returns decimal string of the hash output
 */
export function poseidonHash(inputs: (bigint | number | string)[]): string {
  return poseidon(inputs).toString();
}

/**
 * Derive a canonical field element for a message from its hex digest.
 * Splits the hex into two chunks that fit comfortably inside the 255-bit
 * scalar field (248 bits + 8 bits), then folds them with one Poseidon call.
 */
export function fieldElementFromHex(hex: string): string {
  const clean = hex.replace(/^0x/, '');
  if (clean.length !== 64) throw new Error(`expected 64 hex chars, got ${clean.length}`);
  const lo = BigInt('0x' + clean.slice(0, 62));
  const hi = BigInt('0x' + clean.slice(62, 64));
  return poseidonHash([lo, hi]);
}
