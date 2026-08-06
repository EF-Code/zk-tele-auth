export interface TelegramInitDataRaw {
  query_id?: string;
  user?: string;
  auth_date: number;
  hash: string;
  signature?: string;
}

export interface ParsedTelegramUser {
  id: number;
  first_name?: string;
  last_name?: string;
  username?: string;
  language_code?: string;
  is_premium?: boolean;
  allows_write_to_pm?: boolean;
}

/**
 * Inputs for the telegram_auth Groth16 circuit.
 */
export interface ZkAuthProofInputs {
  /** Numeric Telegram User ID (kept private inside the circuit). */
  userId: number;
  /** initData auth_date (unix seconds), signed by Telegram. */
  authDate: number;
  /** Whether the user holds Telegram Premium. */
  isPremium: boolean;
  /** dApp domain used for domain-separated nullifier derivation. */
  appDomain: string;
  /** Unix seconds at proof generation time (public signal). */
  currentTimestamp: number;
  /** Freshness window in seconds; authDate must satisfy now - authDate <= maxTokenAgeSec. */
  maxTokenAgeSec?: number;
  /** True when the verifier demands Telegram Premium. */
  isPremiumRequired?: boolean;
  /** Optional deterministic salt; a random one is generated when omitted. */
  salt?: string;
}

/**
 * Result of `groth16.fullProve` / accepted by `groth16.verify`.
 * Coordinates are decimal or hex strings in the BN254 field.
 */
export interface Groth16Proof {
  pi_a: string[];
  pi_b: string[][];
  pi_c: string[];
  protocol: string;
  curve: string;
}

/**
 * Public signals layout for `telegram_auth`:
 *   [0] nullifierHash
 *   [1] isVerified
 *   [2] appDomainHash
 *   [3] currentTimestamp
 *   [4] maxTokenAgeSec
 *   [5] isPremiumRequired
 */
export interface ZkAuthProofPayload {
  proof: Groth16Proof;
  publicSignals: string[];
  /** Public signal [0]: anonymous, domain-specific identifier. */
  nullifierHash: string;
  /** Public signal [2]: Poseidon commitment to the app domain. */
  appDomainHash: string;
  /** Public signal [3]: unix seconds the proof was generated. */
  timestamp: number;
  /** Public signal [4]: freshness window enforced by the circuit. */
  maxTokenAgeSec: number;
  /** Public signal [5]: premium requirement enforced by the circuit. */
  isPremiumRequired: boolean;
  /** Public signal [1]: circuit gate; always "1" for a valid proof. */
  isVerified: boolean;
}

export interface VerificationResult {
  isValid: boolean;
  nullifierHash: string;
  appDomainHash?: string;
  error?: string;
}

/** Optional runtime overrides for circuit artifact resolution. */
export interface ProofArtifactOptions {
  /** Root directory that holds `<circuit>/` subfolders with wasm/zkey/vkey. */
  artifactsDir?: string;
  /** Loaded verification key object (skips vkey file read). */
  verificationKey?: object;
  /** Absolute path to the circuit .wasm file (skips directory resolution). */
  wasmPath?: string;
  /** Absolute path to the circuit proving key file (skips directory resolution). */
  zkeyPath?: string;
}
