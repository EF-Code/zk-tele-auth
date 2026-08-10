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
  userId: number | string;
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
  /** Stable private field element held only by the authorized gateway issuer. */
  issuerSecret: string;
}

/** Policy a relying party must pin independently of prover-controlled signals. */
export interface ZkAuthVerificationPolicy {
  expectedAppDomain: string;
  expectedIssuerKeyHash: string;
  maxTokenAgeSec: number;
  requirePremium: boolean;
  clockSkewSec?: number;
}

/** Inputs for a Priva-bound purchase authorization proof. */
export interface PrivaPurchaseAuthInputs extends ZkAuthProofInputs {
  launchIdHash: string;
  /** High and low 128-bit limbs of a canonical basechain launchpad account ID. */
  launchpadAddressHi: string;
  launchpadAddressLo: string;
  /** High and low 128-bit limbs of the exact recipient account ID. */
  recipientAddressHi: string;
  recipientAddressLo: string;
  clientNonce: string;
  /** Unix timestamp after which this authorization is invalid. */
  expiryEpoch: number;
  /** Priva v1 circuit version; constrained to 1 by the circuit. */
  circuitVersion?: number;
}

/** Policy that a Priva relying party must pin independently of the prover. */
export interface PrivaPurchaseAuthVerificationPolicy extends ZkAuthVerificationPolicy {
  expectedLaunchIdHash: string;
  expectedLaunchpadAddressHi: string;
  expectedLaunchpadAddressLo: string;
  expectedRecipientAddressHi: string;
  expectedRecipientAddressLo: string;
  maxAuthorizationTtlSec: number;
  expectedCircuitVersion?: number;
}

/**
 * Result of `groth16.fullProve` / accepted by `groth16.verify`.
 * Coordinates are decimal or hex strings in the BLS12-381 field.
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
 *   [6] issuerKeyHash
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
  /** Public signal [6]: commitment to the authorized gateway issuer secret. */
  issuerKeyHash: string;
  /** Public signal [1]: circuit gate; always "1" for a valid proof. */
  isVerified: boolean;
}

export interface VerificationResult {
  isValid: boolean;
  nullifierHash: string;
  appDomainHash?: string;
  issuerKeyHash?: string;
  error?: string;
}

/**
 * Public signals layout for `priva_purchase_auth`:
 * [identityNullifier, actionNullifier, isAuthorized, appDomainHash,
 *  currentTimestamp, maxTokenAgeSec, isPremiumRequired, issuerKeyHash,
 *  launchIdHash, launchpadAddressHi, launchpadAddressLo, operation,
 *  recipientAddressHi, recipientAddressLo, clientNonce, expiryEpoch,
 *  circuitVersion]
 */
export interface PrivaPurchaseAuthProofPayload {
  proof: Groth16Proof;
  publicSignals: string[];
  identityNullifier: string;
  actionNullifier: string;
  appDomainHash: string;
  timestamp: number;
  maxTokenAgeSec: number;
  isPremiumRequired: boolean;
  issuerKeyHash: string;
  launchIdHash: string;
  launchpadAddressHi: string;
  launchpadAddressLo: string;
  operation: number;
  recipientAddressHi: string;
  recipientAddressLo: string;
  clientNonce: string;
  expiryEpoch: number;
  circuitVersion: number;
  isAuthorized: boolean;
}

export interface MembershipProofInputs {
  leaf: string;
  root: string;
  pathElements: string[];
  pathIndices: Array<number | string>;
}

export interface MembershipProofPayload {
  proof: Groth16Proof;
  publicSignals: string[];
  root: string;
  isMember: boolean;
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
