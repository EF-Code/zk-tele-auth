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

export interface ZkAuthProofInputs {
  userId: number;
  authDate: number;
  isPremium: boolean;
  appDomain: string;
  currentTimestamp: number;
  minAccountAge?: number;
  botSecretSalt?: string;
}

export interface Groth16Proof {
  pi_a: string[];
  pi_b: string[][];
  pi_c: string[];
  protocol: string;
  curve: string;
}

export interface ZkAuthProofPayload {
  proof: Groth16Proof;
  publicSignals: string[];
  nullifierHash: string;
  appDomainHash: string;
  timestamp: number;
}

export interface VerificationResult {
  isValid: boolean;
  nullifierHash: string;
  error?: string;
}
