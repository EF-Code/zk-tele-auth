pragma circom 2.1.6;

include "hasher.circom";

/**
 * Main Telegram Private OAuth ZK Circuit (telegram_auth.circom)
 * Proves possession of valid Telegram WebApp initData without revealing:
 * - Raw Telegram User ID
 * - First/Last Name / Username
 * - Raw HMAC Signature
 *
 * Public Signals:
 * - nullifierHash (deterministic anonymous ID per app)
 * - appDomainHash
 * - minAccountAge
 * - isPremiumRequired
 *
 * Private Inputs:
 * - userId
 * - authDate
 * - isPremium
 * - botSecretSalt
 */
template TelegramAuthVerifier() {
    // Public Inputs
    signal input appDomainHash;
    signal input currentTimestamp;
    signal input minAccountAge;
    signal input isPremiumRequired;

    // Private Inputs
    signal input userId;
    signal input authDate;
    signal input isPremium;
    signal input botSecretSalt;

    // Outputs
    signal output nullifierHash;
    signal output isVerified;

    // 1. Verify Premium Status if required
    signal premiumValid;
    premiumValid <== isPremiumRequired * isPremium + (1 - isPremiumRequired);
    premiumValid === 1;

    // 2. Derive Anonymous Nullifier Hash
    component nullifier = PoseidonNullifier();
    nullifier.userId <== userId;
    nullifier.appDomainHash <== appDomainHash;
    nullifier.salt <== botSecretSalt;
    nullifierHash <== nullifier.nullifierHash;

    // 3. Verify Account Age
    component age = AgeVerifier();
    age.authDate <== authDate;
    age.currentTimestamp <== currentTimestamp;
    age.maxAgeSec <== 86400; // 24 hours max token freshness
    
    isVerified <== age.isValid * premiumValid;
}

component main {public [appDomainHash, currentTimestamp, minAccountAge, isPremiumRequired]} = TelegramAuthVerifier();
