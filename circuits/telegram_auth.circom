pragma circom 2.1.6;

include "../node_modules/circomlib/circuits/comparators.circom";
include "hasher.circom";

/*
 * Main Telegram Private OAuth ZK Circuit (telegram_auth.circom)
 *
 * Proves possession of a valid Telegram WebApp authentication session without
 * revealing the raw Telegram User ID or the per-user salt to the verifier.
 *
 * The gateway server first authenticates the initData against the bot token
 * (HMAC-SHA256 off-circuit), then generates this proof so that dApps and TON
 * smart contracts can independently verify the attestation.
 *
 * Public Signals:
 *  - nullifierHash       deterministic anonymous identifier for the session
 *  - isVerified          boolean gate: every valid proof outputs 1
 *  - appDomainHash       domain separation commitment (prover-agnostic)
 *  - currentTimestamp    unix epoch the proof was issued at
 *  - maxTokenAgeSec      freshness window for authDate
 *  - isPremiumRequired   whether the dApp demands Telegram Premium
 *
 * Private Inputs:
 *  - userId              numeric Telegram User ID (never revealed)
 *  - authDate            initData auth_date (signed by Telegram)
 *  - isPremium           Telegram Premium membership flag
 *  - salt                per-user random secret mixed into the nullifier
 *
 * Security notes:
 *  - Verifiers MUST re-check that currentTimestamp is close to their own clock,
 *    otherwise a stale proof could be replayed with a forged future timestamp.
 *  - isPremiumRequired is a public input so that the premium constraint is
 *    visible to and auditable by the verifier.
 */
template TelegramAuthVerifier() {
    // Public Inputs
    signal input appDomainHash;
    signal input currentTimestamp;
    signal input maxTokenAgeSec;
    signal input isPremiumRequired;

    // Private Inputs
    signal input userId;
    signal input authDate;
    signal input isPremium;
    signal input salt;

    // Outputs
    signal output nullifierHash;
    signal output isVerified;

    // 1. Constrain all boolean flags to be binary
    signal premiumBinary;
    premiumBinary <== isPremium * (1 - isPremium);
    premiumBinary === 0;

    signal premiumRequiredBinary;
    premiumRequiredBinary <== isPremiumRequired * (1 - isPremiumRequired);
    premiumRequiredBinary === 0;

    // 2. If Premium is required, the user must hold Premium:
    //    isPremiumRequired * (1 - isPremium) === 0
    signal premiumViolation;
    premiumViolation <== isPremiumRequired * (1 - isPremium);
    premiumViolation === 0;

    signal premiumOk;
    premiumOk <== 1 - isPremiumRequired * (1 - isPremium);

    // 3. Derive the domain-separated anonymous nullifier
    component nullifier = PoseidonNullifier();
    nullifier.userId <== userId;
    nullifier.appDomainHash <== appDomainHash;
    nullifier.salt <== salt;
    nullifierHash <== nullifier.nullifierHash;

    // 4. Verify initData freshness
    component age = AgeVerifier();
    age.authDate <== authDate;
    age.currentTimestamp <== currentTimestamp;
    age.maxTokenAgeSec <== maxTokenAgeSec;

    // 5. Overall gate
    isVerified <== premiumOk * age.isValid;
}

component main {public [appDomainHash, currentTimestamp, maxTokenAgeSec, isPremiumRequired]} = TelegramAuthVerifier();
