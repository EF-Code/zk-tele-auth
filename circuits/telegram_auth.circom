pragma circom 2.1.6;

include "../node_modules/circomlib/circuits/comparators.circom";
include "hasher.circom";

/*
 * Main Telegram Private OAuth ZK Circuit (telegram_auth.circom)
 *
 * Proves possession of a valid Telegram WebApp authentication session without
 * revealing the raw Telegram User ID or issuer secret to the verifier.
 *
 * The gateway authenticates Telegram initData off-circuit and proves knowledge
 * of a private issuer secret. Relying parties pin issuerKeyHash, so possession
 * of the public proving key alone cannot mint an accepted claim.
 *
 * Public Signals:
 *  - nullifierHash       deterministic anonymous identifier for the session
 *  - isVerified          boolean gate: every valid proof outputs 1
 *  - appDomainHash       domain separation commitment (prover-agnostic)
 *  - currentTimestamp    unix epoch the proof was issued at
 *  - maxTokenAgeSec      freshness window for authDate
 *  - isPremiumRequired   whether the dApp demands Telegram Premium
 *  - issuerKeyHash       commitment to the authorized gateway issuer secret
 *
 * Private Inputs:
 *  - userId              numeric Telegram User ID (never revealed)
 *  - authDate            initData auth_date (signed by Telegram)
 *  - isPremium           Telegram Premium membership flag
 *  - issuerSecret        stable gateway secret; never returned or committed raw
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
    signal input issuerKeyHash;

    // Private Inputs
    signal input userId;
    signal input authDate;
    signal input isPremium;
    signal input issuerSecret;

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

    // 3. Bind the proof to the relying party's authorized gateway issuer.
    component issuer = IssuerKeyCommitment();
    issuer.issuerSecret <== issuerSecret;
    issuer.issuerKeyHash === issuerKeyHash;

    // 4. Derive a stable, domain-separated anonymous nullifier.
    component nullifier = PoseidonNullifier();
    nullifier.userId <== userId;
    nullifier.appDomainHash <== appDomainHash;
    nullifier.issuerSecret <== issuerSecret;
    nullifierHash <== nullifier.nullifierHash;

    // 5. Verify initData freshness
    component age = AgeVerifier();
    age.authDate <== authDate;
    age.currentTimestamp <== currentTimestamp;
    age.maxTokenAgeSec <== maxTokenAgeSec;

    // 6. Overall gate
    isVerified <== premiumOk * age.isValid;
}

component main {public [appDomainHash, currentTimestamp, maxTokenAgeSec, isPremiumRequired, issuerKeyHash]} = TelegramAuthVerifier();
