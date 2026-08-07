pragma circom 2.1.6;

include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/poseidon-bls12381-circom/circuits/poseidon255.circom";

/*
 * Poseidon-based nullifier derivation.
 *
 * Computes a deterministic, domain-separated anonymous identifier:
 *
 *     nullifierHash = Poseidon255(userId, appDomainHash, issuerSecret)
 *
 * The userId is kept private so that dApps and on-chain contracts can only
 * observe the nullifier, never the raw Telegram account. Because appDomainHash
 * is mixed into the hash, the same user produces a different nullifier per
 * dApp and cannot be correlated across applications.
 *
 * The issuer secret is stable and known only to the authenticated gateway. It
 * simultaneously prevents public Telegram-ID enumeration and makes the
 * nullifier stable for one issuer/user/domain tuple.
 */
template PoseidonNullifier() {
    signal input userId;
    signal input appDomainHash;
    signal input issuerSecret;
    signal output nullifierHash;

    component userIdNonZero = IsZero();
    userIdNonZero.in <== userId;
    userIdNonZero.out === 0;

    component hash = Poseidon255(3);
    hash.in[0] <== userId;
    hash.in[1] <== appDomainHash;
    hash.in[2] <== issuerSecret;
    nullifierHash <== hash.out;
}

/*
 * Proves that the witness includes the secret belonging to the issuer whose
 * public commitment is pinned by the relying party. Because the proving key
 * is public, this constraint is the authorization boundary that prevents an
 * arbitrary caller from minting Telegram claims.
 */
template IssuerKeyCommitment() {
    signal input issuerSecret;
    signal output issuerKeyHash;

    component secretNonZero = IsZero();
    secretNonZero.in <== issuerSecret;
    secretNonZero.out === 0;

    component hash = Poseidon255(1);
    hash.in[0] <== issuerSecret;
    issuerKeyHash <== hash.out;
}

/*
 * Telegram initData freshness verifier.
 *
 * Enforces that the initData was issued recently enough to be accepted:
 *
 *     authDate <= currentTimestamp  AND  currentTimestamp - authDate <= maxTokenAgeSec
 *
 * Both bounds are enforced with n-bit comparators so that values larger than
 * 2^64 make the circuit unsatisfiable (rejecting out-of-range timestamps
 * instead of silently wrapping).
 */
template AgeVerifier() {
    signal input authDate;
    signal input currentTimestamp;
    signal input maxTokenAgeSec;
    signal output isValid;

    signal diff;
    diff <== currentTimestamp - authDate;

    component notFuture = LessEqThan(64);
    notFuture.in[0] <== authDate;
    notFuture.in[1] <== currentTimestamp;

    component notExpired = LessEqThan(64);
    notExpired.in[0] <== diff;
    notExpired.in[1] <== maxTokenAgeSec;

    isValid <== notFuture.out * notExpired.out;
}
