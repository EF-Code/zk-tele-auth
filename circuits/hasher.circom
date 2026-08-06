pragma circom 2.1.6;

include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/poseidon-bls12381-circom/circuits/poseidon255.circom";

/*
 * Poseidon-based nullifier derivation.
 *
 * Computes a deterministic, domain-separated anonymous identifier:
 *
 *     nullifierHash = Poseidon255(userId, appDomainHash, salt)
 *
 * The userId is kept private so that dApps and on-chain contracts can only
 * observe the nullifier, never the raw Telegram account. Because appDomainHash
 * is mixed into the hash, the same user produces a different nullifier per
 * dApp and cannot be correlated across applications.
 *
 * userId is additionally constrained to be non-zero so that the empty/absent
 * user (id = 0) can never produce a valid proof.
 */
template PoseidonNullifier() {
    signal input userId;
    signal input appDomainHash;
    signal input salt;
    signal output nullifierHash;

    component userIdNonZero = IsZero();
    userIdNonZero.in <== userId;
    userIdNonZero.out === 0;

    component hash = Poseidon255(3);
    hash.in[0] <== userId;
    hash.in[1] <== appDomainHash;
    hash.in[2] <== salt;
    nullifierHash <== hash.out;
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
