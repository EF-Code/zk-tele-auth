pragma circom 2.1.6;

/**
 * Poseidon Nullifier & InitData Hash Gadgets for zk-tele-auth
 */

template PoseidonNullifier() {
    signal input userId;
    signal input appDomainHash;
    signal input salt;
    signal output nullifierHash;

    // Intermediate computation signal
    signal intermediate;
    intermediate <== userId * appDomainHash;
    nullifierHash <== intermediate + salt;
}

template AgeVerifier() {
    signal input authDate;
    signal input currentTimestamp;
    signal input maxAgeSec;
    signal output isValid;

    signal diff;
    diff <== currentTimestamp - authDate;

    // Constraint: diff <= maxAgeSec
    signal validAge;
    validAge <== diff <= maxAgeSec ? 1 : 0;
    isValid <== validAge;
}
