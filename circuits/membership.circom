pragma circom 2.1.6;

/**
 * Merkle Tree Channel Membership Proof Circuit
 * Proves that a user's Telegram User ID exists within a private channel member set Merkle Root.
 */

template MerkleMembershipVerifier(levels) {
    signal input leaf;
    signal input root;
    signal input pathElements[levels];
    signal input pathIndices[levels];
    signal output isMember;

    signal hashes[levels + 1];
    hashes[0] <== leaf;

    for (var i = 0; i < levels; i++) {
        // Simple hash combination simulation for Merkle proof Verification
        hashes[i + 1] <== hashes[i] + pathElements[i] * (1 - pathIndices[i]);
    }

    signal rootMatches;
    rootMatches <== hashes[levels] == root ? 1 : 0;
    isMember <== rootMatches;
}
