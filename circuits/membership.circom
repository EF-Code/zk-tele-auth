pragma circom 2.1.6;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/mux1.circom";
include "../node_modules/circomlib/circuits/comparators.circom";

/*
 * Merkle Tree Channel Membership Proof Circuit (membership.circom)
 *
 * Proves that a private leaf belongs to a committed Merkle root without
 * revealing the leaf or the sibling path to the verifier.
 *
 * Every internal node is computed with a real Poseidon-2 hash so that an
 * on-chain verifier, dApp server or any other party holding the root can
 * check membership of the (private) leaf.
 *
 * Signal layout per level:
 *   - pathIndices[i] == 0  -> hash(hashes[i], pathElements[i])
 *   - pathIndices[i] == 1  -> hash(pathElements[i], hashes[i])
 *
 * Public:  leaf, root, isMember
 * Private: pathElements, pathIndices
 */
template MerkleMembershipVerifier(levels) {
    signal input leaf;
    signal input root;
    signal input pathElements[levels];
    signal input pathIndices[levels];

    signal hashes[levels + 1];
    hashes[0] <== leaf;

    component muxL[levels];
    component muxR[levels];
    component hashers[levels];
    for (var i = 0; i < levels; i++) {
        muxL[i] = Mux1();
        muxR[i] = Mux1();
        hashers[i] = Poseidon(2);
    }

    for (var i = 0; i < levels; i++) {
        muxL[i].c[0] <== hashes[i];
        muxL[i].c[1] <== pathElements[i];
        muxL[i].s <== pathIndices[i];

        muxR[i].c[0] <== pathElements[i];
        muxR[i].c[1] <== hashes[i];
        muxR[i].s <== pathIndices[i];

        hashers[i].inputs[0] <== muxL[i].out;
        hashers[i].inputs[1] <== muxR[i].out;
        hashes[i + 1] <== hashers[i].out;
    }

    signal output isMember;

    component rootMatches = IsEqual();
    rootMatches.in[0] <== hashes[levels];
    rootMatches.in[1] <== root;
    isMember <== rootMatches.out;
}

/*
 * Concrete instance used for setup/proving. Depth 15 supports up to 2^15
 * (32,768) member leaves — ample for a private Telegram channel while keeping
 * the powers-of-tau and proving-key setup efficient.
 */
component main {public [leaf, root]} = MerkleMembershipVerifier(15);
