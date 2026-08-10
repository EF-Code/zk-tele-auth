pragma circom 2.1.6;

include "hasher.circom";

// Priva purchase authorization.
//
// The gateway first validates Telegram initData, then proves knowledge of its
// stable issuer secret. The resulting authorization is bound to one launchpad
// buy action; it cannot be redirected to another launch, recipient, operation,
// or circuit version.
template PrivaPurchaseAuth() {
    // Public verifier-pinned credential policy.
    signal input appDomainHash;
    signal input currentTimestamp;
    signal input maxTokenAgeSec;
    signal input isPremiumRequired;
    signal input issuerKeyHash;

    // Public Priva action binding.
    signal input launchIdHash;
    signal input launchpadAddressHash;
    signal input operation;
    signal input recipientHash;
    signal input clientNonce;
    signal input expiryEpoch;
    signal input circuitVersion;

    // Private Telegram/issuer witness supplied only by the authenticated gateway.
    signal input userId;
    signal input authDate;
    signal input isPremium;
    signal input issuerSecret;

    signal output identityNullifier;
    signal output actionNullifier;
    signal output isAuthorized;

    // Priva v1 supports only BUY (1) and circuit version 1.
    operation === 1;
    circuitVersion === 1;

    signal premiumBinary;
    premiumBinary <== isPremium * (1 - isPremium);
    premiumBinary === 0;

    signal premiumRequiredBinary;
    premiumRequiredBinary <== isPremiumRequired * (1 - isPremiumRequired);
    premiumRequiredBinary === 0;

    signal premiumViolation;
    premiumViolation <== isPremiumRequired * (1 - isPremium);
    premiumViolation === 0;

    signal premiumOk;
    premiumOk <== 1 - premiumViolation;

    component issuer = IssuerKeyCommitment();
    issuer.issuerSecret <== issuerSecret;
    issuer.issuerKeyHash === issuerKeyHash;

    component identity = PoseidonNullifier();
    identity.userId <== userId;
    identity.appDomainHash <== appDomainHash;
    identity.issuerSecret <== issuerSecret;
    identityNullifier <== identity.nullifierHash;

    component age = AgeVerifier();
    age.authDate <== authDate;
    age.currentTimestamp <== currentTimestamp;
    age.maxTokenAgeSec <== maxTokenAgeSec;

    // The authorization has an explicit short expiry in addition to Telegram
    // credential freshness. The relying party pins its maximum TTL off-circuit.
    component notExpired = LessEqThan(64);
    notExpired.in[0] <== currentTimestamp;
    notExpired.in[1] <== expiryEpoch;

    // Compress all routing/action fields before deriving the one-time action
    // nullifier. `clientNonce` creates a new authorization only for the same
    // stable identity; it cannot bypass the launchpad's cumulative identity cap.
    component destination = Poseidon255(3);
    destination.in[0] <== launchIdHash;
    destination.in[1] <== launchpadAddressHash;
    destination.in[2] <== recipientHash;

    component action = Poseidon255(4);
    action.in[0] <== operation;
    action.in[1] <== clientNonce;
    action.in[2] <== expiryEpoch;
    action.in[3] <== circuitVersion;

    component authorization = Poseidon255(3);
    authorization.in[0] <== identityNullifier;
    authorization.in[1] <== destination.out;
    authorization.in[2] <== action.out;
    actionNullifier <== authorization.out;

    signal credentialFresh;
    credentialFresh <== age.isValid * notExpired.out;
    isAuthorized <== credentialFresh * premiumOk;
}

component main {public [
    appDomainHash,
    currentTimestamp,
    maxTokenAgeSec,
    isPremiumRequired,
    issuerKeyHash,
    launchIdHash,
    launchpadAddressHash,
    operation,
    recipientHash,
    clientNonce,
    expiryEpoch,
    circuitVersion
]} = PrivaPurchaseAuth();
