# Priva integration contract

`priva_purchase_auth_verifier.tolk` is a reusable Groth16 verifier core. `priva_purchase_auth_verifier_wrapper.tolk` is a bounded cryptographic test/deployment wrapper. Neither is a complete production launchpad.

## Required launchpad behavior

The actual launchpad must call the verifier core in the same atomic purchase transition and must:

- parse all 15 public signals in circuit order;
- bind launch ID, executing launchpad address, recipient, BUY operation, client nonce, expiry, and circuit version;
- consume `actionNullifier` exactly once;
- maintain cumulative purchased amount keyed by `identityNullifier` and launch;
- enforce configured cap and available inventory independently of client nonce;
- validate actual sender/recipient and payment/asset/value;
- define overpayment refunds and downstream bounce handling;
- preserve accounting on every action/compute failure;
- measure dictionary/storage/gas growth and fund storage reserves;
- define pause/upgrade/migration authority if those controls exist.

The repository does not currently contain that financial launchpad or its operator-approved pricing, asset, cap, recipient, and bounce policy. Production preflight must therefore keep this gate blocked.

