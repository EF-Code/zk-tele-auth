# Priva integration contract

`priva_purchase_auth_verifier.tolk` is a reusable Groth16 verifier core. `priva_purchase_auth_verifier_wrapper.tolk` is a bounded cryptographic test/deployment wrapper and is not a launchpad. `priva_purchase_launchpad.tolk` is the repository's composed native-TON purchase transition; it synchronously invokes the core and owns the economic/accounting checks.

## Required launchpad behavior

The actual launchpad must call the verifier core in the same atomic purchase transition and must:

- parse all 17 public signals in circuit order (three circuit outputs plus fourteen policy inputs);
- bind launch ID, executing launchpad address, recipient, BUY operation, client nonce, expiry, and circuit version;
- consume `actionNullifier` exactly once;
- maintain cumulative purchased amount keyed by `identityNullifier` and launch;
- enforce configured cap and available inventory independently of client nonce;
- validate actual sender/recipient and payment/asset/value;
- define overpayment refunds and downstream bounce handling;
- preserve accounting on every action/compute failure;
- measure dictionary/storage/gas growth and fund storage reserves;
- define pause/upgrade/migration authority if those controls exist.

The local composition accepts TON, commits price/cap/inventory in StateInit, requires the message sender to equal the body recipient, rejects wrong policy/expiry/value/replay/cap cases, records sold/raised totals, reserves a storage margin, and records overpayment as a sender-keyed refundable credit. It intentionally performs no asynchronous downstream settlement, so a jetton/NFT adapter, withdrawal path, bounce policy for that adapter, and operator-approved economics remain separate review gates. Production preflight stays blocked until the external review and network evidence exist.
