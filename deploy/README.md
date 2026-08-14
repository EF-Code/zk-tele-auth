# TON deployment tooling

`node scripts/deploy-ton.mjs --network testnet --dry-run` deterministically compiles the generic verifier, serializes its configured `StateInit`, derives the address, and emits a review summary. It performs no network mutation.

The script intentionally refuses to deploy with the repository's blank operator profile, development artifacts, or an unapproved mainnet request. Live wallet/multisig submission and chain-provider verification remain operator-controlled integrations and require a reviewed deployment manifest.

Mainnet is never the default. A future live deploy adapter must require all of:

- exact reviewed source/artifact/image hashes;
- explicit `--network mainnet`;
- an interactive or environment approval reference;
- deployer/multisig policy approval;
- a dry-run summary that matches the submitted StateInit.

