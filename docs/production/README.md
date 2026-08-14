# Production release evidence

Production evidence is kept outside ordinary development artifacts and must be linked to an exact source commit and release manifest. This directory contains only non-secret templates and operator-controlled configuration.

The following are external gates and must not be fabricated by CI or an AI agent:

- an independently verified BLS12-381 ceremony/transcript;
- a signed production artifact attestation from a trusted reviewer key;
- an independent review of circuits, generated verifier, and actual launchpad composition;
- a testnet deployment and canary transaction evidence;
- operator/multisig approval for any mainnet mutation.

Use `npm run release:preflight` to produce a machine-readable report. A `blocked` gate is a failed release gate, not an implicit approval.
