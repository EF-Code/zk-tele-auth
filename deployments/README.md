# Deployment evidence

Commit only non-secret manifests that bind a live deployment to the exact source commit, artifact manifest digest, code/data hashes, network, address, transaction reference, and independent provider verification. Do not commit wallet keys, RPC tokens, raw credentials, or private operator data.

`deployments/testnet/manifest.json` is required for the release preflight once a real testnet canary has been deployed and independently checked. A placeholder or locally generated manifest is not evidence.

