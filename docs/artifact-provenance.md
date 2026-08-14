# Artifact provenance and release evidence

The checked-in artifacts are a reproducible development set and are explicitly marked `development-only`. `npm run artifacts:verify:dev` verifies every manifest digest and re-exports each verification key from the final zkey. It does not prove a trusted setup.

Production imports are intentionally separate. `scripts/import-production-artifacts.mjs` requires an operator-supplied phase-one transcript, an independently reviewed transcript SHA-256, a full source commit, a target network, and `snarkjs.zKey.verify` success for every selected circuit. It never creates entropy, copies the transcript into the repository, or changes a status to production-approved.

The v2 manifest (`artifacts/manifest.json`) hash-links circuit sources, R1CS, WASM, zkey, verification key, generated Tolk verifier, the composed Priva launchpad, and circuit metadata. Each circuit also declares `runtimeFiles`; a production image may omit source/R1CS review material while readiness still verifies every attested runtime WASM/zkey/vkey hash. A production attestation must sign the canonical JSON payload with a trusted Ed25519 key listed in `config/attestation-trust.json`. The verifier checks signer identity, network allowlist, validity window, reviewed commit, manifest digest, circuit file hashes, expiry, and signature bytes. A JSON status label is never sufficient.

Never commit phase-one toxic waste, contribution entropy, bot tokens, issuer secrets, deployer keys, or raw private ceremony workspaces. Ceremony logs and hash manifests belong in an external evidence bundle referenced by the signed attestation.

Evidence labels used throughout the repository are:

- `demonstrated locally`: executable tests or deterministic compiler output in this checkout;
- `demonstrated on testnet`: a signed, independently checked deployment manifest and canary evidence;
- `independently reviewed`: a reviewer record names the exact commit and artifact hashes;
- `blocked`: an external requirement has not been supplied and cannot be inferred.
