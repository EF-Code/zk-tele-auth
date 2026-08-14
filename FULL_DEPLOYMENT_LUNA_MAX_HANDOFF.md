# zk-tele-auth full-production deployment handoff for Luna Max

## Mission

Bring this repository from a locally validated/testnet-capable cryptographic prototype to a production-deployable Telegram-to-ZK authorization service and TON integration.

Do not interpret this document as permission to claim production readiness merely because local tests pass. Production readiness requires both implementable repository work and external evidence that an AI agent cannot manufacture, including a real trusted-setup ceremony, independent review, production credentials, operator decisions, and successful testnet/mainnet transactions.

The implementation must remain fail-closed. If required external evidence is absent, the repository must clearly report `NOT PRODUCTION READY` and the production release command must exit non-zero.

## Baseline inspected on 2026-08-14

- Repository: `zk-tele-auth`
- Branch: `main`
- Inspected revision: `059126368c5afa16919c48d599f787324fea2bd7`
- Local `main` matched `origin/main` and the worktree was clean.
- The Git remote did not embed credentials.
- Common GitHub PAT signatures had zero hits in tracked files and reachable Git history.
- `npm run build`: passed.
- `npm test`: passed, with 33 SDK/circuit regression tests and 4 TON sandbox tests.
- Generated Tolk verifier constants matched the checked-in verification keys.
- `npm audit --audit-level=high`: zero reported vulnerabilities.
- `npm run check:priva-production`: failed as designed.
- `artifacts/priva_purchase_auth/production-attestation.json`: absent.
- No `.github/` workflow, Dockerfile, deployment directory, committed deployed-address manifest, or live-chain evidence existed.

Re-check all of this before editing. Do not assume the revision or dependency state is unchanged.

## Current security model that must be preserved

1. Telegram Mini App `initData` is authenticated by the gateway using the Telegram bot token.
2. Telegram HMAC verification is off-circuit, making the gateway a trusted issuer.
3. The circuit requires knowledge of a private stable `issuerSecret`.
4. Relying parties pin the corresponding `issuerKeyHash`; they must never accept that value merely because it appears in a proof payload.
5. The generic identity nullifier is stable for `(issuer, user, app domain)`.
6. The generic TON verifier commits its app domain, issuer, freshness, and Premium policy through immutable `StateInit` data.
7. The Priva circuit additionally binds a purchase authorization to launch, launchpad, operation, recipient, nonce, expiry, and circuit version.
8. The Priva generated verifier is a cryptographic primitive only. The launchpad must enforce replay protection, identity caps, payment rules, and settlement atomically.

Do not weaken these properties for API convenience. In particular, do not make `issuerSecret`, bot tokens, deployer mnemonics, or signing keys client-visible; do not make verifier policy caller-configurable; and do not replace stable/action-scoped nullifiers with random salts.

## Non-negotiable rules for the implementation agent

- Inspect the current checkout and preserve unrelated user changes.
- Never print secrets or `.env` values. Credential diagnostics may report presence only.
- Never generate fake ceremony evidence, fake auditor approval, fake transaction hashes, or a self-signed “independent” approval.
- Never change `provenance.json` to `production` merely to make a test pass.
- Never deploy the standalone Priva verifier wrapper as if it were a complete launchpad.
- Never deploy to mainnet automatically. Mainnet deployment requires an explicit operator confirmation, an exact reviewed artifact manifest, and a dry-run summary.
- Use deterministic serialization and canonical hashing at every TypeScript/Tolk boundary. Add cross-language test vectors.
- Keep cryptographic artifacts, generated verifier constants, source circuits, and deployment manifests hash-linked.
- Pin production tool/runtime versions. Do not silently regenerate verification keys during ordinary builds.
- Use focused commits. Do not mix ceremony artifacts, contract behavior, infrastructure, and documentation into one opaque commit.
- Treat local emulation as local evidence only. Do not describe sandbox tests as public-network proof.

## Decisions the operator must provide

Create `docs/production/OPERATOR_INPUTS.md` as a fillable checklist. The production preflight must fail until every required value is supplied and validated.

Required decisions:

- target product scope: generic Telegram authentication, Priva purchase authorization, membership primitive, or an explicit combination;
- testnet and mainnet network identifiers;
- canonical application domain;
- Telegram bot/application ownership and bot-token secret-manager reference;
- stable issuer-secret secret-manager reference;
- pinned `issuerKeyHash` obtained independently from the configured issuer;
- `maxTokenAgeSec`, allowed clock skew, Premium requirement, and maximum purchase-authorization TTL;
- canonical Priva launchpad contract address and launch identifier encoding;
- recipient-binding rule and address-hashing specification;
- per-identity and per-launch purchase caps;
- pricing, accepted asset, refund, bounce, and settlement rules;
- deployer wallet or multisig policy, approvers, and funding limits;
- hosting environment, region, replica count, reverse proxy/load balancer, and secret manager;
- RPC/indexer providers and a secondary verification provider;
- logging retention, privacy policy, alert destination, incident owner, and rollback/migration owner;
- independent reviewer/auditor and the exact reviewed commit/artifact hashes.

Do not invent defaults for financial policy, addresses, or ownership. Safe technical defaults may be proposed, but production preflight must distinguish proposed values from operator-approved values.

## Workstream 1: replace development-only trusted setup with verifiable production artifacts

### Current gap

`scripts/setup-circuits.cjs` generates a local reproducible phase-one contribution and deterministic phase-two beacon. The repository explicitly says these artifacts are development-only. This affects `telegram_auth`, `priva_purchase_auth`, and `membership`, not only Priva.

The existing Priva production checker verifies file hashes and checks JSON fields, but it does not cryptographically verify that an independent party signed the attestation. A JSON object saying `production-approved` is not an approval.

### Required repository work

1. Split artifact generation into explicit development and production workflows:
   - keep `setup:circuits:dev` for reproducible local tests;
   - add a production import/verification workflow that accepts an externally supplied BLS12-381 phase-one transcript and circuit-specific Groth16 phase-two outputs;
   - production workflow must never use `DEFAULT_ENTROPY`, a repository-known beacon, or unattended single-party entropy;
   - require expected transcript hashes from a reviewed configuration, not from the downloaded file itself.
2. Create a generalized provenance schema for every production circuit, not only Priva. It must include:
   - schema version and circuit version;
   - Git commit containing the exact circuit source;
   - Circom, snarkjs, Node, exporter, and Tolk compiler versions;
   - curve and constraint count;
   - phase-one transcript identifier, origin, digest, verification command, and verification result digest;
   - phase-two contribution/transcript identifiers and verification result digest;
   - SHA-256 hashes for `.circom`, `.r1cs`, `.wasm`, final `.zkey`, verification key, generated Tolk verifier, wrapper/integration contract, and relevant public-signal schema;
   - UTC generation time and reproducible command list;
   - status restricted to a schema enum.
3. Add cryptographic attestation verification:
   - choose one documented mechanism such as Sigstore/cosign, minisign, or detached Ed25519 signatures;
   - pin approved reviewer/ceremony public keys or trusted identities in a reviewed policy file;
   - verify signature, signer identity, payload digest, artifact digests, reviewed commit, and intended network;
   - reject expired, revoked, unknown, malformed, duplicated, or mismatched attestations;
   - do not store private signing keys in this repository or CI.
4. Add commands such as:
   - `npm run artifacts:verify:dev`;
   - `npm run artifacts:verify:production`;
   - `npm run release:preflight`.
5. Make production checks cover all circuits selected in the operator deployment profile.
6. Make generated Tolk-verifier synchronization checks use the attested production verification key.
7. Store ceremony verification logs and machine-readable hash manifests as release evidence, without committing toxic waste or secret contribution entropy.

### External gate that Luna cannot complete

- Obtain or conduct an appropriate BLS12-381 ceremony with independent participation.
- Independently verify phase-one and each circuit-specific phase-two transcript.
- Securely destroy contribution entropy/toxic waste.
- Have authorized independent reviewers sign the exact manifest after reviewing the exact commit and artifacts.

### Acceptance criteria

- Production verification fails against the current development artifacts.
- Modifying any covered source, artifact, verifier constant, version, network, or reviewed commit invalidates production verification.
- A signature-shaped but untrusted or mismatched attestation is rejected.
- The final zkey is checked against the exact R1CS and verified phase-one file with `snarkjs zkey verify`.
- The exported verification key is regenerated from the final zkey and byte/structure compared with the committed key.
- The contract verifier is regenerated from that key and its code hash is recorded.
- No ceremony secrets appear in Git, CI logs, build caches, container layers, or release archives.

## Workstream 2: complete the Priva launchpad contract composition

### Current gap

`contracts/priva_purchase_auth_verifier.tolk` exposes cryptographic verification. `contracts/priva_purchase_auth_verifier_wrapper.tolk` only accepts enough value and verifies a proof. It does not provide launch state, payment validation, replay persistence, cumulative identity caps, recipient enforcement tied to actual settlement, refunds, or bounce-safe accounting.

The current TON sandbox suite exercises the generic `zk_tele_auth_verifier.tolk`; it does not exercise a complete Priva purchase state transition.

### Required design invariants

- **Authorization:** only an authorization pinned to the configured issuer, app domain, launch, launchpad, BUY operation, recipient, TTL, and circuit version can purchase.
- **Action replay:** an `actionNullifier` can cause at most one accepted state transition.
- **Identity cap:** changing `clientNonce` cannot bypass cumulative per-identity/per-launch limits.
- **Recipient authenticity:** the public `recipientHash` must be derived canonically from the actual credited recipient, not from an untrusted duplicated request field.
- **Launch binding:** `launchpadAddressHash` must bind to the executing contract address using one documented workchain/address encoding.
- **Atomicity:** replay markers, identity totals, inventory, payment accounting, and settlement cannot diverge across compute/action failures or bounced messages.
- **Value conservation:** accepted value, fees, token allocation, refunds, and storage reserves reconcile on success and failure.
- **Expiry:** both proof timestamp and authorization expiry are checked against chain time and immutable/configured limits.
- **Initialization:** launch and verifier policy cannot be first-caller configured or silently changed.
- **Liveness/storage:** attacker-controlled dictionary growth or underfunded messages cannot make honest purchases permanently unaffordable.

### Required implementation

1. Add or integrate the actual launchpad contract in this repository, or include it as a pinned auditable dependency/submodule with the exact reviewed revision. A mock integration is insufficient for production approval.
2. Import the Priva verifier core and call it synchronously inside the purchase handler.
3. Parse the 15 public signals in exactly the circuit/snarkjs order. Validate canonical field bounds before using them.
4. Re-check every application-level public signal on-chain. Cryptographic validity alone is insufficient.
5. Derive canonical hashes for:
   - app domain;
   - launch identifier;
   - executing launchpad address including workchain rules;
   - recipient address;
   - operation and circuit version.
   Publish identical TypeScript and Tolk test vectors.
6. Store consumed action nullifiers atomically before or with the purchase state update according to TVM transaction semantics.
7. Store cumulative purchased amount keyed by identity nullifier and launch. Enforce the cap independently of `clientNonce`.
8. Define duplicate-message idempotency. A replay must not double-spend, double-credit, or produce ambiguous partial success.
9. Validate attached value, price/quote freshness, min/max amount, accepted asset, inventory, recipient, and launch status.
10. Reserve enough balance for storage and processing. Define refund behavior for overpayment and rejected purchases.
11. Handle or deliberately avoid asynchronous downstream actions. If tokens/funds are forwarded, implement and test bounce/failure reconciliation.
12. Add getters for deployment verification and operations, but never use unauthenticated getters as authorization inputs.
13. Define upgradeability explicitly. Prefer immutable code for a narrowly scoped launch; if upgrades are required, use a multisig-controlled, timelocked, storage-layout-safe path with an emergency policy and tests.

### Mandatory Priva sandbox tests

- valid production-shaped proof and purchase succeeds;
- exact action replay fails without state drift;
- same identity plus new nonce remains subject to cumulative cap;
- different identity follows its own cap;
- wrong issuer, domain, launch, launchpad, recipient, operation, version, Premium policy, or TTL fails;
- expired and unreasonably future-dated authorizations fail;
- proof valid under a different verification key fails;
- malformed proof points, exotic cells, trailing data, wrong public-signal count, negative/scalar-overflow inputs, and malformed ref chains fail;
- insufficient value and exact boundary values behave as specified;
- overpayment refund behavior is verified;
- downstream bounce/action failure leaves accounting consistent;
- duplicate query/message ordering cannot create a double purchase;
- storage growth and gas consumption are measured at realistic dictionary sizes;
- deployment with empty/malformed StateInit cannot accept a purchase;
- contract address and code/data hashes match deployment tooling.

Use `@ton/sandbox` and Acton/Tolk tooling for executable evidence. Add TSA custom properties for replay, cap preservation, authorization binding, and value conservation where supported. A zero-finding default TSA run is not a substitute for project-specific invariants.

## Workstream 3: harden and package the issuer gateway

### Current gap

The gateway is a library class with a minimal Node HTTP server. It has body-size and in-process concurrency bounds, but lacks a production executable, schema validation, health/readiness endpoints, request timeouts, durable/distributed throttling, structured redacted telemetry, graceful shutdown, container hardening, and deployment configuration.

### Required implementation

1. Add a production entrypoint, for example `src/gateway/main.ts`, that:
   - loads configuration from validated environment variables or secret-manager adapters;
   - fails before listening if required values are missing or inconsistent;
   - reports secret presence only and never logs values;
   - derives and compares the expected issuer commitment at startup;
   - verifies the selected production artifact manifest and signature before readiness becomes true;
   - supports graceful `SIGTERM`/`SIGINT`, stops accepting work, drains bounded in-flight proofs, and exits non-zero on failed shutdown.
2. Define a versioned request/response schema for `/authenticate` and `/v1/purchase-authorizations`:
   - require `application/json`;
   - reject unknown or duplicate semantic fields where ambiguity matters;
   - enforce canonical strings, bounded lengths, safe integers, and exact operation/version enums;
   - return stable machine-readable error codes;
   - do not return stack traces, filesystem paths, secret-derived values, or raw internal exceptions.
3. Add `/livez`, `/readyz`, and `/metrics`:
   - liveness must not perform expensive proofs;
   - readiness must verify artifacts/configuration and prover-worker availability without exposing secrets;
   - metrics must exclude Telegram `initData`, user IDs, proof payloads, nullifiers, nonces, and tokens.
4. Harden HTTP behavior:
   - header/body/request/idle timeouts;
   - aborted-stream and socket-error handling;
   - exact CORS allowlist and correct preflight behavior;
   - security headers appropriate to an API;
   - proxy trust configured explicitly rather than inferred;
   - consistent 400/401/403/409/413/415/422/429/500/503 mapping.
5. Isolate proving work:
   - use a bounded worker pool or separate prover service/process so CPU-heavy proofs do not block health and shutdown paths;
   - bound queue depth, proof duration, memory, and concurrency;
   - reject overload before allocating large witness/proof work;
   - document multi-replica behavior. The current in-memory `activeProofs` counter is not a distributed rate limit.
6. Add layered abuse protection:
   - edge/reverse-proxy rate limiting;
   - application queue/concurrency limiting;
   - idempotency policy for purchase-authorization requests;
   - safe limits by source/session without logging private Telegram material;
   - alerting for invalid HMAC bursts, proof failures, saturation, and latency.
7. Add structured logs with request IDs and an explicit redaction function. Test that logs never contain bot tokens, issuer secrets, raw `initData`, Telegram user JSON/IDs, proofs, nullifiers, or client nonces.
8. Add a secret-provider interface and production adapters/documentation. Do not require secrets to be baked into images or files. Explain that rotating `issuerSecret` changes the issuer commitment and all stable nullifiers, so it is a planned migration, not routine transparent rotation.
9. Add resource and performance tests using realistic proof generation. Define measured p50/p95/p99 proof latency, memory high-water mark, saturation behavior, and safe replica/concurrency settings for the chosen host.
10. Add an API threat model covering forged/tampered Telegram data, replay, proof-generation DoS, malicious JSON, CORS misuse, reverse-proxy spoofing, secret compromise, artifact substitution, insider issuer abuse, and dependency compromise.

### Telegram-specific tests

- official HMAC-valid fixture accepted;
- altered parameter, altered user JSON, missing hash, malformed hex, duplicate parameters, unusual Unicode/encoding, and reordered parameters tested;
- expired and future `auth_date` boundaries tested;
- invalid/missing user ID and malformed JSON rejected;
- raw request and logs remain secret/private-data free;
- validation matches Telegram's current documented algorithm.

The bot token means the gateway can mint issuer-valid proofs after compromise. Document this trust boundary prominently; ZK does not eliminate it.

## Workstream 4: deployment tooling and reproducible on-chain verification

### Required implementation

1. Add `deploy/` with typed, network-aware scripts for compile, derive address, dry-run, deploy, and verify.
2. Production deployment configuration must reference values by environment/secret-manager identifier and must not contain secrets.
3. Serialize StateInit deterministically and emit a review summary containing:
   - network;
   - source commit;
   - circuit/artifact manifest digest;
   - contract code hash and data hash;
   - derived address;
   - app-domain hash and human-readable domain;
   - issuer-key hash;
   - freshness/Premium/action policy;
   - expected funding and fee ceiling.
4. Mainnet scripts must default to dry-run and require explicit network plus operator confirmation. Never select mainnet from a permissive default.
5. After deployment, query and verify the live account's code hash, data/policy getters, address, balance, and active status.
6. Record an immutable deployment manifest under `deployments/<network>/` with transaction hash, logical time/block reference, deployed address, hashes, RPC sources, UTC time, and operator approvals. Do not record mnemonics or API tokens.
7. Cross-check material live state with two independent providers or one provider plus a raw-chain proof/source.
8. Add scripts to submit a canary valid proof and deliberate invalid/replay proofs on testnet, then record exit codes and state deltas.
9. Add gas/storage benchmarking for proof verification and replay dictionaries. Replace the hard-coded minimum attached value only after measurement and document the safety margin.
10. Add a migration plan for issuer-key rotation, circuit-version changes, verifier replacement, and app-domain changes. Since immutable StateInit changes the address, migrations require new-address publication and consumer updates.

## Workstream 5: packaging, container, and runtime supply chain

### Package work

- Add explicit `exports` for the SDK and gateway entrypoints, including type declarations.
- Add a restrictive `files` allowlist so npm packages contain only intended runtime code/artifacts/docs.
- Add supported Node `engines` and test on an LTS Node release. The inspected local runtime was Node 26; do not assume a non-LTS development runtime is the production target.
- Decide whether `.r1cs` and source circuits belong in the runtime package. Provers normally need WASM and zkey; verifiers need vkey. Avoid shipping unnecessary large files to production images.
- Test `npm pack`, install the tarball into a fresh temporary consumer, import every public entrypoint, and generate/verify a proof from the installed package.
- Keep artifact resolution safe and explicit. A production deployment should not silently use artifacts from an unexpected environment-controlled directory without manifest verification.

### Container work

- Add a multi-stage Dockerfile pinned by digest or otherwise reproducibly versioned.
- Run as a non-root user with a read-only root filesystem where practical.
- Copy only production dependencies and attested runtime artifacts.
- Add OCI labels for source revision and artifact-manifest digest.
- Include health checks without embedding credentials.
- Provide CPU/memory limits, temporary-directory policy, dropped capabilities, and no-new-privileges guidance.
- Add `.dockerignore` that excludes `.git`, development artifacts, logs, environment files, ceremony workspaces, and secrets.
- Generate an SBOM and vulnerability scan result for the release image.
- Sign the release image and record its immutable digest in the deployment manifest.

## Workstream 6: CI/CD and repository release controls

No `.github/` automation existed at the inspected revision. Add workflows with least-privilege permissions and third-party actions pinned to immutable commit SHAs.

### Pull-request CI

- clean install from lockfile;
- TypeScript build/type check;
- complete unit/circuit/adversarial suite;
- generic and Priva TON sandbox tests;
- Tolk compilation and verifier-key synchronization;
- development provenance checks;
- lint/format checks;
- `npm audit` or an approved dependency scanner;
- secret scanning;
- package-consumer smoke test;
- container build and non-secret smoke test;
- generated-file drift check;
- fail if production status/attestation is changed without the designated protected review path.

### Release CI

- trigger only from a protected, reviewed tag/commit;
- verify signed commit/tag if adopted by project policy;
- verify ceremony/artifact attestations cryptographically;
- rebuild or validate artifacts and compare hashes;
- produce package/image SBOMs and provenance;
- sign package/image outputs;
- never expose bot tokens, issuer secrets, deployer keys, or ceremony entropy to untrusted pull-request jobs;
- require an environment approval before any testnet/mainnet mutation;
- separate build identity from deployer/multisig authority;
- publish exact immutable digests and a release evidence bundle.

Configure branch protection outside the repository: required checks, required reviews, no force-pushes, restricted environment secrets, and CODEOWNERS for circuits, generated verifiers, contracts, artifact manifests, deployment scripts, and CI workflows.

## Workstream 7: expand test and security assurance coverage

### Circuit tests

- Verify every public signal position and range with named cross-language vectors.
- Add boundary tests for 64-bit timestamps and comparator inputs.
- Test zero, field modulus, modulus minus one, negative encodings, unsafe JavaScript integers, and non-canonical decimal forms.
- Test issuer/domain separation and both stable/action nullifier collision assumptions through deterministic vectors.
- Test witness generation failure is expected and asserted without treating noisy Circom output as a suite failure.
- Run circuit constraint inspection and document unconstrained-signal checks.
- Verify final production zkeys against R1CS and phase-one transcript in CI/release preflight.

### Generic TON verifier tests

- malformed StateInit cells and trailing data;
- malformed proof/public-input cells and exotic cells;
- every policy mismatch and timestamp boundary;
- insufficient/exact/excess attached value;
- nullifier replay under message reordering;
- storage growth, storage fees, and `verifiedCount` overflow assumptions;
- contract balance survival and repeated invalid-message behavior;
- canonical code/data/address hash vectors.

### End-to-end tests

- Telegram fixture -> gateway -> Groth16 proof -> off-chain verifier;
- Telegram fixture -> gateway -> generic TON sandbox acceptance/replay;
- Telegram fixture -> Priva authorization -> composed launchpad purchase;
- packaged/containerized gateway uses the exact attested artifacts;
- testnet deployment accepts a canary and rejects wrong-policy/replay cases.

### Independent review gate

Obtain an independent review covering:

- circuits and constraint completeness;
- trusted-setup transcript and artifact linkage;
- generated BLS12-381 TON verifier correctness;
- Tolk message parsing and TVM execution semantics;
- Priva launchpad composition, economics, replay/caps, and bounce paths;
- gateway/API, secrets, abuse resistance, and deployment infrastructure;
- release/provenance controls.

The review must identify the exact commit and artifact hashes. All material findings must be fixed, regression-tested, and re-reviewed before production approval.

## Workstream 8: observability, privacy, incident response, and operations

Create production runbooks under `docs/operations/`:

- deployment and post-deployment verification;
- rollback for gateway/image changes;
- immutable-contract migration for circuit/verifier/policy changes;
- Telegram bot-token compromise;
- issuer-secret compromise and nullifier migration;
- deployer/multisig compromise;
- proving-artifact or ceremony-integrity failure;
- RPC/provider outage and provider disagreement;
- proof latency/saturation incident;
- suspected forged authorization or replay attempt;
- emergency pause policy, if the actual launchpad supports one;
- backup/recovery of non-secret configuration, manifests, and monitoring state.

Define alerts and SLOs for availability, readiness failures, proof latency, queue saturation, invalid-HMAC rate, proof self-check failures, on-chain rejection rates by exit code, contract balance/storage margin, RPC divergence, and release-attestation failure.

Privacy requirements:

- never log raw `initData`, Telegram user JSON/ID, bot token, issuer secret, proof witness, nullifier, or nonce;
- document what metadata is retained, why, where, for how long, and who can access it;
- prefer aggregate metrics and short-lived request IDs;
- document user-facing privacy/security limitations, including gateway trust and stable pseudonymous nullifiers;
- validate applicable legal/compliance obligations with a qualified human. Luna must not claim legal compliance.

## Workstream 9: documentation deliverables

Update the public README and add focused documents:

- `docs/architecture.md`: components, trust boundaries, data flow, public/private values;
- `docs/threat-model.md`: assets, attacker capabilities, abuse paths, invariants, mitigations, residual risks;
- `docs/artifact-provenance.md`: ceremony/import/verification/attestation process;
- `docs/gateway-production.md`: configuration, secret references, endpoints, limits, deployment;
- `docs/ton-deployment.md`: deterministic StateInit, address derivation, deployment and verification;
- `docs/priva-integration.md`: exact public-signal schema, canonical hashes, replay/cap/economic requirements;
- `docs/operations/*`: runbooks described above;
- `SECURITY.md`: supported versions, private reporting channel, response expectations;
- release checklist and release evidence format.

Every claim must say whether it is demonstrated locally, demonstrated on testnet, independently reviewed, or still pending. Avoid phrases such as “secure,” “audited,” or “production ready” without scoped evidence.

## Required production preflight command

Implement one fail-closed command, preferably `npm run release:preflight`, that produces both human-readable output and a machine-readable JSON report.

It must verify at least:

- clean or explicitly reproducible source revision;
- approved Node/package-manager/tool versions;
- lockfile install and full test suite;
- selected deployment profile is complete;
- every selected circuit has verified production provenance;
- cryptographic attestation signatures and signer policy;
- circuit/R1CS/WASM/zkey/vkey/verifier/integration hashes;
- generated verifier constants and contract compilation;
- composed Priva sandbox suite, if Priva is selected;
- package and container smoke tests;
- independent-review record references the exact commit/artifacts;
- deployment manifest is internally consistent;
- no secret values are present in tracked files, package, image, or evidence bundle;
- testnet evidence exists and matches the release candidate;
- mainnet remains a separate explicitly approved action.

The report must list each gate as `pass`, `fail`, `blocked`, or `not-applicable`, with a reason and evidence path. `blocked` is not success. The command exits zero only when every required gate is `pass` or legitimately `not-applicable` under the reviewed deployment profile.

## Recommended implementation order and commit structure

Use small reviewable commits. A sensible sequence is:

1. document deployment profile schema and operator inputs;
2. add generalized artifact-manifest schema and development verification;
3. add signed production-attestation verification and negative tests;
4. add canonical Priva address/launch/recipient hashing vectors;
5. integrate the verifier core into the real launchpad state transition;
6. add Priva replay/cap/value/bounce sandbox tests;
7. add production gateway entrypoint, schemas, timeouts, redaction, health, and shutdown;
8. add bounded prover workers, overload controls, and performance tests;
9. add deterministic deploy/dry-run/live-verification tooling;
10. add package exports, consumer smoke test, and production container;
11. add CI, release preflight, SBOM/provenance, and secret scanning;
12. add threat model, operational runbooks, release checklist, and evidence templates;
13. import the externally generated ceremony artifacts in a dedicated reviewed commit;
14. apply independent-review remediations in finding-specific commits;
15. record testnet evidence and finalize the production candidate.

Do not squash away security-relevant artifact history unless the owner explicitly requests it. Never rewrite public history just to make generated-artifact changes look cleaner.

## Final test matrix before a production recommendation

Run and preserve exact output for:

```bash
npm ci --no-audit --no-fund
npm run build
npm test
npm run artifacts:verify:production
npm run release:preflight
npm audit --audit-level=high
npm pack --dry-run
```

Also run:

- fresh tarball-consumer tests;
- production image build, scan, signature verification, and runtime smoke tests;
- Acton/Tolk compilation and project-specific TSA checks;
- generic verifier and composed Priva sandbox suites;
- load/resource tests on production-equivalent hardware;
- testnet deploy, live-state verification, valid canary, wrong-policy case, expired case, and replay case;
- independent verification of artifact, image, contract code/data, and deployment-manifest hashes.

Record tool versions and UTC timestamps. Redact credentials without destroying useful evidence.

## Definition of full deployment readiness

The project may be recommended for production only when all of the following are true:

- operator decisions are complete and reviewed;
- selected circuits use independently verified production ceremony artifacts;
- attestations are cryptographically verified, not label-checked;
- exact artifacts and generated verifiers are hash-linked to the reviewed source revision;
- the actual Priva launchpad composition exists and enforces replay, caps, recipient binding, value conservation, and bounce-safe settlement;
- gateway production hardening, secret management, rate limiting, observability, and graceful operations are implemented and tested;
- deterministic deployment and live-verification tooling exists;
- CI/release controls and immutable build provenance are active;
- package/image/runtime supply-chain checks pass;
- full sandbox, adversarial, load, and testnet validation passes;
- an independent review of the exact release candidate is complete and material findings are closed;
- runbooks, monitoring, alerting, ownership, and incident procedures are in place;
- `npm run release:preflight` exits zero against the exact release commit;
- the release candidate is unchanged between approval and deployment;
- mainnet deployment receives explicit operator/multisig approval.

Until then, the correct status is **controlled local/testnet candidate, not full production deployment**.

## External references

- Telegram Mini Apps validation: <https://core.telegram.org/bots/webapps#validating-data-received-via-the-mini-app>
- snarkjs ceremonies and zkey verification: <https://github.com/iden3/snarkjs>
- TON contract testing overview: <https://docs.ton.org/contracts/blueprint/testing/overview>

Use current primary documentation during implementation, but pin behavior with repository tests and exact tool versions.

