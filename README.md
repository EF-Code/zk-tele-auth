# zk-tele-auth

Issuer-bound private Telegram authentication for Web3 and TON applications.

The gateway validates Telegram Mini App `initData` with the bot token, then produces a BLS12-381 Groth16 proof. The proof hides the Telegram user ID while binding the claim to an authorized gateway issuer, application domain, freshness policy, and optional Telegram Premium requirement.

The stable product is issuer-bound Telegram authentication for application backends and TON applications. Priva purchase authorization remains an opt-in experimental research surface under `zk-tele-auth/experimental/priva`; it is not production-supported, not part of the default release profile, and must not be treated as an asset-settlement product.

## Security model

Telegram HMAC verification happens off-circuit because the bot token must remain server-side. The gateway is therefore a trusted issuer. The circuit makes that trust independently verifiable by requiring knowledge of a stable private `issuerSecret` whose Poseidon commitment, `issuerKeyHash`, is pinned by every relying party.

A valid proof establishes all of the following:

- the prover knew the secret for the pinned issuer commitment;
- the hidden Telegram user ID was non-zero;
- the proof is bound to the expected application domain;
- Telegram `auth_date` met the pinned freshness window;
- the pinned Premium policy was satisfied; and
- the nullifier is stable for one issuer/user/domain tuple.

The gateway must remain trusted to validate Telegram correctly before proving. The proof does not reproduce Telegram's HMAC inside Circom. Rotate `issuerSecret` only as a planned identity migration: rotation changes the issuer commitment and every derived nullifier.

Committed proving artifacts use the reproducible development ceremony described below. They are not a production trusted setup.

## Architecture

```text
Telegram Mini App
  │ signed initData
  ▼
Gateway
  ├─ verifies Telegram HMAC and auth_date
  ├─ enforces Premium and age policy
  └─ proves knowledge of issuerSecret with hidden userId
       │
       ├─ dApp verifies Groth16 + pinned domain/issuer/policy
       └─ TON contract verifies the same proof and stores stable nullifier
```

The proving key is public. Security comes from the private issuer witness and the verifier-pinned `issuerKeyHash`, not from restricting access to the proving artifacts.

## Install and validate

```bash
npm install zk-tele-auth
npm run build
npm test
```

For repository development, clone the repository and run `npm ci` instead. Published consumers should import package entrypoints rather than deep paths under `dist/`.

`npm test` runs real Groth16 proofs, adversarial issuer/policy/replay regressions, private-leaf Merkle membership tests, verifier-key synchronization, and Tolk compilation.

The repository includes a generalized artifact manifest, cryptographic attestation verifier, a composed native-TON Priva launchpad, gateway readiness checks, deterministic TON dry-run tooling, package/container checks, and a fail-closed release preflight. Run `npm run release:preflight`; it remains non-zero until genuine ceremony, operator, attestation, and testnet evidence exists. Independent review is controlled by `independentReviewRequired` in the deployment profile and is explicitly waived for this personal-project profile.

Supply-chain hook behavior and the protected-release prerequisites are documented in [docs/supply-chain.md](docs/supply-chain.md).

## Configure the issuer gateway

Generate the issuer secret once and store it in a secret manager:

```bash
node --input-type=module -e "import { CryptoUtils } from 'zk-tele-auth'; console.log(CryptoUtils.randomFieldSecret())"
```

Create the gateway with an explicit policy:

```typescript
import { ZkTeleAuthGateway } from 'zk-tele-auth/gateway';

const gateway = new ZkTeleAuthGateway({
  botToken: process.env.TELEGRAM_BOT_TOKEN!,
  issuerSecret: process.env.ZK_TELE_AUTH_ISSUER_SECRET!,
  appDomain: 'mydapp.example',
  maxTokenAgeSec: 3600,
  requirePremium: true,
  corsOrigin: 'https://mydapp.example',
  maxConcurrentProofs: 2,
});

gateway.createServer().listen(8080);
```

The versioned HTTP gateway accepts `POST /v1/authentications` with `{ "schemaVersion": 1, "initData": "..." }`. `POST /authenticate` remains a deprecated compatibility alias for one release line. Use `zk-tele-auth/client` from a browser instead of hand-writing fetch calls. The gateway limits request bodies and proving work; put normal production rate limiting, TLS, observability, and secret management in front of it.

## Verify off-chain

The application must obtain `issuerKeyHash` out-of-band from its configured issuer; never trust the value supplied inside the proof.

```typescript
import { ZkAuthProofVerifier } from 'zk-tele-auth';

const result = await ZkAuthProofVerifier.verifyProof(proofPayload, {
  expectedAppDomain: 'mydapp.example',
  expectedIssuerKeyHash: process.env.ZK_TELE_AUTH_ISSUER_KEY_HASH!,
  maxTokenAgeSec: 3600,
  requirePremium: true,
});

if (!result.isValid) throw new Error(result.error);
```

Off-chain applications remain responsible for storing accepted nullifiers if authentication is intended to be one-time.

## Deploy on TON

The contract has no configure message. Its immutable domain, issuer, age, and Premium policy must be serialized into the contract's `StateInit` data. The contract address therefore commits to the policy and initialization cannot be won by a first caller.

```typescript
import {
  NullifierDeriver,
  buildTonVerifierStateInitData,
} from 'zk-tele-auth/ton';

const appDomainHash = await NullifierDeriver.hashAppDomain('mydapp.example');
const data = buildTonVerifierStateInitData({
  appDomainHash,
  issuerKeyHash: process.env.ZK_TELE_AUTH_ISSUER_KEY_HASH!,
  maxTokenAgeSec: 3600,
  requirePremium: true,
});

// Use `data` together with the compiled code cell in the deployment StateInit.
```

`contracts/zk_tele_auth_verifier.tolk` checks the Groth16 pairing equation, exact application policy, issuer commitment, chain time, and stable-nullifier replay dictionary. Verification messages must attach at least 0.05 TON. Use the stable TON message encoder and wrapper APIs for a complete wallet transaction; do not rely on repository-only test helpers.

The TON cell encoder is a runtime dependency; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for its license and provenance.

`npm run deploy:dry-run` only derives a deterministic generic-verifier deployment summary after a complete operator profile is supplied. It never submits a transaction. Mainnet submission and live-state verification require an approved multisig/operator adapter and a committed deployment manifest.

## Browser client

The browser-safe client sends Telegram `initData` to the trusted issuer gateway and validates response/error envelopes without importing Node filesystem or proving code:

```typescript
import { ZkTeleAuthClient } from 'zk-tele-auth/client';

const auth = new ZkTeleAuthClient({ baseUrl: 'https://auth.example' });
const result = await auth.authenticate({ initData: window.Telegram.WebApp.initData });
```

The client does not verify Groth16 proofs in the browser. Verify proofs in an application backend or use the stable TON verifier path.

## Experimental Priva purchase authorization

Priva APIs are intentionally excluded from the stable root export and stable quickstart:

```typescript
import { PrivaPurchaseAuthProofVerifier } from 'zk-tele-auth/experimental/priva';
```

The experimental route is disabled by default and cannot be enabled by the production gateway configuration. The current launchpad records native-TON accounting and refundable credits but does not settle jettons/NFTs or provide a reviewed credit-withdrawal adapter. Treat all Priva artifacts, contracts, deployment profiles, and network behavior as experimental until separate ceremony, audit, economic review, and testnet evidence gates pass.

## Private Merkle membership primitive

`membership.circom` proves membership in a depth-12 Poseidon tree while keeping the leaf and path private. Only `[isMember, root]` are public, an incorrect root is unsatisfiable, and `verifyMembershipProof` pins the expected root.

This is a generic whitelist primitive. A production Telegram channel integration must separately define how an authorized service constructs and publishes the member root; the circuit alone does not query Telegram channel membership.

## Trusted setup and artifacts

```bash
npm run setup:circuits
npm run artifacts:verify:dev
```

This compiles both circuits over BLS12-381 and regenerates the R1CS, WASM, proving key, verification key, and manifests. The repository's phase-2 beacon is deterministic for reproducible development builds.

For production, use `npm run artifacts:import:production -- --source-dir <verified-export> --ptau <verified-transcript> --expected-ptau-sha256 <digest> --commit <full-commit> --network <testnet|mainnet> --import` with an independently verified external transcript. The importer never creates ceremony material or marks the manifest approved; a cryptographic signature remains mandatory, while independent review follows the deployment profile policy. After changing `telegram_auth.circom`, regenerate the TON verifier constants with `export-ton-verifier`; `npm test` fails if the embedded contract key is stale.

### Priva purchase artifact release gate

`artifacts/priva_purchase_auth/provenance.json` records SHA-256 hashes for the circuit, proving artifacts, verification key, and generated Tolk verifier. Verify the committed development artifact set with:

```bash
npm run check:priva-artifacts
```

The production gate deliberately fails for the checked-in artifacts:

```bash
npm run check:priva-production
```

It may pass only after replacing the development setup with a reviewed public or independently operated MPC ceremony and recording the regenerated artifact hashes in a cryptographically signed `production-attestation.json`. If the deployment profile requires independent review, that record must also cover the circuit, verifier, and any enabled Priva launchpad integration. Do not mark `provenance.json` as production or add an attestation merely to satisfy this command; those records must correspond to the actual ceremony and reviewed deployment artifact set.

## Repository layout

```text
circuits/       issuer-bound authentication and private membership circuits
artifacts/      committed development R1CS/WASM/zkey/vkey artifacts
src/sdk/        proof generation, verification, membership and TON StateInit helpers
src/gateway/    Telegram HMAC validation and bounded server-side prover
    contracts/      issuer/policy-bound verifiers and composed Priva launchpad
tests/          cryptographic and adversarial regression tests
examples/       Telegram Mini App gateway client
```
