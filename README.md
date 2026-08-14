# zk-tele-auth

Issuer-bound private Telegram authentication for Web3 and TON applications.

The gateway validates Telegram Mini App `initData` with the bot token, then produces a BLS12-381 Groth16 proof. The proof hides the Telegram user ID while binding the claim to an authorized gateway issuer, application domain, freshness policy, and optional Telegram Premium requirement.

For a Priva purchase, use `priva_purchase_auth`, not the generic credential proof. It additionally binds a stable identity nullifier and one-time action nullifier to the launch ID, launchpad, recipient, `BUY` operation, expiry, and circuit version. Its generated Tolk verifier is cryptographic-only and must be composed into the launchpad's state transition; deploying it alone does not enforce caps or replay protection.

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
npm install
npm run build
npm test
```

`npm test` runs real Groth16 proofs, adversarial issuer/policy/replay regressions, private-leaf Merkle membership tests, verifier-key synchronization, and Tolk compilation.

Production work is tracked in [FULL_DEPLOYMENT_LUNA_MAX_HANDOFF.md](FULL_DEPLOYMENT_LUNA_MAX_HANDOFF.md). The repository includes a generalized artifact manifest, cryptographic attestation verifier, gateway readiness checks, deterministic TON dry-run tooling, package/container checks, and a fail-closed release preflight. Run `npm run release:preflight`; it is expected to remain non-zero until genuine ceremony, operator, independent-review, launchpad-composition, and testnet evidence exists.

## Configure the issuer gateway

Generate the issuer secret once and store it in a secret manager:

```bash
node --input-type=module -e "import { CryptoUtils } from './dist/sdk/index.js'; console.log(CryptoUtils.randomFieldSecret())"
```

Create the gateway with an explicit policy:

```typescript
import { ZkTeleAuthGateway } from './dist/gateway/server.js';

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

The HTTP gateway accepts `POST /authenticate` with `{ "initData": "..." }`. It limits request bodies and concurrent proving work. Put normal production rate limiting, TLS, observability, and secret management in front of it.

## Verify off-chain

The application must obtain `issuerKeyHash` out-of-band from its configured issuer; never trust the value supplied inside the proof.

```typescript
import { ZkAuthProofVerifier } from './dist/sdk/index.js';

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
} from './dist/sdk/index.js';

const appDomainHash = await NullifierDeriver.hashAppDomain('mydapp.example');
const data = buildTonVerifierStateInitData({
  appDomainHash,
  issuerKeyHash: process.env.ZK_TELE_AUTH_ISSUER_KEY_HASH!,
  maxTokenAgeSec: 3600,
  requirePremium: true,
});

// Use `data` together with the compiled code cell in the deployment StateInit.
```

`contracts/zk_tele_auth_verifier.tolk` checks the Groth16 pairing equation, exact application policy, issuer commitment, chain time, and stable-nullifier replay dictionary. Verification messages must attach at least 0.05 TON.

`npm run deploy:dry-run` only derives a deterministic generic-verifier deployment summary after a complete operator profile is supplied. It never submits a transaction. Mainnet submission and live-state verification require an approved multisig/operator adapter and a committed deployment manifest.

## Private Merkle membership primitive

`membership.circom` proves membership in a depth-12 Poseidon tree while keeping the leaf and path private. Only `[isMember, root]` are public, an incorrect root is unsatisfiable, and `verifyMembershipProof` pins the expected root.

This is a generic whitelist primitive. A production Telegram channel integration must separately define how an authorized service constructs and publishes the member root; the circuit alone does not query Telegram channel membership.

## Trusted setup and artifacts

```bash
npm run setup:circuits
```

This compiles both circuits over BLS12-381 and regenerates the R1CS, WASM, proving key, verification key, and manifests. The repository's phase-2 beacon is deterministic for reproducible development builds.

For production, use a suitable public ceremony or a properly operated multi-party ceremony and independently verify the resulting artifacts. After changing `telegram_auth.circom`, regenerate the TON verifier constants with `export-ton-verifier`; `npm test` fails if the embedded contract key is stale.

### Priva purchase artifact release gate

`artifacts/priva_purchase_auth/provenance.json` records SHA-256 hashes for the circuit, proving artifacts, verification key, and generated Tolk verifier. Verify the committed development artifact set with:

```bash
npm run check:priva-artifacts
```

The production gate deliberately fails for the checked-in artifacts:

```bash
npm run check:priva-production
```

It may pass only after replacing the development setup with a reviewed public or independently operated MPC ceremony, recording the regenerated artifact hashes in a reviewed `production-attestation.json`, and completing an independent review of the circuit, verifier, and Priva launchpad integration. Do not mark `provenance.json` as production or add an attestation merely to satisfy this command; those records must correspond to the actual ceremony and reviewed deployment artifact set.

## Repository layout

```text
circuits/       issuer-bound authentication and private membership circuits
artifacts/      committed development R1CS/WASM/zkey/vkey artifacts
src/sdk/        proof generation, verification, membership and TON StateInit helpers
src/gateway/    Telegram HMAC validation and bounded server-side prover
contracts/      issuer/policy-bound TON Groth16 verifier
tests/          cryptographic and adversarial regression tests
examples/       Telegram Mini App gateway client
```
