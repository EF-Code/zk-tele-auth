# `zk-tele-auth` (Private Telegram OAuth)

> **Zero-Knowledge Authentication & Identity Attestation Protocol for Telegram & Web3 dApps**

[![Zero Knowledge](https://img.shields.io/badge/ZK-Groth16--BLS12--381-00f2fe.svg)](https://circom.io)
[![Circom](https://img.shields.io/badge/Circuit-Circom_2.1-orange.svg)](https://docs.circom.io)
[![TON Ecosystem](https://img.shields.io/badge/TON-Tolk_Verifier-0088cc.svg)](https://ton.org)

`zk-tele-auth` lets Web3 users log into dApps and prove Telegram identity attestations
(Telegram Premium status, account age, private-channel membership) **without disclosing
their numeric Telegram User ID, username, or phone number** to dApp servers or on-chain
smart contracts.

Everything is real: the circuits are compiled with circom over **BLS12-381**, the SDK
generates and verifies genuine Groth16 proofs with snarkjs, and the TON contract verifies
the same proofs **on-chain** using native TVM BLS12-381 pairings.

---

## Key Features & Advantages

- **Zero-Knowledge User Anonymity** — Groth16 ZK-SNARKs prove valid Telegram credentials without revealing identity metadata.
- **Deterministic Anonymous Nullifier** — `nullifier = Poseidon255(userId, appDomainHash, salt)` prevents double registration and Sybil attacks while keeping users unlinkable across dApps.
- **Telegram Premium & Membership Attestation** — prove Premium membership or private-channel inclusion with a Poseidon-2 Merkle membership proof (depth 12, up to 4,096 members).
- **Real TON On-Chain Verifier** — a Tolk contract (generated with `export-ton-verifier`) checks the full Groth16 pairing equation over BLS12-381 with native TVM opcodes, plus app-domain binding, freshness, and nullifier replay protection.
- **Server-Side Proving Gateway** — the Telegram bot token (the HMAC secret) can never ship inside a circuit, so the gateway authenticates initData and emits proofs; dApps verify off-chain or on-chain.

---

## System Architecture & Protocol

```
┌────────────────────────────────┐
│   Telegram MiniApp / User      │
│ (initData: HMAC-signed userId) │
└───────────────┬────────────────┘
                │ initData (raw query string)
                ▼
┌──────────────────────────────────────────────┐
│ ZkTeleAuthGateway (trusted prover)          │
│ 1. HMAC-SHA256 validate initData w/ bot key │
│ 2. ZkAuthProofGenerator.generateProof(...)  │
│ 3. self-check via ZkAuthProofVerifier       │
└───────────────┬──────────────────────────────┘
                │ proof + publicSignals (nullifier, appDomainHash, …)
                ├────────────────────────────────────────┐
                ▼                                        ▼
┌────────────────────────────────────┐    ┌───────────────────────────────────┐
│ Web3 dApp Server / SDK             │    │ TON Smart Contract (Tolk 1.2)     │
│ ZkAuthProofVerifier.verifyProof()  │    │ zk_tele_auth_verifier.tolk        │
│   (snarkjs groth16.verify, off-    │    │  BLS_PAIRING over BLS12-381        │
│    chain, instant, no gas)         │    │  + domain binding + freshness      │
│                                    │    │  + nullifier replay protection    │
└────────────────────────────────────┘    └───────────────────────────────────┘
```

---

## Project Structure

```
zk-tele-auth/
├── package.json                   # build / test / setup:circuits scripts
├── circuits/
│   ├── telegram_auth.circom       # main Groth16 auth circuit (BLS12-381)
│   ├── hasher.circom              # Poseidon255 nullifier + age-verifier gadgets
│   └── membership.circom          # Poseidon255 Merkle channel-membership circuit
├── contracts/
│   └── zk_tele_auth_verifier.tolk # TON on-chain Groth16 verifier + app layer
├── artifacts/                     # committed circuit artifacts (r1cs/wasm/zkey/vkey)
├── scripts/
│   ├── setup-circuits.cjs         # full trusted setup pipeline (circom→ptau→zkey→vkey)
│   └── run-tests.mjs              # test runner
├── src/
│   ├── sdk/
│   │   ├── types.ts               # SDK interfaces & proof payloads
│   │   ├── poseidon.ts            # Poseidon over BLS12-381 (poseidon-bls12381)
│   │   ├── crypto-utils.ts        # SHA256 / HMAC / random salt helpers
│   │   ├── nullifier.ts           # domain commitment + nullifier derivation
│   │   ├── initdata-parser.ts     # Telegram WebApp initData validator
│   │   ├── artifacts.ts           # circuit artifact resolution
│   │   ├── public-signals.ts      # named public-signal parsing + freshness
│   │   ├── proof-generator.ts     # snarkjs.groth16.fullProve
│   │   └── proof-verifier.ts      # snarkjs.groth16.verify + signal checks
│   ├── gateway/
│   │   └── server.ts              # Telegram gateway: HMAC check + server prover
│   └── types/modules.d.ts
├── examples/
│   └── dapp-demo/                 # browser demo dApp
└── tests/
    └── unit-tests.mjs             # real end-to-end integration tests
```

---

## Quick Start & Usage

### 1. Installation & tests

```bash
git clone https://github.com/EF-Code/zk-tele-auth.git
cd zk-tele-auth
npm install
npm run build       # compile the TypeScript SDK (produces dist/)
npm test            # real Groth16 + Merkle membership integration tests
```

The test suite generates and verifies **real proofs** against the committed
BLS12-381 artifacts: a premium Telegram auth proof, wrong-domain/tampered/stale
rejections, and a depth-12 Merkle membership proof.

### 2. Verify a Telegram identity in TypeScript

```typescript
import { ZkAuthProofGenerator, ZkAuthProofVerifier } from './dist/sdk/index.js';

// Gateway-side: after HMAC validation of initData
const proofPayload = await ZkAuthProofGenerator.generateProof({
  userId: 987654321,
  authDate: Math.floor(Date.now() / 1000) - 300,
  isPremium: true,
  appDomain: 'mydapp.io',
  currentTimestamp: Math.floor(Date.now() / 1000),
});

// dApp-side: verify off-chain (snarkjs pairing check, no gas)
const verification = await ZkAuthProofVerifier.verifyProof(proofPayload, 'mydapp.io');
if (verification.isValid) {
  console.log('Anonymously authenticated! Nullifier:', verification.nullifierHash);
}
```

### 3. Verify the same proof on TON

The committed `contracts/zk_tele_auth_verifier.tolk` embeds the `telegram_auth`
verification key and checks the Groth16 equation on-chain. After deployment:

1. Send a `ZkTeleAuthConfigure` message (`op 0x5a4b4346`, `appDomainHash`,
   `maxTokenAgeSec`) to pin the dApp's domain commitment.
2. Clients submit the proof points + serialized public signals as a
   `ZkTeleAuthVerifierVerify` message. The contract reverts unless the proof is
   valid **and** the domain matches **and** the proof is fresh **and** the
   nullifier has not been seen before.

---

## Trusted Setup

`npm run setup:circuits` runs the full pipeline per circuit:

```
circom <name>.circom --prime bls12381 --r1cs --wasm --sym
snarkjs powersoftau new bls12-381 <power>            (phase 1)
snarkjs powersoftau contribute / prepare phase2
snarkjs zKey newZKey + deterministic beacon          (phase 2)
snarkjs zKey exportVerificationKey
```

> **Important**: the committed artifacts were generated locally with a fixed
> dev beacon for reproducibility. For a production deployment you MUST reuse a
> public ceremony ptau (`powersOfTau`) and discard the toxic waste — see
> [snarkjs docs](https://github.com/iden3/snarkjs).

The circuits use [Poseidon255](https://github.com/jmagan/poseidon-bls12381-circom)
(reference BLS12-381 constants) so JS-derived hashes and circuit outputs are
byte-identical, which the tests assert against a pinned reference vector.

---

## Why BLS12-381?

TVM exposes only BLS12-381 pairing opcodes (`BLS_PAIRING`, `BLS_G1_MULTIEXP`),
so a TON contract cannot verify BN254 proofs. The entire stack — circuits,
setup, SDK hashing, and on-chain verifier — is therefore built over BLS12-381,
the same choice as the official [zk-ton-examples](https://github.com/ton-blockchain/zk-ton-examples).
