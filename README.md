# `zk-tele-auth` (Private Telegram OAuth)

> **Zero-Knowledge Authentication & Identity Attestation Protocol for Telegram & Web3 dApps**

[![Zero Knowledge](https://img.shields.io/badge/ZK-Groth16--BN254-00f2fe.svg)](https://circom.io)
[![Circom](https://img.shields.io/badge/Circuit-Circom_2.1-orange.svg)](https://docs.circom.io)
[![TON Ecosystem](https://img.shields.io/badge/TON-Smart_Contracts-0088cc.svg)](https://ton.org)

`zk-tele-auth` allows Web3 users to log into dApps and verify Telegram identity attestations (such as Telegram Premium status, account age, or private channel membership) **without disclosing their numeric Telegram User ID, username, or phone number** to the dApp frontend or on-chain smart contracts.

---

## Key Features & Advantages

- **Zero-Knowledge User Anonymity**: Proves ownership of valid Telegram credentials via Groth16 ZK-SNARKs without revealing identity metadata.
- **Deterministic Anonymous Nullifier**: Generates a domain-specific nullifier hash (`hash(userId, appDomain, salt)`), preventing double-registration or Sybil attacks while keeping users completely un-linkable across different dApps.
- **Telegram Premium & Membership Attestation**: Prove Telegram Premium membership or private channel inclusion via Merkle tree proofs.
- **TON On-Chain Verifier (Tolk 1.2)**: On-chain Groth16 Snark verifier smart contract allowing TON dApps to verify Telegram membership proofs directly on-chain.
- **Client-Side Proof Generation**: Proofs are generated locally on the user's client device (SnarkJS / Browser WebApp) so private keys and tokens never leave the device.

---

## System Architecture & Protocol

```
┌────────────────────────────────┐
│   Telegram MiniApp / User      │
│ (initData: HMAC, userId, salt) │
└───────────────┬────────────────┘
                │
                ▼
┌────────────────────────────────┐
│ Client-Side ZK Proof Generator │ ◄── Circom 2.1 Circuit
│    (Groth16 / SnarkJS BN254)   │
└───────────────┬────────────────┘
                │
                ├─────────────────────────────────────────┐
                │ 1. Proof & Public Nullifier Hash        │ 2. Verify On-Chain
                ▼                                         ▼
┌────────────────────────────────┐       ┌───────────────────────────────┐
│     Web3 dApp Server / SDK     │       │ TON Smart Contract (Tolk 1.2) │
│ (ZkAuthProofVerifier.verify()) │       │   (zk_tele_auth_verifier)     │
└────────────────────────────────┘       └───────────────────────────────┘
```

---

## Project Structure

```
zk-tele-auth/
├── package.json                   # Project configuration & test scripts
├── .gitignore                     # Git ignore rules
├── circuits/
│   ├── telegram_auth.circom       # Main Groth16 Telegram Auth Circuit
│   ├── hasher.circom              # Poseidon Nullifier & Age verifier gadgets
│   └── membership.circom          # Merkle tree channel membership circuit
├── contracts/
│   └── zk_tele_auth_verifier.tolk # Tolk 1.2 On-Chain Verifier for TON
├── src/
│   ├── sdk/
│   │   ├── types.ts               # SDK interfaces & proof payloads
│   │   ├── crypto-utils.ts        # SHA256 / HMAC helpers
│   │   ├── nullifier.ts           # Nullifier derivation engine
│   │   ├── initdata-parser.ts     # Telegram WebApp initData validator
│   │   ├── proof-generator.ts     # Client-side SnarkJS proof generator
│   │   └── proof-verifier.ts      # Off-chain SnarkJS proof verifier
│   └── gateway/
│       └── server.ts              # Telegram Gateway Server & Bot handler
├── examples/
│   └── dapp-demo/                 # Glassmorphism React/Vite Demo dApp
└── tests/
    └── unit-tests.js              # Automated unit test suite
```

---

## Quick Start & Usage

### 1. Installation

```bash
# Clone the repository
git clone https://github.com/EF-Code/zk-tele-auth.git
cd zk-tele-auth

# Run unit tests
npm test
```

### 2. Verify Telegram Identity in TypeScript

```typescript
import { ZkAuthProofGenerator, ZkAuthProofVerifier } from 'zk-tele-auth';

// 1. Generate local Groth16 Proof
const proofPayload = await ZkAuthProofGenerator.generateProof({
  userId: 987654321,
  authDate: Math.floor(Date.now() / 1000) - 300,
  isPremium: true,
  appDomain: 'mydapp.io',
  currentTimestamp: Math.floor(Date.now() / 1000)
});

// 2. Verify Proof on dApp Server
const verification = await ZkAuthProofVerifier.verifyProof(proofPayload, 'mydapp.io');

if (verification.isValid) {
  console.log('User authenticated anonymously! Nullifier Hash:', verification.nullifierHash);
}
```

---

