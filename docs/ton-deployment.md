# Deterministic TON deployment

`npm run compile:ton` compiles the generic verifier, Priva verifier wrapper, and composed Priva launchpad with the pinned `@ton/tolk-js` toolchain. When available, Acton can independently compile the composition:

```bash
/home/wellington/.acton/bin/acton compile contracts/priva_purchase_launchpad.tolk --project-root .
```

The repository has no `Acton.toml`; the command is an independent source check, not a deployment. Record its exact output in an external evidence bundle.

`node scripts/deploy-ton.mjs --network testnet --contract generic-verifier --dry-run` and `--contract priva-launchpad` compile the selected source, serialize the exact StateInit data, derive the address, and print source/artifact/code/data/policy/funding hashes. The script refuses incomplete operator profiles, implicit modes, live mutations, and unconfirmed mainnet dry-runs. Mainnet is never selected by default.

The Priva launchpad StateInit commits the application domain, issuer key, launch, freshness/Premium policy, authorization TTL, native-TON price, identity cap, and inventory. Its purchase transition synchronously verifies the 17 public signals, derives the executing basechain address and actual sender limbs, consumes action nullifiers atomically, tracks cumulative identity totals, bounds dictionary growth, and records overpayment as a refundable credit. It deliberately performs no asynchronous token settlement; a jetton/NFT adapter and credit withdrawal need an additional independent economic review.

After an authorized deployment, `scripts/verify-ton-deployment.mjs --manifest deployments/<network>/manifest.json` checks local manifest consistency only. A real manifest must include the live account code/data hashes, active state, balance/storage margin, transaction reference, two provider/raw-chain sources, and valid/invalid/replay canary evidence. Sandbox tests never substitute for this network proof.
