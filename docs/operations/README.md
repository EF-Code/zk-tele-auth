# Operations runbooks

These runbooks describe the repository-local response boundary. Operators must add environment-specific owners, secret-manager references, provider names, and alert destinations in `docs/production/OPERATOR_INPUTS.md` before release approval.

## Gateway deploy and rollback

1. Verify the exact source commit, signed artifact attestation, package/image digest, and operator profile.
2. Start with `NODE_ENV=production`; the gateway must refuse development artifacts, a missing expected issuer commitment, or a bad attestation before listening.
3. Check `/livez`, `/readyz`, aggregate `/metrics`, redacted logs, queue depth, and proof p95/p99 before shifting traffic.
4. Roll back the immutable image/package digest and preserve the failed request IDs and preflight report. Never rotate the issuer secret as a routine rollback.

For a container runtime, apply platform-enforced limits and isolation in addition to the image defaults: read-only root filesystem, a writable size-bounded `/tmp`, dropped Linux capabilities, `no-new-privileges`, explicit CPU/memory limits, and an egress policy that permits only the approved RPC/telemetry endpoints. The Dockerfile does not contain credentials or choose those environment-specific network rules.

## Issuer or bot-token compromise

Stop proving, revoke the affected secret-manager version, preserve evidence, and publish a new issuer commitment/address after operator review. Issuer-secret rotation changes every stable nullifier; it is a planned identity migration. A bot-token compromise means the gateway can mint issuer-valid proofs and requires the same incident boundary.

## Artifact or ceremony-integrity failure

Mark the attestation revoked, stop release jobs, quarantine the image/package, and re-run the production importer against a reviewed transcript. Never edit a manifest status to restore readiness.

## RPC/provider disagreement

Pause deployment or canary actions, capture raw responses and UTC timestamps, compare a secondary provider/raw-chain source, and keep the deployment gate blocked until the disagreement is resolved by an operator.

## Proving saturation or suspected replay

Use queue/concurrency/latency metrics without collecting raw initData or nullifiers. Apply edge rate limits, preserve only short-lived request IDs, and inspect on-chain action-nullifier and identity-total getters. Do not replay a customer proof on a public network as a diagnostic.
