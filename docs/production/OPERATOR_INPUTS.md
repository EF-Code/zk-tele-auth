# Production operator inputs

This file is intentionally a template. Do not fill it with guesses or secrets. The release preflight remains blocked until the operator supplies and reviews the deployment-specific values through the approved secret/configuration system.

Public ceremony contributor labels may be pseudonymous for operational privacy. A label such as `REAL_OPERATOR_NAME` is not evidence of a legal identity or an independent review; retain any private mapping to the actual custodian in an access-controlled external evidence record, never in Git or this template.

For this personal project, `docs/production/deployment-profile.json` explicitly sets `independentReviewRequired` to `false`. That makes the independent-review gate `not-applicable`; it does not approve ceremony artifacts, signatures, operator configuration, or network deployment, and it must be changed to `true` for any shared or commercial deployment. Priva's own composition gate remains separate and still requires its dedicated review record if Priva is enabled.

The same personal stable profile sets `productionAttestationRequired` to `false`, which makes the external signed-attestation gate `not-applicable`. This is a self-managed release waiver, not a cryptographic approval: the production artifact manifest must still come from a genuine reviewed ceremony export, and the waiver is rejected for mainnet or Priva deployments.

## Scope

- [ ] Generic Telegram authentication is in scope.
- [ ] Priva purchase authorization is in scope.
- [ ] Membership proofs are in scope and have a separately reviewed root publication process.

## Network and policy

- Network: `PENDING_OPERATOR_INPUT`
- Application domain: `PENDING_OPERATOR_INPUT`
- `issuerKeyHash`: `PENDING_OPERATOR_INPUT` (public commitment only; never put `issuerSecret` here)
- `maxTokenAgeSec`: `PENDING_OPERATOR_INPUT`
- Allowed clock skew: `PENDING_OPERATOR_INPUT`
- Premium required: `PENDING_OPERATOR_INPUT`
- Maximum Priva authorization TTL: `PENDING_OPERATOR_INPUT`
- Circuit versions approved for this release: `PENDING_OPERATOR_INPUT`
- Independent review required: `false` for this personal project; set `true` before shared/commercial deployment
- External production attestation required: `false` for this personal stable profile; set `true` before shared/commercial deployment

## Priva launchpad

- Launchpad address: `PENDING_OPERATOR_INPUT`
- Launch identifier and canonical encoding: `PENDING_OPERATOR_INPUT`
- `launchIdHash`: `PENDING_OPERATOR_INPUT` (canonical field element derived from the reviewed launch identifier)
- Recipient address-binding rule: `PENDING_OPERATOR_INPUT`
- Accepted asset/payment path: `PENDING_OPERATOR_INPUT`
- Price/quote and expiry rules: `PENDING_OPERATOR_INPUT`
- `pricePerUnitNano`: `PENDING_OPERATOR_INPUT` (native TON nanograms, exact decimal integer)
- `perIdentityCap`: `PENDING_OPERATOR_INPUT` (positive uint64 quantity)
- `inventory`: `PENDING_OPERATOR_INPUT` (positive uint64 quantity)
- Refund policy: `accounted-credit-pending-reviewed-withdrawal-adapter`
- Bounce/downstream settlement policy: `no asynchronous settlement in the current composition; any adapter requires separate review`
- Upgrade/pause policy: `PENDING_OPERATOR_INPUT`

## Secrets and operators

- Telegram bot-token secret-manager reference: `PENDING_OPERATOR_INPUT`
- Issuer-secret secret-manager reference: `PENDING_OPERATOR_INPUT`
- Deployer/multisig address: `PENDING_OPERATOR_INPUT`
- Required approvers: `PENDING_OPERATOR_INPUT`
- RPC provider references: `PENDING_OPERATOR_INPUT`
- Secondary chain-data provider reference: `PENDING_OPERATOR_INPUT`
- Hosting/region/replica policy: `PENDING_OPERATOR_INPUT`

## Assurance and release approval

- Ceremony/transcript review reference: `PENDING_EXTERNAL_EVIDENCE`
- Production artifact attestation reference: `PENDING_EXTERNAL_EVIDENCE`
- Production attestation policy: `NOT_APPLICABLE_FOR_PERSONAL_PROJECT` while `productionAttestationRequired` is `false`
- Independent circuit/verifier review: `NOT_APPLICABLE_FOR_PERSONAL_PROJECT` while `independentReviewRequired` is `false`
- Independent launchpad/economic review: `NOT_APPLICABLE_FOR_PERSONAL_PROJECT` while `independentReviewRequired` is `false`; required if Priva is enabled
- Gateway/infrastructure review: `PENDING_EXTERNAL_EVIDENCE`
- Testnet deployment manifest: `PENDING_EXTERNAL_EVIDENCE`
- Testnet canary/replay evidence: `PENDING_EXTERNAL_EVIDENCE`
- Mainnet approval record: `PENDING_OPERATOR_APPROVAL`

## Privacy and operations

- Log retention and redaction approval: `PENDING_OPERATOR_INPUT`
- Incident owner and escalation destination: `PENDING_OPERATOR_INPUT`
- Issuer-secret rotation/migration owner: `PENDING_OPERATOR_INPUT`
- Contract migration owner: `PENDING_OPERATOR_INPUT`
- SLOs and alert thresholds: `PENDING_OPERATOR_INPUT`

Do not mark a checkbox or replace a placeholder until the value has an owner, source, review record, and evidence path.
