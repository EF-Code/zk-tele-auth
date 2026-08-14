# Production operator inputs

This file is intentionally a template. Do not fill it with guesses or secrets. The release preflight remains blocked until the operator supplies and reviews the deployment-specific values through the approved secret/configuration system.

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

## Priva launchpad

- Launchpad address: `PENDING_OPERATOR_INPUT`
- Launch identifier and canonical encoding: `PENDING_OPERATOR_INPUT`
- Recipient address-binding rule: `PENDING_OPERATOR_INPUT`
- Accepted asset/payment path: `PENDING_OPERATOR_INPUT`
- Price/quote and expiry rules: `PENDING_OPERATOR_INPUT`
- Per-identity cap: `PENDING_OPERATOR_INPUT`
- Per-launch inventory/cap: `PENDING_OPERATOR_INPUT`
- Refund and bounce policy: `PENDING_OPERATOR_INPUT`
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
- Independent circuit/verifier review: `PENDING_EXTERNAL_EVIDENCE`
- Independent launchpad/economic review: `PENDING_EXTERNAL_EVIDENCE`
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
