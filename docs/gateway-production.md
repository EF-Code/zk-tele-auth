# Gateway production profile

Run `dist/gateway/main.js` only through a managed runtime with a secret manager, TLS/reverse proxy, edge rate limiting, structured redacted logs, metrics, alerting, and graceful shutdown.

Required environment variables are parsed by `loadGatewayConfig`. Production refuses development artifacts, requires an explicit `ZK_TELE_AUTH_ISSUER_KEY_HASH`, and the entrypoint verifies that commitment against the configured issuer secret before it marks readiness. The artifact readiness check requires a cryptographically valid trusted attestation, not a JSON status label. For local development, `ZK_TELE_AUTH_ALLOW_DEVELOPMENT_ARTIFACTS=1` is allowed only outside `NODE_ENV=production`.

The gateway uses a bounded child-process prover pool with worker crash/timeout recycling. The in-process admission bound is not a distributed rate limit; multi-replica deployments still need edge/application throttling. Request bodies use strict schemas, reject unknown/duplicate fields, enforce size/expiry limits, and time out proving. Do not log raw `initData`, user JSON/IDs, proof payloads, nullifiers, nonces, bot tokens, or issuer secrets; use the environment, mounted-file, or platform adapter secret-provider seam and redacted structured logger.

Recommended operational endpoints:

- `GET /livez`: cheap process liveness;
- `GET /readyz`: process/configuration readiness;
- `GET /metrics`: aggregate metrics only.

## Runtime templates

`compose.dev.yaml` is a loopback-only development profile. The
`compose.production.example.yaml` file is a reviewed-template starting point:
it requires an immutable image digest, external secret objects, a read-only
filesystem, dropped capabilities, and `no-new-privileges`. Replace every
`REPLACE_*` value through an operator-controlled deployment system and validate
the resulting image and evidence separately; this repository does not claim
that the template has been deployed.
