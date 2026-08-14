# Gateway production profile

Run `dist/gateway/main.js` only through a managed runtime with a secret manager, TLS/reverse proxy, edge rate limiting, structured redacted logs, metrics, alerting, and graceful shutdown.

Required environment variables are parsed by `loadGatewayConfig`. Production refuses development artifacts and requires an explicitly trusted signed artifact attestation before the process can report readiness. For local development, `ZK_TELE_AUTH_ALLOW_DEVELOPMENT_ARTIFACTS=1` is allowed only outside `NODE_ENV=production`.

The in-process concurrency bound is not a distributed rate limit. Multi-replica deployments need edge/application throttling and a bounded worker/queue design. Do not log raw `initData`, user JSON/IDs, proof payloads, nullifiers, nonces, bot tokens, or issuer secrets.

Recommended operational endpoints:

- `GET /livez`: cheap process liveness;
- `GET /readyz`: process/configuration readiness;
- `GET /metrics`: aggregate metrics only.

