# Telegram Mini App integration example

This example demonstrates the stable browser client calling the local gateway. It uses development artifacts only and is not a production deployment.

## Run locally

From the repository root:

```bash
npm run build
cp examples/telegram-mini-app/.env.example /tmp/zk-tele-auth-example.env
set -a
. /tmp/zk-tele-auth-example.env
set +a
npm --prefix examples/telegram-mini-app start
```

Open `http://127.0.0.1:3000` from a configured Telegram Mini App. The gateway listens on `http://127.0.0.1:8080` and exposes `/v1/authentications` through the browser-safe `zk-tele-auth/client` entrypoint.

The example does not contain a bot token, issuer secret, user data, proof, or deployment address. Replace the placeholders only in the shell environment or an approved local secret store. Do not commit the temporary environment file.

## Application integration boundary

The browser receives a proof payload from the trusted gateway. Send it to your application backend, verify it with `ZkAuthProofVerifier` using an independently configured issuer commitment/domain/freshness policy, and persist nullifiers atomically if your application requires one-time claims. Never trust policy values returned by the gateway or log raw Telegram `initData`.

The generic TON transaction helper is available from `zk-tele-auth/ton`; this example does not broadcast a wallet transaction. Priva is intentionally absent because it is experimental and unsupported for production.
