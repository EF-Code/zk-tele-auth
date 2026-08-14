# Threat model

## Assets

- Telegram bot token and issuer secret;
- proving keys and production verification keys;
- issuer/domain/policy commitments;
- stable identity and action nullifiers;
- launch inventory, payment, refunds, and recipient balances;
- deployer/multisig authority and contract StateInit;
- gateway availability and privacy of request material;
- release manifests, signatures, and deployment evidence.

## Attacker capabilities

Assume an attacker can submit arbitrary HTTP requests and TON internal messages, replay valid messages, alter public proof fields, provide malformed cells, create many client nonces, exhaust CPU/storage/gas, observe public chain data, compromise a dependency or CI pull request, and attempt to exploit a misconfigured reverse proxy. Do not assume the attacker has the bot token, issuer secret, multisig key, or an honest reviewer signature unless analyzing that compromise separately.

## Required invariants

- only the configured issuer/policy can authorize;
- one action nullifier cannot produce two purchases;
- new client nonces cannot bypass cumulative identity caps;
- the recipient and launch are bound to actual execution context;
- accepted value and settlement remain conserved through success, bounce, and failure;
- initialization and upgrades cannot be front-run or redirected;
- malformed inputs fail closed without persistent liveness loss;
- release artifacts cannot be substituted without invalidating provenance.

## Residual trust

Telegram HMAC verification remains gateway trust. A ZK proof demonstrates knowledge of the configured issuer secret and circuit relation; it does not independently reproduce Telegram's HMAC. The chain enforces the cryptographic proof and policy fields, but the launchpad must enforce business/economic invariants.

