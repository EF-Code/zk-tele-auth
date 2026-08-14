# Incident response checklist

- Record incident owner, UTC start, affected commit/image/manifest, and the last known readiness result.
- Disable traffic or proving at the edge; do not expose bot tokens, issuer secrets, witnesses, proofs, user IDs, nullifiers, or nonces in tickets.
- Preserve redacted logs, preflight JSON, image/package digests, and provider responses.
- For contract incidents, use the reviewed pause/migration policy only. This composition is immutable; replacing policy means publishing a new StateInit address.
- Re-enable traffic only after the exact release candidate passes local validation and the operator/reviewer gates are updated.
