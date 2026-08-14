# Architecture and trust boundaries

The system has four security-relevant boundaries:

1. Telegram Mini App to gateway: the gateway validates Telegram `initData` with the bot token. The gateway is a trusted issuer and compromise of either the bot token or `issuerSecret` can mint accepted proofs.
2. Gateway to relying party: the proof hides the Telegram user ID, but the relying party must pin app domain, issuer commitment, freshness, Premium policy, and action fields independently.
3. Relying party to TON verifier: the TON contract checks the pairing equation and immutable verifier policy. A valid cryptographic proof is not, by itself, a purchase or settlement authorization.
4. TON verifier to launchpad/economics: the actual launchpad must atomically consume action nullifiers, enforce cumulative identity caps, bind the real recipient and launch, account for value, and handle bounce/failure paths.

## Public/private data

Public proof signals include policy commitments, timestamps, action routing fields, and nullifiers. Private witness values include Telegram user ID, Telegram authentication timestamp, Premium flag, and issuer secret. The issuer secret and bot token must never enter browser code, logs, images, Git, or proof responses.

## Current implementation boundary

The generic verifier and Priva verifier core are implemented and locally tested. The Priva wrapper is deliberately not a production launchpad: no economic settlement, identity cap, inventory, or downstream bounce policy is assumed until the operator supplies and reviews the real launchpad design.

