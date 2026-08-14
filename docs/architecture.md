# Architecture and trust boundaries

The system has four security-relevant boundaries:

1. Telegram Mini App to gateway: the gateway validates Telegram `initData` with the bot token. The gateway is a trusted issuer and compromise of either the bot token or `issuerSecret` can mint accepted proofs.
2. Gateway to relying party: the proof hides the Telegram user ID, but the relying party must pin app domain, issuer commitment, freshness, Premium policy, and action fields independently.
3. Relying party to TON verifier: the TON contract checks the pairing equation and immutable verifier policy. A valid cryptographic proof is not, by itself, a purchase or settlement authorization.
4. TON verifier to launchpad/economics: `PrivaPurchaseLaunchpad` composes the verifier core with immutable launch policy, atomic action/identity/inventory accounting, sender-bound recipient checks, native-TON value accounting, storage reserve, and refundable overpayment credits. It deliberately emits no asynchronous settlement action; any jetton/NFT settlement or credit-withdrawal adapter needs a separate review.

## Public/private data

Public proof signals include policy commitments, timestamps, action routing fields, and nullifiers. Private witness values include Telegram user ID, Telegram authentication timestamp, Premium flag, and issuer secret. The issuer secret and bot token must never enter browser code, logs, images, Git, or proof responses.

## Current implementation boundary

The generic verifier, Priva verifier core, and composed native-TON launchpad are implemented and locally sandbox-tested. The standalone wrapper remains a cryptographic primitive and must never be deployed as a launchpad. Production approval still requires independent review of the composition and economics, a verified ceremony, signed attestation, operator profile, and real testnet evidence.
