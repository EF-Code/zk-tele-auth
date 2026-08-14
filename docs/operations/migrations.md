# Immutable-contract migrations

Changing the circuit version, issuer commitment, application domain, verifier key, launch, price, cap, or inventory changes the StateInit data and therefore the contract address. Build and dry-run a new address, publish the new address through an operator-approved migration, preserve old getters/evidence, and update gateway/relying-party policy together. Do not mutate the old contract through an undocumented first-caller or upgrade path.
