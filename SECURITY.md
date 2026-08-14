# Security policy

Do not disclose suspected vulnerabilities, credentials, issuer secrets, bot tokens, ceremony entropy, or deployment keys in public issues. Use the repository owner's private security channel and include the affected commit, exact artifact hashes, reproducible commands, and impact without including secrets.

This project is not considered production-ready solely because local tests pass. The gateway is a trusted Telegram issuer, proving artifacts require an independently verified ceremony, and the Priva verifier must be composed into an audited launchpad transition.

Supported security claims are scoped to the exact reviewed commit and artifact manifest. The repository's native-TON Priva launchpad records accounting and refundable credits without emitting asynchronous settlement actions; do not infer jetton/NFT settlement, refund withdrawal, testnet deployment, or audit approval from local tests. Reported issues are triaged by reproducibility, attacker control, value at risk, and evidence quality.
