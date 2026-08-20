# Third-party notices

The stable TON proof-to-cell helper uses the following runtime dependency:

| Package | Version | License | Source |
| --- | --- | --- | --- |
| `export-ton-verifier` | `3.0.2` | GPL-3.0-or-later | [upstream repository](https://github.com/mysteryon88/export-ton-verifier) |

`export-ton-verifier` is kept as a normal production dependency because
`src/sdk/ton-proof.ts` calls its `proofToMessageCell` implementation at runtime.
Consumers who redistribute this package must review and satisfy the applicable
GPL-3.0-or-later obligations. The upstream license text is distributed by the
dependency in the installed package; this notice records the dependency and
its provenance for release review.
