# Supply-chain release controls

Local development runs `npm run sbom:package`, which always writes a
CycloneDX inventory and reports Syft, Trivy, and Cosign as incomplete when the
tools are not installed. It does not claim that the handwritten dependency
inventory is an authoritative scanner result.

Protected release infrastructure must provision pinned, checksum-verified
versions of Syft and Trivy, and an approved Cosign/OIDC or operator-controlled
signing identity before running `npm run sbom:package:required`. With
`RELEASE_REQUIRED_TOOLS=1`, missing tools, failed HIGH/CRITICAL scans, or an
uninvoked signing hook exit non-zero. Tool installation, OIDC trust policy,
registry credentials, and the resulting SBOM/scan/signature evidence remain
operator-controlled external gates and are not fabricated in this repository.
