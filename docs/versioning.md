# Versioning and release identity

The package follows SemVer for the supported stable surface:

- patch releases fix implementation or documentation defects without changing
  stable request, response, or export contracts;
- minor releases add backwards-compatible stable capabilities;
- major releases may remove deprecated aliases or change stable contracts.

The `/authenticate` HTTP alias is deprecated and remains for one release line
after `/v1/authentications` adoption. Priva APIs are experimental and may
change or move without stable SemVer compatibility; they never become a stable
release gate unless an operator explicitly enables the experimental profile.

Version selection, npm ownership, registry access, provenance signing, and
publication are operator-controlled decisions. CI prepares and verifies
artifacts but does not publish this package automatically from ordinary pushes.
