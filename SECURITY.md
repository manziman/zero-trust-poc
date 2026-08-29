# Security policy

## Project status

Custody is an unaudited proof of concept. It is not production-ready and does
not provide a security warranty. It includes strict token profiles, an offline
PostgreSQL Ed25519 validator, and forced multi-tenant RLS, but it still uses
development HTTP, local fixture secrets, single-instance replay state, and POC
key management. Do not deploy it. See [THREAT-MODEL.md](THREAT-MODEL.md) for
explicit trust anchors and residual risks.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting feature for this
repository. Do not include live credentials, complete bearer tokens, private
keys, or sensitive production data in a report.

If private reporting is unavailable, contact the repository owner through the
contact method on their GitHub profile and request a secure reporting channel
before sharing details.

## Supported versions

Until the first tagged release, only the current default branch is supported.
