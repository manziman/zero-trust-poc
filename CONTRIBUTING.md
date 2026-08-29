# Contributing

Custody is an experimental security architecture. Changes should preserve its
small scope, explicit trust model, and standards traceability.

## Local checks

Run the non-container checks before opening a pull request:

```sh
make check
```

When Docker is available, also run the complete Phase 1 gate:

```sh
make demo
```

Use `make clean` when a change to PostgreSQL initialization must be verified
against a fresh data volume.

## Change expectations

- Add tests for behavior changes and negative security paths.
- Record architectural changes as ADRs under `docs/adr/`.
- Update the versioned fixtures under `testdata/contracts/` when a pinned draft
  or profile changes.
- Never commit live tokens, secrets, private keys, database data, or complete
  token values in logs and fixtures.
- Keep the PostgreSQL validator bounded, warning-free, offline, and fail
  closed; every accepted claim or key-profile change requires a negative test.

Security vulnerabilities should follow [SECURITY.md](SECURITY.md), not a public
issue.
