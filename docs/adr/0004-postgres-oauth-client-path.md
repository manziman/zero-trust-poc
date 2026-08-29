# ADR 0004: pgx client and C validator for PostgreSQL OAUTHBEARER

- Status: Accepted by Phase 0 gate
- Date: 2026-08-05

## Context

PostgreSQL 18 implements SASL OAUTHBEARER and a server-side validator ABI but
does not ship a general token validator. The application must also be able to
provide an already-minted per-request database token during connection setup.

libpq exposes `PQsetAuthDataHook`, but adopting it from Go would require a cgo
adapter and complicate the resource-service build. pgx v5.10 added a
context-aware `OAuthTokenProvider` specifically for PostgreSQL 18 OAUTHBEARER.

PostgreSQL distinguishes authenticated identity (`system_user`) from active
authorization role (`current_user`). A convincing demonstration must show both.

## Decision

- Pin pgx v5.10 or newer and use `OAuthTokenProvider` in the Go resource
  service.
- Implement the PostgreSQL validator in C against the matching PostgreSQL 18
  server headers.
- Start with ordinary `pg_ident.conf` mapping; do not use
  `delegate_ident_mapping`.
- Make the Phase 0 exit gate compile and load the validator, invoke its callback
  through a Phase 0 OAuth login, assert the historical sentinel identity
  (`system_user = oauth:alice`, `current_user = alice`), and reject an invalid
  token. ADR 0008 supersedes this identity mapping for the current demo.
- Keep libpq's auth-data hook as the documented fallback if pgx fails a future
  compatibility gate.

## Consequences

- The resource service remains pure Go.
- The validator is a high-risk in-process component and must validate
  signature, issuer, audience, time, scope, token type, and key rotation before
  leaving the spike.
- `--with-libcurl` is not required for the validator ABI or pgx token callback.
  A production validator may link libcurl separately for discovery or JWKS.
- Per-actor connections limit conventional pooling; the POC accepts and later
  benchmarks that cost.
