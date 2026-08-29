# ADR 0006: Separate issuer keys and offline database validation

- Status: Accepted
- Date: 2026-08-05

## Context

Transaction Tokens and PostgreSQL access tokens have different substitution
risks and audiences. Performing HTTP discovery inside a PostgreSQL backend
would also add network latency and availability to authentication.

## Decision

- The TTS uses independent Ed25519 keys, issuers, types, audiences, and JWKS
  endpoints for Transaction Tokens and database access tokens.
- Private keys live only in the TTS key volume and are generated on first use.
- At startup the TTS atomically writes its database issuer public key into a
  public-only volume mounted read-only by PostgreSQL. No private key crosses
  that boundary and no synchronization workload is required.
- The C validator accepts only `alg=EdDSA`, `typ=at+jwt`, `kid=db-current`, the
  exact issuer/audience/scope, a maximum 30-second lifetime, safe bounded
  subject/actor/tenant identifiers, exact persona-to-role consistency,
  safe `txn`/`jti` values, and a public key newer than 120 seconds. PostgreSQL
  performs no network call during login.

## Consequences

Unknown keys, missing public-key publication, malformed JSON/JWS, cross-token
substitution, and OAuth downgrade all fail closed. Phase 1 demonstrates one
current key; a production system needs an operational rotation controller and
overlapping retiring-key window.
