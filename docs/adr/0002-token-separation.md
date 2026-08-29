# ADR 0002: Separate transaction and database access tokens

- Status: Accepted
- Date: 2026-08-05
- Standards baseline: `draft-ietf-oauth-transaction-tokens-11`

## Context

The initial proposal forwarded one Transaction Token into PostgreSQL as the
SASL OAUTHBEARER credential. Draft 11 explicitly states that a Transaction
Token is not an OAuth access token or a workload-authentication credential.
Accepting it in a custom database validator would work mechanically while
contradicting the standard the project claims to implement.

The same draft also replaced older claim names: `azd` became `tctx`, and
transaction purpose is expressed by `scope`. The required claims now include
`iat`, `aud`, `exp`, `txn`, `sub`, `scope`, and `req_wl`; `tctx` and `rctx` are
recommended.

## Decision

Use two artifacts:

1. A Transaction Token is forwarded unchanged between HTTP workloads in the
   dedicated `Txn-Token` header.
2. A distinct, short-lived OAuth access token authenticates a PostgreSQL
   connection. It has a database audience and repeats `txn` for correlation.

Workload authentication remains separate from both. The database credential
may use RFC 8693 `act` semantics as an explicitly documented profile; `act` is
not presented as a base Transaction Tokens claim.

Replay state is scoped to the receiving workload and token acceptance window.
The same `txn` appearing at different workloads is expected and is not replay.

## Consequences

- The architecture remains standards-conformant and its token types cannot be
  confused accidentally.
- A database token issuer becomes an explicit trust anchor.
- The gateway authorizes database-token issuance only after an allow decision.
- Operational events may be correlated by `txn`, but `txn` alone is not treated
  as proof or a replay-prevention mechanism.
- Draft changes are isolated behind versioned contract fixtures and this ADR.
