# Phase 1 research: identity, issuance, and database validation

**Research date:** 2026-08-05
**Scope:** Current implementation contracts and risks for Custody Phase 1.

## Executive conclusions

1. Phase 1 should implement the base
   [Transaction Tokens draft 11](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-transaction-tokens-11)
   without adopting an unstable agent-chain extension. The originating human
   is `sub`; the authenticated agent workload is `req_wl`. A separate database
   access token may derive an RFC 8693 `act.sub` from that verified workload as
   a versioned Custody profile.
2. Keycloak can make the identity setup reproducible through a committed realm
   import. The human path should be Authorization Code with mandatory S256
   PKCE; every workload should have a distinct client-credentials identity.
3. The PostgreSQL validator should perform offline verification against a
   locally published database public key. This avoids a network call inside
   every database authentication callback.
4. pgx must set `RequireAuth = "oauth"`; installing `OAuthTokenProvider` alone
   does not prohibit authentication downgrade. Phase 1 should use one physical
   database connection per transaction and close it immediately.
5. PostgreSQL exposes validator-controlled `authn_id` as immutable `system_user`;
   this is the reliable input for RLS context, unlike application-set session
   variables.

## Transaction Token contract

Draft 11 defines a signed JWT with `typ: txntoken+jwt`. Required claims are
`iat`, `aud`, `exp`, `txn`, `sub`, `scope`, and `req_wl`; `tctx` and `rctx` are
recommended. The token travels in the dedicated `Txn-Token` header, is
validated by each receiving workload, and is forwarded unchanged. It is not
an OAuth access token or workload credential. See the
[current draft](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-transaction-tokens-11).

Remote issuance profiles [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693.html):
the request is form encoded and includes the token-exchange grant, audience,
scope, requested token type, subject token, and subject-token type. The
response uses `access_token` as the response member but identifies it as a
Transaction Token and uses `token_type: N_A`; no refresh token is issued.

Phase 1 should enforce:

- an authenticated requesting workload independent of the subject token;
- an exact trust-domain audience and allowlisted scopes;
- subject-token issuer, audience, signature, time, and authority validation;
- a 60-second maximum Transaction Token lifetime;
- size/depth limits and an allowlist for request context/details;
- receiver-scoped replay state based on the token hash, never a global cache
  keyed only by `txn`;
- exact byte-for-byte propagation between gateway and resource service;
- no token bodies or token fragments in logs.

The individual
[Transaction Tokens for Agents draft](https://datatracker.ietf.org/doc/draft-araut-oauth-transaction-tokens-for-agents/02/)
is explicitly work in progress and has changed actor-context shapes. Phase 1
does not need it: `req_wl` already identifies the agent workload that requested
the base token. Multi-agent actor chains remain a Phase 3 concern.

## Keycloak 26.7 identity configuration

Keycloak imports committed realm configuration from
`/opt/keycloak/data/import` when started with `--import-realm`; startup import
skips a realm that already exists. Keeping demo state ephemeral preserves
determinism. Realm files support environment-variable placeholders. See the
official [import/export guide](https://www.keycloak.org/server/importExport).

The human CLI client should be public, enable only Standard Flow, require S256
PKCE, disable implicit and Direct Access Grants, and register an exact loopback
callback URI. Keycloak's official administration guide describes
[Authorization Code and PKCE](https://www.keycloak.org/docs/26.7.0/server_admin/#_oidc-auth-flows),
and its source defines the realm attribute as
[`pkce.code.challenge.method`](https://github.com/keycloak/keycloak/blob/26.7.0/server-spi-private/src/main/java/org/keycloak/protocol/oidc/OIDCConfigAttributes.java#L64).

Each agent, gateway, and resource should have a separate confidential client
with service accounts enabled, interactive
flows disabled, `fullScopeAllowed: false`, and narrowly assigned roles/scopes.
Keycloak documents both
[service accounts](https://www.keycloak.org/docs/26.7.0/server_admin/#_service_accounts)
and the need for explicit
[audience mappers](https://www.keycloak.org/docs/26.7.0/server_admin/#_audience).
Development secrets come from environment placeholders and are never copied
into the realm fixture.

The portfolio demo should perform a real interactive Authorization Code +
PKCE login. Headless CI should not introduce a password-grant bypass. It can
exercise the same spine with a clearly labeled automation service principal,
while unit and component tests cover PKCE state, nonce, callback, and token
validation. CI therefore proves protocol mechanics; the recorded/manual demo
proves the human flow.

## Go JOSE and issuer boundaries

Use distinct signing keys, `kid` namespaces, issuer identifiers, audiences,
and token types for Transaction Tokens and database access tokens. This makes
cross-token substitution fail even if a verifier is misconfigured in one
dimension. Private keys are generated into local named volumes on first start,
stored with restrictive permissions, and never committed.

The implementation needs strict JWS/JWT/JWK support rather than handwritten
compact-token parsing. A reviewed, pinned v3 release of
[`lestrrat-go/jwx`](https://github.com/lestrrat-go/jwx) is a suitable Go
candidate; Go's standard
[`crypto/ed25519`](https://pkg.go.dev/crypto/ed25519) supplies the primitive.
Selection should be locked by an ADR and backed by algorithm-confusion,
unknown-key, malformed-token, and key-rotation tests.

The TTS can host both logical issuers in one process for Phase 1 while keeping
their modules and keys separate. A private database-token endpoint derives
`sub`, `txn`, and actor data exclusively from a validated Transaction Token;
callers cannot submit replacement identity claims.

## PostgreSQL 18 validator

PostgreSQL invokes a module's required `validate_cb` after checking only basic
bearer-token syntax. The validator must decide authorization and return a
`palloc`-allocated authenticated identity. The official callback contract is
documented in
[OAuth Validator Callbacks](https://www.postgresql.org/docs/18/oauth-validator-callbacks.html),
with security guidance in
[Safely Designing a Validator Module](https://www.postgresql.org/docs/18/oauth-validator-design.html).

The production Phase 1 validator should:

- allowlist EdDSA and require `typ: at+jwt` plus a known `kid`;
- verify the signature using a local database JWKS;
- require the exact database issuer and audience;
- validate `iat`, `exp`, optional `nbf`, maximum age, and bounded clock skew;
- require `jti`, `txn`, stable `sub`, `act.sub`, and `custody.db.connect`;
- reject malformed JSON, duplicate security-sensitive members, unknown
  critical JOSE parameters, excessive sizes, and every token-type confusion;
- return the stable opaque subject—not email or display name—as `authn_id`;
- emit only a bounded, redacted operational acceptance event, never the token.

Use ordinary exact `pg_ident.conf` mapping from the opaque subject to a
least-privileged role. Do not enable `delegate_ident_mapping`; PostgreSQL warns
that it transfers all role-authorization responsibility to the validator. See
[OAuth HBA options](https://www.postgresql.org/docs/18/auth-oauth.html) and
[user maps](https://www.postgresql.org/docs/18/auth-username-maps.html).

The TTS should atomically publish the database issuer public key to a volume
mounted read-only by PostgreSQL. The validator fails closed if the file is
absent or invalid. This keeps network and JSON/JWK discovery out of the
in-process database authentication callback without adding another service.

## pgx connection contract

pgx v5.10's
[`OAuthTokenProvider`](https://github.com/jackc/pgx/blob/v5.10.0/pgconn/config.go#L85-L87)
is called when PostgreSQL offers OAUTHBEARER. The
[mechanism-selection source](https://github.com/jackc/pgx/blob/v5.10.0/pgconn/pgconn.go#L472-L493)
also shows why the client must set `RequireAuth = "oauth"` to reject weaker
server offers.

The callback runs for a physical connection, so the authenticated human
identity belongs to that whole PostgreSQL session. Phase 1 should not use a
general pool across subjects. It creates one connection for one database
transaction, uses a context-bounded token provider, and closes the connection.
Tests cover cancellation, provider failure, missing/invalid tokens, wrong
issuer/audience/scope, expiration, unknown key, and a server that does not
offer OAuth.

## Recommended Phase 1 gates

1. Harden the Phase 0 pgx spike with `RequireAuth = "oauth"` and a downgrade
   rejection test.
2. Prove deterministic Keycloak import and real human PKCE login separately
   from the headless automation-principal CI path.
3. Pass Transaction Token fixture and negative conformance tests before adding
   resource behavior.
4. Prove byte-identical Transaction Token propagation through agent, gateway,
   and resource.
5. Replace the sentinel validator and pass the full negative matrix plus key
   rotation before calling the database integration complete.
6. Demonstrate exact RLS results for each principal profile and fail closed on
   malformed database OAuth credentials.

## Primary references

- [Transaction Tokens draft 11](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-transaction-tokens-11)
- [RFC 8693: OAuth 2.0 Token Exchange](https://www.rfc-editor.org/rfc/rfc8693.html)
- [Keycloak 26.7 Server Administration Guide](https://www.keycloak.org/docs/26.7.0/server_admin/)
- [Keycloak import/export guide](https://www.keycloak.org/server/importExport)
- [PostgreSQL 18 OAuth authentication](https://www.postgresql.org/docs/18/auth-oauth.html)
- [PostgreSQL 18 validator design](https://www.postgresql.org/docs/18/oauth-validator-design.html)
- [PostgreSQL 18 validator callbacks](https://www.postgresql.org/docs/18/oauth-validator-callbacks.html)
- [pgx v5.10 OAuth configuration](https://github.com/jackc/pgx/blob/v5.10.0/pgconn/config.go)
