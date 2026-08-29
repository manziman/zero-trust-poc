# Phase 0 research: standards and feasibility

**Research date:** 2026-08-05
**Scope:** Standards and implementation risks that Phase 0 should resolve before feature work begins.

## Executive conclusions

1. The plan's Transaction Token reference is outdated. The current work item is [draft-ietf-oauth-transaction-tokens-11](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-transaction-tokens-11), published 2026-07-30 and still an Internet-Draft. Its claims and wire protocol differ materially from revision 08.
2. A Transaction Token cannot conformantly double as PostgreSQL's OAuth bearer credential. Draft 11 says it is not an OAuth access token or workload-authentication credential. Phase 0 therefore needs an architecture decision between a standards-aligned two-token design and an explicitly nonconformant experiment.
3. [AuthZEN Authorization API 1.0 Final](https://openid.net/specs/authorization-api-1_0-final.html) returns a boolean decision, not a four-state decision enum. Approval belongs in the new [Access Request and Approval Profile, Working Group Draft 1](https://openid.github.io/authzen/authzen-access-request-approval-profile-1_0.html): deny with an access-request instruction, create a durable approval task, then perform a fresh authorization evaluation after approval.
4. PostgreSQL 18's OAuth extension points make the POC feasible. The server validator is a C ABI module; clients can provide a token through libpq's `PQsetAuthDataHook` or, for a pure-Go resource service, pgx v5.10's `OAuthTokenProvider`. The demo must distinguish authenticated identity (`system_user`) from the active database role (`current_user`).
5. Recommended stack: one Go module for the three services and a small C validator module for the lowest-risk Phase 0 ABI spike. Rust is viable only through unsafe C FFI at this seam; if chosen for portfolio value, make compile/load/callback interoperability a time-boxed Phase 0 gate rather than scaffolding both implementations.

## Transaction Tokens

### Current contract

Draft 11 defines a signed JWT with `typ: txntoken+jwt`. Its required claims are `iat`, `aud`, `exp`, `txn`, `sub`, `scope`, and `req_wl`; `iss` is optional, while `tctx` and `rctx` are recommended. The earlier `azd` shape has become `tctx`, and transaction purpose is represented by `scope`. The base specification does not define `act`.

The HTTP propagation mechanism is a dedicated `Txn-Token` header. A receiving workload validates the JWS signature, audience, and expiry and forwards the exact token unchanged. Remote issuance uses the OAuth token-exchange request shape, including `grant_type`, `audience`, `scope`, `requested_token_type`, `subject_token`, and `subject_token_type`; the response places the JWT in `access_token` but identifies it with `issued_token_type: urn:ietf:params:oauth:token-type:txn_token` and `token_type: N_A`. It must not issue a refresh token. These details are specified in [draft 11](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-transaction-tokens-11).

### Architecture consequence

Draft 11 explicitly says Transaction Tokens must not be used as OAuth 2.0 access tokens and are not workload-authentication credentials. PostgreSQL SASL OAUTHBEARER, by contrast, accepts a bearer access token. Passing the Transaction Token itself as that credential would therefore contradict the draft even if a custom validator accepted it.

Phase 0 should record an ADR choosing one of these paths:

- **Recommended:** preserve the Transaction Token in `Txn-Token` across HTTP, and mint a separate, short-lived PostgreSQL OAuth access token at the resource boundary. Carry `txn` and principal context in that credential; do not describe it as the propagated Transaction Token.
- **Experimental:** deliberately feed the Transaction Token to OAUTHBEARER, label the design nonconformant, and explain that the POC is testing a possible extension rather than implementing the current draft.

For agent identity, [`draft-araut-oauth-transaction-tokens-for-agents-02`](https://datatracker.ietf.org/doc/html/draft-araut-oauth-transaction-tokens-for-agents-02) defines `sub` as the principal and `act` as the agent, but it is an individual draft rather than an OAuth Working Group standard. Use it only as an explicitly versioned experimental profile.

### Replay and trust

Transaction Tokens are bearer artifacts and replayable within their short lifetime. A workload may reject repeated use of a `txn` value at that workload, but the same `txn` is expected to appear at different workloads along a legitimate call chain; a global replay cache keyed only by `txn` would reject valid traffic. Keep TTLs to minutes or less, make replay state receiver-scoped, use `txn` only as a correlation identifier, and never log the complete token. The token service and requesting workload also require authenticated channels, and requested scope must not exceed the subject token's authority.

The phrase “no trusted services” should be narrowed. The gateway/PEP, token issuer and signing keys, PostgreSQL validator, and database remain trusted computing-base components. The defensible claim is that services receive no implicit or shared identity and each boundary performs explicit verification with minimized trust.

## AuthZEN and approval workflow

The minimum interoperable API is `POST /access/v1/evaluation` with `subject`, `action`, and `resource`, plus optional `context`. Its response contains required boolean `decision` and optional `context`; `allow`, `deny`, `require_approval`, and `require_two_party` are not conformant wire values in [Authorization API 1.0 Final](https://openid.net/specs/authorization-api-1_0-final.html).

The [Access Request and Approval Profile, Working Group Draft 1](https://openid.github.io/authzen/authzen-access-request-approval-profile-1_0.html), published in July 2026, is a direct fit for human-in-the-loop behavior:

1. The PDP returns `decision: false` with `context.access_request` guidance.
2. The PEP submits an access request to an Access Request Service and receives a durable task handle.
3. A user or second approver completes the task through polling or callback-based workflow.
4. The PEP performs a fresh AuthZEN evaluation; only a new `decision: true` permits the operation.

Approval state therefore belongs in a durable workflow service, not in a stateful PDP. “Two party” is workflow policy attached to the access request, not an authorization decision enum. Correlating AuthZEN's `X-Request-ID` with `txn` is a useful project convention, not a normative requirement. The PEP-to-PDP channel must be protected and the PDP should authenticate the PEP.

## PostgreSQL 18 OAuth feasibility

PostgreSQL 18 does not ship a server token validator. An operator configures `oauth_validator_libraries` in `postgresql.conf`; the named module exports `_PG_oauth_validator_module_init` and a static-lifetime `OAuthValidatorCallbacks` structure with a required validation callback. PostgreSQL only performs basic token syntax checks: the module is responsible for cryptographic verification or introspection, issuer/audience/time validation, authorization, and returning a `palloc`-allocated authenticated identity. See the official [OAuth validator](https://www.postgresql.org/docs/18/oauth-validators.html), [initialization ABI](https://www.postgresql.org/docs/18/oauth-validator-init.html), and [validator safety guidance](https://www.postgresql.org/docs/18/oauth-validator-design.html).

Validator acceptance tests must include invalid signature, issuer, audience, expiry, scope, and key-rotation cases. It must not log tokens. Network discovery or introspection needs authenticated TLS, must remain interruptible, and must finish within `authentication_timeout`; offline verification therefore needs a bounded JWKS cache.

Identity semantics matter to the portfolio demonstration:

- `system_user` exposes the authenticated OAuth identity as `oauth:<identity>`.
- `current_user` is the database execution role and can change through `SET ROLE` or security-definer functions.
- Showing `current_user = <individual>` requires provisioning/requesting/mapping a per-actor role. Otherwise the honest demonstration shows `system_user` as identity and `current_user` as the database authorization role.

Start with normal `pg_ident` mapping. PostgreSQL's `delegate_ident_mapping=1` makes the validator the complete authorization point and is an unnecessarily risky Phase 0 shortcut.

### Client and build choices

The official [libpq OAuth documentation](https://www.postgresql.org/docs/18/libpq-oauth.html) exposes `PQsetAuthDataHook`, allowing an application to supply OAuth bearer data instead of using libpq's built-in flow. This proves the client boundary is extensible, but a Go service need not adopt cgo: [pgx v5.10 added `OAuthTokenProvider`](https://github.com/jackc/pgx/pull/2400), a context-aware callback that returns the bearer token. Pin pgx at v5.10 or newer and test callback cancellation and refresh behavior.

PostgreSQL's `--with-libcurl` enables its optional libpq OAuth client module; it is not a requirement for a custom server validator or for pgx's token callback. Use a pinned official PostgreSQL 18 image and compile only the validator against matching server headers. If the validator performs OIDC discovery/JWKS retrieval, it may independently link libcurl.

[Percona's `pg_oidc_validator`](https://github.com/percona/pg_oidc_validator) is useful reference code for the callback ABI, OIDC discovery, JWKS caching, and error handling, but its published packages are experimental and its test coverage is not evidence of production readiness. Treat it as a design reference, not a dependency or assurance claim.

## Repository and language shape

Use one root Go module with `cmd/tts`, `cmd/gateway`, and `cmd/resource`, plus shared internal packages for health endpoints and token contracts. Keep the validator isolated under `validator/` with its own PGXS build. Commit machine-readable fixtures for Transaction Token, AuthZEN evaluation, access-request, and database-token claims; these fixtures should encode the selected draft/profile version so contract drift is visible in review.

For the server validator, C has the smallest interoperability surface because PostgreSQL defines a C ABI. Rust can improve internal memory safety, but it still requires exported C symbols, unsafe pointer/lifetime handling, PostgreSQL allocation rules, and panic containment. `pgrx` supports PostgreSQL 18 but does not remove the need to prove this OAuth callback ABI. Do not maintain parallel C and Rust validators in the POC.

## Reproducible Compose environment

Compose's short `depends_on` form waits only for a container to start. Use long-form dependencies with `condition: service_healthy`, and `service_completed_successfully` for one-shot initialization, as described by [Docker's startup-order guidance](https://docs.docker.com/compose/how-tos/startup-order/). The standard entrypoint should run `docker compose up --build --wait --wait-timeout <seconds>`.

Every long-running service needs a semantic readiness check. `pg_isready` proves PostgreSQL readiness, not OAuth correctness, so keep a separate end-to-end smoke test that attempts an OAuth connection and checks `system_user` and `current_user`.

Pin tested images. As of this review, official examples use Keycloak 26.7.0; enable `KC_HEALTH_ENABLED`, probe its readiness endpoint on management port 9000, and import a committed realm fixture from `/opt/keycloak/data/import` using `start-dev --import-realm`. Keycloak skips importing a realm that already exists, so use ephemeral state or an explicit reset for deterministic demos. Label `start-dev` as local-demo-only. PostgreSQL 18 uses a version-specific `PGDATA` layout; mount the parent `/var/lib/postgresql` rather than relying on the pre-18 `/var/lib/postgresql/data` convention. See the official [Keycloak container](https://www.keycloak.org/server/containers), [realm import](https://www.keycloak.org/server/importExport), and [health endpoint](https://www.keycloak.org/observability/health) documentation.

## Public-repository CI and security baseline

Phase 0 CI should run on pull requests and pushes to the default branch and include Go formatting/vet/tests, validator compilation, Compose validation/build, and the OAuth smoke test. Keep workflow permissions at `contents: read` or `{}` where possible, pin third-party actions to full commit SHAs, and do not use `pull_request_target` for untrusted code. These controls follow GitHub's [workflow permissions](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax) and [secure-use](https://docs.github.com/en/actions/reference/security/secure-use) guidance.

Add Apache-2.0 `LICENSE`, `SECURITY.md`, `.gitignore`, `.dockerignore`, and weekly Dependabot coverage for `gomod`, `docker`, and `github-actions`. CodeQL supports public repositories and the planned Go/C or Go/Rust stack, but it can be enabled after real source exists if keeping the first Phase 0 gate small.

## Phase 0 implications and approval gates

Phase 0 should be considered complete only when all of the following are true:

- A standards-profile ADR records draft 11, the optional agent extension, AuthZEN Final plus the approval-profile draft, and the chosen database credential model.
- Versioned contract fixtures cover the normative `Txn-Token` header, token-exchange response, boolean AuthZEN response, durable access request, and separate PostgreSQL credential if the conformant design is selected.
- The Go service skeletons expose semantic health endpoints and share only deliberately small internal packages.
- A single validator implementation compiles against the pinned PostgreSQL 18 image, loads through `oauth_validator_libraries`, and has its callback invoked during an OAuth login.
- A Go pgx client supplies a credential through `OAuthTokenProvider`; the smoke test proves both `system_user` and `current_user` semantics and contains at least one rejection case.
- Keycloak realm import and Compose startup are deterministic from a clean clone, with pinned images, health-gated dependencies, and no manual console steps.
- CI runs the checks with minimal permissions and pinned actions, and the public-repository licensing/security baseline is committed.

The highest-value additional Phase 0 implication is the compile/load/login vertical spike. Without it, the phase proves repository cosmetics but leaves the project's most unusual and resume-worthy integration risk unresolved.
