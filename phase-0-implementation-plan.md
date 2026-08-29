# Custody Phase 0 Implementation Plan

**Status:** Implemented and locally verified; CI pending first push
**Prepared:** 2026-08-05
**Estimated effort:** 3 focused days, or 4–5 evenings
**Outcome:** A reproducible, security-conscious repository skeleton that boots cleanly, proves the riskiest PostgreSQL client assumption, and gives Phase 1 stable technical contracts.

## Recommendation

Proceed with Phase 0, but amend the original architecture before scaffolding it.

The original proposal is strong as a portfolio narrative, but two contracts have changed or need sharper wording:

1. Implement the current `draft-ietf-oauth-transaction-tokens-11`, not `-08`. The current profile uses required `iat`, `aud`, `exp`, `txn`, `sub`, `scope`, and `req_wl` claims, with recommended `tctx` and `rctx`. The old `azd` claim was renamed to `tctx`, and purpose is represented by `scope`, not `purp`.
2. Do not present a Transaction Token directly to PostgreSQL as its OAuth bearer credential. The current draft says a Transaction Token is neither an OAuth access token nor a workload authentication credential. Instead, carry the Transaction Token unchanged through the HTTP call chain and use a distinct, short-lived database access token containing the same `txn` correlation identifier.

This separation preserves the project's central demonstration: PostgreSQL authenticates principal context while shared roles express only the operation capability.

## Decisions to lock in Phase 0

### 1. Technology boundary

- **Go 1.26** for the TTS, gateway, resource service, and `custody` CLI.
- **C** for the PostgreSQL OAuth validator.
- A single Go module, proposed as `github.com/manziman/custody`, with commands under `cmd/` and non-public packages under `internal/`.

C is the lower-risk validator choice because PostgreSQL exposes this server module interface in C and ships a C test validator. Rust would add an FFI/framework compatibility question to the project's already novel authentication path without improving the demo.

Use pgx v5.10 or newer for the Go resource service. Its `OAuthTokenProvider` callback supplies a bearer token directly to PostgreSQL's OAUTHBEARER exchange, so the application path can stay pure Go; `libpq` and its auth-data hook remain a standards reference and fallback, not the default runtime dependency.

### 2. Token contract

Define two deliberately different tokens:

| Token | Purpose | Transport | Important claims |
|---|---|---|---|
| Transaction Token | Immutable identity and transaction context across internal HTTP workloads | `Txn-Token` HTTP header | `typ=txntoken+jwt`, `txn`, `sub`, `req_wl`, `scope`, `tctx`, `rctx`, `aud`, `iat`, `exp` |
| Database access token | Authenticate one actor-scoped database connection after policy permits it | PostgreSQL SASL OAUTHBEARER | `typ=at+jwt`, `txn`, `sub`, optional RFC 8693 `act`, database audience, scope, `iat`, `exp`, `jti` |

The Phase 2 gateway will cause the database token to be minted only after an `allow` or completed approval outcome. The database validator will validate the database access token, map its action to a role, and retain `txn` plus principal context in `system_user`.

Workload authentication remains a separate channel from both tokens. The TTS and requesting workload must authenticate each other, and logs record correlation identifiers or token hashes—not complete bearer or Transaction Tokens.

### 3. AuthZEN compatibility

Pin two different maturity levels explicitly:

- AuthZEN Authorization API 1.0 Final for ordinary evaluation.
- AuthZEN Access Request and Approval Profile Draft 1 for escalation.

Keep AuthZEN's wire decision boolean. Map the project's four domain outcomes as follows:

- `allow` → `decision: true`;
- `deny` → `decision: false` with no requestable-denial context;
- `require_approval` → `decision: false` with the profile's `context.access_request`;
- `require_two_party` → the same requestable-denial protocol, with separation of duties enforced by the Access Request Service's workflow policy.

The gateway submits the access request, persists the opaque task handle needed to resume its own execution, and waits or receives a callback. Approval never grants access by itself: the gateway must perform a fresh AuthZEN evaluation, and only a new `decision: true` permits execution. Durable approval state belongs to the Access Request Service, not the stateless PDP or an in-memory gateway request.

### 4. Security wording

Use these claims in public documentation:

- “No implicitly trusted shared service identity in the request path,” rather than “no trusted services.” The issuer, signing keys, policy system, validator, and database policies are explicit trust anchors.
- “Cryptographically verifiable and tamper-evident trace,” rather than “cryptographic proof with no trusted intermediary.” A locally signed hash chain still relies on key custody and is rewritable after key compromise unless independently anchored.
- “The gateway is the business-authorization enforcement point.” Every receiving workload and PostgreSQL still independently validates authenticity, audience, expiry, and scope.

## Scope

### Included

- Git repository and public OSS baseline.
- Architecture corrections and Architecture Decision Records (ADRs).
- Health-only Go processes for TTS, gateway, resource service, and CLI shell.
- Keycloak and PostgreSQL 18 containers with real readiness checks but no Phase 1 identity configuration.
- Reproducible Docker Compose orchestration and a single `make demo` entry point.
- Unit, lint, build, Compose validation, and container smoke checks in CI.
- A time-boxed PostgreSQL OAuth client feasibility spike.

### Explicitly excluded

- Keycloak realm/users/clients and production TLS configuration.
- Transaction-token issuance, JWT verification, JWKS, replay detection, or token exchange.
- Production PostgreSQL validator logic or role mapping.
- PDP integration, policies, approvals, durable compliance logging, demo data, or agent integration.
- Kubernetes, SPIRE, deployment automation, releases, or performance benchmarks.

## Proposed repository shape

```text
.
├── .github/
│   └── workflows/ci.yml
├── cmd/
│   ├── custody/
│   ├── gateway/
│   ├── resource/
│   └── tts/
├── deploy/
│   ├── keycloak/
│   └── postgres/
├── docs/
│   └── adr/
│       ├── 0001-language-and-module-boundaries.md
│       ├── 0002-token-separation.md
│       ├── 0003-authzen-approval-profile.md
│       └── 0004-postgres-oauth-client-path.md
├── internal/
│   ├── health/
│   └── service/
├── scripts/
│   ├── smoke.sh
│   └── verify-format.sh
├── spikes/
│   └── postgres-oauth/
├── testdata/
│   └── contracts/
├── ARCHITECTURE.md
├── CONTRIBUTING.md
├── LICENSE
├── Makefile
├── README.md
├── SECURITY.md
├── compose.yaml
├── go.mod
└── go.sum
```

The spike stays isolated from production packages. Once it proves the path, ADR 0004 records the result; reusable parts move into Phase 1 deliberately rather than becoming accidental production code.

## Work plan

### Workstream A — Correct and freeze the architecture contracts (half day)

1. Update the proposal's standards table from Transaction Tokens `-08` to `-11` and label it clearly as a work in progress.
2. Replace `azd`/`purp` with the current `tctx`/`rctx`/`scope` model and distinguish `req_wl` from the RFC 8693 `act` claim.
3. Revise the diagram to show a Transaction Token on internal HTTP calls and a separate database access token at the PostgreSQL boundary.
4. Correct replay handling: reuse of one `txn` across different workloads is expected, so detection is scoped to a receiving workload and acceptance window rather than implemented as one global uniqueness check.
5. Correct the PostgreSQL build assumption: `--with-libcurl` enables libpq's optional built-in client flow; it is not required for the server validator ABI or pgx's bearer-token callback.
6. Document both PostgreSQL identity values: `system_user` is the authenticated OAuth identity, while `current_user` is the active database authorization role and may change.
7. Add the four ADRs listed above, including rejected alternatives.
8. Add an architecture diagram, trust boundaries, token lifecycle, and explicit invariants to `ARCHITECTURE.md`.
9. Check in specification-derived JSON fixtures for Transaction Token request/response/claims/header propagation and AuthZEN allow, hard-deny, requestable-deny, completed-approval, and fresh re-evaluation messages. Fixtures contain synthetic values and never full live tokens.

**Acceptance:** No Phase 1 task depends on an undefined token type, claim, trust anchor, or policy response shape.

### Workstream B — Establish the OSS repository baseline (quarter day)

1. Initialize Git with `main` as the default branch.
2. Add Apache-2.0 `LICENSE`, `.gitignore`, `.gitattributes`, `.editorconfig`, `SECURITY.md`, and concise contribution guidance.
3. Add a minimal README: thesis, experimental status, prerequisites, `make demo`, component status, and non-production warning.
4. Initialize `github.com/manziman/custody` as a Go 1.26 module.
5. Pin dependencies and container images; record readable versions next to immutable digests where practical.
6. Add `.dockerignore` and weekly Dependabot coverage for Go modules, container images, and GitHub Actions.

**Acceptance:** A clean clone contains no generated files or secrets, has an explicit license, and has one documented developer entry point.

### Workstream C — Scaffold health-only services (half day)

1. Implement a small shared HTTP server package with:
   - `GET /health/live`;
   - `GET /health/ready`;
   - JSON response containing service name and status;
   - bounded HTTP timeouts, structured logs, and graceful shutdown.
2. Create minimal TTS, gateway, and resource command entry points using that package.
3. Create a `custody` command that reports its version and exposes placeholder help without claiming Phase 1 functionality.
4. Add focused tests for health responses, signal-driven shutdown behavior where practical, and configuration validation.
5. Add multi-stage container builds that run the Go processes as a non-root user.

**Acceptance:** Each Go service builds independently, has tests, starts without another service, and exposes no business endpoint.

### Workstream D — Compose the empty architecture (half day)

1. Add these services:
   - Keycloak 26.7.x in development mode with health endpoints enabled;
   - PostgreSQL 18.4 on the Debian-based image needed by the later validator build;
   - TTS, gateway, and resource Go containers.
2. Use health checks plus long-form `depends_on.condition: service_healthy`; container start order alone is not readiness.
3. Bind host-published ports to `127.0.0.1`; do not publish PostgreSQL or the resource service unless a test specifically needs it.
4. Separate front-path and data-path Compose networks so the intended call path is visible, while documenting that Compose networking is not an authorization control.
5. Harden the Go containers with a non-root user, dropped capabilities, `no-new-privileges`, and read-only filesystems with explicit temporary storage.
6. Mount PostgreSQL 18 data at `/var/lib/postgresql`, accounting for the official image's version-specific `PGDATA` layout.
7. Add `.env.example` for non-secret configuration. Development-only credentials must be clearly labeled and confined to local Compose.
8. Make `make demo` run `docker compose up --build --wait --wait-timeout <seconds>`, execute the smoke test, and print a compact component-health table. Add `make down`, `make logs`, `make test`, `make lint`, `make build`, and `make check`.

**Acceptance:** `make demo` starts the stack from a clean clone without manual UI work; every container becomes healthy; the smoke script reaches all intended health endpoints; `make down` stops it cleanly.

### Workstream E — Prove the PostgreSQL OAuth client path (half to one day, time-boxed)

This is the Phase 0 risk-reduction gate, not production authentication.

1. Compile a minimal C validator against the pinned PostgreSQL 18 server headers, load it through `oauth_validator_libraries`, and prove its callback runs.
2. Pin pgx v5.10 or newer and use `OAuthTokenProvider` in a Go test client to provide a pre-existing sentinel bearer token.
3. Connect over OAUTHBEARER and run `SELECT system_user, current_user`, proving both authenticated identity and mapped execution-role semantics.
4. Attempt the same connection with an absent/invalid sentinel token and prove it fails closed.
5. Test provider cancellation and prevent fallback to a weaker authentication method.
6. Run the proof on Linux/amd64 CI and locally on arm64 if Docker access is available.
7. Record the chosen Phase 1 application path in ADR 0004:
   - preferred: pgx's context-aware `OAuthTokenProvider`, keeping the resource service pure Go;
   - fallback: a narrow libpq adapter using `PQsetAuthDataHook` if the pgx path fails the spike;
   - rejected: assuming the older `lib/pq` driver supports PostgreSQL 18 OAUTHBEARER;
   - rejected: using the Transaction Token itself as the bearer credential.

**Acceptance:** The positive and negative paths are automated. If the proof cannot be made reliable within one day, Phase 0 stops with a documented blocker and Phase 1 does not begin.

### Workstream F — CI and handoff (half day)

1. Add a least-privilege GitHub Actions workflow for pushes and pull requests.
2. Pin third-party actions to full commit SHAs and set top-level `permissions: contents: read`.
3. Run:
   - formatting check;
   - `go vet`;
   - unit tests with the race detector;
   - builds for every command;
   - `docker compose config --quiet`;
   - container build and `docker compose up --wait` smoke test;
   - PostgreSQL OAuth feasibility test.
4. Use workflow concurrency cancellation for superseded branch runs.
5. On failure, print Compose status and service logs; always tear the stack down.

**Acceptance:** The same `make check` contract works locally and in CI, and a deliberately broken health check makes CI fail.

## Exit criteria

Phase 0 is complete only when all of the following are true:

- `make demo` is the only command needed to build, start, wait for, and smoke-test the empty architecture.
- TTS, gateway, resource, Keycloak, and PostgreSQL report healthy.
- `make check` passes from a clean clone in GitHub Actions.
- Service containers run non-root and do not contain repository source in their runtime layers.
- No secrets or manually exported Keycloak state are required.
- The PostgreSQL OAUTHBEARER spike proves validator compile/load/callback, pgx token injection, `system_user`/`current_user` semantics, and fail-closed rejection.
- The architecture explicitly separates Transaction Tokens from database access tokens.
- ADRs capture the Go/C boundary, token model, AuthZEN approval-profile mapping, and database client choice.
- The original implementation plan is corrected so Phase 1 cannot accidentally implement the superseded `-08` claim model.

## Planned commits

1. `docs: align architecture with current transaction-token draft`
2. `chore: initialize the custody repository`
3. `feat: add health-only service and compose skeleton`
4. `spike: prove postgres oauth bearer client path`
5. `ci: verify code and compose stack`

Phase 1 should then begin with the Keycloak realm import, followed by TTS issuance and conformance tests. This replaces the original “first three commits” sequence, which started identity configuration before resolving the database-token contract.

## Main risks and controls

| Risk | Phase 0 control |
|---|---|
| The Transaction Tokens draft changes again | Pin implementation and conformance fixtures to `-11`; isolate the profile mapping and record draft status prominently. |
| Transaction Token is misused as OAuth credential | Separate token types in diagrams, ADRs, Go types, issuer audiences, and tests. |
| Go database client path is newer and insufficiently exercised | Pin pgx v5.10+ and prove `OAuthTokenProvider`, cancellation, identity semantics, and fail-closed behavior before Phase 1. |
| Four outcomes are presented as standard AuthZEN behavior | Keep the wire result boolean and implement requestable denials using Access Request and Approval Profile Draft 1. |
| “Zero trust” claim overpromises | Document explicit trust anchors and use NIST-aligned “no implicit trust” wording. |
| Containers work on CI but not the developer's Apple Silicon machine | Use images supporting both amd64 and arm64 and exercise the smoke test on both when available. |
| `make demo` becomes a collection of hidden prerequisites | Check Docker/Compose versions up front and produce actionable errors; keep all configuration committed. |

## Approval checkpoint

Approval of this plan authorizes Phase 0 only. The default assumptions are:

- project/repository name: `custody`;
- Go module: `github.com/manziman/custody`;
- license: Apache-2.0;
- service language: Go 1.26;
- PostgreSQL validator language: C;
- current Transaction Tokens target: draft `-11`;
- AuthZEN approval target: Access Request and Approval Profile Draft 1, isolated because it is not final;
- Phase 0 includes the time-boxed PostgreSQL OAuth client spike.

No repository publication, remote creation, push, or Phase 1 feature implementation is part of this approval.

## Primary references

- [IETF Transaction Tokens draft](https://datatracker.ietf.org/doc/draft-ietf-oauth-transaction-tokens/)
- [RFC 8693: OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/rfc8693/)
- [OpenID Authorization API 1.0](https://openid.net/specs/authorization-api-1_0.html)
- [AuthZEN Access Request and Approval Profile Draft 1](https://openid.github.io/authzen/authzen-access-request-approval-profile-1_0.html)
- [PostgreSQL 18 OAuth authentication](https://www.postgresql.org/docs/18/auth-oauth.html)
- [PostgreSQL 18 OAuth validator modules](https://www.postgresql.org/docs/18/oauth-validators.html)
- [PostgreSQL 18 libpq OAuth hooks](https://www.postgresql.org/docs/18/libpq-oauth.html)
- [pgx OAuth support](https://github.com/jackc/pgx/pull/2400)
- [PostgreSQL upstream OAuth validator test module](https://doxygen.postgresql.org/validator_8c_source.html)
- [NIST SP 800-207: Zero Trust Architecture](https://csrc.nist.gov/pubs/sp/800/207/final)
- [Docker Compose startup order and readiness](https://docs.docker.com/compose/how-tos/startup-order/)
- [GitHub Actions secure use](https://docs.github.com/en/actions/reference/security/secure-use)
