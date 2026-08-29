# Keycloak deployment

Custody imports `custody-realm.json` on every fresh Keycloak container. It
contains one stable human fixture, a public S256-PKCE-only CLI client, an
explicit automation principal, and distinct confidential service-account
clients with narrow audiences and `fullScopeAllowed: false`.

The realm explicitly declares and attaches the `custody-subject` client scope.
Its `oidc-sub-mapper` keeps the human `sub` in the access token even though the
realm intentionally does not import Keycloak's broader built-in default scopes.
The fixture test treats that mapper as part of the attribution contract.

Passwords and client secrets use environment placeholders resolved by
Keycloak during import. Compose supplies development-only defaults; the realm
file itself does not contain a deployable secret.

`start-dev` and the bootstrap credentials in `compose.yaml` are for the
isolated local demonstration only.
