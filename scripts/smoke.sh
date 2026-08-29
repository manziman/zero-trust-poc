#!/bin/sh
set -eu

for service_name in tts gateway resource agent; do
  docker compose exec -T "${service_name}" /custody-service healthcheck
  echo "healthy: ${service_name}"
done

docker compose --profile demo run --build --rm demo-run

if CUSTODY_OAUTH_TOKEN=not-a-jwt \
  docker compose --profile smoke run --rm oauth-smoke >/dev/null 2>&1; then
  echo 'error: PostgreSQL accepted an invalid OAuth token' >&2
  exit 1
fi

echo 'rejected: invalid PostgreSQL OAuth token'
echo 'The stack enforced four principal paths, scheduling capabilities, multi-tenant RLS, and a fail-closed OAuth boundary.'
