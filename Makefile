SHELL := /bin/sh

.PHONY: build check clean compose-check demo demo-ci down fmt identity-check lint logs oauth-smoke test

build:
	go build ./...

test:
	go test -race ./...

fmt:
	gofmt -w cmd internal spikes

lint:
	./scripts/verify-format.sh
	go vet ./...

compose-check:
	docker compose config --quiet

check: lint test build compose-check

oauth-smoke:
	@if CUSTODY_OAUTH_TOKEN=not-a-jwt docker compose --profile smoke run --rm oauth-smoke >/dev/null 2>&1; then \
		echo 'error: PostgreSQL accepted an invalid OAuth token' >&2; \
		exit 1; \
	fi
	@echo 'rejected: invalid PostgreSQL OAuth token'

demo:
	./scripts/check-prerequisites.sh
	docker compose up --build --wait --wait-timeout 180
	./scripts/smoke.sh

demo-ci: demo

identity-check:
	docker compose up -d --wait keycloak
	@docker compose exec -T keycloak bash -c "exec 3<>/dev/tcp/127.0.0.1/8080; printf 'GET /realms/custody/.well-known/openid-configuration HTTP/1.1\\r\\nHost: 127.0.0.1\\r\\nConnection: close\\r\\n\\r\\n' >&3; grep -q '200 OK' <&3"
	@echo 'Keycloak custody realm imported.'

logs:
	docker compose logs --tail=200

down:
	docker compose --profile smoke down --remove-orphans

clean:
	docker compose --profile smoke down --remove-orphans --volumes
