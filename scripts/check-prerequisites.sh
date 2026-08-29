#!/bin/sh
set -eu

if ! command -v docker >/dev/null 2>&1; then
  echo 'error: Docker is required' >&2
  exit 1
fi

if ! docker compose version >/dev/null 2>&1; then
  echo 'error: Docker Compose v2 or newer is required' >&2
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  echo 'error: the Docker daemon is not available' >&2
  exit 1
fi
