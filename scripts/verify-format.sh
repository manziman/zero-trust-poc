#!/bin/sh
set -eu

unformatted="$(gofmt -l cmd internal spikes)"
if [ -n "${unformatted}" ]; then
  echo 'Go files require formatting:' >&2
  echo "${unformatted}" >&2
  exit 1
fi
