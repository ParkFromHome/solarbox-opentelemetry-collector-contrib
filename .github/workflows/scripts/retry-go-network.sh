#!/usr/bin/env bash

# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

# Retry known Go module transport failures and preserve the final command status.
set -eu -o pipefail

log=$(mktemp)
trap 'rm -f "$log"' EXIT

for attempt in 1 2 3; do
  if "$@" >"$log" 2>&1; then
    cat "$log"
    exit 0
  else
    status=$?
  fi
  cat "$log"
  if [[ "$attempt" -eq 3 ]] || ! grep -Eq '(read|Get) "https://(proxy\.golang\.org|sum\.golang\.org|storage\.googleapis\.com)/[^"]+":.*(INTERNAL_ERROR|connection reset by peer|TLS handshake timeout|i/o timeout|unexpected EOF)' "$log"; then
    exit "$status"
  fi
  echo "Transient Go download failure; retrying ($attempt/3)" >&2
  sleep "$((attempt * 2))"
done
