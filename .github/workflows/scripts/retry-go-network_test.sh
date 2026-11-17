#!/usr/bin/env bash

# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

set -eu -o pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
test_dir=$(mktemp -d)
trap 'rm -rf "$test_dir"' EXIT

# Stub only the command and backoff; the retry wrapper itself is unmodified.
cat >"$test_dir/command" <<'EOF'
#!/usr/bin/env bash
count=0
[[ ! -e "$TEST_COUNT" ]] || count=$(cat "$TEST_COUNT")
count=$((count + 1))
echo "$count" >"$TEST_COUNT"
case "$TEST_CASE" in
  transient)
    if [[ "$count" -ge 3 ]]; then exit 0; fi
    ;;
  exhausted) ;;
  forbidden)
    echo 'read "https://proxy.golang.org/example/@v/v1.zip": 403 Forbidden'
    exit 19
    ;;
  compiler)
    echo 'compile error: undefined: incompatibleAPI'
    exit 17
    ;;
  success)
    echo 'read "https://proxy.golang.org/example/@v/v1.zip": stream error: INTERNAL_ERROR'
    exit 0
    ;;
esac
echo 'read "https://proxy.golang.org/example/@v/v1.zip": stream error: stream ID 93; INTERNAL_ERROR; received from peer'
exit 23
EOF
printf '#!/usr/bin/env bash\nexit 0\n' >"$test_dir/sleep"
chmod +x "$test_dir/command" "$test_dir/sleep"
export PATH="$test_dir:$PATH"
export TEST_COUNT="$test_dir/count"

check() {
  export TEST_CASE=$1
  local expected_status=$2 expected_count=$3 status=0
  rm -f "$TEST_COUNT"
  bash "$script_dir/retry-go-network.sh" "$test_dir/command" >"$test_dir/log" 2>&1 || status=$?
  if [[ "$status" -ne "$expected_status" || "$(cat "$TEST_COUNT")" -ne "$expected_count" ]]; then
    cat "$test_dir/log"
    echo "Failed retry contract: $TEST_CASE" >&2
    exit 1
  fi
}

check transient 0 3
check exhausted 23 3
check forbidden 19 1
check compiler 17 1
check success 0 1
echo 'Go network retry: 5 checks passed'
