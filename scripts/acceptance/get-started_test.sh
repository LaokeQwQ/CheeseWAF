#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
runner="${repo_root}/scripts/acceptance/get-started.sh"

fail() { echo "FAIL: $*" >&2; exit 1; }
[[ -x "$runner" ]] || fail "missing executable get-started acceptance runner"

output="$(mktemp)"
trap 'rm -f "$output"' EXIT

if ! bash "$runner" --static-contract >"$output" 2>&1; then
  cat "$output" >&2
  fail "static contract acceptance failed"
fi
grep -Fq "temporary profile" "$output" || fail "temporary profile evidence missing"
grep -Fq "production profile rejected" "$output" || fail "production rejection evidence missing"
grep -Fq "runtime data isolated" "$output" || fail "runtime isolation evidence missing"
grep -Fq "cleanup verified" "$output" || fail "cleanup evidence missing"

echo "get-started acceptance test passed"
