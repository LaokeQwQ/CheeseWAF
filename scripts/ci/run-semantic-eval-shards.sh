#!/usr/bin/env bash
# Run the full semantic evaluation platform in N parallel shards.
#
# The large external benign corpus (cybersec_benign_clean.jsonl, ~107 MiB) is
# normally report-only and skipped by -short. Running it as one process exceeds
# the Go test 10-minute limit when the paranoia sweep (0..5) re-scans every
# sample. This script shards deterministically by case name via
# internal/securitytest.ShardIndexFor so shards can be merged/aggregated.
#
# Usage:
#   SEMANTIC_EVAL_SHARDS=8 bash scripts/ci/run-semantic-eval-shards.sh
#
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
shards="${SEMANTIC_EVAL_SHARDS:-8}"
timeout="${SEMANTIC_EVAL_TIMEOUT:-20m}"

if ! [[ "$shards" =~ ^[1-9][0-9]*$ ]]; then
  echo "::error::SEMANTIC_EVAL_SHARDS must be a positive integer (got '${shards}')" >&2
  exit 1
fi
if [[ "$shards" -eq 1 ]]; then
  echo "Single-shard run; using a single process."
fi

log_dir="${SEMANTIC_EVAL_LOG_DIR:-/tmp/semantic-eval-shards}"
mkdir -p "$log_dir"

pids=""
fail=0
for (( i = 0; i < shards; i++ )); do
  log="${log_dir}/shard-${i}.log"
  (
    cd "$repo_root"
    SEMANTIC_EVAL_SHARDS="$shards" \
    SEMANTIC_EVAL_SHARD_INDEX="$i" \
      go test -run TestEvaluationPlatform -count=1 -timeout "$timeout" ./internal/engine/semantic/ >"$log" 2>&1
  ) &
  pids="$pids $!"
done

for p in $pids; do
  if ! wait "$p"; then
    fail=1
  fi
done

if [[ "$fail" -ne 0 ]]; then
  echo "::error::semantic eval shards failed (logs in ${log_dir})" >&2
  for (( i = 0; i < shards; i++ )); do
    if grep -qE 'FAIL|fatal|panic' "${log_dir}/shard-${i}.log" 2>/dev/null; then
      echo "--- shard ${i} tail ---" >&2
      tail -40 "${log_dir}/shard-${i}.log" >&2 || true
    fi
  done
  exit 1
fi

echo "All ${shards} semantic eval shards passed; logs: ${log_dir}/shard-*.log"
