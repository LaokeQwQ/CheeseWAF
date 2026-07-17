#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$repo_root"

mode="${1:-all}"
coverage_floor="${GO_COVERAGE_FLOOR:-20.0}"

verify_format() {
  mapfile -t unformatted < <(gofmt -l cmd internal)
  if (( ${#unformatted[@]} > 0 )); then
    printf '::error::gofmt is required for:\n' >&2
    printf '%s\n' "${unformatted[@]}" >&2
    return 1
  fi
}

verify_vet() {
  bash scripts/ci/go-env.sh go vet ./cmd/... ./internal/...
}

verify_coverage() {
  local profile total
  profile="$(mktemp)"
  trap 'rm -f "$profile"' RETURN
  bash scripts/ci/go-env.sh go test -count=1 -covermode=atomic -coverprofile="$profile" ./cmd/... ./internal/...
  total="$(go tool cover -func="$profile" | awk '/^total:/ { sub(/%$/, "", $3); print $3 }')"
  [[ "$total" =~ ^[0-9]+([.][0-9]+)?$ ]] || {
    echo "::error::unable to parse Go coverage" >&2
    return 1
  }
  awk -v actual="$total" -v floor="$coverage_floor" 'BEGIN { exit !(actual + 0 >= floor + 0) }' || {
    echo "::error::Go coverage ${total}% is below ${coverage_floor}%" >&2
    return 1
  }
  echo "Go coverage ${total}% meets ${coverage_floor}% floor."
}

case "$mode" in
  format) verify_format ;;
  vet) verify_vet ;;
  coverage) verify_coverage ;;
  all)
    verify_format
    verify_vet
    verify_coverage
    ;;
  *)
    echo "usage: $0 [format|vet|coverage|all]" >&2
    exit 2
    ;;
esac
