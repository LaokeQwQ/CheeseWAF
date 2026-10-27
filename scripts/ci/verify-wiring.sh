#!/usr/bin/env bash
# Fail when an internal package is unreachable from every binary entrypoint.
#
# A package that no main imports still compiles and still passes its tests, so
# nothing else in CI notices it. This gate is the one place that does.
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$repo_root"

allowlist="scripts/ci/unreachable-internal.allow"

mains="$(bash scripts/ci/go-env.sh go list -f '{{if eq .Name "main"}}{{.ImportPath}}{{end}}' ./... | sed '/^$/d')"
if [[ -z "$mains" ]]; then
  echo "::error::verify-wiring: no main packages found" >&2
  exit 1
fi

reachable="$(mktemp)"
all_internal="$(mktemp)"
offenders="$(mktemp)"
trap 'rm -f "$reachable" "$all_internal" "$offenders"' EXIT

# shellcheck disable=SC2086 # import paths never contain whitespace
bash scripts/ci/go-env.sh go list -deps $mains | sort -u > "$reachable"
bash scripts/ci/go-env.sh go list ./internal/... | sort -u > "$all_internal"

if [[ -f "$allowlist" ]]; then
  grep -vE '^[[:space:]]*(#|$)' "$allowlist" | sed 's/[[:space:]]*$//' | sort -u > "${offenders}.allow"
else
  : > "${offenders}.allow"
fi

comm -13 "$reachable" "$all_internal" | sort -u > "$offenders"
comm -23 "$offenders" "${offenders}.allow" > "${offenders}.unallowed"

if [[ -s "${offenders}.unallowed" ]]; then
  while IFS= read -r path; do
    echo "::error::internal package is unreachable from any binary: ${path}" >&2
  done < "${offenders}.unallowed"
  echo "verify-wiring: add a deliberate entry to ${allowlist} only for an optional adapter that no binary composes." >&2
  exit 1
fi

total="$(wc -l < "$all_internal" | tr -d ' ')"
allowed="$(wc -l < "$offenders" | tr -d ' ')"
if [[ "$allowed" == "0" ]]; then
  echo "wiring: ${total} internal packages, all reachable"
else
  echo "wiring: ${total} internal packages, ${allowed} allowlisted as optional adapters"
fi
