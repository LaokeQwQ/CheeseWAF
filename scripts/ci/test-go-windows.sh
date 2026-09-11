#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$repo_root"

go_cmd() {
  bash scripts/ci/go-env.sh go "$@"
}

fail() {
  echo "::error::$*" >&2
  exit 1
}

# Windows does not provide the POSIX mode-bit and directory-fsync semantics
# required by these packages' current secure-file implementations. Keep their
# tests on the POSIX runners until equivalent Windows ACL/file-flush adapters
# exist; do not weaken the production checks just to make this job pass.
windows_excluded_suffixes=(
  /internal/cli/migration
  /internal/controlplane/nativeraft
  /internal/controlplane/runtime
  /internal/crp
  /internal/crp/activation
  /internal/cwedp/transport
  /internal/diagnostics/integration
  /internal/diagnostics/queue
  /internal/netlease
  /internal/recovery
  /internal/recovery/kms
  /internal/setup
)

echo "::group::go test compile (all packages, Windows)"
go_cmd test -race -short -count=1 -run '^$' ./cmd/... ./internal/...
echo "::endgroup::"

all_packages=()
while IFS= read -r package; do
  [[ -n "$package" ]] || continue
  all_packages+=("$package")
done < <(go_cmd list ./cmd/... ./internal/...)
[[ "${#all_packages[@]}" -gt 0 ]] || fail "go list returned no Windows test packages"

portable_packages=()
for package in "${all_packages[@]}"; do
  excluded=false
  for suffix in "${windows_excluded_suffixes[@]}"; do
    if [[ "$package" == *"$suffix" ]]; then
      excluded=true
      break
    fi
  done
  if [[ "$excluded" == false ]]; then
    portable_packages+=("$package")
  fi
done
[[ "${#portable_packages[@]}" -gt 0 ]] || fail "Windows portable package set is empty"

echo "Windows POSIX-only exclusions:"
printf '  - %s\n' "${windows_excluded_suffixes[@]}"
echo "::group::go test portable packages (Windows)"
# The CLI package is portable except for CRP tests that materialize the
# POSIX-mode RuntimeStore. Keep the package in the job and skip only those
# explicitly named tests; all other CLI tests still run on Windows.
go_cmd test -race -short -count=1 -skip '^TestCRP' "${portable_packages[@]}"
echo "::endgroup::"
