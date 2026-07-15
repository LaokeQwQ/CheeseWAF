#!/usr/bin/env bash
# Build every package (and its tests) so the CodeQL Go extractor can see
# production sources, _test.go files, and optional build-tagged packages.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

go_cmd() {
  bash scripts/ci/go-env.sh go "$@"
}

null_out="/dev/null"
uname_s="$(uname -s 2>/dev/null || true)"
if [[ "${OS:-}" == "Windows_NT" || "${uname_s}" == MINGW* || "${uname_s}" == MSYS* || "${uname_s}" == CYGWIN* ]]; then
  null_out="NUL"
fi

# Parallel package compiles (compile only; do not run tests).
jobs="$(go_cmd env GOMAXPROCS 2>/dev/null || true)"
if [[ -z "${jobs}" || "${jobs}" -lt 1 ]]; then
  jobs="$(getconf _NPROCESSORS_ONLN 2>/dev/null || nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)"
fi

echo "::group::go build (default tags)"
go_cmd build ./...
echo "::endgroup::"

compile_tests() {
  local tags="${1:-}"
  local -a list_args=(./...)
  local -a test_base=(-c -o "${null_out}")
  if [[ -n "${tags}" ]]; then
    list_args=(-tags "${tags}" ./...)
    test_base=(-tags "${tags}" -c -o "${null_out}")
  fi

  local pkgs
  mapfile -t pkgs < <(go_cmd list "${list_args[@]}")
  if [[ "${#pkgs[@]}" -eq 0 ]]; then
    return 0
  fi

  # Prefer one-shot compile+noop-exec when available (fast path).
  # Falls back to parallel per-package -c if the bulk path fails.
  local -a bulk=(-count=1 -exec true)
  if [[ -n "${tags}" ]]; then
    bulk=(-tags "${tags}" -count=1 -exec true)
  fi
  if go_cmd test "${bulk[@]}" ./...; then
    return 0
  fi

  echo "::warning::bulk go test -exec true failed (tags=${tags:-default}); falling back to parallel go test -c"

  printf '%s\n' "${pkgs[@]}" | xargs -P "${jobs}" -n 1 -I{} bash -c '
    set +e
    pkg="$1"
    shift
    bash scripts/ci/go-env.sh go test "$@" "$pkg"
    status=$?
    if [[ $status -ne 0 ]]; then
      echo "::warning::go test -c failed for ${pkg}; continuing"
    fi
    exit 0
  ' _ {} "${test_base[@]}"
}

echo "::group::go test (default tags, extract _test.go)"
compile_tests ""
echo "::endgroup::"

# Optional lab / e2e plan only present under //go:build captchae2e.
if go_cmd list -e -tags captchae2e ./internal/captcha ./scripts/e2e/captcha-integration/fixture >/dev/null 2>&1; then
  echo "::group::go build/test -tags captchae2e"
  if ! go_cmd build -tags captchae2e ./internal/captcha/... ./scripts/e2e/captcha-integration/fixture/...; then
    echo "::warning::captchae2e build failed; continuing"
  fi
  compile_tests "captchae2e"
  echo "::endgroup::"
fi

echo "CodeQL Go extract build finished (GOOS=$(go_cmd env GOOS) GOARCH=$(go_cmd env GOARCH) jobs=${jobs})"
