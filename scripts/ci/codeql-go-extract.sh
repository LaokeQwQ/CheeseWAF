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

echo "::group::go build (default tags)"
go_cmd build ./...
echo "::endgroup::"

compile_tests() {
  local tags="${1:-}"
  local -a list_args=(./...)
  local -a test_args=(-c -o "${null_out}")
  if [[ -n "${tags}" ]]; then
    list_args=(-tags "${tags}" ./...)
    test_args=(-tags "${tags}" -c -o "${null_out}")
  fi

  local pkg
  while IFS= read -r pkg; do
    [[ -z "${pkg}" ]] && continue
    # Packages without tests still compile cleanly with -c on modern Go.
    if ! go_cmd test "${test_args[@]}" "${pkg}"; then
      echo "::warning::go test -c failed for ${pkg} (tags=${tags:-default}); continuing"
    fi
  done < <(go_cmd list "${list_args[@]}")
}

echo "::group::go test -c (default tags, extract _test.go)"
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

echo "CodeQL Go extract build finished (GOOS=$(go_cmd env GOOS) GOARCH=$(go_cmd env GOARCH))"
