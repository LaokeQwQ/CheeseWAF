#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$repo_root"

fail() {
  echo "::error::$*" >&2
  exit 1
}

expect_targets() {
  local profile="$1"
  local expected="$2"
  local got
  got="$(CHEESEWAF_RELEASE_PROFILE="$profile" bash scripts/ci/release-targets.sh)" ||
    fail "target selection failed for profile ${profile}"
  [[ "$got" == "$expected" ]] ||
    fail "target selection for ${profile}: got '${got}', want '${expected}'"
}

expect_targets server $'linux/amd64\nlinux/arm64\nlinux/loong64'
expect_targets full $'linux/amd64\nlinux/arm64\nlinux/loong64\ndarwin/amd64\ndarwin/arm64\nwindows/amd64\nwindows/arm64'

if CHEESEWAF_RELEASE_PROFILE=unknown bash scripts/ci/release-targets.sh >/dev/null 2>&1; then
  fail "unknown release profile must fail"
fi

explicit=$'linux/arm64\nlinux/amd64'
got="$(CHEESEWAF_RELEASE_PROFILE=server CHEESEWAF_TARGETS='linux/arm64 linux/amd64' bash scripts/ci/release-targets.sh)" ||
  fail "explicit target override must be accepted"
[[ "$got" == "$explicit" ]] ||
  fail "explicit target override: got '${got}', want '${explicit}'"

if CHEESEWAF_RELEASE_PROFILE=server CHEESEWAF_TARGETS='windows/amd64 linux/amd64' \
  bash scripts/ci/release-targets.sh >/dev/null 2>&1; then
  fail "server profile must reject desktop target overrides"
fi

echo "package release profile tests passed."
