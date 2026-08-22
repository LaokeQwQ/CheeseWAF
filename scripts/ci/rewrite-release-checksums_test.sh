#!/usr/bin/env bash
set -euo pipefail

root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$root"

fail() {
  echo "::error::$*" >&2
  exit 1
}

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
release_dir="${tmp}/release"
mkdir -p "$release_dir"
printf 'archive\n' >"${release_dir}/cheesewaf-test.tar.gz"
printf '{}\n' >"${release_dir}/artifacts.manifest.json"
printf 'notes\n' >"${release_dir}/release-manifest.txt"
printf 'stale\n' >"${release_dir}/SHA256SUMS.bundle"

bash scripts/ci/rewrite-release-checksums.sh "$release_dir"
bash scripts/ci/rewrite-release-checksums.sh "$release_dir"

[[ "$(wc -l <"${release_dir}/SHA256SUMS" | tr -d '[:space:]')" == 2 ]] ||
  fail "checksum rewrite must be idempotent and list exactly two payloads"
grep -Fq 'artifacts.manifest.json' "${release_dir}/SHA256SUMS" ||
  fail "fallback artifact manifest must be checksummed"
grep -Fq 'cheesewaf-test.tar.gz' "${release_dir}/SHA256SUMS" ||
  fail "release archive must be checksummed"
if grep -Eq 'SHA256SUMS|release-manifest|\.bundle|\.sig' "${release_dir}/SHA256SUMS"; then
  fail "checksum manifest contains a generated or excluded sidecar"
fi
(
  cd "$release_dir"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -c SHA256SUMS
  else
    shasum -a 256 -c SHA256SUMS
  fi
) >/dev/null

echo "release checksum rewrite tests passed."
