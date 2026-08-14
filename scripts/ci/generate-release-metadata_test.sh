#!/usr/bin/env bash
set -euo pipefail

root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$root"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

bash scripts/ci/generate-release-metadata.sh \
  "$tmp" '0.1.0-beta.1+abc' stable master abcdef123456 '2026-08-15T00:00:00Z' 'Alpha-0.1.0-beta.1-abc'

grep -Fx 'version=0.1.0-beta.1+abc' "$tmp/VERSION"
grep -Fx 'prerelease_tag=Alpha-0.1.0-beta.1-abc' "$tmp/VERSION"
grep -F '"prerelease_tag": "Alpha-0.1.0-beta.1-abc"' "$tmp/release.json"

bash scripts/ci/generate-release-metadata.sh \
  "$tmp/plain" '0.1.0' dev dev abcdef123456 '2026-08-15T00:00:00Z'
if grep -q prerelease_tag "$tmp/plain/VERSION"; then
  echo "::error::prerelease_tag must be omitted when unset" >&2
  exit 1
fi

echo "generate-release-metadata tests passed."
