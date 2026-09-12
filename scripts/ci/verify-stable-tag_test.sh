#!/usr/bin/env bash
set -euo pipefail

root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$root"

fail() {
  echo "::error::$*" >&2
  exit 1
}

head_sha="$(git rev-parse HEAD)"
parent_sha="$(git rev-parse HEAD^)"

CHEESEWAF_REF_NAME=v0.3.9 \
CHEESEWAF_TAG_COMMIT="$head_sha" \
CHEESEWAF_MASTER_REF=HEAD \
  bash scripts/ci/verify-stable-tag.sh >/dev/null ||
  fail "stable tag verifier must accept the product version on protected master"

if CHEESEWAF_REF_NAME=v9.9.9 \
  CHEESEWAF_TAG_COMMIT="$head_sha" \
  CHEESEWAF_MASTER_REF=HEAD \
  bash scripts/ci/verify-stable-tag.sh >/dev/null; then
  fail "stable tag verifier must reject a tag that differs from product-version"
fi

if CHEESEWAF_REF_NAME=v0.3.9 \
  CHEESEWAF_TAG_COMMIT="$parent_sha" \
  CHEESEWAF_MASTER_REF=HEAD \
  bash scripts/ci/verify-stable-tag.sh >/dev/null; then
  fail "stable tag verifier must reject a commit that is not protected master"
fi

if CHEESEWAF_REF_NAME='v0.3.9;echo-injected' \
  CHEESEWAF_TAG_COMMIT="$head_sha" \
  CHEESEWAF_MASTER_REF=HEAD \
  bash scripts/ci/verify-stable-tag.sh >/dev/null; then
  fail "stable tag verifier must reject non-semver ref names"
fi

echo "stable tag verifier tests passed."
