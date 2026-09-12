#!/usr/bin/env bash
set -euo pipefail

root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
verifier="${root}/scripts/ci/verify-stable-tag.sh"
test_repo="$(mktemp -d)"
trap 'rm -rf -- "$test_repo"' EXIT

fail() {
  echo "::error::$*" >&2
  exit 1
}

git -C "$test_repo" init -q
git -C "$test_repo" config user.name "CheeseWAF CI"
git -C "$test_repo" config user.email "ci@localhost"
git -C "$test_repo" commit --allow-empty -qm "test: non-master commit"
parent_sha="$(git -C "$test_repo" rev-parse HEAD)"
git -C "$test_repo" commit --allow-empty -qm "test: protected master"
head_sha="$(git -C "$test_repo" rev-parse HEAD)"

run_verifier() {
  local ref_name="$1"
  local tag_commit="$2"
  local master_ref="$3"

  (
    cd "$test_repo"
    CHEESEWAF_REF_NAME="$ref_name" \
      CHEESEWAF_TAG_COMMIT="$tag_commit" \
      CHEESEWAF_MASTER_REF="$master_ref" \
      bash "$verifier"
  )
}

run_verifier v0.3.9 "$head_sha" "$head_sha" >/dev/null ||
  fail "stable tag verifier must accept the product version on protected master"

if run_verifier v9.9.9 "$head_sha" "$head_sha" >/dev/null; then
  fail "stable tag verifier must reject a tag that differs from product-version"
fi

if run_verifier v0.3.9 "$parent_sha" "$head_sha" >/dev/null; then
  fail "stable tag verifier must reject a commit that is not protected master"
fi

if run_verifier 'v0.3.9;echo-injected' "$head_sha" "$head_sha" >/dev/null; then
  fail "stable tag verifier must reject non-semver ref names"
fi

echo "stable tag verifier tests passed."
