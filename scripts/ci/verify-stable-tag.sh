#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ref_name="${CHEESEWAF_REF_NAME:-${GITHUB_REF_NAME:-}}"
tag_commit="${CHEESEWAF_TAG_COMMIT:-${GITHUB_SHA:-}}"
master_ref="${CHEESEWAF_MASTER_REF:-origin/master}"
product_version="$(tr -d '[:space:]' <"${script_dir}/product-version")"

fail() {
  echo "::error::$*" >&2
  exit 1
}

[[ "$ref_name" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] ||
  fail "stable release ref must use vMAJOR.MINOR.PATCH: ${ref_name}"
[[ "$ref_name" == "v${product_version}" ]] ||
  fail "stable release ref ${ref_name} does not match product version v${product_version}"
[[ "$tag_commit" =~ ^[0-9a-fA-F]{40}$ ]] ||
  fail "stable release commit must be a full 40-character SHA"

tag_commit_resolved="$(git rev-parse --verify --end-of-options "${tag_commit}^{commit}")" ||
  fail "could not resolve stable tag commit ${tag_commit}"
master_commit="$(git rev-parse --verify --end-of-options "${master_ref}^{commit}")" ||
  fail "could not resolve protected master ref ${master_ref}"
[[ "$tag_commit_resolved" == "$master_commit" ]] ||
  fail "stable tag ${ref_name} does not point at ${master_ref} (${tag_commit_resolved} != ${master_commit})"

echo "Stable tag ${ref_name} matches product version and protected master commit ${master_commit}."
