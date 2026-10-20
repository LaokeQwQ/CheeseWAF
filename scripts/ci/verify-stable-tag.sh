#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ref_name="${CHEESEWAF_REF_NAME:-${GITHUB_REF_NAME:-}}"
tag_commit="${CHEESEWAF_TAG_COMMIT:-${GITHUB_SHA:-}}"
master_ref="${CHEESEWAF_MASTER_REF:-origin/master}"
ref_protected="${CHEESEWAF_REF_PROTECTED:-${GITHUB_REF_PROTECTED:-}}"
product_version="$(tr -d '[:space:]' <"${script_dir}/product-version")"

fail() {
  echo "::error::$*" >&2
  exit 1
}

case "$ref_name" in
  "v${product_version}") ;;
  "v${product_version}-beta") ;;
  *)
    fail "release ref ${ref_name} must be v${product_version} or v${product_version}-beta"
    ;;
esac
[[ "$tag_commit" =~ ^[0-9a-fA-F]{40}$ ]] ||
  fail "stable release commit must be a full 40-character SHA"

tag_commit_resolved="$(git rev-parse --verify --end-of-options "${tag_commit}^{commit}")" ||
  fail "could not resolve stable tag commit ${tag_commit}"
master_commit="$(git rev-parse --verify --end-of-options "${master_ref}^{commit}")" ||
  fail "could not resolve protected master ref ${master_ref}"
[[ "$tag_commit_resolved" == "$master_commit" ]] ||
  fail "stable tag ${ref_name} does not point at ${master_ref} (${tag_commit_resolved} != ${master_commit})"

# A matching commit is necessary but insufficient: signing credentials are
# only released for tags protected by repository rules. Local regression tests
# omit this value; CI must pass the GitHub ref-protection signal explicitly.
if [[ -n "$ref_protected" && "$ref_protected" != "true" ]]; then
  fail "stable release tag ${ref_name} is not protected by repository rules"
fi

echo "Stable tag ${ref_name} matches product version and protected master commit ${master_commit}."
