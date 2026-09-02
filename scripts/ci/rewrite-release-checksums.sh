#!/usr/bin/env bash
set -euo pipefail

release_dir="${1:-}"
[[ -n "$release_dir" && -d "$release_dir" ]] || {
  echo "::error::usage: rewrite-release-checksums.sh RELEASE_DIR" >&2
  exit 2
}

abs_release="$(cd "$release_dir" && pwd)"
checksum_tmp="$(mktemp "${abs_release}/.SHA256SUMS.XXXXXX")"
cleanup() {
  if [[ -n "$checksum_tmp" && -f "$checksum_tmp" ]]; then
    rm -f "$checksum_tmp"
  fi
}
trap cleanup EXIT

(
  cd "$abs_release"
  files=()
  while IFS= read -r file; do
    [[ -n "$file" ]] || continue
    files+=("$file")
  done < <(
    find . -maxdepth 1 -type f \
      ! -name SHA256SUMS \
      ! -name '.SHA256SUMS.*' \
      ! -name release-manifest.txt \
      ! -name '*.bundle' \
      ! -name '*.sig' \
      -print | sed 's#^\./##' | sort
  )
  [[ "${#files[@]}" -gt 0 ]] || {
    echo "::error::no release files available for SHA256SUMS" >&2
    exit 1
  }
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "${files[@]}"
  else
    shasum -a 256 "${files[@]}"
  fi
) >"$checksum_tmp"

mv "$checksum_tmp" "${abs_release}/SHA256SUMS"
checksum_tmp=""
