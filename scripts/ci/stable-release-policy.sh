#!/usr/bin/env bash

# Shared fail-closed policy for the server-only stable release profile.
# This file is sourced by verification and publishing scripts; it must not
# perform work when executed directly.

stable_release_archive_patterns() {
  printf '%s\n' \
    'cheesewaf-amd64-linux-*.tar.gz' \
    'cheesewaf-arm64-linux-*.tar.gz' \
    'cheesewaf-loong64-linux-*.tar.gz'
}

stable_release_asset_is_allowed() {
  local name="$1"
  local version="${2:-}"
  if [[ -n "$version" ]]; then
    case "$name" in
      "cheesewaf-amd64-linux-${version}.tar.gz" \
        | "cheesewaf-arm64-linux-${version}.tar.gz" \
        | "cheesewaf-loong64-linux-${version}.tar.gz" \
        | SHA256SUMS \
        | SHA256SUMS.bundle \
        | cheesewaf.cdx.json \
        | cheesewaf.cdx.json.bundle \
        | cheesewaf-artifacts.cdx.json \
        | cheesewaf-artifacts.cdx.json.bundle \
        | artifacts.manifest.json \
        | artifacts.manifest.json.bundle)
        return 0
        ;;
      *)
        return 1
        ;;
    esac
  fi
  case "$name" in
    cheesewaf-amd64-linux-*.tar.gz \
      | cheesewaf-arm64-linux-*.tar.gz \
      | cheesewaf-loong64-linux-*.tar.gz \
      | SHA256SUMS \
      | SHA256SUMS.bundle \
      | cheesewaf.cdx.json \
      | cheesewaf.cdx.json.bundle \
      | cheesewaf-artifacts.cdx.json \
      | cheesewaf-artifacts.cdx.json.bundle \
      | artifacts.manifest.json \
      | artifacts.manifest.json.bundle)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

stable_release_validate_top_level() {
  local release_dir="$1"
  local label="${2:-stable release}"
  local version="${3:-}"
  local file
  local name
  while IFS= read -r file; do
    [[ -n "$file" ]] || continue
    name="$(basename "$file")"
    [[ "$name" == "release-manifest.txt" ]] && continue
    stable_release_asset_is_allowed "$name" "$version" || {
      echo "::error::${label} rejects unclassified top-level asset: ${name}" >&2
      return 1
    }
  done < <(find "$release_dir" -maxdepth 1 -type f -print | sort)
}

stable_release_require_archives() {
  local release_dir="$1"
  local version="${2:-}"
  local pattern
  local count
  while IFS= read -r pattern; do
    [[ -n "$pattern" ]] || continue
    if [[ -n "$version" ]]; then
      pattern="${pattern/\*/${version}}"
    fi
    count="$(find "$release_dir" -maxdepth 1 -type f -name "$pattern" -print | awk 'END { print NR + 0 }')"
    [[ "$count" -eq 1 ]] || {
      echo "::error::stable server release requires exactly one ${pattern} artifact" >&2
      return 1
    }
  done < <(stable_release_archive_patterns)
}
