#!/usr/bin/env bash
set -euo pipefail

output_dir="${1:?output directory is required}"
version="${2:?version is required}"
channel="${3:?channel is required}"
branch="${4:?branch is required}"
commit="${5:?commit is required}"
build_time="${6:?build time is required}"
prerelease_tag="${7:-}"

for value in "$version" "$channel" "$branch" "$commit" "$build_time" "$prerelease_tag"; do
  if [[ "$value" == *$'\n'* || "$value" == *$'\r'* ]]; then
    echo "::error::release metadata values must be single-line" >&2
    exit 1
  fi
done

json_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\t/\\t/g'
}

mkdir -p "$output_dir"
{
  printf 'version=%s\n' "$version"
  printf 'channel=%s\n' "$channel"
  printf 'branch=%s\n' "$branch"
  printf 'commit=%s\n' "$commit"
  printf 'build_time=%s\n' "$build_time"
  if [[ -n "$prerelease_tag" ]]; then
    printf 'prerelease_tag=%s\n' "$prerelease_tag"
  fi
} >"${output_dir}/VERSION"

{
  printf '{\n'
  printf '  "name": "CheeseWAF",\n'
  printf '  "version": "%s",\n' "$(json_escape "$version")"
  printf '  "channel": "%s",\n' "$(json_escape "$channel")"
  printf '  "branch": "%s",\n' "$(json_escape "$branch")"
  printf '  "commit": "%s",\n' "$(json_escape "$commit")"
  printf '  "build_time": "%s"' "$(json_escape "$build_time")"
  if [[ -n "$prerelease_tag" ]]; then
    printf ',\n  "prerelease_tag": "%s"' "$(json_escape "$prerelease_tag")"
  fi
  printf '\n}\n'
} >"${output_dir}/release.json"
