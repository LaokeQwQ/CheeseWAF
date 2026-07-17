#!/usr/bin/env bash
set -euo pipefail

output_dir="${1:?output directory is required}"
version="${2:?version is required}"
channel="${3:?channel is required}"
branch="${4:?branch is required}"
commit="${5:?commit is required}"
build_time="${6:?build time is required}"

for value in "$version" "$channel" "$branch" "$commit" "$build_time"; do
  if [[ "$value" == *$'\n'* || "$value" == *$'\r'* ]]; then
    echo "::error::release metadata values must be single-line" >&2
    exit 1
  fi
done

json_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\t/\\t/g'
}

mkdir -p "$output_dir"
cat >"${output_dir}/VERSION" <<EOF
version=${version}
channel=${channel}
branch=${branch}
commit=${commit}
build_time=${build_time}
EOF

cat >"${output_dir}/release.json" <<EOF
{
  "name": "CheeseWAF",
  "version": "$(json_escape "$version")",
  "channel": "$(json_escape "$channel")",
  "branch": "$(json_escape "$branch")",
  "commit": "$(json_escape "$commit")",
  "build_time": "$(json_escape "$build_time")"
}
EOF
