#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/cheesewaf-authorized-blind-lab-test.XXXXXX")"
trap 'rm -rf "$tmp_dir"' EXIT

if ! bash "$repo_root/scripts/ci/run-authorized-blind-lab.sh" >"$tmp_dir/stdout" 2>"$tmp_dir/stderr"; then
  tail -n 40 "$tmp_dir/stderr" >&2 || true
  exit 1
fi
grep -Fxq "authorized blind lab passed" "$tmp_dir/stdout"
echo "authorized blind lab smoke passed"
