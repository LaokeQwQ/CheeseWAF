#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
release_dir="${1:-release}"
release_kind="$(awk -F': ' '/^release_kind:/{print $2; exit}' "${release_dir}/release-manifest.txt")"
case "$release_kind" in
  stable | beta) ;;
  *)
    echo "::error::publish-release requires release_kind stable or beta: ${release_kind}" >&2
    exit 1
    ;;
esac
CHEESEWAF_RELEASE_KIND="$release_kind" exec bash "${script_dir}/publish-prerelease.sh" "$@"
