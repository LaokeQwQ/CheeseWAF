#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHEESEWAF_RELEASE_KIND=stable exec bash "${script_dir}/publish-prerelease.sh" "$@"
