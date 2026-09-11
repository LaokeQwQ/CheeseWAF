#!/usr/bin/env bash
set -euo pipefail
repo_root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$repo_root"
exec python3 "$repo_root/scripts/acceptance/matrix.py" "$@"
