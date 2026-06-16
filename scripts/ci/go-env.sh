#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"

# Keep Go caches outside the repository. Go treats every directory under the
# module root as a potential package during `go mod tidy` and `go test ./...`;
# a module cache under tmp/ contains @version paths that break those commands.
cache_root="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/cheesewaf-go"
mkdir -p "${cache_root}/mod" "${cache_root}/build"

export GOMODCACHE="${GOMODCACHE:-${cache_root}/mod}"
export GOCACHE="${GOCACHE:-${cache_root}/build}"

needs_repo_cache_stash=false
if [ "${1:-}" = "go" ]; then
  shift
  set -- go "$@"
  case "${2:-}" in
    mod)
      if [ "${3:-}" = "tidy" ]; then
        needs_repo_cache_stash=true
      fi
      ;;
    test|list)
      for arg in "$@"; do
        if [ "$arg" = "./..." ]; then
          needs_repo_cache_stash=true
          break
        fi
      done
      ;;
  esac
fi

restore_path=""
if [ "${needs_repo_cache_stash}" = true ] && [ -d "${repo_root}/tmp/gomodcache" ]; then
  restore_root="${cache_root}/repo-cache-stash-$$"
  mkdir -p "${restore_root}"
  mv "${repo_root}/tmp/gomodcache" "${restore_root}/gomodcache"
  restore_path="${restore_root}/gomodcache"
fi

restore_repo_cache() {
  if [ -n "${restore_path}" ] && [ -d "${restore_path}" ] && [ ! -e "${repo_root}/tmp/gomodcache" ]; then
    mkdir -p "${repo_root}/tmp"
    mv "${restore_path}" "${repo_root}/tmp/gomodcache"
  fi
}
trap restore_repo_cache EXIT

"$@"
