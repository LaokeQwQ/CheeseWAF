#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"

# Go's test helpers use os.TempDir for process-sidecar fixtures. A shared
# runner /tmp is commonly mode 0777, which must be rejected by production
# sidecar admission. Keep every wrapped Go command on a private, disposable
# temp root whose path components remain outside shared, world-writable space.
private_tmp_parent="${RUNNER_TEMP:-${HOME:-/tmp}}"
if [[ ! -d "${private_tmp_parent}" || -L "${private_tmp_parent}" ]]; then
  private_tmp_parent="${repo_root}"
fi
private_tmp="$(mktemp -d "${private_tmp_parent%/}/cheesewaf-ci-tmp.XXXXXX")"
chmod 700 "${private_tmp}"

# Keep Go caches outside the repository. Go treats every directory under the
# module root as a potential package during `go mod tidy` and `go test ./...`;
# a module cache under tmp/ contains @version paths that break those commands.
# Normalize caller-provided temporary roots first: Go rejects relative
# GOMODCACHE/GOCACHE values even when the surrounding shell script is valid.
cache_parent="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
if [[ "${cache_parent}" != /* ]]; then
  # A relative TMPDIR is useful for exercising the higher-level scripts, but
  # putting Go's persistent cache under the repository dirties the worktree
  # (and can make `go test ./...` discover cache internals as packages). Keep
  # the cache in the host temporary area instead; output paths are normalized
  # independently by the caller that owns them.
  cache_parent="/tmp"
fi
if ! cache_parent="$(cd "${cache_parent}" 2>/dev/null && pwd -P)"; then
  echo "temporary cache root must name an existing directory: ${RUNNER_TEMP:-${TMPDIR:-/tmp}}" >&2
  exit 1
fi
cache_root="${cache_parent}/cheesewaf-go"
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
cleanup() {
  restore_repo_cache
  rm -rf -- "${private_tmp}"
}
trap cleanup EXIT

export TMPDIR="${private_tmp}"
"$@"
