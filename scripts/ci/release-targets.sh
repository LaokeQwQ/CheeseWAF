#!/usr/bin/env bash
set -euo pipefail

release_targets() {
  local profile="${CHEESEWAF_RELEASE_PROFILE:-full}"
  local default_targets

  case "$profile" in
    server)
      default_targets='linux/amd64 linux/arm64 linux/loong64'
      ;;
    full)
      default_targets='linux/amd64 linux/arm64 linux/loong64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64'
      ;;
    *)
      echo "::error::CHEESEWAF_RELEASE_PROFILE must be server or full: ${profile}" >&2
      return 2
      ;;
  esac

  local target_spec="${CHEESEWAF_TARGETS:-$default_targets}"
  local targets=()
  read -r -a targets <<<"$target_spec"
  [[ "${#targets[@]}" -gt 0 ]] || {
    echo "::error::release target list must not be empty" >&2
    return 2
  }
  # A server release is an immutable Linux-only contract. Keep explicit
  # overrides useful for Linux smoke tests, but never allow desktop targets
  # into a stable server release.
  if [[ "$profile" == "server" ]]; then
    local target
    for target in "${targets[@]}"; do
      case "$target" in
        linux/amd64 | linux/arm64 | linux/loong64) ;;
        *)
          echo "::error::server release profile only permits Linux targets: ${target}" >&2
          return 2
          ;;
      esac
    done
  fi
  printf '%s\n' "${targets[@]}"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  release_targets
fi
