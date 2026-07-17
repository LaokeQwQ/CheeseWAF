#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../.." && pwd)"
versions_file="${script_dir}/tool-versions.env"
checksums_file="${script_dir}/tool-checksums.txt"

if [[ ! -r "$versions_file" || ! -r "$checksums_file" ]]; then
  echo "::error::repository tool version or checksum manifest is missing"
  exit 1
fi

# shellcheck disable=SC1090
source "$versions_file"
: "${NODE_VERSION:?NODE_VERSION is required}"

node_satisfies() {
  command -v node >/dev/null 2>&1 || return 1
  command -v npm >/dev/null 2>&1 || return 1
  [[ "$(node -p 'process.versions.node')" == "$NODE_VERSION" ]]
}

if node_satisfies; then
  node --version
  npm --version
else
  command -v curl >/dev/null 2>&1 || {
    echo "::error::curl is required to install Node"
    exit 1
  }
  command -v sha256sum >/dev/null 2>&1 || {
    echo "::error::sha256sum is required to verify Node"
    exit 1
  }

  machine="$(uname -m)"
  case "$machine" in
    x86_64 | amd64)
      nodearch="x64"
      ;;
    aarch64 | arm64)
      nodearch="arm64"
      ;;
    *)
      echo "::error::unsupported runner architecture: ${machine}"
      exit 1
      ;;
  esac

  archive="node-v${NODE_VERSION}-linux-${nodearch}.tar.xz"
  expected_sha="$(awk -v file="$archive" '$2 == file { print $1; exit }' "$checksums_file")"
  if [[ ! "$expected_sha" =~ ^[0-9a-f]{64}$ ]]; then
    echo "::error::missing authoritative checksum for ${archive}"
    exit 1
  fi

  cache_root="${RUNNER_TOOL_CACHE:-${HOME}/.cache/cheesewaf-toolcache}"
  install_dir="${cache_root}/node/${NODE_VERSION}/${nodearch}"
  checksum_marker="${install_dir}/.archive.sha256"

  if [[ ! -x "${install_dir}/bin/node" ]] ||
    [[ ! -r "$checksum_marker" ]] ||
    [[ "$(<"$checksum_marker")" != "$expected_sha" ]] ||
    [[ "$("${install_dir}/bin/node" -p 'process.versions.node')" != "$NODE_VERSION" ]]; then
    tmp_dir="$(mktemp -d)"
    trap 'rm -rf "${tmp_dir}"' EXIT

    mirrors=(
      "${NODE_DIST_MIRROR:-https://npmmirror.com/mirrors/node}"
      "https://nodejs.org/dist"
    )
    downloaded=""
    for mirror in "${mirrors[@]}"; do
      url="${mirror%/}/v${NODE_VERSION}/${archive}"
      echo "Attempting Node ${NODE_VERSION} from ${url}"
      if curl --fail --location --connect-timeout 20 --retry 3 --retry-delay 5 \
        --output "${tmp_dir}/${archive}" "$url"; then
        downloaded="yes"
        break
      fi
    done

    if [[ -z "$downloaded" ]]; then
      echo "::error::unable to download Node ${NODE_VERSION} for linux-${nodearch}"
      exit 1
    fi

    actual_sha="$(sha256sum "${tmp_dir}/${archive}" | awk '{ print $1 }')"
    if [[ "$expected_sha" != "$actual_sha" ]]; then
      echo "::error::Node archive checksum mismatch for ${archive}"
      exit 1
    fi

    rm -rf "$install_dir"
    mkdir -p "$install_dir"
    tar -C "$install_dir" --strip-components=1 -xJf "${tmp_dir}/${archive}"
    printf '%s\n' "$expected_sha" >"$checksum_marker"
  fi

  if [[ -n "${GITHUB_PATH:-}" ]]; then
    echo "${install_dir}/bin" >>"$GITHUB_PATH"
  fi

  "${install_dir}/bin/node" --version
  "${install_dir}/bin/npm" --version
fi

if [[ -n "${GITHUB_ENV:-}" ]]; then
  echo "NPM_CONFIG_REGISTRY=${NPM_CONFIG_REGISTRY:-https://registry.npmmirror.com}" >>"$GITHUB_ENV"
fi
