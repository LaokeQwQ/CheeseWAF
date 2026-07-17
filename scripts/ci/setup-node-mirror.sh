#!/usr/bin/env bash
set -euo pipefail

node_satisfies() {
  command -v node >/dev/null 2>&1 || return 1
  command -v npm >/dev/null 2>&1 || return 1
  node - <<'NODE'
const [major, minor] = process.versions.node.split('.').map(Number);
const ok = (major === 20 && minor >= 19) || (major === 22 && minor >= 12) || major > 22;
process.exit(ok ? 0 : 1);
NODE
}

if node_satisfies; then
  node --version
  npm --version
else
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

  major="${NODE_MAJOR:-25}"
  mirror="${NODE_DIST_MIRROR:-https://npmmirror.com/mirrors/node}"
  release_dir="${mirror}/latest-v${major}.x"
  cache_root="${RUNNER_TOOL_CACHE:-${HOME}/.cache/cheesewaf-toolcache}"
  tmp_dir="$(mktemp -d)"
  trap 'rm -rf "${tmp_dir}"' EXIT

  curl --fail --location --connect-timeout 20 --retry 3 --retry-delay 5 \
    --output "${tmp_dir}/SHASUMS256.txt" "${release_dir}/SHASUMS256.txt"

  archive="$(awk -v arch="${nodearch}" '$2 ~ ("node-v.*-linux-" arch ".tar.xz") { print $2; exit }' "${tmp_dir}/SHASUMS256.txt")"
  if [[ -z "$archive" ]]; then
    echo "::error::unable to find Node ${major}.x linux-${nodearch} archive in mirror index"
    exit 1
  fi

  version="${archive#node-v}"
  version="${version%-linux-${nodearch}.tar.xz}"
  install_dir="${cache_root}/node/${version}/${nodearch}"

  if [[ ! -x "${install_dir}/bin/node" ]]; then
    curl --fail --location --connect-timeout 20 --retry 3 --retry-delay 5 \
      --output "${tmp_dir}/${archive}" "${release_dir}/${archive}"
    expected="$(awk -v file="${archive}" '$2 == file { print $1; exit }' "${tmp_dir}/SHASUMS256.txt")"
    actual="$(sha256sum "${tmp_dir}/${archive}" | awk '{ print $1 }')"
    if [[ "$expected" != "$actual" ]]; then
      echo "::error::Node archive checksum mismatch"
      exit 1
    fi

    rm -rf "${install_dir}"
    mkdir -p "${install_dir}"
    tar -C "${install_dir}" --strip-components=1 -xJf "${tmp_dir}/${archive}"
  fi

  if [[ -n "${GITHUB_PATH:-}" ]]; then
    echo "${install_dir}/bin" >>"${GITHUB_PATH}"
  fi

  "${install_dir}/bin/node" --version
  "${install_dir}/bin/npm" --version
fi

if [[ -n "${GITHUB_ENV:-}" ]]; then
  echo "NPM_CONFIG_REGISTRY=${NPM_CONFIG_REGISTRY:-https://registry.npmmirror.com}" >>"${GITHUB_ENV}"
fi
