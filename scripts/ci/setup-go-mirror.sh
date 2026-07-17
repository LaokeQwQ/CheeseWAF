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
: "${GO_VERSION:?GO_VERSION is required}"

mod_version="$(awk '$1 == "go" { print $2; exit }' "${repo_root}/go.mod")"
if [[ "$mod_version" != "$GO_VERSION" ]]; then
  echo "::error::go.mod requires ${mod_version}, but tool-versions.env pins ${GO_VERSION}"
  exit 1
fi

command -v curl >/dev/null 2>&1 || {
  echo "::error::curl is required to install Go"
  exit 1
}
command -v sha256sum >/dev/null 2>&1 || {
  echo "::error::sha256sum is required to verify Go"
  exit 1
}

machine="$(uname -m)"
case "$machine" in
  x86_64 | amd64)
    goarch="amd64"
    ;;
  aarch64 | arm64)
    goarch="arm64"
    ;;
  *)
    echo "::error::unsupported runner architecture: ${machine}"
    exit 1
    ;;
esac

archive="go${GO_VERSION}.linux-${goarch}.tar.gz"
expected_sha="$(awk -v file="$archive" '$2 == file { print $1; exit }' "$checksums_file")"
if [[ ! "$expected_sha" =~ ^[0-9a-f]{64}$ ]]; then
  echo "::error::missing authoritative checksum for ${archive}"
  exit 1
fi

cache_root="${RUNNER_TOOL_CACHE:-${HOME}/.cache/cheesewaf-toolcache}"
install_dir="${cache_root}/go/${GO_VERSION}/${goarch}"
checksum_marker="${install_dir}/.archive.sha256"

if [[ ! -x "${install_dir}/bin/go" ]] ||
  [[ ! -r "$checksum_marker" ]] ||
  [[ "$(<"$checksum_marker")" != "$expected_sha" ]] ||
  ! "${install_dir}/bin/go" version | grep -q "go${GO_VERSION} "; then
  tmp_dir="$(mktemp -d)"
  trap 'rm -rf "${tmp_dir}"' EXIT

  mirrors=(
    "${GO_DIST_MIRROR:-https://mirrors.aliyun.com/golang}"
    "https://mirrors.ustc.edu.cn/golang"
    "https://golang.google.cn/dl"
    "https://go.dev/dl"
  )
  downloaded=""
  for mirror in "${mirrors[@]}"; do
    url="${mirror%/}/${archive}"
    echo "Attempting Go ${GO_VERSION} from ${url}"
    if curl --fail --location --connect-timeout 20 --retry 3 --retry-delay 5 \
      --output "${tmp_dir}/${archive}" "$url"; then
      downloaded="yes"
      break
    fi
  done

  if [[ -z "$downloaded" ]]; then
    echo "::error::unable to download Go ${GO_VERSION} for linux-${goarch}"
    exit 1
  fi

  actual_sha="$(sha256sum "${tmp_dir}/${archive}" | awk '{ print $1 }')"
  if [[ "$expected_sha" != "$actual_sha" ]]; then
    echo "::error::Go archive checksum mismatch for ${archive}"
    exit 1
  fi

  tar -tzf "${tmp_dir}/${archive}" >/dev/null
  rm -rf "$install_dir"
  mkdir -p "$install_dir"
  tar -C "$install_dir" --strip-components=1 -xzf "${tmp_dir}/${archive}"
  printf '%s\n' "$expected_sha" >"$checksum_marker"
fi

"${install_dir}/bin/go" version

if [[ -n "${GITHUB_PATH:-}" ]]; then
  echo "${install_dir}/bin" >>"$GITHUB_PATH"
fi

if [[ -n "${GITHUB_ENV:-}" ]]; then
  echo "GOROOT=${install_dir}" >>"$GITHUB_ENV"
  echo "GOTOOLCHAIN=local" >>"$GITHUB_ENV"
  if [[ -n "${HTTP_PROXY:-}${HTTPS_PROXY:-}${http_proxy:-}${https_proxy:-}" ]]; then
    echo "GOPROXY=${GOPROXY:-https://proxy.golang.org,direct}" >>"$GITHUB_ENV"
    echo "GOSUMDB=${GOSUMDB:-sum.golang.org}" >>"$GITHUB_ENV"
  else
    echo "GOPROXY=${GOPROXY:-https://goproxy.cn,direct}" >>"$GITHUB_ENV"
    echo "GOSUMDB=${GOSUMDB:-sum.golang.google.cn}" >>"$GITHUB_ENV"
  fi
fi
