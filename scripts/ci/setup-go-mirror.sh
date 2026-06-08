#!/usr/bin/env bash
set -euo pipefail

version="${GO_VERSION:-}"
if [[ -z "$version" ]]; then
  version="$(awk '$1 == "go" { print $2; exit }' go.mod)"
fi

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

cache_root="${RUNNER_TOOL_CACHE:-${HOME}/.cache/cheesewaf-toolcache}"
install_dir="${cache_root}/go/${version}/${goarch}"

if [[ ! -x "${install_dir}/bin/go" ]] || ! "${install_dir}/bin/go" version | grep -q "go${version}"; then
  tmp_dir="$(mktemp -d)"
  trap 'rm -rf "${tmp_dir}"' EXIT
  archive="go${version}.linux-${goarch}.tar.gz"

  urls=(
    "${GO_DIST_MIRROR:-https://mirrors.aliyun.com/golang}/${archive}"
    "https://mirrors.ustc.edu.cn/golang/${archive}"
    "https://golang.google.cn/dl/${archive}"
    "https://go.dev/dl/${archive}"
  )

  downloaded=""
  for url in "${urls[@]}"; do
    echo "Attempting Go ${version} from ${url}"
    if curl --fail --location --connect-timeout 20 --retry 3 --retry-delay 5 --output "${tmp_dir}/go.tgz" "${url}"; then
      downloaded="yes"
      break
    fi
  done

  if [[ -z "$downloaded" ]]; then
    echo "::error::unable to download Go ${version} for linux-${goarch}"
    exit 1
  fi

  expected_sha="${GO_DOWNLOAD_SHA256:-}"
  if [[ -z "$expected_sha" ]] && command -v python3 >/dev/null 2>&1; then
    checksum_urls=(
      "${GO_CHECKSUM_INDEX:-https://golang.google.cn/dl/?mode=json&include=all}"
      "https://go.dev/dl/?mode=json&include=all"
    )
    for checksum_url in "${checksum_urls[@]}"; do
      if curl --fail --location --connect-timeout 10 --retry 1 --output "${tmp_dir}/go-dl.json" "${checksum_url}"; then
        expected_sha="$(python3 - "${tmp_dir}/go-dl.json" "${archive}" <<'PY'
import json
import sys

path, archive = sys.argv[1], sys.argv[2]
with open(path, "r", encoding="utf-8") as handle:
    releases = json.load(handle)
for release in releases:
    for file_info in release.get("files", []):
        if file_info.get("filename") == archive:
            print(file_info.get("sha256", ""))
            sys.exit(0)
sys.exit(0)
PY
)"
        if [[ -n "$expected_sha" ]]; then
          break
        fi
      fi
    done
  fi

  if [[ -n "$expected_sha" ]]; then
    actual_sha="$(sha256sum "${tmp_dir}/go.tgz" | awk '{ print $1 }')"
    if [[ "$expected_sha" != "$actual_sha" ]]; then
      echo "::error::Go archive checksum mismatch"
      exit 1
    fi
  else
    echo "::warning::Go checksum metadata unavailable; continuing after tar structure and version checks"
  fi

  tar -tzf "${tmp_dir}/go.tgz" >/dev/null
  rm -rf "${install_dir}"
  mkdir -p "${install_dir}"
  tar -C "${install_dir}" --strip-components=1 -xzf "${tmp_dir}/go.tgz"
fi

"${install_dir}/bin/go" version

if [[ -n "${GITHUB_PATH:-}" ]]; then
  echo "${install_dir}/bin" >>"${GITHUB_PATH}"
fi

if [[ -n "${GITHUB_ENV:-}" ]]; then
  echo "GOROOT=${install_dir}" >>"${GITHUB_ENV}"
  echo "GOTOOLCHAIN=local" >>"${GITHUB_ENV}"
  if [[ -n "${HTTP_PROXY:-}${HTTPS_PROXY:-}${http_proxy:-}${https_proxy:-}" ]]; then
    echo "GOPROXY=${GOPROXY:-https://proxy.golang.org,direct}" >>"${GITHUB_ENV}"
    echo "GOSUMDB=${GOSUMDB:-sum.golang.org}" >>"${GITHUB_ENV}"
  else
    echo "GOPROXY=${GOPROXY:-https://goproxy.cn,direct}" >>"${GITHUB_ENV}"
    echo "GOSUMDB=${GOSUMDB:-sum.golang.google.cn}" >>"${GITHUB_ENV}"
  fi
fi
