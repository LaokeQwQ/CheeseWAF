#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${script_dir}/tool-versions.env"

version="${ACTIONLINT_VERSION#v}"
case "$(uname -s):$(uname -m)" in
  Linux:x86_64 | Linux:amd64)
    archive="actionlint_${version}_linux_amd64.tar.gz"
    checksum="023070a287cd8cccd71515fedc843f1985bf96c436b7effaecce67290e7e0757"
    checksum_tool="sha256sum"
    ;;
  Linux:aarch64 | Linux:arm64)
    archive="actionlint_${version}_linux_arm64.tar.gz"
    checksum="401942f9c24ed71e4fe71b76c7d638f66d8633575c4016efd2977ce7c28317d0"
    checksum_tool="sha256sum"
    ;;
  Darwin:arm64)
    archive="actionlint_${version}_darwin_arm64.tar.gz"
    checksum="2693315b9093aeacb4ebd91a993fea54fc215057bf0da2659056b4bc033873db"
    checksum_tool="shasum"
    ;;
  Darwin:x86_64)
    archive="actionlint_${version}_darwin_amd64.tar.gz"
    checksum="28e5de5a05fc558474f638323d736d822fff183d2d492f0aecb2b73cc44584f5"
    checksum_tool="shasum"
    ;;
  *)
    echo "::error::unsupported actionlint runner platform: $(uname -s) $(uname -m)" >&2
    exit 1
    ;;
esac

command -v curl >/dev/null 2>&1 || {
  echo "::error::curl is required to download actionlint" >&2
  exit 1
}
command -v tar >/dev/null 2>&1 || {
  echo "::error::tar is required to unpack actionlint" >&2
  exit 1
}
command -v "$checksum_tool" >/dev/null 2>&1 || {
  echo "::error::${checksum_tool} is required to verify actionlint" >&2
  exit 1
}

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT
archive_path="${tmp_dir}/${archive}"
curl -fsSL -o "$archive_path" \
  "https://github.com/rhysd/actionlint/releases/download/v${version}/${archive}"
printf '%s  %s\n' "$checksum" "$archive_path" | "$checksum_tool" -c -
tar -xzf "$archive_path" -C "$tmp_dir" actionlint
exec "${tmp_dir}/actionlint" "$@"
