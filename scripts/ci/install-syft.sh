#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
# shellcheck disable=SC1091
source "${repo_root}/scripts/ci/tool-versions.env"

os="$(uname -s | tr '[:upper:]' '[:lower:]')"
arch="$(uname -m)"
case "$arch" in
  x86_64 | amd64) arch="amd64" ;;
  aarch64 | arm64) arch="arm64" ;;
  *)
    echo "::error::unsupported syft architecture: ${arch}" >&2
    exit 1
    ;;
esac
case "$os" in
  linux | darwin) ;;
  *)
    echo "::error::unsupported syft OS: ${os}" >&2
    exit 1
    ;;
esac

version="${SYFT_VERSION#v}"
archive="syft_${version}_${os}_${arch}.tar.gz"
checksum="$(awk -v file="$archive" '$2 == file { print $1; exit }' "${repo_root}/scripts/ci/tool-checksums.txt")"
[[ "$checksum" =~ ^[0-9a-f]{64}$ ]] || {
  echo "::error::missing checksum for ${archive}" >&2
  exit 1
}

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
curl -fsSL "https://github.com/anchore/syft/releases/download/${SYFT_VERSION}/${archive}" -o "${work}/${archive}"
(
  cd "$work"
  if command -v sha256sum >/dev/null 2>&1; then
    echo "${checksum}  ${archive}" | sha256sum -c -
  else
    echo "${checksum}  ${archive}" | shasum -a 256 -c -
  fi
  tar -xzf "$archive" syft
)

dest="${SYFT_INSTALL_DIR:-${HOME}/.local/bin}"
mkdir -p "$dest"
install -m 0755 "${work}/syft" "${dest}/syft"
if [[ -n "${GITHUB_PATH:-}" ]]; then
  echo "$dest" >>"${GITHUB_PATH}"
fi
export PATH="${dest}:${PATH}"
syft version
