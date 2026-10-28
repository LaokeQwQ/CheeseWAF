#!/usr/bin/env bash
# One-command Linux bootstrap installer. Safe to pipe from curl.
set -euo pipefail

repo="${CHEESEWAF_REPO:-LaokeQwQ/CheeseWAF}"
release_ref="${CHEESEWAF_RELEASE:-latest}"
lang="${CHEESEWAF_LANG:-}"
official_repo="LaokeQwQ/CheeseWAF"
official_index="https://ota.cheesesec.com/v1/software/channels/stable/index.json"
official_releases="https://res.cheesesec.com/releases"

die() { echo "ERROR: $*" >&2; exit 1; }
prompt_read() {
  if [[ -r /dev/tty ]]; then read -r "$@" </dev/tty; else read -r "$@"; fi
}
has_interactive_terminal() {
  [[ -t 0 ]] && return 0
  [[ -r /dev/tty && -w /dev/tty ]] || return 1
  { : </dev/tty; } 2>/dev/null
}
[[ "$(uname -s)" == "Linux" ]] || die "this installer supports Linux only"
[[ "$(id -u)" -eq 0 ]] || die "run as root: curl ... | sudo bash"
[[ "$repo" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || die "invalid CHEESEWAF_REPO"
if command -v curl >/dev/null 2>&1; then
  downloader=curl
elif command -v wget >/dev/null 2>&1; then
  downloader=wget
else
  die "curl or GNU wget with HTTPS support is required"
fi
command -v tar >/dev/null 2>&1 || die "tar is required"
command -v sha256sum >/dev/null 2>&1 || die "sha256sum is required"

tmp_dir="$(mktemp -d -t cheesewaf-install.XXXXXX)"
trap 'rm -rf "$tmp_dir"' EXIT

download() {
  local url="$1" destination="$2" status location attempt origin
  if [[ "$downloader" == curl ]]; then
    curl --disable --proto '=https' --proto-redir '=https' -fsSL --retry 3 \
      --connect-timeout 10 --max-time 600 -o "$destination" "$url"
    return
  fi

  # Wget's --https-only applies to recursive links, not HTTP redirects.
  # Follow each redirect ourselves so no hop can downgrade TLS or use FTP.
  for ((attempt = 0; attempt < 10; attempt++)); do
    [[ "$url" =~ ^https://[A-Za-z0-9.-]+(:[0-9]+)?/[^[:space:]\\\\]*$ ]] || die "download redirect is not a safe HTTPS URL"
    if wget --no-config --server-response --max-redirect=0 --tries=3 \
      --connect-timeout=10 --timeout=60 -O "$destination" "$url" 2>"${tmp_dir}/wget-headers"; then
      return 0
    fi
    status="$(awk '$1 ~ /^HTTP\/[0-9.]+$/ {status = $2} END {print status}' "${tmp_dir}/wget-headers")"
    case "$status" in 301|302|303|307|308) ;; *) return 1 ;; esac
    location="$(awk '
      $1 ~ /^HTTP\/[0-9.]+$/ {location = ""}
      /^[[:space:]]/ && tolower($1) == "location:" {
        sub(/^[[:space:]]*[^:]+:[[:space:]]*/, ""); sub(/\r$/, ""); location = $0
      }
      END {print location}' "${tmp_dir}/wget-headers")"
    case "$location" in
      https://*) url="$location" ;;
      //*) url="https:${location}" ;;
      /*) origin="${url#https://}"; url="https://${origin%%/*}${location}" ;;
      *) die "download redirect must use HTTPS" ;;
    esac
  done
  return 1
}

download_release_file() {
  local name="$1" destination="$2"
  if [[ "$repo" == "$official_repo" ]]; then
    if download "${official_releases}/${tag}/${name}" "$destination"; then
      return 0
    fi
    echo "Official download unavailable for ${name}; trying GitHub for ${tag}." >&2
    rm -f "$destination"
  fi
  download "https://github.com/${repo}/releases/download/${tag}/${name}" "$destination"
}

if [[ -z "$lang" ]] && has_interactive_terminal; then
  printf 'Language / 语言 [1=English, 2=简体中文] (1): '
  prompt_read choice
  [[ "$choice" == "2" ]] && lang="zh-CN" || lang="en"
fi
[[ "$lang" == "zh-CN" ]] || lang="en"

case "$(uname -m)" in
  x86_64|amd64) arch="amd64" ;;
  aarch64|arm64) arch="arm64" ;;
  loongarch64|loong64) arch="loong64" ;;
  *) die "unsupported architecture: $(uname -m)" ;;
esac

if [[ "$release_ref" != "latest" ]]; then
  [[ "$release_ref" =~ ^v?[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]] || die "CHEESEWAF_RELEASE must be a semver tag such as v0.4.5 or v0.4.5-beta"
  tag="$release_ref"
  [[ "$tag" == v* ]] || tag="v${tag}"
else
  metadata_file="${tmp_dir}/release.json"
  if [[ "$repo" != "$official_repo" ]] || ! download "$official_index" "$metadata_file"; then
    [[ "$repo" != "$official_repo" ]] || echo 'Official release index unavailable; trying GitHub.' >&2
    rm -f "$metadata_file"
    download "https://api.github.com/repos/${repo}/releases/latest" "$metadata_file" || die "unable to read the CheeseWAF release metadata"
  fi
  metadata="$(tr '\r\n' '  ' <"$metadata_file")"
  [[ "$metadata" =~ ^[[:space:]]*\{.*\}[[:space:]]*$ ]] || die "release metadata is not a JSON object"
  # Only the canonical tag is consumed; asset URLs are fixed below instead
  # of trusting arbitrary download URLs supplied by metadata.
  tag_fields="$(printf '%s' "$metadata" | grep -oE '"tag_name"[[:space:]]*:[[:space:]]*"[^"]*"' || true)"
  [[ "$(printf '%s\n' "$tag_fields" | awk 'NF {count++} END {print count + 0}')" == 1 ]] || die "release metadata must contain exactly one tag_name"
  tag="$(printf '%s' "$tag_fields" | sed 's/^[^:]*:[[:space:]]*"\([^"]*\)"$/\1/')"
fi
[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]] || die "release is not a semver tag"
version="${tag#v}"
asset="cheesewaf-${arch}-linux-${version}.tar.gz"
download_release_file "$asset" "${tmp_dir}/${asset}" || die "unable to download ${asset}"
download_release_file SHA256SUMS "${tmp_dir}/SHA256SUMS" || die "unable to download SHA256SUMS"
checksum_lines="$(cd "$tmp_dir" && awk -v name="$asset" '$2 == name || $2 == "*"name {print}' SHA256SUMS)"
[[ "$(printf '%s\n' "$checksum_lines" | awk 'NF {count++} END {print count + 0}')" == "1" ]] || die "SHA256SUMS must contain exactly one entry for ${asset}"
(cd "$tmp_dir" && printf '%s\n' "$checksum_lines" | sha256sum -c -) || die "checksum verification failed for ${asset}"

# SHA256SUMS is published beside the archive, so it protects transport
# integrity only. Operators that require release provenance can install the
# pinned cosign package separately and opt into verification of the keyless
# GitHub Actions bundle. The identity is fixed to this repository's release
# workflow and a version tag; an unsigned or unrelated release is rejected.
# The official release channel is verified by default: the checksum alone only
# covers transport integrity. Set CHEESEWAF_VERIFY_SIGNATURE=0 to opt out on a
# host that cannot install cosign.
verify_signature="${CHEESEWAF_VERIFY_SIGNATURE:-auto}"
if [[ "$verify_signature" == "auto" ]]; then
  if [[ "$repo" == "$official_repo" ]]; then verify_signature=1; else verify_signature=0; fi
fi
if [[ "$verify_signature" == "1" ]]; then
  command -v cosign >/dev/null 2>&1 || die "cosign is required to verify official releases; install cosign or rerun with CHEESEWAF_VERIFY_SIGNATURE=0"
  download_release_file SHA256SUMS.bundle "${tmp_dir}/SHA256SUMS.bundle" || die "unable to download SHA256SUMS signature bundle"
  cosign verify-blob \
    --bundle "${tmp_dir}/SHA256SUMS.bundle" \
    --certificate-identity "https://github.com/${repo}/.github/workflows/ci.yml@refs/tags/${tag}" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
    "${tmp_dir}/SHA256SUMS" >/dev/null || die "SHA256SUMS signature verification failed"
fi

package_name="${asset%.tar.gz}"
tar -tzf "${tmp_dir}/${asset}" >"${tmp_dir}/archive-members" || die "unable to list ${asset}"
while IFS= read -r member; do
  [[ ("$member" == "$package_name" || "$member" == "${package_name}/"*) && "$member" != /* && "$member" != *"../"* && "$member" != *"/../"* && "$member" != *"/.." ]] || die "release archive contains an unsafe member: ${member}"
done <"${tmp_dir}/archive-members"
tar -tvzf "${tmp_dir}/${asset}" | awk '$1 ~ /^[lh]/ {exit 1}' || die "release archive contains a link entry"
tar --no-same-owner --no-same-permissions -xzf "${tmp_dir}/${asset}" -C "$tmp_dir" || die "unable to extract ${asset}"
package_root="${tmp_dir}/${package_name}"
[[ -d "$package_root" && ! -L "$package_root" ]] || die "release archive must contain the expected Linux package root"
[[ -f "${package_root}/install-linux.sh" && ! -L "${package_root}/install-linux.sh" && -x "${package_root}/install-linux.sh" ]] || die "release archive has no regular Linux installer"
(cd "$package_root" && CHEESEWAF_LANG="$lang" CHEESEWAF_RELEASE_VERSION="$version" ./install-linux.sh)
