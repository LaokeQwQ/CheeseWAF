#!/usr/bin/env bash
# One-command Linux bootstrap installer. Safe to pipe from curl.
set -euo pipefail

repo="${CHEESEWAF_REPO:-LaokeQwQ/CheeseWAF}"
release_ref="${CHEESEWAF_RELEASE:-latest}"
lang="${CHEESEWAF_LANG:-}"

die() { echo "ERROR: $*" >&2; exit 1; }
prompt_read() {
  if [[ -r /dev/tty ]]; then read -r "$@" </dev/tty; else read -r "$@"; fi
}
[[ "$(uname -s)" == "Linux" ]] || die "this installer supports Linux only"
[[ "$(id -u)" -eq 0 ]] || die "run as root: curl ... | sudo bash"
[[ "$repo" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || die "invalid CHEESEWAF_REPO"
command -v curl >/dev/null 2>&1 || die "curl is required"
command -v tar >/dev/null 2>&1 || die "tar is required"
command -v sha256sum >/dev/null 2>&1 || die "sha256sum is required"

if [[ -z "$lang" && ( -t 0 || -r /dev/tty ) ]]; then
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

api_url="https://api.github.com/repos/${repo}/releases/latest"
if [[ "$release_ref" != "latest" ]]; then
  api_url="https://api.github.com/repos/${repo}/releases/tags/${release_ref#v}"
fi
metadata="$(curl --proto '=https' --proto-redir '=https' -fsSL --retry 3 --connect-timeout 10 "$api_url")" || die "unable to read the CheeseWAF release metadata"
tag="$(printf '%s' "$metadata" | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\(v[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\)".*/\1/p' | head -n 1)"
[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "latest release is not a stable semver tag"
version="${tag#v}"
asset="cheesewaf-${arch}-linux-${version}.tar.gz"
asset_url="https://github.com/${repo}/releases/download/${tag}/${asset}"
sum_url="https://github.com/${repo}/releases/download/${tag}/SHA256SUMS"

tmp_dir="$(mktemp -d -t cheesewaf-install.XXXXXX)"
trap 'rm -rf "$tmp_dir"' EXIT
curl --proto '=https' --proto-redir '=https' -fsSL --retry 3 --connect-timeout 10 -o "${tmp_dir}/${asset}" "$asset_url" || die "unable to download ${asset}"
curl --proto '=https' --proto-redir '=https' -fsSL --retry 3 --connect-timeout 10 -o "${tmp_dir}/SHA256SUMS" "$sum_url" || die "unable to download SHA256SUMS"
checksum_lines="$(cd "$tmp_dir" && awk -v name="$asset" '$2 == name || $2 == "*"name {print}' SHA256SUMS)"
[[ "$(printf '%s\n' "$checksum_lines" | awk 'NF {count++} END {print count + 0}')" == "1" ]] || die "SHA256SUMS must contain exactly one entry for ${asset}"
(cd "$tmp_dir" && printf '%s\n' "$checksum_lines" | sha256sum -c -) || die "checksum verification failed for ${asset}"

package_prefix="cheesewaf-${arch}-linux-"
while IFS= read -r member; do
  [[ ("$member" == "${package_prefix}"* || "$member" == "${package_prefix}"*/*) && "$member" != /* && "$member" != *"../"* && "$member" != *"/../"* && "$member" != *"/.." ]] || die "release archive contains an unsafe member: ${member}"
done < <(tar -tzf "${tmp_dir}/${asset}")
tar -tvzf "${tmp_dir}/${asset}" | awk '$1 ~ /^[lh]/ {exit 1}' || die "release archive contains a link entry"
tar --no-same-owner --no-same-permissions -xzf "${tmp_dir}/${asset}" -C "$tmp_dir" || die "unable to extract ${asset}"
mapfile -t package_roots < <(find "$tmp_dir" -mindepth 1 -maxdepth 1 -type d -name "${package_prefix}*" -print)
[[ "${#package_roots[@]}" -eq 1 ]] || die "release archive must contain exactly one Linux package root"
package_root="${package_roots[0]}"
[[ -f "${package_root}/install-linux.sh" && ! -L "${package_root}/install-linux.sh" && -x "${package_root}/install-linux.sh" ]] || die "release archive has no regular Linux installer"
CHEESEWAF_LANG="$lang" CHEESEWAF_RELEASE_VERSION="$version" "${package_root}/install-linux.sh"
