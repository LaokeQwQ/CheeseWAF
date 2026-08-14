#!/usr/bin/env bash
set -euo pipefail

release_dir="${1:-release}"
[[ -d "$release_dir" ]] || {
  echo "::error::release directory not found: ${release_dir}" >&2
  exit 1
}

tag=""
if [[ -f "${release_dir}/release-manifest.txt" ]]; then
  tag="$(awk -F': ' '/^prerelease_tag:/{print $2; exit}' "${release_dir}/release-manifest.txt")"
fi
if [[ -z "$tag" ]]; then
  echo "::error::prerelease_tag is missing from release-manifest.txt" >&2
  exit 1
fi
[[ "$tag" == Alpha-* ]] || {
  echo "::error::pre-release tag must start with Alpha-: ${tag}" >&2
  exit 1
}

notes="$(mktemp)"
trap 'rm -f "$notes"' EXIT
cat >"$notes" <<EOF
CheeseWAF pre-release \`${tag}\`.

This is an alpha build, not a stable release. Configuration and APIs may change.

Download the archive that matches your OS and CPU:

| File | Platform |
| --- | --- |
| \`cheesewaf-*-linux-amd64.tar.gz\` | Linux x86_64 |
| \`cheesewaf-*-linux-arm64.tar.gz\` | Linux ARM64 |
| \`cheesewaf-*-linux-loong64.tar.gz\` | Linux LoongArch64 |
| \`cheesewaf-*-darwin-amd64.tar.gz\` | macOS Intel |
| \`cheesewaf-*-darwin-arm64.tar.gz\` | macOS Apple Silicon |
| \`cheesewaf-*-windows-amd64.zip\` | Windows x86_64 portable |
| \`cheesewaf-*-windows-arm64.zip\` | Windows ARM64 portable |
| \`CheeseWAF-*-windows-amd64-setup.exe\` | Windows x86_64 installer |
| \`CheeseWAF-*-windows-arm64-setup.exe\` | Windows ARM64 installer |

Linux archives include \`systemd/cheesewaf.service\`. Verify downloads with \`SHA256SUMS\`.
EOF

mapfile -t assets < <(find "$release_dir" -maxdepth 1 -type f ! -name release-manifest.txt | sort)
[[ "${#assets[@]}" -gt 0 ]] || {
  echo "::error::no files to publish in ${release_dir}" >&2
  exit 1
}

if gh release view "$tag" >/dev/null 2>&1; then
  echo "release ${tag} already exists; uploading missing assets"
  gh release upload "$tag" "${assets[@]}" --clobber
  exit 0
fi

gh release create "$tag" \
  --prerelease \
  --title "$tag" \
  --notes-file "$notes" \
  "${assets[@]}"
