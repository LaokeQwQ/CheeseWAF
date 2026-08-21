#!/usr/bin/env bash
set -euo pipefail

release_dir="${1:-release}"
[[ -d "$release_dir" ]] || {
  echo "::error::release directory not found: ${release_dir}" >&2
  exit 1
}

tag=""
suffix=""
if [[ -f "${release_dir}/release-manifest.txt" ]]; then
  tag="$(awk -F': ' '/^prerelease_tag:/{print $2; exit}' "${release_dir}/release-manifest.txt")"
  suffix="$(awk -F': ' '/^file_suffix:/{print $2; exit}' "${release_dir}/release-manifest.txt")"
  if [[ -z "$suffix" ]]; then
    suffix="$(awk -F': ' '/^channel:/{print $2; exit}' "${release_dir}/release-manifest.txt")"
  fi
fi
if [[ -z "$tag" ]]; then
  echo "::error::prerelease_tag is missing from release-manifest.txt" >&2
  exit 1
fi
[[ "$tag" == Alpha-* ]] || {
  echo "::error::pre-release tag must start with Alpha-: ${tag}" >&2
  exit 1
}
if [[ -z "$suffix" ]]; then
  suffix="PreTest"
fi
if [[ "$suffix" == "stable" ]]; then
  suffix="beta"
fi

rewrite_checksums() {
  local dir="$1"
  (
    cd "$dir"
    rm -f SHA256SUMS
    files=()
    while IFS= read -r f; do
      [[ -n "$f" ]] || continue
      files+=("$f")
    done < <(find . -maxdepth 1 -type f ! -name SHA256SUMS ! -name release-manifest.txt | sed 's#^\./##' | sort)
    [[ ${#files[@]} -gt 0 ]] || {
      echo "::error::no files to checksum in ${dir}" >&2
      exit 1
    }
    if command -v sha256sum >/dev/null 2>&1; then
      sha256sum "${files[@]}" >SHA256SUMS
    else
      shasum -a 256 "${files[@]}" >SHA256SUMS
    fi
  )
}

rewrite_checksums "$release_dir"

notes="$(mktemp)"
trap 'rm -f "$notes"' EXIT
cat >"$notes" <<EOF
CheeseWAF pre-release \`${tag}\`.

This is an alpha build, not a stable release. Configuration and APIs may change.

Download the archive that matches your OS and CPU:

| File | Platform |
| --- | --- |
| \`cheesewaf-amd64-linux-*-${suffix}.tar.gz\` | Linux x86_64 |
| \`cheesewaf-arm64-linux-*-${suffix}.tar.gz\` | Linux ARM64 |
| \`cheesewaf-loong64-linux-*-${suffix}.tar.gz\` | Linux LoongArch64 |
| \`cheesewaf-amd64-darwin-*-${suffix}.tar.gz\` / \`.dmg\` | macOS Intel |
| \`cheesewaf-arm64-darwin-*-${suffix}.tar.gz\` / \`.dmg\` | macOS Apple Silicon |
| \`cheesewaf-amd64-windows-*-${suffix}.exe\` | Windows x86_64 single-file CLI |
| \`cheesewaf-arm64-windows-*-${suffix}.exe\` | Windows ARM64 single-file CLI |
| \`cheesewaf-amd64-windows-*-${suffix}.zip\` | Windows x86_64 portable folder |
| \`cheesewaf-arm64-windows-*-${suffix}.zip\` | Windows ARM64 portable folder |
| \`cheesewaf-amd64-windows-*-${suffix}-setup.exe\` | Windows x86_64 GUI installer |
| \`cheesewaf-arm64-windows-*-${suffix}-setup.exe\` | Windows ARM64 GUI installer |

Linux archives include \`systemd/cheesewaf.service\`. Verify downloads with \`SHA256SUMS\`.
EOF

assets=()
while IFS= read -r f; do
  [[ -n "$f" ]] || continue
  assets+=("$f")
done < <(find "$release_dir" -maxdepth 1 -type f ! -name release-manifest.txt | sort)
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
