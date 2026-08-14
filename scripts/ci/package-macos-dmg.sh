#!/usr/bin/env bash
set -euo pipefail

# Build a drag-to-Applications DMG with CheeseWAF.app. Requires macOS hdiutil.
# Opening the app starts the local GUI controller.

release_dir="${1:-release}"
if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "::error::package-macos-dmg.sh must run on macOS" >&2
  exit 1
fi
command -v hdiutil >/dev/null 2>&1 || {
  echo "::error::hdiutil is required" >&2
  exit 1
}
[[ -d "$release_dir" ]] || {
  echo "::error::release directory not found: ${release_dir}" >&2
  exit 1
}

repo_root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
abs_release="$(cd "$release_dir" && pwd)"
tarballs=()
while IFS= read -r tarball; do
  [[ -n "$tarball" ]] || continue
  tarballs+=("$tarball")
done < <(find "$abs_release" -maxdepth 1 -type f -name 'cheesewaf-*-darwin-*.tar.gz' | sort)
if [[ ${#tarballs[@]} -eq 0 ]]; then
  echo "no darwin tarballs in ${abs_release}; skipped DMG"
  exit 0
fi

stage_root="$(mktemp -d)"
trap 'rm -rf "$stage_root"' EXIT

append_checksum() {
  local file="$1"
  local base
  base="$(basename "$file")"
  (
    cd "$abs_release"
    if command -v sha256sum >/dev/null 2>&1; then
      sha256sum "$base"
    else
      shasum -a 256 "$base"
    fi
  ) >>"${abs_release}/SHA256SUMS"
}

write_icon() {
  local dest_icns="$1"
  local logo=""
  for candidate in \
    "${repo_root}/web/public/cheesewaf-logo.png" \
    "${2}/web/dist/cheesewaf-logo.png"; do
    if [[ -f "$candidate" ]]; then
      logo="$candidate"
      break
    fi
  done
  [[ -n "$logo" ]] || return 0
  command -v sips >/dev/null 2>&1 || return 0
  command -v iconutil >/dev/null 2>&1 || return 0
  local iconset="${stage_root}/AppIcon.iconset"
  rm -rf "$iconset"
  mkdir -p "$iconset"
  local size
  for size in 16 32 64 128 256 512; do
    sips -z "$size" "$size" "$logo" --out "${iconset}/icon_${size}x${size}.png" >/dev/null
  done
  sips -z 32 32 "$logo" --out "${iconset}/icon_16x16@2x.png" >/dev/null
  sips -z 64 64 "$logo" --out "${iconset}/icon_32x32@2x.png" >/dev/null
  sips -z 256 256 "$logo" --out "${iconset}/icon_128x128@2x.png" >/dev/null
  sips -z 512 512 "$logo" --out "${iconset}/icon_256x256@2x.png" >/dev/null
  sips -z 1024 1024 "$logo" --out "${iconset}/icon_512x512@2x.png" >/dev/null
  iconutil -c icns "$iconset" -o "$dest_icns" >/dev/null
}

assemble_app() {
  local package_dir="$1"
  local version="$2"
  local app_root="$3"
  local macos="${app_root}/Contents/MacOS"
  local resources="${app_root}/Contents/Resources"
  mkdir -p "$macos" "$resources/web" "$resources/configs"
  local gui=""
  if [[ -x "${package_dir}/cheesewaf-gui" ]]; then
    gui="${package_dir}/cheesewaf-gui"
  elif [[ -x "${package_dir}/CheeseWAF" ]]; then
    gui="${package_dir}/CheeseWAF"
  else
    echo "::error::darwin package is missing cheesewaf-gui" >&2
    return 1
  fi
  [[ -x "${package_dir}/cheesewaf" ]] || {
    echo "::error::darwin package is missing cheesewaf" >&2
    return 1
  }
  cp "${package_dir}/cheesewaf" "${macos}/cheesewaf"
  cp "$gui" "${macos}/CheeseWAF"
  chmod +x "${macos}/cheesewaf" "${macos}/CheeseWAF"
  if [[ -d "${package_dir}/web/dist" ]]; then
    cp -R "${package_dir}/web/dist/." "${resources}/web/"
  fi
  if [[ -d "${package_dir}/configs" ]]; then
    cp -R "${package_dir}/configs/." "${resources}/configs/"
  fi
  local plist="${repo_root}/deploy/macos/Info.plist"
  [[ -f "$plist" ]] || {
    echo "::error::missing ${plist}" >&2
    return 1
  }
  sed "s/APP_VERSION/${version}/g" "$plist" >"${app_root}/Contents/Info.plist"
  write_icon "${resources}/AppIcon.icns" "$package_dir" || true
}

for tarball in "${tarballs[@]}"; do
  name="$(basename "$tarball" .tar.gz)"
  version="${name#cheesewaf-}"
  version="${version%-darwin-*}"
  extract="${stage_root}/${name}"
  mkdir -p "$extract"
  tar -xzf "$tarball" -C "$extract"
  package_dir="$(find "$extract" -mindepth 1 -maxdepth 1 -type d | head -n 1)"
  [[ -n "$package_dir" ]] || {
    echo "::error::${name}.tar.gz has no package directory" >&2
    exit 1
  }

  dmg_root="${stage_root}/dmg-${name}"
  mkdir -p "$dmg_root"
  assemble_app "$package_dir" "$version" "${dmg_root}/CheeseWAF.app"
  ln -s /Applications "${dmg_root}/Applications"

  dmg_path="${abs_release}/${name}.dmg"
  echo "creating ${dmg_path}"
  rm -f "$dmg_path"
  hdiutil create \
    -volname "CheeseWAF" \
    -srcfolder "$dmg_root" \
    -ov \
    -format UDZO \
    "$dmg_path" >/dev/null
  append_checksum "$dmg_path"
done

if [[ -f "${abs_release}/release-manifest.txt" ]]; then
  {
    echo
    echo "macOS disk images:"
    find "$abs_release" -maxdepth 1 -type f -name '*.dmg' -exec basename {} \; | sort | sed 's/^/- /'
  } >>"${abs_release}/release-manifest.txt"
fi

echo "DMG images written to ${abs_release}/"
