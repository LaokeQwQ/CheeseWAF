#!/usr/bin/env bash
set -euo pipefail

# Build a signed-looking CheeseWAF.app and a Finder-styled UDZO DMG.
# Requires macOS: hdiutil, codesign. osascript is used for icon layout.

bundle_version_from_label() {
  local raw="$1"
  local numeric
  numeric="$(printf '%s' "$raw" | sed -E 's/[^0-9.]+/./g; s/\.+/./g; s/^\.//; s/\.$//')"
  if [[ -z "$numeric" ]]; then
    numeric="0.0.0"
  fi
  printf '%s' "$numeric"
}

if [[ "${1:-}" == --print-bundle-version ]]; then
  bundle_version_from_label "${2:-}"
  echo
  exit 0
fi

release_dir="${1:-release}"
if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "::error::package-macos-dmg.sh must run on macOS" >&2
  exit 1
fi
command -v hdiutil >/dev/null 2>&1 || {
  echo "::error::hdiutil is required" >&2
  exit 1
}
command -v codesign >/dev/null 2>&1 || {
  echo "::error::codesign is required" >&2
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

sign_app() {
  local app_root="$1"
  xattr -cr "$app_root" 2>/dev/null || true
  local bin
  for bin in "${app_root}/Contents/MacOS"/*; do
    [[ -f "$bin" ]] || continue
    codesign --force --sign - --timestamp=none "$bin"
  done
  codesign --force --sign - --timestamp=none "$app_root"
  codesign --verify "$app_root" >/dev/null
}

assemble_app() {
  local package_dir="$1"
  local version_label="$2"
  local app_root="$3"
  local macos="${app_root}/Contents/MacOS"
  local resources="${app_root}/Contents/Resources"
  mkdir -p "$macos" "$resources/web" "$resources/configs" "$resources/bin"
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
  cp "${package_dir}/cheesewaf" "${resources}/bin/cheesewaf"
  cp "$gui" "${macos}/CheeseWAF"
  chmod +x "${resources}/bin/cheesewaf" "${macos}/CheeseWAF"
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
  local short_version="$version_label"
  local bundle_version
  bundle_version="$(bundle_version_from_label "$version_label")"
  sed \
    -e "s/APP_SHORT_VERSION/${short_version//\//\\/}/g" \
    -e "s/APP_BUNDLE_VERSION/${bundle_version//\//\\/}/g" \
    "$plist" >"${app_root}/Contents/Info.plist"
  printf 'APPL????' >"${app_root}/Contents/PkgInfo"
  write_icon "${resources}/AppIcon.icns" "$package_dir" || true
  sign_app "$app_root"
}

layout_dmg_window() {
  local mount="$1"
  command -v osascript >/dev/null 2>&1 || return 0
  osascript <<EOF >/dev/null
tell application "Finder"
  tell disk "CheeseWAF"
    open
    set current view of container window to icon view
    set toolbar visible of container window to false
    set statusbar visible of container window to false
    set bounds of container window to {200, 120, 840, 560}
    set theViewOptions to the icon view options of container window
    set arrangement of theViewOptions to not arranged
    set icon size of theViewOptions to 128
    try
      set background picture of theViewOptions to file ".background:background.png"
    end try
    try
      set position of item "CheeseWAF.app" of container window to {170, 220}
    end try
    try
      set position of item "Applications" of container window to {470, 220}
    end try
    try
      set position of item "Fix Gatekeeper.command" of container window to {170, 390}
    end try
    try
      set position of item "Read Me.txt" of container window to {470, 390}
    end try
    update without registering applications
    delay 1
    close
    open
    delay 1
  end tell
end tell
EOF
}

for tarball in "${tarballs[@]}"; do
  name="$(basename "$tarball" .tar.gz)"
  # cheesewaf-{arch}-{os}-{version}[-{suffix}]
  version="${name#cheesewaf-}"
  version="${version#*-}"
  version="${version#*-}"
  if [[ -z "$version" || "$version" == "$name" ]]; then
    version="0.0.0"
  fi
  extract="${stage_root}/${name}"
  mkdir -p "$extract"
  tar -xzf "$tarball" -C "$extract"
  package_dir="$(find "$extract" -mindepth 1 -maxdepth 1 -type d | head -n 1)"
  [[ -n "$package_dir" ]] || {
    echo "::error::${name}.tar.gz has no package directory" >&2
    exit 1
  }

  dmg_root="${stage_root}/dmg-${name}"
  mkdir -p "${dmg_root}/.background"
  assemble_app "$package_dir" "$version" "${dmg_root}/CheeseWAF.app"
  ln -s /Applications "${dmg_root}/Applications"
  cp "${repo_root}/deploy/macos/first-open.txt" "${dmg_root}/Read Me.txt"
  cp "${repo_root}/deploy/macos/fix-gatekeeper.command" "${dmg_root}/Fix Gatekeeper.command"
  chmod +x "${dmg_root}/Fix Gatekeeper.command"
  if [[ -f "${repo_root}/deploy/macos/dmg-background.png" ]]; then
    cp "${repo_root}/deploy/macos/dmg-background.png" "${dmg_root}/.background/background.png"
  fi

  rw_dmg="${stage_root}/${name}.rw.dmg"
  rm -f "$rw_dmg"
  hdiutil create \
    -volname "CheeseWAF" \
    -srcfolder "$dmg_root" \
    -ov \
    -fs HFS+ \
    -format UDRW \
    "$rw_dmg" >/dev/null

  if [[ -d /Volumes/CheeseWAF ]]; then
    hdiutil detach /Volumes/CheeseWAF -quiet || hdiutil detach /Volumes/CheeseWAF -force || true
  fi
  device="$(hdiutil attach -readwrite -noverify -noautoopen "$rw_dmg" | awk '/^\/dev\// { print $1; exit }')"
  [[ -n "$device" && -d /Volumes/CheeseWAF ]] || {
    echo "::error::failed to attach ${rw_dmg}" >&2
    exit 1
  }
  layout_dmg_window /Volumes/CheeseWAF || true
  sync
  hdiutil detach "$device" -quiet || hdiutil detach "$device" -force || hdiutil detach /Volumes/CheeseWAF -force

  dmg_path="${abs_release}/${name}.dmg"
  echo "creating ${dmg_path}"
  rm -f "$dmg_path"
  hdiutil convert "$rw_dmg" -format UDZO -imagekey zlib-level=9 -o "$dmg_path" >/dev/null
  xattr -cr "$dmg_path" 2>/dev/null || true
  codesign --force --sign - --timestamp=none "$dmg_path" 2>/dev/null || true
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
