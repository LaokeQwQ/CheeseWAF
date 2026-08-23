#!/usr/bin/env bash
set -euo pipefail

# Build a signed or explicitly ad-hoc CheeseWAF.app and a Finder-styled UDZO DMG.
# Requires macOS: hdiutil, codesign. osascript is used for icon layout.

umask 077
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

run_with_timeout() {
  local seconds="$1"
  shift
  "$@" &
  local command_pid=$!
  (
    sleep "$seconds"
    kill -TERM "$command_pid" >/dev/null 2>&1 || exit 0
    sleep 2
    kill -KILL "$command_pid" >/dev/null 2>&1 || true
  ) >/dev/null 2>&1 &
  local watchdog_pid=$!
  local status=0
  wait "$command_pid" || status=$?
  kill "$watchdog_pid" >/dev/null 2>&1 || true
  wait "$watchdog_pid" >/dev/null 2>&1 || true
  return "$status"
}

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
device=""
signing_keychain=""
original_user_keychains=()
cleanup() {
  if [[ -n "$device" ]]; then
    run_with_timeout 30 hdiutil detach "$device" -force >/dev/null 2>&1 || true
  fi
  if [[ -n "$signing_keychain" ]]; then
    if [[ "${#original_user_keychains[@]}" -gt 0 ]]; then
      security list-keychain -d user -s "${original_user_keychains[@]}" >/dev/null 2>&1 || true
    fi
    security delete-keychain "$signing_keychain" >/dev/null 2>&1 || true
  fi
  rm -rf "$stage_root"
}
trap cleanup EXIT

CODESIGN_IDENTITY="-"
CODESIGN_BIN_ARGS=(--timestamp=none)
CODESIGN_DMG_ARGS=(--timestamp=none)
NOTARIZE=0
APPLE_KEY_FILE=""

setup_macos_signing() {
  if [[ -n "${MACOS_P12_BASE64:-}" ]]; then
    local p12="${stage_root}/developer-id.p12"
    local pem="${stage_root}/developer-id.pem"
    local pass_file="${stage_root}/developer-id.pass"
    local keychain="${stage_root}/codesign.keychain-db"
    local kc_pass
    command -v openssl >/dev/null 2>&1 || {
      echo "::error::openssl is required to import MACOS_P12_BASE64 without exposing its password" >&2
      exit 1
    }
    if printf '%s' "$MACOS_P12_BASE64" | base64 --decode >"$p12" 2>/dev/null; then
      :
    else
      printf '%s' "$MACOS_P12_BASE64" | base64 -D >"$p12"
    fi
    [[ -s "$p12" ]] || {
      echo "::error::MACOS_P12_BASE64 did not decode to a PKCS#12 file" >&2
      exit 1
    }
    kc_pass="$(openssl rand -base64 24)"
    security create-keychain -p "$kc_pass" "$keychain"
    security set-keychain-settings -lut 21600 "$keychain"
    security unlock-keychain -p "$kc_pass" "$keychain"
    printf '%s' "${MACOS_P12_PASSWORD:-}" >"$pass_file"
    openssl pkcs12 -in "$p12" -passin "file:${pass_file}" -nodes -out "$pem"
    security import "$pem" -k "$keychain" -T /usr/bin/codesign -T /usr/bin/security
    security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$kc_pass" "$keychain" >/dev/null
    local keychain_path
    while IFS= read -r line; do
      keychain_path="$(printf '%s' "$line" | sed -E 's/^[[:space:]]*"//; s/"[[:space:]]*$//')"
      [[ -n "$keychain_path" ]] || continue
      original_user_keychains+=("$keychain_path")
    done < <(security list-keychain -d user)
    signing_keychain="$keychain"
    keychain_args=("$keychain")
    if [[ "${#original_user_keychains[@]}" -gt 0 ]]; then
      keychain_args+=("${original_user_keychains[@]}")
    fi
    security list-keychain -d user -s "${keychain_args[@]}"
    CODESIGN_IDENTITY="$(security find-identity -v -p codesigning "$keychain" | awk -F'"' '/Developer ID Application/{print $2; exit}')"
    if [[ -z "$CODESIGN_IDENTITY" ]]; then
      CODESIGN_IDENTITY="$(security find-identity -v -p codesigning "$keychain" | awk -F'"' '/"/ {print $2; exit}')"
    fi
    [[ -n "$CODESIGN_IDENTITY" ]] || {
      echo "::error::imported MACOS_P12_BASE64 but no codesigning identity was found" >&2
      exit 1
    }
  elif [[ -n "${MACOS_CODESIGN_IDENTITY:-}" ]]; then
    CODESIGN_IDENTITY="$MACOS_CODESIGN_IDENTITY"
  else
    local found
    found="$(security find-identity -v -p codesigning 2>/dev/null | awk -F'"' '/Developer ID Application/{print $2; exit}')"
    if [[ -n "$found" ]]; then
      CODESIGN_IDENTITY="$found"
    fi
  fi
  if [[ "$CODESIGN_IDENTITY" != "-" ]]; then
    CODESIGN_BIN_ARGS=(--timestamp --options runtime)
    CODESIGN_DMG_ARGS=(--timestamp)
    echo "codesign identity: ${CODESIGN_IDENTITY}"
  else
    echo "::warning::no Developer ID identity is available; macOS artifacts will use ad-hoc signing and will not be notarized"
  fi
  if [[ "$CODESIGN_IDENTITY" != "-" && -n "${APPLE_API_KEY:-}" && -n "${APPLE_API_KEY_ID:-}" && -n "${APPLE_API_ISSUER:-}" ]]; then
    APPLE_KEY_FILE="${stage_root}/AuthKey.p8"
    printf '%s' "$APPLE_API_KEY" >"$APPLE_KEY_FILE"
    NOTARIZE=1
    echo "notarization: enabled"
  fi
}

setup_macos_signing

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
    codesign --force --sign "$CODESIGN_IDENTITY" "${CODESIGN_BIN_ARGS[@]}" "$bin"
  done
  codesign --force --sign "$CODESIGN_IDENTITY" "${CODESIGN_BIN_ARGS[@]}" "$app_root"
  codesign --verify "$app_root" >/dev/null
}

notarize_dmg() {
  local dmg_path="$1"
  [[ "$NOTARIZE" == 1 ]] || return 0
  run_with_timeout 900 xcrun notarytool submit "$dmg_path" \
    --key "$APPLE_KEY_FILE" \
    --key-id "$APPLE_API_KEY_ID" \
    --issuer "$APPLE_API_ISSUER" \
    --wait
  run_with_timeout 120 xcrun stapler staple "$dmg_path"
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
  run_with_timeout 30 osascript <<EOF >/dev/null
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
  run_with_timeout 180 hdiutil create \
    -volname "CheeseWAF" \
    -srcfolder "$dmg_root" \
    -ov \
    -fs HFS+ \
    -format UDRW \
    "$rw_dmg" >/dev/null

  mount_point="${stage_root}/mount-${name}"
  mkdir -p "$mount_point"
  device="$mount_point"
  if ! attach_output="$(run_with_timeout 60 hdiutil attach \
      -readwrite -noverify -noautoopen -mountpoint "$mount_point" "$rw_dmg")"; then
    echo "::error::failed to attach ${rw_dmg}" >&2
    exit 1
  fi
  attached_device="$(printf '%s\n' "$attach_output" | awk '/^\/dev\// { print $1; exit }')"
  [[ -n "$attached_device" && -d "$mount_point" ]] || {
    echo "::error::failed to attach ${rw_dmg}" >&2
    exit 1
  }
  device="$attached_device"
  layout_dmg_window "$mount_point" || true
  sync
  run_with_timeout 30 hdiutil detach "$device" -quiet ||
    run_with_timeout 30 hdiutil detach "$device" -force ||
    run_with_timeout 30 hdiutil detach "$mount_point" -force
  device=""

  dmg_path="${abs_release}/${name}.dmg"
  echo "creating ${dmg_path}"
  rm -f "$dmg_path"
  run_with_timeout 180 hdiutil convert "$rw_dmg" -format UDZO -imagekey zlib-level=9 -o "$dmg_path" >/dev/null
  xattr -cr "$dmg_path" 2>/dev/null || true
  codesign --force --sign "$CODESIGN_IDENTITY" "${CODESIGN_DMG_ARGS[@]}" "$dmg_path"
  notarize_dmg "$dmg_path"
done

bash "${script_dir}/rewrite-release-checksums.sh" "$abs_release"

if [[ -f "${abs_release}/release-manifest.txt" ]]; then
  {
    echo
    echo "macOS disk images:"
    find "$abs_release" -maxdepth 1 -type f -name '*.dmg' -exec basename {} \; | sort | sed 's/^/- /'
  } >>"${abs_release}/release-manifest.txt"
fi

echo "DMG images written to ${abs_release}/"
