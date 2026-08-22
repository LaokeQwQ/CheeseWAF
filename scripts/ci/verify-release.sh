#!/usr/bin/env bash
set -euo pipefail

release_dir="${1:-release}"
max_total_bytes="${RELEASE_TOTAL_MAX_BYTES:-629145600}"
max_artifact_bytes="${RELEASE_ARTIFACT_MAX_BYTES:-134217728}"
max_member_bytes="${RELEASE_MEMBER_MAX_BYTES:-134217728}"
map_duplicate_min_bytes="${MAP_DUPLICATE_MIN_BYTES:-524288}"

fail() {
  echo "::error::$*"
  exit 1
}

warn() {
  echo "::warning::$*"
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$@"
  else
    shasum -a 256 "$@"
  fi
}

verify_sha256_manifest() {
  local manifest="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -c "$manifest"
  else
    shasum -a 256 -c "$manifest"
  fi
}

validate_sha256_manifest() {
  local manifest="$1"
  awk '
    NF != 2 || length($1) != 64 || $1 !~ /^[0-9A-Fa-f]+$/ ||
      $2 !~ /^\*?[A-Za-z0-9][A-Za-z0-9._+-]*$/ { exit 1 }
    END { if (NR == 0) exit 1 }
  ' "$manifest" || fail "checksum manifest has an invalid or unsafe entry: $(basename "$manifest")"
}

checksum_manifest_lists_once() {
  local manifest="$1"
  local name="$2"
  local count
  count="$(awk -v wanted="$name" '
    length($1) == 64 && $1 ~ /^[0-9A-Fa-f]+$/ {
      file = $2
      sub(/^\*/, "", file)
      if (file == wanted) count++
    }
    END { print count + 0 }
  ' "$manifest")"
  [[ "$count" -eq 1 ]]
}

validate_archive_members() {
  local artifact="$1"
  local artifact_name="$2"
  local members="${tmp_dir}/members.txt"
  case "$artifact" in
    *.tar.gz)
      tar -tzf "$artifact" >"$members" || fail "could not list ${artifact_name}"
      ;;
    *.zip)
      unzip -Z1 "$artifact" >"$members" || fail "could not list ${artifact_name}"
      ;;
  esac
  while IFS= read -r member; do
    normalized_member="$(printf '%s' "$member" | tr '\\' '/')"
    normalized_member="${normalized_member#./}"
    case "$normalized_member" in
      "" | /* | ../* | */../* | */.. | [A-Za-z]:/*)
        fail "${artifact_name} contains unsafe archive path: ${member}"
        ;;
    esac
  done <"$members"
}

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

# Channel packages (package-release.sh) ship GUI binaries. GoReleaser archives
# keep one engine binary; VERSION branch=goreleaser marks those archives.
is_goreleaser_archive() {
  grep -Eq '^branch=goreleaser$' "$1/VERSION"
}

# Names are cheesewaf-{arch}-{os}-{version}[...]; match arch and os independently.
host_uname="$(uname -s)"
host_arch="$(uname -m)"
case "$host_uname" in
  Linux | Darwin)
    smoke_binary_name='cheesewaf'
    ;;
  MINGW* | MSYS* | CYGWIN*)
    smoke_binary_name='cheesewaf.exe'
    ;;
  *)
    smoke_binary_name=''
    ;;
esac

artifact_matches_host() {
  local name="$1"
  local os_ok=0
  local arch_ok=0
  case "$host_uname" in
    Linux)
      [[ "$name" == *-linux-* ]] && os_ok=1
      ;;
    Darwin)
      [[ "$name" == *-darwin-* ]] && os_ok=1
      ;;
    MINGW* | MSYS* | CYGWIN*)
      [[ "$name" == *-windows-* ]] && os_ok=1
      ;;
  esac
  case "$host_arch" in
    x86_64 | amd64)
      [[ "$name" == *-amd64-* || "$name" == *-x86_64-* ]] && arch_ok=1
      ;;
    aarch64 | arm64)
      [[ "$name" == *-arm64-* || "$name" == *-aarch64-* ]] && arch_ok=1
      ;;
  esac
  [[ "$os_ok" -eq 1 && "$arch_ok" -eq 1 ]]
}

if [[ "${1:-}" == --print-host-match ]]; then
  shift
  [[ $# -ge 1 ]] || fail "--print-host-match requires an archive name"
  if artifact_matches_host "$1"; then
    echo yes
  else
    echo no
  fi
  exit 0
fi

command -v curl >/dev/null 2>&1 || fail "curl is required for release smoke tests"
if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
  fail "sha256sum or shasum is required"
fi
[[ -d "$release_dir" ]] || fail "release directory not found: ${release_dir}"

artifacts=()
while IFS= read -r artifact; do
  [[ -n "$artifact" ]] || continue
  artifacts+=("$artifact")
done < <(find "$release_dir" -maxdepth 1 -type f \( -name '*.tar.gz' -o -name '*.zip' \) -print | sort)
[[ "${#artifacts[@]}" -gt 0 ]] || fail "no release archives found in ${release_dir}"

checksum_file=""
for candidate in "${release_dir}/SHA256SUMS" "${release_dir}/checksums.txt"; do
  if [[ -f "$candidate" ]]; then
    checksum_file="$candidate"
    break
  fi
done
[[ -n "$checksum_file" ]] || fail "release checksum manifest is missing"
validate_sha256_manifest "$checksum_file"
(
  cd "$release_dir"
  verify_sha256_manifest "$(basename "$checksum_file")"
)
while IFS= read -r distributable; do
  [[ -n "$distributable" ]] || continue
  distributable_name="$(basename "$distributable")"
  checksum_manifest_lists_once "$checksum_file" "$distributable_name" ||
    fail "checksum manifest must list ${distributable_name} exactly once"
done < <(
  find "$release_dir" -maxdepth 1 -type f \
    \( -name '*.tar.gz' -o -name '*.zip' -o -name '*.exe' -o -name '*.dmg' \) \
    -print | sort
)

tmp_dir="$(mktemp -d)"
smoke_root=""
mounted_vol=""
cleanup() {
  if [[ -n "${server_pid:-}" ]]; then
    kill "$server_pid" >/dev/null 2>&1 || true
    wait "$server_pid" >/dev/null 2>&1 || true
  fi
  if [[ -n "$mounted_vol" ]]; then
    run_with_timeout 30 hdiutil detach "$mounted_vol" >/dev/null 2>&1 || true
  fi
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

signing_mode="${CHEESEWAF_REQUIRE_SIGNING:-0}"
signing_scope="${CHEESEWAF_SIGNING_SCOPE:-all}"
case "$signing_mode" in
  0 | "") ;;
  1) ;;
  warn)
    warn "release signing verification is not enforced because signing credentials are unavailable"
    ;;
  *) fail "CHEESEWAF_REQUIRE_SIGNING must be 0, 1, or warn" ;;
esac
case "$signing_scope" in
  all | windows | macos) ;;
  *) fail "CHEESEWAF_SIGNING_SCOPE must be all, windows, or macos" ;;
esac

# Strict release signing gate. CI selects 1 only when the corresponding
# signing/notarization credentials exist; otherwise it selects warn visibly.
if [[ "$signing_mode" == "1" ]]; then
  # --- Windows Authenticode (PE executables at the top level of the release dir) ---
  if [[ "$signing_scope" != "macos" ]]; then
    pe_files=()
    while IFS= read -r pe; do
      [[ -n "$pe" ]] || continue
      pe_files+=("$pe")
    done < <(find "$release_dir" -maxdepth 1 -type f -iname '*.exe' | sort)
    if [[ "${#pe_files[@]}" -gt 0 ]]; then
      command -v osslsigncode >/dev/null 2>&1 ||
        fail "CHEESEWAF_REQUIRE_SIGNING=1 requires osslsigncode to verify Windows Authenticode"
      for pe in "${pe_files[@]}"; do
        if ! out="$(run_with_timeout 60 osslsigncode verify "$pe" 2>&1)"; then
          fail "Authenticode verification failed for $(basename "$pe"): ${out}"
        fi
        if ! grep -qiE '^(Succeeded|Signature verification:[[:space:]]*(ok|successful)|Signing certificate chain:[[:space:]]*ok)[[:space:]]*$' <<<"$out"; then
          fail "Authenticode verifier returned no anchored success result for $(basename "$pe"): ${out}"
        fi
      done
      echo "Authenticode verification passed for ${#pe_files[@]} Windows executable(s)."
    elif [[ "$signing_scope" == "windows" ]]; then
      fail "CHEESEWAF_SIGNING_SCOPE=windows requires at least one top-level .exe artifact"
    else
      warn "CHEESEWAF_REQUIRE_SIGNING=1 but no top-level .exe artifacts were present; Windows verification was not applicable"
    fi
  fi

  # --- macOS Developer ID / notarization (mount any .dmg and assess the .app) ---
  if [[ "$signing_scope" != "windows" ]]; then
    dmg_files=()
    while IFS= read -r dmg; do
      [[ -n "$dmg" ]] || continue
      dmg_files+=("$dmg")
    done < <(find "$release_dir" -maxdepth 1 -type f -iname '*.dmg' | sort)
    if [[ "${#dmg_files[@]}" -gt 0 ]]; then
      command -v hdiutil >/dev/null 2>&1 || fail "CHEESEWAF_REQUIRE_SIGNING=1 with .dmg artifacts requires hdiutil"
      command -v codesign >/dev/null 2>&1 || fail "CHEESEWAF_REQUIRE_SIGNING=1 with .dmg artifacts requires codesign"
      command -v spctl >/dev/null 2>&1 || fail "CHEESEWAF_REQUIRE_SIGNING=1 with .dmg artifacts requires spctl"
      for dmg in "${dmg_files[@]}"; do
        vol="$(mktemp -d "${tmp_dir}/mount.XXXXXX")"
        run_with_timeout 60 hdiutil attach -nobrowse -readonly -mountpoint "$vol" "$dmg" >/dev/null 2>&1 ||
          fail "could not mount ${dmg}"
        mounted_vol="$vol"
        app="$(find "$vol" -maxdepth 2 -type d -name '*.app' -print -quit)"
        if [[ -z "$app" ]]; then
          fail "no .app bundle found in ${dmg}"
        fi
        if ! codesign_out="$(run_with_timeout 60 codesign --verify --deep --strict "$app" 2>&1)"; then
          fail "macOS codesign verification failed for ${app}: ${codesign_out}"
        fi
        if ! spctl_out="$(run_with_timeout 60 spctl --assess --type execute --verbose=4 "$app" 2>&1)"; then
          fail "macOS notarization assessment failed for ${app}: ${spctl_out}"
        fi
        if ! grep -qiE ': accepted[[:space:]]*$' <<<"$spctl_out" ||
          ! grep -qiE '^source=Notarized Developer ID[[:space:]]*$' <<<"$spctl_out"; then
          fail "macOS notarization verifier returned no anchored success result for ${app}: ${spctl_out}"
        fi
        run_with_timeout 30 hdiutil detach "$vol" >/dev/null 2>&1 || fail "could not detach ${dmg}"
        mounted_vol=""
      done
      echo "macOS codesign/notarization verification passed for ${#dmg_files[@]} disk image(s)."
    elif [[ "$signing_scope" == "macos" ]]; then
      fail "CHEESEWAF_SIGNING_SCOPE=macos requires at least one top-level .dmg artifact"
    else
      warn "CHEESEWAF_REQUIRE_SIGNING=1 but no .dmg artifacts were present; macOS verification was not applicable"
    fi
  fi
fi

total_bytes=0
for artifact in "${artifacts[@]}"; do
  size="$(wc -c <"$artifact")"
  total_bytes=$((total_bytes + size))
  if ((size > max_artifact_bytes)); then
    fail "$(basename "$artifact") exceeds artifact budget (${size} > ${max_artifact_bytes})"
  fi
done
if ((total_bytes > max_total_bytes)); then
  fail "release archives exceed total budget (${total_bytes} > ${max_total_bytes})"
fi

for artifact in "${artifacts[@]}"; do
  artifact_name="$(basename "$artifact")"
  extract_dir="${tmp_dir}/${artifact_name//[^A-Za-z0-9._-]/_}"
  map_hash_index="${extract_dir}.map-hashes"
  : >"$map_hash_index"
  mkdir -p "$extract_dir"
  validate_archive_members "$artifact" "$artifact_name"
  case "$artifact" in
    *.tar.gz)
      tar -xzf "$artifact" -C "$extract_dir"
      ;;
    *.zip)
      command -v unzip >/dev/null 2>&1 || fail "unzip is required for ${artifact_name}"
      unzip -q "$artifact" -d "$extract_dir"
      ;;
  esac

  if find "$extract_dir" -type d -name node_modules -print -quit | grep -q .; then
    fail "${artifact_name} contains node_modules"
  fi
  if find "$extract_dir" -type f -name '*.map' -print -quit | grep -q .; then
    fail "${artifact_name} contains source maps"
  fi

  indexes=()
  while IFS= read -r index; do
    [[ -n "$index" ]] || continue
    indexes+=("$index")
  done < <(find "$extract_dir" -type f -path '*/web/dist/index.html')
  [[ "${#indexes[@]}" -eq 1 ]] ||
    fail "${artifact_name} must contain exactly one web/dist/index.html"
  package_root="${indexes[0]%/web/dist/index.html}"
  [[ -f "${package_root}/configs/cheesewaf.yaml" ]] ||
    fail "${artifact_name} is missing configs/cheesewaf.yaml"
  [[ -s "${package_root}/VERSION" ]] ||
    fail "${artifact_name} is missing VERSION metadata"
  [[ -s "${package_root}/release.json" ]] ||
    fail "${artifact_name} is missing release.json metadata"
  grep -Eq '^version=.+$' "${package_root}/VERSION" ||
    fail "${artifact_name} has invalid VERSION metadata"
  grep -Eq '^commit=.+$' "${package_root}/VERSION" ||
    fail "${artifact_name} VERSION metadata is missing commit"
  grep -Eq '"version"[[:space:]]*:[[:space:]]*"[^"]+"' "${package_root}/release.json" ||
    fail "${artifact_name} has invalid release.json metadata"

  if [[ "$artifact_name" == *linux* ]]; then
    [[ -f "${package_root}/systemd/cheesewaf.service" ]] ||
      fail "${artifact_name} is missing systemd/cheesewaf.service"
    grep -Fq 'ExecStart=/usr/local/bin/cheesewaf serve' "${package_root}/systemd/cheesewaf.service" ||
      fail "${artifact_name} systemd unit does not start cheesewaf serve"
  fi
  if ! is_goreleaser_archive "$package_root"; then
    if [[ "$artifact_name" == *darwin* ]]; then
      [[ -x "${package_root}/cheesewaf-gui" ]] ||
        fail "${artifact_name} is missing cheesewaf-gui"
    fi
    if [[ "$artifact" == *.zip && "$artifact_name" == *windows* ]]; then
      [[ -f "${package_root}/cheesewaf.exe" ]] ||
        fail "${artifact_name} is missing cheesewaf.exe"
      [[ -f "${package_root}/cheesewaf-gui.exe" ]] ||
        fail "${artifact_name} is missing cheesewaf-gui.exe"
    fi
  fi

  oversized="$(find "$extract_dir" -type f -size "+${max_member_bytes}c" -print -quit)"
  [[ -z "$oversized" ]] ||
    fail "${artifact_name} contains oversized member ${oversized#"$extract_dir"/}"

  while IFS= read -r -d '' map_file; do
    map_size="$(wc -c <"$map_file")"
    if ((map_size < map_duplicate_min_bytes)); then
      continue
    fi
    map_hash="$(sha256_file "$map_file" | awk '{ print $1 }')"
    previous_map="$(awk -F '\t' -v hash="$map_hash" '$1 == hash { print $2; exit }' "$map_hash_index")"
    if [[ -n "$previous_map" ]]; then
      fail "duplicate large map asset: ${previous_map} and ${map_file}"
    fi
    printf '%s\t%s\n' "$map_hash" "$map_file" >>"$map_hash_index"
  done < <(
    find "${package_root}/web/dist" -type f \
      \( -iname '*.geojson' -o -iname '*.topojson' -o -iname '*map*.json' -o -iname '*map*.js' \) \
      -print0
  )

  if [[ -n "$smoke_binary_name" ]] &&
    artifact_matches_host "$artifact_name" &&
    [[ -z "$smoke_root" ]]; then
    smoke_root="$package_root"
  fi
done

if [[ -z "$smoke_root" || "${VERIFY_RELEASE_STATIC_ONLY:-}" == "1" ]]; then
  echo "Release static verification passed: ${#artifacts[@]} archives, ${total_bytes} bytes."
  if [[ "${VERIFY_RELEASE_STATIC_ONLY:-}" == "1" ]]; then
    echo "Startup and MIME smoke skipped (VERIFY_RELEASE_STATIC_ONLY=1)."
  else
    echo "No archive matches host ${host_uname}/${host_arch}; startup and MIME smoke skipped."
  fi
  exit 0
fi

binary="${smoke_root}/${smoke_binary_name}"
web_dir="${smoke_root}/web/dist"
config="${tmp_dir}/smoke.yaml"
log_file="${tmp_dir}/server.log"
[[ -f "$binary" ]] || fail "host-compatible cheesewaf binary is missing"
if [[ "$host_uname" == "Linux" || "$host_uname" == "Darwin" ]]; then
  [[ -x "$binary" ]] || fail "host-compatible cheesewaf binary is not executable"
  wrapper="${smoke_root}/waf-cli"
  [[ -x "$wrapper" ]] || fail "host-compatible waf-cli wrapper is missing or not executable"
  "$wrapper" --help >/dev/null || fail "waf-cli wrapper does not dispatch to the CLI subcommand"
fi

port_is_available() {
  local port="$1"
  ! (: </dev/tcp/127.0.0.1/"$port") >/dev/null 2>&1
}

base_port=""
for ((attempt = 0; attempt < 40; attempt++)); do
  random_port="$(od -An -N2 -tu2 /dev/urandom | tr -d '[:space:]')"
  candidate=$((20000 + random_port % 40000))
  if port_is_available "$candidate" &&
    port_is_available $((candidate + 1)) &&
    port_is_available $((candidate + 2)); then
    base_port="$candidate"
    break
  fi
done
[[ -n "$base_port" ]] || fail "could not find three available local ports for release smoke"
proxy_port="$base_port"
admin_port=$((base_port + 1))
cluster_port=$((base_port + 2))
sed \
  -e "s/127.0.0.1:8080/127.0.0.1:${proxy_port}/g" \
  -e "s/127.0.0.1:9443/127.0.0.1:${admin_port}/g" \
  -e "s/127.0.0.1:9444/127.0.0.1:${cluster_port}/g" \
  "${smoke_root}/configs/cheesewaf.yaml" >"$config"
grep -Fq "127.0.0.1:${proxy_port}" "$config" || fail "smoke config data listener replacement did not apply"
grep -Fq "127.0.0.1:${admin_port}" "$config" || fail "smoke config admin listener replacement did not apply"
grep -Fq "127.0.0.1:${cluster_port}" "$config" || fail "smoke config cluster listener replacement did not apply"

(
  cd "$tmp_dir"
  config_arg="$config"
  if [[ "$host_uname" == MINGW* || "$host_uname" == MSYS* || "$host_uname" == CYGWIN* ]]; then
    config_arg="$(cygpath -w "$config")"
  fi
  "$binary" serve --config "$config_arg"
) >"$log_file" 2>&1 &
server_pid=$!

js_file="$(find "$web_dir/assets" -type f -name '*.js' -print -quit)"
css_file="$(find "$web_dir/assets" -type f -name '*.css' -print -quit)"
[[ -n "$js_file" && -n "$css_file" ]] || fail "built UI is missing JS or CSS assets"

check_mime() {
  local file="$1"
  local expected="$2"
  local relative="${file#"$web_dir"}"
  local headers="${tmp_dir}/headers.txt"
  curl -fsS --connect-timeout 2 --max-time 5 -D "$headers" -o /dev/null \
    "http://127.0.0.1:${admin_port}${relative}"
  content_type="$(
    awk 'BEGIN { IGNORECASE=1 } /^Content-Type:/ {
      sub(/^[^:]+:[[:space:]]*/, "")
      sub(/\r$/, "")
      print
      exit
    }' "$headers"
  )"
  [[ "$content_type" == *"$expected"* ]] ||
    fail "${relative} returned unexpected Content-Type: ${content_type}"
}

ready=""
for ((attempt = 0; attempt < 30; attempt++)); do
  if ! kill -0 "$server_pid" >/dev/null 2>&1; then
    cat "$log_file"
    fail "release binary exited during startup smoke"
  fi
  if curl -fsS --connect-timeout 2 --max-time 5 "http://127.0.0.1:${admin_port}/" >/dev/null 2>&1; then
    ready="yes"
    break
  fi
  sleep 1
done
if [[ -z "$ready" ]]; then
  cat "$log_file"
  fail "release binary did not become ready"
fi

check_mime "$js_file" "javascript"
check_mime "$css_file" "text/css"

echo "Release verification passed: ${#artifacts[@]} archives, ${total_bytes} bytes."
