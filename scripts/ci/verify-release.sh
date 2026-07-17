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

command -v curl >/dev/null 2>&1 || fail "curl is required for release smoke tests"
command -v sha256sum >/dev/null 2>&1 || fail "sha256sum is required"
[[ -d "$release_dir" ]] || fail "release directory not found: ${release_dir}"

mapfile -t artifacts < <(
  find "$release_dir" -maxdepth 1 -type f \( -name '*.tar.gz' -o -name '*.zip' \) -print |
    sort
)
[[ "${#artifacts[@]}" -gt 0 ]] || fail "no release archives found in ${release_dir}"

checksum_file=""
for candidate in "${release_dir}/SHA256SUMS" "${release_dir}/checksums.txt"; do
  if [[ -f "$candidate" ]]; then
    checksum_file="$candidate"
    break
  fi
done
[[ -n "$checksum_file" ]] || fail "release checksum manifest is missing"
(
  cd "$release_dir"
  sha256sum -c "$(basename "$checksum_file")"
)

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

tmp_dir="$(mktemp -d)"
smoke_root=""
host_uname="$(uname -s)"
host_arch="$(uname -m)"
case "$host_arch" in
  x86_64 | amd64)
    smoke_arch_regex='(amd64|x86_64)'
    ;;
  aarch64 | arm64)
    smoke_arch_regex='(arm64|aarch64)'
    ;;
  *)
    smoke_arch_regex=''
    ;;
esac
case "$host_uname" in
  Linux)
    smoke_os_regex='[Ll]inux'
    smoke_binary_name='cheesewaf'
    ;;
  Darwin)
    smoke_os_regex='[Dd]arwin'
    smoke_binary_name='cheesewaf'
    ;;
  MINGW* | MSYS* | CYGWIN*)
    smoke_os_regex='[Ww]indows'
    smoke_binary_name='cheesewaf.exe'
    ;;
  *)
    smoke_os_regex=''
    smoke_binary_name=''
    ;;
esac
cleanup() {
  if [[ -n "${server_pid:-}" ]]; then
    kill "$server_pid" >/dev/null 2>&1 || true
    wait "$server_pid" >/dev/null 2>&1 || true
  fi
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

for artifact in "${artifacts[@]}"; do
  declare -A map_hashes=()
  artifact_name="$(basename "$artifact")"
  extract_dir="${tmp_dir}/${artifact_name//[^A-Za-z0-9._-]/_}"
  mkdir -p "$extract_dir"
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

  mapfile -t indexes < <(find "$extract_dir" -type f -path '*/web/dist/index.html')
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

  oversized="$(find "$extract_dir" -type f -size "+${max_member_bytes}c" -print -quit)"
  [[ -z "$oversized" ]] ||
    fail "${artifact_name} contains oversized member ${oversized#"$extract_dir"/}"

  while IFS= read -r -d '' map_file; do
    map_size="$(wc -c <"$map_file")"
    if ((map_size < map_duplicate_min_bytes)); then
      continue
    fi
    map_hash="$(sha256sum "$map_file" | awk '{ print $1 }')"
    if [[ -n "${map_hashes[$map_hash]:-}" ]]; then
      fail "duplicate large map asset: ${map_hashes[$map_hash]} and ${map_file}"
    fi
    map_hashes[$map_hash]="$map_file"
  done < <(
    find "${package_root}/web/dist" -type f \
      \( -iname '*.geojson' -o -iname '*.topojson' -o -iname '*map*.json' -o -iname '*map*.js' \) \
      -print0
  )

  if [[ -n "$smoke_os_regex" ]] &&
    [[ -n "$smoke_arch_regex" ]] &&
    [[ "$artifact_name" =~ $smoke_os_regex.*$smoke_arch_regex ]] &&
    [[ -z "$smoke_root" ]]; then
    smoke_root="$package_root"
  fi
done

if [[ -z "$smoke_root" ]]; then
  echo "Release static verification passed: ${#artifacts[@]} archives, ${total_bytes} bytes."
  echo "No archive matches host ${host_uname}/${host_arch}; startup and MIME smoke skipped."
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

base_port=$((22000 + ($$ % 10000)))
proxy_port="$base_port"
admin_port=$((base_port + 1))
cluster_port=$((base_port + 2))
sed \
  -e "s/127.0.0.1:8080/127.0.0.1:${proxy_port}/g" \
  -e "s/127.0.0.1:9443/127.0.0.1:${admin_port}/g" \
  -e "s/127.0.0.1:9444/127.0.0.1:${cluster_port}/g" \
  -e 's/^  admin_public: false$/  admin_public: true/' \
  "${smoke_root}/configs/cheesewaf.yaml" >"$config"

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
  curl -fsS -D "$headers" -o /dev/null "http://127.0.0.1:${admin_port}${relative}"
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
for _ in $(seq 1 30); do
  if ! kill -0 "$server_pid" >/dev/null 2>&1; then
    cat "$log_file"
    fail "release binary exited during startup smoke"
  fi
  if curl -fsS "http://127.0.0.1:${admin_port}/" >/dev/null 2>&1; then
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
