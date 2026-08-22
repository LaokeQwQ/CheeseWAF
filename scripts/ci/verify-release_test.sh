#!/usr/bin/env bash
set -euo pipefail

root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$root"

fail() {
  echo "::error::$*" >&2
  exit 1
}

expect_match() {
  local name="$1"
  local want="$2"
  local got
  got="$(bash scripts/ci/verify-release.sh --print-host-match "$name")"
  [[ "$got" == "$want" ]] || fail "host match ${name}: got ${got}, want ${want}"
}

host_uname="$(uname -s)"
host_arch="$(uname -m)"
case "$host_uname" in
  Darwin)
    expect_match 'cheesewaf-arm64-darwin-0.1.0-PreTest.tar.gz' "$([[ "$host_arch" == arm64 || "$host_arch" == aarch64 ]] && echo yes || echo no)"
    expect_match 'cheesewaf-amd64-darwin-0.1.0-PreTest.tar.gz' "$([[ "$host_arch" == x86_64 || "$host_arch" == amd64 ]] && echo yes || echo no)"
    expect_match 'cheesewaf-amd64-linux-0.1.0-PreTest.tar.gz' no
    ;;
  Linux)
    expect_match 'cheesewaf-amd64-linux-0.1.0-PreTest.tar.gz' "$([[ "$host_arch" == x86_64 || "$host_arch" == amd64 ]] && echo yes || echo no)"
    expect_match 'cheesewaf-arm64-linux-0.1.0-PreTest.tar.gz' "$([[ "$host_arch" == arm64 || "$host_arch" == aarch64 ]] && echo yes || echo no)"
    expect_match 'cheesewaf-arm64-darwin-0.1.0-PreTest.tar.gz' no
    ;;
esac
expect_match 'cheesewaf-sparc-darwin-0.1.0-PreTest.tar.gz' no

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

make_package() {
  local dest="$1"
  local branch="$2"
  local channel="$3"
  local with_gui="$4"
  mkdir -p "${dest}/web/dist" "${dest}/configs"
  printf '<html></html>\n' >"${dest}/web/dist/index.html"
  printf 'listen: 127.0.0.1:8080\n' >"${dest}/configs/cheesewaf.yaml"
  printf 'version=0.1.0-PreTest\nchannel=%s\nbranch=%s\ncommit=abc123\nbuild_time=2026-08-20T00:00:00Z\n' \
    "$channel" "$branch" >"${dest}/VERSION"
  printf '{\n  "name": "CheeseWAF",\n  "version": "0.1.0-PreTest",\n  "channel": "%s",\n  "branch": "%s"\n}\n' \
    "$channel" "$branch" >"${dest}/release.json"
  : >"${dest}/cheesewaf"
  chmod +x "${dest}/cheesewaf"
  : >"${dest}/waf-cli"
  chmod +x "${dest}/waf-cli"
  if [[ "$with_gui" == "yes" ]]; then
    : >"${dest}/cheesewaf-gui"
    chmod +x "${dest}/cheesewaf-gui"
  fi
}

rewrite_sums() {
  local work="$1"
  (
    cd "$work"
    local files=()
    while IFS= read -r file; do
      [[ -n "$file" ]] || continue
      files+=("$file")
    done < <(
      find . -maxdepth 1 -type f \
        \( -name '*.tar.gz' -o -name '*.zip' -o -name '*.exe' -o -name '*.dmg' \) \
        -print | sed 's#^\./##' | sort
    )
    [[ "${#files[@]}" -gt 0 ]] || fail "no fixture files to checksum in ${work}"
    if command -v sha256sum >/dev/null 2>&1; then
      sha256sum "${files[@]}" >SHA256SUMS
    else
      shasum -a 256 "${files[@]}" >SHA256SUMS
    fi
  )
}

pack_and_sum() {
  local work="$1"
  local name="$2"
  tar -C "$work" -czf "${work}/${name}" pkg
  rewrite_sums "$work"
}

run_static() {
  VERIFY_RELEASE_STATIC_ONLY=1 bash scripts/ci/verify-release.sh "$1"
}

goreleaser_dir="${tmp}/goreleaser"
mkdir -p "${goreleaser_dir}/pkg"
make_package "${goreleaser_dir}/pkg" goreleaser release no
pack_and_sum "$goreleaser_dir" 'cheesewaf-sparc-darwin-0.0.1-PreTest.tar.gz'
run_static "$goreleaser_dir" || fail "GoReleaser darwin snapshot without GUI must pass"

channel_missing="${tmp}/channel-missing"
mkdir -p "${channel_missing}/pkg"
make_package "${channel_missing}/pkg" canary PreTest no
pack_and_sum "$channel_missing" 'cheesewaf-sparc-darwin-0.1.0-PreTest.tar.gz'
if run_static "$channel_missing"; then
  fail "channel darwin package without GUI must fail"
fi

channel_ok="${tmp}/channel-ok"
mkdir -p "${channel_ok}/pkg"
make_package "${channel_ok}/pkg" canary PreTest yes
pack_and_sum "$channel_ok" 'cheesewaf-sparc-darwin-0.1.0-PreTest.tar.gz'
run_static "$channel_ok" || fail "channel darwin package with GUI must pass"

expect_authenticode_failure() {
  local name="$1"
  local exit_code="$2"
  local output="$3"
  local fixture="${tmp}/${name}"
  local tools="${fixture}/tools"

  mkdir -p "${fixture}/pkg" "$tools"
  make_package "${fixture}/pkg" goreleaser release no
  pack_and_sum "$fixture" 'cheesewaf-sparc-linux-0.1.0-PreTest.tar.gz'
  : >"${fixture}/cheesewaf.exe"
  rewrite_sums "$fixture"
  cat >"${tools}/osslsigncode" <<EOF
#!/usr/bin/env bash
printf '%s\n' '${output}'
exit ${exit_code}
EOF
  chmod +x "${tools}/osslsigncode"

  if PATH="${tools}:${PATH}" CHEESEWAF_REQUIRE_SIGNING=1 run_static "$fixture"; then
    fail "${name}: invalid Authenticode result must fail"
  fi
}

# Regression guards: neither a reassuring substring on a failed command nor
# the word "invalid" containing "valid" may pass the signing gate.
expect_authenticode_failure signing-exit-code 1 'Signature verification: ok'
expect_authenticode_failure signing-invalid-text 0 'Signature invalid'

signing_ok="${tmp}/signing-ok"
mkdir -p "${signing_ok}/pkg" "${signing_ok}/tools"
make_package "${signing_ok}/pkg" goreleaser release no
pack_and_sum "$signing_ok" 'cheesewaf-sparc-other-0.1.0-PreTest.tar.gz'
: >"${signing_ok}/cheesewaf.exe"
rewrite_sums "$signing_ok"
cat >"${signing_ok}/tools/osslsigncode" <<'EOF'
#!/usr/bin/env bash
echo Succeeded
EOF
chmod +x "${signing_ok}/tools/osslsigncode"
PATH="${signing_ok}/tools:${PATH}" CHEESEWAF_REQUIRE_SIGNING=1 run_static "$signing_ok" ||
  fail "anchored successful Authenticode result must pass"

mac_signing="${tmp}/mac-signing"
mkdir -p "${mac_signing}/pkg" "${mac_signing}/tools"
make_package "${mac_signing}/pkg" goreleaser release no
pack_and_sum "$mac_signing" 'cheesewaf-sparc-other-0.1.0-PreTest.tar.gz'
: >"${mac_signing}/cheesewaf.dmg"
rewrite_sums "$mac_signing"
cat >"${mac_signing}/tools/hdiutil" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

action="${1:-}"
shift || true
case "$action" in
  attach)
    mountpoint=""
    while [[ $# -gt 0 ]]; do
      if [[ "$1" == "-mountpoint" ]]; then
        shift
        mountpoint="${1:-}"
      fi
      shift || true
    done
    [[ -n "$mountpoint" ]] || exit 2
    mkdir -p "${mountpoint}/CheeseWAF.app"
    printf '/dev/disk-test Apple_HFS %s\n' "$mountpoint"
    ;;
  detach) ;;
  *) exit 2 ;;
esac
EOF
cat >"${mac_signing}/tools/codesign" <<'EOF'
#!/usr/bin/env bash
exit "${FAKE_CODESIGN_EXIT:-0}"
EOF
cat >"${mac_signing}/tools/spctl" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "${FAKE_SPCTL_OUTPUT:-/tmp/CheeseWAF.app: accepted}"
exit "${FAKE_SPCTL_EXIT:-0}"
EOF
chmod +x "${mac_signing}/tools/hdiutil" "${mac_signing}/tools/codesign" "${mac_signing}/tools/spctl"

run_macos_signing_static() {
  PATH="${mac_signing}/tools:${PATH}" \
    CHEESEWAF_REQUIRE_SIGNING=1 \
    CHEESEWAF_SIGNING_SCOPE=macos \
    run_static "$mac_signing"
}

if FAKE_CODESIGN_EXIT=1 run_macos_signing_static; then
  fail "non-zero codesign verification must fail"
fi
if FAKE_SPCTL_EXIT=1 \
  FAKE_SPCTL_OUTPUT=$'/tmp/CheeseWAF.app: accepted\nsource=Notarized Developer ID' \
  run_macos_signing_static; then
  fail "non-zero spctl assessment must fail"
fi
if FAKE_SPCTL_OUTPUT=$'/tmp/CheeseWAF.app: not accepted\nsource=Notarized Developer ID' \
  run_macos_signing_static; then
  fail "spctl not-accepted text must not satisfy the anchored success check"
fi
FAKE_SPCTL_OUTPUT=$'/tmp/CheeseWAF.app: accepted\nsource=Notarized Developer ID' \
  run_macos_signing_static || fail "anchored successful macOS assessment must pass"

if CHEESEWAF_REQUIRE_SIGNING=1 CHEESEWAF_SIGNING_SCOPE=windows run_static "$channel_ok"; then
  fail "strict Windows signing scope must reject a release without top-level PE artifacts"
fi

if CHEESEWAF_REQUIRE_SIGNING=1 CHEESEWAF_SIGNING_SCOPE=invalid run_static "$channel_ok"; then
  fail "invalid signing scope must fail"
fi

tampered="${tmp}/tampered"
mkdir -p "${tampered}/pkg"
make_package "${tampered}/pkg" goreleaser release no
pack_and_sum "$tampered" 'cheesewaf-sparc-linux-0.1.0-PreTest.tar.gz'
printf 'tamper\n' >>"${tampered}/cheesewaf-sparc-linux-0.1.0-PreTest.tar.gz"
if run_static "$tampered"; then
  fail "tampered release archive must fail checksum verification"
fi

unlisted="${tmp}/unlisted"
mkdir -p "${unlisted}/pkg"
make_package "${unlisted}/pkg" goreleaser release no
pack_and_sum "$unlisted" 'cheesewaf-sparc-linux-0.1.0-PreTest.tar.gz'
cp "${unlisted}/cheesewaf-sparc-linux-0.1.0-PreTest.tar.gz" \
  "${unlisted}/cheesewaf-sparc-linux-0.1.1-PreTest.tar.gz"
if run_static "$unlisted"; then
  fail "release archive omitted from the checksum manifest must fail"
fi

missing_config="${tmp}/missing-config"
mkdir -p "${missing_config}/pkg"
make_package "${missing_config}/pkg" goreleaser release no
rm "${missing_config}/pkg/configs/cheesewaf.yaml"
pack_and_sum "$missing_config" 'cheesewaf-sparc-linux-0.1.0-PreTest.tar.gz'
if run_static "$missing_config"; then
  fail "release archive missing configs/cheesewaf.yaml must fail"
fi

if command -v python3 >/dev/null 2>&1; then
  unsafe="${tmp}/unsafe-path"
  mkdir -p "$unsafe"
  python3 - "$unsafe/cheesewaf-sparc-linux-0.1.0-PreTest.tar.gz" <<'PY'
import io
import sys
import tarfile

with tarfile.open(sys.argv[1], "w:gz") as archive:
    info = tarfile.TarInfo("../escaped")
    payload = b"escape\n"
    info.size = len(payload)
    archive.addfile(info, io.BytesIO(payload))
PY
  (
    cd "$unsafe"
    if command -v sha256sum >/dev/null 2>&1; then
      sha256sum cheesewaf-sparc-linux-0.1.0-PreTest.tar.gz >SHA256SUMS
    else
      shasum -a 256 cheesewaf-sparc-linux-0.1.0-PreTest.tar.gz >SHA256SUMS
    fi
  )
  unsafe_output="${unsafe}/verify.out"
  if run_static "$unsafe" >"$unsafe_output" 2>&1; then
    fail "archive path traversal must fail"
  fi
  grep -Fq 'unsafe archive path' "$unsafe_output" ||
    fail "archive path traversal must be rejected before extraction"
fi

echo "verify-release tests passed."
