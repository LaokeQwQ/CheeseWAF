#!/usr/bin/env bash
set -euo pipefail

root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$root"

fail() {
  echo "::error::$*" >&2
  exit 1
}

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
fake_bin="${tmp}/bin"
mkdir -p "$fake_bin"
stable_commit='0123456789abcdef0123456789abcdef01234567'
stable_tag_object='1111111111111111111111111111111111111111'

cat >"${fake_bin}/syft" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

target="${2:-}"
output=""
for arg in "$@"; do
  case "$arg" in
    cyclonedx-json=*) output="${arg#cyclonedx-json=}" ;;
  esac
done
[[ -n "$output" ]] || exit 2
if [[ "$target" == "dir:${FAKE_RELEASE_DIR}" && "${FAKE_SYFT_ARTIFACT_MODE}" == "fail" ]]; then
  exit 1
fi
printf '{"bomFormat":"CycloneDX","specVersion":"1.6"}\n' >"$output"
EOF

cat >"${fake_bin}/cosign" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

action="${1:-}"
shift || true
printf '%s %s\n' "$action" "$*" >>"$FAKE_COSIGN_LOG"
if [[ "$action" == "sign-blob" ]]; then
  bundle=""
  while [[ $# -gt 0 ]]; do
    if [[ "$1" == "--bundle" ]]; then
      shift
      bundle="${1:-}"
    fi
    shift || true
  done
  [[ -n "$bundle" ]] || exit 2
  printf 'test bundle\n' >"$bundle"
fi
EOF

cat >"${fake_bin}/gh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

printf '%s\n' "$*" >>"$FAKE_GH_LOG"
if [[ "${1:-}" == "api" ]]; then
  case "${2:-}" in
    */git/ref/tags/*)
      [[ "${FAKE_REMOTE_TAG_MISSING:-0}" != "1" ]] || exit 1
      printf '%s %s\n' "${FAKE_REMOTE_REF_TYPE:-commit}" "${FAKE_REMOTE_REF_SHA:-0123456789abcdef0123456789abcdef01234567}"
      ;;
    */git/tags/*)
      printf '%s %s\n' "${FAKE_REMOTE_TAG_OBJECT_TYPE:-commit}" "${FAKE_REMOTE_TAG_OBJECT_SHA:-0123456789abcdef0123456789abcdef01234567}"
      ;;
    *) exit 2 ;;
  esac
elif [[ "${1:-}" == "release" && "${2:-}" == "view" ]]; then
  if [[ "${FAKE_GH_STABLE_NEW:-0}" == "1" ]]; then
    exit 1
  fi
  field=""
  for arg in "$@"; do
    case "$arg" in
      assets|tagName|isDraft|isPrerelease|targetCommitish) field="$arg" ;;
    esac
  done
  case "$field" in
    assets)
      if [[ -n "${FAKE_REMOTE_ASSETS:-}" ]]; then
        printf '%s\n' "$FAKE_REMOTE_ASSETS"
      else
        find "$FAKE_RELEASE_DIR" -maxdepth 1 -type f ! -name release-manifest.txt -exec basename {} \; | sort
      fi
      ;;
    tagName) printf '%s\n' "${FAKE_REMOTE_TAG_NAME:-v0.3.9}" ;;
    isDraft) printf '%s\n' "${FAKE_REMOTE_IS_DRAFT:-false}" ;;
    isPrerelease) printf '%s\n' "${FAKE_REMOTE_IS_PRERELEASE:-false}" ;;
    targetCommitish) printf '%s\n' "${FAKE_REMOTE_TARGET:-${FAKE_REMOTE_TAG_OBJECT_SHA:-${FAKE_REMOTE_REF_SHA:-0123456789abcdef0123456789abcdef01234567}}}" ;;
  esac
elif [[ "${1:-}" == "release" && "${2:-}" == "download" ]]; then
  pattern=""
  download_dir=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --pattern)
        shift
        pattern="${1:-}"
        ;;
      --dir)
        shift
        download_dir="${1:-}"
        ;;
    esac
    shift || true
  done
  [[ -n "$pattern" && -n "$download_dir" ]] || exit 2
  source="${FAKE_REMOTE_DIR}/${pattern}"
  [[ -f "$source" ]] || source="${FAKE_RELEASE_DIR}/${pattern}"
  mkdir -p "$download_dir"
  cp "$source" "${download_dir}/${pattern}"
elif [[ "${1:-}" == "release" && "${2:-}" == "create" ]]; then
  notes_file=""
  while [[ $# -gt 0 ]]; do
    if [[ "$1" == "--notes-file" ]]; then
      shift
      notes_file="${1:-}"
    fi
    shift || true
  done
  [[ -n "$notes_file" && -f "$notes_file" ]] || exit 2
  cp "$notes_file" "${FAKE_GH_LOG}.notes"
fi
EOF

chmod +x "${fake_bin}/syft" "${fake_bin}/cosign" "${fake_bin}/gh"

make_release() {
  local dir="$1"
  mkdir -p "$dir"
  cat >"${dir}/release-manifest.txt" <<'EOF'
CheeseWAF release artifacts
prerelease_tag: Alpha-0.1.0-test.1-abc123
file_suffix: test
commit: abc123
EOF
  printf 'archive\n' >"${dir}/cheesewaf-amd64-linux-test.tar.gz"
}

verify_sums() {
  local dir="$1"
  (
    cd "$dir"
    if command -v sha256sum >/dev/null 2>&1; then
      sha256sum -c SHA256SUMS
    else
      shasum -a 256 -c SHA256SUMS
    fi
  ) >/dev/null
}

run_publish() {
  local dir="$1"
  local mode="$2"
  local log="$3"
  local remote_dir="${4:-${dir}}"
  local new_release="${5:-0}"
  PATH="${fake_bin}:${PATH}" \
    FAKE_RELEASE_DIR="$dir" \
    FAKE_REMOTE_DIR="$remote_dir" \
    FAKE_SYFT_ARTIFACT_MODE="$mode" \
    FAKE_GH_STABLE_NEW="$new_release" \
    FAKE_REMOTE_REF_TYPE="${FAKE_REMOTE_REF_TYPE:-commit}" \
    FAKE_REMOTE_REF_SHA="${FAKE_REMOTE_REF_SHA:-$stable_commit}" \
    FAKE_GH_LOG="$log" \
    FAKE_COSIGN_LOG="${log}.cosign" \
    bash scripts/ci/publish-prerelease.sh "$dir"
}

run_stable_publish() {
  local dir="$1"
  local log="$2"
  PATH="${fake_bin}:${PATH}" \
    FAKE_RELEASE_DIR="$dir" \
    FAKE_REMOTE_DIR="$dir" \
    FAKE_SYFT_ARTIFACT_MODE=success \
    FAKE_GH_STABLE_NEW=1 \
    FAKE_REMOTE_REF_TYPE=tag \
    FAKE_REMOTE_REF_SHA="$stable_tag_object" \
    FAKE_REMOTE_TAG_OBJECT_TYPE=commit \
    FAKE_REMOTE_TAG_OBJECT_SHA="$stable_commit" \
    FAKE_GH_LOG="$log" \
    FAKE_COSIGN_LOG="${log}.cosign" \
    bash scripts/ci/publish-release.sh "$dir"
}

mismatch_dir="${tmp}/mismatch"
mismatch_remote_dir="${tmp}/mismatch-remote"
mismatch_log="${tmp}/mismatch-gh.log"
make_release "$mismatch_dir"
mkdir -p "$mismatch_remote_dir"
printf 'remote stale archive\n' >"${mismatch_remote_dir}/cheesewaf-amd64-linux-test.tar.gz"
if run_publish "$mismatch_dir" success "$mismatch_log" "$mismatch_remote_dir"; then
  fail "publish must reject an existing asset whose remote SHA-256 differs"
fi
grep -Fq 'release download' "$mismatch_log" ||
  fail "publish must download existing assets before accepting them"

fallback_dir="${tmp}/fallback"
fallback_log="${tmp}/fallback-gh.log"
make_release "$fallback_dir"
printf 'stale product\n' >"${fallback_dir}/cheesewaf-artifacts.cdx.json"
printf 'stale bundle\n' >"${fallback_dir}/cheesewaf-artifacts.cdx.json.bundle"
printf 'stale fallback\n' >"${fallback_dir}/artifacts.manifest.json"
printf 'stale fallback bundle\n' >"${fallback_dir}/artifacts.manifest.json.bundle"
run_publish "$fallback_dir" fail "$fallback_log"
[[ -s "${fallback_dir}/artifacts.manifest.json" ]] ||
  fail "fallback publish must generate artifacts.manifest.json"
[[ -s "${fallback_dir}/artifacts.manifest.json.bundle" ]] ||
  fail "fallback artifact manifest must be signed"
[[ ! -e "${fallback_dir}/cheesewaf-artifacts.cdx.json" ]] ||
  fail "failed artifact scan must not retain a stale product SBOM"
[[ ! -e "${fallback_dir}/cheesewaf-artifacts.cdx.json.bundle" ]] ||
  fail "failed artifact scan must not retain a stale product SBOM bundle"
grep -Fq 'artifacts.manifest.json' "${fallback_dir}/SHA256SUMS" ||
  fail "fallback artifact manifest must be present in the final checksums"
verify_sums "$fallback_dir"

success_dir="${tmp}/success"
success_log="${tmp}/success-gh.log"
make_release "$success_dir"
printf 'stale fallback\n' >"${success_dir}/artifacts.manifest.json"
printf 'stale fallback bundle\n' >"${success_dir}/artifacts.manifest.json.bundle"
run_publish "$success_dir" success "$success_log"
[[ -s "${success_dir}/cheesewaf-artifacts.cdx.json" ]] ||
  fail "successful artifact scan must generate the product SBOM"
[[ -s "${success_dir}/cheesewaf-artifacts.cdx.json.bundle" ]] ||
  fail "product SBOM must be signed"
[[ ! -e "${success_dir}/artifacts.manifest.json" ]] ||
  fail "successful artifact scan must remove a stale fallback manifest"
[[ ! -e "${success_dir}/artifacts.manifest.json.bundle" ]] ||
  fail "successful artifact scan must remove a stale fallback bundle"
grep -Fq 'cheesewaf-artifacts.cdx.json' "${success_dir}/SHA256SUMS" ||
  fail "product SBOM must be present in the final checksums"
verify_sums "$success_dir"

stable_dir="${tmp}/stable"
stable_log="${tmp}/stable-gh.log"
stable_pkg="${tmp}/stable-pkg/cheesewaf"
mkdir -p "$stable_dir"
mkdir -p "${stable_pkg}/web/dist" "${stable_pkg}/configs" "${stable_pkg}/systemd"
printf '<html></html>\n' >"${stable_pkg}/web/dist/index.html"
printf 'listen: 127.0.0.1:8080\n' >"${stable_pkg}/configs/cheesewaf.yaml"
printf 'version=0.3.9\nchannel=stable\nbranch=stable\ncommit=%s\nbuild_time=2026-09-12T00:00:00Z\n' \
  "$stable_commit" >"${stable_pkg}/VERSION"
printf '{"name":"CheeseWAF","version":"0.3.9","channel":"stable","branch":"stable","commit":"%s"}\n' \
  "$stable_commit" >"${stable_pkg}/release.json"
printf '[Service]\nExecStart=/usr/local/bin/cheesewaf serve\n' >"${stable_pkg}/systemd/cheesewaf.service"
: >"${stable_pkg}/cheesewaf"
: >"${stable_pkg}/waf-cli"
chmod +x "${stable_pkg}/cheesewaf" "${stable_pkg}/waf-cli"
printf 'CheeseWAF release artifacts\nversion: 0.3.9\nrelease_tag: v0.3.9\nrelease_kind: stable\nfile_suffix: stable\ncommit: %s\n' \
  "$stable_commit" >"${stable_dir}/release-manifest.txt"
tar -C "${tmp}/stable-pkg" -czf "${stable_dir}/cheesewaf-amd64-linux-0.3.9.tar.gz" cheesewaf
tar -C "${tmp}/stable-pkg" -czf "${stable_dir}/cheesewaf-arm64-linux-0.3.9.tar.gz" cheesewaf
tar -C "${tmp}/stable-pkg" -czf "${stable_dir}/cheesewaf-loong64-linux-0.3.9.tar.gz" cheesewaf
run_stable_publish "$stable_dir" "$stable_log"
grep -Fq 'release create v0.3.9' "$stable_log" ||
  fail "stable publish must create the version tag release"
grep -Fq -- '--verify-tag' "$stable_log" ||
  fail "stable publish must refuse to create a missing tag"
grep -Fq "api repos/LaokeQwQ/CheeseWAF/git/tags/${stable_tag_object}" "$stable_log" ||
  fail "stable publish must peel an annotated remote tag"
grep -Fq '| `cheesewaf-amd64-linux-0.3.9.tar.gz` | Linux x86_64 |' "${stable_log}.notes" ||
  fail "server-only stable notes must list the Linux archive"
if grep -Eq '\| `cheesewaf-.*(darwin|windows)|macOS|Windows' "${stable_log}.notes"; then
  fail "server-only stable notes must not list desktop artifacts"
fi
if grep -Fq -- '--prerelease' "$stable_log"; then
  fail "stable publish must not mark the release as a pre-release"
fi
grep -Fq -- "--certificate-identity https://github.com/LaokeQwQ/CheeseWAF/.github/workflows/ci.yml@refs/tags/v0.3.9" "${stable_log}.cosign" ||
  fail "stable Sigstore verification must bind the certificate identity to this exact tag"
grep -Fq -- "--certificate-identity 'https://github.com/LaokeQwQ/CheeseWAF/.github/workflows/ci.yml@refs/tags/v0.3.9'" "${stable_log}.notes" ||
  fail "stable release notes must publish the exact Sigstore identity constraint"
if grep -Fq -- '--certificate-identity-regexp' "${stable_log}.notes"; then
  fail "stable release notes must not accept another stable tag identity"
fi
if grep -Fq '${identity_value}' "${stable_log}.notes"; then
  fail "stable release notes must not contain an unexpanded identity placeholder"
fi

stable_notes_command="${tmp}/stable-notes-command.sh"
awk '/^```$/ { in_code = !in_code; next } in_code { print }' "${stable_log}.notes" >"$stable_notes_command"
(
  cd "$stable_dir"
  PATH="${fake_bin}:${PATH}" \
    FAKE_COSIGN_LOG="${stable_log}.notes.cosign" \
    bash "$stable_notes_command"
) || fail "the Sigstore command in stable release notes must execute as written"

stable_rerun_log="${tmp}/stable-rerun-gh.log"
run_publish "$stable_dir" success "$stable_rerun_log" "$stable_dir" 0
if grep -Eq 'release (create|upload|edit) v0\.3\.9' "$stable_rerun_log"; then
  fail "a verified stable rerun must not mutate an existing immutable release"
fi
if grep -Fq 'sign-blob ' "${stable_rerun_log}.cosign"; then
  fail "a verified stable rerun must not regenerate nondeterministic SBOM signatures"
fi
grep -Fq 'verify-blob ' "${stable_rerun_log}.cosign" ||
  fail "a verified stable rerun must verify the existing Sigstore bundles"

stable_missing_tag_log="${tmp}/stable-missing-tag-gh.log"
if PATH="${fake_bin}:${PATH}" \
  FAKE_RELEASE_DIR="$stable_dir" \
  FAKE_REMOTE_DIR="$stable_dir" \
  FAKE_SYFT_ARTIFACT_MODE=success \
  FAKE_GH_STABLE_NEW=1 \
  FAKE_REMOTE_TAG_MISSING=1 \
  FAKE_GH_LOG="$stable_missing_tag_log" \
  FAKE_COSIGN_LOG="${stable_missing_tag_log}.cosign" \
  bash scripts/ci/publish-release.sh "$stable_dir"; then
  fail "stable publish must reject a missing remote tag"
fi
if grep -Eq 'release (create|upload) v0\.3\.9' "$stable_missing_tag_log"; then
  fail "stable publish must reject a missing tag before mutating release assets"
fi

stable_moved_tag_log="${tmp}/stable-moved-tag-gh.log"
if PATH="${fake_bin}:${PATH}" \
  FAKE_RELEASE_DIR="$stable_dir" \
  FAKE_REMOTE_DIR="$stable_dir" \
  FAKE_SYFT_ARTIFACT_MODE=success \
  FAKE_GH_STABLE_NEW=1 \
  FAKE_REMOTE_REF_TYPE=commit \
  FAKE_REMOTE_REF_SHA=ffffffffffffffffffffffffffffffffffffffff \
  FAKE_GH_LOG="$stable_moved_tag_log" \
  FAKE_COSIGN_LOG="${stable_moved_tag_log}.cosign" \
  bash scripts/ci/publish-release.sh "$stable_dir"; then
  fail "stable publish must reject a remote tag moved away from the manifest commit"
fi
if grep -Eq 'release (create|upload) v0\.3\.9' "$stable_moved_tag_log"; then
  fail "stable publish must reject a moved tag before mutating release assets"
fi

partial_dir="${tmp}/partial"
partial_log="${tmp}/partial-gh.log"
make_release "$partial_dir"
printf 'disk image\n' >"${partial_dir}/cheesewaf-arm64-darwin-test.dmg"
printf 'installer\n' >"${partial_dir}/cheesewaf-amd64-windows-test-setup.exe"
run_publish "$partial_dir" success "$partial_log" "$partial_dir" 1
grep -Fq '| `cheesewaf-arm64-darwin-test.dmg` | macOS Apple Silicon disk image |' "${partial_log}.notes" ||
  fail "partial notes must list the disk image that actually exists"
grep -Fq '| `cheesewaf-amd64-windows-test-setup.exe` | Windows x86_64 GUI installer |' "${partial_log}.notes" ||
  fail "partial notes must list the installer that actually exists"
if grep -Fq 'cheesewaf-arm64-darwin-test.tar.gz' "${partial_log}.notes"; then
  fail "partial notes must not invent a macOS archive"
fi
if grep -Fq '| `cheesewaf-amd64-windows-test.exe` |' "${partial_log}.notes"; then
  fail "partial notes must not confuse an installer with the single-file CLI"
fi

stable_desktop_dir="${tmp}/stable-desktop"
stable_desktop_log="${tmp}/stable-desktop-gh.log"
cp -R "$stable_dir" "$stable_desktop_dir"
printf 'desktop\n' >"${stable_desktop_dir}/cheesewaf-amd64-windows-0.3.9.exe"
if run_stable_publish "$stable_desktop_dir" "$stable_desktop_log"; then
  fail "stable server publish must reject desktop artifacts"
fi

stable_unknown_dir="${tmp}/stable-unknown"
stable_unknown_log="${tmp}/stable-unknown-gh.log"
cp -R "$stable_dir" "$stable_unknown_dir"
printf 'unknown\n' >"${stable_unknown_dir}/cheesewaf-amd64-linux-0.3.9.deb"
if run_stable_publish "$stable_unknown_dir" "$stable_unknown_log"; then
  fail "stable server publish must reject unclassified top-level assets"
fi

stable_version_dir="${tmp}/stable-version"
stable_version_log="${tmp}/stable-version-gh.log"
cp -R "$stable_dir" "$stable_version_dir"
sed -i.bak 's/release_tag: v0.3.9/release_tag: v9.9.9/' "${stable_version_dir}/release-manifest.txt"
rm "${stable_version_dir}/release-manifest.txt.bak"
if PATH="${fake_bin}:${PATH}" \
  FAKE_RELEASE_DIR="$stable_version_dir" \
  FAKE_REMOTE_DIR="$stable_version_dir" \
  FAKE_SYFT_ARTIFACT_MODE=success \
  FAKE_GH_STABLE_NEW=1 \
  FAKE_REMOTE_REF_SHA="$stable_commit" \
  FAKE_GH_LOG="$stable_version_log" \
  FAKE_COSIGN_LOG="${stable_version_log}.cosign" \
  bash scripts/ci/publish-release.sh "$stable_version_dir"; then
  fail "stable publish must reject a tag that differs from product-version"
fi

stable_remote_extra_log="${tmp}/stable-remote-extra-gh.log"
if PATH="${fake_bin}:${PATH}" \
  FAKE_RELEASE_DIR="$stable_dir" \
  FAKE_REMOTE_DIR="$stable_dir" \
  FAKE_SYFT_ARTIFACT_MODE=success \
  FAKE_GH_STABLE_NEW=0 \
  FAKE_REMOTE_REF_SHA="$stable_commit" \
  FAKE_REMOTE_ASSETS=$'SHA256SUMS\ncheesewaf-amd64-linux-0.3.9.tar.gz\nlegacy-installer.msi' \
  FAKE_GH_LOG="$stable_remote_extra_log" \
  FAKE_COSIGN_LOG="${stable_remote_extra_log}.cosign" \
  bash scripts/ci/publish-release.sh "$stable_dir"; then
  fail "stable publish rerun must reject extra remote assets"
fi

stable_remote_target_log="${tmp}/stable-remote-target-gh.log"
if PATH="${fake_bin}:${PATH}" \
  FAKE_RELEASE_DIR="$stable_dir" \
  FAKE_REMOTE_DIR="$stable_dir" \
  FAKE_SYFT_ARTIFACT_MODE=success \
  FAKE_GH_STABLE_NEW=0 \
  FAKE_REMOTE_REF_SHA="$stable_commit" \
  FAKE_REMOTE_TARGET=deadbeef \
  FAKE_GH_LOG="$stable_remote_target_log" \
  FAKE_COSIGN_LOG="${stable_remote_target_log}.cosign" \
  bash scripts/ci/publish-release.sh "$stable_dir"; then
  fail "stable publish rerun must reject the wrong target commit"
fi

if grep -Fq -- '--clobber' "$fallback_log" "$success_log" "$stable_rerun_log"; then
  fail "publish regression test observed a mutable asset upload"
fi

echo "publish prerelease tests passed."
