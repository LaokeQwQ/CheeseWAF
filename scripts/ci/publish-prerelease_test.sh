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
if [[ "${1:-}" == "release" && "${2:-}" == "view" ]]; then
  if [[ "${FAKE_GH_STABLE_NEW:-0}" == "1" ]]; then
    exit 1
  fi
  for arg in "$@"; do
    if [[ "$arg" == "--json" ]]; then
      find "$FAKE_RELEASE_DIR" -maxdepth 1 -type f -exec basename {} \; | sort
      break
    fi
  done
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
  PATH="${fake_bin}:${PATH}" \
    FAKE_RELEASE_DIR="$dir" \
    FAKE_REMOTE_DIR="$remote_dir" \
    FAKE_SYFT_ARTIFACT_MODE="$mode" \
    FAKE_GH_LOG="$log" \
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
    FAKE_GH_LOG="$log" \
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
mkdir -p "$stable_dir"
cat >"${stable_dir}/release-manifest.txt" <<'EOF'
CheeseWAF release artifacts
release_tag: v1.2.3
release_kind: stable
file_suffix: stable
commit: abc123
EOF
printf 'archive\n' >"${stable_dir}/cheesewaf-amd64-linux-stable.tar.gz"
run_stable_publish "$stable_dir" "$stable_log"
grep -Fq 'release create v1.2.3' "$stable_log" ||
  fail "stable publish must create the version tag release"
if grep -Fq -- '--prerelease' "$stable_log"; then
  fail "stable publish must not mark the release as a pre-release"
fi

if grep -Fq -- '--clobber' "$fallback_log" "$success_log"; then
  fail "publish regression test observed a mutable asset upload"
fi

echo "publish prerelease tests passed."
