#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
test_root="$(mktemp -d)"
trap 'rm -rf "$test_root"' EXIT
fail() { echo "::error::$*" >&2; exit 1; }

# Exercise the real bootstrap, filesystem extraction, and SHA256 verifier.
# Only network responses, host/root detection, and cosign are stubbed.
tool_bin="${test_root}/bin"
mkdir -p "$tool_bin"
for tool in bash tar gzip sha256sum mktemp rm awk tr grep sed chmod cp cat; do
  tool_path="$(command -v "$tool")"
  [[ -n "$tool_path" ]] || fail "test requires ${tool}"
  ln -s "$tool_path" "${tool_bin}/${tool}"
done

uname() { if [[ "$1" == -s ]]; then printf 'Linux\n'; else printf '%s\n' "$BOOTSTRAP_ARCH"; fi; }
id() { printf '0\n'; }
bootstrap_fetch() {
  local downloader="$1" destination="$2" url="$3" name="${3##*/}"
  printf '%s %s\n' "$downloader" "$url" >>"${BOOTSTRAP_CASE}/requests"
  case "$url" in
    https://ota.cheesesec.com/v1/software/channels/stable/index.json|https://api.github.com/repos/*/releases/latest)
      if [[ "$url" == https://ota.cheesesec.com/* ]]; then
        case "$BOOTSTRAP_SCENARIO" in
          all_fallback|metadata_fallback) printf 'partial' >"$destination"; return 22 ;;
          bad_metadata) printf '<html>not JSON</html>' >"$destination"; return 0 ;;
          bad_tag) printf '{"tag_name":"../../evil"}' >"$destination"; return 0 ;;
          duplicate_tag) printf '{"tag_name":"v0.4.5","tag_name":"v0.4.6"}' >"$destination"; return 0 ;;
        esac
      fi
      printf '{"api_version":"ota.cheesesec.com/software/v1","channel":"stable","tag_name":"%s"}\n' "$BOOTSTRAP_TAG" >"$destination"
      return 0 ;;
    https://res.cheesesec.com/releases/*|https://res.cheesesec.com/redirected/*|https://github.com/*/releases/download/*|https://cdn.cheesesec.example/*) ;;
    *) fail "unexpected network URL: ${url}" ;;
  esac
  if [[ "$url" == https://res.cheesesec.com/releases/* ]]; then
    case "$BOOTSTRAP_SCENARIO:$name" in
      all_fallback:*|wget_fallback:*|archive_fallback:*.tar.gz|sum_fallback:SHA256SUMS|bundle_fallback:SHA256SUMS.bundle|missing_bundle:SHA256SUMS.bundle)
        printf 'partial download' >"$destination"; return 22 ;;
      wget_redirect:*.tar.gz|wget_relative_redirect:*.tar.gz|wget_downgrade:*.tar.gz|wget_redirect_loop:*.tar.gz)
        printf '  HTTP/1.1 302 Found\r\n' >&2
        case "$BOOTSTRAP_SCENARIO" in
          wget_redirect)
            printf '  Location: https://cdn.cheesesec.example/%s\r\n' "$name" >&2
            printf 'Location: https://cdn.cheesesec.example/%s [following]\n0 redirections exceeded.\n' "$name" >&2 ;;
          wget_relative_redirect)
            printf '  Location: /redirected/%s\r\n' "$name" >&2
            printf 'Location: /redirected/%s [following]\n0 redirections exceeded.\n' "$name" >&2 ;;
          wget_downgrade) printf '  Location: http://insecure.example/%s\r\n' "$name" >&2 ;;
          wget_redirect_loop) printf '  Location: %s\r\n' "$url" >&2 ;;
        esac
        return 8 ;;
    esac
  fi
  if [[ "$BOOTSTRAP_SCENARIO:$name" == missing_bundle:SHA256SUMS.bundle ]]; then return 22; fi
  if [[ "$name" == SHA256SUMS ]]; then
    case "$BOOTSTRAP_SCENARIO" in
      bad_checksum) printf '%064d  %s\n' 0 "$BOOTSTRAP_ASSET" >"$destination" ;;
      missing_checksum) printf '%064d  other.tar.gz\n' 0 >"$destination" ;;
      duplicate_checksum) command cp "${BOOTSTRAP_CASE}/SHA256SUMS" "$destination"; command cat "${BOOTSTRAP_CASE}/SHA256SUMS" >>"$destination" ;;
      *) command cp "${BOOTSTRAP_CASE}/SHA256SUMS" "$destination" ;;
    esac
  elif [[ "$name" == SHA256SUMS.bundle ]]; then
    printf 'test bundle\n' >"$destination"
  else
    [[ "$url" == *"/${BOOTSTRAP_TAG}/${BOOTSTRAP_ASSET}" || "$url" == "https://cdn.cheesesec.example/${BOOTSTRAP_ASSET}" || "$url" == "https://res.cheesesec.com/redirected/${BOOTSTRAP_ASSET}" ]] || fail 'download changed the requested release'
    command cp "${BOOTSTRAP_CASE}/${BOOTSTRAP_ASSET}" "$destination"
  fi
}
curl() {
  local destination='' url='' previous='' arg
  [[ "$*" == *"--proto =https --proto-redir =https"* ]] || fail 'curl must restrict redirect protocols'
  [[ "$1" == --disable ]] || fail 'curl must ignore ambient curl configuration'
  for arg in "$@"; do
    if [[ "$previous" == -o ]]; then destination="$arg"; fi
    [[ "$arg" != https://* ]] || url="$arg"
    previous="$arg"
  done
  bootstrap_fetch curl "$destination" "$url"
}
wget() {
  local destination='' url='' previous='' arg
  [[ "$*" == *"--max-redirect=0"* && "$*" == *"--no-config"* ]] || fail 'wget must disable automatic redirects and ambient configuration'
  for arg in "$@"; do
    if [[ "$previous" == -O ]]; then destination="$arg"; fi
    [[ "$arg" != https://* ]] || url="$arg"
    previous="$arg"
  done
  bootstrap_fetch wget "$destination" "$url"
}
cosign() {
  printf '%s\n' "$*" >>"${BOOTSTRAP_CASE}/cosign"
  [[ "$*" == *"--certificate-identity https://github.com/${CHEESEWAF_REPO}/.github/workflows/ci.yml@refs/tags/${BOOTSTRAP_TAG}"* ]] || fail 'signature identity must pin the exact repo, workflow, and tag'
  [[ "$*" == *"--certificate-oidc-issuer https://token.actions.githubusercontent.com"* ]] || fail 'signature issuer must remain pinned'
  [[ "$BOOTSTRAP_SCENARIO" != bad_signature ]]
}
export -f fail uname id bootstrap_fetch

for scenario in official all_fallback metadata_fallback archive_fallback sum_fallback \
  explicit explicit_prerelease fork arm64 loong64 bundle_fallback bad_checksum \
  missing_checksum duplicate_checksum bad_metadata bad_tag duplicate_tag \
  bad_signature missing_cosign missing_bundle official_default unsafe_root symlink hardlink missing_installer \
  corrupt_archive wget_official wget_fallback wget_redirect wget_relative_redirect wget_downgrade wget_redirect_loop no_downloader; do
  export BOOTSTRAP_SCENARIO="$scenario" BOOTSTRAP_CASE="${test_root}/${scenario}"
  export BOOTSTRAP_ARCH=x86_64 BOOTSTRAP_TAG=v0.4.5
  export CHEESEWAF_REPO=LaokeQwQ/CheeseWAF CHEESEWAF_RELEASE=latest CHEESEWAF_LANG=en CHEESEWAF_VERIFY_SIGNATURE=0
  package_arch=amd64
  case "$scenario" in
    official_default) unset CHEESEWAF_VERIFY_SIGNATURE ;;
    explicit) export CHEESEWAF_RELEASE=0.4.5 ;;
    explicit_prerelease) export CHEESEWAF_RELEASE=v0.4.5-beta BOOTSTRAP_TAG=v0.4.5-beta ;;
    fork) export CHEESEWAF_REPO=Example/Fork ;;
    arm64) export BOOTSTRAP_ARCH=aarch64; package_arch=arm64 ;;
    loong64) export BOOTSTRAP_ARCH=loongarch64; package_arch=loong64 ;;
    bundle_fallback|bad_signature|missing_cosign|missing_bundle) export CHEESEWAF_VERIFY_SIGNATURE=1 ;;
  esac
  export BOOTSTRAP_ASSET="cheesewaf-${package_arch}-linux-${BOOTSTRAP_TAG#v}.tar.gz"
  package_root="${BOOTSTRAP_CASE}/cheesewaf-${package_arch}-linux-${BOOTSTRAP_TAG#v}"
  mkdir -p "$package_root"
  printf '#!/usr/bin/env bash\nprintf "%%s\\n" "$CHEESEWAF_RELEASE_VERSION" >"${BOOTSTRAP_CASE}/installed"\n' >"${package_root}/install-linux.sh"
  chmod +x "${package_root}/install-linux.sh"
  case "$scenario" in
    unsafe_root) package_root="${BOOTSTRAP_CASE}/other-root"; mkdir -p "$package_root" ;;
    symlink) ln -s install-linux.sh "${package_root}/link" ;;
    hardlink) ln "${package_root}/install-linux.sh" "${package_root}/link" ;;
    missing_installer) rm "${package_root}/install-linux.sh" ;;
  esac
  tar -czf "${BOOTSTRAP_CASE}/${BOOTSTRAP_ASSET}" -C "$BOOTSTRAP_CASE" "${package_root##*/}"
  if [[ "$scenario" == corrupt_archive ]]; then printf 'not gzip\n' >"${BOOTSTRAP_CASE}/${BOOTSTRAP_ASSET}"; fi
  (cd "$BOOTSTRAP_CASE" && sha256sum "$BOOTSTRAP_ASSET") >"${BOOTSTRAP_CASE}/SHA256SUMS"
  status=0
  (
    # Isolated PATH prevents an unstubbed downloader from reaching the network.
    export PATH="$tool_bin"
    case "$scenario" in
      wget_*) unset -f curl; export -f wget ;;
      no_downloader) unset -f curl wget ;;
      *) unset -f wget; export -f curl ;;
    esac
    case "$scenario" in missing_cosign) unset -f cosign ;; *) export -f cosign ;; esac
    bash "${repo_root}/scripts/install-linux.sh"
  ) >"${BOOTSTRAP_CASE}/output" 2>&1 || status=$?
  case "$scenario" in
    official_default) [[ -s "${BOOTSTRAP_CASE}/cosign" ]] || fail 'official install skipped signature verification by default' ;;
  esac
  case "$scenario" in
    bad_*|missing_*|duplicate_*|unsafe_root|symlink|hardlink|corrupt_archive|wget_downgrade|no_downloader)
      ((status != 0)) || fail "${scenario} should fail"
      [[ ! -e "${BOOTSTRAP_CASE}/installed" ]] || fail "${scenario} ran release code"
      case "$scenario" in no_downloader) ;; *)
        ! grep -q 'https://github.com/' "${BOOTSTRAP_CASE}/requests" || { [[ "$scenario" == missing_bundle ]] || fail "${scenario} bypassed a validation failure via GitHub"; } ;;
      esac
      ;;
    *)
      if ((status != 0)); then cat "${BOOTSTRAP_CASE}/output"; fail "${scenario} failed"; fi
      [[ "$(cat "${BOOTSTRAP_CASE}/installed")" == "${BOOTSTRAP_TAG#v}" ]] || fail "${scenario} installed the wrong release"
      ;;
  esac
  case "$scenario" in
    official|arm64|loong64|wget_official|wget_relative_redirect)
      ! grep -q 'https://github.com/\|https://api.github.com/' "${BOOTSTRAP_CASE}/requests" || fail "${scenario} should use only official sources" ;;
    all_fallback|metadata_fallback|archive_fallback|sum_fallback|bundle_fallback|wget_fallback|wget_redirect_loop)
      grep -q 'https://.*github.com/' "${BOOTSTRAP_CASE}/requests" || fail "${scenario} did not fall back to GitHub" ;;
    fork)
      ! grep -q 'cheesesec.com' "${BOOTSTRAP_CASE}/requests" || fail 'fork override contacted the official repository'
      grep -q 'https://github.com/Example/Fork/releases/download/v0.4.5/' "${BOOTSTRAP_CASE}/requests" || fail 'fork override was ignored' ;;
    explicit*)
      ! grep -q 'index.json\|api.github.com' "${BOOTSTRAP_CASE}/requests" || fail 'explicit version should not query latest metadata' ;;
    wget_redirect)
      ! grep -q 'https://github.com/\|https://api.github.com/' "${BOOTSTRAP_CASE}/requests" || fail 'wget redirect should stay on official sources'
      grep -q 'https://cdn.cheesesec.example/' "${BOOTSTRAP_CASE}/requests" || fail 'wget did not follow HTTPS redirect' ;;
  esac
  printf 'Bootstrap source test passed: %s\n' "$scenario"
done
