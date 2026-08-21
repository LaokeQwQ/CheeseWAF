#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$repo_root"

# shellcheck disable=SC1091
source scripts/ci/tool-versions.env

fail() {
  echo "::error::$*"
  exit 1
}

workflow_files=(
  .github/workflows/ci.yml
  .forgejo/workflows/ci.yml
)

for workflow in "${workflow_files[@]}"; do
  [[ -r "$workflow" ]] || fail "missing workflow: ${workflow}"
  grep -Fq 'PR_BASE_REF: ${{ github.base_ref }}' "$workflow" ||
    fail "${workflow} must pass the PR base ref through env"
  grep -Fq 'PR_HEAD_REF: ${{ github.head_ref }}' "$workflow" ||
    fail "${workflow} must pass the PR head ref through env"
  grep -Fq 'base="${PR_BASE_REF}"' "$workflow" ||
    fail "${workflow} must quote PR_BASE_REF in shell"
  grep -Fq 'head="${PR_HEAD_REF}"' "$workflow" ||
    fail "${workflow} must quote PR_HEAD_REF in shell"

  if grep -nE '^[[:space:]]*(base|head)=.*\$\{\{[[:space:]]*github\.(base_ref|head_ref)' "$workflow"; then
    fail "${workflow} directly interpolates untrusted PR refs into shell"
  fi
  if grep -nE '@latest|latest-v[0-9]+' "$workflow"; then
    fail "${workflow} contains a floating tool version"
  fi
  grep -Fq "govulncheck@${GOVULNCHECK_VERSION}" "$workflow" ||
    fail "${workflow} does not pin govulncheck ${GOVULNCHECK_VERSION}"
  grep -Fq "actionlint@${ACTIONLINT_VERSION}" "$workflow" ||
    fail "${workflow} does not pin actionlint ${ACTIONLINT_VERSION}"
  grep -Fq 'bash scripts/ci/verify-go-quality.sh format' "$workflow" ||
    fail "${workflow} does not enforce gofmt"
  grep -Fq 'bash scripts/ci/verify-go-quality.sh vet' "$workflow" ||
    fail "${workflow} does not enforce go vet"
  grep -Fq 'bash scripts/ci/verify-go-quality.sh coverage' "$workflow" ||
    fail "${workflow} does not enforce Go coverage"
  grep -Fq 'npm install --no-save --package-lock=false --ignore-scripts @vitest/coverage-v8@4.1.10' "$workflow" ||
    fail "${workflow} does not pin the Vitest coverage provider"
  grep -Fq 'npm test -- --coverage' "$workflow" ||
    fail "${workflow} does not execute project tests with coverage"
  grep -Fq 'test -s coverage/coverage-summary.json' "$workflow" ||
    fail "${workflow} does not fail closed when coverage output is missing"
  grep -Fq 'npm run typecheck' "$workflow" ||
    fail "${workflow} does not typecheck the dashboard"
  grep -Fq 'npm run build' "$workflow" ||
    fail "${workflow} does not build the dashboard"
done

grep -Fq "node-version: ${NODE_VERSION}" .github/workflows/ci.yml ||
  fail "GitHub Actions must pin Node ${NODE_VERSION}"

mod_go_version="$(awk '$1 == "go" { print $2; exit }' go.mod)"
[[ "$mod_go_version" == "$GO_VERSION" ]] ||
  fail "go.mod and tool-versions.env disagree"

for archive in \
  "go${GO_VERSION}.linux-amd64.tar.gz" \
  "go${GO_VERSION}.linux-arm64.tar.gz" \
  "node-v${NODE_VERSION}-linux-x64.tar.xz" \
  "node-v${NODE_VERSION}-linux-arm64.tar.xz"; do
  checksum="$(awk -v file="$archive" '$2 == file { print $1; exit }' scripts/ci/tool-checksums.txt)"
  [[ "$checksum" =~ ^[0-9a-f]{64}$ ]] ||
    fail "missing authoritative checksum for ${archive}"
done

grep -Fq 'node-v${NODE_VERSION}-linux-${nodearch}.tar.xz' scripts/ci/setup-node-mirror.sh ||
  fail "Node mirror setup must use the pinned version"
grep -Fq 'go${GO_VERSION}.linux-${goarch}.tar.gz' scripts/ci/setup-go-mirror.sh ||
  fail "Go mirror setup must use the pinned version"

[[ "$(head -n 1 .dockerignore)" == "**" ]] ||
  fail ".dockerignore must default-deny the build context"
if grep -Eq 'COPY[[:space:]]+\.[[:space:]]+\.' deploy/docker/Dockerfile; then
  fail "Dockerfile must not copy the full repository"
fi
grep -Eq '^ARG GO_IMAGE=.*@sha256:[0-9a-f]{64}$' deploy/docker/Dockerfile ||
  fail "Go base image must be digest-pinned"
grep -Eq '^ARG NODE_IMAGE=.*@sha256:[0-9a-f]{64}$' deploy/docker/Dockerfile ||
  fail "Node base image must be digest-pinned"
grep -Eq '^ARG RUNTIME_IMAGE=.*@sha256:[0-9a-f]{64}$' deploy/docker/Dockerfile ||
  fail "runtime base image must be digest-pinned"
grep -Fq 'USER cheesewaf' deploy/docker/Dockerfile ||
  fail "runtime container must be non-root"
grep -Fq 'WORKDIR /var/lib/cheesewaf' deploy/docker/Dockerfile ||
  fail "runtime container must use its writable data directory as WORKDIR"
grep -Fq 'admin_listen: "0.0.0.0:9443"' deploy/docker/Dockerfile ||
  fail "container admin listener must be reachable through an explicitly published port"
grep -Fq -- '--read-only' scripts/ci/docker-build.sh ||
  fail "container smoke must use a read-only root filesystem"
grep -Fq -- '--cap-drop ALL' scripts/ci/docker-build.sh ||
  fail "container smoke must drop Linux capabilities"
grep -Fq 'uid=${cheesewaf_uid},gid=${cheesewaf_gid}' scripts/ci/docker-build.sh ||
  fail "container smoke tmpfs must be owned by the non-root runtime UID/GID"
grep -Fq 'CHEESEWAF_UID=10001' deploy/docker/Dockerfile ||
  fail "runtime image must pin CHEESEWAF_UID=10001 for tmpfs ownership"
grep -Fq 'JavaScript asset returned unexpected MIME type' scripts/ci/docker-build.sh ||
  fail "container smoke must verify static asset MIME"
grep -Fq 'CHEESEWAF_SETUP_TOKEN' scripts/ci/docker-build.sh ||
  fail "container smoke must pin CHEESEWAF_SETUP_TOKEN"
grep -Fq 'X-CheeseWAF-Setup-Token' scripts/ci/docker-build.sh ||
  fail "container smoke must send the setup token header"

if grep -Fq 'internal/cli.appVersion' .goreleaser.yaml; then
  fail "GoReleaser still targets removed internal/cli version variables"
fi
for variable in Version Commit BuildTime Channel; do
  grep -Fq "internal/version.${variable}" .goreleaser.yaml ||
    fail "GoReleaser does not inject internal/version.${variable}"
done
grep -Fq 'web/dist/**/*' .goreleaser.yaml ||
  fail "GoReleaser archive must distribute the built UI"
grep -Fq 'web/dist/index.html' .goreleaser.yaml ||
  fail "GoReleaser archive must include the UI entrypoint"
grep -Fq 'cp -R web/dist "${package_root}/web/dist"' scripts/ci/package-release.sh ||
  fail "branch release packages must distribute UI under web/dist"
grep -Fq 'linux/loong64' scripts/ci/package-release.sh ||
  fail "branch release packages must include linux/loong64"
grep -Fq 'systemd/cheesewaf.service' scripts/ci/package-release.sh ||
  fail "Linux packages must include the systemd unit"
grep -Fq 'zip -qr' scripts/ci/package-release.sh ||
  fail "Windows channel packages must be zip archives"
grep -Fq '${package_name}.exe' scripts/ci/package-release.sh ||
  fail "Windows channel packages must include a single-file CLI exe"
grep -Fq 'cheesewaf-${goarch}-${goos}-${version_prefix}' scripts/ci/package-release.sh ||
  fail "branch packages must use cheesewaf-{arch}-{os}-{version}-{suffix} names"
grep -Fq 'hdiutil create' scripts/ci/package-macos-dmg.sh ||
  fail "macOS packaging must create UDZO disk images"
grep -Fq 'CheeseWAF.app' scripts/ci/package-macos-dmg.sh ||
  fail "macOS DMG must ship a CheeseWAF.app bundle"
grep -Fq '/Applications' scripts/ci/package-macos-dmg.sh ||
  fail "macOS DMG must include an Applications drop target"
grep -Fq 'CODESIGN_IDENTITY' scripts/ci/package-macos-dmg.sh ||
  fail "macOS packaging must select a Developer ID when available"
grep -Fq 'timestamp=none' scripts/ci/package-macos-dmg.sh ||
  fail "macOS packaging must keep ad-hoc signing as the fallback without a Developer ID"
grep -Fq 'notarize_dmg' scripts/ci/package-macos-dmg.sh ||
  fail "macOS packaging must notarize when Apple API credentials are present"
grep -Fq 'scripts/ci/sign-windows.sh' scripts/ci/package-release.sh ||
  fail "Windows packages must Authenticode-sign when WINDOWS_CERT_P12 is present"
grep -Fq 'APP_BUNDLE_VERSION' deploy/macos/Info.plist ||
  fail "macOS Info.plist must keep a numeric CFBundleVersion placeholder"
got_ver="$(bash scripts/ci/package-macos-dmg.sh --print-bundle-version '0.1.0-PreTest')"
[[ "$got_ver" == "0.1.0" ]] ||
  fail "macOS CFBundleVersion must strip PreTest labels (got ${got_ver})"
grep -Fq 'package-macos-dmg.sh' .github/workflows/ci.yml ||
  fail "CI must build macOS DMG images on a macOS runner"
grep -Fq 'Alpha-' scripts/ci/package-release.sh ||
  fail "pre-release tags must use the Alpha- prefix"
grep -Fq 'scripts/ci/publish-prerelease.sh' .github/workflows/ci.yml ||
  fail "CI must publish Alpha- GitHub pre-releases"
grep -Fq 'linux/amd64,linux/arm64' scripts/ci/docker-build.sh ||
  fail "container CI must build linux/amd64 and linux/arm64"
grep -Fq 'dst: systemd/cheesewaf.service' .goreleaser.yaml ||
  fail "GoReleaser archive must include the systemd unit"
grep -Fq 'install-linux.sh' scripts/ci/package-release.sh ||
  fail "Linux channel packages must ship install-linux.sh"
grep -Fq 'dst: install-linux.sh' .goreleaser.yaml ||
  fail "GoReleaser archive must include install-linux.sh"
grep -Fq 'cheesewaf serve --config' internal/cluster/deploy/ansible.go ||
  fail "Ansible unit must start cheesewaf serve"
grep -Fq 'internal/webui/dist' scripts/ci/build-web.sh ||
  fail "web build must copy UI files into the embedded dist directory"
grep -Fq 'WorkingDirectory=/var/lib/cheesewaf' deploy/systemd/cheesewaf.service ||
  fail "systemd unit must set WorkingDirectory so relative data paths stay under /var/lib/cheesewaf"
grep -Fq 'CHEESEWAF_WEB_DIR=/usr/share/cheesewaf/web' deploy/systemd/cheesewaf.service ||
  fail "systemd unit must point CHEESEWAF_WEB_DIR at the FHS UI path"
grep -Fq 'func applyCLIDataDir' internal/cli/datadir.go ||
  fail "serve must rebase packaged relative ./data paths onto --data-dir"
grep -Fq 'Secure:   middleware.CookieSecure(r)' internal/cli/service.go ||
  fail "admin entry cookies must follow request TLS like session cookies"
if grep -Fq 'ExecReload=' deploy/systemd/cheesewaf.service; then
  fail "systemd must not advertise SIGHUP reload; the process ignores hangup"
fi
grep -Fq 'rewrite_checksums' scripts/ci/publish-prerelease.sh ||
  fail "publish must rebuild SHA256SUMS after macOS DMG files land"
grep -Fq 'github.ref_name == '\''canary'\''' .github/workflows/ci.yml ||
  fail "publish-prerelease must stay limited to canary and master"
grep -Fq 'id-token: write' .github/workflows/ci.yml ||
  fail "publish-prerelease must request an OIDC token for keyless cosign"
grep -Fq 'sigstore/cosign-installer@' .github/workflows/ci.yml ||
  fail "publish-prerelease must install a pinned cosign"
grep -Fq "cosign-release: ${COSIGN_VERSION}" .github/workflows/ci.yml ||
  fail "publish-prerelease must pin cosign ${COSIGN_VERSION}"
grep -Fq 'scripts/ci/install-syft.sh' .github/workflows/ci.yml ||
  fail "publish-prerelease must install a checksum-pinned syft"
grep -Fq "syft_${SYFT_VERSION#v}_linux_amd64.tar.gz" scripts/ci/tool-checksums.txt ||
  fail "syft ${SYFT_VERSION} linux-amd64 checksum is missing"
grep -Fq 'cyclonedx-json' scripts/ci/publish-prerelease.sh ||
  fail "publish must attach a CycloneDX SBOM"
grep -Fq 'cosign sign-blob' scripts/ci/publish-prerelease.sh ||
  fail "publish must sign SHA256SUMS with cosign"
codeql_file=".github/workflows/codeql.yml"
[[ -r "$codeql_file" ]] || fail "missing ${codeql_file}"
init_sha="$(awk '/uses: github\/codeql-action\/init@/ { n=split($2, a, "@"); print a[n] }' "$codeql_file" | sort -u)"
analyze_sha="$(awk '/uses: github\/codeql-action\/analyze@/ { n=split($2, a, "@"); print a[n] }' "$codeql_file" | sort -u)"
if [[ -z "$init_sha" || "$init_sha" != "$analyze_sha" || "$init_sha" == *$'\n'* ]]; then
  fail "CodeQL init and analyze must share a single action SHA (init=${init_sha} analyze=${analyze_sha})"
fi
grep -Fq '"maplibre-gl": "^6.' web/package.json ||
  fail "dashboard maplibre-gl must track 6.x after the ESM migration"
grep -Fq 'func writeChallengeCookie' internal/protection/bot/policy.go ||
  fail "bot challenge cookies must go through writeChallengeCookie"
grep -Fq 'cookie.Secure = cookieSecure(r)' internal/protection/bot/policy.go ||
  fail "writeChallengeCookie must apply cookieSecure"
if grep -nE 'http\.SetCookie' internal/protection/bot/policy.go; then
  fail "bot cookies must not call http.SetCookie directly"
fi
if grep -nE 'Secure:[[:space:]]*(true|secure)' internal/protection/bot/policy.go; then
  fail "bot cookies must not hard-code Secure or take a caller bool"
fi
grep -Fq 'scripts/ci/channel-from-git.sh' Makefile ||
  fail "Makefile CHANNEL must not embed a case statement with closing parens"
grep -Fq 'npm ci --no-audit --no-fund --ignore-scripts' Makefile ||
  fail "make web-build must skip agent-eyes postinstall"
if grep -Fq 'id: cheesewaf-gui' .goreleaser.yaml; then
  fail "GoReleaser archives must keep one binary per platform; channel packages ship cheesewaf-gui"
fi
grep -Fq 'cp -R "${repo_root}/web/scripts" "${work_web}/scripts"' scripts/ci/build-web.sh ||
  fail "isolated web build must include build verification scripts"
grep -Fq 'scripts/ci/generate-release-metadata.sh' .goreleaser.yaml ||
  fail "GoReleaser must use the shared release metadata generator"
grep -Fq 'scripts/ci/generate-release-metadata.sh' scripts/ci/package-release.sh ||
  fail "branch packaging must use the shared release metadata generator"
grep -Fq 'name_template: "{{ .ProjectName }}-{{ .Arch }}-{{ .Os }}-{{ .Version }}"' .goreleaser.yaml ||
  fail "GoReleaser and branch packages must share the hyphenated archive naming contract"
grep -Fq 'name_template: SHA256SUMS' .goreleaser.yaml ||
  fail "GoReleaser and branch packages must share the SHA256SUMS contract"
for archive_file in waf-cli waf-cli.cmd VERSION release.json; do
  grep -Fq "dst: ${archive_file}" .goreleaser.yaml ||
    fail "GoReleaser archive must preserve ${archive_file} as a named file"
done
if grep -Fq 'format_overrides:' .goreleaser.yaml; then
  fail "all release targets must use the same tar.gz archive format"
fi

if grep -E '^[[:space:]]*version_template:.*incpatch' .goreleaser.yaml; then
  fail "GoReleaser snapshot version must not use incpatch; Alpha- tags are not semver"
fi
grep -Fq 'version_template: "0.1.0-PreTest"' .goreleaser.yaml ||
  fail "GoReleaser snapshot version must be a valid semver PreTest label"

if grep -Fq '*SNAPSHOT*' scripts/ci/verify-release.sh; then
  fail "GoReleaser GUI skip must not depend on SNAPSHOT in the archive name"
fi
grep -Fq 'branch=goreleaser' scripts/ci/verify-release.sh ||
  fail "GoReleaser archives must skip GUI checks via VERSION branch=goreleaser"
grep -Fq 'artifact_matches_host' scripts/ci/verify-release.sh ||
  fail "release smoke must match cheesewaf-{arch}-{os}- names without depending on field order"

bash scripts/ci/generate-release-metadata_test.sh
bash scripts/ci/verify-release_test.sh

echo "CI static regression checks passed."
