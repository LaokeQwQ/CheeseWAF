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
grep -Fq 'ca-certificates' deploy/docker/Dockerfile ||
  fail "runtime image must install ca-certificates for outbound HTTPS"
awk '
  /ca-certificates/ { ca = NR }
  /^USER cheesewaf$/ { user = NR }
  END { if (!ca || !user || ca >= user) exit 1 }
' deploy/docker/Dockerfile ||
  fail "ca-certificates must be installed before USER cheesewaf"
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
grep -Fq '/etc/ssl/certs/ca-certificates.crt' scripts/ci/docker-build.sh ||
  fail "container smoke must assert the runtime CA bundle is readable"
grep -Fq -- '--outbound-tls' scripts/ci/docker-build.sh ||
  fail "container smoke must probe outbound HTTPS with the system CA pool"
grep -Fq 'healthcheck --outbound-tls' scripts/ci/docker-build.sh ||
  fail "container smoke must invoke healthcheck --outbound-tls inside the container"
grep -Fq 'CHEESEWAF_SETUP_TOKEN' scripts/ci/docker-build.sh ||
  fail "container smoke must inject CHEESEWAF_SETUP_TOKEN"
grep -Fq 'secrets.token_urlsafe' scripts/ci/docker-build.sh ||
  fail "container smoke must generate one-run setup credentials"
grep -Fq -- '--env-file "$secret_env_file"' scripts/ci/docker-build.sh ||
  fail "container smoke must keep its setup token out of argv"
grep -Fq -- '--header "@${setup_header}"' scripts/ci/docker-build.sh ||
  fail "container smoke must keep its setup header out of argv"
if grep -Fq 'CheeseWAF-CI-Setup-Token' scripts/ci/docker-build.sh ||
  grep -Fq 'CheeseWAF-CI-Smoke-Only' scripts/ci/docker-build.sh; then
  fail "container smoke must not hard-code setup credentials"
fi
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
grep -Fq 'cheesewaf-${goarch}-${goos}-${artifact_version}' scripts/ci/package-release.sh ||
  fail "branch packages must use cheesewaf-{arch}-{os}-{version} names"
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
[[ "$got_ver" == "$(cat scripts/ci/product-version)" ]] ||
  fail "macOS CFBundleVersion must strip PreTest labels (got ${got_ver})"
grep -Fq 'package-macos-dmg.sh' .github/workflows/ci.yml ||
  fail "CI must build macOS DMG images on a macOS runner"
grep -Fq 'Alpha-' scripts/ci/package-release.sh ||
  fail "pre-release tags must use the Alpha- prefix"
grep -Fq 'scripts/ci/publish-prerelease.sh' .github/workflows/ci.yml ||
  fail "CI must publish Alpha- GitHub pre-releases"
grep -Fq 'scripts/ci/publish-release.sh' .github/workflows/ci.yml ||
  fail "CI must publish stable vMAJOR.MINOR.PATCH releases"
grep -Fq -- "- 'v*'" .github/workflows/ci.yml ||
  fail "CI must run on stable version tags"
grep -Fq 'linux/amd64,linux/arm64' scripts/ci/docker-build.sh ||
  fail "container CI must build linux/amd64 and linux/arm64"
grep -Fq 'dst: systemd/cheesewaf.service' .goreleaser.yaml ||
  fail "GoReleaser archive must include the systemd unit"
if ! grep -A5 '^release:' .goreleaser.yaml | grep -Fq 'disable: true'; then
  fail "GoReleaser must not publish GitHub Latest releases; Alpha- packaging owns GitHub Releases"
fi
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
grep -Fq 'AmbientCapabilities=CAP_NET_BIND_SERVICE' deploy/systemd/cheesewaf.service ||
  fail "systemd unit must grant CAP_NET_BIND_SERVICE so a non-root service can bind :80/:443"
grep -Fq 'CapabilityBoundingSet=CAP_NET_BIND_SERVICE' deploy/systemd/cheesewaf.service ||
  fail "systemd unit must bound capabilities to CAP_NET_BIND_SERVICE"
grep -Fq 'ProtectSystem=strict' deploy/systemd/cheesewaf.service ||
  fail "systemd unit must use ProtectSystem=strict"
grep -Fq 'AmbientCapabilities=CAP_NET_BIND_SERVICE' internal/cluster/deploy/ansible.go ||
  fail "Ansible unit must grant CAP_NET_BIND_SERVICE"
grep -Fq 'ProtectSystem=strict' internal/cluster/deploy/ansible.go ||
  fail "Ansible unit must use ProtectSystem=strict"
grep -Fq 'windowsServiceName = "CheeseWAF"' internal/cli/serve_windows.go ||
  fail "Windows SCM handler must use service name CheeseWAF"
grep -Fq 'svc.IsWindowsService' internal/cli/serve_windows.go ||
  fail "serve must detect Windows Service Control Manager"
grep -Fq 'sc.exe create CheeseWAF' deploy/windows/nsis/cheesewaf.nsi ||
  fail "NSIS must register the CheeseWAF Windows service"
if grep -nE '^Page (directory|instfiles)' deploy/windows/nsis/cheesewaf.nsi; then
  fail "NSIS must not mix classic Page with MUI pages"
fi
if grep -nE '^UninstPage ' deploy/windows/nsis/cheesewaf.nsi; then
  fail "NSIS must not mix classic UninstPage with MUI unpages"
fi
[[ -f .air.toml ]] || fail "make dev requires .air.toml"
grep -Fq 'web-test' Makefile ||
  fail "make test must run frontend tests"
grep -Fq 'npm test' Makefile ||
  fail "make test must invoke npm test"
grep -Fq 'func applyCLIDataDir' internal/cli/datadir.go ||
  fail "serve must rebase packaged relative ./data paths onto --data-dir"
grep -Fq 'middleware.WriteCookie(w, r' internal/cli/service.go ||
  fail "admin entry cookies must follow request TLS like session cookies"
if grep -Fq 'ExecReload=' deploy/systemd/cheesewaf.service; then
  fail "systemd must not advertise SIGHUP reload; the process ignores hangup"
fi
grep -Fq 'rewrite-release-checksums.sh' scripts/ci/publish-prerelease.sh ||
  fail "publish must rebuild SHA256SUMS after macOS DMG files land"
if grep -Fq -- '--clobber' scripts/ci/publish-prerelease.sh; then
  fail "published release assets must be immutable"
fi
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
grep -Fq 'func WriteCookie' internal/api/middleware/session_cookie.go ||
  fail "admin cookies must go through middleware.WriteCookie"
if grep -nE 'http\.SetCookie' internal/api/middleware/session_cookie.go internal/api/handler/handler.go internal/api/handler/setup_wizard.go internal/cli/service.go; then
  fail "admin cookies must not call http.SetCookie directly"
fi
grep -Fq 'scripts/ci/channel-from-git.sh' Makefile ||
  fail "Makefile CHANNEL must not embed a case statement with closing parens"
grep -A1 'canary)' scripts/ci/channel-from-git.sh | grep -Fq 'echo PreTest' ||
  fail "local canary channel must match package-release PreTest metadata"
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
grep -Fq '{{ .Env.CHEESEWAF_VERSION_PREFIX }}-PreTest' .goreleaser.yaml ||
  fail "GoReleaser snapshot version must read the product-version env"
grep -Fq 'export CHEESEWAF_VERSION_PREFIX="$(cat scripts/ci/product-version)"' .github/workflows/ci.yml ||
  fail "GitHub Actions must export the product version before goreleaser"
grep -Fq 'export CHEESEWAF_VERSION_PREFIX="$(cat scripts/ci/product-version)"' .forgejo/workflows/ci.yml ||
  fail "Forgejo must export the product version before goreleaser"

if grep -Fq '*SNAPSHOT*' scripts/ci/verify-release.sh; then
  fail "GoReleaser GUI skip must not depend on SNAPSHOT in the archive name"
fi
grep -Fq 'branch=goreleaser' scripts/ci/verify-release.sh ||
  fail "GoReleaser archives must skip GUI checks via VERSION branch=goreleaser"
grep -Fq 'artifact_matches_host' scripts/ci/verify-release.sh ||
  fail "release smoke must match cheesewaf-{arch}-{os}- names without depending on field order"

# Single source of truth for the product version.
product_version_file="scripts/ci/product-version"
[[ -r "$product_version_file" ]] || fail "missing ${product_version_file}"
product_version="$(cat "$product_version_file")"
[[ "$product_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] ||
  fail "product-version must be plain semver (got: ${product_version})"
grep -Fq 'cat "${script_dir}/product-version"' scripts/ci/package-release.sh ||
  fail "package-release.sh must read the single version source"
grep -Fq 'CHEESEWAF_VERSION_PREFIX' scripts/ci/package-release.sh ||
  fail "package-release.sh must preserve the CHEESEWAF_VERSION_PREFIX override"
grep -Fq 'CHEESEWAF_VERSION_PREFIX' .goreleaser.yaml ||
  fail "GoReleaser must use the CHEESEWAF_VERSION_PREFIX env override"

# Local build naming/ldflags must match the release naming contract and inject
# the same version/commit/build-time/channel metadata as package-release.sh.
grep -Fq 'cheesewaf-${goarch}-${goos}-${FILENAME_VERSION}' scripts/build-all.sh ||
  fail "scripts/build-all.sh must use cheesewaf-{arch}-{os}-{version} names"
grep -Fq 'internal/version.Version=' scripts/build-all.sh ||
  fail "scripts/build-all.sh must inject the Version ldflag"
grep -Fq 'internal/version.Commit=' scripts/build-all.sh ||
  fail "scripts/build-all.sh must inject the Commit ldflag"
grep -Fq 'internal/version.BuildTime=' scripts/build-all.sh ||
  fail "scripts/build-all.sh must inject the BuildTime ldflag"
grep -Fq 'internal/version.Channel=' scripts/build-all.sh ||
  fail "scripts/build-all.sh must inject the Channel ldflag"
grep -Fq 'bin/$(BINARY_NAME)-$$goarch-$$goos-$(subst +,-,$(VERSION))$$ext' Makefile ||
  fail "Makefile build-all must use cheesewaf-{arch}-{os}-{version} names"

# Forgejo alignment: shared npm audit gate. actionlint only lints GitHub YAML;
# Forgejo uses https://data.forgejo.org/... action URLs that actionlint cannot
# parse, so Forgejo workflow correctness stays covered by the static checks above.
grep -Fq 'node scripts/npm-audit-gate.mjs' .forgejo/workflows/ci.yml ||
  fail "Forgejo web-audit must use the shared npm-audit-gate"

# Coverage gates must stay aligned with actual observed coverage so CI is not
# guaranteed to fail.
grep -Fq -- '--coverage.thresholds.lines=20 --coverage.thresholds.functions=20 --coverage.thresholds.statements=20 --coverage.thresholds.branches=10' .github/workflows/ci.yml ||
  fail "GitHub Actions web-build coverage thresholds must be 20/20/20/10"
grep -Fq -- '--coverage.thresholds.lines=20 --coverage.thresholds.functions=20 --coverage.thresholds.statements=20 --coverage.thresholds.branches=10' .forgejo/workflows/ci.yml ||
  fail "Forgejo web-build coverage thresholds must be 20/20/20/10"
grep -Fq 'coverage_floor="${GO_COVERAGE_FLOOR:-50.0}"' scripts/ci/verify-go-quality.sh ||
  fail "Go coverage floor must default to 50%"

# Publish gating: GitHub environment, tag-to-commit, idempotent create, and
# product-level SBOM.
grep -Fq 'environment: publish-prerelease' .github/workflows/ci.yml ||
  fail "publish-prerelease must run in the publish-prerelease environment"
grep -Fq -- '--target "$commit"' scripts/ci/publish-prerelease.sh ||
  fail "publish-prerelease must create the release at the manifest commit"
grep -Fq 'gh release view "$tag"' scripts/ci/publish-prerelease.sh ||
  fail "publish-prerelease must skip create when the release already exists"
grep -Fq 'cheesewaf-artifacts.cdx.json' scripts/ci/publish-prerelease.sh ||
  fail "publish-prerelease must generate a product-level SBOM"
grep -Fq 'artifacts.manifest.json' scripts/ci/publish-prerelease.sh ||
  fail "publish-prerelease must provide a minimal artifact manifest fallback"
grep -Fq 'sign_blob "$product_sbom"' scripts/ci/publish-prerelease.sh ||
  fail "publish-prerelease must sign the product-level SBOM"

# Platform signing gate: ordinary branch builds remain available, but signing
# inputs may only resolve for a tag-triggered package.
grep -Fq -- "- 'Alpha-*'" .github/workflows/ci.yml ||
  fail "GitHub CI must trigger tagged release packaging for signed artifacts"
for signing_secret in \
  WINDOWS_CERT_P12 \
  WINDOWS_CERT_PASSWORD \
  MACOS_P12_BASE64 \
  MACOS_P12_PASSWORD \
  MACOS_CODESIGN_IDENTITY \
  APPLE_API_KEY \
  APPLE_API_KEY_ID \
  APPLE_API_ISSUER; do
  grep -Fq "github.ref_type == 'tag' && secrets.${signing_secret}" .github/workflows/ci.yml ||
    fail "${signing_secret} must only be resolved for tag-triggered signing"
done
grep -Fq "github.ref_name == 'dev' || github.ref_name == 'canary' || github.ref_name == 'master'" .github/workflows/ci.yml ||
  fail "ordinary branch release artifacts must remain enabled"
grep -Fq 'Upload branch release artifacts' .github/workflows/ci.yml ||
  fail "ordinary branch release artifacts must still be uploaded"

# Deployment exposure and macOS release guidance.
grep -Fq '"127.0.0.1:9443:9443"' deploy/docker/docker-compose.yml ||
  fail "Docker admin TLS must bind to host loopback only"
if grep -Fq '"9443:9443"' deploy/docker/docker-compose.yml; then
  fail "Docker admin TLS must not bind to all host interfaces"
fi
grep -Fq 'ReadWritePaths=/var/lib/cheesewaf /var/log/cheesewaf' deploy/systemd/cheesewaf.service ||
  fail "systemd runtime writes must stay under data and log directories"
if grep -E '^ReadWritePaths=.*(/etc/cheesewaf|/etc/)' deploy/systemd/cheesewaf.service; then
  fail "systemd must not make /etc/cheesewaf writable"
fi
if [[ -e deploy/macos/fix-gatekeeper.command ]]; then
  fail "signed macOS release media must not ship a Gatekeeper quarantine helper"
fi
if grep -Fq 'fix-gatekeeper.command' scripts/ci/package-macos-dmg.sh; then
  fail "macOS packaging must not include a Gatekeeper quarantine helper"
fi
for macos_guidance in README.md README_CN.md deploy/macos/first-open.txt; do
  if grep -Fq 'xattr -dr com.apple.quarantine' "$macos_guidance"; then
    fail "${macos_guidance} must not tell release users to recursively clear quarantine"
  fi
done

# Optional release signing gate.
grep -Fq 'CHEESEWAF_REQUIRE_SIGNING' scripts/ci/verify-release.sh ||
  fail "verify-release.sh must support the optional signing gate"
grep -Fq 'osslsigncode verify' scripts/ci/verify-release.sh ||
  fail "optional signing gate must verify Windows Authenticode"
grep -Fq 'codesign --verify' scripts/ci/verify-release.sh ||
  fail "optional signing gate must verify macOS codesign"
grep -Fq 'signing_mode=1' .github/workflows/ci.yml ||
  fail "GitHub release CI must explicitly force signing when credentials exist"
grep -Fq 'CHEESEWAF_REQUIRE_SIGNING="$signing_mode"' .github/workflows/ci.yml ||
  fail "GitHub release CI must pass its explicit signing mode"
grep -Fq 'CHEESEWAF_REQUIRE_SIGNING="$signing_mode"' .forgejo/workflows/ci.yml ||
  fail "Forgejo release CI must pass its explicit signing mode"
grep -Fq 'CHEESEWAF_SIGNING_SCOPE=windows' .github/workflows/ci.yml ||
  fail "GitHub Windows release verification must use the Windows signing scope"
grep -Fq 'CHEESEWAF_SIGNING_SCOPE=macos' .github/workflows/ci.yml ||
  fail "GitHub macOS release verification must use the macOS signing scope"
grep -Fq 'WINDOWS_CERT_PASSWORD: ${{ secrets.WINDOWS_CERT_PASSWORD }}' .forgejo/workflows/ci.yml ||
  fail "Forgejo packaging must receive the Windows signing secret"
grep -Fq 'apt-get install -y --no-install-recommends nsis zip osslsigncode' .forgejo/workflows/ci.yml ||
  fail "Forgejo release packaging must install its signing and archive tools"
grep -Fq 'run_with_timeout 900 xcrun notarytool' scripts/ci/package-macos-dmg.sh ||
  fail "macOS notarization must have a bounded wait"
grep -Fq 'security delete-keychain "$signing_keychain"' scripts/ci/package-macos-dmg.sh ||
  fail "macOS packaging must remove its temporary signing keychain"
grep -Fq -- '-readpass "$pass_file"' scripts/ci/sign-windows.sh ||
  fail "Windows certificate password must be read from a protected file"
if grep -Fq -- '-pass "$WINDOWS_CERT_PASSWORD"' scripts/ci/sign-windows.sh ||
  grep -Fq -- '-P "${MACOS_P12_PASSWORD' scripts/ci/package-macos-dmg.sh; then
  fail "code-signing passwords must not be exposed in argv"
fi
for ci_script in scripts/ci/*.sh; do
  [[ "$ci_script" == scripts/ci/verify-ci-static.sh ]] && continue
  if grep -nE '(^|[^[:alnum:]_])(mapfile|readarray)([^[:alnum:]_]|$)' "$ci_script"; then
    fail "${ci_script} must run on stock macOS Bash 3.2"
  fi
done
if grep -Fq 'seq ' scripts/ci/verify-release.sh; then
  fail "release verification must not depend on non-stock macOS seq"
fi
if grep -n -- '-l=4' Makefile scripts/build-all.sh scripts/build-pgo.sh; then
  fail "release builds must not disable compiler inlining with -l=4"
fi
if grep -Fi 'aggressive inlining' PERFORMANCE_DELIVERY.md docs/performance-optimization.md; then
  fail "performance docs must not misdescribe -l=4 as aggressive inlining"
fi
if grep -Fq '/nonfatal' deploy/windows/nsis/cheesewaf.nsi; then
  fail "NSIS must fail when a required payload file is missing"
fi
grep -Fq 'test -s web/dist/index.html' Makefile ||
  fail "Windows packaging must assert the built UI exists"
grep -Fq 'assert_managed_output_dir' scripts/ci/package-release.sh ||
  fail "package-release must guard recursive cleanup targets"
grep -Fq 'must not traverse a symbolic link' scripts/ci/package-release.sh ||
  fail "package-release must reject symlinked cleanup paths"
grep -Fq 'must not be nested inside' scripts/ci/package-release.sh ||
  fail "package-release must keep release and work outputs disjoint"
CHEESEWAF_VALIDATE_OUTPUT_DIRS_ONLY=1 \
  CHEESEWAF_RELEASE_DIR=tmp/r2-static-release \
  CHEESEWAF_RELEASE_WORK_DIR=tmp/r2-static-work \
  bash scripts/ci/package-release.sh >/dev/null
if CHEESEWAF_VALIDATE_OUTPUT_DIRS_ONLY=1 \
  CHEESEWAF_RELEASE_DIR=tmp/r2-static-release \
  CHEESEWAF_RELEASE_WORK_DIR=tmp/r2-static-release/work \
  bash scripts/ci/package-release.sh >/dev/null 2>&1; then
  fail "package-release accepted a work directory nested inside release output"
fi
if CHEESEWAF_VALIDATE_OUTPUT_DIRS_ONLY=1 \
  CHEESEWAF_RELEASE_DIR=tmp/r2-static-work/release \
  CHEESEWAF_RELEASE_WORK_DIR=tmp/r2-static-work \
  bash scripts/ci/package-release.sh >/dev/null 2>&1; then
  fail "package-release accepted release output nested inside its work directory"
fi
grep -Fq 'unsafe archive path' scripts/ci/verify-release.sh ||
  fail "release verification must reject path-traversal archive members"
for release_script in package-release.sh package-macos-dmg.sh publish-prerelease.sh; do
  grep -Fq 'rewrite-release-checksums.sh' "scripts/ci/${release_script}" ||
    fail "${release_script} must use the shared atomic checksum rewrite"
done
for replacement in \
  'runtime_dir: "/var/lib/cheesewaf/run"' \
  'path: "/var/lib/cheesewaf/cheesewaf.db"' \
  'path: "/var/log/cheesewaf/access.log"' \
  'target: "/var/log/cheesewaf"' \
  'path: "/var/log/cheesewaf/audit.log"'; do
  [[ "$(grep -Fc "$replacement" deploy/docker/Dockerfile)" -ge 2 ]] ||
    fail "Dockerfile must assert config rewrite: ${replacement}"
done
grep -Fq "before 06:00 on tuesday" renovate.json ||
  fail "Renovate must not overlap Dependabot's Monday maintenance window"
grep -A2 '"enabledManagers"' renovate.json | grep -Fq '"dockerfile"' ||
  fail "Renovate must leave Go, npm, and GitHub Actions updates to Dependabot"
if grep -E 'rate_limit:|requests_per_second:|ip_block:' README.md README_CN.md; then
  fail "README configuration examples contain obsolete keys"
fi

bash scripts/ci/generate-release-metadata_test.sh
bash scripts/ci/rewrite-release-checksums_test.sh
bash scripts/ci/publish-prerelease_test.sh
bash scripts/ci/verify-release_test.sh

echo "CI static regression checks passed."
