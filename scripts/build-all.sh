#!/bin/bash
set -e

# Local cross-build helper. Artifact names follow the shared release naming
# contract: cheesewaf-{arch}-{os}-{version}[.exe]. This does not touch the
# release scripts (package-release.sh / publish-prerelease.sh), whose naming
# and semantics are reserved for CI release publishing.

MODULE="${CHEESEWAF_MODULE:-$(go list -m)}"
VERSION="${CHEESEWAF_VERSION:-$(cat scripts/ci/product-version)-$(sh scripts/ci/channel-from-git.sh)}"
COMMIT="${CHEESEWAF_COMMIT:-$(git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)}"
BUILD_TIME="${CHEESEWAF_BUILD_TIME:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
CHANNEL="${CHEESEWAF_CHANNEL:-$(sh scripts/ci/channel-from-git.sh)}"
FILENAME_VERSION="${VERSION//+/-}"

TARGETS=(
    "linux/amd64"
    "linux/arm64"
    "linux/loong64"
    "darwin/amd64"
    "darwin/arm64"
    "windows/amd64"
    "windows/arm64"
)

LDFLAGS="-s -w -X ${MODULE}/internal/version.Version=${VERSION} -X ${MODULE}/internal/version.Commit=${COMMIT} -X ${MODULE}/internal/version.BuildTime=${BUILD_TIME} -X ${MODULE}/internal/version.Channel=${CHANNEL}"

mkdir -p bin

for target in "${TARGETS[@]}"; do
    goos="${target%/*}"
    goarch="${target#*/}"
    ext=""
    [ "$goos" = "windows" ] && ext=".exe"

    output="bin/cheesewaf-${goarch}-${goos}-${FILENAME_VERSION}${ext}"

    echo "Building $goos/$goarch -> ${output} (version ${VERSION}, channel ${CHANNEL})..."
    CGO_ENABLED=0 GOOS=$goos GOARCH=$goarch go build \
        -trimpath \
        -ldflags "$LDFLAGS" \
        -o "$output" \
        ./cmd/cheesewaf/

    echo "✓ $output ($(du -h "$output" | cut -f1))"
done

echo ""
echo "All builds complete:"
ls -lh bin/cheesewaf-*
