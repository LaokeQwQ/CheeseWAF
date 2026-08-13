#!/bin/bash
set -e

TARGETS=(
    "linux/amd64"
    "linux/arm64"
    "linux/loong64"
    "darwin/amd64"
    "darwin/arm64"
    "windows/amd64"
    "windows/arm64"
)

mkdir -p bin

for target in "${TARGETS[@]}"; do
    goos="${target%/*}"
    goarch="${target#*/}"
    ext=""
    [ "$goos" = "windows" ] && ext=".exe"

    output="bin/cheesewaf-$goos-$goarch$ext"

    echo "Building $goos/$goarch..."
    CGO_ENABLED=0 GOOS=$goos GOARCH=$goarch go build \
        -trimpath \
        -gcflags "-l=4" \
        -ldflags "-s -w" \
        -o "$output" \
        ./cmd/cheesewaf/

    echo "✓ $output ($(du -h "$output" | cut -f1))"
done

echo ""
echo "All builds complete:"
ls -lh bin/cheesewaf-*
