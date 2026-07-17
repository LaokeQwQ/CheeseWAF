#!/usr/bin/env bash
set -euo pipefail

version_prefix="${CHEESEWAF_VERSION_PREFIX:-0.1.0}"
ref_name="${CHEESEWAF_REF_NAME:-${GITHUB_REF_NAME:-}}"
if [[ -z "$ref_name" ]]; then
  ref_name="$(git branch --show-current 2>/dev/null || true)"
fi
if [[ -z "$ref_name" ]]; then
  ref_name="detached"
fi

commit="${CHEESEWAF_COMMIT:-${GITHUB_SHA:-}}"
if [[ -z "$commit" ]]; then
  commit="$(git rev-parse HEAD)"
fi
short_commit="${commit:0:12}"
run_number="${CHEESEWAF_RUN_NUMBER:-${GITHUB_RUN_NUMBER:-0}}"
build_time="${CHEESEWAF_BUILD_TIME:-$(date -u +"%Y-%m-%dT%H:%M:%SZ")}"

case "$ref_name" in
  master|main)
    channel="stable"
    version="${version_prefix}-beta.${run_number}+${short_commit}"
    ;;
  canary)
    channel="canary"
    version="${version_prefix}-canary.${run_number}+${short_commit}"
    ;;
  dev)
    channel="dev"
    version="${version_prefix}-dev.${run_number}+${short_commit}"
    ;;
  *)
    channel="$(printf "%s" "$ref_name" | tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9]+/-/g; s/^-+|-+$//g')"
    if [[ -z "$channel" ]]; then
      channel="custom"
    fi
    version="${version_prefix}-${channel}.${run_number}+${short_commit}"
    ;;
esac

artifact_version="${version//+/-}"
module="$(go list -m)"
ldflags="-s -w -X ${module}/internal/version.Version=${version} -X ${module}/internal/version.Commit=${commit} -X ${module}/internal/version.BuildTime=${build_time} -X ${module}/internal/version.Channel=${channel}"
release_dir="${CHEESEWAF_RELEASE_DIR:-release}"
work_dir="${CHEESEWAF_RELEASE_WORK_DIR:-tmp/release-packages}"

echo "Packaging CheeseWAF ${version} (${channel}) from ${commit}"

rm -rf "$release_dir" "$work_dir"
mkdir -p "$release_dir" "$work_dir"

metadata_dir="${work_dir}/release-metadata"
bash scripts/ci/generate-release-metadata.sh \
  "$metadata_dir" "$version" "$channel" "$ref_name" "$commit" "$build_time"

bash scripts/ci/build-web.sh

read -r -a targets <<<"${CHEESEWAF_TARGETS:-linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64}"

for target in "${targets[@]}"; do
  goos="${target%/*}"
  goarch="${target#*/}"
  ext=""
  if [[ "$goos" == "windows" ]]; then
    ext=".exe"
  fi

  package_name="cheesewaf-${artifact_version}-${goos}-${goarch}"
  package_root="${work_dir}/${package_name}"
  mkdir -p "$package_root"

  echo "building ${target} -> ${package_name}"
  GOOS="$goos" GOARCH="$goarch" CGO_ENABLED=0 go build -trimpath -ldflags "$ldflags" -o "${package_root}/cheesewaf${ext}" ./cmd/cheesewaf/
  if [[ "$goos" != "windows" ]]; then
    chmod +x "${package_root}/cheesewaf${ext}"
    cp scripts/ci/waf-cli "${package_root}/waf-cli"
    chmod +x "${package_root}/waf-cli"
  else
    cp scripts/ci/waf-cli.cmd "${package_root}/waf-cli.cmd"
  fi

  mkdir -p "${package_root}/web"
  cp -R web/dist "${package_root}/web/dist"
  cp -R configs "${package_root}/configs"
  for doc in README.md README_CN.md LICENSE; do
    if [[ -f "$doc" ]]; then
      cp "$doc" "$package_root/"
    fi
  done
  cp "${metadata_dir}/VERSION" "${metadata_dir}/release.json" "$package_root/"

  tar -C "$work_dir" -czf "${release_dir}/${package_name}.tar.gz" "$package_name"
done

pushd "$release_dir" >/dev/null
sha256sum ./*.tar.gz > SHA256SUMS
cat > release-manifest.txt <<EOF
CheeseWAF release artifacts
version: ${version}
channel: ${channel}
branch: ${ref_name}
commit: ${commit}
build_time: ${build_time}

Artifacts:
$(ls -1 ./*.tar.gz | sed 's#^\./#- #')
EOF
popd >/dev/null

echo "Artifacts written to ${release_dir}/"
