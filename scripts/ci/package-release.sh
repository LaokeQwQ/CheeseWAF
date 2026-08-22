#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
version_prefix="${CHEESEWAF_VERSION_PREFIX:-$(cat "${script_dir}/product-version")}"
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
    file_suffix="beta"
    version="${version_prefix}-beta.${run_number}+${short_commit}"
    ;;
  canary)
    channel="PreTest"
    file_suffix="PreTest"
    version="${version_prefix}-PreTest.${run_number}+${short_commit}"
    ;;
  dev)
    channel="dev"
    file_suffix="dev"
    version="${version_prefix}-dev.${run_number}+${short_commit}"
    ;;
  *)
    channel="$(printf "%s" "$ref_name" | tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9]+/-/g; s/^-+|-+$//g')"
    if [[ -z "$channel" ]]; then
      channel="custom"
    fi
    file_suffix="$channel"
    version="${version_prefix}-${channel}.${run_number}+${short_commit}"
    ;;
esac

artifact_version="${version//+/-}"
prerelease_tag="Alpha-${artifact_version}"
module="$(go list -m)"
ldflags="-s -w -X ${module}/internal/version.Version=${version} -X ${module}/internal/version.Commit=${commit} -X ${module}/internal/version.BuildTime=${build_time} -X ${module}/internal/version.Channel=${channel}"
repo_root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
release_dir="${CHEESEWAF_RELEASE_DIR:-release}"
work_dir="${CHEESEWAF_RELEASE_WORK_DIR:-tmp/release-packages}"
if [[ "$release_dir" != /* ]]; then
  release_dir="${repo_root}/${release_dir}"
fi
if [[ "$work_dir" != /* ]]; then
  work_dir="${repo_root}/${work_dir}"
fi

echo "Packaging CheeseWAF ${version} (${channel}) from ${commit}"

rm -rf "$release_dir" "$work_dir"
mkdir -p "$release_dir" "$work_dir"

metadata_dir="${work_dir}/release-metadata"
bash scripts/ci/generate-release-metadata.sh \
  "$metadata_dir" "$version" "$channel" "$ref_name" "$commit" "$build_time" "$prerelease_tag"

bash scripts/ci/build-web.sh

read -r -a targets <<<"${CHEESEWAF_TARGETS:-linux/amd64 linux/arm64 linux/loong64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64}"

for target in "${targets[@]}"; do
  goos="${target%/*}"
  goarch="${target#*/}"
  ext=""
  if [[ "$goos" == "windows" ]]; then
    ext=".exe"
  fi

  package_name="cheesewaf-${goarch}-${goos}-${artifact_version}"
  package_root="${work_dir}/${package_name}"
  mkdir -p "$package_root"

  echo "building ${target} -> ${package_name}"
  GOOS="$goos" GOARCH="$goarch" CGO_ENABLED=0 go build -trimpath -ldflags "$ldflags" -o "${package_root}/cheesewaf${ext}" ./cmd/cheesewaf/
  if [[ "$goos" != "windows" ]]; then
    chmod +x "${package_root}/cheesewaf${ext}"
    cp scripts/ci/waf-cli "${package_root}/waf-cli"
    chmod +x "${package_root}/waf-cli"
    if [[ "$goos" == "darwin" ]]; then
      echo "building ${target} gui"
      GOOS="$goos" GOARCH="$goarch" CGO_ENABLED=0 go build -trimpath -ldflags "$ldflags" \
        -o "${package_root}/cheesewaf-gui" ./cmd/cheesewaf-gui/
      chmod +x "${package_root}/cheesewaf-gui"
    fi
  else
    cp scripts/ci/waf-cli.cmd "${package_root}/waf-cli.cmd"
    cp "${package_root}/cheesewaf.exe" "${package_root}/waf-cli.exe"
    echo "building ${target} gui"
    GOOS="$goos" GOARCH="$goarch" CGO_ENABLED=0 go build -trimpath -ldflags "$ldflags" \
      -o "${package_root}/cheesewaf-gui.exe" ./cmd/cheesewaf-gui/
  fi

  if [[ "$goos" == "linux" ]]; then
    mkdir -p "${package_root}/systemd"
    cp "${repo_root}/deploy/systemd/cheesewaf.service" "${package_root}/systemd/cheesewaf.service"
    cp "${repo_root}/scripts/ci/install-linux.sh" "${package_root}/install-linux.sh"
    chmod +x "${package_root}/install-linux.sh"
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

  if [[ "$goos" == "windows" ]]; then
    bash "${repo_root}/scripts/ci/sign-windows.sh" \
      "${package_root}/cheesewaf.exe" \
      "${package_root}/cheesewaf-gui.exe" \
      "${package_root}/waf-cli.exe"
    cp "${package_root}/cheesewaf.exe" "${release_dir}/${package_name}.exe"
    (
      cd "$work_dir"
      zip -qr "${release_dir}/${package_name}.zip" "$package_name"
    )
    if command -v makensis >/dev/null 2>&1; then
      nsis_out="${release_dir}/${package_name}-setup.exe"
      makensis -V2 \
        -DVERSION="${artifact_version}" \
        -DSOURCE_DIR="${package_root}" \
        -DOUTFILE="${nsis_out}" \
        "${repo_root}/deploy/windows/nsis/cheesewaf.nsi"
      bash "${repo_root}/scripts/ci/sign-windows.sh" "$nsis_out"
    else
      echo "makensis not installed; skipped NSIS installer for ${target}"
    fi
  else
    tar -C "$work_dir" -czf "${release_dir}/${package_name}.tar.gz" "$package_name"
  fi
done

pushd "$release_dir" >/dev/null
mapfile -t hashed < <(find . -maxdepth 1 -type f ! -name SHA256SUMS ! -name release-manifest.txt | sed 's#^\./##' | sort)
sha256sum "${hashed[@]}" >SHA256SUMS
cat >release-manifest.txt <<EOF
CheeseWAF release artifacts
version: ${version}
prerelease_tag: ${prerelease_tag}
channel: ${channel}
file_suffix: ${file_suffix}
branch: ${ref_name}
commit: ${commit}
build_time: ${build_time}

Artifacts:
$(printf '%s\n' "${hashed[@]}" | sed 's/^/- /')
EOF
popd >/dev/null

echo "Artifacts written to ${release_dir}/"
echo "Pre-release tag: ${prerelease_tag}"
