#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
release_dir="${1:-release}"
[[ -d "$release_dir" ]] || {
  echo "::error::release directory not found: ${release_dir}" >&2
  exit 1
}

tag=""
suffix=""
commit=""
release_kind="${CHEESEWAF_RELEASE_KIND:-}"
if [[ -f "${release_dir}/release-manifest.txt" ]]; then
	tag="$(awk -F': ' '/^release_tag:/{print $2; exit}' "${release_dir}/release-manifest.txt")"
	if [[ -z "$tag" ]]; then
		tag="$(awk -F': ' '/^prerelease_tag:/{print $2; exit}' "${release_dir}/release-manifest.txt")"
	fi
	if [[ -z "$release_kind" ]]; then
		release_kind="$(awk -F': ' '/^release_kind:/{print $2; exit}' "${release_dir}/release-manifest.txt")"
	fi
  suffix="$(awk -F': ' '/^file_suffix:/{print $2; exit}' "${release_dir}/release-manifest.txt")"
  commit="$(awk -F': ' '/^commit:/{print $2; exit}' "${release_dir}/release-manifest.txt")"
  if [[ -z "$suffix" ]]; then
    suffix="$(awk -F': ' '/^channel:/{print $2; exit}' "${release_dir}/release-manifest.txt")"
  fi
fi
if [[ -z "$tag" ]]; then
	echo "::error::release_tag is missing from release-manifest.txt" >&2
	exit 1
fi
release_kind="${release_kind:-prerelease}"
case "$release_kind" in
  prerelease)
    [[ "$tag" == Alpha-* ]] || {
      echo "::error::pre-release tag must start with Alpha-: ${tag}" >&2
      exit 1
    }
    ;;
  stable)
    [[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
      echo "::error::stable release tag must use vMAJOR.MINOR.PATCH: ${tag}" >&2
      exit 1
    }
    ;;
  *)
    echo "::error::release_kind must be prerelease or stable" >&2
    exit 1
    ;;
esac
if [[ -z "$commit" ]]; then
  echo "::error::commit is missing from release-manifest.txt" >&2
  exit 1
fi
if [[ -z "$suffix" ]]; then
  suffix="PreTest"
fi
if [[ "$suffix" == "stable" ]]; then
  suffix="beta"
fi

repo_root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
command -v syft >/dev/null 2>&1 || {
  echo "::error::syft is required to attach a CycloneDX SBOM" >&2
  exit 1
}
command -v cosign >/dev/null 2>&1 || {
  echo "::error::cosign is required to sign SHA256SUMS and the SBOM" >&2
  exit 1
}

sbom_file="${release_dir}/cheesewaf.cdx.json"
product_sbom="${release_dir}/cheesewaf-artifacts.cdx.json"
artifacts_manifest="${release_dir}/artifacts.manifest.json"

# A rerun must not feed stale generated metadata into the artifact scan or
# publish a sidecar for an SBOM variant that is no longer current.
for generated in "$sbom_file" "$product_sbom" "$artifacts_manifest"; do
  rm -f "$generated" "${generated}.bundle"
done
rm -f "${release_dir}/SHA256SUMS.bundle"

# Rebuild the manifest after the macOS job has added/replaced DMGs. The
# artifact SBOM/fallback below must never consume the pre-DMG manifest.
bash "${script_dir}/rewrite-release-checksums.sh" "$release_dir"

syft scan "dir:${repo_root}" \
  --source-name cheesewaf \
  --source-version "$tag" \
  --exclude '**/.git/**' \
  --exclude '**/node_modules/**' \
  --exclude '**/.grok/**' \
  --exclude '**/tmp/**' \
  --exclude '**/release/**' \
  -o "cyclonedx-json=${sbom_file}"
[[ -s "$sbom_file" ]] || {
  echo "::error::syft did not write ${sbom_file}" >&2
  exit 1
}

# Product-level SBOM: scan the release artifacts directory (tarballs, zips,
# exes, dmg) in addition to the source tree. syft cannot always index opaque
# tar.gz/exe payloads, so if the scan fails we fall back to a signed
# artifacts.manifest.json parsed from SHA256SUMS (minimum viable SBOM).
if ! syft scan "dir:${release_dir}" \
    --source-name cheesewaf-artifacts \
    --source-version "$tag" \
    --exclude '**/.git/**' \
    --exclude '**/node_modules/**' \
    --exclude '**/tmp/**' \
    --exclude '**/cheesewaf.cdx.json' \
    --exclude '**/cheesewaf-artifacts.cdx.json' \
    --exclude '**/artifacts.manifest.json' \
    --exclude '**/SHA256SUMS.bundle' \
    --exclude '**/*.sig' \
    -o "cyclonedx-json=${product_sbom}" 2>/dev/null; then
  echo "syft artifact scan failed; falling back to artifacts.manifest.json"
  rm -f "$product_sbom"
  {
    printf '{\n  "name": "cheesewaf-artifacts",\n  "version": "%s",\n  "artifacts": [\n' "$tag"
    first=1
    while IFS= read -r line; do
      [[ -z "$line" ]] && continue
      sha="${line%% *}"
      name="${line#*  }"
      name="${name# }"
      [[ -n "$sha" && -n "$name" ]] || continue
      if [[ "$first" -eq 1 ]]; then
        first=0
      else
        printf ',\n'
      fi
      printf '    { "sha256": "%s", "name": "%s" }' "$sha" "$name"
    done < "${release_dir}/SHA256SUMS"
    printf '\n  ]\n}\n'
  } >"$artifacts_manifest"
  product_sbom="$artifacts_manifest"
fi
[[ -s "$product_sbom" ]] || {
  echo "::error::could not generate a product-level SBOM for ${release_dir}" >&2
  exit 1
}

bash "${script_dir}/rewrite-release-checksums.sh" "$release_dir"

sign_blob() {
  local file="$1"
  COSIGN_YES=true cosign sign-blob --yes --bundle "${file}.bundle" "$file"
  COSIGN_YES=true cosign verify-blob \
    --bundle "${file}.bundle" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    --certificate-identity-regexp '^https://github.com/LaokeQwQ/CheeseWAF/' \
    "$file"
}

sha256_file() {
  local file="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$file" | awk '{print $1}'
  else
    echo "::error::sha256sum or shasum is required to verify existing release assets" >&2
    return 1
  fi
}

sign_blob "${release_dir}/SHA256SUMS"
sign_blob "$sbom_file"
sign_blob "$product_sbom"

notes="$(mktemp)"
existing_asset_dir="$(mktemp -d)"
trap 'rm -f "$notes"; rm -rf "$existing_asset_dir"' EXIT
release_label="stable release"
release_notice="This is a stable release. Review the upgrade and rollback instructions before deployment."
if [[ "$release_kind" == "prerelease" ]]; then
  release_label="pre-release"
  release_notice="This is an alpha build, not a stable release. Configuration and APIs may change."
fi
cat >"$notes" <<EOF
CheeseWAF ${release_label} \`${tag}\`.

${release_notice}

Download the archive that matches your OS and CPU:

| File | Platform |
| --- | --- |
| \`cheesewaf-amd64-linux-*.tar.gz\` | Linux x86_64 |
| \`cheesewaf-arm64-linux-*.tar.gz\` | Linux ARM64 |
| \`cheesewaf-loong64-linux-*.tar.gz\` | Linux LoongArch64 |
| \`cheesewaf-amd64-darwin-*.tar.gz\` / \`.dmg\` | macOS Intel |
| \`cheesewaf-arm64-darwin-*.tar.gz\` / \`.dmg\` | macOS Apple Silicon |
| \`cheesewaf-amd64-windows-*.exe\` | Windows x86_64 single-file CLI |
| \`cheesewaf-arm64-windows-*.exe\` | Windows ARM64 single-file CLI |
| \`cheesewaf-amd64-windows-*.zip\` | Windows x86_64 portable folder |
| \`cheesewaf-arm64-windows-*.zip\` | Windows ARM64 portable folder |
| \`cheesewaf-amd64-windows-*-setup.exe\` | Windows x86_64 GUI installer |
| \`cheesewaf-arm64-windows-*-setup.exe\` | Windows ARM64 GUI installer |

Linux archives include \`systemd/cheesewaf.service\`. Verify downloads with \`SHA256SUMS\`.

A source-tree CycloneDX SBOM is attached as \`cheesewaf.cdx.json\`, and a product-level SBOM for the release artifacts is attached as \`cheesewaf-artifacts.cdx.json\` (or \`artifacts.manifest.json\` when the artifact scan falls back). \`SHA256SUMS\` and the SBOM(s) are signed with Sigstore keyless identities from GitHub Actions. Verify:

\`\`\`
cosign verify-blob --bundle SHA256SUMS.bundle \\
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \\
  --certificate-identity-regexp '^https://github.com/LaokeQwQ/CheeseWAF/' \\
  SHA256SUMS
\`\`\`
EOF

assets=()
while IFS= read -r f; do
  [[ -n "$f" ]] || continue
  assets+=("$f")
done < <(find "$release_dir" -maxdepth 1 -type f ! -name release-manifest.txt | sort)
[[ "${#assets[@]}" -gt 0 ]] || {
  echo "::error::no files to publish in ${release_dir}" >&2
  exit 1
}

if gh release view "$tag" >/dev/null 2>&1; then
  existing_assets="$(gh release view "$tag" --json assets --jq '.assets[].name')"
  missing_assets=()
  for asset in "${assets[@]}"; do
    asset_name="$(basename "$asset")"
    if grep -Fxq "$asset_name" <<<"$existing_assets"; then
      expected_sha="$(awk -v name="$asset_name" '$2 == name { print $1; found++ } END { exit found > 1 ? 1 : 0 }' "${release_dir}/SHA256SUMS")" || {
        echo "::error::SHA256SUMS contains duplicate entries for existing asset ${asset_name}" >&2
        exit 1
      }
      if [[ -z "$expected_sha" ]]; then
        expected_sha="$(sha256_file "$asset")" || exit 1
      fi
      [[ "$expected_sha" =~ ^[[:xdigit:]]{64}$ ]] || {
        echo "::error::invalid SHA-256 for existing asset ${asset_name}" >&2
        exit 1
      }
      rm -f "${existing_asset_dir}/${asset_name}"
      gh release download "$tag" \
        --pattern "$asset_name" \
        --dir "$existing_asset_dir" || {
          echo "::error::could not download existing release asset ${asset_name} for verification" >&2
          exit 1
        }
      remote_asset="${existing_asset_dir}/${asset_name}"
      [[ -f "$remote_asset" ]] || {
        echo "::error::downloaded release asset is missing: ${asset_name}" >&2
        exit 1
      }
      actual_sha="$(sha256_file "$remote_asset")" || exit 1
      [[ "$actual_sha" == "$expected_sha" ]] || {
        echo "::error::existing release asset ${asset_name} does not match its local SHA256SUMS entry" >&2
        exit 1
      }
      echo "release ${tag} already contains verified immutable asset ${asset_name}; keeping it"
    else
      missing_assets+=("$asset")
    fi
  done
  if [[ "${#missing_assets[@]}" -gt 0 ]]; then
    gh release upload "$tag" "${missing_assets[@]}"
  fi
  exit 0
fi

if [[ "$release_kind" == "prerelease" ]]; then
  gh release create "$tag" \
    --target "$commit" \
    --prerelease \
    --title "$tag" \
    --notes-file "$notes" \
    "${assets[@]}"
else
  gh release create "$tag" \
    --target "$commit" \
    --title "$tag" \
    --notes-file "$notes" \
    "${assets[@]}"
fi
