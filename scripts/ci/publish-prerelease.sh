#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
release_dir="${1:-release}"
# shellcheck disable=SC1091
source "${script_dir}/stable-release-policy.sh"
repo_root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
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

if [[ "$release_kind" == "stable" ]]; then
  product_version="$(tr -d '[:space:]' <"${repo_root}/scripts/ci/product-version")"
  expected_product_tag="v${product_version}"
  [[ "$tag" == "$expected_product_tag" ]] || {
    echo "::error::stable release tag ${tag} does not match product version ${expected_product_tag}" >&2
    exit 1
  }
  [[ "$commit" =~ ^[0-9a-fA-F]{40}$ ]] || {
    echo "::error::stable release manifest commit must be a full 40-character SHA" >&2
    exit 1
  }
  stable_release_validate_top_level "$release_dir" "stable release" "$product_version" || exit 1
  stable_release_require_archives "$release_dir" "$product_version" || exit 1
fi

if [[ "$release_kind" == "stable" ]]; then
  identity_flag='--certificate-identity'
  identity_value="https://github.com/LaokeQwQ/CheeseWAF/.github/workflows/ci.yml@refs/tags/${tag}"
else
  identity_flag='--certificate-identity-regexp'
  identity_value='^https://github\.com/LaokeQwQ/CheeseWAF/\.github/workflows/ci\.yml@refs/(heads/(master|canary)|tags/Alpha-[^/]+)$'
fi

notes=""
existing_asset_dir="$(mktemp -d)"
cleanup() {
  [[ -z "$notes" ]] || rm -f "$notes"
  rm -rf "$existing_asset_dir"
}
trap cleanup EXIT

sha256_file() {
  local file="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$file" | awk '{print $1}'
  else
    echo "::error::sha256sum or shasum is required to verify release assets" >&2
    return 1
  fi
}

verify_sigstore_blob() {
  local file="$1"
  COSIGN_YES=true cosign verify-blob \
    --bundle "${file}.bundle" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    "$identity_flag" "$identity_value" \
    "$file"
}

resolve_remote_tag_commit() {
  local release_repository="${GITHUB_REPOSITORY:-LaokeQwQ/CheeseWAF}"
  local object_line
  local object_type
  local object_sha
  local extra
  local depth

  [[ "$release_repository" == "LaokeQwQ/CheeseWAF" ]] || {
    echo "::error::stable releases may only be published from LaokeQwQ/CheeseWAF" >&2
    return 1
  }
  object_line="$(gh api "repos/${release_repository}/git/ref/tags/${tag}" \
    --jq '.object.type + " " + .object.sha')" || {
    echo "::error::remote stable tag ${tag} does not exist" >&2
    return 1
  }

  for depth in 1 2 3 4 5; do
    object_type=""
    object_sha=""
    extra=""
    read -r object_type object_sha extra <<<"$object_line"
    [[ -z "$extra" && "$object_sha" =~ ^[0-9a-fA-F]{40}$ ]] || {
      echo "::error::GitHub returned invalid object metadata while resolving ${tag}" >&2
      return 1
    }
    case "$object_type" in
      commit)
        printf '%s\n' "$object_sha"
        return 0
        ;;
      tag)
        object_line="$(gh api "repos/${release_repository}/git/tags/${object_sha}" \
          --jq '.object.type + " " + .object.sha')" || {
          echo "::error::could not peel annotated remote tag object ${object_sha}" >&2
          return 1
        }
        ;;
      *)
        echo "::error::remote stable tag ${tag} resolves to unsupported object type ${object_type}" >&2
        return 1
        ;;
    esac
  done

  echo "::error::remote stable tag ${tag} exceeds the supported annotation depth" >&2
  return 1
}

asset_count() {
  local wanted="$1"
  awk -v wanted="$wanted" '$0 == wanted { count++ } END { print count + 0 }' <<<"$existing_assets"
}

verify_existing_stable_release() {
  local existing_tag_name
  local existing_is_draft
  local existing_is_prerelease
  local existing_target
  local duplicate_asset
  local existing_name
  local required_asset
  local product_asset
  local archive_name

  existing_tag_name="$(gh release view "$tag" --json tagName --jq '.tagName')"
  existing_is_draft="$(gh release view "$tag" --json isDraft --jq '.isDraft')"
  existing_is_prerelease="$(gh release view "$tag" --json isPrerelease --jq '.isPrerelease')"
  existing_target="$(gh release view "$tag" --json targetCommitish --jq '.targetCommitish')"
  [[ "$existing_tag_name" == "$tag" ]] || {
    echo "::error::existing release tag name does not match ${tag}" >&2
    return 1
  }
  [[ "$existing_is_draft" == "false" ]] || {
    echo "::error::stable release ${tag} must not be a draft" >&2
    return 1
  }
  [[ "$existing_is_prerelease" == "false" ]] || {
    echo "::error::stable release ${tag} must not be marked as a pre-release" >&2
    return 1
  }
  [[ "$existing_target" == "$commit" ]] || {
    echo "::error::existing release ${tag} targets ${existing_target}, expected ${commit}" >&2
    return 1
  }

  existing_assets="$(gh release view "$tag" --json assets --jq '.assets[].name')"
  [[ -n "$existing_assets" ]] || {
    echo "::error::existing stable release ${tag} has no assets" >&2
    return 1
  }
  duplicate_asset="$(printf '%s\n' "$existing_assets" | sort | uniq -d | head -n 1)"
  [[ -z "$duplicate_asset" ]] || {
    echo "::error::existing stable release contains duplicate asset name: ${duplicate_asset}" >&2
    return 1
  }
  while IFS= read -r existing_name; do
    [[ -n "$existing_name" ]] || continue
    stable_release_asset_is_allowed "$existing_name" "$product_version" || {
      echo "::error::existing stable release contains an unclassified asset: ${existing_name}" >&2
      return 1
    }
  done <<<"$existing_assets"

  for required_asset in \
    "cheesewaf-amd64-linux-${product_version}.tar.gz" \
    "cheesewaf-arm64-linux-${product_version}.tar.gz" \
    "cheesewaf-loong64-linux-${product_version}.tar.gz" \
    SHA256SUMS \
    SHA256SUMS.bundle \
    cheesewaf.cdx.json \
    cheesewaf.cdx.json.bundle; do
    [[ "$(asset_count "$required_asset")" -eq 1 ]] || {
      echo "::error::existing stable release requires exactly one ${required_asset} asset" >&2
      return 1
    }
  done

  product_asset=""
  if [[ "$(asset_count cheesewaf-artifacts.cdx.json)" -eq 1 &&
    "$(asset_count cheesewaf-artifacts.cdx.json.bundle)" -eq 1 &&
    "$(asset_count artifacts.manifest.json)" -eq 0 &&
    "$(asset_count artifacts.manifest.json.bundle)" -eq 0 ]]; then
    product_asset="cheesewaf-artifacts.cdx.json"
  elif [[ "$(asset_count artifacts.manifest.json)" -eq 1 &&
    "$(asset_count artifacts.manifest.json.bundle)" -eq 1 &&
    "$(asset_count cheesewaf-artifacts.cdx.json)" -eq 0 &&
    "$(asset_count cheesewaf-artifacts.cdx.json.bundle)" -eq 0 ]]; then
    product_asset="artifacts.manifest.json"
  else
    echo "::error::existing stable release must contain exactly one signed product SBOM variant" >&2
    return 1
  fi

  cp "${release_dir}/release-manifest.txt" "${existing_asset_dir}/release-manifest.txt"
  while IFS= read -r existing_name; do
    [[ -n "$existing_name" ]] || continue
    gh release download "$tag" \
      --pattern "$existing_name" \
      --dir "$existing_asset_dir" || {
        echo "::error::could not download existing release asset ${existing_name} for verification" >&2
        return 1
      }
  done <<<"$existing_assets"

  VERIFY_RELEASE_STATIC_ONLY=1 \
    CHEESEWAF_REQUIRE_SIGNING=1 \
    CHEESEWAF_SIGNING_SCOPE=server \
    bash "${script_dir}/verify-release.sh" "$existing_asset_dir"

  for archive_name in \
    "cheesewaf-amd64-linux-${product_version}.tar.gz" \
    "cheesewaf-arm64-linux-${product_version}.tar.gz" \
    "cheesewaf-loong64-linux-${product_version}.tar.gz"; do
    [[ "$(sha256_file "${release_dir}/${archive_name}")" == "$(sha256_file "${existing_asset_dir}/${archive_name}")" ]] || {
      echo "::error::existing stable release archive differs from the current verified package: ${archive_name}" >&2
      return 1
    }
  done

  verify_sigstore_blob "${existing_asset_dir}/SHA256SUMS"
  verify_sigstore_blob "${existing_asset_dir}/cheesewaf.cdx.json"
  verify_sigstore_blob "${existing_asset_dir}/${product_asset}"
  echo "Stable release ${tag} already exists with the exact immutable server asset set; keeping it."
}

command -v gh >/dev/null 2>&1 || {
  echo "::error::gh is required to publish or verify a GitHub release" >&2
  exit 1
}
command -v cosign >/dev/null 2>&1 || {
  echo "::error::cosign is required to sign SHA256SUMS and the SBOM" >&2
  exit 1
}

if [[ "$release_kind" == "stable" ]]; then
  remote_tag_commit="$(resolve_remote_tag_commit)" || exit 1
  [[ "$remote_tag_commit" == "$commit" ]] || {
    echo "::error::remote stable tag ${tag} points to ${remote_tag_commit}, expected ${commit}" >&2
    exit 1
  }
fi

if [[ "$release_kind" == "stable" ]] && gh release view "$tag" >/dev/null 2>&1; then
  verify_existing_stable_release
  exit 0
fi

command -v syft >/dev/null 2>&1 || {
  echo "::error::syft is required to attach a CycloneDX SBOM" >&2
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
  verify_sigstore_blob "$file"
}

sign_blob "${release_dir}/SHA256SUMS"
sign_blob "$sbom_file"
sign_blob "$product_sbom"

notes="$(mktemp)"
release_label="stable release"
release_notice="This is a stable release. Review the upgrade and rollback instructions before deployment."
if [[ "$release_kind" == "prerelease" ]]; then
  release_label="pre-release"
  release_notice="This is an alpha build, not a stable release. Configuration and APIs may change."
fi
cat >"$notes" <<EOF
CheeseWAF ${release_label} \`${tag}\`.

${release_notice}

Download the file that matches your OS and CPU:

| File | Platform |
| --- | --- |
EOF

platform_rows=0
while IFS= read -r artifact; do
  [[ -n "$artifact" ]] || continue
  artifact_name="$(basename "$artifact")"
  platform=""
  case "$artifact_name" in
    cheesewaf-amd64-linux-*.tar.gz) platform='Linux x86_64' ;;
    cheesewaf-arm64-linux-*.tar.gz) platform='Linux ARM64' ;;
    cheesewaf-loong64-linux-*.tar.gz) platform='Linux LoongArch64' ;;
    cheesewaf-amd64-darwin-*.tar.gz) platform='macOS Intel archive' ;;
    cheesewaf-arm64-darwin-*.tar.gz) platform='macOS Apple Silicon archive' ;;
    cheesewaf-amd64-darwin-*.dmg) platform='macOS Intel disk image' ;;
    cheesewaf-arm64-darwin-*.dmg) platform='macOS Apple Silicon disk image' ;;
    cheesewaf-amd64-windows-*-setup.exe) platform='Windows x86_64 GUI installer' ;;
    cheesewaf-arm64-windows-*-setup.exe) platform='Windows ARM64 GUI installer' ;;
    cheesewaf-amd64-windows-*.exe) platform='Windows x86_64 single-file CLI' ;;
    cheesewaf-arm64-windows-*.exe) platform='Windows ARM64 single-file CLI' ;;
    cheesewaf-amd64-windows-*.zip) platform='Windows x86_64 portable folder' ;;
    cheesewaf-arm64-windows-*.zip) platform='Windows ARM64 portable folder' ;;
  esac
  [[ -n "$platform" ]] || continue
  printf '| `%s` | %s |\n' "$artifact_name" "$platform" >>"$notes"
  platform_rows=$((platform_rows + 1))
done < <(
  find "$release_dir" -maxdepth 1 -type f \
    \( -name '*.tar.gz' -o -name '*.zip' -o -name '*.exe' -o -name '*.dmg' \) \
    -print | sort
)

if [[ "$platform_rows" -eq 0 ]]; then
  printf '| (none) | No platform archives were produced. |\n' >>"$notes"
fi

cat >>"$notes" <<'EOF'

Linux archives include `systemd/cheesewaf.service`. Verify downloads with `SHA256SUMS`.
Desktop artifacts are optional and are not part of the server release guarantee.

A source-tree CycloneDX SBOM is attached as `cheesewaf.cdx.json`, and a product-level SBOM for the release artifacts is attached as `cheesewaf-artifacts.cdx.json` (or `artifacts.manifest.json` when the artifact scan falls back). `SHA256SUMS` and the SBOM(s) are signed with Sigstore keyless identities from GitHub Actions. Verify:

```
cosign verify-blob --bundle SHA256SUMS.bundle \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
EOF
printf "  %s '%s' %s\n" "$identity_flag" "$identity_value" "\\" >>"$notes"
cat >>"$notes" <<'EOF'
  SHA256SUMS
```
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

if [[ "$release_kind" == "stable" ]]; then
  stable_release_validate_top_level "$release_dir" "stable release" "$product_version" || exit 1
  stable_release_require_archives "$release_dir" "$product_version" || exit 1
  for required_asset in \
    SHA256SUMS \
    SHA256SUMS.bundle \
    cheesewaf.cdx.json \
    cheesewaf.cdx.json.bundle; do
    [[ -s "${release_dir}/${required_asset}" ]] || {
      echo "::error::stable server release is missing signed metadata: ${required_asset}" >&2
      exit 1
    }
  done
  if [[ ! -s "$product_sbom" || ! -s "${product_sbom}.bundle" ]]; then
    echo "::error::stable server release is missing the signed product SBOM" >&2
    exit 1
  fi
fi

if [[ "$release_kind" == "prerelease" ]] && gh release view "$tag" >/dev/null 2>&1; then
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
    --verify-tag \
    --title "$tag" \
    --notes-file "$notes" \
    "${assets[@]}"
fi
