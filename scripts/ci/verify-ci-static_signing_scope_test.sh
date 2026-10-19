#!/usr/bin/env bash
set -euo pipefail

root="$(git rev-parse --show-toplevel)"
verifier="${root}/scripts/ci/verify-ci-static.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

valid_workflow="${tmp}/valid.yml"
cat >"$valid_workflow" <<'EOF'
env:
  WINDOWS_CERT_P12: "${{ github.ref_type == 'tag' && startsWith(github.ref_name, 'v') && github.ref_protected && secrets.WINDOWS_CERT_P12 || '' }}"
  MACOS_P12_BASE64: "${{ github.ref_type == 'tag' && startsWith(github.ref_name, 'v') && github.ref_protected && secrets.MACOS_P12_BASE64 || '' }}"
jobs:
  package:
    env:
      WINDOWS_CERT_P12: "${{ github.ref_type == 'tag' && startsWith(github.ref_name, 'v') && github.ref_protected && secrets.WINDOWS_CERT_P12 || '' }}"
      MACOS_P12_BASE64: "${{ github.ref_type == 'tag' && startsWith(github.ref_name, 'v') && github.ref_protected && secrets.MACOS_P12_BASE64 || '' }}"
EOF

bash "$verifier" --check-protected-tag-secret-scope "$valid_workflow" WINDOWS_CERT_P12
bash "$verifier" --check-protected-tag-secret-scope "$valid_workflow" MACOS_P12_BASE64

# Include names with common prefixes so APPLE_API_KEY_ID is not mistaken for
# another occurrence of APPLE_API_KEY.
for secret in WINDOWS_CERT_PASSWORD MACOS_P12_PASSWORD MACOS_CODESIGN_IDENTITY APPLE_API_KEY APPLE_API_KEY_ID APPLE_API_ISSUER; do
  printf '      %s: "${{ github.ref_type == '\''tag'\'' && startsWith(github.ref_name, '\''v'\'') && github.ref_protected && secrets.%s || '\'''\'' }}"\n' "$secret" "$secret" >>"$valid_workflow"
done
bash "$verifier" --check-signing-secret-scopes "$valid_workflow"

for secret in WINDOWS_CERT_P12 WINDOWS_CERT_PASSWORD MACOS_P12_BASE64 MACOS_P12_PASSWORD MACOS_CODESIGN_IDENTITY APPLE_API_KEY APPLE_API_KEY_ID APPLE_API_ISSUER; do
  for expression in \
    "github.ref_type == 'tag' && startsWith(github.ref_name, 'v') && github.ref_protected || secrets.${secret}" \
    "github.ref_type == 'tag' || startsWith(github.ref_name, 'v') && github.ref_protected && secrets.${secret}" \
    "github.ref_type == 'tag' && startsWith(github.ref_name, 'v') || github.ref_protected && secrets.${secret}" \
    "github.ref_type == 'tag' && startsWith(github.ref_name, 'v') && !github.ref_protected && secrets.${secret}" \
    "secrets.${secret}" \
    "secrets['${secret}']"; do
    unsafe_workflow="${tmp}/unsafe.yml"
    cp "$valid_workflow" "$unsafe_workflow"
    printf '      UNSAFE: "${{ %s }}"\n' "$expression" >>"$unsafe_workflow"
    if bash "$verifier" --check-signing-secret-scopes "$unsafe_workflow" >"${tmp}/unsafe.log" 2>&1; then
      echo "::error::unsafe signing expression was accepted: ${expression}" >&2
      exit 1
    fi
  done
done

unscoped_workflow="${tmp}/unscoped.yml"
cp "$valid_workflow" "$unscoped_workflow"
printf '%s\n' '  WINDOWS_CERT_P12_UNSCOPED: "${{ secrets.WINDOWS_CERT_P12 }}"' >>"$unscoped_workflow"
if bash "$verifier" --check-protected-tag-secret-scope "$unscoped_workflow" WINDOWS_CERT_P12 >"${tmp}/unscoped.log" 2>&1; then
  echo "::error::unscoped Windows signing secret reference was accepted" >&2
  exit 1
fi

duplicate_workflow="${tmp}/duplicate.yml"
cp "$valid_workflow" "$duplicate_workflow"
printf '%s\n' '  WINDOWS_CERT_P12_DUPLICATE: "${{ github.ref_type == '\''tag'\'' && startsWith(github.ref_name, '\''v'\'') && github.ref_protected && secrets.WINDOWS_CERT_P12 || secrets.WINDOWS_CERT_P12 }}"' >>"$duplicate_workflow"
if bash "$verifier" --check-protected-tag-secret-scope "$duplicate_workflow" WINDOWS_CERT_P12 >"${tmp}/duplicate.log" 2>&1; then
  echo "::error::duplicate Windows signing secret references on one line were accepted" >&2
  exit 1
fi

echo "protected signing secret scope tests passed."
