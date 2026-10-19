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
