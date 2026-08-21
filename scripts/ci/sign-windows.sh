#!/usr/bin/env bash
set -euo pipefail

# Authenticode-sign PE files when WINDOWS_CERT_P12 (base64 PKCS#12) is set.
# No-op when the certificate is absent so CI stays green without a code-signing cert.

if [[ $# -lt 1 ]]; then
  echo "usage: sign-windows.sh file.exe [file.exe ...]" >&2
  exit 2
fi

if [[ -z "${WINDOWS_CERT_P12:-}" ]]; then
  echo "WINDOWS_CERT_P12 unset; skipping Authenticode signing"
  exit 0
fi

command -v osslsigncode >/dev/null 2>&1 || {
  echo "::error::WINDOWS_CERT_P12 is set but osslsigncode is not installed" >&2
  exit 1
}

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
p12="${work}/cert.p12"
printf '%s' "$WINDOWS_CERT_P12" | base64 --decode >"$p12"
[[ -s "$p12" ]] || {
  echo "::error::WINDOWS_CERT_P12 did not decode to a PKCS#12 file" >&2
  exit 1
}

pass_args=()
if [[ -n "${WINDOWS_CERT_PASSWORD:-}" ]]; then
  pass_args=(-pass "$WINDOWS_CERT_PASSWORD")
fi

for file in "$@"; do
  [[ -f "$file" ]] || {
    echo "::error::missing PE file: ${file}" >&2
    exit 1
  }
  signed="${work}/$(basename "$file").signed"
  osslsigncode sign \
    -pkcs12 "$p12" \
    "${pass_args[@]}" \
    -n "CheeseWAF" \
    -i "https://github.com/LaokeQwQ/CheeseWAF" \
    -t http://timestamp.digicert.com \
    -in "$file" \
    -out "$signed"
  mv "$signed" "$file"
  echo "signed ${file}"
done
