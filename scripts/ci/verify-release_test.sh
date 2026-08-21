#!/usr/bin/env bash
set -euo pipefail

root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$root"

fail() {
  echo "::error::$*" >&2
  exit 1
}

expect_match() {
  local name="$1"
  local want="$2"
  local got
  got="$(bash scripts/ci/verify-release.sh --print-host-match "$name")"
  [[ "$got" == "$want" ]] || fail "host match ${name}: got ${got}, want ${want}"
}

host_uname="$(uname -s)"
host_arch="$(uname -m)"
case "$host_uname" in
  Darwin)
    expect_match 'cheesewaf-arm64-darwin-0.1.0-PreTest.tar.gz' "$([[ "$host_arch" == arm64 || "$host_arch" == aarch64 ]] && echo yes || echo no)"
    expect_match 'cheesewaf-amd64-darwin-0.1.0-PreTest.tar.gz' "$([[ "$host_arch" == x86_64 || "$host_arch" == amd64 ]] && echo yes || echo no)"
    expect_match 'cheesewaf-amd64-linux-0.1.0-PreTest.tar.gz' no
    ;;
  Linux)
    expect_match 'cheesewaf-amd64-linux-0.1.0-PreTest.tar.gz' "$([[ "$host_arch" == x86_64 || "$host_arch" == amd64 ]] && echo yes || echo no)"
    expect_match 'cheesewaf-arm64-linux-0.1.0-PreTest.tar.gz' "$([[ "$host_arch" == arm64 || "$host_arch" == aarch64 ]] && echo yes || echo no)"
    expect_match 'cheesewaf-arm64-darwin-0.1.0-PreTest.tar.gz' no
    ;;
esac
expect_match 'cheesewaf-sparc-darwin-0.1.0-PreTest.tar.gz' no

if ! type mapfile >/dev/null 2>&1; then
  echo "verify-release tests passed (host match only; bash lacks mapfile)."
  exit 0
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

make_package() {
  local dest="$1"
  local branch="$2"
  local channel="$3"
  local with_gui="$4"
  mkdir -p "${dest}/web/dist" "${dest}/configs"
  printf '<html></html>\n' >"${dest}/web/dist/index.html"
  printf 'listen: 127.0.0.1:8080\n' >"${dest}/configs/cheesewaf.yaml"
  printf 'version=0.1.0-PreTest\nchannel=%s\nbranch=%s\ncommit=abc123\nbuild_time=2026-08-20T00:00:00Z\n' \
    "$channel" "$branch" >"${dest}/VERSION"
  printf '{\n  "name": "CheeseWAF",\n  "version": "0.1.0-PreTest",\n  "channel": "%s",\n  "branch": "%s"\n}\n' \
    "$channel" "$branch" >"${dest}/release.json"
  : >"${dest}/cheesewaf"
  chmod +x "${dest}/cheesewaf"
  : >"${dest}/waf-cli"
  chmod +x "${dest}/waf-cli"
  if [[ "$with_gui" == "yes" ]]; then
    : >"${dest}/cheesewaf-gui"
    chmod +x "${dest}/cheesewaf-gui"
  fi
}

pack_and_sum() {
  local work="$1"
  local name="$2"
  tar -C "$work" -czf "${work}/${name}" pkg
  (
    cd "$work"
    sha256sum "$name" >SHA256SUMS
  )
}

run_static() {
  VERIFY_RELEASE_STATIC_ONLY=1 bash scripts/ci/verify-release.sh "$1"
}

goreleaser_dir="${tmp}/goreleaser"
mkdir -p "${goreleaser_dir}/pkg"
make_package "${goreleaser_dir}/pkg" goreleaser release no
pack_and_sum "$goreleaser_dir" 'cheesewaf-sparc-darwin-0.0.1-PreTest.tar.gz'
run_static "$goreleaser_dir" || fail "GoReleaser darwin snapshot without GUI must pass"

channel_missing="${tmp}/channel-missing"
mkdir -p "${channel_missing}/pkg"
make_package "${channel_missing}/pkg" canary PreTest no
pack_and_sum "$channel_missing" 'cheesewaf-sparc-darwin-0.1.0-PreTest.tar.gz'
if run_static "$channel_missing"; then
  fail "channel darwin package without GUI must fail"
fi

channel_ok="${tmp}/channel-ok"
mkdir -p "${channel_ok}/pkg"
make_package "${channel_ok}/pkg" canary PreTest yes
pack_and_sum "$channel_ok" 'cheesewaf-sparc-darwin-0.1.0-PreTest.tar.gz'
run_static "$channel_ok" || fail "channel darwin package with GUI must pass"

echo "verify-release tests passed."
