#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bin" "$tmp/release"
make_pkg() { local arch="$1"; local dir="$tmp/pkg-$arch"; mkdir -p "$dir/cheesewaf-$arch-darwin-1.0.0"; : >"$dir/cheesewaf-$arch-darwin-1.0.0/cheesewaf"; : >"$dir/cheesewaf-$arch-darwin-1.0.0/cheesewaf-gui"; chmod +x "$dir/cheesewaf-$arch-darwin-1.0.0/"*; tar -czf "$tmp/release/cheesewaf-$arch-darwin-1.0.0.tar.gz" -C "$dir" .; }
make_pkg arm64; make_pkg amd64
printf '#!/usr/bin/env bash\necho Darwin\n' >"$tmp/bin/uname"
for tool in security codesign xattr; do printf '#!/usr/bin/env bash\nexit 0\n' >"$tmp/bin/$tool"; done
cat >"$tmp/bin/hdiutil" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
state=${FAKE_STATE:?}; action=${1:-}; shift || true; attached=${state}.attached; seq=${state}.seq; log=${state}.log; touch "$log"; count=$(cat "$seq" 2>/dev/null || echo 0)
case "$action" in
create) echo create >>"$log"; : >"${@: -1}"; echo $((count+1)) >"$seq";;
attach) mount=''; while [[ $# -gt 0 ]]; do [[ $1 == -mountpoint ]] && { shift; mount=$1; }; shift; done; device="/dev/fake-$count"; printf '%s|%s\n' "$device" "$mount" >"$attached"; echo "attach $device $mount" >>"$log"; printf '%s Apple_HFS %s\n' "$device" "$mount";;
info) echo "info ${FAKE_MODE:-delayed}" >>"$log"; [[ ${FAKE_MODE:-delayed} == info-fail ]] && { echo 'hdiutil info failed' >&2; exit 7; }; [[ ${FAKE_MODE:-delayed} == info-timeout ]] && while :; do :; done; [[ -s "$attached" ]] && cat "$attached"; exit 0;;
detach) echo detach-attempt >>"$log"; [[ -s "$attached" ]] || { echo 'no such device' >&2; exit 3; }; if [[ ${FAKE_MODE:-delayed} == force-timeout && "$*" == *-force* ]]; then echo force-timeout >>"$log"; while :; do :; done; fi; if [[ ${FAKE_MODE:-delayed} == unrelated ]]; then echo 'hdiutil: detach failed - I/O error' >&2; exit 2; fi; if [[ ${FAKE_MODE:-delayed} == permanent || ! -f ${state}.detached ]]; then [[ ${FAKE_MODE:-delayed} == delayed || ${FAKE_MODE:-delayed} == convert-fail ]] && : >"${state}.detached"; echo 'hdiutil: detach failed - Resource busy' >&2; exit 1; fi; rm -f "$attached"; echo detach >>"$log";;
convert) [[ -s "$attached" ]] && { echo 'convert while attached' >&2; exit 9; }; [[ ${FAKE_MODE:-delayed} == convert-fail ]] && { echo 'convert failed' >&2; exit 8; }; : >"${@: -1}"; echo convert >>"$log";;
*) exit 0;; esac
EOF
printf '#!/usr/bin/env bash\nexec /bin/sleep 0.2\n' >"$tmp/bin/sleep"
chmod +x "$tmp/bin"/*
run_case() { local mode="$1"; PATH="$tmp/bin:$PATH" FAKE_STATE="$tmp/state" FAKE_MODE="$mode" bash "$root/scripts/ci/package-macos-dmg.sh" "$tmp/release"; }
: >"$tmp/state.seq"; run_case delayed; grep -q '^convert$' "$tmp/state.log"; [[ $(grep -c '^detach$' "$tmp/state.log") -ge 2 ]] || exit 1
rm -f "$tmp/state.log" "$tmp/state.attached" "$tmp/state.detached"; : >"$tmp/state.seq"; if run_case convert-fail; then exit 1; fi; [[ ! -e "$tmp/state.attached" ]] || exit 1
rm -f "$tmp/state.log" "$tmp/state.attached" "$tmp/state.detached"; : >"$tmp/state.seq"; if run_case permanent; then exit 1; fi
rm -f "$tmp/state.log" "$tmp/state.attached" "$tmp/state.detached"; : >"$tmp/state.seq"; if run_case unrelated; then exit 1; fi
rm -f "$tmp/state.log" "$tmp/state.attached" "$tmp/state.detached"; : >"$tmp/state.seq"; if run_case info-fail; then exit 1; fi; ! grep -q '^convert$' "$tmp/state.log"; grep -q '^detach-attempt$' "$tmp/state.log"
printf '#!/usr/bin/env bash\nexec /bin/sleep 0.2\n' >"$tmp/bin/sleep"
chmod +x "$tmp/bin/sleep"
rm -f "$tmp/state.log" "$tmp/state.attached" "$tmp/state.detached"; : >"$tmp/state.seq"; if run_case info-timeout; then exit 1; fi; ! grep -q '^convert$' "$tmp/state.log"; grep -q '^info info-timeout$' "$tmp/state.log"; [[ $(grep -c '^detach-attempt$' "$tmp/state.log") -ge 2 ]]
rm -f "$tmp/state.log" "$tmp/state.attached" "$tmp/state.detached"; : >"$tmp/state.seq"; if run_case force-timeout; then exit 1; fi; ! grep -q '^convert$' "$tmp/state.log"; grep -q '^force-timeout$' "$tmp/state.log"; [[ $(grep -c '^detach-attempt$' "$tmp/state.log") -ge 2 ]]
echo 'macOS DMG full lifecycle regression tests passed'
