#!/usr/bin/env bash
set -euo pipefail

ansible_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mode="all"
case "${1:-}" in
  "") ;;
  --static-only) mode="static" ;;
  -h|--help) echo "usage: $0 [--static-only]"; exit 0 ;;
  *) echo "unknown option: $1" >&2; exit 2 ;;
esac

fail() { echo "FAIL: $*" >&2; exit 1; }
has() { grep -Eq -- "$2" "$ansible_root/$1" || fail "$1: missing $3"; }
for file in single-node.yml production.yml full.yml vars/defaults.yml tasks/preflight.yml tasks/pigsty.yml tasks/bootstrap.yml; do
  [[ -r "$ansible_root/$file" ]] || fail "missing deployment contract: $file"
done
bash -n "$0"
has single-node.yml 'cheesewaf_storage_profile.*temporary' 'temporary single-node entry point'
has production.yml 'cheesewaf_storage_profile.*production' 'production entry point'
has full.yml 'cheesewaf_storage_profile.*production' 'production full entry point'
has full.yml 'tasks/pigsty.yml' 'explicit Pigsty hand-off'
has tasks/preflight.yml 'native-raft' 'native-raft contract'
has tasks/preflight.yml 'external' 'external PostgreSQL/Redis contract'
has tasks/preflight.yml 'ErrProductionStorageUnavailable' 'production fail-closed boundary'
has tasks/preflight.yml 'CWEDP' 'CWEDP-only plugin boundary'
has tasks/pigsty.yml 'rev-parse' 'verified immutable adapter revision'
has tasks/pigsty.yml 'porcelain' 'clean adapter checkout check'
has tasks/pigsty.yml 'not ansible_check_mode' 'check-mode adapter mutation guard'
has tasks/bootstrap.yml 'checksum_algorithm: sha256' 'pinned local agent artifact'
has tasks/bootstrap.yml 'not ansible_check_mode' 'check-mode host mutation guard'
has vars/defaults.yml '^cheesewaf_offline: true$' 'offline default'
if grep -REn 'ansible\.builtin\.(get_url|uri|git|shell|script|unarchive)|allow_unwired_production' "$ansible_root" --include='*.yml' --include='*.yaml'; then
  fail 'deployment must not download artifacts, run shell scripts, or bypass unavailable production startup'
fi
echo 'PASS: offline static deployment contract'
[[ "$mode" == static ]] && exit 0

ansible_playbook="${ANSIBLE_PLAYBOOK:-ansible-playbook}"
command -v "$ansible_playbook" >/dev/null 2>&1 || fail 'ansible-playbook is required; provision it from approved offline media, or explicitly use --static-only'
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/cheesewaf-ansible-verify.XXXXXX")"
trap 'rm -rf "$work_dir"' EXIT INT TERM
export ANSIBLE_LOCAL_TEMP="$work_dir/local"
export ANSIBLE_REMOTE_TEMP="$work_dir/remote"
# Keep Ansible and ansible-lint caches inside the disposable verification
# directory.  A clean controller may have a read-only home directory, and
# verification must not depend on (or modify) a user's global ~/.ansible.
export ANSIBLE_HOME="$work_dir/ansible-home"
export XDG_CACHE_HOME="$work_dir/cache"
export ANSIBLE_NOCOLOR=1
export ANSIBLE_DEPRECATION_WARNINGS=False
inventory="$ansible_root/tests/inventory.yml"
for entry in single-node production full; do
  "$ansible_playbook" --syntax-check -i "$inventory" "$ansible_root/$entry.yml" >"$work_dir/syntax-$entry.log" 2>&1 || { cat "$work_dir/syntax-$entry.log"; fail "$entry syntax"; }
done
echo 'PASS: three entry-point syntax checks'

expect_pass() {
  local name="$1"
  shift
  "$ansible_playbook" -i "$inventory" --check "$@" >"$work_dir/$name.log" 2>&1 || { cat "$work_dir/$name.log"; fail "$name unexpectedly failed"; }
  grep -Eq 'changed=0 .*failed=0' "$work_dir/$name.log" || { cat "$work_dir/$name.log"; fail "$name was not a read-only check"; }
  echo "PASS: $name"
}
expect_fail() {
  local name="$1" expected="$2"
  shift 2
  if "$ansible_playbook" -i "$inventory" --check "$@" >"$work_dir/$name.log" 2>&1; then
    cat "$work_dir/$name.log"; fail "$name unexpectedly accepted invalid deployment"
  fi
  grep -Fq "$expected" "$work_dir/$name.log" || { cat "$work_dir/$name.log"; fail "$name failed for the wrong reason"; }
  echo "PASS: $name rejected"
}
expect_pass temporary-no-services "$ansible_root/single-node.yml"
expect_fail temporary-with-pigsty 'temporary must not provision PostgreSQL or Redis' "$ansible_root/single-node.yml" -e cheesewaf_pigsty_enabled=true
expect_fail full-with-temporary 'full.yml requires production' "$ansible_root/full.yml" -e cheesewaf_storage_profile=temporary
expect_fail production-without-dependencies 'production requires explicit external PostgreSQL, external Redis and native-raft' "$ansible_root/production.yml"
expect_pass production-provision-only "$ansible_root/production.yml" -e "@$ansible_root/tests/production-contract.yml" -e cheesewaf_provision_only=true
expect_pass full-provision-only "$ansible_root/full.yml" -e "@$ansible_root/tests/production-contract.yml" -e cheesewaf_provision_only=true
expect_fail production-runtime-unavailable 'ErrProductionStorageUnavailable' "$ansible_root/production.yml" -e "@$ansible_root/tests/production-contract.yml"
expect_fail plugin-push 'plugins are negotiated by CWEDP' "$ansible_root/single-node.yml" -e cheesewaf_plugin_push=true
expect_fail remote-management-without-tls 'remote management requires TLS, ACL, audit and rollback' "$ansible_root/single-node.yml" -e cheesewaf_management_listen=0.0.0.0:9443
expect_fail floating-pigsty-ref 'Pigsty requires a fixed version, immutable commit and local files' "$ansible_root/full.yml" -e "@$ansible_root/tests/production-contract.yml" -e cheesewaf_provision_only=true -e cheesewaf_pigsty_enabled=true -e cheesewaf_pigsty_ref=main
if command -v ansible-lint >/dev/null 2>&1; then
  (cd "$ansible_root" && ansible-lint --offline -c .ansible-lint single-node.yml production.yml full.yml)
  echo 'PASS: ansible-lint --offline'
else
  echo 'SKIP: ansible-lint is not installed; syntax and behavior checks passed'
fi
echo 'PASS: Ansible offline verification; no database, Redis, Pigsty or systemd service was contacted'
