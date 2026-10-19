#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
installer="${repo_root}/scripts/ci/install-linux.sh"
test_root="$(mktemp -d)"
test_root="$(cd "$test_root" && pwd -P)"
trap 'rm -rf "$test_root"' EXIT
export INSTALL_TEST_HOST_OS="$(uname -s)"

fail() { echo "::error::$*" >&2; exit 1; }

# Run the real installer against an isolated archive. Stub only privileged
# account/service commands; filesystem copies, permission changes, and path
# checks still execute against the temporary installation.
uname() { printf 'Linux\n'; }
id() {
  if [[ "$*" == '-u' ]]; then printf '0\n'; return; fi
  [[ -f "${INSTALL_TEST_CASE}/user" ]] || return 1
  case "${1:-}" in -u|-g) printf '1001\n';; *) printf 'uid=1001(cheesewaf) gid=1001(cheesewaf)\n';; esac
}
getent() { [[ -f "${INSTALL_TEST_CASE}/group" ]]; }
groupadd() { touch "${INSTALL_TEST_CASE}/group"; }
useradd() {
  printf 'useradd %s\n' "$*" >>"${INSTALL_TEST_CASE}/commands"
  [[ " $* " == *' --gid cheesewaf '* ]] || return 9
  [[ -f "${INSTALL_TEST_CASE}/group" ]] || return 10
  touch "${INSTALL_TEST_CASE}/user"
  if [[ "$INSTALL_TEST_SCENARIO" == late_symlink ]]; then
    ln -sf "${INSTALL_TEST_CASE}/sentinel" "${CHEESEWAF_CONFIG_DIR}/cheesewaf.yaml"
  fi
}
chown() { printf 'chown %s\n' "$*" >>"${INSTALL_TEST_CASE}/commands"; }
install() { printf 'install %s\n' "$*" >>"${INSTALL_TEST_CASE}/commands"; command install "$@"; }
ip() { return 0; }
systemctl() {
  printf 'systemctl %s\n' "$*" >>"${INSTALL_TEST_CASE}/commands"
  case "$1" in
    is-active)
      [[ -f "${INSTALL_TEST_CASE}/active" ]] || return 3
      [[ "${2:-}" == --quiet ]] || printf 'active\n'
      ;;
    stop)
      [[ "$INSTALL_TEST_SCENARIO" != stop_failure ]] || return 1
      rm -f "${INSTALL_TEST_CASE}/active"
      if [[ "$INSTALL_TEST_SCENARIO" == service_symlink ]]; then
        ln -sf "${INSTALL_TEST_CASE}/sentinel" "${CHEESEWAF_CONFIG_DIR}/cheesewaf.yaml"
      fi
      ;;
    restart) touch "${INSTALL_TEST_CASE}/active" ;;
  esac
}
sed() {
  if [[ "$INSTALL_TEST_HOST_OS" == Darwin && "${1:-}" == -i ]]; then
    shift
    local arg
    local args=()
    for arg in "$@"; do
      [[ "$arg" != *'}' ]] || arg="${arg%\}};}"
      args+=("$arg")
    done
    command sed -i '' "${args[@]}"
  else
    command sed "$@"
  fi
}
export -f uname id getent groupadd useradd chown install ip systemctl sed

for scenario in fresh upgrade service_symlink late_symlink dangling_symlink stop_failure; do
  export INSTALL_TEST_SCENARIO="$scenario"
  export INSTALL_TEST_CASE="${test_root}/${scenario}"
  export CHEESEWAF_INSTALL_DIR="${INSTALL_TEST_CASE}/app"
  export CHEESEWAF_PREFIX="$CHEESEWAF_INSTALL_DIR"
  export CHEESEWAF_CONFIG_DIR="${CHEESEWAF_INSTALL_DIR}/config"
  export CHEESEWAF_DATA_DIR="${CHEESEWAF_INSTALL_DIR}/data"
  export CHEESEWAF_WEB_DIR="${CHEESEWAF_INSTALL_DIR}/web"
  export CHEESEWAF_LOG_DIR="${CHEESEWAF_INSTALL_DIR}/logs"
  export CHEESEWAF_UNIT_DIR="${INSTALL_TEST_CASE}/units"
  export CHEESEWAF_LANG=en CHEESEWAF_SECURITY_ENTRY=RegressionEntry123
  export CHEESEWAF_SETUP_URL_WAIT_SECONDS=0 CHEESEWAF_SHOW_SECRETS=0 CHEESEWAF_NO_START=0
  export CHEESEWAF_ADMIN_LISTEN=127.0.0.1:9443 CHEESEWAF_ADMIN_PUBLIC_HOST=127.0.0.1
  mkdir -p "${INSTALL_TEST_CASE}/archive/configs" "${INSTALL_TEST_CASE}/archive/web/dist" "${INSTALL_TEST_CASE}/archive/systemd" "$CHEESEWAF_CONFIG_DIR"
  cp "${repo_root}/configs/cheesewaf.yaml" "${INSTALL_TEST_CASE}/archive/configs/cheesewaf.yaml"
  cp "${repo_root}/deploy/systemd/cheesewaf.service" "${INSTALL_TEST_CASE}/archive/systemd/cheesewaf.service"
  printf '#!/usr/bin/env bash\nprintf "test-version\\n"\n' >"${INSTALL_TEST_CASE}/archive/cheesewaf"
  chmod +x "${INSTALL_TEST_CASE}/archive/cheesewaf"
  printf 'test web\n' >"${INSTALL_TEST_CASE}/archive/web/dist/index.html"
  printf 'do not touch\n' >"${INSTALL_TEST_CASE}/sentinel"
  if [[ "$scenario" != fresh ]]; then
    cp "${INSTALL_TEST_CASE}/archive/configs/cheesewaf.yaml" "${CHEESEWAF_CONFIG_DIR}/cheesewaf.yaml"
    command sed -e 's#path: /admin#path: /ExistingEntry123#' "${CHEESEWAF_CONFIG_DIR}/cheesewaf.yaml" >"${INSTALL_TEST_CASE}/existing.yaml"
    cp "${INSTALL_TEST_CASE}/existing.yaml" "${CHEESEWAF_CONFIG_DIR}/cheesewaf.yaml"
    touch "${INSTALL_TEST_CASE}/active"
  fi
  if [[ "$scenario" == upgrade ]]; then touch "${INSTALL_TEST_CASE}/user" "${INSTALL_TEST_CASE}/group"; fi
  if [[ "$scenario" == dangling_symlink ]]; then
    ln -sf "${INSTALL_TEST_CASE}/missing" "${CHEESEWAF_CONFIG_DIR}/cheesewaf.yaml"
  fi
  status=0
  (cd "${INSTALL_TEST_CASE}/archive" && bash "$installer") >"${INSTALL_TEST_CASE}/output" 2>&1 || status=$?
  if [[ "$scenario" == fresh || "$scenario" == upgrade ]]; then
    if ((status != 0)); then command cat "${INSTALL_TEST_CASE}/output"; fail "${scenario} installation failed"; fi
    if [[ "$scenario" == upgrade ]]; then
      cmp "${INSTALL_TEST_CASE}/existing.yaml" "${CHEESEWAF_CONFIG_DIR}/cheesewaf.yaml" || fail "upgrade replaced existing configuration"
    fi
    grep -q '^systemctl restart cheesewaf$' "${INSTALL_TEST_CASE}/commands" || fail "service was not restarted"
  else
    ((status != 0)) || fail "${scenario} should reject the installation"
    if [[ "$scenario" == stop_failure ]]; then
      ! grep -q '^install ' "${INSTALL_TEST_CASE}/commands" || fail "failed service stop allowed privileged writes"
    else
      grep -q 'existing config file must be a regular file' "${INSTALL_TEST_CASE}/output" || fail "${scenario} did not reject the unsafe config file"
    fi
    ! grep -q '^chown ' "${INSTALL_TEST_CASE}/commands" || {
      [[ "$scenario" == late_symlink ]] || fail "unsafe config reached ownership changes"
      ! grep -q '^chown -R ' "${INSTALL_TEST_CASE}/commands" || fail "late symlink reached ownership reconciliation"
    }
    [[ "$(command cat "${INSTALL_TEST_CASE}/sentinel")" == 'do not touch' ]] || fail "symlink target was overwritten"
    ! grep -q '^systemctl restart ' "${INSTALL_TEST_CASE}/commands" || fail "unsafe installation restarted the service"
  fi
  if [[ "$scenario" != fresh ]]; then
    first_mutation="$(grep -E '^(install |chown |systemctl stop )' "${INSTALL_TEST_CASE}/commands" | head -n 1)"
    [[ "$first_mutation" == 'systemctl stop cheesewaf' ]] || fail "service was not stopped before configuration writes"
  fi
done

echo 'Linux installer account and configuration lifecycle tests passed.'
