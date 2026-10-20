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
install() {
  printf 'install %s\n' "$*" >>"${INSTALL_TEST_CASE}/commands"
  command install "$@" || return
  if [[ "${!#}" == "${CHEESEWAF_PREFIX}/bin/cheesewaf" ]]; then
    case "$INSTALL_TEST_SCENARIO" in
      binary_install_failure|restore_failure|inactive_failure) return 1 ;;
      binary_interrupt) kill -TERM "$$" ;;
      changed_config) printf '\n# operator change\n' >>"${CHEESEWAF_CONFIG_DIR}/cheesewaf.yaml"; return 1 ;;
      root_symlink)
        command mv "$CHEESEWAF_CONFIG_DIR" "${INSTALL_TEST_CASE}/preserved-config"
        ln -s "${INSTALL_TEST_CASE}/outside" "$CHEESEWAF_CONFIG_DIR"
        return 1 ;;
    esac
  fi
}
cp() {
  command cp "$@" || return
  if [[ "$INSTALL_TEST_SCENARIO" == web_copy_failure && " $* " == *' ./web/dist/. '* ]]; then return 1; fi
}
mv() {
  if [[ "$INSTALL_TEST_SCENARIO" == restore_failure && "${1:-}" == -f && " $* " == *'.restore.'* ]]; then return 1; fi
  command mv "$@"
}
stat() {
  if [[ "$INSTALL_TEST_HOST_OS" == Darwin && "${1:-}" == -c ]]; then
    if [[ "$2" == $'%a\n%u\n%g' ]]; then
      command stat -f $'%Lp\n%u\n%g' "${!#}"
    else
      command stat -f '%Lp %u %g' "${!#}"
    fi
  else
    command stat "$@"
  fi
}
mktemp() {
  if [[ "$#" == 1 && "$1" == -d ]]; then
    command mktemp -d "${INSTALL_TEST_CASE}/backup.XXXXXX"
  else
    command mktemp "$@"
  fi
}
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
      if [[ "$INSTALL_TEST_SCENARIO" == stop_interrupt && ! -e "${INSTALL_TEST_CASE}/interrupted" ]]; then
        touch "${INSTALL_TEST_CASE}/interrupted"
        kill -TERM "$$"
      fi
      ;;
    restart)
      touch "${INSTALL_TEST_CASE}/active"
      if [[ "$INSTALL_TEST_SCENARIO" == inactive_restart ]]; then rm -f "${INSTALL_TEST_CASE}/active"; fi
      [[ "$INSTALL_TEST_SCENARIO" != restart_failure ]] || return 1
      ;;
    start)
      grep -q old-version "${CHEESEWAF_PREFIX}/bin/cheesewaf" || return 90
      cmp -s "${INSTALL_TEST_CASE}/existing.yaml" "${CHEESEWAF_CONFIG_DIR}/cheesewaf.yaml" || return 91
      cmp -s "${INSTALL_TEST_CASE}/existing.service" "${CHEESEWAF_UNIT_DIR}/cheesewaf.service" || return 92
      [[ "$(command cat "${CHEESEWAF_WEB_DIR}/index.html")" == old-web ]] || return 93
      touch "${INSTALL_TEST_CASE}/active"
      ;;
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
export -f uname id getent groupadd useradd chown install cp mv stat mktemp ip systemctl sed

for scenario in fresh upgrade service_symlink late_symlink dangling_symlink stop_failure \
  public_reoptin_failure invalid_wait invalid_host invalid_listener invalid_entry \
  binary_install_failure web_copy_failure stop_interrupt binary_interrupt restart_failure \
  root_symlink changed_config restore_failure inactive_failure inactive_restart; do
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
  export CHEESEWAF_ADMIN_PUBLIC=0
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
    chmod 0640 "${CHEESEWAF_CONFIG_DIR}/cheesewaf.yaml"
    ln "${CHEESEWAF_CONFIG_DIR}/cheesewaf.yaml" "${INSTALL_TEST_CASE}/original-config-inode"
    chmod 01770 "$CHEESEWAF_CONFIG_DIR"
    stat -c '%a %u %g' "$CHEESEWAF_CONFIG_DIR" >"${INSTALL_TEST_CASE}/existing.config-mode"
    mkdir -p "${CHEESEWAF_PREFIX}/bin" "$CHEESEWAF_WEB_DIR" "$CHEESEWAF_UNIT_DIR" "$CHEESEWAF_DATA_DIR" "$CHEESEWAF_LOG_DIR"
    printf '#!/usr/bin/env bash\nprintf "old-version\\n"\n' >"${CHEESEWAF_PREFIX}/bin/cheesewaf"
    chmod +x "${CHEESEWAF_PREFIX}/bin/cheesewaf"
    printf 'old-web\n' >"${CHEESEWAF_WEB_DIR}/index.html"
    cp "${repo_root}/deploy/systemd/cheesewaf.service" "${CHEESEWAF_UNIT_DIR}/cheesewaf.service"
    printf '\n# original unit\n' >>"${CHEESEWAF_UNIT_DIR}/cheesewaf.service"
    cp "${CHEESEWAF_UNIT_DIR}/cheesewaf.service" "${INSTALL_TEST_CASE}/existing.service"
    printf 'CHEESEWAF_ADMIN_PUBLIC_HOST=old.example\n' >"${CHEESEWAF_CONFIG_DIR}/admin.env"
    cp "${CHEESEWAF_CONFIG_DIR}/admin.env" "${INSTALL_TEST_CASE}/existing.env"
    printf 'user database\n' >"${CHEESEWAF_DATA_DIR}/database"
    chmod 0750 "$CHEESEWAF_DATA_DIR" "$CHEESEWAF_LOG_DIR" "${CHEESEWAF_PREFIX}/bin" "$CHEESEWAF_UNIT_DIR"
    touch "${INSTALL_TEST_CASE}/active"
    if [[ "$scenario" != late_symlink ]]; then touch "${INSTALL_TEST_CASE}/user" "${INSTALL_TEST_CASE}/group"; fi
  fi
  if [[ "$scenario" == dangling_symlink ]]; then
    ln -sf "${INSTALL_TEST_CASE}/missing" "${CHEESEWAF_CONFIG_DIR}/cheesewaf.yaml"
  fi
  case "$scenario" in
    public_reoptin_failure)
      command sed 's#admin_listen: "127.0.0.1:9443"#admin_listen: "0.0.0.0:9443"#' "${CHEESEWAF_CONFIG_DIR}/cheesewaf.yaml" >"${INSTALL_TEST_CASE}/public.yaml"
      cp "${INSTALL_TEST_CASE}/public.yaml" "${CHEESEWAF_CONFIG_DIR}/cheesewaf.yaml" ;;
    invalid_wait) export CHEESEWAF_SETUP_URL_WAIT_SECONDS=invalid ;;
    invalid_host) export CHEESEWAF_ADMIN_PUBLIC_HOST='bad/host' ;;
    invalid_listener) export CHEESEWAF_ADMIN_LISTEN='127.0.0.1:70000' ;;
    invalid_entry) export CHEESEWAF_SECURITY_ENTRY='invalid/entry' ;;
    root_symlink)
      mkdir "${INSTALL_TEST_CASE}/outside"
      printf 'outside file\n' >"${INSTALL_TEST_CASE}/outside/cheesewaf.yaml" ;;
    inactive_failure) rm -f "${INSTALL_TEST_CASE}/active" ;;
  esac
  status=0
  (cd "${INSTALL_TEST_CASE}/archive" && bash "$installer") >"${INSTALL_TEST_CASE}/output" 2>&1 || status=$?
  if [[ "$scenario" == fresh || "$scenario" == upgrade ]]; then
    if ((status != 0)); then command cat "${INSTALL_TEST_CASE}/output"; fail "${scenario} installation failed"; fi
    if [[ "$scenario" == upgrade ]]; then
      cmp "${INSTALL_TEST_CASE}/existing.yaml" "${CHEESEWAF_CONFIG_DIR}/cheesewaf.yaml" || fail "upgrade replaced existing configuration"
    fi
    grep -q '^systemctl restart cheesewaf$' "${INSTALL_TEST_CASE}/commands" || fail "service was not restarted"
  elif [[ "$scenario" == public_reoptin_failure || "$scenario" == invalid_* || "$scenario" == dangling_symlink ]]; then
    ((status != 0)) || fail "${scenario} should fail preflight"
    [[ -f "${INSTALL_TEST_CASE}/active" ]] || fail "preflight failure stopped the original service"
    if [[ -f "${INSTALL_TEST_CASE}/commands" ]]; then
      ! grep -Eq '^(systemctl stop |install |chown )' "${INSTALL_TEST_CASE}/commands" || fail "preflight failure mutated the installation"
    fi
  elif [[ "$scenario" == binary_install_failure || "$scenario" == web_copy_failure || "$scenario" == stop_interrupt || "$scenario" == binary_interrupt || "$scenario" == restart_failure || "$scenario" == inactive_restart ]]; then
    ((status != 0)) || fail "${scenario} must retain the original failure status"
    [[ -f "${INSTALL_TEST_CASE}/active" ]] || { command cat "${INSTALL_TEST_CASE}/output"; fail "${scenario} did not restore the old service"; }
    grep -q '^systemctl start cheesewaf$' "${INSTALL_TEST_CASE}/commands" || fail "${scenario} did not recover the previously running service"
    grep -q old-version "${CHEESEWAF_PREFIX}/bin/cheesewaf" || fail "${scenario} restarted a new binary"
    cmp "${INSTALL_TEST_CASE}/existing.yaml" "${CHEESEWAF_CONFIG_DIR}/cheesewaf.yaml" || fail "${scenario} changed runtime configuration"
    [[ "${INSTALL_TEST_CASE}/original-config-inode" -ef "${CHEESEWAF_CONFIG_DIR}/cheesewaf.yaml" ]] || fail "${scenario} replaced the user's config file"
    [[ "$(stat -c '%a %u %g' "${CHEESEWAF_CONFIG_DIR}/cheesewaf.yaml")" == 640\ * ]] || fail "${scenario} did not restore config permissions"
    cmp "${INSTALL_TEST_CASE}/existing.service" "${CHEESEWAF_UNIT_DIR}/cheesewaf.service" || fail "${scenario} left a partially rendered unit"
    cmp "${INSTALL_TEST_CASE}/existing.env" "${CHEESEWAF_CONFIG_DIR}/admin.env" || fail "${scenario} retained a new environment file"
    [[ "$(stat -c '%a %u %g' "$CHEESEWAF_CONFIG_DIR")" == "$(command cat "${INSTALL_TEST_CASE}/existing.config-mode")" ]] || fail "${scenario} did not restore config-directory access"
    for directory in "$CHEESEWAF_DATA_DIR" "$CHEESEWAF_LOG_DIR" "${CHEESEWAF_PREFIX}/bin" "$CHEESEWAF_UNIT_DIR"; do
      [[ "$(stat -c '%a %u %g' "$directory")" == 750\ * ]] || fail "${scenario} did not restore directory access: ${directory}"
    done
  else
    ((status != 0)) || fail "${scenario} should reject the installation"
    if [[ "$scenario" == stop_failure ]]; then
      ! grep -q '^install ' "${INSTALL_TEST_CASE}/commands" || fail "failed service stop allowed privileged writes"
    elif [[ "$scenario" == service_symlink || "$scenario" == late_symlink ]]; then
      grep -Eq 'regular file|changed while stopping' "${INSTALL_TEST_CASE}/output" || fail "${scenario} did not reject the unsafe config file"
    fi
    [[ "$(command cat "${INSTALL_TEST_CASE}/sentinel")" == 'do not touch' ]] || fail "symlink target was overwritten"
    ! grep -Eq '^systemctl (start|restart) ' "${INSTALL_TEST_CASE}/commands" || fail "unsafe installation restarted the service"
    if [[ "$scenario" != stop_failure ]]; then
      [[ ! -f "${INSTALL_TEST_CASE}/active" ]] || fail "unsafe installation left the service running"
    fi
    if [[ "$scenario" == root_symlink ]]; then
      [[ "$(command cat "${INSTALL_TEST_CASE}/outside/cheesewaf.yaml")" == 'outside file' ]] || fail "recovery followed a symlink outside the installation"
      [[ -f "${INSTALL_TEST_CASE}/preserved-config/cheesewaf.yaml" ]] || fail "recovery removed the original configuration"
    fi
    if [[ "$scenario" == changed_config ]]; then
      grep -q '# operator change' "${CHEESEWAF_CONFIG_DIR}/cheesewaf.yaml" || fail "recovery overwrote an operator's changed configuration"
    fi
  fi
  if [[ "$scenario" != fresh && "$scenario" != public_reoptin_failure && "$scenario" != invalid_* && "$scenario" != dangling_symlink && "$scenario" != inactive_failure ]]; then
    first_mutation="$(grep -E '^(install |chown |systemctl stop )' "${INSTALL_TEST_CASE}/commands" | head -n 1)"
    [[ "$first_mutation" == 'systemctl stop cheesewaf' ]] || fail "service was not stopped before configuration writes"
  fi
  if [[ "$scenario" != fresh ]]; then
    [[ "$(command cat "${CHEESEWAF_DATA_DIR}/database")" == 'user database' ]] || fail "recovery modified runtime data"
  fi
done

echo 'Linux installer account and configuration lifecycle tests passed.'
