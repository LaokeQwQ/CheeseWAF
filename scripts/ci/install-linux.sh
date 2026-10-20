#!/usr/bin/env bash
# Install a Linux CheeseWAF archive onto FHS paths.
# The repository-level scripts/install-linux.sh downloads an archive and then
# delegates here, so this script also remains useful for offline installs.
set -euo pipefail

install_root="${CHEESEWAF_INSTALL_DIR:-}"
prefix="${CHEESEWAF_PREFIX:-/usr/local}"
bin_dir="${prefix}/bin"
web_dir="${CHEESEWAF_WEB_DIR:-/usr/share/cheesewaf/web}"
config_dir="${CHEESEWAF_CONFIG_DIR:-/etc/cheesewaf}"
data_dir="${CHEESEWAF_DATA_DIR:-/var/lib/cheesewaf}"
log_dir="${CHEESEWAF_LOG_DIR:-/var/log/cheesewaf}"
unit_dir="${CHEESEWAF_UNIT_DIR:-/etc/systemd/system}"
die() { echo "ERROR: $*" >&2; exit 1; }
template_admin_listen=""
if [[ -f ./configs/cheesewaf.yaml ]]; then
  template_admin_listen="$(awk '$1 == "admin_listen:" {gsub(/"/, "", $2); print $2; exit}' ./configs/cheesewaf.yaml)"
fi
[[ -n "$template_admin_listen" ]] || die "configs/cheesewaf.yaml has no admin_listen bootstrap value"
admin_listen="${CHEESEWAF_ADMIN_LISTEN:-$template_admin_listen}"
admin_port="${admin_listen##*:}"
admin_public=false
case "$admin_listen" in 127.0.0.1:*|localhost:*|'[::1]':*) ;; *)
 [[ "${CHEESEWAF_ADMIN_PUBLIC:-0}" == 1 ]] || die "public admin listener requires CHEESEWAF_ADMIN_PUBLIC=1"
 admin_public=true ;;
esac
validate_install_path() {
  local label="$1"
  local path="$2"
  local component current="/"
  [[ "$path" =~ ^/[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$ ]] || die "${label} must be an absolute path with safe ASCII components"
  case "$path" in
    /bin|/boot|/dev|/etc|/home|/lib|/lib64|/media|/mnt|/opt|/proc|/root|/run|/sbin|/srv|/sys|/tmp|/usr|/var|/var/lib|/var/log)
      die "${label} must name a dedicated application directory, not a shared system directory" ;;
  esac
  IFS='/' read -r -a components <<< "${path#/}"
  for component in "${components[@]}"; do
    [[ -n "$component" && "$component" != "." && "$component" != ".." ]] || die "${label} contains an unsafe path component"
    current="${current%/}/${component}"
    [[ ! -L "$current" ]] || die "${label} traverses a symbolic link: ${current}"
  done
}
validate_admin_listener() {
  admin_port="${admin_listen##*:}"
  [[ "$admin_listen" =~ ^(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9._-]*):[0-9]{1,5}$ ]] || die "invalid CHEESEWAF_ADMIN_LISTEN: use host:port"
  ((10#$admin_port >= 1 && 10#$admin_port <= 65535)) || die "invalid admin port: ${admin_port}"
  admin_public=false
  case "$admin_listen" in 127.0.0.1:*|localhost:*|'[::1]':*) ;; *)
    [[ "${CHEESEWAF_ADMIN_PUBLIC:-0}" == 1 ]] || die "public admin listener requires CHEESEWAF_ADMIN_PUBLIC=1"
    admin_public=true ;;
  esac
}
validate_existing_config() {
  fresh_config=1
  if [[ -e "${config_dir}/cheesewaf.yaml" || -L "${config_dir}/cheesewaf.yaml" ]]; then
    [[ -f "${config_dir}/cheesewaf.yaml" && ! -L "${config_dir}/cheesewaf.yaml" ]] || die "existing config file must be a regular file"
    fresh_config=0
    existing_entry="$(sed -n '/^[[:space:]]*security_entry:[[:space:]]*$/,/^[[:space:]]*background:/p' "${config_dir}/cheesewaf.yaml" | awk '$1 == "path:" {gsub(/"/, "", $2); print $2; exit}')"
    [[ "$existing_entry" == /* && "$existing_entry" != *".."* && "$existing_entry" != *"?"* && "$existing_entry" != *"#"* ]] || die "existing config has an invalid security-entry path"
    admin_listen="$(awk '$1 == "admin_listen:" {gsub(/"/, "", $2); print $2; exit}' "${config_dir}/cheesewaf.yaml")"
    [[ -n "$admin_listen" ]] || die "config has no server.admin_listen"
    validate_admin_listener
  fi
}
validate_public_host() {
  local host="$1"
  if [[ "$host" =~ ^\[([0-9A-Fa-f:.]+)\]$ ]]; then
    return 0
  elif [[ "$host" == *:* ]]; then
    [[ "$host" =~ ^[0-9A-Fa-f:.]+$ ]]
  else
    [[ "$host" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]]
  fi
}
prompt_read() {
  if [[ -r /dev/tty ]]; then read -r "$@" </dev/tty; else read -r "$@"; fi
}
has_interactive_terminal() {
  [[ -t 0 ]] && return 0
  [[ -r /dev/tty && -w /dev/tty ]] || return 1
  { : </dev/tty; } 2>/dev/null
}

[[ "$(uname -s)" == "Linux" ]] || die "install-linux.sh is for Linux hosts"
[[ "$(id -u)" -eq 0 ]] || die "run as root (sudo ./install-linux.sh)"
[[ -x ./cheesewaf ]] || die "cheesewaf binary not found in $(pwd)"
[[ -f ./web/dist/index.html ]] || die "web/dist/index.html missing; extract the full tar.gz"
command -v awk >/dev/null 2>&1 || die "awk is required"
command -v od >/dev/null 2>&1 || die "od is required"
lang="${CHEESEWAF_LANG:-}"
if [[ -z "$lang" ]] && has_interactive_terminal; then
  printf 'Language / 语言 [1=English, 2=简体中文] (1): '
  prompt_read choice
  [[ "$choice" == "2" ]] && lang="zh-CN" || lang="en"
fi
[[ "$lang" == "zh-CN" ]] || lang="en"

msg() {
  if [[ "$lang" == "zh-CN" ]]; then
    case "$1" in
      entry_prompt) printf '安全入口（8-64位，仅字母和数字，回车自动生成）: ' ;;
      install_root_prompt) printf '应用安装根目录（回车保留分散的 FHS 默认目录）: ' ;;
      entry_invalid) printf '安全入口无效：只能包含8-64位 ASCII 字母和数字。\n' >&2 ;;
      entry_generated) printf '已生成安全入口：/%s\n' "$2" ;;
      installed) printf 'CheeseWAF 安装完成（版本 %s）。\n' "$2" ;;
      service) printf '服务状态：%s\n' "$2" ;;
      setup) printf '一次性初始化地址（10分钟内有效）：%s\n' "$2" ;;
      login) printf '初始化完成后的安全入口：%s\n' "$2" ;;
      private) printf '内网地址：%s\n' "$2" ;;
      public) printf '公网地址：%s\n' "$2" ;;
      paths) printf '路径：二进制=%s 配置=%s 数据=%s 日志=%s\n' "$2" "$3" "$4" "$5" ;;
      tls) printf '提示：当前使用 CheeseWAF 自签名管理证书，浏览器首次访问会提示不受信；生产环境请替换为受信证书或反向代理。\n' ;;
      firewall) printf '请确认云防火墙/主机防火墙仅开放 TCP 9443，并保留一次性 Token 与安全入口。\n' ;;
      secret_file) printf '敏感安装信息已保存到（仅 root 可读）：%s\n' "$2" ;;
      public_note) printf '未自动确认公网可达地址；如需对外展示，请设置 CHEESEWAF_ADMIN_PUBLIC_HOST。\n' ;;
    esac
  else
    case "$1" in
      entry_prompt) printf 'Admin security entry (8-64 ASCII letters/digits, Enter to generate): ' ;;
      install_root_prompt) printf 'Application install root (Enter to keep the standard FHS directories): ' ;;
      entry_invalid) printf 'Invalid security entry: use 8-64 ASCII letters and digits only.\n' >&2 ;;
      entry_generated) printf 'Generated security entry: /%s\n' "$2" ;;
      installed) printf 'CheeseWAF installation complete (version %s).\n' "$2" ;;
      service) printf 'Service status: %s\n' "$2" ;;
      setup) printf 'One-time setup URL (valid for 10 minutes): %s\n' "$2" ;;
      login) printf 'Secure entry after setup: %s\n' "$2" ;;
      private) printf 'Private address: %s\n' "$2" ;;
      public) printf 'Public address: %s\n' "$2" ;;
      paths) printf 'Paths: binary=%s config=%s data=%s logs=%s\n' "$2" "$3" "$4" "$5" ;;
      tls) printf 'Note: the admin interface uses a CheeseWAF self-signed certificate. Browsers will warn on first access; replace it with a trusted certificate or reverse proxy for production.\n' ;;
      firewall) printf 'Ensure the cloud/host firewall exposes only TCP 9443, and keep the one-time token and secure entry private.\n' ;;
      secret_file) printf 'Sensitive install details were saved (root-readable only): %s\n' "$2" ;;
      public_note) printf 'A publicly reachable address was not confirmed. Set CHEESEWAF_ADMIN_PUBLIC_HOST to advertise a public IP or DNS name.\n' ;;
    esac
  fi
}

if [[ -z "$install_root" ]] && has_interactive_terminal; then
  msg install_root_prompt
  prompt_read selected_install_root
  install_root="${selected_install_root:-}"
fi
if [[ -n "$install_root" ]]; then
  prefix="${CHEESEWAF_PREFIX:-$install_root}"
  bin_dir="${prefix}/bin"
  web_dir="${CHEESEWAF_WEB_DIR:-${install_root}/web}"
  config_dir="${CHEESEWAF_CONFIG_DIR:-${install_root}/config}"
  data_dir="${CHEESEWAF_DATA_DIR:-${install_root}/data}"
  log_dir="${CHEESEWAF_LOG_DIR:-${install_root}/logs}"
fi

# Validate after interactive root selection: these are the paths privileged
# writes below actually use, rather than only the initial FHS defaults.
validate_install_path CHEESEWAF_PREFIX "$prefix"
validate_install_path CHEESEWAF_BIN_DIR "$bin_dir"
validate_install_path CHEESEWAF_WEB_DIR "$web_dir"
validate_install_path CHEESEWAF_CONFIG_DIR "$config_dir"
validate_install_path CHEESEWAF_DATA_DIR "$data_dir"
validate_install_path CHEESEWAF_LOG_DIR "$log_dir"
validate_install_path CHEESEWAF_UNIT_DIR "$unit_dir"
validate_admin_listener
setup_wait_seconds="${CHEESEWAF_SETUP_URL_WAIT_SECONDS:-15}"
[[ "$setup_wait_seconds" =~ ^[0-9]+$ ]] || die "CHEESEWAF_SETUP_URL_WAIT_SECONDS must be a non-negative integer"
if [[ -n "${CHEESEWAF_ADMIN_PUBLIC_HOST:-}" ]]; then
  validate_public_host "$CHEESEWAF_ADMIN_PUBLIC_HOST" || die "invalid CHEESEWAF_ADMIN_PUBLIC_HOST"
fi
if id cheesewaf >/dev/null 2>&1; then
  [[ "$(id -u cheesewaf)" != 0 && "$(id -g cheesewaf)" != 0 ]] || die "existing cheesewaf account must not be root"
fi
secret_file="${config_dir}/install-secrets.txt"

entry="${CHEESEWAF_SECURITY_ENTRY:-}"
if [[ -z "$entry" ]]; then
  alphabet='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
  entry=''
  while (( ${#entry} < 32 )); do
    for byte in $(od -An -N64 -tu1 /dev/urandom); do
      index=$((byte % ${#alphabet}))
      entry+="${alphabet:index:1}"
      (( ${#entry} >= 32 )) && break
    done
  done
fi
if has_interactive_terminal && [[ -z "${CHEESEWAF_SECURITY_ENTRY:-}" ]]; then
  msg entry_prompt
  prompt_read custom_entry
  [[ -n "$custom_entry" ]] && entry="$custom_entry"
fi
[[ "$entry" =~ ^[A-Za-z0-9]{8,64}$ ]] || { msg entry_invalid; exit 1; }

# Read-only preflight runs while the old service is still available. Re-read
# after stopping it: the service can replace its own configuration atomically.
validate_existing_config
service_was_running=0
stop_requested=0
mutations_started=0
upgrade_complete=0
recovery_dir=""
admin_env_tmp=""

recovery_paths_safe() {
  (validate_install_path CHEESEWAF_BIN_DIR "$bin_dir" &&
   validate_install_path CHEESEWAF_WEB_DIR "$web_dir" &&
   validate_install_path CHEESEWAF_CONFIG_DIR "$config_dir" &&
   validate_install_path CHEESEWAF_DATA_DIR "$data_dir" &&
   validate_install_path CHEESEWAF_LOG_DIR "$log_dir" &&
   validate_install_path CHEESEWAF_UNIT_DIR "$unit_dir") || return 1
  [[ -f "${config_dir}/cheesewaf.yaml" && ! -L "${config_dir}/cheesewaf.yaml" ]] || return 1
  [[ ! -L "${config_dir}/admin.env" && ( ! -e "${config_dir}/admin.env" || -f "${config_dir}/admin.env" ) ]] || return 1
  cmp -s "${recovery_dir}/config" "${config_dir}/cheesewaf.yaml"
}
restore_upgrade_file() {
  local source="$1" destination="$2" temporary
  [[ ! -L "$destination" && ( ! -e "$destination" || -f "$destination" ) ]] || return 1
  temporary="$(mktemp "${destination}.restore.XXXXXX")" || return 1
  cp -p "$source" "$temporary" && mv -f -- "$temporary" "$destination"
}
metadata_path_safe() {
  local path="$1"
  while [[ -n "$path" && "$path" != / ]]; do
    [[ ! -L "$path" ]] || return 1
    path="${path%/*}"
  done
}
recover_previous_service() {
  local name restore_web
  # A failed restart may already have launched the new binary. Stop it even
  # when changed configuration prevents us from safely restoring the old one.
  if (( mutations_started == 1 )); then systemctl stop cheesewaf || return 1; fi
  recovery_paths_safe || return 1
  if (( mutations_started == 1 )); then
    for name in binary unit admin.env wrapper; do
      [[ ! -e "${recovery_dir}/${name}" ]] || [[ -f "${recovery_dir}/${name}" && ! -L "${recovery_dir}/${name}" ]] || return 1
    done
    restore_upgrade_file "${recovery_dir}/binary" "${bin_dir}/cheesewaf" || return 1
    restore_upgrade_file "${recovery_dir}/unit" "${unit_dir}/cheesewaf.service" || return 1
    if [[ -e "${config_dir}/admin.env" ]]; then
      cmp -s "${recovery_dir}/admin.env" "${config_dir}/admin.env" ||
        cmp -s "${recovery_dir}/new-admin.env" "${config_dir}/admin.env" || return 1
    fi
    if [[ -f "${recovery_dir}/admin.env" ]]; then
      restore_upgrade_file "${recovery_dir}/admin.env" "${config_dir}/admin.env" || return 1
    elif [[ -e "${config_dir}/admin.env" || -L "${config_dir}/admin.env" ]]; then
      [[ -f "${config_dir}/admin.env" && ! -L "${config_dir}/admin.env" ]] || return 1
      cmp -s "${recovery_dir}/new-admin.env" "${config_dir}/admin.env" || return 1
      rm -f -- "${config_dir}/admin.env" || return 1
    fi
    if [[ -f "${recovery_dir}/wrapper" ]]; then
      restore_upgrade_file "${recovery_dir}/wrapper" "${bin_dir}/waf-cli-wrapper" || return 1
    elif [[ -e "${bin_dir}/waf-cli-wrapper" || -L "${bin_dir}/waf-cli-wrapper" ]]; then
      [[ -f "${bin_dir}/waf-cli-wrapper" && ! -L "${bin_dir}/waf-cli-wrapper" ]] || return 1
      cmp -s ./waf-cli "${bin_dir}/waf-cli-wrapper" || return 1
      rm -f -- "${bin_dir}/waf-cli-wrapper" || return 1
    fi
    [[ -d "$web_dir" && ! -L "$web_dir" ]] || return 1
    restore_web="$(mktemp -d "${web_dir}.recovery.XXXXXX")" || return 1
    cp -Rp "${recovery_dir}/web" "${restore_web}/web" || return 1
    mv -- "$web_dir" "${restore_web}/failed-web" || return 1
    mv -- "${restore_web}/web" "$web_dir" || return 1
    echo "Failed upgrade web files retained in ${restore_web}/failed-web" >&2
    # Restore metadata in place; never replace user configuration or data.
    recovery_paths_safe || return 1
    local path mode uid gid
    while IFS= read -r -d '' path && IFS= read -r mode && IFS= read -r uid && IFS= read -r gid; do
      [[ -e "$path" ]] && metadata_path_safe "$path" || return 1
      chown "${uid}:${gid}" "$path" || return 1
      chmod "$mode" "$path" || return 1
    done <"${recovery_dir}/permissions"
    systemctl daemon-reload || return 1
  fi
  [[ -x "${bin_dir}/cheesewaf" && ! -L "${bin_dir}/cheesewaf" && -f "${unit_dir}/cheesewaf.service" && ! -L "${unit_dir}/cheesewaf.service" ]] || return 1
  recovery_paths_safe || return 1
  systemctl start cheesewaf && systemctl is-active --quiet cheesewaf
}
finish_install() {
  local status="$1"
  trap - EXIT HUP INT TERM
  if (( status != 0 && service_was_running == 1 && stop_requested == 1 && upgrade_complete == 0 )); then
    if (( mutations_started == 0 )) && systemctl is-active --quiet cheesewaf; then
      : # A failed stop left the unchanged service running.
    elif recover_previous_service; then
      echo "Upgrade failed; the previous CheeseWAF service was restored." >&2
    else
      echo "Upgrade failed; automatic recovery was unsafe or failed. The service was not restarted." >&2
    fi
    echo "Upgrade recovery files: ${recovery_dir}" >&2
  elif [[ -n "$recovery_dir" ]]; then
    rm -rf -- "$recovery_dir"
  fi
  if [[ -n "$admin_env_tmp" ]] && (validate_install_path CHEESEWAF_CONFIG_DIR "$config_dir"); then
    rm -f -- "$admin_env_tmp"
  fi
  exit "$status"
}
trap 'finish_install "$?"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet cheesewaf; then
  service_was_running=1
  [[ "$fresh_config" == 0 && -x "${bin_dir}/cheesewaf" && ! -L "${bin_dir}/cheesewaf" && -f "${unit_dir}/cheesewaf.service" && ! -L "${unit_dir}/cheesewaf.service" && -d "$web_dir" ]] || die "running installation cannot be safely backed up at the selected paths"
  [[ ! -L "${config_dir}/admin.env" && ( ! -e "${config_dir}/admin.env" || -f "${config_dir}/admin.env" ) ]] || die "existing admin.env must be a regular file"
  [[ ! -L "${bin_dir}/waf-cli-wrapper" && ( ! -e "${bin_dir}/waf-cli-wrapper" || -f "${bin_dir}/waf-cli-wrapper" ) ]] || die "existing CLI wrapper must be a regular file"
  recovery_dir="$(mktemp -d)"
  cp -Pp "${config_dir}/cheesewaf.yaml" "${recovery_dir}/config"
  [[ -f "${recovery_dir}/config" && ! -L "${recovery_dir}/config" ]] || die "existing config file must be a regular file"
  stop_requested=1
  systemctl stop cheesewaf
  recovery_paths_safe || die "installation paths or configuration changed while stopping the service"
  validate_existing_config
  cp -Pp "${bin_dir}/cheesewaf" "${recovery_dir}/binary"
  cp -Pp "${unit_dir}/cheesewaf.service" "${recovery_dir}/unit"
  [[ -f "${recovery_dir}/binary" && ! -L "${recovery_dir}/binary" && -f "${recovery_dir}/unit" && ! -L "${recovery_dir}/unit" ]] || die "installation files changed while stopping the service"
  cp -Rp "$web_dir" "${recovery_dir}/web"
  for file in admin.env; do
    [[ ! -L "${config_dir}/${file}" ]] || die "existing ${file} must not be a symlink"
    if [[ -e "${config_dir}/${file}" ]]; then
      [[ -f "${config_dir}/${file}" ]] || die "existing ${file} must be a regular file"
      cp -p "${config_dir}/${file}" "${recovery_dir}/${file}"
    fi
  done
  if [[ -e "${bin_dir}/waf-cli-wrapper" || -L "${bin_dir}/waf-cli-wrapper" ]]; then
    [[ -f "${bin_dir}/waf-cli-wrapper" && ! -L "${bin_dir}/waf-cli-wrapper" ]] || die "existing CLI wrapper must be a regular file"
    cp -p "${bin_dir}/waf-cli-wrapper" "${recovery_dir}/wrapper"
  fi
  # Ownership reconciliation below touches these trees recursively. Record
  # metadata only, so rollback cannot overwrite databases or user config.
  for directory in "$config_dir" "$data_dir" "$log_dir"; do
    [[ -d "$directory" ]] || continue
    find "$directory" -print0 >"${recovery_dir}/paths"
    while IFS= read -r -d '' file; do
      [[ ! -L "$file" ]] || die "existing runtime tree contains a symbolic link: ${file}"
      printf '%s\0' "$file" >>"${recovery_dir}/permissions"
      stat -c $'%a\n%u\n%g' "$file" >>"${recovery_dir}/permissions"
    done <"${recovery_dir}/paths"
  done
  for directory in "$bin_dir" "$unit_dir"; do
    printf '%s\0' "$directory" >>"${recovery_dir}/permissions"
    stat -c $'%a\n%u\n%g' "$directory" >>"${recovery_dir}/permissions"
  done
fi
mutations_started=1

install -d -m 0755 "$bin_dir" "$web_dir" "$unit_dir"
install -d -m 0700 "$config_dir" "$data_dir" "$log_dir"
# Re-check final destinations after creation so a pre-existing symlink cannot
# redirect a privileged write through a selected install root.
validate_install_path CHEESEWAF_PREFIX "$prefix"
validate_install_path CHEESEWAF_BIN_DIR "$bin_dir"
validate_install_path CHEESEWAF_WEB_DIR "$web_dir"
validate_install_path CHEESEWAF_CONFIG_DIR "$config_dir"
validate_install_path CHEESEWAF_DATA_DIR "$data_dir"
validate_install_path CHEESEWAF_LOG_DIR "$log_dir"
validate_install_path CHEESEWAF_UNIT_DIR "$unit_dir"
install -m 0755 ./cheesewaf "${bin_dir}/cheesewaf"
ln -sfn "${bin_dir}/cheesewaf" "${bin_dir}/waf-cli"
if [[ -x ./waf-cli ]]; then install -m 0755 ./waf-cli "${bin_dir}/waf-cli-wrapper"; fi
cp -R ./web/dist/. "$web_dir/"
if [[ -f ./configs/cheesewaf.yaml && ! -e "${config_dir}/cheesewaf.yaml" ]]; then
  install -m 0640 ./configs/cheesewaf.yaml "${config_dir}/cheesewaf.yaml"
  fresh_config=1
fi
[[ -f "${config_dir}/cheesewaf.yaml" ]] || die "config file is missing: ${config_dir}/cheesewaf.yaml"
if [[ -f ./systemd/cheesewaf.service ]]; then
  install -m 0644 ./systemd/cheesewaf.service "${unit_dir}/cheesewaf.service"
  # Render the unit from the same paths used above. This keeps supported
  # CHEESEWAF_*_DIR overrides from starting an older/default installation.
  sed -i -E \
    -e "s#^WorkingDirectory=.*#WorkingDirectory=${data_dir}#" \
    -e "s#^Environment=CHEESEWAF_WEB_DIR=.*#Environment=CHEESEWAF_WEB_DIR=${web_dir}#" \
    -e "s#^EnvironmentFile=-/etc/cheesewaf/admin.env\$#EnvironmentFile=-${config_dir}/admin.env#" \
    -e "s#^EnvironmentFile=-/etc/cheesewaf/edge-origin.env\$#EnvironmentFile=-${config_dir}/edge-origin.env#" \
    -e "s#^ExecStart=.*#ExecStart=${bin_dir}/cheesewaf serve --config ${config_dir}/cheesewaf.yaml --data-dir ${data_dir}#" \
    -e "s#^ReadWritePaths=.*#ReadWritePaths=${config_dir} ${data_dir} ${log_dir}#" \
    "${unit_dir}/cheesewaf.service"
fi

# The installer owns bootstrap fields only for a fresh config. Existing
# listener, TLS, security-entry, site, and policy settings stay untouched.
if (( fresh_config == 1 )); then
  sed -i -E "s#^([[:space:]]*)admin_listen:.*#\1admin_listen: \"${admin_listen}\"#" "${config_dir}/cheesewaf.yaml"
  sed -i -E "s#^([[:space:]]*)admin_public:.*#\\1admin_public: ${admin_public}#" "${config_dir}/cheesewaf.yaml"
  sed -i -E '/^[[:space:]]*admin_tls:/,/^[[:space:]]*read_timeout:/{s#^([[:space:]]*)enabled:.*#\1enabled: true#}' "${config_dir}/cheesewaf.yaml"
  sed -i -E '/^[[:space:]]*security_entry:/,/^[[:space:]]*background:/{s#^([[:space:]]*)path:.*#\1path: /'"${entry}"'#}' "${config_dir}/cheesewaf.yaml"
  sed -i -E '/^[[:space:]]*security_entry:/,/^[[:space:]]*background:/{s#^([[:space:]]*)enabled:.*#\1enabled: true#}' "${config_dir}/cheesewaf.yaml"
fi

# Fail closed if a template format change made one of the installer-owned
# substitutions miss its target. A silent partial patch could start a service
# with a different listener, TLS mode, or security-entry route than the receipt.
installed_admin_listen="$(awk '$1 == "admin_listen:" {gsub(/"/, "", $2); print $2; exit}' "${config_dir}/cheesewaf.yaml")"
[[ -n "$installed_admin_listen" ]] || die "config has no server.admin_listen"
if (( fresh_config == 1 )); then
  [[ "$installed_admin_listen" == "$admin_listen" ]] || die "failed to set server.admin_listen"
  grep -Eq "^[[:space:]]+admin_public:[[:space:]]*${admin_public}[[:space:]]*$" "${config_dir}/cheesewaf.yaml" || die "failed to enable public admin mode"
  sed -n '/^[[:space:]]*admin_tls:[[:space:]]*$/,/^[[:space:]]*read_timeout:/p' "${config_dir}/cheesewaf.yaml" | grep -Eq '^[[:space:]]+enabled:[[:space:]]*true[[:space:]]*$' || die "failed to enable admin TLS"
else
  admin_listen="$installed_admin_listen"
  validate_admin_listener
fi
installed_entry="$(sed -n '/^[[:space:]]*security_entry:[[:space:]]*$/,/^[[:space:]]*background:/p' "${config_dir}/cheesewaf.yaml" | awk '$1 == "path:" {gsub(/"/, "", $2); print $2; exit}')"
if (( fresh_config == 1 )); then
  [[ "$installed_entry" =~ ^/[A-Za-z0-9]{8,64}$ ]] || die "config has an invalid security-entry path"
  [[ "$installed_entry" == "/${entry}" ]] || die "failed to set security-entry path"
  sed -n '/^[[:space:]]*security_entry:[[:space:]]*$/,/^[[:space:]]*background:/p' "${config_dir}/cheesewaf.yaml" | grep -Eq '^[[:space:]]+enabled:[[:space:]]*true[[:space:]]*$' || die "failed to enable security entry"
else
  [[ "$installed_entry" == /* && "$installed_entry" != *".."* && "$installed_entry" != *"?"* && "$installed_entry" != *"#"* ]] || die "config has an invalid security-entry path"
  entry="${installed_entry#/}"
fi

global_hosts=""
private_hosts=""
public_candidates=""
if command -v ip >/dev/null 2>&1; then
  global_hosts="$(ip -o -4 addr show scope global 2>/dev/null | awk '{split($4, parts, "/"); print parts[1]}' || true)"
  private_hosts="$(printf '%s\n' "$global_hosts" | awk '
    function private(ip, octets) {
      split(ip, octets, ".")
      return octets[1] == 10 || (octets[1] == 172 && octets[2] >= 16 && octets[2] <= 31) || (octets[1] == 192 && octets[2] == 168) || (octets[1] == 169 && octets[2] == 254)
    }
    NF && private($1) { print $1 }
  ' | paste -sd, - || true)"
  public_candidates="$(printf '%s\n' "$global_hosts" | awk '
    function private(ip, octets) {
      split(ip, octets, ".")
      return octets[1] == 10 || (octets[1] == 172 && octets[2] >= 16 && octets[2] <= 31) || (octets[1] == 192 && octets[2] == 168) || (octets[1] == 169 && octets[2] == 254)
    }
    NF && !private($1) { print $1 }
  ' | head -n 1)"
fi
[[ -n "$private_hosts" ]] || private_hosts="127.0.0.1"

public_host="${CHEESEWAF_ADMIN_PUBLIC_HOST:-$public_candidates}"
if [[ -z "$public_host" && "${CHEESEWAF_DETECT_PUBLIC_IP:-0}" == "1" ]] && command -v curl >/dev/null 2>&1; then
  public_host="$(curl --proto '=https' --proto-redir '=https' -4fsS --max-time 4 https://api.ipify.org 2>/dev/null || true)"
fi
public_detected=1
[[ -n "$public_host" ]] || { public_host="127.0.0.1"; public_detected=0; }
validate_public_host "$public_host" || die "invalid CHEESEWAF_ADMIN_PUBLIC_HOST"
if [[ "$public_host" =~ ^\[([0-9A-Fa-f:.]+)\]$ ]]; then
  public_host="${BASH_REMATCH[1]}"
fi
public_url_host="$public_host"
[[ "$public_url_host" == *:* ]] && public_url_host="[${public_url_host}]"
# The service account owns the runtime directory for normal config updates.
# Never let a service-created symlink turn this privileged receipt write into
# an arbitrary-file overwrite: create the file outside that directory and
# atomically rename it over the destination (rename replaces a symlink).
# Keep the temporary and final file on the same filesystem so rename is
# atomic. The configuration directory is root-owned and writable only by the
# dedicated service group. The sticky bit prevents the service from unlinking
# root-owned bootstrap/secret files while config.Save can replace its own file.
service_group="cheesewaf"
if ! getent group "$service_group" >/dev/null 2>&1; then
  groupadd --system "$service_group"
fi
chown root:"$service_group" "$config_dir"
chmod 01770 "$config_dir"
admin_env_tmp="$(mktemp "${config_dir}/.admin.env.XXXXXX")"
printf 'CHEESEWAF_ADMIN_PUBLIC_HOST=%s\n' "$public_host" >"$admin_env_tmp"
if [[ -n "$recovery_dir" ]]; then cp "$admin_env_tmp" "${recovery_dir}/new-admin.env"; fi
chmod 0640 "$admin_env_tmp"
chown root:root "$admin_env_tmp"
mv -f -- "$admin_env_tmp" "${config_dir}/admin.env"
admin_env_tmp=""
chmod 0640 "${config_dir}/admin.env"

if id cheesewaf >/dev/null 2>&1; then
  service_uid="$(id -u cheesewaf)"
  service_gid="$(id -g cheesewaf)"
  [[ "$service_uid" != "0" && "$service_gid" != "0" ]] || die "existing cheesewaf account must not be root"
else
  useradd --system --gid "$service_group" --home "$data_dir" --shell /usr/sbin/nologin cheesewaf
fi
[[ -f "${config_dir}/cheesewaf.yaml" && ! -L "${config_dir}/cheesewaf.yaml" ]] || die "existing config file must be a regular file"
chown -R root:"$service_group" "$config_dir"
chown -R cheesewaf:cheesewaf "$data_dir" "$log_dir"
# Runtime configuration is replaced atomically by the service account. Make
# that file service-owned and private; the sticky directory protects the
# root-owned admin.env, edge-origin.env, and installation receipt files.
[[ -f "${config_dir}/cheesewaf.yaml" && ! -L "${config_dir}/cheesewaf.yaml" ]] || die "existing config file must be a regular file"
chown cheesewaf:cheesewaf "${config_dir}/cheesewaf.yaml"
chmod 0600 "${config_dir}/cheesewaf.yaml"
chmod 01770 "$config_dir"

if command -v systemctl >/dev/null 2>&1 && [[ -f "${unit_dir}/cheesewaf.service" && "${CHEESEWAF_NO_START:-0}" != "1" ]]; then
  systemctl daemon-reload
  systemctl enable cheesewaf >/dev/null
  systemctl restart cheesewaf
  service_state="$(systemctl is-active cheesewaf)"
  [[ "$service_state" == active ]] || die "CheeseWAF did not become active after restart"
else
  service_state="not started (systemd unavailable or CHEESEWAF_NO_START=1)"
fi
upgrade_complete=1

version="$(${bin_dir}/cheesewaf version 2>/dev/null | head -n 1 || echo unknown)"
msg installed "$version"
msg service "$service_state"
msg paths "${bin_dir}/cheesewaf" "${config_dir}/cheesewaf.yaml" "$data_dir" "$log_dir"
msg private "$(printf '%s' "$private_hosts" | sed 's/,/, /g')"
IFS=',' read -r -a private_ip_list <<< "$private_hosts"
for private_ip in "${private_ip_list[@]}"; do
  msg private "https://${private_ip}:${admin_port}/setup"
done
msg public "https://${public_url_host}:${admin_port}/setup"
(( public_detected == 1 )) || msg public_note
msg tls
msg firewall

setup_url_file="${data_dir}/setup.url"
setup_url=""
if [[ ! -r "$setup_url_file" && "$service_state" == "active" ]]; then
  setup_wait_deadline=$((SECONDS + setup_wait_seconds))
  while (( SECONDS <= setup_wait_deadline )); do
    [[ -r "$setup_url_file" ]] && break
    sleep 1
  done
fi
if [[ -r "$setup_url_file" ]]; then
  setup_url="$(sed -n 's/^url=//p' "$setup_url_file" | head -n 1)"
fi

# Keep secrets out of CI/remote sudo logs by default. An interactive terminal
# receives the copy/paste values; non-interactive callers can opt in with
# CHEESEWAF_SHOW_SECRETS=1 and always have a root-only local receipt.
secret_tmp="$(mktemp "${config_dir}/.install-secrets.XXXXXX")"
{
  printf 'CHEESEWAF_SECURITY_ENTRY=/%s\n' "$entry"
  if [[ -n "$setup_url" ]]; then printf 'CHEESEWAF_SETUP_URL=%s\n' "$setup_url"; fi
} >"$secret_tmp"
chmod 0600 "$secret_tmp"
mv -f "$secret_tmp" "$secret_file"
chown root:root "$secret_file"
msg secret_file "$secret_file"

show_secrets=0
[[ -t 1 || "${CHEESEWAF_SHOW_SECRETS:-0}" == "1" ]] && show_secrets=1
if (( show_secrets == 1 )); then
  msg entry_generated "$entry"
  msg login "https://${public_url_host}:${admin_port}/${entry}"
  if [[ -n "$setup_url" ]]; then
    public_setup_url="${setup_url/127.0.0.1/$public_url_host}"
    msg setup "$public_setup_url"
  else
    echo "Setup URL file will appear after the service starts: ${setup_url_file}"
  fi
else
  echo "Setup URL and security entry are in ${secret_file}; use CHEESEWAF_SHOW_SECRETS=1 only on a trusted terminal."
fi
