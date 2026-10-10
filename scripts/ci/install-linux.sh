#!/usr/bin/env bash
# Install a Linux CheeseWAF archive onto FHS paths.
# The repository-level scripts/install-linux.sh downloads an archive and then
# delegates here, so this script also remains useful for offline installs.
set -euo pipefail

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
secret_file="${config_dir}/install-secrets.txt"
validate_install_path() {
  local label="$1"
  local path="$2"
  local component current="/"
  [[ "$path" == /* && "$path" != "/" ]] || die "${label} must be an absolute non-root path"
  case "$path" in
    /bin|/boot|/dev|/etc|/home|/lib|/lib64|/media|/mnt|/opt|/proc|/root|/run|/sbin|/srv|/sys|/tmp|/usr|/var|/var/lib|/var/log)
      die "${label} must name a dedicated application directory, not a shared system directory" ;;
  esac
  [[ "$path" != *$'\n'* && "$path" != *$'\r'* && "$path" != *' '* && "$path" != *'#'* && "$path" != *'%'* && "$path" != *'&'* && "$path" != *'\\'* ]] || die "${label} contains unsupported characters"
  IFS='/' read -r -a components <<< "${path#/}"
  for component in "${components[@]}"; do
    [[ -n "$component" && "$component" != "." && "$component" != ".." ]] || die "${label} contains an unsafe path component"
    current="${current%/}/${component}"
    [[ ! -L "$current" ]] || die "${label} traverses a symbolic link: ${current}"
  done
}
prompt_read() {
  if [[ -r /dev/tty ]]; then read -r "$@" </dev/tty; else read -r "$@"; fi
}

[[ "$(uname -s)" == "Linux" ]] || die "install-linux.sh is for Linux hosts"
[[ "$(id -u)" -eq 0 ]] || die "run as root (sudo ./install-linux.sh)"
[[ -x ./cheesewaf ]] || die "cheesewaf binary not found in $(pwd)"
[[ -f ./web/dist/index.html ]] || die "web/dist/index.html missing; extract the full tar.gz"
command -v awk >/dev/null 2>&1 || die "awk is required"
command -v od >/dev/null 2>&1 || die "od is required"
validate_install_path CHEESEWAF_PREFIX "$prefix"
validate_install_path CHEESEWAF_WEB_DIR "$web_dir"
validate_install_path CHEESEWAF_CONFIG_DIR "$config_dir"
validate_install_path CHEESEWAF_DATA_DIR "$data_dir"
validate_install_path CHEESEWAF_LOG_DIR "$log_dir"
validate_install_path CHEESEWAF_UNIT_DIR "$unit_dir"
[[ "$admin_listen" =~ ^(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9._-]*):[0-9]{1,5}$ ]] || die "invalid CHEESEWAF_ADMIN_LISTEN: use host:port"
((10#$admin_port >= 1 && 10#$admin_port <= 65535)) || die "invalid admin port: ${admin_port}"

lang="${CHEESEWAF_LANG:-}"
if [[ -z "$lang" && ( -t 0 || -r /dev/tty ) ]]; then
  printf 'Language / 语言 [1=English, 2=简体中文] (1): '
  prompt_read choice
  [[ "$choice" == "2" ]] && lang="zh-CN" || lang="en"
fi
[[ "$lang" == "zh-CN" ]] || lang="en"

msg() {
  if [[ "$lang" == "zh-CN" ]]; then
    case "$1" in
      entry_prompt) printf '安全入口（8-64位，仅字母和数字，回车自动生成）: ' ;;
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
if [[ ( -t 0 || -r /dev/tty ) && -z "${CHEESEWAF_SECURITY_ENTRY:-}" ]]; then
  msg entry_prompt
  prompt_read custom_entry
  [[ -n "$custom_entry" ]] && entry="$custom_entry"
fi
[[ "$entry" =~ ^[A-Za-z0-9]{8,64}$ ]] || { msg entry_invalid; exit 1; }

install -d -m 0755 "$bin_dir" "$web_dir" "$config_dir" "$data_dir" "$log_dir" "$unit_dir"
install -m 0755 ./cheesewaf "${bin_dir}/cheesewaf"
ln -sfn "${bin_dir}/cheesewaf" "${bin_dir}/waf-cli"
if [[ -x ./waf-cli ]]; then install -m 0755 ./waf-cli "${bin_dir}/waf-cli-wrapper"; fi
cp -R ./web/dist/. "$web_dir/"
if [[ -f ./configs/cheesewaf.yaml && ! -e "${config_dir}/cheesewaf.yaml" ]]; then
  install -m 0640 ./configs/cheesewaf.yaml "${config_dir}/cheesewaf.yaml"
fi
[[ -f "${config_dir}/cheesewaf.yaml" ]] || die "config file is missing: ${config_dir}/cheesewaf.yaml"
if [[ -f ./systemd/cheesewaf.service ]]; then
  install -m 0644 ./systemd/cheesewaf.service "${unit_dir}/cheesewaf.service"
  # Render the unit from the same paths used above. This keeps supported
  # CHEESEWAF_*_DIR overrides from starting an older/default installation.
  sed -i -E \
    -e "s#^WorkingDirectory=.*#WorkingDirectory=${data_dir}#" \
    -e "s#^Environment=CHEESEWAF_WEB_DIR=.*#Environment=CHEESEWAF_WEB_DIR=${web_dir}#" \
    -e "s#^EnvironmentFile=-/etc/cheesewaf/admin.env$#EnvironmentFile=-${config_dir}/admin.env#" \
    -e "s#^EnvironmentFile=-/etc/cheesewaf/edge-origin.env$#EnvironmentFile=-${config_dir}/edge-origin.env#" \
    -e "s#^ExecStart=.*#ExecStart=${bin_dir}/cheesewaf serve --config ${config_dir}/cheesewaf.yaml --data-dir ${data_dir}#" \
    -e "s#^ReadWritePaths=.*#ReadWritePaths=${config_dir}/cheesewaf.yaml ${data_dir} ${log_dir}#" \
    "${unit_dir}/cheesewaf.service"
fi

# The installer owns only bootstrap fields. Existing site and policy settings
# remain untouched on upgrades.
sed -i -E "s#^([[:space:]]*)admin_listen:.*#\1admin_listen: \"${admin_listen}\"#" "${config_dir}/cheesewaf.yaml"
sed -i -E 's#^([[:space:]]*)admin_public:.*#\1admin_public: true#' "${config_dir}/cheesewaf.yaml"
sed -i -E '/^[[:space:]]*admin_tls:/,/^[[:space:]]*read_timeout:/{s#^([[:space:]]*)enabled:.*#\1enabled: true#}' "${config_dir}/cheesewaf.yaml"
sed -i -E '/^[[:space:]]*security_entry:/,/^[[:space:]]*background:/{s#^([[:space:]]*)path:.*#\1path: /'"${entry}"'#}' "${config_dir}/cheesewaf.yaml"
sed -i -E '/^[[:space:]]*security_entry:/,/^[[:space:]]*background:/{s#^([[:space:]]*)enabled:.*#\1enabled: false#}' "${config_dir}/cheesewaf.yaml"

# Fail closed if a template format change made one of the installer-owned
# substitutions miss its target. A silent partial patch could start a service
# with a different listener, TLS mode, or security-entry route than the receipt.
installed_admin_listen="$(awk '$1 == "admin_listen:" {gsub(/"/, "", $2); print $2; exit}' "${config_dir}/cheesewaf.yaml")"
[[ "$installed_admin_listen" == "$admin_listen" ]] || die "failed to set server.admin_listen"
grep -Eq '^[[:space:]]+admin_public:[[:space:]]*true[[:space:]]*$' "${config_dir}/cheesewaf.yaml" || die "failed to enable public admin mode"
sed -n '/^[[:space:]]*admin_tls:[[:space:]]*$/,/^[[:space:]]*read_timeout:/p' "${config_dir}/cheesewaf.yaml" | grep -Eq '^[[:space:]]+enabled:[[:space:]]*true[[:space:]]*$' || die "failed to enable admin TLS"
installed_entry="$(sed -n '/^[[:space:]]*security_entry:[[:space:]]*$/,/^[[:space:]]*background:/p' "${config_dir}/cheesewaf.yaml" | awk '$1 == "path:" {gsub(/"/, "", $2); print $2; exit}')"
[[ "$installed_entry" == "/${entry}" ]] || die "failed to set security-entry path"
sed -n '/^[[:space:]]*security_entry:[[:space:]]*$/,/^[[:space:]]*background:/p' "${config_dir}/cheesewaf.yaml" | grep -Eq '^[[:space:]]+enabled:[[:space:]]*false[[:space:]]*$' || die "failed to keep security entry disabled during setup"

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
if [[ "$public_host" =~ ^\[([0-9A-Fa-f:.]+)\]$ ]]; then
  public_host="${BASH_REMATCH[1]}"
elif [[ "$public_host" == *:* ]]; then
  [[ "$public_host" =~ ^[0-9A-Fa-f:.]+$ ]] || die "invalid CHEESEWAF_ADMIN_PUBLIC_HOST"
elif [[ ! "$public_host" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]]; then
  die "invalid CHEESEWAF_ADMIN_PUBLIC_HOST"
fi
public_url_host="$public_host"
[[ "$public_url_host" == *:* ]] && public_url_host="[${public_url_host}]"
printf 'CHEESEWAF_ADMIN_PUBLIC_HOST=%s\n' "$public_host" >"${config_dir}/admin.env"
chmod 0640 "${config_dir}/admin.env"

if id cheesewaf >/dev/null 2>&1; then
  service_uid="$(id -u cheesewaf)"
  service_gid="$(id -g cheesewaf)"
  [[ "$service_uid" != "0" && "$service_gid" != "0" ]] || die "existing cheesewaf account must not be root"
else
  useradd --system --home "$data_dir" --shell /usr/sbin/nologin cheesewaf
fi
chown -R cheesewaf:cheesewaf "$config_dir" "$data_dir" "$log_dir"

if command -v systemctl >/dev/null 2>&1 && [[ -f "${unit_dir}/cheesewaf.service" && "${CHEESEWAF_NO_START:-0}" != "1" ]]; then
  systemctl daemon-reload
  systemctl enable cheesewaf >/dev/null
  systemctl restart cheesewaf
  service_state="$(systemctl is-active cheesewaf || true)"
else
  service_state="not started (systemd unavailable or CHEESEWAF_NO_START=1)"
fi

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
