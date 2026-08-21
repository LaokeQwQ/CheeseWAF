#!/usr/bin/env bash
# Install a Linux CheeseWAF archive onto FHS paths. Run from the extracted package root.
set -euo pipefail

prefix="${CHEESEWAF_PREFIX:-/usr/local}"
bin_dir="${prefix}/bin"
web_dir="${CHEESEWAF_WEB_DIR:-/usr/share/cheesewaf/web}"
config_dir="${CHEESEWAF_CONFIG_DIR:-/etc/cheesewaf}"
data_dir="${CHEESEWAF_DATA_DIR:-/var/lib/cheesewaf}"
log_dir="${CHEESEWAF_LOG_DIR:-/var/log/cheesewaf}"
unit_dir="${CHEESEWAF_UNIT_DIR:-/etc/systemd/system}"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "install-linux.sh is for Linux hosts" >&2
  exit 1
fi
if [[ "$(id -u)" -ne 0 ]]; then
  echo "run as root (sudo ./install-linux.sh)" >&2
  exit 1
fi
[[ -x ./cheesewaf ]] || {
  echo "cheesewaf binary not found in $(pwd)" >&2
  exit 1
}
[[ -f ./web/dist/index.html ]] || {
  echo "web/dist/index.html missing; extract the full tar.gz, not just the binary" >&2
  exit 1
}

install -d -m 0755 "$bin_dir" "$web_dir" "$config_dir" "$data_dir" "$log_dir"
install -m 0755 ./cheesewaf "${bin_dir}/cheesewaf"
ln -sfn "${bin_dir}/cheesewaf" "${bin_dir}/waf-cli"
if [[ -x ./waf-cli ]]; then
  install -m 0755 ./waf-cli "${bin_dir}/waf-cli-wrapper"
fi
cp -R ./web/dist/. "$web_dir/"
if [[ -f ./configs/cheesewaf.yaml && ! -e "${config_dir}/cheesewaf.yaml" ]]; then
  install -m 0640 ./configs/cheesewaf.yaml "${config_dir}/cheesewaf.yaml"
fi
if [[ -f ./systemd/cheesewaf.service ]]; then
  install -m 0644 ./systemd/cheesewaf.service "${unit_dir}/cheesewaf.service"
fi

if ! id cheesewaf >/dev/null 2>&1; then
  useradd --system --home "$data_dir" --shell /usr/sbin/nologin cheesewaf
fi
chown -R cheesewaf:cheesewaf "$config_dir" "$data_dir" "$log_dir"

echo "Installed ${bin_dir}/cheesewaf"
echo "Admin UI files: ${web_dir}"
echo "Config: ${config_dir}/cheesewaf.yaml"
echo "Next: systemctl daemon-reload && systemctl enable --now cheesewaf"
echo "Then open http://127.0.0.1:9443/setup (default admin bind is loopback)."
