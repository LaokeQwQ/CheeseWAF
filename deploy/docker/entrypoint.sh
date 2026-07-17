#!/bin/sh
set -eu

config_path="${CHEESEWAF_CONFIG:-/var/lib/cheesewaf/config/cheesewaf.yaml}"
template_path="/usr/share/cheesewaf/config/cheesewaf.yaml"

if [ -L "$config_path" ]; then
  echo "CheeseWAF configuration path must not be a symbolic link" >&2
  exit 1
fi

if [ ! -e "$config_path" ]; then
  config_dir=$(dirname "$config_path")
  mkdir -p "$config_dir"
  umask 077
  temporary_path="${config_path}.tmp.$$"
  trap 'rm -f "$temporary_path"' EXIT HUP INT TERM
  cp "$template_path" "$temporary_path"
  chmod 600 "$temporary_path"
  mv "$temporary_path" "$config_path"
  trap - EXIT HUP INT TERM
fi

exec /usr/local/bin/cheesewaf \
  --config "$config_path" \
  --data-dir /var/lib/cheesewaf \
  "$@"
