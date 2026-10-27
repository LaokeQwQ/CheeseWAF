#!/usr/bin/env bash
# Isolated instance lifecycle for the CheeseWAF attack-chain audit.
set -euo pipefail

HARNESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=env.sh
source "$HARNESS_DIR/env.sh"

cmd="${1:-}"; id="${2:-}"
if [[ -z "$cmd" || -z "$id" ]]; then
  echo "usage: instance.sh <up|finish-setup|set|restart|down|reset|status|logs> <ID> [args]" >&2
  exit 2
fi

read -r DATA_PORT ADMIN_PORT ORIGIN_PORT <<<"$(port_for "$id")"
DIR="$AU_ROOT/$id"
CFG="$DIR/config/cheesewaf.yaml"
ENVF="$DIR/instance.env"
mkdir -p "$DIR/config" "$DIR/data" "$DIR/logs"

load_env() {
  ADAPTER_TOKEN=""; ENTRY_ENABLED="false"; ENTRY_PATH="/__cheesewaf-entry"
  CAPTCHA_ENABLED="false"; ADMIN_TLS_ENABLED="false"
  HTTP3_ENABLED="false"; HTTP3_LISTEN=""; WS_ENABLED="false"; CLUSTER_ENABLED="false"
  case "$id" in
    T1) ENTRY_ENABLED="true"; ENTRY_PATH="/g7k2m9" ;;
    T3) ADAPTER_TOKEN="audit-adapter-token-T3" ;;
  esac
  if [[ -f "$ENVF" ]]; then source "$ENVF"; fi
}

render() {
  load_env
  local tmp="$CFG.tmp"
  sed -e "s|__DATA_PORT__|$DATA_PORT|g" \
      -e "s|__ADMIN_PORT__|$ADMIN_PORT|g" \
      -e "s|__ORIGIN_PORT__|$ORIGIN_PORT|g" \
      -e "s|__DIR__|$DIR|g" \
      -e "s|__ADAPTER_TOKEN__|$ADAPTER_TOKEN|g" \
      -e "s|__ENTRY_ENABLED__|$ENTRY_ENABLED|g" \
      -e "s|__ENTRY_PATH__|$ENTRY_PATH|g" \
      -e "s|__CAPTCHA_ENABLED__|$CAPTCHA_ENABLED|g" \
      -e "s|__ADMIN_TLS_ENABLED__|$ADMIN_TLS_ENABLED|g" \
      -e "s|__HTTP3_ENABLED__|$HTTP3_ENABLED|g" \
      -e "s|__HTTP3_LISTEN__|$HTTP3_LISTEN|g" \
      -e "s|__WS_ENABLED__|$WS_ENABLED|g" \
      -e "s|__CLUSTER_ENABLED__|$CLUSTER_ENABLED|g" \
      "$HARNESS_DIR/config.template.yaml" > "$tmp"
  mv "$tmp" "$CFG"
}

wait_ready() {
  local i
  for i in $(seq 1 40); do
    if grep -q "CheeseWAF admin API listening on" "$DIR/serve.log" 2>/dev/null; then
      return 0
    fi
    if [[ -f "$DIR/serve.pid" ]] && ! kill -0 "$(cat "$DIR/serve.pid")" 2>/dev/null; then
      echo "serve exited early" >&2
      tail -50 "$DIR/serve.log" >&2 || true
      return 1
    fi
    sleep 0.5
  done
  echo "serve did not become ready in 20s" >&2
  tail -50 "$DIR/serve.log" >&2 || true
  return 1
}

start_serve() {
  CHEESEWAF_WEB_DIR="$DIR/web" nohup "$BIN" serve \
    --config "$CFG" --data-dir "$DIR/data" > "$DIR/serve.log" 2>&1 &
  echo $! > "$DIR/serve.pid"
  wait_ready
}

stop_pid() {
  local f="$1"
  if [[ -f "$f" ]]; then
    local pid; pid="$(cat "$f")"
    if kill -0 "$pid" 2>/dev/null; then kill "$pid" 2>/dev/null || true; fi
    for _ in $(seq 1 20); do kill -0 "$pid" 2>/dev/null || break; sleep 0.2; done
    kill -9 "$pid" 2>/dev/null || true
    rm -f "$f"
  fi
}

start_origin() {
  python3 "$HARNESS_DIR/origin.py" --port "$ORIGIN_PORT" --log "$DIR/origin.jsonl" --pid "$DIR/origin.pid" &
  echo $! > "$DIR/origin.pid"
  sleep 0.3
}

do_up() {
  local no_setup="${1:-}"
  stop_pid "$DIR/serve.pid"; stop_pid "$DIR/origin.pid"
  rm -rf "$DIR"; mkdir -p "$DIR/config" "$DIR/data" "$DIR/logs" "$DIR/web"
  cp -R "$REPO/web/dist/." "$DIR/web/" 2>/dev/null || true
  if [[ ! -s "$DIR/web/index.html" ]]; then echo "warning: web/dist missing" >&2; fi
  render
  start_origin
  start_serve
  echo "instance $id up: data=127.0.0.1:$DATA_PORT admin=127.0.0.1:$ADMIN_PORT origin=127.0.0.1:$ORIGIN_PORT"
  if [[ "$no_setup" != "--no-setup" ]]; then
    do_finish_setup
    bash "$HARNESS_DIR/selftest.sh" "$id"
  fi
}

do_finish_setup() {
  printf '%s\n' "$PASSWORD" | "$BIN" setup --yes \
    --username admin --password-stdin --profile low \
    --admin-listen "127.0.0.1:$ADMIN_PORT" --skip-probe --skip-external \
    --config "$CFG" --data-dir "$DIR/data" > "$DIR/setup.log" 2>&1
  render
  stop_pid "$DIR/serve.pid"
  start_serve
  echo "setup complete for $id (admin/admin)"
}

do_set() {
  shift 2 || true
  touch "$ENVF"
  local kv
  for kv in "$@"; do
    local k="${kv%%=*}" v="${kv#*=}"
    if grep -q "^${k}=" "$ENVF"; then
      sed -i.bak "s|^${k}=.*|${k}=\"${v}\"|" "$ENVF"
    else
      printf '%s="%s"\n' "$k" "$v" >> "$ENVF"
    fi
  done
  rm -f "$ENVF.bak"
  render
  stop_pid "$DIR/serve.pid"
  start_serve
  echo "applied: $*"
}

do_down() { stop_pid "$DIR/serve.pid"; stop_pid "$DIR/origin.pid"; }
do_reset() { do_down; rm -rf "$DIR"; }
do_status() {
  for p in serve origin; do
    if [[ -f "$DIR/$p.pid" ]] && kill -0 "$(cat "$DIR/$p.pid")" 2>/dev/null; then
      echo "$p: running ($(cat "$DIR/$p.pid"))"
    else
      echo "$p: stopped"
    fi
  done
  echo "data=$DATA_PORT admin=$ADMIN_PORT origin=$ORIGIN_PORT"
}

case "$cmd" in
  up) do_up "${3:-}" ;;
  finish-setup) do_finish_setup ;;
  set) do_set "$@" ;;
  restart) do_down; start_origin; start_serve ;;
  down) do_down ;;
  reset) do_reset ;;
  status) do_status ;;
  logs) tail -n 80 "$DIR/serve.log" 2>/dev/null || true ;;
  *) echo "unknown command: $cmd" >&2; exit 2 ;;
esac
