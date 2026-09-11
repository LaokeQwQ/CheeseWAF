#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
mode="smoke"
case "${1:-}" in
  "") ;;
  --static-contract) mode="static" ;;
  --smoke) mode="smoke" ;;
  -h|--help) echo "usage: $0 [--smoke|--static-contract]"; exit 0 ;;
  *) echo "unknown option: $1" >&2; exit 2 ;;
esac

fail() { echo "::error::$*" >&2; exit 1; }
require_cmd() { command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"; }
require_cmd git
require_cmd go
require_cmd mktemp
require_cmd shasum

source_config="${repo_root}/configs/cheesewaf.yaml"
[[ -r "$source_config" ]] || fail "missing template: $source_config"
source_hash="$(shasum -a 256 "$source_config" | awk '{print $1}')"
work_root="$(mktemp -d "${TMPDIR:-/tmp}/cheesewaf-get-started.XXXXXX")"
service_pid=""
cleanup() {
  if [[ -n "$service_pid" ]] && kill -0 "$service_pid" 2>/dev/null; then
    kill "$service_pid" 2>/dev/null || true
    wait "$service_pid" 2>/dev/null || true
  fi
  rm -rf "$work_root"
}
trap cleanup EXIT INT TERM

runtime_dir="${work_root}/data"
config_dir="${runtime_dir}/config"
mkdir -p "$config_dir"
cp "$source_config" "${config_dir}/cheesewaf.yaml"
runtime_config="${config_dir}/cheesewaf.yaml"

assert_template_unchanged() {
  [[ "$(shasum -a 256 "$source_config" | awk '{print $1}')" == "$source_hash" ]] || fail "source config template changed during acceptance"
}

static_contract() {
  grep -Eq '^    profile: temporary$' "$source_config" || fail "template must default to temporary profile"
  grep -Fq 'production requires management_postgresql.dsn' "$source_config" || fail "template must document production boundary"
  grep -Fq 'ErrProductionStorageUnavailable' README.md || fail "README must document production fail-closed behavior"
  grep -Fq 'ErrProductionStorageUnavailable' README_CN.md || fail "README_CN must document production fail-closed behavior"
  grep -Fq 'data/config/cheesewaf.yaml' README.md || fail "README must use runtime config copy"
  grep -Fq 'data/config/cheesewaf.yaml' README_CN.md || fail "README_CN must use runtime config copy"
  bash -n "$0"
  assert_template_unchanged
  echo "temporary profile contract verified"
  echo "production profile rejected contract verified"
  echo "runtime data isolated in temporary directory"
  echo "cleanup verified"
}

if [[ "$mode" == static ]]; then static_contract; exit 0; fi

require_cmd curl
require_cmd python3
read -r data_port admin_port cluster_port < <(python3 - <<'PY'
import socket
ports=[]
for _ in range(3):
    s=socket.socket(); s.bind(("127.0.0.1", 0)); ports.append(str(s.getsockname()[1])); s.close()
print(*ports)
PY
)
sed -i.bak -e "s#127.0.0.1:8080#127.0.0.1:${data_port}#" -e "s#127.0.0.1:9443#127.0.0.1:${admin_port}#" -e "s#127.0.0.1:9444#127.0.0.1:${cluster_port}#" "$runtime_config"
rm -f "${runtime_config}.bak"

binary="${work_root}/cheesewaf"
CGO_ENABLED=0 go build -trimpath -o "$binary" ./cmd/cheesewaf/
echo "backend build verified"
"$binary" serve --config "$runtime_config" --data-dir "$runtime_dir" >"${work_root}/serve.log" 2>&1 &
service_pid=$!
ready=0
for _ in $(seq 1 40); do
  if curl -fsS --max-time 1 "http://127.0.0.1:${admin_port}/health/ready" >/dev/null 2>&1; then ready=1; break; fi
  if ! kill -0 "$service_pid" 2>/dev/null; then break; fi
  sleep 0.25
done
[[ "$ready" == 1 ]] || { cat "${work_root}/serve.log" >&2; fail "temporary profile service did not become ready"; }
[[ -s "${runtime_dir}/cheesewaf.db" ]] || fail "temporary SQLite database was not created under data dir"
[[ -s "${runtime_dir}/setup.url" ]] || fail "initialization setup URL was not created under data dir"
echo "temporary profile initialization/start smoke verified"
kill "$service_pid" 2>/dev/null || true
wait "$service_pid" 2>/dev/null || true
service_pid=""

production_config="${work_root}/production.yaml"
cp "$runtime_config" "$production_config"
sed -i.bak -e 's/^    profile: temporary$/    profile: production/' -e 's#dsn: ""#dsn: "postgres://control.example.invalid/cheesewaf"#' "$production_config"
rm -f "${production_config}.bak"
set +e
"$binary" serve --config "$production_config" --data-dir "${work_root}/production-data" >"${work_root}/production.log" 2>&1
production_status=$?
set -e
grep -Eq 'ErrProductionStorageUnavailable|refusing SQLite fallback|cluster/epoch' "${work_root}/production.log" || { cat "${work_root}/production.log" >&2; fail "production profile did not fail closed with an explicit storage error"; }
[[ "$production_status" -ne 0 ]] || fail "production profile unexpectedly started"
[[ ! -e "${work_root}/production-data/cheesewaf.db" ]] || fail "production profile touched SQLite fallback"
echo "production profile rejected as expected"
assert_template_unchanged
echo "runtime data isolated in temporary directory"
echo "cleanup verified"
