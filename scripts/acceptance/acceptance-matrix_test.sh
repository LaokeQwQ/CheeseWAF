#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
runner="${repo_root}/scripts/acceptance/matrix.sh"
fail() { echo "FAIL: $*" >&2; exit 1; }
[[ -x "$runner" ]] || fail "missing executable matrix runner"

work_root="$(mktemp -d "${TMPDIR:-/tmp}/cheesewaf-matrix-test.XXXXXX")"
trap 'rm -rf "$work_root"' EXIT
report="${work_root}/report.json"
markdown="${work_root}/report.md"

set +e
bash "$runner" --list >"${work_root}/list.out" 2>&1
status=$?
set -e
[[ $status -eq 0 ]] || { cat "${work_root}/list.out" >&2; fail "--list failed"; }
grep -Fq 'temporary_get_started' "${work_root}/list.out" || fail "temporary gate missing"
grep -Fq 'production_fail_closed' "${work_root}/list.out" || fail "production gate missing"
for gate in control_health_ready_status control_postgres_dsn native_raft_single_node_restart native_raft_join_only crp_activation crp_rollback approval_http token_strict_identity diagnostics_encryption diagnostics_queue diagnostics_runtime_delivery offline_no_egress temporary_network_confirmation production_artifact_scan cleanup_no_tracked_pollution; do
  grep -Fxq "$gate" "${work_root}/list.out" || fail "v2 gate missing: $gate"
done

set +e
bash "$runner" --static --report "$report" --markdown "$markdown" >"${work_root}/run.out" 2>&1
status=$?
set -e
[[ $status -ne 0 ]] || fail "static matrix unexpectedly passed despite known unimplemented gates"
[[ -s "$report" ]] || fail "machine-readable report missing"
[[ -s "$markdown" ]] || fail "markdown report missing"
python3 - "$report" <<'PY'
import json, sys
data = json.load(open(sys.argv[1], encoding='utf-8'))
assert data['schema_version'] == 2
assert data['summary']['total'] >= 20
assert data['summary']['failed'] >= 1
assert data['summary']['skipped'] == 0
assert all('positive' in gate and 'negative' in gate for gate in data['gates'])
assert any(g['id'] == 'crp_activation' and g['status'] == 'failed' for g in data['gates'])
for gate in data['gates']:
    assert gate['status'] in {'pass', 'failed'}, gate
    assert gate['scope'], gate
    for side in ('positive', 'negative'):
        assert gate[side]['command'], gate
        assert gate[side]['evidence'], gate
        assert gate[side]['status'] in {'pass', 'failed'}, gate
        if gate[side]['command'].startswith('go test '):
            assert '[no tests to run]' not in gate[side]['evidence'], gate
    if not gate['implemented']:
        assert gate['status'] == 'failed' and gate['blockers'], gate
    if gate['status'] == 'pass':
        assert all(gate[side]['status'] == 'pass' for side in ('positive', 'negative')), gate
assert data['cleanup']['runtime_removed'] is True
assert data['cleanup']['processes_stopped'] is True
assert data['cleanup']['source_template_unchanged'] is True
PY
python3 -m unittest discover -s "${repo_root}/scripts/acceptance" -p '*_test.py'

echo "acceptance matrix v2 contract tests passed"
