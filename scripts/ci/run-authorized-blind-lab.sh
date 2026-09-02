#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
tmp_parent="${TMPDIR:-/tmp}"
[[ "$tmp_parent" = /* ]] || tmp_parent="$repo_root/$tmp_parent"
tmp_parent="$(cd "$tmp_parent" && pwd -P)"
tmp_dir="$(mktemp -d "${tmp_parent%/}/cheesewaf-authorized-blind-lab.XXXXXX")"
lab_dir="$tmp_dir/lab"
mkdir -m 700 "$lab_dir"
trap 'rm -rf "$tmp_dir"' EXIT

command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 1; }
command -v go >/dev/null || { echo "go is required" >&2; exit 1; }

run_logged() {
  local log="$1"; shift
  "$@" >"$log" 2>&1 || { tail -n 40 "$log" >&2; return 1; }
}

cd "$repo_root"
run_logged "$tmp_dir/lab.log" bash scripts/ci/go-env.sh go run ./scripts/e2e/blind-lab --timestamp 2025-01-01T00:00:00Z --output-dir "$lab_dir"
[[ -f "$lab_dir/cases.jsonl" ]] || { echo "blind lab did not produce cases.jsonl" >&2; exit 1; }

python3 - "$lab_dir" "$tmp_dir" <<'PY'
import hashlib, json, pathlib, sys
lab, root = map(pathlib.Path, sys.argv[1:])
manifest = json.loads((lab / "manifest.json").read_text())
grouping = manifest.get("grouping", [])
cases = [json.loads(line) for line in (lab / "cases.jsonl").read_text().splitlines() if line.strip()]
def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
if manifest.get("record_count") != len(cases) or len(grouping) != len(cases):
    raise SystemExit("blind-lab manifest record count mismatch")
for field, filename in (("snapshot_sha256", "snapshot.jsonl"), ("evaluation_sha256", "evaluation.jsonl"), ("cases_sha256", "cases.jsonl"), ("grouping_sha256", "grouping.jsonl")):
    if manifest.get(field) != digest(lab / filename):
        raise SystemExit(f"blind-lab {filename} hash mismatch")
case_names = {case.get("name") for case in cases}
group_names = {entry.get("id") for entry in grouping}
if None in case_names or case_names != group_names:
    raise SystemExit("blind-lab grouping does not bind exactly to case names")
(root / "grouping.jsonl").write_text("".join(json.dumps(x, separators=(",", ":")) + "\n" for x in grouping))
(root / "grouping.jsonl").chmod(0o600)
sources = []
for i, case in enumerate(cases):
    p = root / f"case-{i}.jsonl"; p.write_text(json.dumps(case) + "\n"); p.chmod(0o600)
    sources.append({"path": str(p), "name": f"local-generated-blind-lab-{i}", "license": "project-license", "access": "local-generated", "allow_formal": True})
config = {
    "pipeline_version": "corpus-governance-v1", "rule_version": "v1",
    "sources": sources,
    "limits": {"max_records": 32, "max_input_bytes": 1 << 20, "max_decompressed_bytes": 1 << 20, "max_expansion_ratio": 10},
    "formal_path": str(root / "formal.jsonl"), "quarantine_path": str(root / "quarantine.jsonl"),
    "manifest_path": str(root / "manifest.json"),
}
(root / "governance.json").write_text(json.dumps(config, indent=2) + "\n")
(root / "split.json").write_text(json.dumps({"seed": "authorized-blind-lab-41", "validation_fraction": 0.25, "blind_fraction": 0.25}) + "\n")
(root / "governance.json").chmod(0o600)
(root / "split.json").chmod(0o600)
PY

run_logged "$tmp_dir/govern.log" bash scripts/ci/go-env.sh go run ./cmd/cheesewaf-corpus --mode govern \
  --governance-config "$tmp_dir/governance.json" --output "$tmp_dir/govern-summary.json"
python3 - "$tmp_dir/manifest.json" "$tmp_dir/formal.jsonl" <<'PY'
import json, pathlib, sys
m = json.loads(pathlib.Path(sys.argv[1]).read_text())
assert m["formal"] == 4 and m["quarantine"] == 0 and m["by_decision"].get("hard_reject", 0) == 0
assert pathlib.Path(sys.argv[2]).stat().st_size > 0
PY

# Bind the envelope to the governed formal rows; grouping metadata never enters detector cases.
python3 - "$tmp_dir/formal.jsonl" "$tmp_dir/grouping.jsonl" "$tmp_dir/envelope.jsonl" <<'PY'
import json, pathlib, sys
formal, grouping, out = map(pathlib.Path, sys.argv[1:])
meta = {x["id"]: x for x in map(json.loads, grouping.read_text().splitlines()) if x}
rows = []
for line in formal.read_text().splitlines():
    case = json.loads(line); g = meta[case["name"]]
    # Governance annotations belong to the envelope, while the nested detector
    # case must remain the canonical Case schema.
    annotations = {k: case.pop(k) for k in list(case) if k.startswith("governance_") or k in {"fingerprint", "raw_hash", "decision", "review_rule_version", "rule_version", "reviewer", "review_reason", "reviewed_at"}}
    source = annotations.get("governance_source")
    if not source:
        raise SystemExit(f"formal row {case.get('name', '<unknown>')} is missing governance_source")
    path = annotations.get("governance_path")
    if not path:
        raise SystemExit(f"formal row {case.get('name', '<unknown>')} is missing governance_path")
    rows.append({"case": case, "governance_source": source, "site": g["site"], "session": g["session"], "timestamp": g["timestamp"], "fingerprint": g["fingerprint"], "governance_path": path, "governance_line": annotations.get("governance_line", 0), "raw_hash": annotations.get("raw_hash", ""), "decision": annotations.get("decision", "auto"), "review_rule_version": annotations.get("review_rule_version", ""), "reviewer": annotations.get("reviewer", ""), "review_reason": annotations.get("review_reason", ""), "reviewed_at": annotations.get("reviewed_at", "")})
out.write_text("".join(json.dumps(x, separators=(",", ":")) + "\n" for x in rows))
PY
run_logged "$tmp_dir/split.log" bash scripts/ci/go-env.sh go run ./cmd/cheesewaf-corpus --mode split \
  --corpus "$tmp_dir/envelope.jsonl" --split-config "$tmp_dir/split.json" \
  --governance-manifest "$tmp_dir/manifest.json" --governance-formal "$tmp_dir/formal.jsonl" \
  --output "$tmp_dir/evaluation-split.json"

artifact_hash="$(shasum -a 256 "$tmp_dir/evaluation-split.json" | awk '{print $1}')"
run_logged "$tmp_dir/replay.log" bash scripts/ci/go-env.sh go run ./cmd/cheesewaf-corpus --mode evaluate-split \
  --corpus "$tmp_dir/evaluation-split.json" --governance-manifest "$tmp_dir/manifest.json" \
  --expected-artifact-sha256 "$artifact_hash" --evaluation-split blind --output "$tmp_dir/blind-report.json"
run_logged "$tmp_dir/lock.log" bash scripts/ci/lock-evaluation-artifact.sh \
  "$tmp_dir/evaluation-split.json" "$tmp_dir/manifest.json" blind "$tmp_dir/blind.lock.json"

python3 - "$tmp_dir" <<'PY'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1]); report = json.loads((root / "blind-report.json").read_text()); lock = json.loads((root / "blind.lock.json").read_text())
assert report.get("split") == "blind" and report.get("governance_manifest_sha256") and report.get("artifact_sha256")
assert report.get("evaluated_records", 0) == 2
assert report.get("benign_total", 0) == 1 and report.get("attack_total", 0) == 1
assert report.get("false_positive", 0) == 0 and report.get("attack_missed", 0) == 0
assert report.get("repaired", False) is False and report.get("groups", 0) >= 2
assert report.get("evaluated_records", 0) > 0 and lock.get("governed") is True and lock["capture"]["first_capture"] is True
PY
echo "authorized blind lab passed"
