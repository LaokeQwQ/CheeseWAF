#!/usr/bin/env bash
set -euo pipefail

# Build a clean, deduplicated formal snapshot before replaying or evaluating
# semantic cases. Raw testdata paths are inputs to governance only; every
# detector-facing command below consumes the hash-bound formal artifact.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
tmp_parent="${TMPDIR:-/tmp}"
if [[ "${tmp_parent}" != /* ]]; then
  tmp_parent="${PWD}/${tmp_parent}"
fi
if ! tmp_parent="$(cd "${tmp_parent}" 2>/dev/null && pwd -P)"; then
  echo "TMPDIR must name an existing directory: ${TMPDIR:-/tmp}" >&2
  exit 1
fi
tmp_dir="$(mktemp -d "${tmp_parent}/cheesewaf-governed-gate.XXXXXX")"
config_file="${tmp_dir}/governance-config.json"
output_dir="${tmp_dir}/output"
formal="${output_dir}/formal.jsonl"
manifest="${output_dir}/manifest.json"
summary="${output_dir}/summary.json"
replay_report="${output_dir}/replay.json"
quarantine_source="${repo_root}/internal/engine/semantic/testdata/quarantine_malformed_samples.jsonl"
mkdir -p "${output_dir}"
trap 'rm -rf "${tmp_dir}"' EXIT

python3 - "${config_file}" "${output_dir}" <<'PY'
import json
import pathlib
import sys

config_path = pathlib.Path(sys.argv[1])
output = pathlib.Path(sys.argv[2])
sources = [
    "internal/engine/semantic/testdata/curated_external_shapes.jsonl",
    "internal/engine/semantic/testdata/benign_production_shapes.jsonl",
    "internal/engine/semantic/testdata/handcrafted_attack_neighbors.jsonl",
]
config = {
    "pipeline_version": "corpus-governance-v1",
    "rule_version": "v1",
    "sources": [
        {
            "path": path,
            "name": path,
            "license": "repository-curated",
            "access": "local-file",
            "allow_formal": True,
        }
        for path in sources
    ],
    "limits": {
        "max_records": 100000,
        "max_input_bytes": 1073741824,
        "max_decompressed_bytes": 1073741824,
        "max_expansion_ratio": 200,
    },
    "formal_path": str(output / "formal.jsonl"),
    "quarantine_path": str(output / "quarantine.jsonl"),
    "manifest_path": str(output / "manifest.json"),
}
with config_path.open("w", encoding="utf-8") as stream:
    json.dump(config, stream, ensure_ascii=False, indent=2)
    stream.write("\n")
PY

(
  cd "${repo_root}"
  bash scripts/ci/go-env.sh go run ./cmd/cheesewaf-corpus \
    --mode govern \
    --governance-config "${config_file}" \
    --output "${summary}"
)

python3 - "${formal}" "${manifest}" "${quarantine_source}" <<'PY'
import collections
import hashlib
import json
import os
import sys

formal_path, manifest_path, quarantine_source = sys.argv[1:]
with open(manifest_path, encoding="utf-8") as stream:
    manifest = json.load(stream)
if not isinstance(manifest, dict):
    raise SystemExit("governed gate manifest must be a JSON object")
digest = hashlib.sha256()
labels = {"benign": 0, "attack": 0}
categories = collections.Counter()
sources = collections.Counter()
rows = 0
with open(formal_path, "rb") as stream:
    for raw in stream:
        if not raw.strip():
            continue
        digest.update(raw)
        row = json.loads(raw)
        label = row.get("label")
        if label not in labels:
            raise SystemExit(f"formal snapshot contains unsupported label: {label!r}")
        if not row.get("fingerprint") or not row.get("raw_hash") or not row.get("governance_source"):
            raise SystemExit("formal snapshot row is missing governance provenance")
        labels[label] += 1
        categories[f"{label}:{row.get('category') or ''}"] += 1
        sources[row["governance_source"]] += 1
        rows += 1

expected_labels = {"benign": 293, "attack": 14040}
expected_categories = {
    "attack:lfi": 3411,
    "attack:nosqli": 4409,
    "attack:rce": 22,
    "attack:sqli": 1340,
    "attack:ssrf": 361,
    "attack:ssti": 28,
    "attack:xss": 4466,
    "attack:xxe": 3,
    "benign:": 293,
}
expected_sources = {
    "internal/engine/semantic/testdata/benign_production_shapes.jsonl": 82,
    "internal/engine/semantic/testdata/curated_external_shapes.jsonl": 14225,
    "internal/engine/semantic/testdata/handcrafted_attack_neighbors.jsonl": 26,
}
expected_input_hashes = {
    "internal/engine/semantic/testdata/benign_production_shapes.jsonl": "46dc5c810c381cbc22a42591117b8f8a5a41fabafec5940d19b89d3ed4f0bf44",
    "internal/engine/semantic/testdata/curated_external_shapes.jsonl": "7954e503e0af3ac38bd359dcf66de50a4ed24f6a682fadb745e8b7ee515ecb1f",
    "internal/engine/semantic/testdata/handcrafted_attack_neighbors.jsonl": "ed621cf76e3e9ce7312d4315f26aeef6ba281fcbd35b920011697d921307d52e",
}
expected_quarantine_source_hash = "3738156cb70b46d4b3fbd2b3a26bf201833370a9db2b166c0f800ce04fe68914"
expected_quarantine_line_hash = "bf001e3b558a0a1ef65316124db9cd55c176fa5580f8340dca85052883b94224"
# These values bind the detector-facing snapshot to the reviewed governance
# pipeline and exact formal rows. A manifest cannot make a changed pipeline or
# substituted same-count rows look clean by merely recomputing its own hash.
expected_pipeline = "corpus-governance-v1"
expected_version = "v1"
expected_policy_hash = "f7a14247f037ad6e984eb08abc0189a6f05a6c8850747717b68903cce9d7731a"
expected_review_hash = "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"
expected_formal_hash = "5a5173d3d52067f10be2b18cbbcc1ee6dd8db1743ae277e71896ca3c1549af75"

if not os.path.isfile(quarantine_source):
    raise SystemExit("pinned quarantine source is missing")
with open(quarantine_source, "rb") as stream:
    quarantine_bytes = stream.read()
if hashlib.sha256(quarantine_bytes).hexdigest() != expected_quarantine_source_hash:
    raise SystemExit("pinned quarantine source changed; review its explicit isolation decision")
quarantine_lines = [line for line in quarantine_bytes.splitlines() if line.strip()]
if len(quarantine_lines) != 1 or hashlib.sha256(quarantine_lines[0]).hexdigest() != expected_quarantine_line_hash:
    raise SystemExit("pinned quarantine source identity changed")

if manifest.get("pipeline") != expected_pipeline:
    raise SystemExit(
        f"governed gate pipeline changed: {manifest.get('pipeline')!r} != {expected_pipeline!r}"
    )
if manifest.get("version") != expected_version:
    raise SystemExit(
        f"governed gate rule version changed: {manifest.get('version')!r} != {expected_version!r}"
    )
if manifest.get("policy_hash") != expected_policy_hash:
    raise SystemExit("governed gate policy hash changed; review the governance policy explicitly")
if manifest.get("review_hash") != expected_review_hash:
    raise SystemExit("governed gate review hash changed; review decisions must be audited explicitly")

def require_non_negative_int(name):
    value = manifest.get(name)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise SystemExit(f"governed gate manifest field {name!r} must be a non-negative integer")
    return value


by_decision = manifest.get("by_decision")
if not isinstance(by_decision, dict):
    raise SystemExit("governed gate manifest field 'by_decision' must be an object")
hard_reject = by_decision.get("hard_reject")
if isinstance(hard_reject, bool) or not isinstance(hard_reject, int) or hard_reject < 0:
    raise SystemExit("governed gate manifest field 'by_decision.hard_reject' must be a non-negative integer")
rejected = require_non_negative_int("rejected")
formal_count = require_non_negative_int("formal")
output_hashes = manifest.get("output_hashes")
if not isinstance(output_hashes, dict):
    raise SystemExit("governed gate manifest field 'output_hashes' must be an object")
formal_hash = output_hashes.get("formal")
if not isinstance(formal_hash, str) or not formal_hash:
    raise SystemExit("governed gate manifest field 'output_hashes.formal' must be a non-empty string")

if rows != formal_count:
    raise SystemExit(f"formal line count mismatch: {rows} != {manifest.get('formal')}")
if digest.hexdigest() != formal_hash:
    raise SystemExit("formal snapshot hash mismatch")
if formal_hash != expected_formal_hash:
    raise SystemExit("governed formal snapshot hash changed; review the exact formal rows explicitly")
if rejected != 0:
    raise SystemExit("governed gate input contains structurally rejected rows")
if hard_reject != 0:
    raise SystemExit(f"governed gate input contains hard-rejected rows: {by_decision}")
if labels != expected_labels:
    raise SystemExit(f"governed gate label baseline changed: {labels} != {expected_labels}")
if dict(categories) != expected_categories:
    raise SystemExit(f"governed gate category baseline changed: {dict(categories)} != {expected_categories}")
if dict(sources) != expected_sources:
    raise SystemExit(f"governed gate source baseline changed: {dict(sources)} != {expected_sources}")
if manifest.get("input_hashes") != expected_input_hashes:
    raise SystemExit("governed gate input hashes changed; review and update the pinned corpus baseline explicitly")
print(f"governed formal snapshot: rows={rows} benign={labels['benign']} attack={labels['attack']}")
PY

(
  cd "${repo_root}"
  bash scripts/ci/go-env.sh go run ./cmd/cheesewaf-corpus \
    --mode analyzer \
    --corpus "${formal}" \
    --output "${replay_report}"

  SEMANTIC_EVAL_GOVERNED_CORPUS="${formal}" \
  SEMANTIC_EVAL_GOVERNANCE_MANIFEST="${manifest}" \
  FPR_GATE="${FPR_GATE-0.8}" \
  TPR_GATE="${TPR_GATE-99.0}" \
  FPR_MIN_BENIGN="${FPR_MIN_BENIGN-250}" \
  TPR_MIN_ATTACK="${TPR_MIN_ATTACK-10000}" \
    bash scripts/ci/go-env.sh go test \
      -run '^TestEvaluationPlatform$' \
      -short \
      -count=1 \
      ./internal/engine/semantic/
)

echo "governed semantic replay and evaluation passed"
