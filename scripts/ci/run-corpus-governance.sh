#!/usr/bin/env bash
set -euo pipefail

# Run the corpus governance command against every JSONL corpus in testdata.
# Inputs are read-only; all configuration and outputs live below a temporary
# directory so CI cannot modify (or accidentally commit) corpus data.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
testdata_dir="${repo_root}/internal/engine/semantic/testdata"
tmp_parent="${TMPDIR:-/tmp}"
if [[ "${tmp_parent}" != /* ]]; then
  tmp_parent="${PWD}/${tmp_parent}"
fi
if ! tmp_parent="$(cd "${tmp_parent}" 2>/dev/null && pwd -P)"; then
  echo "TMPDIR must name an existing directory: ${TMPDIR:-/tmp}" >&2
  exit 1
fi
tmp_dir="$(mktemp -d "${tmp_parent}/cheesewaf-corpus-governance.XXXXXX")"
config_file="${tmp_dir}/governance-config.json"
output_dir="${CORPUS_GOVERNANCE_OUTPUT_DIR:-${tmp_dir}/output}"
# Resolve caller-provided relative output directories before changing into the
# repository below. Otherwise the Go command writes relative to the caller's
# directory while the post-run verifier resolves the same path from repo_root.
if [[ "${output_dir}" != /* ]]; then
  output_dir="${PWD}/${output_dir}"
fi
trap 'rm -rf "${tmp_dir}"' EXIT

command -v python3 >/dev/null 2>&1 || { echo "python3 is required to build the governance config" >&2; exit 1; }

# Structural corruption has no accepted debt.  The two non-zero defaults pin
# the currently-reviewed corpus debt and may be tightened (or explicitly
# overridden for a larger local optional corpus) without editing this script.
CORPUS_GOVERNANCE_MAX_PARSE_ERRORS="${CORPUS_GOVERNANCE_MAX_PARSE_ERRORS-0}"
CORPUS_GOVERNANCE_MAX_INVALID_UTF8="${CORPUS_GOVERNANCE_MAX_INVALID_UTF8-0}"
CORPUS_GOVERNANCE_MAX_OVERLONG="${CORPUS_GOVERNANCE_MAX_OVERLONG-0}"
CORPUS_GOVERNANCE_MAX_LABEL_CONFLICTS="${CORPUS_GOVERNANCE_MAX_LABEL_CONFLICTS-3}"
CORPUS_GOVERNANCE_MAX_REPAIRS="${CORPUS_GOVERNANCE_MAX_REPAIRS-127}"

# Build the source registry in Python so recursive enumeration, ordering and
# repository-relative names have identical semantics on GNU/Linux and macOS.
# Optional source recognition uses the logical JSONL leaf name, so a file keeps
# its optional status when it is nested or stored as .jsonl.gz.
python3 - "${repo_root}" "${testdata_dir}" "${output_dir}" "${config_file}" "${CORPUS_GOVERNANCE_REVIEW_PATH:-}" <<'PY'
import json
import pathlib
import sys

repo_root = pathlib.Path(sys.argv[1]).resolve()
testdata = pathlib.Path(sys.argv[2]).resolve()
output_dir = pathlib.Path(sys.argv[3]).resolve()
config_path = pathlib.Path(sys.argv[4])
review_path = sys.argv[5].strip()

try:
    output_dir.relative_to(testdata)
except ValueError:
    pass
else:
    raise SystemExit(
        f"governance output directory must not be inside corpus inputs: {output_dir}"
    )

# These files are intentionally git-ignored because of their size. Preserve
# their absence as auditable optional inputs instead of silently dropping them.
optional_leaves = {
    "cybersec_benign_clean.jsonl",
    "cybersec_attack_clean.jsonl",
    "mined_secprose_probe.jsonl",
    "openappsec_benign_clean.jsonl",
    "openappsec_attack_clean.jsonl",
    "modsec_attack_clean.jsonl",
}
research_quarantine_leaves = {"aetherguard_undetectable.jsonl"}
quarantine_only_leaves = {"quarantine_malformed_samples.jsonl"}


def logical_leaf(path):
    leaf = path.name.lower()
    return leaf[:-3] if leaf.endswith(".jsonl.gz") else leaf


def is_corpus(path):
    lower = path.name.lower()
    return path.is_file() and (lower.endswith(".jsonl") or lower.endswith(".jsonl.gz"))


def repo_name(path):
    return path.resolve().relative_to(repo_root).as_posix()


def truth_for(leaf):
    lower = leaf.lower()
    # This corpus is intentionally an attack research set whose upstream name
    # says only that the current detector did not model its classes.
    if lower in research_quarantine_leaves or lower in quarantine_only_leaves:
        return "attack"
    # Normalized Case files carry their own ground truth and may be mixed.
    # Only raw/payload-only sources require a file-level default.
    if "benign_clean" in lower or "secprose_probe" in lower:
        return "benign"
    if "attack" in lower:
        return "attack"
    return ""


def source(path, optional):
    path = path.resolve()
    leaf = logical_leaf(path)
    research_only = leaf in research_quarantine_leaves or leaf in quarantine_only_leaves
    stable_path = repo_name(path)
    # The governance core requires explicit provenance fields before a source
    # can be admitted to formal. These values describe local, already-present
    # files only; they do not assert external redistribution rights. Research-
    # only input is deliberately given a non-promotable access class.
    return {
        "path": stable_path,
        "name": stable_path,
        "default_truth": truth_for(leaf),
        "license": "unverified" if optional or research_only else "repository-curated",
        "access": "research-quarantine" if research_only else "local-file",
        "allow_formal": False,
        "optional": optional,
    }


all_files = sorted(
    (path for path in testdata.rglob("*") if is_corpus(path)),
    key=lambda path: path.relative_to(repo_root).as_posix(),
)
if not all_files:
    raise SystemExit(f"no JSONL corpus files found under {testdata}")

required = [path for path in all_files if logical_leaf(path) not in optional_leaves]
present_optional = [path for path in all_files if logical_leaf(path) in optional_leaves]
present_optional_leaves = {logical_leaf(path) for path in present_optional}

research_present = [path for path in required if logical_leaf(path) in research_quarantine_leaves]
if len(research_present) != 1:
    raise SystemExit(
        "required research source aetherguard_undetectable.jsonl must exist exactly once "
        "as .jsonl or .jsonl.gz"
    )

sources = [source(path, False) for path in required]
sources.extend(source(path, True) for path in present_optional)
for leaf in sorted(optional_leaves - present_optional_leaves):
    sources.append(source(testdata / leaf, True))

config = {
    "pipeline_version": "corpus-governance-v1",
    "rule_version": "v1",
    "sources": sources,
    "limits": {
        "max_records": 2000000,
        "max_input_bytes": 2147483648,
        "max_decompressed_bytes": 4294967296,
        "max_expansion_ratio": 500,
    },
    "formal_path": str(output_dir / "formal.jsonl"),
    "quarantine_path": str(output_dir / "quarantine.jsonl"),
    "manifest_path": str(output_dir / "manifest.json"),
}
if review_path:
    config["review_path"] = str(pathlib.Path(review_path).resolve())
with config_path.open("w", encoding="utf-8") as stream:
    json.dump(config, stream, ensure_ascii=False, indent=2)
    stream.write("\n")

print(
    f"governance inputs: {len(required)} present required file(s), "
    f"{len(present_optional)} present optional file(s); optional inputs declared in {config_path}"
)
PY

mkdir -p "${output_dir}"
output_dir="$(cd "${output_dir}" && pwd -P)"

# Same go-env.sh wrapper every other Go step in CI uses: it keeps GOMODCACHE and
# GOCACHE outside the repository so this build shares the cache with the
# neighbouring jobs instead of writing a second one.
if ! (cd "${repo_root}" && bash scripts/ci/go-env.sh go run ./cmd/cheesewaf-corpus --mode govern --governance-config "${config_file}" --output "${output_dir}/summary.json"); then
  echo "corpus governance command failed" >&2
  exit 1
fi

formal="${output_dir}/formal.jsonl"
quarantine="${output_dir}/quarantine.jsonl"
manifest="${output_dir}/manifest.json"
for artifact in "${formal}" "${quarantine}" "${manifest}"; do
  [[ -e "${artifact}" ]] || { echo "missing governance output: ${artifact}" >&2; exit 1; }
done

(cd "${repo_root}" && python3 - \
  "${manifest}" \
  "${config_file}" \
  "${formal}" \
  "${quarantine}" \
  "${CORPUS_GOVERNANCE_MAX_PARSE_ERRORS}" \
  "${CORPUS_GOVERNANCE_MAX_INVALID_UTF8}" \
  "${CORPUS_GOVERNANCE_MAX_OVERLONG}" \
  "${CORPUS_GOVERNANCE_MAX_LABEL_CONFLICTS}" \
  "${CORPUS_GOVERNANCE_MAX_REPAIRS}" <<'PY'
import copy, hashlib, json, os, re, sys
(
    manifest_path,
    config_path,
    formal,
    quarantine,
    max_parse_errors,
    max_invalid_utf8,
    max_overlong,
    max_label_conflicts,
    max_repairs,
) = sys.argv[1:]


def parse_budget(name, raw):
    try:
        value = int(raw, 10)
    except ValueError as exc:
        raise SystemExit(f"{name} must be a non-negative integer (got {raw!r})") from exc
    if value < 0:
        raise SystemExit(f"{name} must be a non-negative integer (got {raw!r})")
    return value


budgets = {
    "parse_error": parse_budget("CORPUS_GOVERNANCE_MAX_PARSE_ERRORS", max_parse_errors),
    "invalid_utf8": parse_budget("CORPUS_GOVERNANCE_MAX_INVALID_UTF8", max_invalid_utf8),
    "overlong": parse_budget("CORPUS_GOVERNANCE_MAX_OVERLONG", max_overlong),
    "label_conflict": parse_budget("CORPUS_GOVERNANCE_MAX_LABEL_CONFLICTS", max_label_conflicts),
    "repairs": parse_budget("CORPUS_GOVERNANCE_MAX_REPAIRS", max_repairs),
}
with open(manifest_path, encoding="utf-8") as f:
    manifest = json.load(f)
with open(config_path, encoding="utf-8") as f:
    config = json.load(f)
if not isinstance(manifest, dict):
    raise SystemExit("governance manifest must be a JSON object")
for key in ("input_hashes", "output_hashes", "counts", "by_source", "by_reason", "by_decision"):
    if key not in manifest:
        raise SystemExit(f"governance manifest missing required key: {key}")


def require_non_negative_int(name):
    value = manifest.get(name)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise SystemExit(f"governance manifest field {name!r} must be a non-negative integer")
    return value


def require_count_map(name):
    value = manifest.get(name)
    if not isinstance(value, dict):
        raise SystemExit(f"governance manifest field {name!r} must be an object")
    for key, count in value.items():
        if not isinstance(key, str):
            raise SystemExit(f"governance manifest field {name!r} contains a non-string key")
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise SystemExit(f"governance manifest field {name!r}.{key!r} must be a non-negative integer")
    return value


def require_string_map(name):
    value = manifest.get(name)
    if not isinstance(value, dict):
        raise SystemExit(f"governance manifest field {name!r} must be an object")
    for key, item in value.items():
        if not isinstance(key, str) or not isinstance(item, str) or not item:
            raise SystemExit(f"governance manifest field {name!r} must map strings to non-empty strings")
    return value


total = require_non_negative_int("total")
formal_count = require_non_negative_int("formal")
quarantine_count = require_non_negative_int("quarantine")
duplicates_count = require_non_negative_int("duplicates")
overlong_count = require_non_negative_int("overlong")
repairs_count = require_non_negative_int("repairs")
rejected_count = require_non_negative_int("rejected")
input_hashes = require_string_map("input_hashes")
output_hashes = require_string_map("output_hashes")
counts = require_count_map("counts")
by_source = require_count_map("by_source")
by_reason = require_count_map("by_reason")
by_decision = require_count_map("by_decision")
for key in ("formal", "quarantine", "parse_error", "invalid_utf8", "overlong", "rejected"):
    if key not in counts:
        raise SystemExit(f"governance manifest field 'counts.{key}' is required")
if "label_conflict" not in by_reason:
    raise SystemExit("governance manifest field 'by_reason.label_conflict' is required")
if "hard_reject" not in by_decision:
    raise SystemExit("governance manifest field 'by_decision.hard_reject' is required")
if not os.path.isfile(formal) or not os.path.isfile(quarantine):
    raise SystemExit("governance manifest check could not find formal/quarantine outputs")
expected = {os.path.abspath(x["path"]) for x in config.get("sources", []) if x.get("optional") is not True or os.path.isfile(x["path"])}
listed = {os.path.abspath(x) for x in input_hashes}
if expected and not expected.issubset(listed):
    raise SystemExit("governance manifest does not account for every present required/optional input")
if formal_count + quarantine_count > total:
    raise SystemExit("governance output counts exceed input count")
if formal_count + quarantine_count + counts["parse_error"] + counts["invalid_utf8"] + overlong_count != total:
    raise SystemExit("governance manifest does not account for every non-empty input row")
declared_missing = sorted(os.path.abspath(x["path"]) for x in config.get("sources", []) if x.get("optional") is True and not os.path.isfile(x["path"]))
reported_missing = sorted(os.path.abspath(x) for x in manifest.get("missing_optional", []))
if declared_missing != reported_missing:
    raise SystemExit("governance manifest missing_optional does not match declared optional inputs")
if set(output_hashes) != {"formal", "quarantine"}:
    raise SystemExit("governance manifest must hash both deterministic output sets")
def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
for path, expected_hash in input_hashes.items():
    if not os.path.isfile(path) or sha256_file(path) != expected_hash:
        raise SystemExit(f"governance input hash mismatch: {path}")
for key, path in (("formal", formal), ("quarantine", quarantine)):
    if not isinstance(output_hashes[key], str) or not re.fullmatch(r"[0-9a-f]{64}", output_hashes[key]):
        raise SystemExit(f"governance output hash is malformed: {key}")
    if sha256_file(path) != output_hashes[key]:
        raise SystemExit(f"governance output hash mismatch: {key}")
duplicate_relations = manifest.get("duplicate_relations", [])
if not isinstance(duplicate_relations, list):
    raise SystemExit("governance manifest field 'duplicate_relations' must be an array")
if len(duplicate_relations) != duplicates_count:
    raise SystemExit("governance duplicate relation count does not match duplicates")
if sum(by_source.values()) != formal_count + quarantine_count:
    raise SystemExit("governance per-source counts do not match classified rows")
if counts["formal"] != formal_count or counts["quarantine"] != quarantine_count:
    raise SystemExit("governance classified counters do not match manifest totals")

required_sources = [source for source in config.get("sources", []) if source.get("optional") is not True]
for source in required_sources:
    classified = by_source.get(source["name"], 0)
    if classified <= 0:
        raise SystemExit(
            f"required corpus source produced 0 classified rows (empty or entirely rejected/unadaptable): {source['name']}"
        )

research_sources = [
    source for source in required_sources
    if os.path.basename(source["path"]).lower().rsplit(".gz", 1)[0] == "aetherguard_undetectable.jsonl"
]
if len(research_sources) != 1:
    raise SystemExit("aetherguard_undetectable.jsonl must be declared exactly once as a required research source")
research = research_sources[0]
if research.get("allow_formal") is True or research.get("access") != "research-quarantine" or research.get("default_truth") != "attack":
    raise SystemExit("aetherguard_undetectable.jsonl must remain an attack-labelled, non-formal research-quarantine source")

with open(formal, "rb") as stream:
    formal_lines = sum(1 for line in stream if line.strip())
rejected = counts["parse_error"] + counts["invalid_utf8"] + overlong_count
if rejected != rejected_count or counts["rejected"] != rejected_count:
    raise SystemExit("governance rejected counters do not match manifest totals")
quarantine_kinds = {"canonical": 0, "duplicate": 0, "rejected": 0}
with open(quarantine, encoding="utf-8") as stream:
    for line_no, line in enumerate(stream, 1):
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError as exc:
            raise SystemExit(f"quarantine artifact line {line_no} is not JSON: {exc}") from exc
        reasons = set(entry.get("reasons", []))
        if entry.get("kind") == "rejected_record":
            quarantine_kinds["rejected"] += 1
        elif reasons.intersection({"duplicate_exact", "duplicate_semantic"}):
            quarantine_kinds["duplicate"] += 1
        else:
            quarantine_kinds["canonical"] += 1
quarantine_lines = sum(quarantine_kinds.values())
expected_canonical = quarantine_count - duplicates_count
if expected_canonical < 0:
    raise SystemExit("governance duplicate count exceeds classified quarantine count")
if quarantine_kinds != {
    "canonical": expected_canonical,
    "duplicate": duplicates_count,
    "rejected": rejected,
}:
    raise SystemExit(
        "quarantine artifact canonical/duplicate/rejected line counts do not match manifest totals: "
        f"got={quarantine_kinds} expected={{'canonical': {expected_canonical}, "
        f"'duplicate': {duplicates_count}, 'rejected': {rejected}}}"
    )
if formal_lines != formal_count or quarantine_lines != quarantine_count + rejected:
    raise SystemExit("governance artifact line counts do not match manifest totals")
recorded_manifest_hash = manifest.get("manifest_payload_hash", "")
if not re.fullmatch(r"[0-9a-f]{64}", recorded_manifest_hash):
    raise SystemExit("governance manifest is missing manifest_payload_hash")
payload_manifest = copy.deepcopy(manifest)
payload_manifest.pop("manifest_payload_hash", None)


def go_json_marshal_indent(value):
    # encoding/json escapes HTML-significant characters even when non-ASCII
    # characters are otherwise emitted verbatim. Keep this byte-for-byte
    # compatible with json.MarshalIndent for the manifest payload hash.
    encoded = json.dumps(value, ensure_ascii=False, indent=2, separators=(",", ": "))
    return (
        encoded
        .replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    ).encode("utf-8")


payload = go_json_marshal_indent(payload_manifest)
if hashlib.sha256(payload).hexdigest() != recorded_manifest_hash:
    raise SystemExit("governance manifest payload hash mismatch")

observed = {
    "parse_error": counts["parse_error"],
    "invalid_utf8": counts["invalid_utf8"],
    "overlong": overlong_count,
    "label_conflict": by_reason["label_conflict"],
    "repairs": repairs_count,
}
exceeded = [name for name, value in observed.items() if value > budgets[name]]
if exceeded:
    detail = ", ".join(f"{name}={observed[name]}>{budgets[name]}" for name in exceeded)
    raise SystemExit(f"corpus governance quality budget exceeded: {detail}")

print(
    "quarantine artifact lines: "
    f"canonical={quarantine_kinds['canonical']} duplicate={quarantine_kinds['duplicate']} "
    f"rejected={quarantine_kinds['rejected']} total={quarantine_lines}"
)
print(
    "quality budgets: "
    + " ".join(f"{name}={observed[name]}/{budgets[name]}" for name in budgets)
)
PY
)

echo "corpus governance outputs verified (formal, quarantine, manifest)"
