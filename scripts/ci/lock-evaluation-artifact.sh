#!/usr/bin/env bash
set -euo pipefail

# Capture the first, independently recorded identity of an evaluation split.
# This script deliberately never reads an existing lock record as evidence.
# The caller must preserve the resulting JSON outside the writable location
# that contains the artifact and manifest (or otherwise provide an independent
# trust anchor) before using it for a publication replay.

usage() {
  cat >&2 <<'EOF'
usage: lock-evaluation-artifact.sh ARTIFACT MANIFEST SPLIT LOCK_PATH

ARTIFACT and MANIFEST must be local, regular files. SPLIT must be one of
train, validation, or blind. LOCK_PATH must not already exist and is written
atomically as a JSON lock record without request bodies or input paths.
EOF
}

if [[ $# -ne 4 ]]; then
  usage
  exit 2
fi

artifact_path="$1"
manifest_path="$2"
split_name="$(printf '%s' "$3" | tr '[:upper:]' '[:lower:]')"
lock_path="$4"

# Resolve caller-relative paths before changing directory to the repository.
# Reject control characters that would make line-oriented diagnostics or
# sidecar handling ambiguous.  The files themselves are checked below.
caller_dir="$(pwd -P)"
absolute_path() {
  python3 - "$1" <<'PY'
import os
import sys

value = sys.argv[1]
if "\x00" in value or "\n" in value or "\r" in value:
    raise SystemExit("paths must not contain NUL/newline characters")
# Keep the final path components intact.  The validation pass below must see
# symlinks instead of receiving an already-resolved target; otherwise a
# symlinked artifact, manifest, or output directory could bypass the explicit
# no-indirection checks.
print(os.path.normpath(os.path.abspath(os.path.join(os.environ["CHEESEWAF_CALLER_DIR"], value))))
PY
}

case "$split_name" in
  train|validation|blind) ;;
  *)
    echo "invalid split: $3 (want train, validation, or blind)" >&2
    exit 2
    ;;
esac

command -v python3 >/dev/null 2>&1 || {
  echo "python3 is required to create an evaluation artifact lock" >&2
  exit 1
}

export CHEESEWAF_CALLER_DIR="$caller_dir"
artifact_path="$(absolute_path "$artifact_path")"
manifest_path="$(absolute_path "$manifest_path")"
lock_path="$(absolute_path "$lock_path")"
if [[ -n "${CORPUS_CLI:-}" ]]; then
  CORPUS_CLI="$(absolute_path "$CORPUS_CLI")"
  export CORPUS_CLI
fi

repo_root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$repo_root"

# Resolve and validate all paths in one bounded Python pass. Symlinks are not
# accepted: a first-capture record must name the regular files that were read,
# not a mutable indirection that can be retargeted after capture.
python3 - "$artifact_path" "$manifest_path" "$lock_path" <<'PY'
import os
import sys

artifact, manifest, lock = (os.path.abspath(value) for value in sys.argv[1:])
for label, path in (("artifact", artifact), ("manifest", manifest)):
    if os.path.islink(path) or os.path.realpath(path) != path or not os.path.isfile(path):
        raise SystemExit(f"{label} must be a local regular file")
    if not os.access(path, os.R_OK):
        raise SystemExit(f"{label} is not readable")

if os.path.exists(lock) or os.path.islink(lock):
    raise SystemExit("lock output already exists; refusing to replace a first-capture record")
if artifact == manifest or lock in (artifact, manifest):
    raise SystemExit("lock output must not overlap an input")

parent = os.path.dirname(lock) or os.curdir
if os.path.islink(parent) or os.path.realpath(parent) != parent or not os.path.isdir(parent):
    raise SystemExit("lock output parent must be an existing local directory")
if not os.access(parent, os.W_OK | os.X_OK):
    raise SystemExit("lock output parent is not writable")
PY

sha256_file() {
  local path="$1"
  local digest
  if [[ -L "$path" || ! -f "$path" || ! -r "$path" ]]; then
    echo "input must remain a readable regular file: $path" >&2
    exit 1
  fi
  if command -v sha256sum >/dev/null 2>&1; then
    digest="$(sha256sum "$path" | awk '{print $1}')"
  elif command -v shasum >/dev/null 2>&1; then
    digest="$(shasum -a 256 "$path" | awk '{print $1}')"
  else
    echo "sha256sum or shasum is required" >&2
    exit 1
  fi
  if [[ ! "$digest" =~ ^[0-9a-fA-F]{64}$ ]]; then
    echo "failed to compute SHA-256 for $path" >&2
    exit 1
  fi
  printf '%s\n' "$digest" | tr '[:upper:]' '[:lower:]'
}

artifact_sha256="$(sha256_file "$artifact_path")"
manifest_sha256="$(sha256_file "$manifest_path")"

tmp_parent="${TMPDIR:-/tmp}"
if [[ "$tmp_parent" != /* ]]; then
  tmp_parent="$repo_root/$tmp_parent"
fi
tmp_parent="$(cd "$tmp_parent" 2>/dev/null && pwd -P)" || {
  echo "TMPDIR must name an existing directory" >&2
  exit 1
}
tmp_dir="$(mktemp -d "${tmp_parent%/}/cheesewaf-artifact-lock.XXXXXX")"
trap 'rm -rf "$tmp_dir"' EXIT

# Reuse the detector-facing CLI as the single source of truth for artifact
# parsing, governed binding validation, complete-load checks, partition
# selection, and the expected artifact hash. GOPROXY=off makes this operation
# fail rather than downloading modules or data when a local build cache is
# incomplete. A prebuilt binary may be supplied for hermetic CI via
# CORPUS_CLI.
validation_report="$tmp_dir/evaluation-report.json"
validation_error="$tmp_dir/evaluation-report.stderr"
if [[ -n "${CORPUS_CLI:-}" ]]; then
  [[ -f "$CORPUS_CLI" && ! -L "$CORPUS_CLI" && -x "$CORPUS_CLI" ]] || {
    echo "CORPUS_CLI must point to an executable local file" >&2
    exit 1
  }
  cli_command=("$CORPUS_CLI")
else
  cli_command=(bash scripts/ci/go-env.sh go run ./cmd/cheesewaf-corpus)
fi

if ! env \
  -u FPR_GATE -u TPR_GATE -u FPR_MIN_BENIGN -u TPR_MIN_ATTACK -u BLIND_MIN_GROUPS \
  GOPROXY=off \
  "${cli_command[@]}" \
  --mode evaluate-split \
  --corpus "$artifact_path" \
  --governance-manifest "$manifest_path" \
  --evaluation-split "$split_name" \
  --expected-artifact-sha256 "$artifact_sha256" \
  --workers 1 \
  --output "$validation_report" \
  >"$tmp_dir/cli.stdout" 2>"$validation_error"; then
  echo "evaluation artifact/manifest failed governed validation" >&2
  sed -n '1,120p' "$validation_error" >&2 || true
  exit 1
fi

# The CLI's expected-artifact check catches mutations observed during
# validation. Re-read both files after validation as well; the lock must never
# pair a report validated against one byte sequence with metadata read from a
# later sequence.
artifact_sha256_after="$(sha256_file "$artifact_path")"
manifest_sha256_after="$(sha256_file "$manifest_path")"
if [[ "$artifact_sha256_after" != "$artifact_sha256" || "$manifest_sha256_after" != "$manifest_sha256" ]]; then
  echo "artifact or governance manifest changed during validation; refusing lock capture" >&2
  exit 1
fi

# The CLI has already validated the complete artifact. This pass only projects
# non-sensitive aggregate metadata for the lock record; it intentionally omits
# source/path strings, request bodies, headers, targets, names, and per-row
# results. Source identities are one-way hashes so a lock cannot disclose local
# paths accidentally copied into a source field.
lock_parent="$(dirname "$lock_path")"
lock_tmp="$(mktemp "${lock_parent%/}/.evaluation-artifact-lock.XXXXXX")"
cleanup_lock_tmp() {
  rm -f "$lock_tmp"
}
trap 'cleanup_lock_tmp; rm -rf "$tmp_dir"' EXIT

python3 - "$artifact_path" "$manifest_path" "$split_name" "$artifact_sha256" "$manifest_sha256" "$validation_report" "$lock_tmp" <<'PY'
import collections
import datetime as dt
import hashlib
import json
import os
import re
import sys

(
    artifact_path,
    manifest_path,
    split_name,
    artifact_sha256,
    manifest_sha256,
    validation_report,
    lock_tmp,
) = sys.argv[1:]

def read_bounded(path, limit):
    chunks = []
    total = 0
    with open(path, "rb") as stream:
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                raise SystemExit(f"{path} exceeds the projection size limit")
            chunks.append(chunk)
    return b"".join(chunks)

artifact_bytes = read_bounded(artifact_path, 64 * 1024 * 1024)
artifact = json.loads(artifact_bytes)
manifest_bytes = read_bounded(manifest_path, 8 * 1024 * 1024)
manifest = json.loads(manifest_bytes)
with open(validation_report, "rb") as stream:
    report = json.load(stream)

if hashlib.sha256(artifact_bytes).hexdigest() != artifact_sha256:
    raise SystemExit("artifact changed while projecting lock metadata")
if hashlib.sha256(manifest_bytes).hexdigest() != manifest_sha256:
    raise SystemExit("governance manifest changed while projecting lock metadata")

if artifact.get("governed") is not True:
    raise SystemExit("validated artifact is not governed")
governance = artifact.get("governance")
if not isinstance(governance, dict):
    raise SystemExit("validated artifact is missing governance binding")
if not isinstance(manifest, dict) or not isinstance(report, dict):
    raise SystemExit("validated governance or evaluation report is not a JSON object")
if report.get("split") != split_name:
    raise SystemExit("CLI validation report selected an unexpected partition")
if report.get("artifact_sha256") != artifact_sha256:
    raise SystemExit("CLI validation report artifact hash does not match the captured bytes")
if governance.get("manifest_sha256") != manifest_sha256:
    raise SystemExit("artifact governance binding does not match the captured manifest")
if report.get("governance_manifest_sha256") != manifest_sha256:
    raise SystemExit("CLI validation report manifest hash does not match the captured bytes")
if report.get("split_input_sha256") != governance.get("input_sha256"):
    raise SystemExit("CLI validation report split input hash does not match the artifact governance binding")

def is_sha256(value):
    return isinstance(value, str) and len(value) == 64 and all(char in "0123456789abcdef" for char in value)

for key in (
    "manifest_sha256",
    "manifest_payload_hash",
    "formal_sha256",
    "input_sha256",
    "policy_hash",
    "review_hash",
):
    if not is_sha256(governance.get(key)):
        raise SystemExit(f"governance binding field {key} is not a lowercase SHA-256")
records_sha256 = artifact.get("records_sha256")
if not is_sha256(records_sha256):
    raise SystemExit("validated artifact is missing a canonical records_sha256")

records = artifact.get("records")
if not isinstance(records, list) or not records:
    raise SystemExit("validated artifact has no records")

def sha_text(value):
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()

def safe_identity(value):
    """Keep short version tokens; hash arbitrary manifest metadata."""
    if not isinstance(value, str):
        return ""
    value = value.strip()
    if not value:
        return ""
    if len(value) <= 96 and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", value):
        return value
    return "sha256:" + sha_text(value)

source_rows = {}
site_ids = set()
session_ids = set()
groups = set()
selected_groups = set()
split_counts = collections.Counter()
label_counts = collections.Counter()
selected_label_counts = collections.Counter()
category_counts = collections.Counter()
selected_category_counts = collections.Counter()
for row in records:
    source = str(row.get("source", ""))
    if not source:
        raise SystemExit("validated artifact record is missing source metadata")
    source_key = sha_text(source)
    item = source_rows.setdefault(source_key, {"records": 0, "benign": 0, "attack": 0})
    item["records"] += 1
    case = row.get("case") or {}
    label = str(case.get("label", "")).lower()
    if label in ("benign", "attack"):
        item[label] += 1
        label_counts[label] += 1
        if row.get("split") == split_name:
            selected_label_counts[label] += 1
    category = str(case.get("category", "")).strip().lower()
    if label == "attack" and category:
        category_counts[category] += 1
        if row.get("split") == split_name:
            selected_category_counts[category] += 1
    split = str(row.get("split", ""))
    if split:
        split_counts[split] += 1
    if split == split_name and row.get("group"):
        selected_groups.add(str(row["group"]))
    if row.get("site"):
        site_ids.add(sha_text(row["site"]))
    if row.get("session"):
        session_ids.add(sha_text(row["session"]))
    if row.get("group"):
        groups.add(str(row["group"]))

source_metadata = {
    "input_records": int(artifact.get("input_records", len(records))),
    "groups": len(groups),
    "selected_groups": len(selected_groups),
    "sources": [
        {"id_sha256": key, **source_rows[key]}
        for key in sorted(source_rows)
    ],
    "source_count": len(source_rows),
    "site_count": len(site_ids),
    "session_count": len(session_ids),
    "split_counts": {key: split_counts[key] for key in sorted(split_counts)},
    "selected_records": split_counts.get(split_name, 0),
    "labels": {key: label_counts[key] for key in sorted(label_counts)},
    "selected_labels": {key: selected_label_counts[key] for key in sorted(selected_label_counts)},
    "attack_categories": {key: category_counts[key] for key in sorted(category_counts)},
    "selected_attack_categories": {key: selected_category_counts[key] for key in sorted(selected_category_counts)},
    "repaired": bool((artifact.get("summary") or {}).get("repaired", False)),
}

selected_records = split_counts.get(split_name, 0)
if selected_records < 1:
    raise SystemExit(f"selected partition {split_name!r} is empty")
if split_name == "blind":
    if source_metadata["repaired"]:
        raise SystemExit("blind partition assignment was repaired; refusing to create an evidence lock")
    if selected_label_counts.get("benign", 0) < 1 or selected_label_counts.get("attack", 0) < 1:
        raise SystemExit("blind partition must contain both benign and attack records")
    if len(selected_groups) < 2:
        raise SystemExit("blind partition must contain at least two independent groups")

lock = {
    "version": "evaluation-artifact-lock-v1",
    "artifact_sha256": artifact_sha256,
    "manifest_sha256": manifest_sha256,
    "records_sha256": records_sha256,
    "split": split_name,
    "created_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    "governed": True,
    "source_metadata": source_metadata,
    "tool": {
        "name": "cheesewaf-corpus",
        "lock_version": "evaluation-artifact-lock-v1",
        "artifact_version": safe_identity(artifact.get("version", "")),
        "assignment_policy": safe_identity(artifact.get("assignment_policy", "")),
        "pipeline": safe_identity(governance.get("pipeline", manifest.get("pipeline", ""))),
        "policy_version": safe_identity(governance.get("version", manifest.get("version", ""))),
        "rule_version": safe_identity(governance.get("version", manifest.get("version", ""))),
    },
    "governance": {
        "manifest_payload_hash": governance.get("manifest_payload_hash", ""),
        "formal_sha256": governance.get("formal_sha256", ""),
        "input_sha256": governance.get("input_sha256", ""),
        "formal_records": governance.get("formal_records", 0),
        "policy_hash": governance.get("policy_hash", manifest.get("policy_hash", "")),
        "review_hash": governance.get("review_hash", manifest.get("review_hash", "")),
    },
    # This is a declaration, not a self-authenticating trust decision. The
    # artifact hash must be copied to an independently controlled record.
    "capture": {
        "first_capture": True,
        "existing_lock_consulted": False,
        "independent_storage_required": True,
        "same_writable_location_is_not_trusted": True,
    },
}

with open(lock_tmp, "w", encoding="utf-8") as stream:
    json.dump(lock, stream, ensure_ascii=False, indent=2, sort_keys=False)
    stream.write("\n")
os.chmod(lock_tmp, 0o600)
PY

# Refuse a race that creates the destination after the initial path check.
if [[ -e "$lock_path" || -L "$lock_path" ]]; then
  echo "lock output appeared while validation was running; refusing replacement" >&2
  exit 1
fi
# `mv` is not a no-clobber primitive: a concurrent first capture could create
# the destination between the check above and rename, causing the later move
# to replace the trusted record.  The temporary file is in the destination
# directory, so an atomic hard-link create is available on macOS and Linux and
# fails if *any* destination (including a symlink) already exists.
if ! ln "$lock_tmp" "$lock_path" 2>/dev/null; then
  echo "lock output appeared while validation was running; refusing replacement" >&2
  exit 1
fi
rm -f "$lock_tmp"
trap - EXIT
rm -rf "$tmp_dir"

echo "evaluation artifact lock written (first capture; store independently): ${lock_path}" >&2
