#!/usr/bin/env bash
set -euo pipefail

# Small integration smoke for the first-capture helper. It creates only a
# temporary, locally governed fixture and never adds data to the repository.
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
tmp_parent="${TMPDIR:-/tmp}"
if [[ "$tmp_parent" != /* ]]; then
  tmp_parent="$repo_root/$tmp_parent"
fi
tmp_parent="$(cd "$tmp_parent" 2>/dev/null && pwd -P)" || {
  echo "TMPDIR must name an existing directory" >&2
  exit 1
}
tmp_dir="$(mktemp -d "${tmp_parent%/}/cheesewaf-lock-smoke.XXXXXX")"
trap 'rm -rf "$tmp_dir"' EXIT

command -v python3 >/dev/null 2>&1 || { echo "python3 is required" >&2; exit 1; }
command -v go >/dev/null 2>&1 || { echo "go is required" >&2; exit 1; }

python3 - "$tmp_dir" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
rows = [
    {"name": "lock-smoke-a", "source_family": "lock-smoke", "label": "benign", "method": "GET", "target": "/health"},
    {"name": "lock-smoke-b", "source_family": "lock-smoke", "label": "benign", "method": "GET", "target": "/status"},
    {"name": "lock-smoke-c", "source_family": "lock-smoke", "label": "benign", "method": "GET", "target": "/ready"},
]
input_paths = []
for index, row in enumerate(rows):
    path = root / f"input-{index}.jsonl"
    path.write_text(json.dumps(row) + "\n", encoding="utf-8")
    input_paths.append(path)
config = {
    "sources": [{
        "path": str(path),
        "name": f"lock-smoke-{index}",
        "license": "internal",
        "access": "local-file",
        "allow_formal": True,
    } for index, path in enumerate(input_paths)],
    "formal_path": str(root / "formal.jsonl"),
    "quarantine_path": str(root / "quarantine.jsonl"),
    "manifest_path": str(root / "manifest.json"),
    "pipeline_version": "local/path/with-sensitive",
    "rule_version": "rules/v1",
}
(root / "governance.json").write_text(json.dumps(config), encoding="utf-8")
(root / "split.json").write_text(json.dumps({
    "seed": "lock-smoke",
    # Keep three independent source components so the production fractional
    # assignment/repair policy can populate train, validation, and blind
    # deterministically. A one-source fixture is a single connected component
    # and may legitimately land outside train.
    "validation_fraction": 0.2,
    "blind_fraction": 0.2,
}), encoding="utf-8")
PY

cd "$repo_root"
run_logged() {
  local log_file="$1"
  shift
  if ! "$@" >"$log_file" 2>&1; then
    echo "command failed: $*" >&2
    tail -n 120 "$log_file" >&2 || true
    return 1
  fi
}

run_logged "$tmp_dir/build.log" bash scripts/ci/go-env.sh go build -trimpath -o "$tmp_dir/cheesewaf-corpus" ./cmd/cheesewaf-corpus
run_logged "$tmp_dir/govern.log" bash scripts/ci/go-env.sh go run ./cmd/cheesewaf-corpus \
  --mode govern --governance-config "$tmp_dir/governance.json" \
  --output "$tmp_dir/governance-summary.json"
run_logged "$tmp_dir/split.log" bash scripts/ci/go-env.sh go run ./cmd/cheesewaf-corpus \
  --mode split --corpus "$tmp_dir/formal.jsonl" \
  --split-config "$tmp_dir/split.json" \
  --governance-manifest "$tmp_dir/manifest.json" \
  --output "$tmp_dir/evaluation-split.json"

export CORPUS_CLI="$tmp_dir/cheesewaf-corpus"
run_logged "$tmp_dir/lock.log" bash scripts/ci/lock-evaluation-artifact.sh \
  "$tmp_dir/evaluation-split.json" "$tmp_dir/manifest.json" train \
  "$tmp_dir/train.lock.json"
unset CORPUS_CLI

python3 - "$tmp_dir" <<'PY'
import json
import pathlib
import stat
import sys

root = pathlib.Path(sys.argv[1])
lock_path = root / "train.lock.json"
lock = json.loads(lock_path.read_text(encoding="utf-8"))
assert lock["version"] == "evaluation-artifact-lock-v1"
assert lock["split"] == "train"
assert len(lock["records_sha256"]) == 64
assert all(char in "0123456789abcdef" for char in lock["records_sha256"])
assert lock["capture"]["first_capture"] is True
assert stat.S_IMODE(lock_path.stat().st_mode) == 0o600
serialized = lock_path.read_text(encoding="utf-8")
assert str(root) not in serialized
assert "/" not in lock["tool"]["pipeline"]
assert "/" not in lock["tool"]["policy_version"]
assert "/" not in lock["tool"]["rule_version"]
assert lock["source_metadata"]["selected_records"] > 0
PY

if CORPUS_CLI="$tmp_dir/cheesewaf-corpus" \
  bash scripts/ci/lock-evaluation-artifact.sh \
  "$tmp_dir/evaluation-split.json" "$tmp_dir/manifest.json" train \
  "$tmp_dir/train.lock.json" \
  >"$tmp_dir/second.stdout" 2>"$tmp_dir/second.stderr"; then
  echo "existing lock was unexpectedly replaced" >&2
  exit 1
fi

# Path normalization must not resolve the final component before the script's
# no-indirection checks.  A symlinked input or output parent is therefore
# rejected even when its target is an otherwise valid local file/directory.
ln -s "$tmp_dir/evaluation-split.json" "$tmp_dir/artifact-link.json"
if CORPUS_CLI="$tmp_dir/cheesewaf-corpus" \
  bash scripts/ci/lock-evaluation-artifact.sh \
  "$tmp_dir/artifact-link.json" "$tmp_dir/manifest.json" train \
  "$tmp_dir/symlink-artifact.lock.json" \
  >"$tmp_dir/symlink-artifact.stdout" 2>"$tmp_dir/symlink-artifact.stderr"; then
  echo "symlinked artifact was unexpectedly accepted" >&2
  exit 1
fi
grep -Fq "artifact must be a local regular file" "$tmp_dir/symlink-artifact.stderr" || {
  echo "symlinked artifact failure did not identify the rejected input" >&2
  cat "$tmp_dir/symlink-artifact.stderr" >&2
  exit 1
}

ln -s "$tmp_dir/manifest.json" "$tmp_dir/manifest-link.json"
if CORPUS_CLI="$tmp_dir/cheesewaf-corpus" \
  bash scripts/ci/lock-evaluation-artifact.sh \
  "$tmp_dir/evaluation-split.json" "$tmp_dir/manifest-link.json" train \
  "$tmp_dir/symlink-manifest.lock.json" \
  >"$tmp_dir/symlink-manifest.stdout" 2>"$tmp_dir/symlink-manifest.stderr"; then
  echo "symlinked manifest was unexpectedly accepted" >&2
  exit 1
fi
grep -Fq "manifest must be a local regular file" "$tmp_dir/symlink-manifest.stderr" || {
  echo "symlinked manifest failure did not identify the rejected input" >&2
  cat "$tmp_dir/symlink-manifest.stderr" >&2
  exit 1
}

ln -s "$tmp_dir" "$tmp_dir/output-link"
if CORPUS_CLI="$tmp_dir/cheesewaf-corpus" \
  bash scripts/ci/lock-evaluation-artifact.sh \
  "$tmp_dir/evaluation-split.json" "$tmp_dir/manifest.json" train \
  "$tmp_dir/output-link/symlink-parent.lock.json" \
  >"$tmp_dir/symlink-parent.stdout" 2>"$tmp_dir/symlink-parent.stderr"; then
  echo "symlinked lock parent was unexpectedly accepted" >&2
  exit 1
fi
grep -Fq "lock output parent must be an existing local directory" "$tmp_dir/symlink-parent.stderr" || {
  echo "symlinked lock parent failure did not identify the rejected parent" >&2
  cat "$tmp_dir/symlink-parent.stderr" >&2
  exit 1
}

echo "evaluation artifact lock smoke passed"
