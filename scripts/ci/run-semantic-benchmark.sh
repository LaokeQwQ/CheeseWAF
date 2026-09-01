#!/usr/bin/env bash
set -euo pipefail

# Run the fixed semantic request-path benchmark and emit a compact, structured
# report. This is a trend/diagnostic artifact, not a pass/fail quality gate:
# benchmark numbers are meaningful only when compared on the same runner class
# and with the same Go/runtime settings.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
caller_dir="$(pwd -P)"
bench_time="${SEMANTIC_BENCH_TIME:-1s}"
bench_count="${SEMANTIC_BENCH_COUNT:-5}"
bench_cpu="${SEMANTIC_BENCH_CPU:-1,4}"
output_path="${SEMANTIC_BENCH_OUTPUT:-}"

if [[ -n "$output_path" && "$output_path" != /* ]]; then
  output_path="$caller_dir/$output_path"
fi

tmp_parent="${TMPDIR:-/tmp}"
if [[ "$tmp_parent" != /* ]]; then
  tmp_parent="$caller_dir/$tmp_parent"
fi
tmp_parent="$(cd "$tmp_parent" 2>/dev/null && pwd -P)" || {
  echo "TMPDIR must name an existing directory" >&2
  exit 1
}
tmp_dir="$(mktemp -d "${tmp_parent%/}/cheesewaf-semantic-bench.XXXXXX")"
trap 'rm -rf "$tmp_dir"' EXIT
raw_json="$tmp_dir/benchmark.jsonl"

case "$bench_count" in
  ''|*[!0-9]*) echo "SEMANTIC_BENCH_COUNT must be a positive integer" >&2; exit 2 ;;
esac
if (( bench_count < 1 )); then
  echo "SEMANTIC_BENCH_COUNT must be a positive integer" >&2
  exit 2
fi
if [[ -z "$bench_time" || -z "$bench_cpu" ]]; then
  echo "SEMANTIC_BENCH_TIME and SEMANTIC_BENCH_CPU must not be empty" >&2
  exit 2
fi

if [[ -n "${SEMANTIC_BENCH_GO_BIN:-}" ]]; then
  go_command=("${SEMANTIC_BENCH_GO_BIN}")
else
  go_command=(bash scripts/ci/go-env.sh go)
fi

if ! (cd "$repo_root" && "${go_command[@]}" test \
    -run '^$' \
    -bench '^BenchmarkSemanticAnalyzerMixedRequestPath$' \
    -benchmem \
    -benchtime="$bench_time" \
    -count="$bench_count" \
    -cpu="$bench_cpu" \
    -json \
    ./internal/engine/semantic >"$raw_json"); then
  echo "semantic benchmark command failed" >&2
  exit 1
fi

go_env_value() {
  local key="$1"
  local value
  if value="$(cd "$repo_root" && "${go_command[@]}" env "$key" 2>/dev/null)" && [[ -n "$value" ]]; then
    printf '%s\n' "$value"
    return 0
  fi
  printf '%s\n' unknown
}

go_version="$(go_env_value GOVERSION)"
goos="$(go_env_value GOOS)"
goarch="$(go_env_value GOARCH)"
if [[ "$go_version" == unknown ]]; then
  go_version="$(cd "$repo_root" && "${go_command[@]}" version 2>/dev/null || printf '%s' unknown)"
fi
git_commit="$(git -C "$repo_root" rev-parse HEAD 2>/dev/null || printf '%s' unknown)"
git_dirty=false
if [[ -n "$(git -C "$repo_root" status --porcelain --untracked-files=all 2>/dev/null)" ]]; then
  git_dirty=true
fi
raw_sha256="$(python3 - "$raw_json" <<'PY'
import hashlib
import sys
with open(sys.argv[1], "rb") as stream:
    print(hashlib.sha256(stream.read()).hexdigest())
PY
)"

python3 - "$raw_json" "$output_path" "$bench_time" "$bench_count" "$bench_cpu" "$go_version" "$goos" "$goarch" "$git_commit" "$git_dirty" "$raw_sha256" <<'PY'
import datetime as dt
import json
import math
import os
import platform
import re
import statistics
import sys
import tempfile
from collections import Counter

(raw_path, output_path, bench_time, bench_count, bench_cpu, go_version, goos, goarch, git_commit, git_dirty, raw_sha256) = sys.argv[1:]
pattern = re.compile(
    r"BenchmarkSemanticAnalyzerMixedRequestPath/(sequential|parallel)(?:-(\d+))?"
    r"\s+\d+\s+([0-9]+(?:\.[0-9]+)?)\s+ns/op"
    r"(?:\s+([0-9]+(?:\.[0-9]+)?)\s+B/op)?"
    r"(?:\s+([0-9]+(?:\.[0-9]+)?)\s+allocs/op)?"
)
runs = {"sequential": [], "parallel": []}
requested_cpus = []
for raw_cpu in bench_cpu.split(","):
    raw_cpu = raw_cpu.strip()
    if not raw_cpu.isdigit() or int(raw_cpu) < 1:
        raise SystemExit("SEMANTIC_BENCH_CPU must be a comma-separated list of positive integers")
    requested_cpus.append(int(raw_cpu))
if not requested_cpus:
    raise SystemExit("SEMANTIC_BENCH_CPU must not be empty")
raw_output = []
with open(raw_path, encoding="utf-8") as stream:
    for line in stream:
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        output = event.get("Output", "")
        if not isinstance(output, str):
            continue
        raw_output.append(output)
for match in pattern.finditer("".join(raw_output)):
    name, cpu_suffix, ns, bytes_per_op, allocs_per_op = match.groups()
    cpu = int(cpu_suffix) if cpu_suffix is not None else requested_cpus[0]
    runs[name].append({
                "cpu": cpu,
                "ns_per_op": float(ns),
                "bytes_per_op": float(bytes_per_op) if bytes_per_op is not None else None,
                "allocs_per_op": float(allocs_per_op) if allocs_per_op is not None else None,
            })

expected_per_mode = int(bench_count) * len(requested_cpus)
expected_cpu_counts = Counter(requested_cpus * int(bench_count))
for name, samples in runs.items():
    if len(samples) != expected_per_mode:
        raise SystemExit(
            f"{name} benchmark sample count {len(samples)} does not match "
            f"expected {expected_per_mode} for count={bench_count} cpu={bench_cpu}"
        )
    observed_cpu_counts = Counter(item["cpu"] for item in samples)
    if observed_cpu_counts != expected_cpu_counts:
        raise SystemExit(
            f"{name} benchmark CPU samples {dict(observed_cpu_counts)} do not match "
            f"requested {dict(expected_cpu_counts)}"
        )

def percentile(values, fraction):
    ordered = sorted(values)
    if not ordered:
        return None
    index = max(0, min(len(ordered) - 1, math.ceil(fraction * len(ordered)) - 1))
    return ordered[index]

def summarize(samples):
    if not samples:
        raise SystemExit("semantic benchmark output did not contain the expected sub-benchmarks")
    summary = {"samples": samples}
    for key, output_key in (("ns_per_op", "ns_per_op"), ("bytes_per_op", "bytes_per_op"), ("allocs_per_op", "allocs_per_op")):
        values = [item[key] for item in samples if item[key] is not None]
        if not values:
            continue
        summary["median_" + output_key] = statistics.median(values)
        summary["p95_" + output_key] = percentile(values, 0.95)
        summary["min_" + output_key] = min(values)
        summary["max_" + output_key] = max(values)
    summary["by_cpu"] = {
        str(cpu): summarize_cpu([item for item in samples if item["cpu"] == cpu])
        for cpu in sorted({item["cpu"] for item in samples})
    }
    return summary

def summarize_cpu(samples):
    summary = {"sample_count": len(samples)}
    for key in ("ns_per_op", "bytes_per_op", "allocs_per_op"):
        values = [item[key] for item in samples if item[key] is not None]
        if not values:
            continue
        summary["median_" + key] = statistics.median(values)
        summary["p95_" + key] = percentile(values, 0.95)
        summary["min_" + key] = min(values)
        summary["max_" + key] = max(values)
    return summary

def metadata_value(*names):
    """Read a bounded, single-line runner label without copying raw env."""
    for name in names:
        value = os.environ.get(name, "").strip()
        if value:
            return " ".join(value.split())[:128]
    return "unknown"

runner_class = metadata_value("SEMANTIC_BENCH_RUNNER_CLASS")
runner_image = metadata_value("ImageOS", "RUNNER_IMAGE", "CI_RUNNER_IMAGE")
runner_image_version = metadata_value("ImageVersion", "RUNNER_IMAGE_VERSION", "CI_RUNNER_IMAGE_VERSION")
runner_labels = metadata_value("RUNNER_LABELS", "FORGEJO_RUNNER_LABELS")
if runner_class == "unknown":
    runner_os = metadata_value("RUNNER_OS", "CI_RUNNER_OS")
    runner_arch = metadata_value("RUNNER_ARCH", "CI_RUNNER_ARCH")
    runner_parts = [value for value in (runner_os, runner_arch) if value != "unknown"]
    runner_class = "/".join(runner_parts) if runner_parts else "unknown"

report = {
    "version": "semantic-benchmark-v1",
    "captured_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    "package": "internal/engine/semantic",
    "benchmark": "BenchmarkSemanticAnalyzerMixedRequestPath",
    "settings": {
        "benchtime": bench_time,
        "count": int(bench_count),
        "cpu": bench_cpu,
        "requested_cpus": requested_cpus,
    },
    "environment": {
        "go": go_version,
        "goos": goos,
        "goarch": goarch,
        "host_os": platform.system().lower(),
        "host_arch": platform.machine().lower(),
        "python": platform.python_version(),
        "cpus": os.cpu_count(),
        "runner_class": runner_class,
        "runner_image": runner_image,
        "runner_image_version": runner_image_version,
        "runner_labels": runner_labels,
    },
    "source": {
        "git_commit": git_commit,
        "git_dirty": git_dirty == "true",
    },
    "raw_output_sha256": raw_sha256,
    "runs": {name: summarize(samples) for name, samples in runs.items()},
}

encoded = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=False) + "\n"
if not output_path:
    sys.stdout.write(encoded)
else:
    parent = os.path.dirname(os.path.abspath(output_path)) or os.curdir
    if not os.path.isdir(parent):
        raise SystemExit(f"benchmark output parent does not exist: {parent}")
    fd, temporary = tempfile.mkstemp(prefix=".semantic-benchmark.", dir=parent, text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, output_path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
PY
