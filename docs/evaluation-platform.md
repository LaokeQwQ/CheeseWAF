# Semantic Evaluation Platform

The semantic evaluation lives in `internal/engine/semantic/eval_platform_test.go`.
It reports false-positive rate (FPR), true-positive rate (TPR or recall),
precision, F1, per-source counts, per-category recall, optional paranoia-level
metrics, performance counters, and up to 100 failed-case examples per test
process.

## Short and full runs

`TestEvaluationPlatform` uses a block-mode analyzer at paranoia level 2 for its
primary report.

With `-short`, the test runs the required `curated_corpus` and the optional
`mined_probe` when that file is present. It skips `external_dataset` and skips
the corpus-wide paranoia sweep. The standalone report-only mined probe test is
opt-in in short runs (`MINED_FP_PROBE_SHORT=1`) to avoid evaluating the same
2,000-row probe twice under the race-enabled CI job. Short mode is still a real
evaluation run, so the overall FPR and TPR gates apply to the samples that it
processes.

The package's short test suite also runs
`TestParanoiaOfflineGradingMatchesOnlineAcrossSampleShapes`. That focused test
checks online block-mode decisions against offline hit grading at levels 0
through 5 for URI, query, header, cookie, form, JSON, raw-body, and multipart
inputs. It does not add corpus-wide `by_paranoia_level` metrics to the short
evaluation report.

Without `-short`, the test also reads `external_dataset` when its benign and
attack files are present, and computes the `by_paranoia_level` report. The full
run streams the selected corpus data, with a default cap of 20,000 valid cases
per source/label bucket; set `SEMANTIC_EVAL_MAX_CASES=0` to process every valid
case. Optional sources that are absent are logged and skipped; failure to read
or parse a source after it has been opened fails the run.

## Paranoia levels

The report covers paranoia levels 0 through 5:

| Level | Evaluation meaning |
| --- | --- |
| 0 | Record only. Hits do not block. |
| 1 | Monitoring. Hits do not block. |
| 2 | Block hits that meet the production evidence gate; embedded hits pass. This is the primary report level. |
| 3 | Uses the same evidence and embedded-payload behavior as level 2. |
| 4 | Uses the same static analyzer decision as levels 2 and 3. Runtime promotion is outside this corpus test. |
| 5 | Uses the same evidence gate and also permits embedded hits to block. |

The full paranoia sweep analyzes each case once in log mode, then applies the
same `blockableHit` policy used by a live block-mode analyzer at each level.
The short parity test guards that equivalence.

## Gates and report output

`FPR_GATE` is the strict upper bound for the overall false-positive percentage;
the measured value must be lower than the configured number.
`TPR_GATE` is the minimum required overall true-positive percentage. Values are
percentages, not fractions: `0.25` means 0.25 percent and `99` means 99 percent.
Both gates apply to the primary level-2 aggregate, not to individual sources,
categories, or `by_paranoia_level` entries. Values must be finite percentages in
the inclusive range 0–100; malformed values fail the test instead of silently
disabling a gate. A gate is disabled when its environment variable is unset.

When an FPR or TPR gate is enabled, `FPR_MIN_BENIGN` and `TPR_MIN_ATTACK`
respectively require a minimum number of samples before the percentage is
accepted. Both default to 100 in direct test runs. They must be positive
integers; blank or malformed values fail the test. The governed CI gate raises
these minimums to 250 benign and 10,000 attack samples.

Setting `SEMANTIC_EVAL_GOVERNED_CORPUS` replaces the default evaluation sources
with one formal governance snapshot. In that mode,
`SEMANTIC_EVAL_GOVERNANCE_MANIFEST` is mandatory. The evaluator verifies the
formal output SHA-256 and non-empty line count against the manifest before it
processes any case, so a stale, truncated, or substituted snapshot fails closed.

`EVAL_REPORT_PATH` writes the JSON report to a file in addition to printing it.
For a sharded run, each Go test process evaluates its own gates before reports
are merged, so per-process gates are not equivalent to a gate over the merged
global percentages.

> Which corpora actually participate depends on the checkout: several large
> datasets are git-ignored and therefore absent on CI, so a short CI run covers
> fewer sources than a local full run. See
> `internal/engine/semantic/EVAL_PLATFORM.md` (数据源 table and 已知限制 5/6)
> for the current CI coverage and for corpora that are committed but unwired.

候选开放来源、日志/PCAP/payload 的粒度边界、许可证证据和研究隔离规则见
[开放语料与日志目录](open-corpus-catalog.md) 与
[治理证据要求](semantic-corpus-governance.md#外部源登记与证据)。目录中的来源均须先
经过全局去重、初筛、语义挑选、隐私/密钥清洗和二次复核；「公开」不代表可直接
进入 formal 或 blind。

## Sharding and merge behavior

`SEMANTIC_EVAL_SHARDS` sets the positive shard count and
`SEMANTIC_EVAL_SHARD_INDEX` selects a zero-based shard. Defaults are one shard
and index zero. Invalid values fall back to those defaults.

Shard membership is a deterministic hash of the trimmed raw JSONL line. The
primary report and paranoia sweep use the same membership, so each non-empty
line belongs to exactly one shard and the same cases feed both aggregates.
Each shard writes an ordinary evaluation report. The
`merge-semantic-eval-shards.py` script sums source, category, and paranoia
integer counts, then recomputes FPR, TPR, precision, and F1 from those counts;
it does not average shard percentages. Failed cases are diagnostic examples and
do not participate in metric calculation.

## Independent splits and blind-set isolation

`cmd/cheesewaf-corpus --mode split` creates a deterministic, auditable
`train`/`validation`/`blind` assignment from an already governed evaluation
JSONL file. `--mode evaluate-split` is the corresponding replay entry point:
it consumes a validated split artifact and exactly one selected partition. Run
governance first and pass the formal or otherwise approved snapshot as the
split input. Both commands only open local files and never download a source.

The split command deliberately reads the complete input in one process. Do not
pass pre-sharded input: sharding before grouping could put records from one
site, session, or connected source component into different partitions and
invalidate the leakage guarantee. `--stream` is unsupported in this mode.

### Command

```bash
# Hash-based assignment (the default is 20% validation, 20% blind).
make evaluation-split \
  CORPUS=/absolute/path/governed-evaluation.jsonl \
  SPLIT_CONFIG=/absolute/path/split.json \
  GOVERNANCE_MANIFEST=/absolute/path/manifest.json \
  OUTPUT=/absolute/path/evaluation-split.json

# The finite default can be lowered for a local smoke test or raised explicitly.
go run ./cmd/cheesewaf-corpus \
  --mode split \
  --corpus /absolute/path/governed-evaluation.jsonl.gz \
  --split-config /absolute/path/split.json \
  --governance-manifest /absolute/path/manifest.json \
  --max-records 50000 \
  --output /absolute/path/evaluation-split.json

# If the split input adds site/session/time grouping metadata around the formal
# rows, bind that envelope to the exact governed formal snapshot as well.
go run ./cmd/cheesewaf-corpus \
  --mode split \
  --corpus /absolute/path/grouping-envelope.jsonl \
  --split-config /absolute/path/split.json \
  --governance-manifest /absolute/path/manifest.json \
  --governance-formal /absolute/path/formal.jsonl \
  --output /absolute/path/evaluation-split.json

# Replay only the immutable blind partition. Raw corpus JSONL is rejected here.
make evaluation-replay \
  CORPUS=/absolute/path/evaluation-split.json \
  GOVERNANCE_MANIFEST=/absolute/path/manifest.json \
  EVALUATION_SPLIT=blind \
  EXPECTED_ARTIFACT_SHA256=<64-lowercase-sha256> \
  OUTPUT=/absolute/path/blind-evaluation.json

# The equivalent direct command is useful when selecting custom worker limits.
go run ./cmd/cheesewaf-corpus \
  --mode evaluate-split \
  --corpus /absolute/path/evaluation-split.json \
  --governance-manifest /absolute/path/manifest.json \
  --expected-artifact-sha256 <64-lowercase-sha256> \
  --evaluation-split blind \
  --output /absolute/path/blind-evaluation.json
```

`--max-records 0` means the finite default of 100,000 records. A positive value
is a hard cap, not a request to silently truncate: an additional valid record
beyond the cap fails with `ErrEvaluationRecordLimit`. Each physical line is bounded
by the corpus line limit (2 MiB by default; `CHEESEWAF_CORPUS_MAX_LINE_BYTES`
may lower it). Overlong records, invalid UTF-8, duplicate JSON keys, malformed
JSON, and invalid cases fail closed. Validation happens before any shard
filtering in the shared loader, so a malformed row cannot be hidden by a
selection flag.

### Input schema

The loader accepts either a nested governance envelope or the flat case shape.
The following fields are required after decoding:

| Field | Required value | Purpose |
| --- | --- | --- |
| `case` (or flat case fields) | `name`, `source_family`, `label`, `method`, `target`; `category` for `attack` | Request-level case sent to an evaluator after split selection |
| `source` | Non-empty stable source pseudonym | Prevents source leakage |
| `site` | Non-empty site/tenant pseudonym | Prevents site leakage |
| `session` | Non-empty session/batch pseudonym | Prevents session leakage |
| `fingerprint` | Non-empty request-level semantic fingerprint | Global duplicate identity |
| `timestamp` | RFC3339 when time boundaries are used | Temporal split assignment |

`source` also accepts the governance alias `governance_source`; `site` accepts
`site_id` or `host`, and `session` accepts `session_id`. A missing fingerprint
can be derived from the case by the decoder, but formal governance output
should always carry the pinned fingerprint and raw-line provenance explicitly.
Grouping fields must be stable pseudonyms; do not put names, tokens, cookies,
or other personal data in them.

Nested example:

```json
{
  "id": "case-001",
  "source": "source-a",
  "site": "tenant-17",
  "session": "batch-2026-08-31-01",
  "timestamp": "2026-08-31T00:00:00Z",
  "fingerprint": "<64-lowercase-hex>",
  "case": {
    "name": "case-001",
    "source_family": "reviewed-open-source",
    "label": "benign",
    "method": "GET",
    "target": "/docs"
  }
}
```

The flat form keeps the same envelope fields beside `name`, `source_family`,
`label`, `method`, and `target`. Unknown split configuration fields are
rejected; this prevents a misspelled boundary from changing the assignment.

`split` requires governed provenance by default. Each row must carry a
`governance_path`, positive `governance_line`, lowercase 64-hex `raw_hash`, and
`decision` equal to `auto` or `approve`; approved rows additionally require
`review_rule_version`, `reviewer`, and an RFC3339 `reviewed_at`. Formal
governance output derives a pseudonymous site/session boundary from its source
and snapshot path when those grouping fields are absent. Hand-authored rows are
available only with the explicit `--allow-ungoverned` escape hatch and must not
be described as a governed or blind result.

An ungoverned train or validation smoke replay may omit the external artifact
hash, but any FPR/TPR gate still requires it and an ungoverned artifact can never
be published as quality evidence.

The JSONL loader defaults to 256 MiB decompressed input and 100,000 records;
explicit limits are still capped at 512 MiB and 1,000,000 records. The artifact
loader has its separate 64 MiB serialized cap. These bounds protect the
slice-backed splitter from configuration-induced memory and CPU exhaustion.

### Split configuration

Choose exactly one strategy. Fractions use a stable hash of each connected
group and must be non-negative with a sum below 1. If a positive-fraction
partition receives no group because the input has only a few connected
components, the splitter deterministically moves complete components to fill
the empty partition, preserving the leakage boundary. This repair is only
possible when there are at least as many independent components as requested
partitions; it does not manufacture independent evidence. Always enforce the
FPR/TPR minimum sample gates before publishing a blind result. If all fields are
omitted, the normalized configuration is `validation_fraction: 0.2`,
`blind_fraction: 0.2`, and a versioned default seed.

```json
{
  "seed": "evaluation-2026-08-31",
  "validation_fraction": 0.20,
  "blind_fraction": 0.20
}
```

For a chronological holdout, use RFC3339 boundaries instead of fractions:

```json
{
  "seed": "evaluation-2026-08-31",
  "validation_start": "2026-07-01T00:00:00Z",
  "blind_start": "2026-08-01T00:00:00Z"
}
```

`validation_start` must precede `blind_start`. A source/site/session group
that crosses a configured boundary is rejected rather than split. This is
intentional: moving one row to make the boundary fit would create temporal
leakage.

### Output artifact and blind handling

The output is JSON (`evaluation-split-v1`) with the normalized configuration,
an explicit `assignment_policy`, complete-load counters, partition counts, a
`records_sha256` digest over every complete assigned record, and one assignment
per input row. The records digest detects accidental record edits during load,
but because it is stored inside the artifact it is not an independent trust
anchor. A governed artifact also binds the raw manifest
SHA-256, the manifest payload self-hash, the formal snapshot SHA-256, the
decompressed split-input SHA-256, the formal row count, and governance policy
identities. New artifacts use `group-hash-repair-v1`; governed artifacts must
carry the records digest. Only explicitly ungoverned local train/validation
smoke files may omit it for compatibility, and they cannot become training
input or quality evidence:

```json
{
  "version": "evaluation-split-v1",
  "assignment_policy": "group-hash-repair-v1",
  "governed": true,
  "records_sha256": "<64-lowercase-sha256>",
  "config": {"seed": "evaluation-2026-08-31", "validation_fraction": 0.2, "blind_fraction": 0.2},
  "input_records": 3,
  "load_stats": {
    "non_empty_lines": 3,
    "total_records": 3,
    "selected_records": 3,
    "skipped_overlong": 0
  },
  "summary": {"train": 1, "validation": 1, "blind": 1, "groups": 3, "repaired": true},
  "records": [
    {
      "id": "case-001",
      "case": {"name": "case-001", "source_family": "reviewed-open-source", "label": "benign", "method": "GET", "target": "/docs"},
      "source": "source-a",
      "site": "tenant-17",
      "session": "batch-2026-08-31-01",
      "timestamp": "2026-08-31T00:00:00Z",
      "fingerprint": "<64-lowercase-hex>",
      "governance_path": "/absolute/path/formal.jsonl",
      "governance_line": 1,
      "raw_hash": "<64-lowercase-hex>",
      "decision": "auto",
      "split": "blind",
      "group": "sha256:..."
    },
    {
      "id": "case-002",
      "case": {"name": "case-002", "source_family": "reviewed-open-source", "label": "benign", "method": "GET", "target": "/health"},
      "source": "source-b",
      "site": "tenant-18",
      "session": "batch-2026-08-31-02",
      "timestamp": "2026-08-31T00:00:00Z",
      "fingerprint": "<64-lowercase-hex-2>",
      "governance_path": "/absolute/path/formal.jsonl",
      "governance_line": 2,
      "raw_hash": "<64-lowercase-hex-2>",
      "decision": "auto",
      "split": "validation",
      "group": "sha256:...2"
    },
    {
      "id": "case-003",
      "case": {"name": "case-003", "source_family": "reviewed-open-source", "label": "benign", "method": "GET", "target": "/status"},
      "source": "source-c",
      "site": "tenant-19",
      "session": "batch-2026-08-31-03",
      "timestamp": "2026-08-31T00:00:00Z",
      "fingerprint": "<64-lowercase-hex-3>",
      "governance_path": "/absolute/path/formal.jsonl",
      "governance_line": 3,
      "raw_hash": "<64-lowercase-hex-3>",
      "decision": "auto",
      "split": "train",
      "group": "sha256:...3"
    }
  ]
}
```

`fingerprint` is the 64-character lowercase request fingerprint emitted by
governance (it does not include a `sha256:` prefix); `group` is a hash of all
unique source/site/session/fingerprint keys in the
connected component. A component is assigned atomically, so no grouping key
can occur in two partitions. Duplicate fingerprints are an error and must be
removed by the global governance pass before splitting; the split command does
not silently choose a winner.

`summary.repaired=true` means a complete component was moved only to fill an
empty requested fractional partition. It is useful for audit and smoke fixtures,
but it does not create new independent evidence. A blind publication run must
use independently sourced components and should reject or separately label a
repaired artifact.

Treat `blind` as write-once evaluation material: lock its artifact and manifest,
do not use its rows for rule changes, threshold tuning, feature selection, or
failure triage, and record any access. `evaluate-split` must select exactly one
of `train`, `validation`, or `blind`, verify the artifact version and every
assignment with `ValidateEvaluationSplit`, and evaluate only the selected rows.
It refuses a raw corpus JSONL path, a missing/unknown partition, malformed
assignment metadata, duplicate/leaking grouping keys, and an empty selection.
`analyzer` remains a raw case-JSONL replay command; passing an artifact to it is
an input-format error. Publish an independent blind FPR/TPR result only through
`evaluate-split` after the blind artifact has been locked.

The locked artifact is the replay source for `split_input_sha256`: replay does
not re-open the original grouping envelope or source files. During split
creation, however, the command re-hashes every present `source_specs` file as
raw bytes (including compressed bytes) and compares it with the manifest's
`input_hashes`; it also requires each row's `governance_path` to resolve to one
of those declared files. This catches appended or replaced unreferenced source
rows before a governed artifact is created. The command re-opens the supplied
manifest during replay, verifies its self-hash and raw file hash against the
artifact, and then publishes both the artifact and governance hashes in the
report. Record the complete artifact SHA-256 in an independent release record
or immutable object metadata. Every governed replay must pass that independently
stored value through `--expected-artifact-sha256`; a missing value or mismatch
fails before evaluation. An ungoverned train or validation smoke artifact may
omit the flag, but it is not training input or formal quality evidence; any
supplied value is still checked. An artifact, its internal records digest, and a
manifest stored together in the same writable location cannot protect one
another from coordinated replacement. Missing optional sources remain absent;
if one appears after governance, split creation fails closed.
The split and replay entry points also open their local corpus, formal snapshot,
and artifact with an `Lstat`/`SameFile` identity check, so a final-component
symlink or a path swap during opening is rejected before parsing.

For a first-use capture, run the lock helper after the artifact and manifest
have passed governed replay:

```bash
make evaluation-lock \
  CORPUS=/absolute/path/evaluation-split.json \
  GOVERNANCE_MANIFEST=/absolute/path/manifest.json \
  EVALUATION_SPLIT=blind \
  LOCK_OUTPUT=/absolute/path/evaluation-split.lock.json
```

The helper refuses an existing lock, revalidates the complete artifact with the
detector-facing CLI, records the artifact/manifest/records hashes and only
aggregate source identities, and never writes request bodies, headers, targets,
or input paths into the lock. A blind lock also requires both labels and at
least two independent groups and rejects a repaired partition. The lock is a
first-capture record, not an independent authority by itself: copy it and the
artifact hash to storage controlled separately from the writable artifact
directory before publishing a result. Path normalization preserves final
components so symlinked inputs and output directories are rejected instead of
silently resolving to a mutable target. `make evaluation-replay` still requires
that independently retained artifact hash.

When `FPR_GATE` or `TPR_GATE` is set for a blind replay, the CLI also requires at
least one benign and one attack row and at least two independent connected
groups. `BLIND_MIN_GROUPS` raises that floor for a publication run. These shape
checks complement the configured class sample minima; with no gate, tiny smoke
artifacts remain runnable but are not quality evidence.

The artifact is still useful for audit and future replay because its source,
group, fingerprint, and timestamp metadata remain attached while the detector
request is kept under `case`. Keep the artifact, input hash, split config, and
governance manifest together for reproducibility, while keeping the expected
artifact hash in an independently controlled record.

训练只允许使用已批准的 `train` 分区；`validation` 仅用于调参和回归，`blind`
仅用于最终验收，二者不得回灌规则或特征。日志、PCAP、payload 和规则文本必须
先在本地靶场转换为带完整 HTTP 上下文的记录，再经过同一套去重、初筛、清洗和
复核流程；它们不能直接改变请求级评测分母。

The governed formal snapshot proves case membership, not the truth of extra
grouping sidecar fields. Generate `site`, `session`, and `timestamp` metadata in
a controlled pipeline, capture the first split-input and artifact hashes there,
and treat that capture boundary as part of the trusted evaluation process.

### Confidence bounds

Reports include point estimates plus 99% Wilson fields where a denominator is
available: `fpr_upper_99_percent` and `tpr_lower_99_percent` (also present for
each paranoia level). The current `FPR_GATE` and `TPR_GATE` compare point
estimates; the Wilson values are uncertainty indicators and must not be
described as a guarantee. A blind report should publish both values, sample
counts, source/site/time slices, and the immutable artifact hash.

## Commands

Run the short evaluation and enforce aggregate gates:

```bash
FPR_GATE=0.8 TPR_GATE=99 go test -short -run '^TestEvaluationPlatform$' -count=1 ./internal/engine/semantic
```

Run the short-safe online/offline parity test under the race detector:

```bash
go test -short -race -run '^TestParanoiaOfflineGradingMatchesOnlineAcrossSampleShapes$' -count=1 ./internal/engine/semantic
```

Run the full evaluation in one process and write its report:

```bash
EVAL_REPORT_PATH=/tmp/semantic-eval.json go test -run '^TestEvaluationPlatform$' -count=1 -timeout 30m ./internal/engine/semantic
```

Run the full evaluation in eight parallel shards and merge the reports:

```bash
SEMANTIC_EVAL_SHARDS=8 SEMANTIC_EVAL_LOG_DIR=/tmp/semantic-eval-shards SEMANTIC_EVAL_TIMEOUT=20m bash scripts/ci/run-semantic-eval-shards.sh
```

Merge existing shard reports directly:

```bash
python3 scripts/ci/merge-semantic-eval-shards.py /tmp/semantic-eval-shards/report-shard-*.json > /tmp/semantic-eval-shards/merged-report.json
```

## Semantic engine microbenchmark

Run the fixed semantic request-path benchmark with:

```bash
make semantic-bench
```

`BenchmarkSemanticAnalyzerMixedRequestPath` uses a deterministic 50/50 mix of
clean and attack requests, validates those labels before timing, and reports
both sequential and `RunParallel` results. One benchmark operation constructs
an HTTP request and `RequestContext` and invokes the block-mode semantic
analyzer, so the result includes request-path allocations plus the production
cache and metrics behavior. The Make target selects only this benchmark, skips
ordinary tests, enables `-benchmem`, repeats each case five times, and runs with
`GOMAXPROCS=1` and `GOMAXPROCS=4`. Go therefore prints `ns/op`, `B/op`, and
`allocs/op` for every result.

For a compile-and-execute smoke run:

```bash
make semantic-bench SEMANTIC_BENCH_TIME=1x SEMANTIC_BENCH_COUNT=1 SEMANTIC_BENCH_CPU=1
```

For a machine-readable trend sample, use the structured runner:

```bash
SEMANTIC_BENCH_TIME=1s SEMANTIC_BENCH_COUNT=5 SEMANTIC_BENCH_CPU=1,4 \
  SEMANTIC_BENCH_OUTPUT=/tmp/semantic-benchmark.json \
  bash scripts/ci/run-semantic-benchmark.sh
```

The report records the raw benchmark output hash, runner/runtime settings
(including a bounded runner class, image/version and label summary when the CI
environment provides them), source revision/dirty state, and per-mode samples grouped by each requested
`GOMAXPROCS` value. Each group contains median, p95, minimum, and maximum
`ns/op`, `B/op`, and `allocs/op`; a missing or extra sample makes the runner
fail instead of silently producing a partial baseline. CI writes the report to
`/tmp` and uploads a short-retention artifact named with the run and commit, so
repeated runs can be compared without putting generated files in the checkout.
It remains a no-threshold trend capture: it does not turn scheduler or hardware
variance into a release failure. The output intentionally excludes request
payloads and the raw `go test` stream.

The benchmark has no absolute pass/fail threshold. Compare before/after output
on the same machine, Go version, CPU settings, and power/load conditions;
numbers from different machines are informational rather than a release gate.

The clean 2026-09-01 snapshot at commit
`4bf3fe84bd80023bb5d6e63b1c0e05940bba3015` used `count=5`,
`GOMAXPROCS=1,4`, and runner class `local-baseline`. Its raw output SHA-256 is
`034c99091449e58de5bf105162885ec7ddc3f99049a2244f2d70c83a007d8b9c`; sequential
and parallel medians were `7616.5` and `5650.5 ns/op`, with `59 allocs/op`, and
the CPU4 parallel median was `3085.0 ns/op`. This is a local trend snapshot,
not a cross-machine SLO or quality claim.

Request-body upload time is outside the 100 ms detector CPU budget. Detection
starts only after a complete bounded snapshot has been read and decoded; read
failure, overload, or cancellation never publishes a partial replay body.
Truncated, malformed, or over-limit multipart coverage is reported as
incomplete analysis and follows the configured open/observe/closed fail-mode,
while an already confirmed block or challenge still wins. Unknown-length bodies
that exceed the site limit are returned as HTTP 413, and truly empty GET/HEAD
requests retain retry, cache, compression, and upstream failover eligibility.

## Corpus governance gate

CI runs two complementary governance paths.

The all-corpus integrity audit recursively and deterministically enumerates
`.jsonl` and `.jsonl.gz` files under `internal/engine/semantic/testdata/`, using
repository-relative paths as stable source names. It applies global
deduplication, initial triage, selection/cleaning, and review rules, then keeps
all existing rows in a quarantine snapshot (`allow_formal=false`). Missing
git-ignored large files remain explicit optional inputs in the manifest;
optional recognition also works for nested and gzip-compressed copies. Every
required source must classify at least one row, and parse errors, invalid UTF-8,
overlong records, label conflicts, and repairs have explicit budgets.

The governed replay/evaluation gate uses three repository-curated inputs:
`curated_external_shapes.jsonl`, `benign_production_shapes.jsonl`, and
`handcrafted_attack_neighbors.jsonl`. Governance first writes a formal snapshot
whose rows carry source, fingerprint, and raw-line provenance. The gate then
checks the pinned input hashes, snapshot hash, line count, provenance, exact
source/label/category coverage, and requires zero structurally or hard-rejected
rows before both the CLI analyzer and `TestEvaluationPlatform` consume that same
artifact. This prevents a difficult row or whole attack family from being
silently replaced or removed while an aggregate percentage still passes. Once
governance starts, neither detector-facing command reads the raw source paths
directly.

CI currently requires at least 250 benign and 10,000 attack rows, an overall
request-level FPR strictly below 0.8%, and TPR of at least 99%. These are
regression gates for the current hash-bound repository snapshot, not a claim
that an independent blind set or every quarantined research corpus meets the
same result. No data is downloaded.

Run both paths locally with:

```bash
make corpus-governance
make security-corpus
```

## Historical external corpus baseline (quarantine-only, opt-in)

`testdata/` also holds seven committed public corpora that no Go code referenced
until 2026-08-30. They are quarantine fixtures, not independent evidence. They are
useful for integrity checks, defect localization, and opt-in research statistics:
`curated_corpus` and `mined_probe` were authored against this engine, so a green
gate over those alone is close to a tautology.

The seven external files remain `research-quarantine` even though they are clean
and tracked. Their measurements must not be used as an independent blind set,
independent FPR/TPR, or release-quality gate. A file being public, visible, or
committed does not prove file-level licence, label fidelity, or independence.

Measure them with:

```bash
SEMANTIC_EXTERNAL_BASELINE=1 SEMANTIC_EVAL_MAX_CASES=0 \
  go test -run TestExternalCorpusBaseline -v ./internal/engine/semantic
```

The test skips unless `SEMANTIC_EXTERNAL_BASELINE=1` and enforces no FPR/TPR
thresholds — it exists to answer "what is the value?" before anyone decides what
the threshold should be. It does fail when a constructed request has incomplete
semantic coverage or an unexpected analyzer error; those rows are reported as
`INCOMPLETE`/`ERROR` and omitted from rates, never treated as clean outcomes.
`TestExternalCorpusBaselineFilesAreCommitted` runs unconditionally so the
measurement cannot silently rot.

The initial 2026-08-30 **historical, non-gating, research-only** baseline was
**TPR 78.02%** and **FPR 0.494%** over 44,600 input rows. A single full
traversal on 2026-09-01, after the narrow SQL fingerprint gate,
measured **144 FP /
28,947 benign = 0.49746%** (99% one-sided upper bound **0.60335%**) and
**12,859 / 15,641 attack = 82.2134%** (99% one-sided lower bound **81.4910%**).
Twelve multipart rows had incomplete semantic coverage and two rows were
unbuildable; they were omitted from the rates and made the opt-in test fail
closed. The temporary report SHA-256 is
`44a6d63af204d63b71c5579261c65bf5c9436d6d7f57e46f32674570c99dfa8f`.
Neither measurement is an independent blind or independent FPR/TPR result, and
neither is evaluated as part of the current governed CI snapshot.

When a report is persisted, use `/tmp` or an ignored output directory for
`SEMANTIC_EXTERNAL_BASELINE_OUT` and failure dumps; an explicit output path can
otherwise place generated reports in the checkout.

Each persisted external-baseline report also carries a `provenance` object:
the UTC run time, full code revision, repository dirty state, and byte count plus
SHA-256 for every input file. `provenance_complete` is true only when every input
hash and Git state were captured and the worktree was clean; a dirty or otherwise
incomplete report is intentionally unbound and must not be compared as a
reproducible run. Compare the recorded input hashes and revision before reading
a failure dump or quoting any historical rate.
