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

## External corpus baseline (opt-in)

`testdata/` also holds seven committed public corpora that no Go code referenced
until 2026-08-30. They are the only generalisation coverage in the repository:
`curated_corpus` and `mined_probe` were authored against this engine, so a green
gate over those alone is close to a tautology.

Measure them with:

```bash
SEMANTIC_EXTERNAL_BASELINE=1 SEMANTIC_EVAL_MAX_CASES=0 \
  go test -run TestExternalCorpusBaseline -v ./internal/engine/semantic
```

The test skips unless `SEMANTIC_EXTERNAL_BASELINE=1`, enforces no thresholds, and
cannot fail on its numbers — it exists to answer "what is the value?" before
anyone decides what the threshold should be. `TestExternalCorpusBaselineFilesAreCommitted`
runs unconditionally so the measurement cannot silently rot.

As of 2026-08-30 the baseline is **TPR 78.02%** and **FPR 0.494%** over 44,600
samples. This opt-in baseline is informational and is not evaluated as part of
the current governed CI snapshot. Per-source and per-category numbers, plus two
corpus defects the adapter had to repair, are recorded under "已知限制" in
`internal/engine/semantic/EVAL_PLATFORM.md`.
