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
the corpus-wide paranoia sweep. Short mode is still a real evaluation run, so
the overall FPR and TPR gates apply to the samples that it processes.

The package's short test suite also runs
`TestParanoiaOfflineGradingMatchesOnlineAcrossSampleShapes`. That focused test
checks online block-mode decisions against offline hit grading at levels 0
through 5 for URI, query, header, cookie, form, JSON, raw-body, and multipart
inputs. It does not add corpus-wide `by_paranoia_level` metrics to the short
evaluation report.

Without `-short`, the test also reads `external_dataset` when its benign and
attack files are present, and computes the `by_paranoia_level` report. The full
run streams the selected corpus data and does not cap or subsample valid cases
to reduce runtime. Optional sources that are absent are logged and skipped;
failure to read or parse a source after it has been opened fails the run.

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

`FPR_GATE` is the maximum allowed overall false-positive percentage.
`TPR_GATE` is the minimum required overall true-positive percentage. Values are
percentages, not fractions: `0.25` means 0.25 percent and `99` means 99 percent.
Both gates apply to the primary level-2 aggregate, not to individual sources,
categories, or `by_paranoia_level` entries. A gate is disabled when its
environment variable is unset.

`EVAL_REPORT_PATH` writes the JSON report to a file in addition to printing it.
For a sharded run, each Go test process evaluates its own gates before reports
are merged, so per-process gates are not equivalent to a gate over the merged
global percentages.

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
FPR_GATE=0.25 TPR_GATE=99 go test -short -run '^TestEvaluationPlatform$' -count=1 ./internal/engine/semantic
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
