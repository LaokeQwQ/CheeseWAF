# CheeseWAF R2 Consolidated Task Report

Updated: 2026-08-23
Integration branch: `fix/audit-round2`

This report tracks integration and fresh verification evidence.

## Status

| Workflow | Scope | Status | Integration commit(s) |
| --- | --- | --- | --- |
| R2-1 | cluster consensus boundary | integrated | `f300187` |
| R2-2 | realtime event delivery | integrated | `57deb7c` |
| R2-3 | web auth and realtime client | integrated | `11c6f1b` |
| R2-4 | protection pipeline and policy hardening | integrated | `3f1c48e` |
| R2-5 | engine detection hardening | integrated | `b7389fd` |
| R2-6 | API and operations | integrated | `4edd4a7` |
| R2-7 | proxy, cluster, and storage | integrated + PostgreSQL follow-up verified locally | `2ecb695`, `085c54f` |
| R2-8 | release, CI, and docs | integrated | `c45ab3a` |
| R2-9 | attack map and keyset pagination | integrated | `931de19` |

## Current Evidence

- The integration branch contains the nine R2 merge commits above, the
  PostgreSQL log-sink follow-up, and the current PR #386 repair set;
  `origin/dev` / `9ccb5ee` is its ancestor.
- Fresh full Go verification completed with exit code 0:
  `go test ./... -short -count=1`, `go vet ./...`, and `go build ./cmd/...`.
- Fresh focused storage verification completed with exit code 0:
  `go test ./internal/storage/log_sink -count=1`,
  `go test -race ./internal/storage/log_sink -count=1`, and
  `go vet ./internal/storage/log_sink`. The follow-up covers bounded
  PostgreSQL multi-row INSERTs (up to 64 rows), per-operation deadlines,
  queue/failure/close alerts with cooldown, and regression tests for those
  contracts.
- Fresh web verification completed with exit code 0: `npm test -- --run`
  (63 files and 338 tests), `npm run typecheck`, and `npm run build`.
- Fresh release/CI local gates completed with exit code 0:
  `bash scripts/ci/verify-release_test.sh`, `bash scripts/ci/verify-ci-static.sh`,
  and the changed Shell scripts' syntax checks.
- R2-7's malformed `Forwarded` regression was corrected before final
  integration; R2-8's signing and Docker assertions require final remote CI
  for the real credentials and Docker daemon environments.
- The first PR #386 run for `00e0dab` was not a final green result. Its
  `go-quality` failure identified two pre-existing formatting mismatches and
  the macOS Bash 3.2-only `mapfile` use in `verify-go-quality.sh`; the working
  tree now contains the gofmt corrections and the Bash 3.2-compatible
  `while read` replacement.
- That same run exposed two platform/security failures which are now addressed:
  Windows `go-test` crashed in `TestPIDLeaseIsExclusiveAndPublishesIdentityRecord`
  because `LockFileEx`/`UnlockFileEx` received a nil `OVERLAPPED` pointer, and
  CodeQL reported an unchecked integer narrowing in `process_windows.go` plus
  an allocation-size multiplication in `postgresql.go`. The fixes are covered
  by local CLI/storage tests, Windows cross-compilation, and the Go quality
  format/vet checks; a fresh GitHub run is still required for Windows and
  CodeQL confirmation.
- Fresh Go coverage verification now exits 0 at `70.3%`, above the `50.0%`
  floor. The coverage command uses `-short` so the report-only, 107 MiB
  semantic benign corpus is not run under atomic instrumentation; the ordinary
  full test command remains the corpus regression gate.
- The async writer follow-up now waits for each Flush result to be acknowledged
  before a later operation can overtake it, so a canceled waiter cannot silently
  acknowledge a write failure. Alert dispatch drains admitted events during
  shutdown, rejects new events after stopping, and starts cooldown only when an
  event is actually queued.
- The local unshortened `go test ./... -count=1` run reached every package but
  timed out at the Go test binary's 10-minute limit in
  `TestEvaluationPlatform` while scanning the locally ignored 107 MiB external
  corpus; its stack remained in regex analysis. The CI workflows now explicitly
  pass `-short`, which is the test's documented CI mode and still runs the
  curated quality gate. This local full-corpus timeout is retained as an
  environment-bound verification gap, not recorded as a pass.

## Final Gates

The focused PostgreSQL follow-up and local gates passed fresh before the
current remote rerun:

```text
go test ./... -short -count=1
go vet ./...
go build ./cmd/...
cd web && npm test -- --run
cd web && npm run typecheck
cd web && npm run build
bash scripts/ci/verify-ci-static.sh
bash scripts/ci/verify-release_test.sh
bash -n scripts/ci/*.sh scripts/build-all.sh scripts/build-pgo.sh
sh -n scripts/ci/channel-from-git.sh
go test -race ./internal/storage/log_sink -count=1
bash scripts/ci/verify-go-quality.sh coverage
```

The Web test gate reported 63 files and 338 tests, all passing. The build
completed with only the existing Vite native-config and large-chunk warnings.

The latest remote PR #386 run had passed all release, web, static, Linux and
macOS checks, but remained blocked by `go-quality`, Windows `go-test`, and
CodeQL. Those failures are recorded above and must be rechecked on the new
commit. The unrelated non-required `package-macos-dmg` failure on an earlier
`dev` run was caused by a busy `hdiutil` disk image.

## Progress Log

- 2026-08-23: Completed the R2-7 PostgreSQL sink follow-up. The async writer
  now supports bounded contiguous batches, per-backend-operation deadlines,
  and cooldown-limited queue/failure/close alerts. PostgreSQL now uses a
  1024-entry/64 MiB queue and parameterized multi-row INSERTs of at most 64
  rows while preserving all 19 columns and `ON CONFLICT (id) DO UPDATE`.
  Added timeout, batch/barrier, alert, and SQL-builder regression tests.
- 2026-08-23: Follow-up concurrency review closed overlapping Flush barrier
  failure re-reporting, severed processed barrier predecessor references, and
  moved alert delivery to a bounded dispatcher so re-entrant or slow alert
  callbacks cannot block the backend worker.
- 2026-08-23: Investigated PR #386's failed remote checks. Fixed the Windows
  PID lease crash by supplying a valid `OVERLAPPED`, added the Windows PID
  upper-bound guard required by CodeQL, removed the PostgreSQL allocation
  multiplication flagged by CodeQL, corrected two gofmt mismatches, and made
  `verify-go-quality.sh` work on Bash 3.2. Fresh targeted verification and the
  local coverage gate passed; remote Windows/CodeQL confirmation remains open
  until the new commit runs.
- 2026-08-23: Completed a fresh coverage gate after making its scope explicit:
  `bash scripts/ci/verify-go-quality.sh coverage` passed with `70.3%` against
  the `50.0%` floor. The gate now passes `-short` because the large semantic
  corpus is report-only and otherwise exceeds the instrumentation budget.
- 2026-08-23: Closed the async writer acknowledgement and alert-shutdown
  races, added focused cancellation/drain regression tests, and aligned the
  GitHub/Forgejo cross-platform Go test commands with the documented `-short`
  CI scope. Targeted normal/race/vet checks passed; the local unshortened
  external-corpus run timed out at 10 minutes as recorded above.
- 2026-08-23: Fixed the remaining stock Bash 3.2 portability findings in
  `verify-ansible.sh` and `codeql-go-extract.sh`, and made the macOS keychain
  and Windows signing argument arrays safe under `set -u`. The static check
  now scans every `scripts/ci/*.sh` file for `mapfile` and `readarray`.
  GitHub Go test and macOS release steps now declare `shell: bash` explicitly.
  Fresh `/bin/bash` syntax, CI static, release regression, format, Windows
  cross-compile, and focused Go checks passed. The repaired PR still needs a
  new remote run before merge.
- 2026-08-23: A portability review found that comparing an `int` PID directly
  with `math.MaxUint32` fails to compile for `GOARCH=386`. The Windows PID
  guards now widen to `int64` and compare with the direct constant
  `4294967295`, which CodeQL can verify; fresh Windows `386`, `amd64`, and
  `arm64` test binaries all compile.
- 2026-08-23: CodeQL continued to trace the legacy PID file's `strconv.Atoi`
  result through the Windows process helpers. The legacy parser now uses
  `strconv.ParseInt` with a 32-bit size, as recommended by the CodeQL rule;
  the focused CLI tests and Windows cross-compiles remain green.
- 2026-08-23: The first Windows rerun after CodeQL passed exposed a separate
  auth-secret permission bug: NTFS reports POSIX mode bits as `0666`, so the
  Unix-only `0600` assertion was invalid on Windows. Auth secrets now use a
  protected Windows DACL for the current user, LocalSystem, and Administrators,
  while Unix keeps the exact `0600` check.

## Final Delivery

- PR #386 merged into GitHub `dev` at `012fbab` from final head `8f2420c`.
- The final PR run passed CodeQL, `go-quality`, all three Go test jobs,
  `cross-build`, Docker, Web, vulnerability, static, GoReleaser, and release
  smoke checks. Release publication jobs were skipped because this was a pull
  request, as expected.
- Local `dev` now points to GitHub `origin/dev` at `012fbab`. Forgejo `dev`
  still needs the same merge commit pushed before the repository is fully
  synchronized.
- Temporary R2 worktrees and branches remain until the final synchronization
  and cleanup commands complete.
