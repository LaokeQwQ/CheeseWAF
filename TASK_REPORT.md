# R2-6 API and Operations Task Report

Status: `DONE_WITH_CONCERNS`

Implementation commit: `613121e`

## Finding Disposition

1. Rule create/update paths reuse bounded custom-rule validation.
2. Management API and admin handlers use stable panic recovery responses with
   trace/event IDs and optional audit records. Login, refresh, and bootstrap
   responses no longer return raw JWTs in JSON bodies.
3. Configuration mutations use cloned immutable snapshots, serialized
   persistence, and rollback/freeze behavior. Site hot updates therefore do not
   mutate a shared nested configuration graph in place.
4. Service startup uses an exclusive PID lease with identity records; stop
   validates process identity and escalates from interrupt to terminate/kill.
   Restart starts a detached service and waits for its lease.
5. Remote-write, alert persistence, and notifier errors are logged. Review AI
   analysis uses a bounded worker queue, timeout, deduplication, and per-site
   quota. Auth secrets use safe file creation, mode and size checks, and
   symlink rejection.
6. AI model max tokens are configurable and validated; captcha receipt
   eviction is oldest-first; winctl no longer exposes its control token in the
   unauthenticated landing response.

## Verification

`env GOCACHE=/private/tmp/cw-r2-apiops-gocache go test ./internal/api/... ./internal/ai/... ./internal/captcha/... ./internal/cli/... ./internal/config/... ./internal/monitor/... ./internal/review/... ./internal/storage/... ./internal/winctl/... -short -count=1`

Exit `0`; all affected packages passed.

`git diff --check` was clean before commit. The new rule, recovery, PID lease,
and review queue regression tests are included in the implementation commit.

## Concerns

- Detached restart and process identity behavior is platform-specific and
  should receive native Windows CI coverage.
- Remote monitoring integrations were verified through error-path tests and
  logging; live external endpoints were not available locally.
