# R2-9 Attack Map and Log/Review Pagination Task Report

Status: `DONE_WITH_CONCERNS`

## Finding Disposition

1. **Attack map and screen polling:** fixed. Added authenticated `/api/attack-map/aggregate` with bounded security projections, stable `(timestamp,id)` cursors, bounded event samples, and incremental frontend merging. Payload, user-agent, and non-whitelisted metadata are excluded; scalar projection values are bounded by type and invalid floats are ignored.
2. **Logs and Review reachability:** fixed. Added server-side search, exact ID lookup, and keyset cursor filters across the file, SQLite Review, PostgreSQL, ClickHouse, Elasticsearch, and VictoriaLogs paths. Logs and Review pages now use server-side filtering and snapshot watermarks rather than bounded client-side scans.
3. **Cursor correctness:** fixed. Timestamp and ID ordering is explicit across backends; SQLite Review normalizes RFC3339 fractional precision; map feed rejects stale overlapping responses and deduplicates event/aggregate state.
4. **Error and empty states:** preserved and covered. Existing query error states remain visible; empty first snapshots replace prior state; map and screen retain bounded state for long-running polling.

## Changed Files

- `internal/api/handler/attack_map.go`
- `internal/api/handler/attack_map_test.go`
- `internal/api/handler/log.go`
- `internal/api/handler/log_test.go`
- `internal/api/handler/review.go`
- `internal/api/router.go`
- `internal/storage/types.go`
- `internal/storage/review.go`
- `internal/storage/review_test.go`
- `internal/storage/log_sink/file.go`
- `internal/storage/log_sink/file_test.go`
- `internal/storage/log_sink/postgresql.go`
- `internal/storage/log_sink/postgresql_test.go`
- `internal/storage/log_sink/clickhouse.go`
- `internal/storage/log_sink/clickhouse_test.go`
- `internal/storage/log_sink/elasticsearch.go`
- `internal/storage/log_sink/elasticsearch_test.go`
- `internal/storage/log_sink/victorialogs.go`
- `internal/storage/log_sink/victorialogs_test.go`
- `web/src/api/client.ts`
- `web/src/api/client.test.ts`
- `web/src/types/api.ts`
- `web/src/pages/AttackMap/AttackMapPage.tsx`
- `web/src/pages/AttackMap/AttackMapPage.test.tsx`
- `web/src/pages/AttackMap/AttackScreenPage.tsx`
- `web/src/pages/AttackMap/AttackScreenPage.test.tsx`
- `web/src/pages/AttackMap/attackMapFeed.ts`
- `web/src/pages/AttackMap/attackMapFeed.test.ts`
- `web/src/pages/AttackMap/useAttackMapFeed.ts`
- `web/src/pages/Logs/LogsPage.tsx`
- `web/src/pages/Logs/LogsPage.test.tsx`
- `web/src/pages/Review/ReviewPage.tsx`
- `web/src/pages/Review/ReviewPage.test.tsx`

## Verification Evidence

```text
go test ./internal/api/... ./internal/storage/... ./internal/review/... -short -count=1
```

Exit `0`; API, handler, middleware, storage, log sinks, and review packages passed.

```text
npm test -- --run
```

Exit `0`; 61 test files and 320 tests passed.

```text
npm run typecheck
```

Exit `0`.

```text
npm run build
```

Exit `0`; Vite build and build-budget verification passed. Vite emitted only existing configuration/chunk-size warnings.

```text
git diff --check
```

Exit `0` before commit.

## Concerns

- External PostgreSQL, ClickHouse, Elasticsearch, and VictoriaLogs services were not available locally; their query builders have focused regression coverage, while live dialect compatibility remains part of CI/integration validation.
- The attack-map feed intentionally retains only a bounded recent event window and the top 1000 aggregate buckets in browser memory; historical map replay is outside this finding's scope.
- R2-3 owns unrelated web-core findings such as subject caching, SSE parsing, path encoding, and GlobeMap `any` cleanup; those are not changed here.

Implementation commit: `ffd530e`
