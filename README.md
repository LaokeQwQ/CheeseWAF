# CheeseWAF

CheeseWAF is a Go-based Web Application Firewall scaffold focused on a
single-binary deployment model, a shared management API, and unified Web,
mobile browser, and `waf-cli` TUI operations.

## Current Status

The repository currently includes:

- Reverse proxy WAF flow with staged semantic analysis (input extraction, deep decoding, lexical/syntax/behavior scoring), custom rules, IP/ACL/rate-limit/Bot protection, threat intel import/subscription, signed JS proof-of-work challenge, Altcha-style PoW CAPTCHA, waiting room, edge cache/header/compression policy, and response inspection.
- Shared Web/API/TUI management model with RBAC, audit logs, monitoring, API security, production deployment files, and a single-binary admin listener that serves both the REST API and built Web console. The Web site workspace covers domains, upstreams, TLS material, origin tuning, health checks, response inspection, access control, and rewrite rules.
- AI operations surfaces for real attack/block/challenge event analysis, per-event recommendations, and a console assistant backed by recent WAF events and monitor snapshots.
- First-run setup wizard for local HTTPS bootstrap, admin creation, SQLite migration, default config/certificate generation, and setup completion locking.
- Prometheus metrics, alert evaluation, remote write, and queryable multi-sink logs for local file, ClickHouse, VictoriaLogs, PostgreSQL, and Elasticsearch.
- GitHub Actions CI for PR flow validation, Go tests, web build, and cross-platform builds.

## Development

```bash
go test ./cmd/... ./internal/...
go test -race -count=1 ./cmd/... ./internal/...
go build -trimpath -o bin/cheesewaf ./cmd/cheesewaf/
cd web && npm ci && npm run build
```

Private local planning files such as `task.md` and `implementation_plan.md` are
intentionally ignored by Git.

Semantic engine maturity is tracked in `docs/semantic-readiness.md`; the current
claim is "working and explainable", not "ModSecurity/OWASP CRS parity".

## Stage Snapshot

As of 2026-06-06, the active development line is `fix/admin-ui-dashboard-map`
with PR #8 targeting `dev`. CI is green for branch-flow validation, Go tests on
Linux/Windows/macOS, web build, go-mod-tidy, and cross-build. `master` and
`canary` intentionally remain behind `dev` until the upward promotion flow is
completed.

## Pre-Release Gaps

- The admin plane must be treated as a production security boundary: keep it
  behind TLS or a trusted reverse proxy, bind it to localhost/private networks by
  default, and avoid exposing browser tokens over plain HTTP.
- Bot challenge signing secrets must be generated per install or rejected when a
  placeholder value is used; do not enable Bot protection with
  `change-me-in-production`.
- Setup should use one shared validation/completion path across the local wizard
  and the REST setup API.
- Before a public release, run repeatable sqlmap, XSStrike, nuclei, OWASP ZAP,
  CRS/Coraza or ModSecurity comparison, and admin-surface security tests.
- Legacy scaffolding scripts should be cleaned so generated directories and
  package names match the current `internal/edge` layout.
