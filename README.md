# CheeseWAF

CheeseWAF is a Go-based Web Application Firewall scaffold focused on a
single-binary deployment model, a shared management API, and unified Web,
mobile browser, and `waf-cli` TUI operations.

## Current Status

The repository currently includes:

- Reverse proxy WAF flow with staged semantic analysis (input extraction, deep decoding, lexical/syntax/behavior scoring), custom rules, IP/ACL/rate-limit/Bot protection, threat intel import/subscription, signed JS proof-of-work challenge, waiting room, edge cache/header/compression policy, and response inspection.
- Shared Web/API/TUI management model with RBAC, audit logs, monitoring, API security, production deployment files, a Web site workspace for domains, upstreams, TLS material, origin tuning, health checks, response inspection, access control, and rewrite rules, plus a system settings workspace for listeners, storage backends, OTA, vulnerability feeds, and 2FA.
- Prometheus metrics, alert evaluation, remote write, multi-sink logs for local file, ClickHouse, VictoriaLogs, PostgreSQL, and Elasticsearch.
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
