# CheeseWAF

CheeseWAF is a Go-based Web Application Firewall scaffold focused on a
single-binary deployment model, a shared management API, and unified Web,
mobile browser, and `waf-cli` TUI operations.

## Current Status

The repository currently includes:

- Reverse proxy WAF flow with semantic detectors, custom rules, IP/ACL/rate-limit/Bot protection, edge cache/header/compression policy, and response inspection.
- Shared Web/API/TUI management model with RBAC, audit logs, monitoring, API security, and production deployment files.
- Prometheus metrics, alert evaluation, remote write, multi-sink logs for local file, ClickHouse, VictoriaLogs, and PostgreSQL.
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
