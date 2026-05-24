# CheeseWAF

CheeseWAF is a Go-based Web Application Firewall scaffold focused on a
single-binary deployment model, a shared management API, and unified Web,
mobile browser, and `waf-cli` TUI operations.

## Current Status

Phase 0 backend scaffolding is in progress. The repository currently includes:

- BusyBox-style `cheesewaf` / `waf-cli` entrypoint wiring.
- Core package skeletons and interfaces.
- First-launch setup defaults and self-signed admin certificate generation.
- GitHub Actions CI for PR flow validation, Go tests, and cross-platform builds.

## Development

```bash
go test ./...
go test -race -count=1 ./...
go build -trimpath -o bin/cheesewaf ./cmd/cheesewaf/
```

Private local planning files such as `task.md` and `implementation_plan.md` are
intentionally ignored by Git.
