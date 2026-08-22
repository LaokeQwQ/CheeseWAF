# R2-2 Realtime Task Report

Status: DONE

Base implementation: `0a7aac617b588c39afd5675a65b679556ba20163`
Follow-up: `fix(realtime): close evicted SSE handlers`

## Changed Files

- `internal/realtime/hub.go`
- `internal/realtime/hub_test.go`
- `internal/realtime/log_sink.go`
- `internal/realtime/log_sink_test.go`
- `internal/realtime/sse.go`
- `internal/realtime/types.go`
- `internal/realtime/ws.go`
- `internal/api/router.go`
- `internal/api/handler/handler.go`
- `internal/api/handler/ai_tools.go`
- `internal/api/handler/ai_test.go`
- `internal/cli/service.go`
- `internal/cli/service_test.go`

## Requirement Disposition

- `MsgStats`: DONE. The production monitor collection loop publishes every collected `monitor.Snapshot` through the shared Hub, independently of remote-write enablement.
- `MsgAlert`: DONE. Alerts emitted by the production `monitor.Alerter` are published through the shared Hub before external remote-write/notifier I/O.
- `MsgLog`: DONE. The production log sink is wrapped once at service startup; successful writes publish a cloned `storage.LogEntry`, while failed and nil writes do not publish.
- `MsgApproval`: DONE. Successfully persisted pending AI tool approval requests publish from the central assistant-tool execution path through the same Hub used by the realtime routes.
- Shared Hub wiring: DONE. Service startup creates one Hub before sink/proxy/API construction and passes it to all four producer paths and both transports.
- SSE hardening: DONE. Sends are mutex-serialized, bounded by response write deadlines, cancellation-aware, and flush errors are surfaced. Initial connection writes complete before Hub registration.
- Hub concurrency/backpressure: DONE. Each client has one sender goroutine and a bounded queue. Broadcast only enqueues; full queues, send timeouts, send errors, and disconnects remove the affected client without blocking unrelated clients.
- WebSocket enhancement: DONE. WebSocket writes retain a five-second timeout and Hub serialization; disconnect uses immediate `CloseNow` so cleanup cannot wait on a close handshake.
- Goroutine lifecycle: DONE. Removing a client cancels its sender context, transports must honor cancellation, and the sender owns final transport close. `SSETransport.Close` now also signals the handler, so Hub eviction cannot leave the HTTP handler blocked on only the request context. Runtime shutdown still cancels HTTP request contexts and the monitoring loop.
- Authorization: DONE. Existing management authentication, CSRF middleware, and `read:realtime` RBAC guards on both `/api/realtime/events` and `/api/realtime/ws` are unchanged.
- Focused regressions: DONE. Coverage proves all four producers, per-client write serialization, SSE write serialization/deadline use, timeout/error disconnects, bounded-queue backpressure, and healthy-client isolation.
- Forbidden file: DONE. `deepseek_822_tasks.md` was not edited.

## Commands And Results

- `env GOCACHE=/private/tmp/cw-r2-realtime/.gocache go test ./internal/realtime ./internal/api/handler ./internal/cli -run 'Test(Hub|SSETransport|PublishingLogSink|ExecuteAssistantToolPublishesPendingApproval|PublishMonitorEvents)' -count=1` -> exit 1, expected TDD red compile failure for the not-yet-implemented Hub constructor and producer hooks.
- `env GOCACHE=/private/tmp/cw-r2-realtime/.gocache go test -race ./internal/realtime ./internal/api/handler ./internal/cli -run 'Test(Hub|SSETransport|PublishingLogSink|ExecuteAssistantToolPublishesPendingApproval|PublishMonitorEvents)' -count=1` -> exit 0; all focused regressions passed under the race detector.
- `env GOCACHE=/private/tmp/cw-r2-realtime/.gocache go test ./internal/realtime/... ./internal/api/... ./internal/cli/... -short` -> exit 1 inside the restricted sandbox because existing `httptest` cases could not bind loopback sockets (`operation not permitted`).
- `env GOCACHE=/private/tmp/cw-r2-realtime/.gocache go test ./internal/realtime/... ./internal/api/... ./internal/cli/... -short` -> exit 0 with local-listener permission; all requested packages passed.
- `env GOCACHE=/private/tmp/cw-r2-realtime/.gocache go test ./internal/realtime/... ./internal/api/... ./internal/cli/... -short -count=1` -> exit 0 with local-listener permission; fresh uncached full-suite result passed.
- `go test ./internal/realtime -run '^TestSSEHandlerReturnsWhenHubRemovesTransport$' -count=1` on the base implementation -> exit 1 after 1 second; this reproduced the handler leak before the follow-up fix.
- `go test ./internal/realtime -run '^TestSSEHandlerReturnsWhenHubRemovesTransport$' -count=1` after the follow-up fix -> exit 0.
- `go test -race ./internal/realtime -count=1` -> exit 0; all realtime tests passed under the race detector.
- `go test ./internal/api/... ./internal/cli/... -short -count=1` -> exit 0; all affected API and CLI packages passed fresh.
- `git diff --check` -> exit 0 before commit.
- `git diff --name-only -- deepseek_822_tasks.md` -> exit 0 with no output.
- `git show --stat --oneline --decorate HEAD` -> exit 0; commit `0a7aac6`, 13 files, 728 insertions, 25 deletions.

## Concerns

- Frontend reconnect, fallback, and consumption are intentionally unchanged because the brief assigns them to R2-3.
- Per-client queue capacity (32) and send timeout (5 seconds) are fixed backend defaults rather than operator-configurable settings.
