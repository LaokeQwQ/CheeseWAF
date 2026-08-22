# R2-2 Realtime Task Report

Status: DONE

Independent review worktree: `/private/tmp/cw-r2-realtime`
Branch: `fix/r2-realtime`
Baseline: `9ccb5eeaa450fefad792dadeebff653b95de8827`
Reviewed implementation commits: `0a7aac617b588c39afd5675a65b679556ba20163`, `8cdfe07a21602a7b2ab2d664a15cc2a667a1d4f4`
Independent review fix: `a395804243470313f0d2e2232619ce107404a22e`

## Independent Findings

1. FIXED: Hub send timeouts depended on `Transport.Send` voluntarily honoring context cancellation. A stuck send could retain its sender goroutine forever, and there was no Hub shutdown path to close long-lived SSE/WebSocket clients when the service stopped.
2. FIXED: `MsgApproval` broadcast the complete object-scoped approval request to every `read:realtime` subscriber. The event is now a generic pending-status invalidation; clients must refetch through the existing requester/approver-scoped API.
3. FIXED: `NewPublishingLogSink` hid the underlying optional `Count` capability used by monitor endpoints, forcing less efficient query fallback behavior.

## Changed Files Since Baseline

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
- `TASK_REPORT.md`

No other R2 worktree and no `deepseek_822_tasks.md` content was changed.

## Requirement Disposition

- `MsgStats`: production monitor snapshots publish through the shared Hub even when remote write is disabled.
- `MsgAlert`: production alerter results publish before external persistence/notifier I/O.
- `MsgLog`: successful production sink writes publish a defensive log-entry copy; failed/nil writes do not publish, and optional count support is preserved.
- `MsgApproval`: persisted pending requests publish a non-sensitive invalidation through the same Hub while object details remain behind the scoped approval API.
- Shared Hub: service startup passes one Hub to producers, API handlers, SSE, and WebSocket routes.
- Concurrency/backpressure: per-client bounded queues and one sender serialize writes; queue eviction, send failure, timeout, and even blocking close behavior cannot stall unrelated clients.
- Lifecycle: timeout cancellation independently closes transports, SSE close interrupts blocked writes, Hub shutdown drains senders and rejects late clients, and service shutdown invokes it before server teardown.
- Authorization: management authentication and `read:realtime` route guards remain; approval payloads no longer bypass requester/approver object scope.
- Frontend reconnect/fallback remains assigned to R2-3.

## Fresh Verification

- `go test ./internal/realtime -run 'Test(HubSendTimeoutClosesTransportThatIgnoresContext|HubShutdownClosesClientsAndRejectsNewClients|SSETransportCloseInterruptsBlockedWrite|PublishingLogSinkPreservesCountCapability)' -count=1` -> exit 1 before the repair (`Hub.Shutdown` missing), establishing the focused regression.
- `go test ./internal/realtime ./internal/api/handler ./internal/api ./internal/cli -run 'Test(Hub|SSETransport|PublishingLogSink|ExecuteAssistantToolPublishesPendingApproval|RouterAIApprovalRecoveryPreservesObjectScope|PublishMonitorEvents)' -count=1` -> exit 0.
- `go test -race ./internal/realtime ./internal/api/handler ./internal/api ./internal/cli -run 'Test(Hub|SSETransport|PublishingLogSink|ExecuteAssistantToolPublishesPendingApproval|RouterAIApprovalRecoveryPreservesObjectScope|PublishMonitorEvents)' -count=1` -> exit 0.
- `go test -race ./internal/realtime -count=1` -> exit 0.
- `go test ./internal/realtime/... ./internal/api/... ./internal/cli/... -short -count=1` -> exit 0.
- `git diff --check 9ccb5ee` -> exit 0.
- `git diff --name-only 9ccb5ee -- deepseek_822_tasks.md` -> exit 0 with no output.

## Concerns

- The fixed queue capacity (32) and send timeout (5 seconds) remain backend defaults rather than operator-configurable settings.
- `MsgApproval` consumers must treat the event as an invalidation and reload approvals through the authorized API.
