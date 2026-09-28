# AI 审批 Gate 适配层

## 目的

`internal/ai.ApprovalStore` 是历史兼容接口。它保存工具参数摘要、预览摘要和执行状态，原来的 `ApproveFor` 只有一次调用，不能表达告警等待、语言短语和第三次确认。

`internal/ai.GateApprovalAdapter` 把 AI 的 `Destructive` 工具映射到 `internal/approval.Gate`。适配层不改变旧方法的签名，也不把旧的一次确认升级成高风险授权。

## 当前范围

- `ReadOnly`：不创建审批单。
- `Modify`：使用 `ApprovalStore` 流程处理常规修改，保持既有 API 和控制台交互兼容，需要独立审批人审核。
- `Destructive`：必须通过 `GateApprovalAdapter`。没有适配器时，`Assistant.ExecuteTool` 和旧 `ApproveFor` 都拒绝授权。

适配器创建请求后，审批人先调用 `BeginConfirmation`。服务器记录告警开始时间，并返回一次性确认 ID、语言和服务端短语。审批人等待至少 10 秒，再调用 `Confirm`：

1. 第一次有效点击记录二次确认检查点，并返回 `approval.ErrThirdConfirmation`。
2. 第二次调用必须使用同一确认 ID、会话、语言、短语和操作摘要，并设置 `ThirdConfirmation`。
3. Gate 返回 `AuthorizationCommit` 后，适配器才把兼容审批单改为 `approved`。执行前还要再次校验请求者的原始 Session、工具名、参数摘要和预览摘要。

Gate 同时检查当前策略代次、TTL、Nonce、Scope、本地控制面来源和确认短语。适配器不会从客户端接收 Scope、Nonce 或 WarningReadAt，因此调用方不能直接替换这些绑定字段。

`internal/approval/runtime` 已提供一条独立的生产运行时组合根：它连接真实审批 PostgreSQL ledger、epoch checkpoint/restore、管理用户和 Session 健康检查、bcrypt/TOTP verifier 以及 `ApprovalHTTP`。这条组合根默认只接受 `admin` 管理用户的普通审批，并把它映射为 `operator`。调用方必须显式配置 `ApprovalRoles` 或 `AuthorityResolver` 才能放行 `security_admin`；`tenant_owner` 的 Break-glass 还必须绑定精确 tenant scope。HTTP 和本适配器共用 `approval.CanonicalActorRole`，未知和自定义角色不会被转换为受限 authority。AI 适配器目前聚焦于普通操作与 Destructive 破坏性操作的审批确认，角色解析与权限凭证遵循统一的 Gate 合约约束。

## 最小调用示例

```go
store := ai.NewApprovalStore()
gate := approval.NewGate(1)
adapter, err := ai.NewGateApprovalAdapter(store, gate, 1)
if err != nil {
    return err
}
assistant := ai.NewAssistantWithApprovalGate(registry, store, adapter)

pending, err := adapter.CreateFor(tool, args, diff, requester)
challenge, err := adapter.BeginConfirmation(pending.ID, approver, "en-US")
// 等待 challenge.WarningStartedAt 之后至少 10 秒。
_, err = adapter.Confirm(pending.ID, approver, ai.GateApprovalConfirmation{
    PasswordConfirmed: true, SecondConfirmation: true,
    ConfirmationPhrase: challenge.Phrase,
})
// err 应为 approval.ErrThirdConfirmation。
result, err := adapter.Confirm(pending.ID, approver, ai.GateApprovalConfirmation{
    PasswordConfirmed: true, SecondConfirmation: true,
    ThirdConfirmation: true, ConfirmationPhrase: challenge.Phrase,
})
if err != nil || result.Commit == nil {
    return err
}
```

示例中的 `approval.NewGate(1)` 只是 contract 测试用的策略代次。生产启动必须从控制面读取当前代次，并在同一进程内复用 Gate；不能把固定值当成集群 fencing。

## 兼容和失败边界

`ApprovalStore` 仍负责持久化 AI 审批快照。适配器自己的绑定和确认挑战只在进程内保存；Gate 审计是否持久化取决于调用方注入的 Gate。生产环境配置 PostgreSQL ledger 支持 record、event、epoch 和幂等状态的持久化保存。进程重启后，旧的确认挑战不会继续使用；调用方可以针对仍为 `pending` 的兼容审批单重新开始一段新的告警等待，并获得新的确认 ID。已经写入 Gate 的审批提交如果没有对应的兼容快照，也会拒绝执行。

旧的 `BeginExecutionForWithPreview`、`MarkExecuted` 和 `MarkExecutionFailed` 也会拒绝 `Destructive` 请求；只有适配器内部在验证 Gate 提交后才能调用对应状态转换。

这层适配器本身不拥有 HTTP、密码或 TOTP 校验器，也不直接管理 PG。它通过显式注入的 credential verifier 和 Gate 工作；`internal/approval/runtime` 已为 `ApprovalHTTP` 提供管理用户、Session、bcrypt/TOTP 和真实 PG 组合。Destructive 破坏性审批操作严格依赖 Gate 的高风险授权与二次确认机制。

## 集成约束与规范

1. 从控制面注入策略代次和本地控制面证明，并将 AI 适配器绑定到生产运行时的 durable Gate。
2. `GateApprovalChallenge` 和 `GateApprovalConfirmation` 复用服务端密码或 TOTP 校验结果，拒绝客户端伪造 `Local`、Session 或时间。
3. 验证 AI 请求、Gate record/event、epoch fencing 与执行状态保持统一生命周期一致性。
4. `security_admin` 与 `tenant_owner` 的 Break-glass authority 须绑定精确 tenant scope 与严格审计。
