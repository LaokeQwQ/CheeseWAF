# ApprovalGate Contract（阶段 5）

`internal/approval` 是控制面最终授权边界的纯 Go 合约。它只负责把一条不可变的操作请求转换为授权提交（`AuthorizationCommit`），并生成内存中的 append-only `AuditEvent` 快照。它不连接网络、不读写 PG/Redis、不等待计时器，也不执行操作；调用方必须在每次调用时传入 `Now`（`time.Time`）。普通 `NewGate` 始终启用严格模式：不会为了兼容旧调用而自动修剪身份字段或跳过确认字段。

已验证的生产运行时组合根位于 `internal/approval/runtime`。它要求管理 PostgreSQL 健康检查、审批 PostgreSQL DSN 和当前 `PolicyEpoch`，负责创建真实的审批 PostgreSQL ledger、初始化或校验 epoch checkpoint、恢复 epoch/record/events，并绑定管理用户、Session、bcrypt/TOTP verifier、`ApprovalHTTP` 和 `PolicyEpoch`。这证明了审批运行时组合根和真实 PG 集成可用，但不等于主 `cheesewaf serve` 已完成生产接线；默认 factory 在最终 `WireServe` 或管理消费者缺失时仍 fail-closed。

## 风险和审批决策

| 风险 | 默认状态 | 自动批准 | 确认要求 |
|---|---|---|---|
| `low` | `pending` | 只有明确登记的预批准可自动提交 | 预批准无需交互确认；人工路径仍需完整本地确认 |
| `medium` | `pending` | 否 | 本地人工、密码、二次确认、告警阅读满 10 秒 |
| `high` | `pending` | 否 | 同上，并必须第三次最终确认 |
| `emergency` | `pending` | 否 | 受限 Break-glass、完整三次确认、理由和授权角色 |

即使请求标记为 `low`，以下操作也永远不能自动批准：不可信来源、测试包、Token、KMS、集群操作，以及任何 `high`/`emergency` 请求。Emergency 请求提交时必须声明 Break-glass，确认人必须是 `security_admin` 或 `tenant_owner`。

上表描述的是 Gate 合约层规则。生产运行时默认只接受 `admin` 管理用户的普通审批会话，并把它映射为 `operator`。调用方必须通过 `Options.ApprovalRoles` 或显式 `AuthorityResolver` 放行受限角色；`security_admin` 只有在显式策略中才具备 Break-glass authority，`tenant_owner` 还必须命中精确的 tenant scope。claims 中的角色必须与数据库用户角色一致，未知和自定义角色保持拒绝。主 `serve` 的完整接线、会话租约和持久 authority proof 仍未完成，不能据此声称生产 Break-glass 流程已经闭合。

角色到 Gate authority 的转换使用 `approval.CanonicalActorRole`。它只识别 `admin`、`security_admin` 和 `tenant_owner` 三个精确名称；普通 `admin` 永远不会被转换为 emergency authority。HTTP 和 AI 适配器共用这份转换契约，未知角色最多保留为普通 `operator` 的非特权映射，不能绕过 runtime 的 authority policy。

## 确认状态和绑定

`Confirmation` 至少包含并绑定以下字段：

- `WarningReadAt`：告警阅读时间；服务端检查 `Now-WarningReadAt >= 10s`，不在 gate 内 sleep。
- `PasswordConfirmed` 或 `TOTPConfirmed`：当前会话完成密码或 TOTP 强认证；二次确认由 `SecondConfirmation` 表示。
- `ThirdConfirmation`：高风险、敏感类别和不可信/测试操作必须在此前的二次确认检查点之后再次点击；首次只记录 checkpoint 并返回 `ErrThirdConfirmation`，不得用一次请求同时伪造第三次点击。
- `ConfirmationID`：一次性确认 ID；全局重放会被拒绝。请求还会获得不可变的 `Nonce`，确认、提交和审计必须带同一 nonce，避免把一条确认材料搬到另一条请求。
- `Actor`、`ActorRole`、`SessionID`、`Local`：操作者、角色、当前会话和本地控制面来源证明。身份字段拒绝首尾或嵌入的 Unicode 空白、控制字符（`Cc`）和格式/不可见字符（`Cf`）；不得使用 `TrimSpace`、大小写转换或其他静默归一化。交互授权必须来自本地控制面。
- `ConfirmationLanguage`、`ConfirmationPhrase`：调用方必须显式提交已解析的 UI 语言；语言与服务端期望短语必须精确匹配（`zh-CN` 对应“确认”，`zh-TW` 对应“確認”，`en-US` 对应 `CONFIRM`）；短语不能通过 trim 或大小写转换绕过。
- `Scope`、`IntentDigest`、`WorkflowDigest`、`Nonce`、`PolicyEpoch`：精确范围、操作摘要、工作流版本、请求 nonce 和策略代次；任一发生实质变化都拒绝旧确认并要求新请求/新确认。
- `TTL`：由请求写入确认状态和提交结果；如果调用方提供非零值，必须与请求 TTL 完全相同。`ExpiresAt` 取提交时的请求 TTL，平台硬上限为 30 分钟。

确认不能扩大请求范围，也不能把旧策略代次升级为新策略。过期、撤销、状态非 pending、确认 ID 重放和任何绑定不一致均 fail-closed。

## AuthorizationCommit

成功确认返回 `AuthorizationCommit`，其中包含 `RequestID`、一次性 `ConfirmationID`、`Actor`、精确 `Scope`、`PolicyEpoch`、风险级别、`TTL`、签发时间和过期时间，以及 `SessionID`、语言、`IntentDigest`、工作流摘要和 `Nonce`。下游 broker/控制面必须把 commit 作为不可变能力证明，并在执行前再次检查 TTL、epoch、scope、摘要、会话和 nonce。

## 审计

每次提交会追加 `AuditSubmitted`；高风险首次二次确认会追加 `AuditCheckpoint`；自动或交互授权追加 `AuditAuthorized`；撤销、过期和拒绝分别追加对应事件。事件带单调 `Sequence`、时间、请求、操作者、范围、epoch、会话、操作摘要、确认 ID、确认阶段和原因。内存 `AuditEvents` 返回防御性副本；`MemoryPersistence`/PostgreSQL 适配器还会把每个事件的 request、scope、epoch、intent/workflow digest、session、nonce 与同一 Record 精确绑定，并校验序号、previous hash、事件 JSON hash 及 PostgreSQL `event_hash` 列。PG 的 `Apply`/`ApplyBatch` 写入会在同一事务中锁定并检查 epoch；旧 Gate 在 durable epoch 漂移后写入会返回 `ErrEpochChanged`，事务回滚，不会留下旧代次的 record、event 或幂等状态。该真实 PG epoch fencing 集成已通过验证，但完整服务 wiring 仍未完成。PG outbox、SIEM/WORM 的生产接线仍由后续适配器负责，不能把当前持久化 contract 误称为完整生产耐久审计。

## 与工作流和运行时的边界

workflow sidecar 可以编排 DAG、通知和超时，但不能直接授权；只有核心 gate 能生成 `AuthorizationCommit`。`PlanWorkflow` 只输出 39/50 风险路由决策，`WorkflowBinding`/`ValidateWorkflowBinding` 用 approval、摘要、scope、session、nonce、epoch、TTL 和事件序号绑定 sidecar 状态；`ValidateSuperBatch` 只做 Logical Super Batch 的全量预检，`ApprovalDelegation` 只允许预配置的一跳、一次性委托。上述 API 都不执行操作、不改变请求状态，也不把 sidecar 状态当成核心授权。

本合约不实现 Token、Redis、KMS、UI、Break-glass 会话租约或实际操作执行。Gate 现在可由调用方显式绑定 `Persistence`，并通过 `Restore`/`RestoreRecord` 在启动时校验 record、事件哈希链、scope/intent/session/nonce/epoch/TTL 后恢复；未绑定时仍为纯内存模式。实现可选的 `EpochSnapshotPersistence.LoadWithEventsAtEpoch` 时，Gate 会在一次一致性读取中同时绑定期望的策略代次、record 和事件链；`MemoryPersistence` 在同一读锁内检查 epoch，PostgreSQL adapter 在只读 `REPEATABLE READ` 事务内读取 epoch、record 和事件，epoch 不匹配直接返回 `ErrEpochChanged`。仅实现 `SnapshotPersistence.LoadWithEvents` 的旧 adapter 仍保持 Record+Events 快照，但继续沿用独立 epoch 检查；未实现快照能力的旧 `Persistence` 继续使用 `Load` 后 `Events` 的兼容回退，所有路径均 fail-closed。持久 Gate 的 `AdvanceEpoch` 只有在 adapter 实现 durable `CompareAndSetEpoch` 时才可用：先拒绝回退，再执行 CAS，CAS 失败不会改变内存 epoch；外部已经推进 durable epoch 时必须显式重建并恢复对应代次的 Gate，不能让陈旧实例静默认领新代次。`DelegationLedger` 当前仅是进程内 contract，生产环境仍需接入 PG/控制面幂等账本。PostgreSQL adapter 已提供 request ID 枚举；`internal/approval/runtime` 已另外提供真实 credential verifier 和 `ApprovalHTTP` 组合，但这些能力尚未通过主服务的完整消费者 wiring 上线。

生产接线必须保留：请求数据面不等待 gate 或工作流 I/O；管理面不可用时已有 last-known-good 数据面继续服务；高风险确认失败不得静默降级为自动批准。
