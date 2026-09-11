# 生产控制面启动接线契约

本文描述 `internal/controlplane.Bootstrap` 的最小启动边界。
它固定启动顺序和失败行为。
PostgreSQL、native-raft 和管理面适配器都应遵守这份契约。当前 `cheesewaf serve`
的 production 分支会调用统一启动单元，但默认 factory 尚未提供完整的审批 consumer
和最终 `WireServe`，因此仍会 fail-closed。temporary 分支不调用该生产启动流程。

## 启动顺序

生产启动必须按下面顺序执行：

1. `DurableBootstrap.Prepare` 完成 PostgreSQL 控制面表的幂等迁移。
2. `DurableBootstrap.Health` 检查连接和读写能力。检查失败时不启动共识组件。
3. `DurableStore.LoadState` 读取 PG 的控制面快照。
4. `ConsensusBootstrap.Prepare` 启动或连接 native-raft coordinator。
5. `ConsensusBootstrap.Health` 检查成员、term 和当前领导状态。
6. `ConsensusStore.Current` 读取共识快照。
   PG 和共识快照必须逐字段一致。
   需要比较 cluster、term、epoch、revision、leader、desired digest、payload、冻结状态和 nonce ledger。
7. 在临时状态机中校验快照，并检查它没有回退本机已经保存的 last-known-good revision、epoch 或 term。
8. `FenceBootstrap.Establish` 返回与快照绑定的 fencing token。
   token 的 cluster、leader、epoch、revision、digest 和 nonce 必须匹配。
9. fencing 完成后再次读取 native-raft 状态。
   如果 term、leader、epoch、revision 或摘要发生变化，启动失败并保持冻结。
10. 只有以上步骤成功后，才把快照安装到运行状态，并报告 `StartupStageReady`。

当 PostgreSQL 与 native-raft 都没有 desired payload 时，启动不会把空状态变成
默认配置。必须提供一次性的 `InitialStateRequest`，其中包含版本、JSON payload、
nonce 以及严格的管理员确认 ID、操作者和原因；如果配置了外部
`InitialStateAuthorizer`，还必须通过该授权边界。首次提交仍按 consensus → PG
顺序持久化，任一步失败都保持冻结。

如果两份快照的 desired payload、revision 和 nonce ledger 完全一致，但 term、
epoch 或 leader 不同，启动只能调用显式的 `LeadershipCheckpointStore`。该边界
负责验证并记录 leadership-only 变化；缺少能力、返回改变 payload 的结果或 PG
无法持久化 checkpoint 时，启动失败并保持 last-known-good，不能直接用较新的
共识快照覆盖 PostgreSQL。

实现不能在 fencing 成功前暴露未验证的快照，也不能用 PG 较旧快照覆盖本机较新的 last-known-good。

## 健康失败和 last-known-good

`FailClosed` 会冻结新的控制面写入。
它会保留 `StateMachine` 中已经提交的 desired state。
数据面可以继续使用这个 last-known-good 快照。
控制面不得继续接受新的 proposal。
恢复流程必须重新执行双快照比较和 fencing。
调用方不能直接解除冻结。

启动失败返回失败阶段和错误，不返回 ready。
失败路径不会调用后续组件。
`StartupResult.LastKnownGood` 始终来自 committed state。
它不包含只存在于内存中的未提交 proposal。

## 后端边界

启动契约要求 durable backend 返回 `postgresql`。
consensus backend 必须返回 `native-raft`。
SQLite 只属于 `storage.profile: temporary`。
现有 builtin coordinator 只服务单节点兼容路径。
etcd 选择也不能伪装成 native-raft。
这些不兼容后端会在任何 Prepare 或 Health 调用前被拒绝。

`internal/controlplane/postgres.Store` 目前实现 `controlplane.DurableBootstrap`。
它仍没有实现完整的 `storage.Store`。
因此本契约不把它当作管理面存储。
接口测试也不能证明生产服务已经接入。
外层启动器仍需先准备完整管理面存储。
之后再把对应的生命周期适配器传给控制面。

## 当前未接入范围

- `cheesewaf serve` 的 production profile 已调用独立管理/控制 PostgreSQL、native-raft、Redis 和审批依赖的统一启动单元；默认 factory 仍因未提供完整审批 consumer 和最终 `WireServe` 而 fail-closed。temporary profile 才选择 SQLite。
- native-raft coordinator、成员身份、领导选举和 fencing token 已有独立适配器与测试，
  但多节点部署、成员注册和生产证书交接仍需外部运行环境。
- 管理面 PostgreSQL `storage.Store`、Redis 短租约、审计 outbox 和恢复后的自动轮换已
  有适配器边界，但默认 production launcher 尚未把完整审批 consumer、持久审计和所有
  管理消费者挂入 `WireServe`。
- 本文和 `startup_test.go` 证明接口顺序、双快照校验和 fail-closed 行为；它们不单独
  证明外部网络集群或生产数据库已经部署。
