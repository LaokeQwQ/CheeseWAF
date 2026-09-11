# `cheesewaf serve` 生产启动接线边界

主 `cheesewaf serve` 仍以 `storage.profile` 选择管理存储。`temporary` 路径继续打开现有 SQLite，生产路径不会创建或探测 SQLite 文件。

在进入 profile 分支前，`serve` 会先调用 `ensureNoPendingMigration`。这个检查连接了迁移 runner 的本地 recovery record/fence 与服务启动生命周期：迁移中断、commit outcome unknown、恢复文件损坏或权限不安全时，服务不会创建数据目录、PID lease、生产 backend 或 listener。temporary 侧的 SQLite `credential_epoch` 提升和 Session 撤销由迁移源在 fence 发布后执行；回滚只有在快照恢复成功后才清理 fence。对应的回归测试是 `internal/cli/migration/recovery_test.go` 中的 `TestTemporaryInvalidationBindsSessionEpochToServeFenceAndRollback`。

生产启动使用一个不可拆分的依赖组合：

1. 管理面 PostgreSQL `storage.management_postgresql.dsn`，实现 `storage.Store`，先完成迁移。
2. 控制面 PostgreSQL `storage.control_postgresql.dsn`，只实现 `controlplane.DurableBootstrap`；它不能被转换成管理面 `storage.Store`。
3. native-raft `cluster.consensus.native_raft`，使用显式 `data_dir`、`listen` 和 `mode`，与控制面 PostgreSQL 一起调用 `controlplane.Bootstrap`。
4. Redis 必须启用并提供地址和实例身份。Redis 只提供短期协调与缓存状态，不能替代 PostgreSQL 或 Raft 真相。
5. 审批依赖必须通过生产启动 factory 注入并通过健康检查。默认 factory
   在拿到管理 PostgreSQL、控制面 DSN 和 Bootstrap 后的当前 epoch 时打开
   `internal/approval/runtime`，由它创建真实 approval PostgreSQL ledger、恢复
   epoch+record+events 快照，并绑定管理用户、Session 和 TOTP verifier。只有同时实现
   `ProductionApprovalDependency.ApprovalHTTP()` 的审批服务才会把严格
   `ApprovalHTTP` Gate 传给管理路由；单纯的健康探针不会暴露审批端点。
   当前默认 factory 可以打开该运行时，但仍未提供最终 `WireServe`，因此主服务保持 fail-closed。

   该运行时的凭证验证会检查管理用户、活动 Session、bcrypt 密码或原子 `ConsumeTOTP`，并且当前只接受 `admin` 用户的普通审批。PostgreSQL Gate 写入通过同一事务中的 epoch 行锁保护；旧 Gate 在 durable epoch 漂移后写入失败并回滚。`security_admin` 和 `tenant_owner` 的 Break-glass authority resolver 仍是后续 P1，不能把 Gate 合约中的角色规则写成生产流程已经完成。

factory 通过 `ProductionDependencyFactory` 暴露每一个打开点，`ProductionDependencies.Close` 按审批、Redis、native-raft、控制面 PostgreSQL、管理面 PostgreSQL 的逆序关闭，启动失败、Bootstrap 失败和最终 serve 接线失败都执行相同清理。主 `serve` 在 production profile 下先完成这组打开、迁移、健康检查、Bootstrap、fencing 和 `WireServe`，之后才创建运行目录和 PID lease；因此依赖缺失不会留下 serving 进程的 PID 或 listener 副作用。只有控制面 `Bootstrap` 返回 `StartupStageReady`，Redis/审批健康检查通过，并且显式 `WireServe` 完成后才会返回 `Ready=true`。

默认 factory 在启动上下文不完整时仍返回 `ErrProductionApprovalUnavailable`，因此缺少
management store、当前 epoch、控制面 DSN 或完整 `WireServe` 时主 `serve` 仍会在绑定
HTTP listener 前 fail-closed。部署 launcher 也可以通过 factory 提供其他实现
`ProductionApprovalDependency` 的审批服务；主 router 随后消费 factory 返回的
`ApprovalHTTP`，并将管理 PostgreSQL `storage.Store` 作为所有管理 API 的存储。测试可以
注入完整 factory 来验证顺序、双 PG 边界、Bootstrap、ApprovalHTTP 传递和失败清理；测试
fake 不代表真实生产后端已上线。

这条本地 fence/Session 纵切片不等于 production switch 已完成。生产路径仍要求 `ProductionDependencyFactory.WireServe` 把管理 PostgreSQL、control-plane、Redis、审批和所有管理消费者绑定到同一服务生命周期；默认 factory 虽可打开真实审批运行时，但尚未提供最终 `WireServe`，因此审批和管理消费者仍未接入主服务。`TestOpenProductionDependenciesRejectsUnwiredServeEvenWhenBackendsHealthy` 必须继续通过并保持主服务 fail-closed。不得通过跳过 fence、恢复记录或 epoch 检查来解除该门禁。
