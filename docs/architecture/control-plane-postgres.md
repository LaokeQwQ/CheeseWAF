# PostgreSQL 控制面持久化适配器

`internal/controlplane/postgres` 是控制面 `DurableBootstrap` 的 PostgreSQL 适配器。
它保存期望状态、提交历史和 nonce ledger，不保存请求日志或大对象。

## 写入顺序

`Coordinator` 先提交共识，再调用适配器。适配器在同一事务内为 cluster
获取事务级 advisory lock，并锁定已有状态行，检查 epoch、revision、leader、
digest、payload 和 nonce ledger，写入提交历史后更新状态。原始 payload 只保存在
BYTEA 列；JSONB 的 `state_json` 只保存状态元数据，避免 JSONB 规范化空格后破坏
逐字节幂等比较。相同 `(cluster_id, epoch, revision, nonce)` 且内容完全相同的请求
幂等成功；内容不同、旧 revision、revision gap 或写冻结状态都会拒绝。

## 恢复

`LoadState` 返回完整状态和 nonce ledger。上层必须同时读取共识状态并比较
epoch、revision、leader、digest、payload、冻结状态和 nonce ledger；两边不一致
时停止写入，不能用较旧的 PostgreSQL 快照覆盖共识状态。

## 迁移和验证

`Migrate` 创建状态表、append-only 提交表和顺序索引。测试会为每个集成用例创建
随机 schema，并只删除自己的 schema；这样不会清空测试 DSN 指向的其他数据。
当前适配器已通过纯函数、并发首写、重复提交、事务回滚和真实 PostgreSQL 集成
测试。设置 `CHEESEWAF_POSTGRES_TEST_DSN` 后可运行这些集成测试；没有 DSN 时会
明确跳过，而不是伪造通过。生产 serve 已通过 `OpenProductionDependencies` 在统一
production startup unit 中打开该 control-plane adapter；默认 factory 在缺少最终
`WireServe` 或完整生产消费者时仍 fail-closed，本文不宣称生产服务已部署。
生产启动的最小生命周期和 fencing 顺序见
[`control-plane-startup.md`](control-plane-startup.md)。当前统一启动单元已打开
control-plane PostgreSQL、Coordinator 和 native-raft；最终 `WireServe`、完整管理
消费者和生产部署仍待完成。

## 存储 profile 门禁

`storage.profile` 默认是 `temporary`，启动继续使用现有 SQLite 数据库。
只有显式设置为 `production` 才会请求耐久管理存储，并且必须提供
独立的 `storage.management_postgresql.dsn` 和 `storage.control_postgresql.dsn`。这组依赖虽已由
统一启动单元打开，但在最终 `WireServe` 和完整生产消费者接线前，校验和启动路径都
返回 `ErrProductionStorageUnavailable`，明确拒绝静默回退
SQLite。这样可以为后续适配器保留独立接口，同时不改变临时 profile 的默认
行为，也不会在当前代码中尝试连接外部网络。`storage.postgresql` 仍只表示
异步访问日志 sink。

## 管理面 PostgreSQL 接线契约

当前 `internal/controlplane/postgres.Store` 实现
`controlplane.DurableBootstrap`：它保存控制面状态、提交历史和 nonce ledger。它
不是 `internal/storage.Store`，也不能直接作为 `cheesewaf serve` 的管理存储。
`storage.Store` 还必须提供站点、规则、用户、会话、通知、审查项和 TOTP
持久化接口；其中用户安全字段更新必须和全量会话撤销处于同一个数据库事务。
因此，控制面 durable store 与管理面 store 即使共用一个 PostgreSQL 连接，接口
和事务边界也不能互换或省略。

将来启用 `storage.profile: production` 时，启动器必须把以下步骤视为一个不可
拆分的安全单元：

1. 校验 profile、独立的 `storage.management_postgresql.dsn` 和
   `storage.control_postgresql.dsn`，以及 TLS/ACL 等外部连接要求；
2. 打开完整的管理面 `storage.Store`，设置连接超时并执行幂等 schema migration，
   然后执行 health check；
3. 打开同一生产边界内的 `controlplane.DurableBootstrap`、Coordinator 和
   native-raft consensus，分别恢复快照并比较 cluster、term、epoch、revision、
   leader、digest、payload、冻结状态和 nonce ledger；
4. 只有两份快照一致且 fencing 已建立后，才启动管理 API、站点同步和后台写入
   任务。任一步失败都必须停止写入并返回错误，绝不能改用或悄悄创建 SQLite。

本仓库目前已交付管理面 `storage.Store`、control-plane PostgreSQL durable adapter、
native-raft adapter、Redis runtime adapter 和统一 production startup unit；serve 已
调用该启动单元，但完整管理消费者、最终 `WireServe`、生产审计和外部部署仍待完成。
在最终生产接线完成前，production profile 继续保持 fail-closed。新增的 profile 回归
测试会检查错误同时说明 `storage.Store` 与 `controlplane.DurableBootstrap` 不可互换，
并保留 SQLite fallback 拒绝行为。
