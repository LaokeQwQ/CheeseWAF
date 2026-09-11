# Control-plane Contract（阶段 1）

`internal/controlplane` 是 CheeseWAF 商业化控制面的纯 Go 状态转换核心。它不建立网络连接、不读写数据库，也不负责选举；这些职责由后续 native-raft、PostgreSQL 和 Redis 适配器实现。

## 状态字段

- `cluster_id`：租户/集群边界，跨集群 token 一律拒绝。
- `term` 与 `leader_id`：当前共识领导代次和领导者。
- `epoch`：每次领导者或 term 变化递增，旧 epoch 不可写入。
- `revision`：期望配置在当前状态中的单调递增序号。
- `desired.version`、`desired.digest`、`desired.payload`：最后一次已提交的期望状态；digest 必须是 payload 的小写 SHA-256。
- `write_frozen`：维护、多数派丢失或安全门禁期间冻结新写入；不影响已安装的数据面快照。

## 提交流程

1. 控制面读取当前 snapshot。
2. 客户端携带 `expected_epoch`、`expected_revision`、`leader_id`、版本、payload、digest 和一次性 nonce 发起 proposal。
3. 状态机验证领导者、冻结状态、epoch/revision compare-and-swap 和 digest；任一失败都拒绝。
4. 成功后 revision 加一，生成待持久化的 `FenceToken`；只有 consensus log 与 PG 以幂等键 `(cluster_id, epoch, revision, nonce)` 都确认后，控制面才安装 committed fence。
5. 数据面只接受当前 cluster/leader/epoch/revision/digest 完全匹配且已经 committed 的 fencing token；未持久化提案即使在内存中存在也会拒绝。

首次初始化是受保护的单独流程：只有在 PG 与 native-raft 都没有 desired
payload 时，带管理员确认对象的 `InitialStateRequest` 才能生成 revision 1；
空状态不会自动推导默认配置。已有 payload 在新 term/epoch 下恢复时，必须通过
`LeadershipCheckpointStore` 记录 leadership-only 变化，并由 durable adapter 显式
持久化 checkpoint。缺少该能力时保持 fail-closed。

## 存储边界

| 组件 | 允许保存 | 禁止承担 |
|---|---|---|
| native-raft | 成员、term、epoch、fencing、期望状态顺序、回滚引用 | 业务访问日志和大对象 |
| PostgreSQL | 用户、Session、Token、审批、审计、队列、CRP 元数据及状态快照 | 请求线程实时锁 |
| Redis | 短租约、锁、缓存、黑名单加速、通知 | 唯一持久真相、配置恢复依据 |
| SQLite | 临时模式/兼容路径 | 生产模式静默回退的管理真相 |

这些边界是 contract，不代表对应后端已经接入。实现状态必须在 `tasks.md` 和发布说明中单独标记。
