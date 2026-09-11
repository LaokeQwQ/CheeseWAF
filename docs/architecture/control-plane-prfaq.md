# CheeseWAF 控制面状态模型 PR/FAQ

状态：阶段 1 实施基线（代码 contract 已落地，后端接入待完成）
日期：2026-09-05

## Press Release

CheeseWAF 将配置提交、集群领导权和数据面应用切换统一到一个可验证的控制面状态模型。管理员看到的是带版本、摘要、epoch 和回滚引用的配置变更；数据面只接受当前领导者签发的 fencing token，因此网络抖动、重复提交或旧节点恢复都不会把陈旧配置重新写回生产流量。即使 PostgreSQL、Redis、LLM 或外部审计系统暂时不可用，已经建立的数据面仍继续使用 last-known-good 快照转发业务。

客户不需要理解 Raft 日志细节即可完成一次安全变更：控制台先展示当前版本和影响范围，提交时执行 compare-and-swap，冲突会明确提示“状态已更新，请重新载入”，而不是静默覆盖。发生维护或多数派丢失时，控制面冻结新的写入，但不会因为管理面故障主动切断已确认安全的站点流量。

## FAQ

### 客户侧

**为什么要有 epoch 和 fencing token？**  集群节点可能在网络分区后恢复。单靠时间戳或节点在线状态无法阻止旧节点继续下发配置；epoch 代表领导代次，revision 代表该代次中的顺序，二者共同构成可拒绝陈旧写入的栅栏。

**配置提交失败会不会影响业务流量？**  不会。提交失败只影响新的期望状态，数据面继续使用最后一个已验证快照。只有显式的管理员硬规则或安全底线才允许阻断流量。

**Redis 宕机会不会丢配置？**  不会。Redis 只承载短期租约、锁、缓存和通知；PG 保存持久管理真相，native-raft 保存顺序、epoch、fencing 和回滚引用。

### 内部可行性

**为什么先提供纯 Go 状态机？**  这样可以在接入 PG/native-raft 前先验证状态转移、并发 compare-and-swap 和陈旧 token 拒绝，避免把后端连通性误当成一致性证明。

**当前是否已经替换现有 etcd？**  没有。阶段 1 的 `internal/controlplane` 是新 contract 和测试基线；现有 `internal/cluster/consensus` 兼容路径保持不变，待后续阶段完成迁移和双读校验后再切换。

**如何证明实现没有把旧配置写回去？**  每次提交都要求 expected epoch/revision；领导变更会递增 epoch 并使旧 fencing token 失效。回归测试覆盖旧 revision、旧 leader、错误 digest 和冻结写入。

**如何回滚？**  回滚仍然是一个新的、带新 revision 的提交，不能重放旧 token。后端需要把 rollback reference 持久化到 PG 和 consensus log，并在数据面验证新的 fencing token 后再切换快照。
