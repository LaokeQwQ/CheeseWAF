# Redis 短期状态边界合约

`internal/cluster/redis` 是 Redis 适配器接入前的纯 Go 合约。它不导入 Redis client，不建立网络连接，也不改变现有 `storage`/`serve` 路径。

## 权威边界

- PostgreSQL 保存持久管理真相（Session、Token、审计和队列元数据）。native-raft 保存成员、任期、epoch、fencing 和期望状态。
- Redis 只承载短期锁、租约、缓存、黑名单加速和通知；Redis 的 key、value、TTL 或实例身份都不能成为唯一恢复依据。
- 所有短期状态都必须带非零 `policy epoch` 和明确 TTL；epoch 变化后旧状态不可跨代使用。

## 故障矩阵

| 状态 | 租约/锁 | 黑名单 | 缓存 |
| --- | --- | --- | --- |
| available | Redis | Redis | Redis |
| unavailable/timeout | TTL 不超过本地上限时仅允许有界本地回退，否则 fail-closed | fail-closed | 仅可读本地短期值；无值即 miss |
| unknown instance | fail-closed，禁止静默切换实例 | fail-closed | miss |

本地回退是进程内、容量受限、TTL 受限的安全降级，不是 Redis 或控制面的替代品。集群部署不能把本地回退当作分布式互斥；需要持久或跨节点一致性时必须回到控制面/PG/native-raft。

## 合约 API

- `Evaluate` 将操作、后端状态、epoch 和 TTL 映射为 `redis`、`local`、`fail-closed` 或 `cache-miss`，并拒绝缺少 epoch 或无效 TTL。
- `LocalState` 提供有界的租约/锁 reservation、黑名单标记和缓存值。`Valid` 在使用点再次检查 epoch 和 TTL；缓存和黑名单按 epoch 隔离并在过期后删除。
- 合约只产生确定性决策和内存状态；外部适配器负责 Redis 请求超时、实例身份验证、PG/raft 权威校验、审计和持久化。

当前测试使用 `go test -race` 与 `go vet` 验证并发访问和纯 Go 合约；不代表 Redis 生产接线已经完成。
