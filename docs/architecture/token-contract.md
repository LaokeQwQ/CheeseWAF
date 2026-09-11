# Token Contract（阶段 5）

`internal/tokens` 是 CheeseWAF 管理 Token 的纯 Go 合约。它只实现确定性的签发、授权、状态转换和清理决策，不连接网络、PostgreSQL、Redis、KMS，也不创建后台 goroutine。每个操作都由调用方传入 `time.Time`；生产适配器负责把状态和事件投影到持久存储及通知系统。

## 能力模型

Token 是不可扩大的权限快照。签发请求必须同时给出非空的 `Permissions` 和 `Resources`：

`PolicyEpoch` 必须是非零策略代次；缺少它的 Token 不得签发。控制面据此防止权限快照跨策略代次重放。

- `Permissions` 是功能级能力，例如 `rules.read`、`sites.write`；支持显式 `*` 作为已授权的全量能力。
- `Resources` 是资源或接口范围，例如 `site:alpha`、`api:/v1/rules`；同样支持显式 `*`。
- `Scopes` 是 `Resources` 的兼容别名；两者同时给出时合并并去重，内部以同一不可变范围快照校验。
- `Owner`、`Note`、`PolicyEpoch`、创建时间、失效时间和状态属于元数据；`Get`/`List` 永远不返回密钥原文。
- 签发后权限和资源不能被管理器扩大。权限变更应通过新 Token 或更高层的带 epoch 的授权适配器完成。

签发结果 `Issued` 只在创建调用中返回一次 `Secret`。管理器只保留 SHA-256 摘要，并使用常数时间比较验证，避免把可重放的原文写进元数据或事件。

## 生命周期和确认

默认 Token 有效期为 90 天，允许的最大有效期为 365 天。`NeverExpire` 必须显式设置 `ConfirmNeverExpire=true`（对应 UI/CLI 的二次确认）；永不过期 Token 不携带 `ExpiresAt`，但仍受 180 天无活动自动销毁约束。

`Authorize` 在执行前按以下顺序 fail-closed 检查：Token 存在、调用时间不早于创建和最后活动时间、密钥摘要、撤销/禁用状态、有效期、180 天无活动、权限精确匹配、资源精确匹配。只有全部通过才更新 `LastActivityAt`。失败不会刷新活动时间，也不会扩大权限。

显式 `Disable` 和 `Revoke` 都是不可逆的状态标记；后续授权分别返回 `ErrDisabled` 或 `ErrRevoked`。调用方应把这两个动作接入审批、密码确认和审计策略；本合约不假设交互界面。

## 延迟清理和通知

管理器维护一个可观察的 `NextCleanupAt`，不为每个 Token 创建定时器。批量创建使用滑动清理窗口：每次创建最多把 deadline 推迟到“本次创建时间 + 10 分钟”，但不能超过首个创建时间 + 60 分钟。因此连续创建不会无限推迟清理。外部调度器在 deadline 到达后调用 `Cleanup(now)`：

1. 一次性扫描并删除已过期或 180 天无活动的 Token；
2. 为每个删除追加 `EventAutoDestroyed`，并设置 `Notification=true`，供 PG outbox/通知适配器发送提醒；
3. 有 Token 留存时，把下一次 deadline 设置为 `now + 10m`；没有待处理 Token 时清空 `NextCleanupAt`。重复调用不会重复删除。

`Cleanup` 在 deadline 之前返回 0，不阻塞授权路径。授权始终即时拒绝过期和不活动 Token，即使清理调度器暂时不可用。
授权不会等待清理：只要当前时间达到 Token 的失效时间，`Authorize` 立即返回 `ErrExpired`；达到 180 天无活动时立即返回 `ErrInactive`。

## 事件和防御性复制

`Events`、`Get` 和 `List` 都返回副本；权限、资源切片和事件结构的调用方修改不能改变内部状态。事件序号单调递增，包含 Token、操作者、原因和时间。事件仅是内存快照，不等同于耐久审计；生产适配器必须使用幂等 outbox 写入 PG，并在通知失败时重试而不改变授权结果。

## 适配边界

当前已提供 `internal/tokens.Persistence` 与 `internal/tokens/postgres.Store` 合约实现边界。PostgreSQL 适配器将 Token 状态、幂等键和 append-only 事件放进同一事务，并使用 `ExpectedVersion`（乐观版本）与 `LeaseID`（租约/栅栏值）拒绝并发冲突。`MemoryPersistence` 仅用于确定性测试，不能用于生产。

- `cheesewaf_token_state` 只保存权限/资源快照、状态、活动时间、策略代次、版本、租约和 64 个十六进制字符的 SHA-256 摘要；数据库表没有明文密钥列。
- `cheesewaf_token_events` 是按租户、Token 和序号排序的追加表；自动销毁先追加通知事件，再删除状态行，事件仍可恢复查询。
- `cheesewaf_token_idempotency` 保存请求指纹；同一租户/幂等键只有完全相同的重试才成功，内容不同直接拒绝。
- 适配器创建 PostgreSQL 事务失败、连接不可用或版本/租约冲突时返回错误；它不负责、也不得静默回退 SQLite。生产接线必须由配置层显式选择 PostgreSQL。

- PG 保存 Token 元数据、状态、活动时间和事件 outbox；密钥摘要可按租户密钥策略加密存储。
- Redis 只能用于短期黑名单/缓存加速，不能成为唯一真相；Redis 故障时按本地 last-known-good 权限快照 fail-closed 或有限回退。
- 控制面在接线时应为权限快照绑定策略 epoch，恢复或集群切换时按策略撤销或轮换 Token。
- Web/API 的一次性显示、密码/二次/三次确认、180 天通知和恢复后撤销由上层服务实现，不能通过绕过本合约放宽权限。

## 当前管理 API 接线边界

管理控制台使用的 `POST /api/system/api-tokens` 已接入同一有效期上限：未提供
有效期时默认 90 天，`ttl` 和绝对 `expires_at` 都不能超过 365 天。新建不过期
令牌必须同时提交 `never_expire=true`、`confirm_never_expire=true` 和非空的
`confirmation_id`；该操作只接受管理员 Session，不能由 Management API Bearer
Token 自己签发。服务端对确认 ID 保留短期、一次性的重放屏障，配置提交失败时会
释放该保留。当前 Web 管理页将“不过期”选项置为不可用，避免把普通点击冒充
强确认；待 password/TOTP、10 秒警告阅读、当前本地 Session 和 ApprovalGate
接线完成后，再开放完整向导并生成该 ID。

旧配置里 `expires_at` 为空但没有 `never_expire` 标记的 Token 被视为历史永久
Token，升级不会静默缩短或删除它们；只要存在 `created_at` 或 `last_used_at`，认证
仍会在连续 180 天无活动后 fail-closed。没有任何活动时间的历史记录不能安全推断
年龄，必须由管理员轮换或撤销。

`cheesewaf serve` 为管理 API Token 启动一个单 worker 清理循环。它只在合并的
deadline 到达后扫描：新建 Token 将 deadline 滑到“最后一次创建 + 10 分钟”，并
受“本批首次创建 + 60 分钟”上限约束。自动销毁先完成配置提交，再尽力写入本地审计
和管理员通知；审计/通知失败不会使 Token 恢复可用。请求认证路径仅做常数时间摘要、
有效期和无活动检查，不做全表清理扫描。

这不是完整的生产 TokenService：确认尚未接入密码/TOTP、10 秒警告阅读、审批
Gate 或 PG outbox；API 为保持既有自动化兼容性仍在创建响应中返回一次明文，因此
尚未满足“外部 API 只返回 ID/元数据”和 CSV 一次性导出的最终交付要求。生产集群
的 PG 真相、Redis 黑名单和恢复后统一轮换也仍待接线。
