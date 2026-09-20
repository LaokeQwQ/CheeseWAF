# 管理控制面的期望状态载荷（management.v1）

本文说明管理控制面目前可以复制的第一种配置载荷。它只包含
`PUT /protection/policy` 的完整防护策略快照。它没有把管理 API、物化器或生产模式的
`WireServe` 接入。实际进度以 `tasks.md` 为准。

## 范围

控制面保存版本明确、可验证、可重放的期望配置，不保存节点的完整 `config.Config`。
完整配置中会出现本地路径、数据库连接、凭据、证书、密钥和运行时状态。这些值只能留在
节点本地配置或受保护的管理存储中，不能进入 Raft、控制面 PostgreSQL 或审计事件。

这个阶段只允许下面这个固定文档：

```json
{"version":"management.v1","kind":"protection.policy","spec":{"web_attack":"smart","api_security":"high","bot_cc":"low","threat_intel":"off"}}
```

## 字段与值

| JSON 路径 | 类型 | 约束 |
|---|---|---|
| `version` | string | 必须是 `management.v1` |
| `kind` | string | 必须是 `protection.policy` |
| `spec.web_attack` | string | `off`、`low`、`smart`、`high` 或 `strict` |
| `spec.api_security` | string | 同上 |
| `spec.bot_cc` | string | 同上 |
| `spec.threat_intel` | string | 同上 |

四个策略轴都是完整快照。HTTP 层可以接受局部修改，但必须先和当前节点配置合并，
再生成包含四个字段的文档。局部 patch 不能直接作为可提交的期望状态。

## 编码和检查规则

`internal/controlplane/desiredstate` 是唯一的编码和解码入口：

1. 编码只接受完整、有效的 `config.ProtectionPolicyConfig`，生成字段顺序固定的 JSON，
   并返回这段字节的小写 SHA-256 摘要（digest）。
2. 解码会拒绝未知字段、重复对象键、缺失字段、空值、非法枚举、错误的
   `version`/`kind`、尾随 JSON 文档、非 UTF-8 载荷和非规范 JSON（包括空白或字段
   顺序变化）。
3. 载荷上限为 1 KiB。超过上限时，JSON 解码前就会返回错误。
4. `ProtectionPolicyDocument.Config` 会再次检查导出的文档值，避免调用方通过
   直接构造或修改导出字段绕过校验。
5. proposal 必须提交本包生成的规范字节和对应摘要。调用方不能把原始 HTTP body、
   完整 `config.Config` 或未经本包检查的 `json.RawMessage` 直接放入
   `controlplane.Proposal`。

摘要绑定实际提交的字节，不绑定解码后的结构。因此，PostgreSQL、native-raft 和重试
路径会把同一份提交识别为同一个字节序列。

## 计划中的物化顺序

接入真实写入路径前，必须按下面的顺序实现：

1. Handler 在节点本地快照上合并并检查局部请求。身份字段不能被静默修剪。
2. Handler 通过本约定生成完整策略和摘要。`Coordinator` 独占一次
   `ProposeAndApply` 调用。
3. `Coordinator` 使用 expected epoch、expected revision、leader、一次性 nonce 和精确的
   `Commit`。native-raft 只复制这份 `Commit`，不会重复提案。
4. 物化器先检查 `Commit` 中的 fencing token、nonce、载荷和摘要，再把四个策略轴合并
   回节点本地配置。
5. 物化器会检查合并后的完整本地配置，然后按既有的运行时、YAML 和发布通知补偿顺序
   应用。任一步失败时，保留 last-known-good 配置、冻结新的写入，并用同一份 `Commit`
   重试。
6. 重试时不能重新编码、重新生成时间戳或创建第二个 revision。全部成功后才能解除冻结。

站点、Token、AI、调度器和其他完整配置修改还不能复用这个编码器。每种新的期望状态类型
都必须有独立的字段范围、敏感字段审查、物化器和
故障注入测试。

## 当前状态与非目标

- 已完成：`management.v1/protection.policy` 的固定字段文档、规范 JSON、摘要、严格解码
  和单元测试。
- 已完成本地 contract：`internal/controlplane/materializer` 提供纯注入式
  `ProtectionPolicyApplier.ApplyCommitted`，只接受 exact current commit validator、节点本地
  config snapshot、窄的 YAML/runtime/rollback callbacks 和 `JournalStore`。它按
  `prepared → yaml_persisted → runtime_applied → applied` 推进，成功后才写 LKG；同一 exact
  receipt 重试幂等，旧 epoch/revision 和同 revision 冲突拒绝。receipt 仍只保存 metadata 和
  typed protection-policy payload，不保存完整 Config、DSN、TLS 或 Bot secret。
- 本地 fencing contract 已补强：`StateMachine.WithCurrentCommit` 会在校验通过后持有
  committed-state 读锁直到本次物化 callback 返回，避免校验和 YAML/runtime 副作用之间发生
  revision 或 leader 变化。callback 不得在该临界区内调用会获取 StateMachine 写锁的变更方法；
  这只是单节点边界，不是跨进程或跨节点租约。
- journal/LKG 的两份镜像如果都可读但内容不一致，读取会返回 `ErrReceiptAmbiguous` 并保持
  fail-closed，不会依据时间戳或文件位置自行选择“较新”版本。操作员必须先核对节点本地配置和
  审计记录，再通过受控恢复流程修复；该状态不能作为自动重试成功的证据。runtime callback 已
  产生副作用后即使 context 被取消，也会使用不可取消的继续上下文尝试补偿；补偿目标不可证明
  或补偿失败时写入 `compensation_pending`；上层协调器必须据此冻结后续写入。
- 已完成本地 Handler/CLI 适配 contract：`Handler.ConfigSnapshot`、
  `Handler.PersistMaterializedConfig` 和 `NewProtectionPolicyMaterializer` 已将节点本地
  YAML、runtime callback、journal/LKG 组合为可测试的单节点物化器。适配器要求真实的
  `OnProtectionChanged` 回调和运行目录，缺失时 fail-closed；它不会发布 Handler 内存快照，
  也不会自行创建 proposal。
- 已完成本地 mutation preparation contract：`ProtectionPolicyMutationService` 只接收当前
  四轴策略和 field-presence-aware partial patch，严格校验 actor、leader、nonce 身份，合并
  默认值并生成带 expected epoch/revision、nonce、canonical payload 和 digest 的
  `controlplane.Proposal`。该服务无持久化、网络、Handler、HTTP 或 runtime 副作用；`Actor`
  只保留给后续授权/审计层，不能把身份字段写进复制的策略 payload。
- Handler 现在只提供显式的 `PrepareProtectionPolicyMutation` 注入 seam：它读取不可变策略快照、
  透传请求并在未注入 mutator 时 fail-closed；当前 production router 没有注入它，也不会因此
  绕过旧的本地写路径或宣称 endpoint 已接线。
- 已补充纯 Coordinator consumer：`ProtectionPolicyCoordinatorService` 组合上述 mutator 与
  `Coordinator.ProposeAndApply`，保留 actor 仅供授权/审计，返回 exact commit 供持久化失败后用
  `Apply` 重试；它不依赖 Handler、HTTP、AI、YAML、runtime 或 materializer，缺依赖即拒绝构造。
- 已补充本地跨层回归：真实 Coordinator consumer 生成的 commit 交给真实
  `ProtectionPolicyApplier`，验证 YAML/runtime callback 顺序、exact materialization retry 幂等、
  journal `applied` 以及 DSN、路径和节点 secret 等本地字段不被 desired-state 覆盖。
- 仍未完成：将 `/protection/policy` 接入 `Coordinator`、生产 Handler/endpoint、真实 YAML/runtime
  wiring、跨存储回滚和生产模式的 `WireServe`。runtime 失败且没有可靠的旧 config snapshot 时，
  物化器只写 `compensation_pending` 并 fail-closed；不会猜测当前已持久化 candidate 作为回滚目标。
- 在这些工作完成前，生产模式的 `WireServe` 必须保持失败即拒绝的状态。读取快照或通过
  readiness 探针，都不能替代真实的消费者。
- 本文不改变 `configs/cheesewaf.yaml` 模板和运行时配置副本的边界，也不允许把密钥、
  DSN、Token、证书、私钥或本地路径写入 Git。

## 验收证据

编码器的定向测试覆盖规范字节、摘要、重复键、未知字段、尾随文档、缺失字段、非法枚举、
大小和 UTF-8 边界，以及导出文档的二次检查。真实 API、物化器和跨存储恢复测试完成后，
才能把这个配置修改标记为可用于生产环境。
