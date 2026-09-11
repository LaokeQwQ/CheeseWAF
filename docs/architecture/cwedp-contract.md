# CWEDP 分发契约（阶段 3）

`internal/cwedp` 定义 CheeseWAF Edge Distribution Protocol 的纯 Go 契约。
协议包只校验消息、选择来源、处理调用方送入的分块，并维护可恢复状态；网络
解析、TLS/HTTP、文件读取和 NetLease 绑定位于独立的
`internal/cwedp/transport` 与 `internal/netlease` 包。`Broker` 的异步 worker
只消费 `Push` 送入的分块，不是主服务的插件安装器。

`internal/cwedp/postgres.ResumeStore` 是单独的持久化适配器：显式接线时可用
数据库保存续传状态。`transport` 包已经提供 broker-bound 的 HTTP/file pull、
Range 续传、TLS/mTLS/NodeID/leaf pin 和 pre-dial fail-closed 逻辑，并有独立
测试证据；这些包仍未接入主 `serve`、节点注册、插件安装/升级/回滚或生产编排。

## 协商

控制面发布带包标识、版本、大小、MD5/SHA-1/SHA-256 摘要、签名引用和候选
来源的 `DistributionIntent`。节点发送 `HELLO` 与 `CAPABILITIES`；只有协议
版本、节点身份、来源能力和离线边界都匹配时才选择来源。离线节点只能选择
`offline-crp`，没有可用离线来源时必须拒绝。

来源独立性默认要求至少两个独立的供应链根和独立性分组。受信任的低风险或
observe 部署可以在 broker 配置中显式把最低值降为一个，但不能提高平台上限。
`Ansible` 仍只用于基础设施和分发代理引导。

## 来源注册与独立性

控制面通过不可变的 `SourceRegistry` 登记来源 ID、来源类型、供应链根
（`Root`）和独立性分组（`IndependenceGroup`）。`ValidateSourceIndependence`
只接受已登记且类型匹配的来源；`DistributionIntent` 自报的 `TrustRoot`、
组织或证书指纹不能覆盖注册表中的受信记录。

独立性同时按登记的供应链根和独立性分组计算，不按 URL、来源类型或传输方式
计算。同一根或同一分组中的多个镜像只计一个独立来源；同一类型的来源只有在
属于不同的已授权根和分组时才可计为多个独立来源。未登记来源、缺少根/分组或
未知类型都必须拒绝。Peer、镜像和 seed 不能修改 manifest、签名或 promotion
状态。

## 隔离源（source quarantine）

`ResumeState.QuarantinedSources` 是按 intent 保存的追加-only 记录。隔离源的
身份是 `(SourceKind, Source.ID)`，而不是 URL 或调用方附带的元数据；同一来源
一旦记录了 `integrity-mismatch`、`transport-failure` 或 `policy-failure`，就
不能再次被该 intent 选择。重复上报是幂等的，不能覆盖原始原因或悄悄解除隔离；
持久化时使用 intent 中的规范来源字段。

完整性或策略失败会触发供应链根隔离：fallback 选择必须跳过与已隔离来源共享
注册表 `Root` 的镜像。单纯的传输失败只隔离精确的 `(kind, ID)` 来源，不因
传输错误自动把同根镜像视为完整性不可信；但所有候选仍须通过来源独立性和
能力校验。

## 传输、续传与原子保存

内容按连续 `offset` 分块传输。接收端拒绝重叠、跳跃、负数、超出 artifact
大小、超过状态协商块大小或空分块，并按 `next_offset` 继续续传。broker 在
提交时限制总 artifact 大小，在入队时限制单个分块大小；队列有界，队列满时
拒绝入队。

`Broker` **强制要求** `AtomicResumeStore`。持久层必须实现
`SaveExpected(ctx, expectedOffset, state)`；broker 创建任务、追加分块、隔离/切换
来源和写入失败状态时都以 worker 读取的 `next_offset` 做 compare-and-swap。
只有 `Save`/`Load` 的非原子实现会被 `Submit` 以 `ErrAtomicResumeRequired` 拒绝，
不能作为 broker 的生产接线。过期 offset 返回冲突，不能让并发 worker 无条件覆盖；
相同 intent 的重复提交复用已保存的 offset，intent 或其不可变字段发生实质变化
则拒绝。

`MaxChunk`、`MaxSourceSwitches` 和 intent 是续传状态的不可变绑定。`SaveExpected`
还必须遵守状态转换约束：普通传输只能追加已有前缀；首次记录来源失败并切换时
必须带有一条新的隔离证据、恰好增加一次切换计数，并通过事务/锁和终态校验。
能力/策略刷新时对既有隔离证据的显式复用不重复增加计数。

## `MaxSourceSwitches`

平台默认值和硬上限都是 `3`（`DefaultMaxSourceSwitches`）。部署可以显式选择
更低值；零值使用默认值，超过上限的配置被收敛到平台上限，不能由 peer capability
扩大。任务状态持久化 `SourceSwitches` 和 `MaxSourceSwitches`；每新增一条来源
隔离（无论当下是否找到 fallback）切换计数恰好增加一次，重复上报同一来源不重复
消耗预算。

达到上限后，新的来源失败不得再追加隔离或消耗切换预算，broker 持久化
`ErrSourceSwitchLimit` 对应的失败状态。如果暂时没有满足能力/策略的 fallback，
传输失败会保存隔离证据和失败状态；后续能力或策略刷新仍可显式复用这条既有证据
选择未隔离的新来源，但不增加计数。这种恢复不等同于新的失败切换，也不得重新
选择已隔离来源。

## 完整性失败与传输失败

完成最后一个分块后，必须同时校验 MD5、SHA-1 和 SHA-256；任一摘要不匹配都属于
完整性失败，不能把当前字节标记为完成或继续沿用为可信前缀。两类失败的状态语义
如下：

| 事件 | 隔离记录与来源选择 | `Data` / `next_offset` | 结果 |
|---|---|---|---|
| 完整性失败（摘要不匹配） | 记录当前来源 `integrity-mismatch`；跳过同一 `Root` 的镜像 | 可重试的切源路径丢弃全部部分字节并重置为 `0`；无 fallback 时保留为不可继续使用的失败记录 | 有合资格来源且预算未耗尽时切源并返回 `Retrying`；否则写入失败状态，禁止继续写入 |
| 传输失败 | 由调用方显式报告并记录当前来源 `transport-failure`；不自动扩大到同根来源 | 保留已验证前缀，可从原 `next_offset` 续传 | 有合资格来源时切源；无来源时保存失败和隔离证据，能力刷新后可显式恢复 |
| 策略失败 | 记录 `policy-failure`，按注册表 `Root` 隔离同根来源 | 保留已验证前缀 | 按来源策略选择 fallback；无来源时失败 |
| 非法分块、损坏状态或新的切换预算耗尽 | 不得绕过状态机或继续写入 | 保留/终止状态由校验结果决定 | 进入失败终态并阻止继续写入；新的预算耗尽返回 `ErrSourceSwitchLimit`，既有隔离证据可在能力刷新后显式恢复 |

broker 不会从任意 transport 错误字符串推断隔离原因；调用方必须通过明确的
`QuarantineSource` 原因枚举报告。完整性失败的重试只允许从零开始，传输/策略失败
的切换才允许复用已验证前缀。

## 持久化边界

`ResumeStore` 保存 intent、当前来源、连续数据前缀、摘要、隔离源列表、切换计数、
失败/完成状态和更新时间。当前提供仅用于确定性 contract 测试的
`MemoryResumeStore`，以及使用事务锁、`FOR UPDATE`、期望 offset、终态约束和
`BYTEA` 的 PostgreSQL 适配器。适配器拒绝实质 intent 变化、过期写入、损坏状态
和已完成任务的后续修改。

## 尚未接入的生产生命周期

协议 API 和独立 transport 不包含主服务启动接线、节点注册/成员管理、持久租约
生命周期、上传/下载方向策略的生产编排、CRP 安装激活或回滚。它们仍不能替代
网络隔离、持久审计、生产部署、控制面授权和空网演练验收。`cheesewaf
temporary-online probe` 是独立的一次性运维工具，不等于插件出站 API。

命令返回时会显式收口临时 session 并撤销一次性 lease；成功、传输失败和
审计失败都不会留下后台 worker 或隐式的长期外连能力。
