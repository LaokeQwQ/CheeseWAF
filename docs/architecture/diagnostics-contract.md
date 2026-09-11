# 诊断 Broker 契约（阶段 4）

internal/diagnostics 是插件、控制面和未来队列适配器之间的纯 Go 边界。它只做确定性的输入校验、脱敏数据模型、配额、幂等和队列状态转移；不会建立网络、写文件、调用 KMS、PG 或 Redis。任何外部副作用必须由集成层异步执行。

## 固定 Schema 与数据边界

所有回执标记 diagnostic.v1。Package 只允许 metadata、health 和固定的 findings 字段。默认允许 metadata、health、sanitized 三种包；raw 只用于脱敏/扫描失败后的受控例外。Schema 没有原始 HTTP 请求正文、任意文件路径或任意字段扩展入口，因此插件不能借 broker 传递未声明数据。

以下内容无论默认包还是原始包都禁止出现：secret、Token、Cookie、Authorization、Session、Origin 凭据、密码、私钥、credential 以及原始请求正文。输入字段名称会做大小写、连字符和空格归一化后检查；集成层还应在序列化前做内容扫描。

## 高风险原始包

raw 请求必须同时带有：高风险告警确认、确认 ID、当前账户密码已确认、第三次最终确认。10 秒等待、审批/Break-glass 会话和审计由 UI/控制面编排，但 broker 不会接受缺少任何确认状态的请求。原始包仍然使用相同固定 Schema，不能借“原始”名义上传凭据或请求正文。

## 异步队列、幂等和配额

Submit 只做内存校验和入队，立即返回 upload_id，绝不等待目标端。队列有项目数和字节上限；TTL 到期的项目标记为 expired。幂等键绑定包内容、目标、插件 ID/版本、策略 epoch 和 socket lease；同一键重复提交返回原回执，绑定任一项变化则拒绝。

工作线程通过 Next 领取项目（状态 uploading），由适配器调用 Complete 报告成功或失败。失败在次数上限内进入 retrying，只有显式 Retry 才重新入队；达到上限进入 failed。这些状态转移不包含网络或持久化，PG/Redis 只能在上层保存元数据或协调状态，不能替代本地队列的安全边界。

## 运行时接线门禁

根包 `internal/diagnostics` 仍只提供 broker contract；`internal/diagnostics/integration` 已提供
broker → canonical envelope → 本地持久加密队列 → 失败重试/replay → metadata-only audit
的可验证组合 runtime。该组合不代表对象存储复制、外部目标签名回执、跨进程 exactly-once
或主 serve 已接入。接线时必须保留请求线程不等待、离线模式暂停外发、目标和租约预检、
信封加密、重试/取消/TTL 可观察，以及所有确认和失败事件可审计。

## 应用侧信封加密（`diagnostic-envelope.v1`）

`internal/diagnostics/envelope` 子包是当前 `diagnostic-envelope.v1` 的 canonical 实现。集成层应使用其中的 `Envelope`、`KeyProvider`、`Seal`、`Open`、`Verify` 和 `Rewrap`；它可以把 `KeyProvider` 连接到外部 KMS，也可以在符合离线/单节点审批要求的情况下显式接入批准的内建提供者。该子包本身不会建立 KMS、对象存储或网络连接。

根包 `internal/diagnostics` 里保留的 `CiphertextEnvelope`/`KeyWrapper`/`SealEnvelope` 只作为旧兼容 API，不与子包共享 wire format、AAD 或错误 sentinel，禁止把两种对象互传。需要迁移旧对象时必须增加带版本标记和测试的显式 legacy adapter，不能仅依赖同名结构体转换。

每次 `envelope.Seal` 都使用密码学安全随机数生成独立的 32 字节 DEK，并用 AES-256-GCM 加密一个诊断包。DEK 只交给 `KeyProvider.Wrap` 以指定的 KEK 代次包装；`Envelope` 还包含随机 envelope identity，序列化对象只包含 schema、算法、identity、KEK 代次、包装后的 DEK、随机 nonce、密文和元数据，不包含明文。空包装结果、错误代次、重复 key version 和错误长度都会失败。

认证附加数据（AAD）绑定信封身份、Schema、算法、`tenant_id`、`plugin_id`、`plugin_version`、`target`、明文 SHA-256 摘要和 `policy_epoch`，并使用长度前缀编码避免字段拼接歧义。解封时先验证 Schema、算法、字段和摘要格式，再由 KMS 解包 DEK，最后通过 GCM 标签和重新计算的 SHA-256 摘要验证内容；元数据、密文、nonce 或摘要任一处被篡改都会拒绝。`envelope.Verify` 只返回错误，不向调用者暴露明文。

普通 KEK 轮换由 `envelope.Rewrap` 支持：先验证旧包，再只重新包装同一个 DEK，返回带新 `key_version` 的新对象。原对象的密文、nonce 和 identity 不变，旧对象保持可解封，便于异步、可暂停的延迟重包装和灾备保留。key version 是不可复用的密钥身份；本地提供者拒绝覆盖已有代次，重包装到当前代次也会失败。包装/解包失败通过可判定错误返回，集成层必须保留本地加密包并异步重试，不能阻塞 WAF 请求线程。

队列的 `EnqueueEncrypted` 入口只保存 opaque bytes，不验证 bytes 是否为合法 envelope；需要强格式、AAD 和 digest 校验的路径必须经过 `integration.Runtime` 的 seal/decode/verify 链路。`ReplayGuard` 是可选的消费屏障。支持 `TransactionalReplayGuard` 的实现按“认证后 `Reserve`、上传失败 `Release`、上传成功 `Commit`”提供并发重复抑制和失败可重试语义；篡改或认证失败发生在 `Reserve` 之前，不消费身份。仅实现旧 `CheckAndMark` 的 guard 只能在上传成功后标记，不能阻止并发上传，适配器必须按 `UploadID` 或对象摘要幂等。未注入 guard 时，队列提供 at-least-once 语义，适配器同样必须幂等。

外部上传成功后，如果 replay `Commit` 或旧 guard 标记失败，运行时不会自动重复已经发生的外部副作用；它会记录 `replay_commit` 失败审计，交给运维显式核对。队列 worker 若无法把成功或失败结果持久化，会写入 `WorkerError` 并停止继续取任务，避免在完成状态不确定时静默运行。进程级 replay guard、worker 停止和本地队列仍不等于跨进程 exactly-once；生产目标端必须保留幂等键和可查询回执。
