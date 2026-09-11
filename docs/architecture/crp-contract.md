# CheeseWAF Resource Package Contract

状态：阶段 2 manifest、签名信任和离线导入准入 contract；本地 `RuntimeStore`、activation/rollback service、mTLS transport/server TLS 与 CLI 入口已实现并有测试；生产 control-plane provider、持久授权/审计、sidecar launcher、集群分发和插件执行仍待接入
版本：`crp.cheesewaf.io/v1`

CRP 是离线扩展、OTA 和 CWEDP 分发共同使用的内容寻址包格式。`internal/crp` 只负责确定性校验，不建立网络连接，也不授予插件运行权限。

## Manifest 门禁

Manifest 使用严格 JSON：拒绝未知字段和尾随 JSON 值。必须包含 `name` 或 `plugin_id`、SemVer `version`、合法 `namespace`、`source_root`、发布序号和 artifact 摘要。artifact 可以使用顶层 `digests` 兼容字段，但两处同时存在时必须完全一致。

CRP 必须携带同一 artifact 的 MD5、SHA-1、SHA-256：MD5/SHA-1 仅用于断点续传和传输完整性，SHA-256 是内容身份。摘要不匹配、缺摘要、大小不符都必须拒绝，不能由管理员强制绕过。

## 命名空间和来源

- 官方：`official/<plugin>`，只能绑定 CheeseSec Vendor Root。
- 企业：`enterprise/<org-id>/<plugin>`，只能绑定该企业登记的独立根。
- 社区/个人/测试/开发：`<class>/<publisher>/<plugin>`，来源根独立，默认需要管理员确认，不直接授予高权限。

命名空间、来源根、签名者和传输来源必须分开验证。Peer、镜像、OTA 和 Ansible 不能修改 manifest、签名或 promotion 状态。

控制面加载不可变 `SourceRegistry` 快照：每个 root ID 必须绑定至少一个 namespace prefix 和显式 source allowlist（例如 `ota`、`peer`、`offline`）。导入时先验证 manifest 的 root、namespace 和 source 同时命中同一注册项；未知 root、未登记 source、跨 namespace 复用或空 allowlist 都是硬失败。URL 不是信任根，换一个下载地址不能改变 root 的授权范围。

## 防降级

导入上下文同时比较 SemVer 和 `release_sequence`。候选版本或序号低于当前已安装版本时拒绝；候选缺少序号也不能覆盖已有序号。SemVer prerelease 按数值/字典规则比较，build metadata 不影响优先级。回滚不是重放旧包，而是由控制面批准的新 revision，并携带新的 fencing/审计信息。

## 签名信任 contract

`internal/crp/signatures.go` 提供无网络副作用的 Ed25519 验签层：

- 官方根默认普通操作 2-of-3，严重操作 3-of-5；高风险策略在根完成轮换补齐五把 key 前保持不可用。
- 企业根独立于官方根，可在平台最低值之上自定义阈值；普通发布至少 2-of-3，严重操作至少 3-of-5。社区、个人、测试、开发根默认单签但需要管理员确认，不直接授予高权限。
- 未知 key、吊销 key、过期 key、错误算法、错误签名和未满足阈值均拒绝。
- 不可信根/签名返回 `needs_confirmation`；必须显式传入 `AllowConfirmation` 才能继续，调用方应在 UI/CLI 完成密码和三次确认等更高层门禁。
- `Rotate` 和 `Revoke` 返回新的不可变 `TrustStore`，旧快照不变；吊销从指定时间起生效。
- 每个签名覆盖带域分离前缀的确定性 JSON，其中同时包含 manifest、KeyID、算法和 SignedAt；篡改任一字段都会使签名失效。官方和企业密钥默认最长 3 年，社区/个人/测试/开发分别为 1 年、1 年、30 天和 7 天。`ContentIdentity` 可用于透明日志索引。

上述 API 只证明信任、签名和离线准入。`internal/crp.RuntimeStore` 已提供本地、无网络的
暂存、晋级、回滚和重启恢复状态层：它保存 manifest identity 与 artifact SHA-256 两种身份，
使用单调 revision 和 CAS，健康检查或授权失败不会改变当前版本，回滚也会生成新 revision。
运行时会要求由 `Import` 生成的不透明准入结果、健康检查、当前信任快照复核和高风险授权；
它不会启动插件、建立网络连接或改变 WAF 请求线程。

准入结果把包指纹、签名报告指纹、阈值和“是否需要确认”保存在不可导出的 admission 中。
调用方可以读取展示用的签名报告，但不能篡改报告后降低确认门槛。Stage 在调用外部复核器前
释放进程内锁，复核完成后再用 revision 做 CAS；复核器可以读取同一状态层，不会造成自锁。
本地根目录和受管目录会被收紧为仅属主可访问，state、artifact 和 metadata 文件要求属主专用
权限；重启时会重新核对路径、slot、manifest 字段、内容身份和 artifact 摘要。
每次写入提交还会在运行目录的永久 `.runtime.lock` 哨兵文件上取得非阻塞的进程间独占
lease：Unix-like 使用 `flock`，Windows 使用 `LockFileEx`；竞争时立即返回
`ErrRuntimeBusy`，不会等待，也不会触及 WAF 数据面。提交窗口内会重新读取并校验磁盘快照，
再按 revision 做 CAS，因此不同进程不会以各自陈旧内存快照覆盖彼此的插件状态。锁文件本身
不得删除、替换或纳入普通垃圾回收；进程崩溃时由操作系统释放句柄锁，重启不依赖 PID 或
按时间清理的脆弱“陈旧锁”判断。

`state.json` 先写入属主专用临时文件、同步文件内容，再做同目录原子替换并同步父目录；
Windows 使用带替换和写穿语义的 `MoveFileEx` 适配器。artifact 和 metadata 是内容寻址的
追加式对象，当前没有自动 GC，以避免在状态提交和复核并发时误删仍可达内容。未来若要回收，
必须停止该运行目录的写入、持有同一 runtime lease、按已提交快照计算可达集并可审计恢复；
不能把跨节点或网络文件系统上的 advisory lock 当作集群 fencing。

`cheesewaf crp stage` 要求显式提供本地包、信任根、来源注册表、校验时间和运行目录。它只写
staged 槽位，不执行 promotion。当前 CLI 不提供绕过确认的参数；需要管理员确认的签名类别会
被拒绝，直到密码、10 秒等待、第三次确认和耐久审计接入控制面。

该状态层仍不是完整安装系统。透明日志、吊销快照持久化、PG/控制面状态、CWEDP 分发、
商店、OTA、sidecar 启动和跨节点 promotion 尚未接入；生产环境必须由控制面
提供授权、持久状态和集群 fencing 适配器。
Unix-like 主机在 artifact、metadata 和 state 原子替换后同步父目录；Windows 当前保留平台
适配器边界，仍需在生产验收中验证底层文件系统的持久化语义。

`internal/crp.Import` 已提供无文件、无网络的离线准入：它限制 manifest 和 artifact
大小，串联 manifest、来源注册表、版本防降级、三摘要和签名阈值校验，并返回内容
身份。它不会写入插件目录、激活进程或改变运行中的策略。

`internal/crp.ParseArchive` 可把 `.crp` ZIP 归档解析为上述内存包。归档只能包含
`manifest.json`、一个 `artifact/<file>` 和 `signatures/manifest.json`；解析器拒绝
未知条目、重复路径、路径穿越、符号链接、超出文件数/未压缩大小限制的条目，并在
读取时再次限制大小。解析后仍必须调用 `Import`，归档解析本身不等于签名通过或安装成功。

## CRP 归档布局

`ParseArchive` 接收 `.crp` ZIP 字节并只在内存中生成 `crp.Package`。当前严格布局为：

`manifest.json`、`artifact/<exactly-one-file>`、`signatures/manifest.json`。

解析器拒绝未知路径、重复 entry、路径穿越（反斜杠、绝对路径和盘符）、目录、符号链接及非
regular entry。它在打开 entry 前按 ZIP 声明的未压缩大小检查文件数、总解压字节和各文件上限，
读取时再次使用有界 reader 防止声明不实；缺少必需文件、多个 artifact、manifest 的 artifact
大小与实际字节数不一致、签名 JSON 有未知字段或尾随数据时均拒绝。函数不写文件、不联网、
不执行 artifact，也不激活插件；签名阈值、来源绑定、摘要和版本防降级仍由 `Import` 完成。
