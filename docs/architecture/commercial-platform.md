# CheeseWAF 商业化平台架构基线

状态：实施基线
版本：2026-09-05
对应规划：[2026-09-05-commercial-grilling-plan.md](../superpowers/plans/2026-09-05-commercial-grilling-plan.md)

## 目的与边界

本文把本次 1–133 项 grilling 结果转换成实现时必须遵守的架构边界。它是代码、API、配置、部署脚本、CRP、插件开发手册和运维手册的共同来源之一。实现完成前，任何与本文冲突的代码或文档都必须先修正文档或记录例外。

数据平面的首要目标是持续转发已配置的业务流量。控制面、插件、外部 KMS、PG、Redis、对象存储、透明日志、SIEM 和 LLM 的故障不得把可恢复的管理面问题扩散成 WAF 全局故障。安全完整性门禁仍然严格：签名、摘要、命名空间、版本、防降级、吊销和权限范围不能因为可用性目标而被绕过。

## 平面和组件

阶段 1 的可执行状态定义见 [control-plane-prfaq.md](control-plane-prfaq.md) 与 [control-plane-contract.md](control-plane-contract.md)。这两份文档和 `internal/controlplane` 只定义可验证边界；在 native-raft/PG 适配器接入前，不得把它们描述为已替换现有 etcd/SQLite 运行路径。

当前配置以 `storage.profile: temporary` 为默认；`production` profile 必须显式
提供独立的 `storage.management_postgresql.dsn`，并在控制面 PostgreSQL、
Coordinator 与 native-raft 的 cluster/epoch backend 全部就绪前 fail-closed，
不得静默回退 SQLite。`storage.postgresql` 仍只用于异步访问日志 sink。

```text
业务请求 → WAF 数据面 / reverse proxy
              │ 100ms 有界检测、快照、last-known-good
              ├── async hint/telemetry → cheesewaf-control
              │                         ├── PG：持久管理真相
              │                         ├── native-raft：期望状态/epoch/fencing
              │                         └── Redis：租约/锁/缓存/短期状态
              └── sidecar 插件 → broker → 加密队列 → 外部目标/企业对象存储
```

### 数据面

- 请求线程只执行有界、确定性的检测和策略快照读取。
- 插件使用 sidecar、异步 observe、snapshot 和 hint；不得在请求线程等待插件 I/O、PG、Redis、KMS、LLM 或外部网络。
- `Availability Guard` 只允许降低概率性 block/challenge/rate 动作；协议、安全底线、管理员硬规则和核心控制不能被弱化。
- 检测器、LLM、审计 sink 或响应检查器故障时，按站点/路由策略进入 observe/pass 并标记 `inspection_incomplete`；现有 last-known-good 继续生效。

### 控制面

`cheesewaf-control` 拥有最终授权提交权。审批 sidecar 可以提供可视化 DAG、连接器、通知和计时，但只能提交带版本、摘要、epoch、scope、nonce 和 TTL 的提案。PG 保存持久管理真相，native-raft 保存成员、任期、epoch、fencing、期望配置和回滚引用。

### 身份与角色边界

管理员、操作者、租户和服务账号的身份字段必须按原始值精确校验。用户名沿用统一规范：3–32 个 ASCII 字符，以 ASCII 字母开头、以 ASCII 字母或数字结尾，只允许 ASCII 字母、数字、点号、下划线和连字符。用户名和身份标识一律拒绝首尾或嵌入的 Unicode 空白、控制字符（Cc）及格式/不可见字符（Cf）；服务端不得使用 TrimSpace、大小写转换或其他静默归一化。

用户的 role 必须精确匹配当前 apisec.permissions 中的已配置角色键（默认包括 admin 与 readonly），不得把星号或冒号权限表达式当作角色。空值、未知角色、包含首尾或嵌入 Unicode 空白、控制字符或 Cf 的角色都必须拒绝；Web 可以提示重新输入，API/CLI 应返回明确错误。历史数据库中的脏用户名不会由普通更新或重新初始化隐式修复，必须先按不可变用户 ID 执行 cheesewaf user repair-username USER_ID NEW_USERNAME --reason '...'；该命令保留凭据、角色和 TOTP 状态，并在同一事务中撤销 Session 与写入追加审计。

### 存储

- PG：用户、Session、Token 元数据、审批、审计、队列元数据、CRP 状态和恢复索引。
- Redis：短期锁、租约、缓存、黑名单加速和通知；故障按操作定义有限回退，不承载唯一持久真相。
- SQLite：临时模式和兼容路径；生产模式不得静默回退 SQLite。
- DuckDB：可选 sidecar/CLI，仅读取 Parquet 做跨集群分析和审计，不进入热路径。

## 插件和 CRP 信任链

官方使用 CheeseSec Vendor Root、离线根和多发布密钥；普通 CRP 为 2-of-3，高风险 CRP 为 3-of-5。企业使用独立根，但被限制在 `enterprise/<org-id>/*` 命名空间。社区、个人、测试和开发根默认不可信。

CRP 导入顺序固定为：格式/大小 → MD5/SHA1/SHA256 → 签名链与阈值 → 命名空间/来源根/发布者 → 防降级和吊销 → 可选时间/透明日志/SBOM 证据 → 能力和网络预检 → observe/staged/Canary/promotion。缺少可选证据必须告警、等待 10 秒、二次确认并审计，不能绕过硬门禁。

传输源、签名者和发布者分开验证。Peer、镜像、OTA 和 Ansible 不能改变 manifest、签名、来源根或 promotion 状态。重打包必须生成新 artifact、摘要、发布者和 provenance。

## 离线和临时联网

离线模式是显式、可持久化、可审计的设置。开启后默认禁止管理面、插件和后台任务外部出站；业务数据面到已配置 Origin 的反向代理连接不受影响。插件默认 `egress=deny`，只允许登记的内部逻辑资源。

插件可以通过控制面申请临时 Socket Lease。租约绑定插件、版本、目标资源、协议、端口、TLS 指纹、策略 epoch 和短 TTL。申请需要管理员密码确认并记录目标、字节数、租约和结果；离线模式下不存在后台自动联网。

## 诊断上传和加密

插件只能调用结构化 `upload_diagnostic` API。broker 负责固定 Schema、数据源、脱敏/扫描、配额、幂等、临时租约和审计。上传统一进入有界加密异步队列，返回 `upload_id`，不阻塞插件或 WAF。

默认上传元数据、健康状态和脱敏诊断。扫描失败时可按 77B 经过高风险告警、10 秒等待、密码和第三次确认上传固定 Schema 的原始诊断字段；凭据、Token、密钥、管理员 Session、Origin 认证和原始请求正文永远不能进入诊断包。

每个包采用应用侧信封加密：独立 DEK 加密包，KEK 包装 DEK，AAD 绑定租户、插件、版本、目标、摘要和策略代次。对象存储只保存密文。普通 KEK 轮换异步延迟重包装；泄露或滥用时按密钥代次、租户和插件最小范围紧急吊销。

## 审批、Token 和恢复

- 高风险操作由核心 `ApprovalGate` 最终提交；workflowd 只能提案。
- Break-glass 由安全管理员或租户最高管理员启用，使用受限会话级授权；原始诊断最长 30 分钟、空闲 5 分钟失效。
- Token 按能力和资源拆分，权限快照带 epoch；默认 90 天，最长 365 天，180 天无活动自动销毁；永不过期必须二次确认。
- Web 恢复文件一次性交付；CLI/Ansible 只导出本地临时文件。恢复先在隔离环境校验，再切换生产对象。
- 恢复后默认撤销临时 Session、恢复/Join/Break-glass Token，长期 Token 按管理员策略轮换。

## 失败模式不变量

- 管理面故障不能阻塞已建立的数据面转发。
- 无法验证 CRP 完整性、签名、命名空间或防降级条件时不得安装或晋级。
- 队列、对象存储、SIEM、透明日志、KMS 或 LLM 故障只改变对应管理任务状态，不静默扩大权限。
- 所有外部上传、确认、租约、重试、回执、删除、吊销和恢复都可查询并进入哈希链审计。
- 企业策略只能收紧平台硬上限，不能扩大网络、留存、重试、租约、权限或确认范围。

## 实施顺序

1. 状态模型、epoch/fencing、manifest、签名和审计事件。
2. 离线、网络租约、broker、队列、信封加密和对象复制。
3. 商店、OTA、CWEDP 和插件开发标准。
4. 中英文 README、线上手册、迁移说明和部署手册。
5. 单节点、集群、断网、临时联网、轮换、吊销、恢复和生产构建验收。

完成标准以命令输出、状态转移、审计记录和产物扫描为证据；不能只以文档存在或代码编译通过作为完成依据。
