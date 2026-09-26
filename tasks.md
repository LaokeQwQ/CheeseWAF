# CheeseWAF 实施交接记录

计划来源：[商业化 grilling 全流程](docs/superpowers/plans/2026-09-05-commercial-grilling-plan.md)
架构基线：[commercial-platform.md](docs/architecture/commercial-platform.md)
目标线程：商业化架构分阶段实施

## 交接规则

- 每完成一个阶段，先更新本文件，再运行该阶段的验证命令。
- 记录必须包含：时间、操作者、范围、实际改动、验证命令、完整结果、遗留风险、下一步。
- 未运行验证命令不得写“完成”“通过”或“已修复”；只能写进行中或阻塞及证据。
- 不覆盖其他工作者已有改动；不把运行数据、凭据、截图和临时验收产物写入源码树。
- 外部 CheeseSec 仓库的文档同步必须保留各自 AGENTS.md 和 Git 状态边界。

## 阶段看板

| 阶段 | 范围 | 状态 | 证据 |
|---|---|---|---|
| 0 | 计划、约束、架构和交接基线 | 已完成 | 2026-09-05 文档构建、diff 检查和编号检查通过 |
| 1 | 控制面状态、epoch/fencing、PG/Redis 边界 | 主 serve production 组合、PG cutover/recovery 和 Session 失效的本地真实集成探针通过；多节点部署交接仍待做 | `internal/controlplane`、PG/Redis/native-raft contract 通过；`--full` 运行 PG recovery/cutover 分类及真实 production `runServe` login/session invalidation。GitHub Actions 集成 job 已配置，远端 CI 尚待提交后验证；多节点成员/证书交接仍待做 |
| 2 | CRP manifest、签名根、阈值、轮换和吊销 | production `runServe` 的 CRP activation 与精确 rollback 本地真实集成探针通过；云端部署验收仍待做 | `internal/crp` manifest + Ed25519、阈值/轮换/吊销、严格导入及 observe→canary→active/精确回滚测试通过；真实 route 使用 PostgreSQL approval/audit 和 mTLS control-plane/sidecar。远端 CI 与云端多节点部署仍待验证 |
| 3 | CWEDP 分发、离线模式、网络租约 | 主 serve 的 session-bound provider、CWEDP/CRP runtime、PG ResumeStore、mTLS sidecar 和公网 route 已有真实验收；插件安装、节点注册和多节点长期部署仍待做 | `internal/cwedp` 及 `internal/cwedp/postgres` 覆盖协商、不可变 SourceRegistry、来源独立性、隔离源、分块续传、三摘要、切换上限、总包/单块字节预算、幂等和 offset fencing；`internal/cwedp/transport`、`internal/netlease` 与真实 `runServe` route 通过 HTTPS、CA/client cert/NodeID/leaf pin、Range、pre-dial fail-closed、Session/lease 清理和公网 mTLS peer 验收 |
| 4 | broker、诊断队列、信封加密、对象复制 | broker、canonical envelope、持久队列、组合 runtime 和 diagnostics PG metadata 已验证 / 对象复制与外部回执待做 | `internal/diagnostics` 覆盖固定 Schema、raw 三重确认、AES-GCM/AAD、不可复用 KEK 代次、持久队列、replay reserve/commit/release、worker 完成错误可观察、metadata-only 审计，以及真实 PG Cancel/claim/outbox 往返；对象存储复制、目标回执和完整启动接线仍待做 |
| 5 | 审批、Token、恢复和审计状态机 | ApprovalGate、Token、迁移恢复与 PG 持久适配器已有证据 / 生产服务生命周期待做 | `internal/approval` 已覆盖批次原子持久化、事件 hash/binding、durable epoch CAS 和 epoch+record+events 一致恢复快照；`internal/tokens`、`internal/tokens/postgres`、`internal/cli/migration` 覆盖 180 天清理、Token 重放、通知、v1/v2 recovery 和真实 PG 往返；真实 credential verifier、生产审计 outbox 和主服务挂载仍待做 |
| 6 | 插件商店、OTA、开发规范和双语手册 | 边缘路由、契约和 OTA 只读检查已实现 / 线上资源待配置 | Pages Worker、R2 键映射、Origin HMAC、Tunnel 配置、OTA 客户端和只读状态接口已有本地证据；Cloudflare 账号、R2 桶、域名、Access ACL、Tunnel 和 CRP/CWEDP 激活仍未完成 |
| 7 | 全量验收、生产构建和空网演练 | 公网测试节点完整验收矩阵通过；稳定发布、远端 CI/CodeQL、Cloudflare 生产资源和空网演练仍待做 | 公网节点 `matrix.py --full` 为 23 passed、0 failed、0 skipped；Pages/Web/OTA/Ansible 和产物门禁已有分项证据；稳定发布与线上空网演练仍需在最终提交后执行 |

## 2026-09-05 当前交接

### 已做

- 建立了 1–133 全流程规划文档，包含完整决策表和实施顺序。
- 新增商业化架构基线，明确数据面/控制面、PG/Redis/native-raft、插件 sidecar、CRP 信任链、离线联网、诊断上传和失败不变量。
- 新增本 `tasks.md`，定义按阶段交接和“证据先于完成声明”的记录格式。
- 已读取 CheeseWAF、CheeseSec_Docs、CheeseSec_pages、CheeseWAF-Adapters 的 AGENTS.md 约束。

### 本次实际改动

- 新增 `docs/architecture/commercial-platform.md`。
- 新增 `tasks.md`。
- 新增 CheeseSec_Docs 中英文商业化架构页。
- 更新 CheeseSec_pages 中英文 README 的产品手册、商店/OTA 和架构来源说明。
- 更新 CheeseWAF-Adapters `.project/current-progress.md` 的跨仓库架构交接说明。
- 放开根仓库对 `tasks.md`、商业化架构和 grilling plan 的精确 Markdown 白名单，保证交接文档可版本化。

### 尚未声称完成的项目

- 尚未实现控制面、CRP、离线联网、诊断队列或密钥轮换代码。
- 尚未完成外部文档构建和完整 Get Started 验收。
- 尚未完成生产产物扫描和空网演练。

### 阶段 0 验证证据

- `hugo --gc --minify`（`/Users/laoke/Dev/CheeseSec_Docs`）：退出码 0，EN 106 页、ZH 104 页构建完成。
- `npm run typecheck && npm run build`（`/Users/laoke/Dev/CheeseSec_pages`）：退出码 0，TypeScript 检查和 Astro 静态构建完成。
- `git diff --check`：CheeseWAF、CheeseSec_Docs、CheeseSec_pages、CheeseWAF-Adapters 均无格式错误。
- grilling plan 编号检查：1–133 共 133 行，编号无缺失、无重复。
- 本阶段没有运行时功能实现，因此不能据此声称控制面、CRP、离线联网或诊断上传已经可用。

### 下一步

1. 阶段 2 先实现 CRP manifest 完整性、命名空间、来源根和防降级基础。
2. 控制面运行时接线另列任务，不能由 contract 测试替代。
3. 每个阶段先更新本文件，再按阶段运行 Go 测试、静态检查和状态机验证。

### 2026-09-05 交接续做

范围：全量回归、入口文档口径收口、插件商店/开发手册骨架。

实际改动：

- 重新运行完整 `go test ./...`；CRP 最新 SemVer 修改未影响其他包。
- 修正 `CheeseSec_pages` 中英文首页，将“纯 Go + SQLite”改为临时 SQLite / 生产 PostgreSQL 控制面的准确描述。
- 新建 `/Users/laoke/Dev/CheeseSec_Plugin` 与 `/Users/laoke/Dev/CheeseSec_Plugin_Docs` 的最小商店与 CRP 开发手册骨架，明确 `store.cheesesec.com`、`ota.cheesesec.com`、`res.cheesesec.com`、`.crp`、CWEDP、签名根和生产依赖边界。

验证命令：

- `go test ./...`：退出码 0；语义引擎约 304 秒，其余包通过。
- `git diff --check`：根仓库通过。
- `npm run typecheck && npm run build`（CheeseSec_pages）：退出码 0，7 个静态页面构建完成。
- `hugo --gc --minify`（CheeseSec_Docs）：退出码 0，EN 106 / ZH 104 页构建完成。

遗留风险：签名链、阈值、吊销、CRP 导入运行时、CWEDP、PG/Redis/native-raft 接线仍未完成；`CheeseSec_Plugin` 与 `CheeseSec_Plugin_Docs` 已初始化为独立 Git 仓库，当前仍只有文档骨架。

下一步：收集并验证文档构建结果；完成 `internal/crp` 签名根/阈值/吊销 contract；再进入运行时导入和分发协议。

### 2026-09-05 阶段 1（进行中）

范围：控制面状态模型、期望配置提交、epoch/fencing 以及 PG/Redis/native-raft 接口边界。

实际改动：已开始新增 `internal/controlplane`，先提供纯 Go、无网络副作用的状态机和存储接口；同步补充客户视角 PR/FAQ 与阶段 1 contract 文档。当前不会替换现有 `builtin/etcd` 运行路径，也不会把接口存在误报为后端已接入。

验证命令：已运行 `gofmt -w internal/controlplane/state.go internal/controlplane/state_test.go`、`go test ./internal/controlplane ./internal/cluster/...`、`go test ./...`、`hugo --gc --minify`（CheeseSec_Docs）、`git diff --check`。

验证结果：状态机与全部集群子包测试通过；全量 `go test ./...` 退出码 0（语义引擎包约 310 秒）；Hugo 退出码 0，EN 106 / ZH 104 页；CheeseWAF、CheeseSec_Docs、CheeseSec_pages、CheeseWAF-Adapters 的 `git diff --check` 均通过。阶段 1 仍进行中，尚无生产运行时接入证据。

遗留风险：现有生产路径仍使用 SQLite 管理主存储和 builtin/etcd 兼容实现；native-raft、PG 管理真相、Redis 租约尚未接入运行时。

下一步：进入阶段 2，先实现 CRP manifest 完整性、命名空间和防降级基础；控制面运行时接线另列任务，不能由 contract 测试替代。

### 2026-09-05 阶段 2（进行中）

范围：CRP manifest 的固定 schema、MD5/SHA1/SHA256 传输完整性、namespace/source 绑定和版本/发布序号防降级。

实际改动：新增 `internal/crp/manifest.go` 与测试，定义 CheeseWAF Resource Package manifest；拒绝未知/尾随 JSON、缺失或大写摘要、非法 namespace/source、摘要不匹配、artifact 大小不符和版本/序号降级。新增不可变 `SourceRegistry`，将 root ID、namespace prefix 和 source allowlist 绑定，拒绝未知 root、跨 namespace 和未登记来源。MD5/SHA1 仅作为传输完整性校验，SHA256 作为内容身份；尚未实现签名、阈值、透明日志或网络分发。SemVer 比较按 prerelease 数值/字典规则处理，忽略 build metadata。

验证命令：已运行 `gofmt -w internal/crp/*.go`、`go test ./internal/crp -count=1`、`go test ./internal/crp -race -count=1`、`go vet ./internal/crp`、`git diff --check`。

验证结果：上述命令均退出码 0；CRP manifest、SourceRegistry、摘要、namespace/source 绑定和 SemVer 防降级 contract 测试通过。阶段 2 仍进行中。

遗留风险：`SourceRegistry`、官方/企业独立签名根、2-of-3/3-of-5 阈值、密钥轮换/吊销和 CRP 导入运行时尚未实现；不能据此宣称插件安装或 OTA 已可用。

下一步：补充来源根注册表与 namespace 绑定，再实现签名阈值 contract；完成后单独验证，不能把 manifest 校验替代签名验证。

### 2026-09-05 阶段 2 签名 contract

范围：Ed25519 签名、官方/企业来源根、阈值、有效期、轮换和吊销。

实际改动：新增 `internal/crp/signatures.go` 与测试。签名使用域分离的
签名覆盖 manifest、KeyID、算法和 SignedAt 的确定性封装；官方和企业默认
普通 2-of-3、严重操作 3-of-5；企业根独立且不能降低平台下限；社区/个人/
测试/开发默认有效期分别为 1 年、1 年、30 天和 7 天，并要求管理员确认；
支持不可变轮换和吊销快照。

验证命令：`go test ./internal/crp -race -count=1`、`go vet ./internal/crp`、
`git diff --check`。结果：均退出码 0。

遗留风险：仍未接入 CRP 导入、透明日志持久化、管理员三次确认编排或
商店/OTA；验签 API 本身不授予插件运行权限。

### 2026-09-05 阶段 3 CWEDP contract

范围：DistributionIntent、HELLO/CAPABILITIES、离线来源选择、来源类型
独立性、连续分块断点续传、三摘要校验和失败次数上限。

实际改动：新增 `internal/cwedp/protocol.go` 与测试；补充不可变
`SourceRegistry`，按已登记来源 ID、供应链根和独立性分组判断来源，不信任
intent 自报根；拒绝未知类型、缺根、未登记来源和同组镜像重复计数；同时
补充整数溢出防护、严格小写十六进制摘要校验；新增
`docs/architecture/cwedp-contract.md`。

验证命令：`gofmt -w internal/cwedp/*.go`、`go test ./internal/cwedp -race -count=1`、
`go vet ./internal/cwedp`、`git diff --check`。结果：均退出码 0。

遗留风险：协议尚未接入网络/文件/节点运行时、来源根注册表、Socket
Lease、离线设置、CRP 安装或 OTA。

下一步：审查 CWEDP 来源独立性字段设计，随后实现离线策略和 Socket Lease
contract；再接入导入服务前先补持久化与审计事件模型。

## 后续交接模板

### 2026-09-13 Cloudflare Pages/Workers 分流接线

范围：把适合边缘读取的商店、OTA、策略、schema 和内容寻址资源留在 Cloudflare，把控制台、管理 API、认证、审批、CRP/CWEDP、诊断、SSE 和 WebSocket 固定回源到 CheeseWAF loopback 管理端口。

实际改动：

- `CheeseSec_pages` 增加 Host/路径白名单、R2 发布物读取、Range 响应、ETag、缓存策略、固定 Origin 回源和 HMAC 信封；构建使用 `npm ci --ignore-scripts`，并增加产物边界检查。提交 `e238bf0`，已推送到 Pages PR #2。
- `CheeseSec_Plugin` 和 `CheeseSec_Plugin_Docs` 增加固定路径、缓存类别、R2 来源角色和中英文边缘路由契约。Plugin PR #8、Plugin_Docs PR #9 已推送。
- CheeseWAF 增加 `VerifyEdgeOrigin`、写请求 ID 重放保护、可选 Cloudflare Access 身份校验、OTA 严格只读客户端、last-known-good 文件存储、`GET /api/system/ota` 和只读候选版本展示。提交 `af6816fd`，已推送到 PR #444 的 `dev` 目标。
- `CheeseSec_Plugin` 增加确定性 `build_publication_bundle.py` 和默认只读的 `publish_r2.sh`。只有显式 `--apply` 才会写 R2，序号回退直接拒绝。
- Ansible 增加 origin-admin Tunnel 模板、systemd 单元、外部凭据文件检查和回滚说明。管理端口仍为 `127.0.0.1:9443`，`admin_public` 保持 `false`。

验证命令与结果：

- `CheeseSec_pages`: `npm ci --ignore-scripts`、`npm run typecheck`、`npm test`（51 项）、`npm run build`、`npm run check:artifacts`、`npx wrangler deploy --dry-run` 均通过。
- `CheeseSec_Plugin`: `validate_repo.py`、`validate_commercial_contracts.py`、18 项测试和脚本语法检查通过。
- `CheeseSec_Plugin_Docs`: `validate_docs.py`、`validate_commercial_contracts.py` 和 2 项测试通过。
- CheeseWAF: `go test ./internal/ota -race`、API/CLI/中间件回归、`go vet` 和 `deploy/ansible/verify-offline.sh` 通过；`go test ./...` 的一次 native-raft 选主超时在同一环境连续 3 次单测重跑通过，需在 CI 再观察。
- Cloudflare `wrangler whoami` 返回未登录，因此没有执行生产部署；dry-run 只证明配置可解析，不证明 R2、域名、Access 或 Tunnel 已存在。

遗留风险：Cloudflare 生产账号和资源尚未提供；Worker Secret、Tunnel 凭据、Origin HMAC 和 Access ACL 不能写入 Git；OTA 目前只读，CRP 验签后的 CWEDP staging、审批、激活和回滚还没有接入主服务。临时测试服务器也没有经过该域名和 Tunnel 的端到端验收，因此不能给出线上预览地址。

下一步：先在 Cloudflare 创建 staging R2 桶和自定义域名，注入最小权限 Secret，使用空索引做 `GET`、`HEAD`、`Range`、`404`、`405`、`421` 和回源 HMAC 验收；再在测试服务器启用 Tunnel，验证 `/health/ready`、登录、CSRF、SSE 和 WebSocket，最后才评估生产切换。

### 2026-09-05 阶段 3 网络策略与 Socket Lease contract

范围：离线默认拒绝插件外部出站、内部资源精确白名单、一次性临时联网租约。

实际改动：新增 internal/netlease 纯 Go contract。OfflinePolicy 对未登记目标默认拒绝，对已登记主机的端口/协议偏差返回范围错误；Manager 的 Lease 绑定插件 ID/版本、目标、协议/端口、TLS 指纹、策略 epoch、管理员确认 ID 和 TTL，支持过期、撤销、精确范围校验与内存审计事件。新增 docs/architecture/netlease-contract.md，明确无网络副作用和运行时接入边界。

验证命令：go test ./internal/netlease -race -count=1；go vet ./internal/netlease；git diff --check。

验证结果：三项命令均退出码 0；覆盖默认拒绝、内部白名单、范围偏差、过期、撤销、插件/版本/epoch/TLS 绑定和审计行为。

遗留风险：尚未接入实际 broker、主机网络防火墙、DNS/IP 校验、TLS 握手 pinning、持久化审计或控制面策略 epoch；contract 测试不等于生产网络隔离已启用。

下一步：在诊断 broker 与 CWEDP 运行时接入前，复用该 contract，并补充系统级无外连验收和离线临时联网的管理员密码确认链路。

### 2026-09-05 文档现状复核

范围：根 README、CheeseSec_Docs、CheeseSec_pages 的运行时事实与商业化规划表述。

实际改动：按源码核对并修正 SQLite、PostgreSQL、Redis、builtin/etcd、
controlplane、CRP、CWEDP、Socket Lease 的现状说明；补充 `CheeseSec_Plugin`
与 `CheeseSec_Plugin_Docs` 独立仓库的 README、AGENTS 和中英文 CRP 手册。

验证命令：CheeseSec_Docs 使用临时目标运行 `hugo --destination <tmp> --cleanDestinationDir`；
CheeseSec_pages 运行 `npm run typecheck && npm run build`；三个仓库分别运行
`git diff --check`。结果：Hugo EN 106 / ZH 104 页、网站 7 页均构建成功，
三个 diff 检查均退出码 0。

遗留风险：手册已说明“契约不等于运行时”，但 CRP 商店、OTA、CWEDP 下载器、
插件安装和热载仍未实现；独立插件仓库尚未提交初始版本。

### 2026-09-05 阶段 2/3 安全复核补强

范围：签名元数据完整性、企业阈值下限、快照不可变性、CWEDP 分块边界和 Socket Lease TTL。

实际改动：签名现在把 `KeyID`、算法和 `SignedAt` 一起纳入域分离签名；拒绝未来或篡改时间戳、弱于平台最低值的企业阈值、重复公钥和超长密钥有效期；轮换/吊销返回深拷贝快照，旧快照不受吊销影响。CWEDP 拒绝大写摘要和整数溢出分块；Socket Lease 将 TTL 限制为 10 分钟。

验证命令：`go test ./internal/crp -race -count=1`、`go vet ./internal/crp`、`go test ./internal/cwedp -race -count=1`、`go test ./internal/netlease -race -count=1`、`go vet ./internal/netlease`、`git diff --check`。

验证结果：上述命令均退出码 0。

遗留风险：这些仍是纯 contract；签名存储、吊销快照同步、实际分发、网络防火墙、DNS/IP 校验、TLS pinning、管理员密码/三次确认编排尚未接入。

### 2026-09-05 阶段 4 诊断 broker contract

范围：固定 `diagnostic.v1` Schema、敏感字段和值扫描、原始包三重确认、
异步有界队列、幂等绑定、TTL、失败重试和配额。

实际改动：新增 `internal/diagnostics/broker.go` 与测试、
`docs/architecture/diagnostics-contract.md`。`DecodePackage` 拒绝未知字段
和尾随 JSON；字段名和值都扫描 Secret、Token、Cookie、Authorization、
Session、Origin 凭据、密码、私钥和原始请求正文。raw 包要求高风险确认、
确认 ID、密码确认和第三次确认。`Submit` 立即返回 `upload_id`，队列限制
项目数、字节数和 TTL；活动任务计入项目上限，终态立即清除包内容，历史
记录有界，过期幂等键不返回旧回执，原始包最多两次尝试，重试不会重复计算
已占用字节。

验证命令：`go test ./internal/diagnostics -race -count=1`、
`go vet ./internal/diagnostics`、`git diff --check`。结果：均退出码 0。

遗留风险：当前只有内存 contract，尚未接入信封加密、PG/Redis 元数据、
对象存储复制、外部回执、持久审计或真实上传；请求线程不应直接调用
外部网络。

### 2026-09-05 全量回归与生产产物检查

验证命令：`go test ./...`、`go vet ./...`、`bash scripts/ci/build-web.sh`。

验证结果：完整 Go 测试退出码 0，语义引擎测试约 305 秒；`go vet ./...` 退出码 0；
生产 Web 构建退出码 0，
构建预算检查通过（1 个初始 preload、6 个主题样式表），产物边界检查未发现
依赖目录、源码目录、符号链接或不安全归档路径。构建使用了 `npm ci --ignore-scripts`。

注意：Vite 仍输出一个关于 `vite.proxy` 扩展名的非阻断警告；尝试改成 `.ts`
会触发 TypeScript `TS5097`，因此保留当前可构建写法，不隐藏警告。
另外修正 `build-web.sh`，让嵌入产物占位文件 `.keep` 每次都保持同样内容，
生产构建不会再制造无关的跟踪文件变更。

### 2026-09-05 插件仓库远端交付

范围：把插件商店和开发手册放到 `/Users/laoke/Dev` 下的独立仓库，并设置
许可证、忽略规则和远端分支。

实际改动：创建并初始化 `CheeseSec_Plugin`、`CheeseSec_Plugin_Docs` 两个
独立 Git 仓库；补充 `AGENTS.md`、`README`、`CONTRIBUTING.md`、`SECURITY.md`、
Apache-2.0 `LICENSE` 和 `.gitignore`，包含 CRP、签名、供应链、离线发布、
CWEDP、审批与审计规范。两个仓库均使用 HTTPS 远端并推送 `main` 初始提交。

验证命令：两个仓库分别运行 `git diff --check`、许可证与 CheeseWAF 根目录
`LICENSE` 使用 `cmp` 校验，并用 `gh repo view` 回读远端元数据。结果：
`LaokeQwQ/CheeseSec_Plugin` 与 `LaokeQwQ/CheeseSec_Plugin_Docs` 均为公开仓库，
默认分支为 `main`，本地工作树干净且跟踪 `origin/main`。

遗留风险：远端目前只有治理文档和 CRP 开发手册，商店 API、OTA 服务、签名
服务和 CWEDP 节点实现尚未开发；不得把仓库存在描述成服务已上线。

### 2026-09-05 阶段 5 ApprovalGate contract

范围：风险分级、预批准边界、本地确认、10 秒告警阅读、密码/二次/三次确认、
Break-glass、scope/epoch/TTL、确认 ID 防重放、AuthorizationCommit 和审计事件。

实际改动：新增 `internal/approval/gate.go` 与测试、
`docs/architecture/approval-gate-contract.md`。low 只有明确预批准且不敏感时
可自动提交；high、emergency、Token、KMS、集群、不可信和测试操作不能自动
批准。Emergency 只接受 security admin 或 tenant owner 的受限 Break-glass。
确认 ID 全局防重放，审批 TTL 上限为 30 分钟。

验证命令：`go test ./internal/approval -race -count=1`、
`go vet ./internal/approval`、`git diff --check`。结果：均退出码 0。

遗留风险：仍是内存 contract；尚未接入 Token 权限、PG 持久化、哈希链审计、
工作流 sidecar、恢复流程或实际操作执行。

### 2026-09-05 阶段 5 Token contract

范围：功能/资源范围权限、子 Key 元数据、一次性密钥、禁用/撤销、永不过期二次确认、
180 天无活动清理、通知、延迟清理和批量性能。

实际改动：新增 `internal/tokens/manager.go` 与测试、`docs/architecture/token-contract.md`。
Token 保存权限与资源快照、备注、创建/失效/最后活动时间和策略代次；明文 Secret 只在
签发结果返回一次，内部只保留 SHA-256 摘要并用常数时间比较。默认 90 天、最长 365 天；
永不过期必须二次确认，仍受 180 天无活动销毁。清理器使用创建后 10 分钟合并计时器，
新增 Token 会重置 deadline，并发批量不会创建定时器风暴；自动销毁会产生通知事件。

验证命令：`go test ./internal/tokens -race -count=1`、`go vet ./internal/tokens`、
`git diff --check`。结果：均退出码 0。

遗留风险：仍是内存 contract；尚未接入 PG 真相、Redis 黑名单加速、Token API、审批 Gate、
恢复后的批量撤销和 180 天通知发送。

### 2026-09-05 阶段 5 全量回归

验证命令：`go test ./...`、`go vet ./...`、`git diff --check`。

验证结果：完整 Go 测试退出码 0，语义引擎测试约 310 秒；`go vet ./...`
退出码 0；diff 检查通过。新增的 approval、diagnostics、cwedp、netlease
和 crp 包均出现在全量输出中并通过。

当前交付边界：阶段 0 的约束/文档基线、阶段 1/2/3/4/5 的纯 contract、
外部文档现状纠偏、生产 Web 产物扫描、插件双仓库初始提交与 GitHub 远端
仓库已建立。控制面运行时接线、PG/Redis/native-raft 迁移、CRP 导入、
CWEDP 网络下载、Socket Lease broker、诊断加密/对象复制、Token/恢复、
商店/OTA 服务和空网演练仍未完成。

### 2026-09-05 后续安全复核与扩展 contract

实际改动：新增控制面 `Coordinator`，诊断信封加密（AES-256-GCM、独立 DEK、
KEK 包装与重包装），并补充 Token 清理的首创建后 60 分钟上限、CWEDP
不可变来源注册表和独立信任根校验。

复核结论：控制面只读审查发现 `Propose` 失败回滚、PG/共识恢复比较、旧
revision 倒写和 nonce 历史恢复仍有高风险缺口，已拆出修复任务；在修复和
验证完成前，不接入真实 PG/native-raft。

验证命令：阶段 contract 分别运行对应 `go test -race`、`go vet` 和
`git diff --check`；最近一次 `go test ./...` 与 `go vet ./...` 在新增
approval、tokens、diagnostics、cwedp 和 netlease 后通过。

### 2026-09-06 控制面安全修复与 PostgreSQL 适配器

实际改动：控制面增加 committed/ tentative 状态区分、失败冻结、共识与
持久状态比较、nonce ledger 恢复和历史提交安全安装；新增
`internal/controlplane/postgres`，提供事务迁移、行锁、幂等提交、顺序/冻结
校验和状态加载；新增 `docs/architecture/control-plane-postgres.md`。

验证命令：`go test ./internal/controlplane -race -count=1`、
`go vet ./internal/controlplane`、`go test ./internal/controlplane/postgres -v -count=1`、
`go vet ./internal/controlplane/postgres`、`git diff --check`。结果：均退出码 0；
PostgreSQL 集成测试因 `CHEESEWAF_POSTGRES_TEST_DSN` 未设置而显式 `SKIP`，
随后尝试的隔离 Docker PostgreSQL 因 Docker Hub DNS 失败，未伪造集成通过；
临时 Colima profile 已删除。

遗留风险：真实 PG 集成仍待可用数据库环境；适配器尚未接入 `cheesewaf serve`、
native-raft 或现有 API，当前只能作为显式选择的持久层。

安全复核补充：适配器增加 cluster 级事务锁、同 cluster/revision 与 nonce 唯一约束、
term/leader 单调检查、完整 nonce ledger 继承校验、幂等状态完整比较和损坏状态拒绝。
`Coordinator` 对空 DurableStore 支持首次提交；旧 revision、状态冻结和共识/持久快照
差异仍保持拒绝。

后续验证：控制面在历史提交安装、重试解冻、领导权切换 nonce 保留、冻结状态差异、
空持久层首提案和 PostgreSQL BIGINT/nonce ledger 校验后，`go test ./...` 退出码 0；
`go vet ./...` 与 `git diff --check` 也通过。真实 PostgreSQL 集成因 Docker Hub DNS
不可用仍未执行，不能把适配器声明为已接入生产。
本轮为数据库集成创建的 `cheesewaf-pg-test` Colima profile 已停止并删除；默认
Colima profile 保持停止，没有残留 WAF、数据库或开发服务进程。

最新验证（2026-09-06）：在 committed fence、首提案空库、nonce ledger 和
PostgreSQL 适配器边界修复后重新运行 `go test ./...` 与 `go vet ./...`，
均退出码 0；主仓库 `git diff --check` 通过。
控制面进一步只让 committed fence 进入数据面，允许共识/持久层同时为空的
首次启动，并在历史提交安装时保持更高 tentative 状态；受影响 package race/vet
和针对性回归通过。
随后在 PostgreSQL 幂等、迁移、控制面状态恢复和 fencing 改动后再次运行
`go test ./...` 与 `go vet ./...`，均退出码 0；完整输出包含
`internal/controlplane/postgres`。

### 2026-09-06 PostgreSQL 适配器全量回归

验证命令：`go test ./...`、`go vet ./...`、`git diff --check`。结果：均退出码 0；
全量输出包含 `internal/controlplane/postgres`。适配器真实数据库测试仍因
`CHEESEWAF_POSTGRES_TEST_DSN` 未设置而显式跳过，不能替代真实 PostgreSQL 演练。

### 2026-09-06 控制面 fencing 复核

新增 committed fence 历史：未完成持久化的提案 token 不会被数据面接受；
历史提交安装不会回退较新的 tentative 状态；领导权切换保留已使用 nonce。
恢复比较现在包含冻结状态和 nonce ledger。受影响包 race/vet、全量 Go 测试
和 PostgreSQL 适配器单元检查均通过。

### 2026-09-06 PostgreSQL 真实集成回归与状态完整性修复

范围：PostgreSQL 适配器的重复提交、首写并发、首 revision、nonce 历史、多 revision
往返和事务回滚。

实际改动：新增随机独立 schema 的集成测试辅助代码。测试只清理自己创建的 schema，
不会清空测试 DSN 指向的其他数据。原始 payload 只写入 BYTEA；`state_json` 只保留
元数据，避免 JSONB 规范化空格造成相同提交误报冲突。按 cluster 计算事务锁键，
并校验首 revision、冻结初始状态、合法 JSON、nonce 必须是本次提交新增项，以及
nonce ledger 必须覆盖每个 revision 且不能重复。数据库唯一约束冲突统一映射为
`ErrCommitConflict`；零时间戳提交在入口直接拒绝。

验证命令：

- 新增回归测试先运行并确认旧实现失败：nonce 不一致、冻结初始状态和不完整 ledger
  均复现错误行为；真实数据库首重试也复现 JSONB 规范化导致的冲突。
- `go test ./internal/controlplane/postgres -run Integration -v -count=1`（临时
  PostgreSQL 17.11 Unix socket）：8 个集成测试通过，包括多 revision 往返、后续
  revision 回滚和 3 个元数据变更子用例。
- `go test -race ./internal/controlplane/postgres -run Integration -count=1`：退出码 0。
- `go test ./internal/controlplane/postgres -count=1`、`go vet ./internal/controlplane/postgres`
  和 `git diff --check`：退出码 0。
- 追加零时间戳入口回归后再次运行 `go test ./internal/controlplane/postgres -race -count=1`、
  `go vet ./internal/controlplane/postgres` 和 `git diff --check`：退出码 0。
- 最新 `go test ./...` 退出码 0，语义引擎耗时 328.678 秒。该次全量命令未设置数据库
  DSN，数据库集成证据来自前面的独立运行；全量测试不能替代数据库测试。
- 在入口增加完整 nonce ledger 和 JSON 校验后再次运行 `go test ./...`，退出码 0；
  `internal/controlplane/postgres` 与 `internal/crp` 均重新编译并通过。

清理：临时 PostgreSQL 已停止；`/tmp/cheesewaf-pg-verify.WNFUrd` 和原生 PostgreSQL
17.11 临时构建目录已删除；未留下数据库进程或服务。

遗留风险：真实集成依赖显式设置 `CHEESEWAF_POSTGRES_TEST_DSN`；本次环境已用
临时 PostgreSQL 验证，新增 CI 任务尚无远端运行记录。适配器仍未接入 `cheesewaf serve`、
native-raft 或现有 API；生产 profile 继续 fail-closed，避免静默回退 SQLite。

补充改动：`.github/workflows/ci.yml` 新增隔离的 `postgres-controlplane-integration`
任务。它使用按 SHA-256 固定的官方 PostgreSQL 17.6 服务、健康检查和显式测试 DSN，
运行控制面和 Token PostgreSQL 适配器集成测试。生产镜像和 `cheesewaf serve` 路径没有改变。

补充验证：`bash scripts/ci/verify-ci-static.sh` 退出码 0；直接使用临时 Go 缓存运行
`actionlint v1.7.7` 检查全部 workflow，退出码 0。第一次通过 `go-env.sh` 运行时，
共享临时模块缓存中依赖文件缺失，具体原因尚未定位；改用独立构建缓存后检查通过。
镜像固定摘要已通过 `docker buildx imagetools inspect` 回读验证，退出码 0。

文档验证：由于外部文档仓库的构建缓存目录只读，直接在原目录运行会被旧的
`.hugo_build.lock` 和 `resources/_gen` 拦截；将当前源文件复制到明确的临时目录后，
`hugo --cleanDestinationDir --noBuildLock` 构建通过（EN 106 / ZH 104，259 个输出文件）。
同样将当前 `CheeseSec_pages` 源文件复制到临时目录并重新执行 `npm ci --ignore-scripts`、
`npm run typecheck`、`npm run build`，构建通过（7 个页面、464 个输出文件）。临时副本
和依赖均已删除，外部仓库未写入新的构建产物。

清理纠错：曾误将默认 Colima 的共享 BuildKit 缓存容器当成验收容器删除。其状态卷
保留，随后使用原 builder 的 `docker buildx inspect --bootstrap` 重建，状态已回到
running。默认 Colima 还承载其他任务容器，不属于本次临时 PostgreSQL 范围，不再
停止或清理；不能宣称宿主机上所有服务已停。

下一步：补充 CI 的迁移版本管理，再实现控制面启动单元与 native-raft/Redis 的运行时
接线；在接线前继续保持 temporary profile 为默认。

### 2026-09-06 CRP 离线导入准入

范围：在安装激活之前，提供只读内存准入层。

实际改动：新增 `internal/crp/importer.go` 和测试。`Import` 限制 manifest 与
artifact 大小，拒绝未知或尾随 JSON，串联来源注册表、版本/发布序号防降级、三种
摘要、签名阈值和管理员确认，并返回内容身份。它不读路径、不写文件、不联网、不
启动 goroutine，也不授予插件运行权限。

验证命令：`go test ./internal/crp -race -count=1`、`go vet ./internal/crp`、
`git diff --check`，均退出码 0。测试覆盖有效离线包、manifest 超限、artifact 超限、
尾随 JSON 和版本降级。

遗留风险：这只是安装前准入 contract，未实现插件目录原子替换、激活/回滚、吊销快照
持久化、透明日志、能力与网络预检、CWEDP/OTA/store/sidecar。

下一步：设计带 last-known-good 和 fencing 绑定的安装事务；先在内存 fake store 上
验证原子提交和回滚，再接入本地加密队列与控制面审计。

### 2026-09-06 Token 持久化适配器

范围：Token 状态、权限/资源快照、租约、幂等请求和追加事件的 PostgreSQL 边界。

实际改动：新增 `internal/tokens.Persistence`、仅用于测试的
`MemoryPersistence`，以及 `internal/tokens/postgres.Store`。适配器将 Token 状态、
事件和幂等指纹放在同一事务，使用租户/Token advisory lock、`FOR UPDATE`、
`ExpectedVersion` 和 `LeaseID` 拒绝并发写入。数据库只保存 64 位十六进制 SHA-256
摘要，不保存密钥原文。自动销毁先写通知事件，再删除 Token 状态。补充了 PostgreSQL
BIGINT 范围校验、摘要格式校验和错误路径。

验证命令：`go test ./internal/tokens/... -race -count=1`、
`go vet ./internal/tokens/...`、`go test ./internal/tokens/postgres -run
TestPostgresRoundTripIsAtomicAndIdempotent -race -count=1`（临时 PostgreSQL 17.6）和
`git diff --check`，均退出码 0。真实集成覆盖创建、幂等重试、内容冲突、禁用、
版本冲突、自动销毁和事件恢复。

遗留风险：适配器尚未接入 Token Manager、控制面、CLI/API、Redis 黑名单加速、恢复
流程和持久 outbox；`MemoryPersistence` 不能用于生产。

下一步：定义 TokenService 运行时接口，把审批确认、策略 epoch、Redis 短期缓存和
PG 事务接起来；先保持当前 temporary profile，不允许未经验证的 SQLite 回退。

### 2026-09-06 CRP `.crp` 归档解析

范围：在离线导入准入之前，安全解析本地 ZIP 包，不安装、不激活。

实际改动：新增 `internal/crp/archive.go` 和测试。`ParseArchive` 只接受
`manifest.json`、唯一 `artifact/<file>` 和 `signatures/manifest.json`，拒绝未知/重复
条目、绝对路径、路径穿越、反斜杠、目录、符号链接和非 regular 条目。解析前按
文件数、总未压缩大小和单文件大小限制，读取时再次限流；签名 JSON 也使用严格解析。

验证命令：`go test ./internal/crp -race -count=1`、`go vet ./internal/crp`、
`git diff --check`，均退出码 0。

遗留风险：归档解析和 `Import` 仍是安装前 contract；尚未接入安装目录原子替换、
激活/回滚、透明日志、吊销快照持久化、商店或 OTA。

### 2026-09-06 CWEDP 异步 broker contract

范围：在真实网络传输之前，固定异步分发的队列、续传和租约边界。

实际改动：新增 `internal/cwedp/broker.go` 与测试。`Broker.Submit` 先完成
HELLO/CAPABILITIES 协商、来源独立性校验和结构化 LeaseBinding 验证；`Push` 进入
有界队列，worker 按连续 offset 写入 `ResumeStore`；完成时同时校验 MD5、SHA-1 和
SHA-256。重复提交相同 intent 会复用已保存的 offset；intent 或来源发生实质变化时
拒绝。Broker 在提交和入队前分别限制总包、单个分块的字节数，避免超大数据绕过队列
项目数限制；并强制 ResumeStore 实现原子 `SaveExpected`，以读取到的 offset 进行
CAS，拒绝只有 `Save`/`Load` 的非原子持久层。

来源失败写入追加-only 的隔离源记录，并由 `MaxSourceSwitches` 限制切源次数。摘要
不匹配不是无条件终态：Broker 隔离当前来源和同一供应链根，丢弃可重试路径上的部分
字节并从 offset 0 选择 fallback；没有合资格 fallback 或预算耗尽才保存失败。传输
失败只隔离精确来源，保留已验证前缀；调用方可在能力/策略刷新后显式用既有隔离证据
选择 fallback。损坏状态和非法分块仍会进入失败终态，不能继续写入。`MemoryResumeStore`
只用于 contract 测试。

验证命令：`go test ./internal/cwedp -race -count=1`、`go vet ./internal/cwedp`、
`git diff --check`，均退出码 0。

遗留风险：尚未接入真实 transport、节点身份认证、真实 netlease 适配器、DNS/IP
校验、TLS pinning、来源失败上报接线、CRP 安装激活或 OTA/store；纯 contract 不等于
网络隔离或节点下载器已经启用。

随后为 `Broker` 增加总包和单块字节预算、重复 intent 复用 offset、损坏状态终态写入，
并把 `AtomicResumeStore.SaveExpected` 变为 broker 的强制前置条件，非原子持久层以
`ErrAtomicResumeRequired` 拒绝。针对损坏状态的切片 panic 先复现，再加长度校验；
新增回归和 `go test ./internal/cwedp -race -count=1`、`go vet ./internal/cwedp`、
`git diff --check` 均退出码 0。

### 2026-09-06 CWEDP PostgreSQL ResumeStore

范围：为断点续传提供事务持久化边界，不接入真实网络。

实际改动：新增 `internal/cwedp/postgres/store.go` 和测试。适配器把原始分块数据
保存到 BYTEA，把 intent、来源和摘要保存到结构化列；使用事务 advisory lock、
`FOR UPDATE`、期望 offset 和终态条件更新，拒绝过期写入、实质变更和已完成任务
继续修改。修复首个空 offset 状态写入 SQL `NULL` 的问题，统一保存为空字节；补充
损坏状态切片的长度检查，避免 panic。

验证命令：`go test ./internal/cwedp/... -race -count=1`、
`go vet ./internal/cwedp/...`、`go test ./internal/cwedp/postgres -race -count=1 -v`
（临时 PostgreSQL 17.6）和 `git diff --check`，均退出码 0。

遗留风险：Broker 强制使用 `AtomicResumeStore.SaveExpected` 传递 worker 读取的 offset；
旧的仅有 `Save` 的实现会被拒绝，不能作为 broker 接线。真实 transport、节点身份认证、
netlease 适配器和安装回滚仍未接线。

真实集成首次运行还发现空 offset 的 `nil []byte` 会被 PostgreSQL 驱动编码为 `NULL`，
与 `BYTEA NOT NULL` 冲突；现在统一编码为空字节后，临时 PostgreSQL race 集成测试通过。
随后加入损坏续传状态的短数据回归，确认不会触发切片 panic。

### 2026-09-06 运行时接线安全审计

范围：检查 contract 接入现有 `cheesewaf serve` 的最小安全边界。

审计结果：当前生产 profile 会在启动副作用前 fail-closed，且生产工厂不会回退 SQLite。
现有 `controlplane/postgres.Store` 与 `storage.Store` 的数据模型不同；native-raft 和
epoch fencing 还没有运行实现，暂时不能直接接入。补充防御性检查：生产工厂返回
`(nil, nil)` 时明确返回 `ErrProductionStorageUnavailable`，不再把空指针推迟到服务启动。

验证命令：新增回归测试先确认旧实现失败，再运行
`go test ./internal/cli ./internal/config -race -count=1`、
`go vet ./internal/cli ./internal/config` 和 `git diff --check`，均退出码 0。

遗留风险：真正的生产启动单元仍需一次性接入 PostgreSQL durable store、Coordinator、
native-raft、成员身份和 Redis 短期状态；在此之前 production profile 必须继续拒绝。

### 2026-09-06 代理并行后的全量回归

范围：合并 Token 持久化和 CWEDP broker 后检查所有 Go 包。

验证命令：`go test ./...`、`go vet ./...`、`git diff --check`。

验证结果：三项命令均退出码 0；全量测试包含 `internal/tokens/postgres`、
`internal/crp`、`internal/cwedp`、`internal/controlplane/postgres`。

交接说明：本轮使用的临时 PostgreSQL 容器和镜像已经删除。默认 Colima 当前仍有
其他任务容器运行，不能把共享环境状态写成“全部服务已停止”。

随后补充生产工厂空返回保护、Token 数据库行完整性校验和 CRP 显式验证时间校验，
再次运行 `go test ./...`、`go vet ./...`、`git diff --check`，均退出码 0。

Token 读取审计随后补充了 `Load` 与 `List` 的损坏行测试。新增测试先因 `scanToken`
接口只接受具体 `*sql.Rows` 而无法编译，随后改成共享 `rowScanner` 并在转换成
`uint64` 前校验 epoch、version 和 digest。`go test -race ./internal/tokens/postgres`、
`go vet ./internal/tokens/postgres` 和 `git diff --check` 均退出码 0。

随后加入 CWEDP 总包/单块字节预算、重复 intent 幂等、损坏状态终态持久化和
PostgreSQL ResumeStore 修复；最新 `go test ./...`、`go vet ./...`、`git diff --check`
均退出码 0。该全量输出包含 `internal/cwedp` 和 `internal/cwedp/postgres`，新增
broker 的 `SaveExpected` 接线也在同一轮回归中通过。

在新增 CWEDP PostgreSQL 适配器、Token 读取校验和 broker 原子 offset 接线后，
又运行一次 `go test ./...`、`go vet ./...`、`git diff --check`；三项均退出码 0，
语义引擎测试耗时 300.580 秒。该轮还包含 `.crp` 归档解析和 CWEDP PostgreSQL
适配器最新代码。

### 2026-09-07 恢复管理员身份输入加固

范围：恢复凭证的 2-of-3 管理员确认。

实际改动：管理员身份现在使用严格的无空白格式。服务器拒绝前后空格和控制空白，
不再悄悄 `TrimSpace` 后计数，避免同一管理员通过不同空白写法绕过 distinct threshold。

验证命令：先运行回归测试确认带空格身份会被错误计数；随后运行
`go test ./internal/recovery -race -count=1`、`go vet ./internal/recovery`、
`git diff --check`，均退出码 0。

遗留风险：恢复 contract 仍未接入持久审计、实际 KMS、TokenService 和现有 API；
调用层仍必须在恢复前执行密码/MFA、审批和本地会话绑定。

### 2026-09-07 账户用户名一致性修复

范围：修复管理员及其他人类账户在 Web、REST API、CLI、SQLite、JWT、Session、登录 CAPTCHA、审计和限流路径中的用户名表示不一致问题。

实际改动：

- 新增 `internal/identity.ValidateUsername`，统一要求用户名为 3–32 个 ASCII 字符，以 ASCII 字母开头，以 ASCII 字母或数字结尾，中间只允许字母、数字、`.`、`_` 和 `-`。空格、控制字符、不可见字符和非 ASCII 字符都会被拒绝。
- Web 初始化、登录和用户管理保留原始输入；页面提示用户重新输入，不自动去空格或转小写。
- API、CLI、SQLite `CreateUser`/`UpdateUser`、人类 JWT claims、Session 中间件和登录 CAPTCHA receipt 使用同一规则；API Token 的显示备注不套用人类用户名规则。
- 新增 `cheesewaf user repair-username USER_ID NEW_USERNAME --reason ...`，只按不可变用户 ID 修复历史非法用户名。命令拒绝重名、合法账号和不存在的 ID，不合并账号；用户名变更、撤销该账号全部 Session 和追加审计记录在同一 SQLite 事务中完成。
- SQLite Schema 从 3 升到 4，迁移保留历史脏数据，不自动改写；降级必须恢复升级前备份。
- 登录审计和限流键保留精确的尝试用户名，避免把 `admin` 与 ` admin ` 混成同一审计对象。

验证命令：

- `go test ./... -count=1`：退出码 0；包含 `internal/identity`、用户存储修复、认证、CAPTCHA、CLI 和现有全部 Go 包。语义引擎测试约耗时 317 秒。
- `go test ./internal/api/handler ./internal/api/middleware ./internal/captcha ./internal/cli ./internal/setup ./internal/storage ./internal/monitor/notifier -count=1`：退出码 0。
- `npm test`（`web`）：70 个测试文件、461 个测试通过。
- `npm run typecheck`（`web`）：退出码 0。
- `git diff --check`：CheeseWAF 和 CheeseSec_Docs 均退出码 0。

结果边界：身份输入一致性和历史 SQLite 修复路径已有代码与测试证据；PG 管理用户表、生产控制面、native-raft、Redis 运行时和集中式审计仍未接入，不能据此宣称生产集群已完成。

下一步：把本地 CRP 导入结果接入可回滚的运行时安装状态，再处理 PG/Redis/native-raft 启动单元；每一步继续维护中英文手册和清洁工作区验收。

### 2026-09-08 账户启动边界和 CRP 本地状态层

范围：继续修复历史账号的启动可用性边界，并把已验签 CRP 接入本地可回滚状态层。

实际改动：

- 新增 `CompleteSetup` 遇到任何已有账号都拒绝重复初始化，不再按大小写相似度重置密码、角色、2FA 或会话；错误信息指向 `ensure-admin` 或按 ID 的 `repair-username`。
- 启动完整性检查只把规范用户名和精确 `admin` 角色视为可用管理员；已有可用管理员时，脏只读账号只记录修复提示，不阻断 WAF 启动；没有可用管理员时才阻断并给出按 ID 修复命令。
- 用户密码修改会撤销该账号已有 Session；普通用户 API 不能绕过历史用户名的 repair 审计；非法登录输入仍进入来源限流窗口，避免用空白用户名持续触发审计写入。
- CLI 行读取只去除一组传输层 CRLF，额外控制字符保留给用户名校验处理。
- 新增 `internal/crp.RuntimeStore` 本地状态层：暂存、健康检查、晋级、回滚、单调 revision/CAS、一次性确认、内容寻址 artifact、manifest/signature 元数据和重启恢复。运行时重新校验 `Import` 内部准入标记、摘要和身份，不启动插件、不联网、不改变请求线程。

验证命令：

- `go test ./internal/setup ./internal/cli -race -count=1`、`go vet ./internal/setup ./internal/cli`：退出码 0。
- `go test ./internal/api/handler ./internal/api/middleware ./internal/captcha ./internal/cli ./internal/setup ./internal/storage -count=1`：退出码 0。
- `go test ./internal/crp -race -count=1`、`go vet ./internal/crp`：退出码 0。
- `go test ./... -count=1`：本轮身份修复前的全量回归曾退出码 0；加入 CRP 运行时后需重新运行，不能沿用旧证据。
- `npm test`：70 个测试文件、461 个测试通过；`npm run typecheck`：退出码 0。
- `git diff --check`：退出码 0。

遗留风险：RuntimeStore 是单节点本地状态层，尚未接入 PG、native-raft、CWEDP、控制面授权服务或 sidecar 生命周期；跨进程锁、透明日志、吊销快照和生产安装回滚仍需后续阶段实现。当前不要把 CRP CLI verify 或 RuntimeStore 描述成商店、OTA 或集群安装已经可用。

下一步：重新运行全量 Go 回归；随后把 RuntimeStore 接入控制面适配器，并补充离线 CRP/CWEDP 验收脚本。

### 2026-09-08 管理 API Token 生命周期接线

范围：把阶段 5 的有效期和无活动策略接到现有 Management API，同时不破坏历史
Token 和现有自动化调用。

实际改动：`internal/tokens.ResolveLifetime` 统一默认 90 天、最长 365 天和显式
不过期确认；管理 API 创建请求新增 `never_expire`、`confirm_never_expire`、
`confirmation_id`，只允许管理员 Session 确认，并对确认 ID 做进程内一次性重放
屏障。配置模型保存 `never_expire`，校验不过期令牌不能携带失效时间、活动时间
不能早于创建时间；PG/内存 Token 持久化校验同步保留该字段。Management API
认证连续 180 天无活动后立即拒绝；`cheesewaf serve` 启动单 worker 合并清理循环，
按 10 分钟滑动、首创建后 60 分钟上限删除过期/不活动令牌，并在提交后写本地审计、
尽力发送管理员通知。Web 管理页新增 90 天/365 天选项，并将不过期选项置为不可用；
后端在未注入 password/TOTP、10 秒警告、本地 Session 和 ApprovalGate verifier 时
fail-closed 返回 `API_TOKEN_CONFIRMATION_UNAVAILABLE`，避免把普通点击当成强确认。

验证命令：`go test ./internal/tokens ./internal/tokens/postgres ./internal/api/middleware ./internal/api/handler ./internal/config ./internal/cli -race -count=1`、
`go vet ./internal/tokens ./internal/tokens/postgres ./internal/api/middleware ./internal/api/handler ./internal/config ./internal/cli`、
`npm test -- --run src/pages/System/SystemPage.behavior.test.tsx`、`npm run typecheck`。

结果：上述定向测试与 vet 均退出码 0；新增 Web 行为测试验证不过期创建必须经过
二次确认并携带一次性确认 ID。

边界：当前仍保留创建响应中的一次性明文以兼容已有 API；密码/TOTP、10 秒警告、
ApprovalGate、PG TokenService/outbox、Redis 黑名单和 Web CSV 一次性导出尚未接入。
旧配置中没有时间戳的历史永久 Token 不会被猜测年龄，必须人工轮换或撤销。

### 2026-09-08 CRP 暂存安全加固、用户名事务和文档漂移处理

范围：把本地 CRP 暂存从“能跑的 contract”推进到可审计的安全基础层，并修正账户/存储和文档边界。

实际改动：

- `ImportResult` 使用不可导出的 admission，运行时不再根据可变的 `SignatureReport` 降低确认要求；Stage 在外部复核期间释放锁，回写时用 revision CAS，并拒绝同 artifact 不同 manifest 的伪幂等。
- RuntimeStore 要求绝对运行目录；根目录和受管目录自动收紧为 0700，state、artifact、metadata 要求属主专用权限；重启校验 manifest 的 key/名称/插件 ID、slot、revision、内容身份和摘要；确认有效期限制为不超过 24 小时且校验时间顺序。
- 新增 `cheesewaf crp stage`：显式包、信任根、来源、校验时间和 runtime-dir，只暂存不激活；移除没有密码、10 秒等待、第三次确认和耐久审计支撑的 `--allow-confirmation` 绕过参数。
- SQLite 用户安全变更和会话撤销统一在一个事务中完成，调用方删除重复撤销；审计修复 reason 增加 UTF-8、控制字符和长度校验，并开启 `recursive_triggers` 防止 `REPLACE` 绕过 append-only trigger。
- OTA 默认域名统一为 `https://ota.cheesesec.com/`；根 README/中文 README 增加 CRP staged 边界和当前 setup 不导出系统主密钥的说明。
- 独立 `CheeseSec_Plugin` 与 `CheeseSec_Plugin_Docs` 已在 `~/Dev`，CRP v1 手册与当前三条目解析器对齐，并补最小可解析示例；各仓库本地已有未推送提交，待最终审查后推送。

验证命令（本轮已新鲜通过）：

- `go test ./internal/crp -race -count=1`、`go vet ./internal/crp`。
- `go test ./internal/storage -race -count=1`、`go test ./internal/config ./internal/setup ./internal/cli -count=1`。
- `go fmt` 检查：`gofmt -l cmd internal` 无输出；`git diff --check` 通过。
- `npm run typecheck` 通过；此前前端 70 个测试文件/461 个测试和生产标记扫描通过，但 OTA/README 最新改动后仍需在最终快照重跑。

遗留风险：RuntimeStore 仍是单节点本地状态层，没有跨进程锁、透明日志、吊销快照、PG/native-raft/CWEDP、插件 sidecar 生命周期或完整审批审计；Unix-like 原子替换已同步父目录，Windows 仍需文件系统持久化验收。CLI stage 不是安装器。UpdateUser 与 Login 之间的 credential epoch 竞态、PG 主存储和 Redis 运行时仍未接入。外部文档还有代理正在同步，不能把 contract 说成生产功能。

下一步：等待并审查 Token、Approval、NetLease、CWEDP、PG 和外部文档代理；合并后重新跑全量 Go/前端/Hugo/Get Started/产物扫描，再分别审查并推送两个独立 GitHub 仓库。

### 2026-09-08 CWEDP contract 文档同步

范围：把 CWEDP 最新 contract 口径同步到架构文档和阶段交接记录，覆盖原子续传保存、
来源独立性与隔离源、`MaxSourceSwitches`，以及完整性失败和传输失败的可恢复语义。

实际改动：

- 更新 `docs/architecture/cwedp-contract.md`：明确 `Broker` 强制要求
  `AtomicResumeStore.SaveExpected`，只有 `Save`/`Load` 的非原子实现必须拒绝；
  `SourceQuarantine` 按 `(kind, ID)` 追加-only 保存，完整性/策略失败隔离同一供应链
  根，传输失败只隔离精确来源。
- 明确 `MaxSourceSwitches` 默认值和硬上限均为 3；新增隔离证据恰好消耗一次预算，
  能力刷新对既有证据的显式复用不重复计数；新的失败切换预算耗尽返回失败，既有
  隔离证据仍可在能力刷新后显式恢复。
- 明确三摘要不匹配时可在合资格 fallback 存在时清空不可信字节、从 offset 0 重试；
  传输/策略失败保留已验证前缀；没有 fallback 或新的切换预算耗尽时先保存失败，
  既有隔离证据可在能力刷新后显式恢复；状态/分块非法时阻止继续写入。
- 明确 `internal/cwedp`、异步 broker 和 PostgreSQL ResumeStore 都不提供真实网络
  transport；当前仍是纯 contract，不能替代节点服务、网络隔离或插件安装验收。

验证命令：

- `go test ./internal/cwedp/... -race -count=1`
- `go vet ./internal/cwedp/...`
- `git diff --no-index --check /dev/null docs/architecture/cwedp-contract.md`
- `git diff --no-index --check /dev/null tasks.md`

验证结果：`go test ./internal/cwedp/... -race -count=1` 退出码 0（`internal/cwedp`、
`internal/cwedp/postgres` 均通过）；`go vet ./internal/cwedp/...` 退出码 0；两个相关
文档的 `git diff --no-index --check` 退出码 0。

遗留风险：真实 transport、节点身份认证、DNS/IP 与 TLS pinning、netlease 适配器、
来源失败上报接线、CRP 安装激活/回滚和空网演练仍未实现。

下一步：保持 broker 的原子持久化和来源隔离语义，在接入真实 transport 前补系统级
网络隔离、审计、失败预算和安装回滚验收。

### 2026-09-08 管理员身份输入专项审计

范围：复核 Go/API、Web、配置、CLI、SQLite、JWT、Session、登录 CAPTCHA、恢复确认和使用说明中的管理员及人类账户身份输入。

审计结论：人类用户名已经统一调用 `internal/identity.ValidateUsername`。带前后空格的 `admin`、控制字符、不可见字符、非 ASCII 字符和嵌入空白都会被服务端拒绝；登录审计和限流保留原始尝试值，不会把 `admin` 与 ` admin ` 合并。恢复确认的管理员 ID 也会通过严格的无空白检查。配置中的 ClickHouse/Elasticsearch `username` 是外部服务凭据字段，不是 CheeseWAF 管理员身份，因此继续按凭据原样传递。

实际改动：用户管理 API 的角色校验不再先 `TrimSpace`。服务端现在拒绝带空白、控制字符或不可见字符的角色值，避免请求中的 `" admin "` 被按 `admin` 授权检查后写入脏角色；角色权限查询也按原始键匹配。新增 Create/Update API 回归测试，覆盖空格、制表符、换行、不换行空格、零宽字符和 BOM，并确认拒绝请求不会创建账号、降权最后管理员或撤销有效 Session。中英文 README 增加用户名精确匹配、拒绝空白和历史账号按 ID 修复说明。

验证命令：

- `go test ./internal/api/handler -run 'Test(CreateUserRejectsWhitespaceRoleWithoutCreatingAccount|UpdateUserRejectsWhitespaceAdminRoleWithoutChangingLastAdmin)' -count=1`：通过。
- `gofmt -w internal/api/handler/user.go internal/api/handler/user_role_identity_test.go`：通过。
- `git diff --check`：待主线程合并其他并行改动后重跑。

结果边界：本次只修复用户管理 API 的角色输入边界并补充文档；Token owner、租户/集群标识和外部服务凭据字段的空白语义仍由各自 contract 负责，不能把本次结果扩展为所有标识字段都已统一。

### YYYY-MM-DD 阶段 N

### 2026-09-08 AI 高风险审批 Gate 适配层

范围：审查 `internal/ai.ApprovalStore` 与 `internal/approval.Gate` 的确认语义差距，
在不改旧 API 签名的前提下，为 AI `Destructive` 工具增加最小 Gate 适配。

实际改动：新增 `internal/ai/approval_gate_adapter.go`。适配器保留 AI 审批单的参数和
预览摘要，同时把高风险请求绑定到 Gate 的策略代次、Scope、IntentDigest、Nonce、
Session 和一次性确认 ID。`BeginConfirmation` 由服务端记录告警开始时间；`Confirm`
复用 Gate 的 10 秒等待、语言短语、密码或 TOTP、二次检查点和第三次最终确认。旧的
`ApproveFor` 对 `Destructive` 请求 fail-closed；`Assistant` 新增可选的
`NewAssistantWithApprovalGate`，未配置适配器时拒绝执行高风险工具。`Modify` 仍使用兼容
流程，避免现有页面在没有完整确认字段时被悄悄改变。

验证命令：

- `go test ./internal/ai -count=1`
- `go test ./internal/approval ./internal/api/handler -count=1`
- `go vet ./internal/ai ./internal/api/handler`
- `git diff --check`

结果：上述 AI、Gate、Handler 测试和 vet 已通过；完整仓库回归待主线程合并其他并行改动后
统一运行。

遗留风险：Gate 挑战、确认检查点和审计仍是进程内状态；适配器尚未接入 HTTP 确认 API、
密码或 TOTP 校验器、PG 真相、跨进程锁和耐久审计。生产接入前必须从控制面注入策略代次，
并验证本地控制面来源；当前 `Modify` 页面不能直接宣称支持高风险三次确认。

下一步：把适配器接入受保护的管理 API，补齐 Gate 的持久化和重启恢复，再评估是否把
`Modify` 迁移到同一套确认材料。

### 2026-09-08 最终快照回归与插件仓库交付

范围：对本轮并行改动做合并后验证，并把插件商店代码与手册保持在 `~/Dev` 的独立仓库中交付。

实际改动与边界：

- AI `Destructive` 工具必须通过 `internal/approval` Gate 适配层；没有适配器或旧
  `ApproveFor` 路径均 fail-closed。适配器仍是进程内 contract，HTTP/UI、PG 真相、
  密码/TOTP 注入和耐久审计未接线。
- Token 后端保留默认 90 天、最长 365 天和 180 天无活动清理；清理由单 worker 合并
  调度。完整 ApprovalGate、密码/TOTP、10 秒告警等待尚未注入，因此生产 Handler
  对 `never_expire` 返回 `API_TOKEN_CONFIRMATION_UNAVAILABLE`，Web 选项禁用。
- CWEDP contract 强制原子续传 CAS、来源根/独立组隔离、隔离源和切换预算；仍无真实
  transport、节点服务或 CRP 安装接线。
- NetLease 对内部白名单资源允许无人工提示；仅临时外连要求显式标记、操作者、一次性
  确认、短租约、epoch/资源/TLS 绑定和审计；默认外连拒绝。
- 修复 `verify-ci-static.sh` 对不存在的历史 `PERFORMANCE_DELIVERY.md` 的错误引用。
- `CheeseSec_Plugin` 与 `CheeseSec_Plugin_Docs` 均位于 `~/Dev`，Apache-2.0、CODEOWNERS、
  Dependabot、SHA 固定且最小权限 CI、CRP schema/示例/secret scan 已推送到 GitHub；
  两个 `main` 均启用强制 PR、CODEOWNERS 审查、线性历史和必需 CI。

验证命令与结果：

- `go test ./... -count=1`：全仓通过；语义引擎约 304 秒。
- `go test ./... -run '^$' -count=1`、`go vet ./...`、`gofmt -l cmd internal`、
  `git diff --check`：通过。
- CWEDP、NetLease、Approval、Token、AI 和 Handler 定向 race/vet：通过。
- `npm test`：70 个测试文件、462 个测试通过；`npm run typecheck`、
  `npm run build` 和产物预算/边界扫描通过。
- `bash scripts/acceptance/get-started.sh --static-contract` 与 `--smoke`：通过，
  包含 temporary 可运行、production fail-closed、运行时目录隔离和清理验证。
- 根仓库 `bash scripts/ci/verify-ci-static.sh`：通过；Hugo 文档站中英文 106/104 页、
  259 个文件生成通过；外部 CheeseSec_Docs 的中英文 Token/CWEDP 口径已同步。

遗留风险：生产控制面仍未把 PG、native-raft、Redis、CWEDP、NetLease、ApprovalGate、
TokenService、KMS、透明/耐久审计和插件 sidecar 接成一个启动单元；RuntimeStore 仍是
单节点本地状态层，跨进程锁、吊销快照、安装激活/回滚和真实断网集群演练仍未完成。不要
把本轮 contract 测试或 CLI stage 描述成生产商店、OTA 或集群安装已经交付。

下一步：优先做控制面生产接线（PG + native-raft + fencing），随后接入持久 Approval/Token
服务和 CWEDP/NetLease 节点 transport；每一步都重新跑本文件记录的全量验收门禁。

### 2026-09-08 控制面生产启动编排契约

范围：固定 PostgreSQL durable state、native-raft/coordinator、双快照校验、fencing token、health/fail-closed 和 last-known-good 的最小启动顺序。

实际改动：新增 `internal/controlplane/startup.go` 与 `startup_test.go`。`Bootstrap` 要求生产 profile、PostgreSQL durable backend 和 native-raft backend；依次执行 durable prepare/health/load、consensus prepare/health/current、双快照比较、临时状态机校验和 fencing token 校验，全部成功后才返回 `StartupStageReady`。任一步失败都会冻结写入并保留已提交的 last-known-good；未验证的新快照不会先写入现有状态机。兼容的 SQLite、builtin 和 etcd 后端在任何启动副作用前拒绝。新增 `docs/architecture/control-plane-startup.md`，说明管理面 `storage.Store` 仍需由外层启动器单独准备，当前 `cheesewaf serve` 仍保持 production fail-closed 和 temporary SQLite 路径。

验证命令：

- `gofmt -w internal/controlplane/startup.go internal/controlplane/startup_test.go`
- `go test ./internal/controlplane -count=1`
- `go test ./internal/controlplane -race -count=1`
- `go vet ./internal/controlplane`
- `git diff --check`

验证结果：`internal/controlplane` 普通测试、race 测试和 vet 均退出码 0；相关文件 diff 检查通过。本轮只交付启动编排接口和 contract 测试，没有接入真实 native-raft、完整管理面 PostgreSQL `storage.Store` 或 `cheesewaf serve`。

遗留风险：真实生产启动单元仍需由外层打开完整管理面 PostgreSQL store，并把 native-raft 成员身份、领导选举、Redis 短租约、审计 outbox 和健康探针接入同一生命周期；不能把本轮 contract 测试当作生产控制面已经上线。

下一步：将真实适配器实现 `DurableBootstrap`、`ConsensusBootstrap` 和 `FenceBootstrap`，先在集成测试中证明迁移、快照恢复和重启后的 fencing，再评估接入 `cheesewaf serve`。

### 2026-09-08 RuntimeStore 单节点跨进程锁与状态原子性复核

范围：审计 `internal/crp.RuntimeStore` 的进程内互斥、跨进程并发提交、`state.json` 原子替换以及未引用 artifact 的 GC 风险。

实际改动：新增永久 `.runtime.lock` 哨兵和操作级、非阻塞内核 lease。Unix-like 使用 `flock(LOCK_EX|LOCK_NB)`，Windows 使用 `LockFileEx(LOCKFILE_FAIL_IMMEDIATELY)`；竞争时立即返回 `ErrRuntimeBusy`，不等待、不进入数据面。Stage/Promote/Rollback 在最终提交窗口重新读取并校验磁盘快照，再按插件 revision 做 CAS，避免不同进程以陈旧内存快照覆盖彼此状态。外部 revalidate、health 和 authorizer 回调仍在 lease 之外执行。

状态文件继续采用临时文件写入、文件同步、同目录原子替换和父目录同步；Windows 通过 `MoveFileEx(REPLACE_EXISTING|WRITE_THROUGH)` 适配。锁哨兵永不删除或替换，崩溃释放由操作系统句柄保证，不依赖 PID/时间型陈旧锁清理。当前不执行 artifact/metadata 自动 GC；未来回收必须在同一 lease 下按已提交快照计算可达集并提供恢复审计，不能把该本地锁当作跨节点 fencing。

验证命令：

- `go test ./internal/crp -race -count=1`
- `go vet ./internal/crp`
- `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go test -c ./internal/crp -o /tmp/crp-windows-test.exe`
- `git diff --check -- internal/crp docs/architecture/crp-contract.md tasks.md`

结果：上述测试、vet、Windows 交叉编译和 diff 检查通过；跨进程 helper 回归确认竞争立即 fail-closed，stale-store 回归确认不同插件状态不会丢失。

遗留风险：RuntimeStore 仍是单节点本地状态层；没有透明/耐久审计、PG/native-raft、真实安装/sidecar 生命周期、跨节点 fencing 或网络文件系统锁验收。不得据此宣称生产集群安装已完成。

### 2026-09-08 严格身份与角色文档同步

范围：同步根仓库架构契约与 CheeseSec_Docs 中用户管理、CLI、API、初始化和统一管理入口的身份约束，确保文档不暗示服务端会静默修剪或归一化身份输入。

实际改动：补充用户名 3–32 个 ASCII 字符、首尾字符和允许字符规则，明确 Unicode 空白、控制字符（Cc）及格式/不可见字符（Cf）在用户名和操作者身份中均拒绝；补充用户 role 必须精确匹配 apisec.permissions 配置键，拒绝空值、未知角色、权限表达式及上述空白/控制/Cf 字符，不使用 TrimSpace 或大小写转换。API 文档记录 USERNAME_INVALID/ROLE_INVALID 与历史账号边界；历史脏用户名统一按不可变用户 ID 使用 cheesewaf user repair-username USER_ID NEW_USERNAME --reason '...'，保留凭据、角色和 TOTP 状态并在事务中撤销 Session、追加审计。

验证命令：

- CheeseSec_Docs：hugo --gc --minify（英文 106 页、中文 104 页）
- CheeseWAF：git diff --check
- CheeseSec_Docs：git diff --check

结果：Hugo 构建与两个仓库的差异检查均退出码 0；只修改文档和本任务记录，未改变运行时代码。

### 2026-09-08 控制面/RuntimeStore/credential epoch 收口回归

本轮完成：控制面生产启动编排 contract（PG durable → native-raft → 双快照 → fencing → Ready，失败冻结并保留 last-known-good）；RuntimeStore 跨进程非阻塞锁、最终窗口磁盘重载与 revision CAS；用户凭据 epoch 在安全字段变更、Session 创建/轮换/撤销之间的事务校验。严格角色输入拒绝空白、控制和不可见字符，避免 `" admin "` 绕过管理员保护。

验证：`go test ./... -count=1`、`go vet ./...`、`gofmt -l cmd internal`、`git diff --check` 均通过；CRP race/vet、控制面 race/vet、身份/API/存储定向测试通过，Windows CRP 交叉编译通过。

边界：控制面和 RuntimeStore 仍主要是 contract/本地状态接线，真实 cheesewaf-control、PG management `storage.Store`、native-raft 集群生命周期、Redis、CWEDP/NetLease transport、ApprovalGate HTTP/UI、KMS 和耐久审计尚未形成一个生产启动单元；不得把本轮测试宣称为完整 HA/商店/OTA 交付。

### 2026-09-08 商业运行时第二批实现

本批新增并完成包级验证：

- 完整 PostgreSQL management `storage.Store`，覆盖站点、规则、用户、严格角色、credential epoch、Session、评审、通知、TOTP、防重放和用户名修复；真实 PG 集成测试通过 `CHEESEWAF_POSTGRES_TEST_DSN` 显式启用，当前环境未提供 DSN，因此不记作真实数据库证据。
- HashiCorp Raft + Bolt 的 native-raft adapter，覆盖稳定 NodeID、bootstrap、join-only、显式 AddVoter、提交复制、重启恢复和旧 term fence 失效。
- Redis RESP2 runtime adapter，覆盖实例身份、epoch、短 lease/lock、黑名单、缓存和有界本地回退；Redis 仍不是持久真相。
- CWEDP file/HTTP pull transport，覆盖来源注册、Range 续传、HELLO/CAPABILITIES、mTLS/证书指纹接口、三摘要、来源隔离/切换和离线来源限制。
- CRP sidecar activation service，按 observe → canary → active 运行，失败保留 staged/current；回滚只允许精确 last-known-good previous，并继续执行 trust、revocation、confirmation 和 fence 检查。
- Approval HTTP Gate，服务端持有 10 秒告警起点、Session/本地来源和 scope/intent/epoch/TTL/nonce，密码/TOTP verifier 在锁外调用，高风险需第三次确认，并发只能生成一个 commit。
- TokenService、严格 Token 身份边界、180 天无活动清理、policy epoch 二次校验、持久化幂等和 deny-only Redis cache；永不过期仍要求注入强确认 Gate。
- 诊断信封加密、本地持久队列、统一审计 journal/outbox/spool、KMS/keyring/2-of-3 恢复 contract，以及 single-node/production/full Ansible/Pigsty 交接剧本。

本批新鲜验证：`go test ./internal/controlplane/... -race -count=1`、`go test ./internal/storage/... -race -count=1`、`go test ./internal/cwedp/... -race -count=1`、`go test ./internal/crp/... -count=1`、`go test ./internal/diagnostics/envelope ./internal/diagnostics/queue -race -count=1`、`go test ./internal/api/handler ./internal/api/middleware ./internal/tokens/... -race -count=1`、相关 `go vet` 和 `git diff --check` 通过。前端 `npm test` 为 70 个文件/462 个测试，typecheck、`npm run build`、Get Started static/smoke、CI 静态门禁和 Hugo EN106/ZH104 均通过。

验收矩阵当前为 10 项通过、3 项显式失败、0 项跳过。失败项是临时→生产迁移与 Session 失效的端到端接线、CRP activation 的 CLI/服务挂载、临时联网确认的生产 Session/网络 enforcement。独立 `cheesewaf-control` 二进制仍在实现中；主 `cheesewaf serve` 的 production profile 在完整启动单元接好前继续 fail-closed。

### 2026-09-08 独立控制面入口与身份边界复核

新增 `internal/controlplane/runtime` 和 `cmd/cheesewaf-control`：入口严格要求 production、PG DSN、显式 Raft 模式、loopback 管理/raft 地址和严格身份；`/healthz`、`/readyz`、`/status` 不返回 DSN；未 ready 的写请求返回 503。当前入口把 PG control state、native-raft 和 Bootstrap 接在一起，但首次空集群初始化与主 `cheesewaf serve` 的 production management store 仍未自动切换，故不能宣称完整 HA 已上线。

Token 身份复核同步到 API 和 middleware：Name/Notes 作为展示文本保留原值；Token ID、Owner、Tenant、Scope/Permission、Confirmation ID、Prefix、Hash 和 Secret 拒绝 Unicode 空白、控制字符和不可见格式字符，不使用 `TrimSpace` 静默改写；Bearer 协议只解析 ASCII 空格分隔，凭据内容原样保留。KMS 恢复测试改为带恢复凭证的 `RecoverWithCredential`，无凭证 `Recover` 继续 fail-closed。

验证：控制面 runtime/CLI race、vet、diff-check 通过；Token API/middleware/tokens race、vet 通过；KMS race、vet 通过；前端 70 个测试文件/462 个测试、typecheck、生产构建、Get Started 和 CI 静态检查通过。CheeseSec_Docs 最新 Hugo 为 EN108/ZH106。

控制面入口新增：`cmd/cheesewaf-control` 只在明确 production 配置、PG DSN、loopback 管理/raft 地址和 bootstrap/join 模式下启动；健康、就绪、状态接口不暴露 DSN，未 write-ready 时 proposal 固定 503。该入口目前只承载控制面状态服务，首次空集群初始化和主 `cheesewaf serve` 的 production management store 切换仍未自动化；运行时与 native-raft 复用同一 StateMachine，失去 leader 或进入 freeze 时动态降为不可写。

### 2026-09-09 ApprovalHTTP 路由挂载边界

范围：把已有严格 ApprovalGate HTTP contract 接入主 API 的可注入边界，避免“实现了 handler 但生产路由完全不可达”，同时不把未完成的审批服务伪装成可用。

实际改动：`api.Options` 新增可选 `ApprovalHTTP`；主管理 API 仅在显式注入时注册提交、告警开始和确认三个端点，并继续经过 management authentication、RBAC 和审计中间件。`approvalSessionFromRequest` 拒绝 `api_token`/`api-token:*` 身份，交互式密码/TOTP 确认只能来自真实 Session。生产启动依赖新增可选 `ProductionApprovalDependency.ApprovalHTTP()` 边界，`runServe` 只转发该已验证 handler；默认 factory 不实现，仍在 listener 绑定前 fail-closed。

验证命令与结果：

- `GOCACHE=/tmp/cheesewaf-gocache go test ./internal/api ./internal/api/handler -run 'TestApprovalHTTP|TestRouter.*Approval|TestRouterRequiresBearer' -count=1`：退出码 0。
- `GOCACHE=/tmp/cheesewaf-gocache go test ./internal/api ./internal/api/handler -race -count=1`：退出码 0；API 178.078s，Handler 85.730s。
- `gofmt -w internal/api/router.go internal/api/router_test.go internal/api/handler/approval_http.go internal/cli/service.go internal/cli/serve_production.go`：已执行；`git diff --check` 待本轮其他改动收口后重跑。

边界：默认 production factory 仍没有真实 PG-backed ApprovalGate、密码/TOTP verifier 和耐久审批账本；因此这次是可注入路由接线，不是完整生产审批上线。临时→生产迁移、CRP activation/rollback、临时联网 enforcement 等验收失败项仍然保留，不能改成通过。

### 2026-09-09 Redis runtime fail-closed 回归修复

范围：复核 Redis 短状态适配器在协议错误、调用方取消、并发关闭、typed-nil 依赖和超长 RESP 行上的失败语义。

实际改动：RESP 未终止且超过上限的行现在归类为 `ErrProtocol`；`GetCache` 只对可用性/未知实例做明确 cache-miss 降级，协议、输入和调用方取消错误原样 fail-closed；`NewWithClient` 拒绝 typed-nil client；`Refresh` 在 PING/身份读取和最终状态写入前后检查关闭状态，防止 Close 后状态复活；生产身份输入继续拒绝 Unicode 空白和不可见字符。

验证命令与结果：

- `GOCACHE=/tmp/cheesewaf-gocache go test ./internal/cluster/redis -race -count=1`：退出码 0。
- `GOCACHE=/tmp/cheesewaf-gocache go vet ./internal/cluster/redis`：退出码 0。
- `git diff --check`：待本轮文档和其他并行改动统一收口后重跑。

边界：Redis 仍只承担短期租约、锁、黑名单和缓存；没有提升为 PG/native-raft 真相，也没有改变主 `serve` production 默认审批/完整消费者未接线的 fail-closed 状态。

### 2026-09-10 临时 PostgreSQL 验收与恢复边界补强

范围：使用隔离的临时 Debian 13 主机验证真实 PostgreSQL/Redis 安装边界，修复真实 PostgreSQL 回归暴露的 diagnostics Cancel 状态错误，并补齐 temporary→production 迁移的 v1 ledger 兼容边界。

实际改动：

- 临时服务器只安装 PostgreSQL 17.11、Redis 8.0.2；两者保持 loopback 监听，没有开放公网数据库端口。测试库使用无超级用户、无建库、无建角色权限的独立账号，凭据不写入仓库。
- `internal/diagnostics/postgres` 的 `Cancel` 不再把 canceled 状态误传入来源参数；现在只允许显式取消迁移，拒绝 terminal/canceled 重复迁移，严格拒绝空白/控制/Cf upload ID 和 worker，并检查取消 UPDATE 必须影响一行。
- `internal/cli/migration` 把 v1 ledger 的全零 Token 摘要建模为 `unverified-v1`，返回 `ErrCutoverTokenMetadataUnverified` 与 `ErrCutoverAmbiguous` 的组合错误；新增真实 PostgreSQL 门控测试，覆盖 v1→v2 ALTER 后 fail-closed、v2 management/token exact match 和事务回滚无残留。
- `internal/cwedp/transport` 的在线 OTA、Seed、Peer 统一强制 CA、客户端证书/私钥、预期 NodeID、leaf fingerprint 和响应握手绑定；source kind 重标不能降低 TLS 身份校验。该结论由独立 Terra 静态审查复核。
- `temporary-online probe` 在返回、传输失败和审计失败时都会显式关闭临时 session、撤销一次性 lease；它仍是一次性 CLI，不会启动后台网络 worker。
- AI provider 模型发现和 JSON 运维端点增加最多一次、最多 2 秒的 429 重试；定向测试和生产 Web 构建通过，完整 AI httptest 回归仍需授权环境。
- AI provider 元数据 GET 现对 429/503 都只重试一次，覆盖 Retry-After 边界、取消、body close 和 GET-only 约束；`internal/ai` 完整普通/race/vet 已通过。
- ApprovalGate 增加可选 durable persistence、部分写入失败回滚、ListIDs/Restore 和完整事件绑定校验；PG adapter 会核对 JSON hash 与数据库 `event_hash`。默认 production opener 仍拒绝无真实 verifier/provider，未接入主 `serve`。

验证证据：

- 真实 PostgreSQL 17.11：`internal/storage/postgres`、`internal/controlplane/postgres`、`internal/tokens/postgres`、`internal/cwedp/postgres` 的首次集成回归通过；diagnostics 首次暴露 Cancel 状态为空，修复后真实 PostgreSQL Cancel 回归、普通测试、race 和 vet 均通过。
- 迁移包：`go test ./internal/setup/migration ./internal/cli/migration ./internal/controlplane ./internal/controlplane/postgres ./internal/storage/postgres -count=1`、对应 `-race`、`go vet`、`gofmt -l` 和 `git diff --check` 均通过。
- diagnostics：`go test ./internal/diagnostics/...`、对应 `-race`、`go vet` 均通过。
- CWEDP/NetLease：无端口定向测试、普通/race/vet（无法绑定 loopback 的测试明确记录为沙箱限制）和静态安全审查；未把这部分证据扩展为主 `serve` 或生产节点编排已完成。
- 最终全仓 Go 回归：在允许 loopback 的受控环境运行 `GOCACHE=/private/tmp/cheesewaf-go-full-final go test ./... -count=1`，全部包通过；语义引擎约 316 秒。此前 fresh data dir 失败已修复并由该回归覆盖。
- 最新 NetLease 生命周期改动后的增量验证：`go test`、`go test -race`、`go vet` 覆盖 `internal/cli`、`internal/cwedp/transport`、`internal/netlease` 均通过。
- 在 NetLease 生命周期改动之后重新执行的全仓编译扫描 `GOCACHE=/private/tmp/cheesewaf-all-compile-final go test ./... -run '^$' -count=1`、全仓 `go vet ./...`、`gofmt -l cmd internal` 和 `git diff --check` 均通过；变更包完整 race 也均通过。
- Approval/PG 变更后的普通、race、vet 和格式检查通过；持久 Gate 仍需后续真实 PostgreSQL adapter 恢复/篡改集成测试与 production service wiring，不能据此宣称审批服务已上线。
- Web：70 个测试文件、465 个测试、`npm run typecheck`、`bash scripts/ci/build-web.sh`、预算和产物边界扫描通过。
- 验收脚本：`python3 -m unittest discover -s scripts/acceptance -p '*_test.py'`、`bash scripts/acceptance/acceptance-matrix_test.sh` 通过；static matrix 生成 14 通过、8 失败、0 跳过。失败项均保留为环境限制或未接线 blocker，没有改成 skipped。

遗留风险：主服务仍未挂载完整 migration/CRP/CWEDP/NetLease/Approval/Token 生产生命周期；CheeseSec 外部仓库仍保留各自的其他脏改动，尚未提交或推送。

下一步：保留临时服务器作为后续 native-raft/完整服务接线环境；随后重新运行全量 Go/Web/Get Started/产物扫描，并继续处理主 `serve` 的 migration、CRP、CWEDP/NetLease 和 Approval/Token 生命周期接线。

### 2026-09-11 Approval 一致恢复与诊断交付补强

范围：继续收紧持久 Approval 的原子性/epoch 恢复边界，并修复诊断加密队列在 replay 与 worker 完成阶段可能丢失重试或吞掉错误的问题。

实际改动：

- Approval 持久层的多事件写入使用 `AtomicPersistence.ApplyBatch`；Memory adapter 在同一互斥锁内完成批次，PostgreSQL adapter 在同一事务内提交，失败不留下 durable 前缀。
- durable epoch 先拒绝回退，再执行 PostgreSQL CAS；checkpoint 缺失时不能用非零 expected 静默重建。外部 epoch 已推进时，陈旧 Gate 保持 fail-closed，必须按新代次显式重建。
- 新增 `EpochSnapshotPersistence.LoadWithEventsAtEpoch`。PostgreSQL 在一个只读 `REPEATABLE READ` 事务内读取 epoch、record 和事件链，避免恢复时跨提交拼接状态；旧 adapter 保留兼容回退。
- PostgreSQL 事件读取先区分 binding 冲突，再验证 sequence/previous hash/JSON hash/数据库 `event_hash`，篡改仍然拒绝。
- `internal/diagnostics/envelope` 明确为 canonical `diagnostic-envelope.v1`；根包旧 API 标注 legacy 且不承诺 wire/AAD/错误值互通。KEK 代次不可覆盖，同代次 rewrap 失败。
- 诊断 replay 使用 `Reserve`/`Commit`/`Release`：上传失败释放 reservation 允许重试，成功后提交，篡改不会占用身份。上传成功但 replay commit 失败时记录 `replay_commit` 失败审计，不自动重复外部副作用。
- 本地队列 worker 不再吞掉 `Complete` 错误；成功或失败结果无法持久化时写入 `WorkerError` 并停止继续领取任务。
- 验收矩阵新增 `diagnostics_runtime_delivery`，单独验证 broker→canonical envelope→持久队列→失败重试→metadata-only 审计组合链路，同时继续声明对象存储和外部回执未上线。
- 默认 production Approval opener 继续返回 `ErrProductionApprovalUnavailable`；没有真实 password/TOTP verifier、持久 Gate 服务和 AI destructive 适配接线时不挂载假服务。

当前验证证据：

- 通过 SSH 隧道连接隔离 PostgreSQL 17.11，`CHEESEWAF_POSTGRES_TEST_DSN` 门控的 Approval 普通与 race 集成测试通过，覆盖事件篡改、epoch 回退、checkpoint 缺失、CAS 冲突和 epoch+record+events 一致恢复。
- 同一 PostgreSQL 环境下 diagnostics 普通与 race 集成测试通过，覆盖幂等、claim、retry、cancel 和 outbox。
- `go test ./internal/diagnostics/... -count=1`、对应 `-race` 和 `go vet ./internal/diagnostics/...` 通过。
- replay commit 审计与 queue completion 定向普通/race 测试通过；`go vet` 通过。
- `go test ./internal/ai/... -count=1`、对应 `-race` 和 `go vet ./internal/ai/...` 在允许 loopback 的受控环境通过。
- `python3 -m unittest discover -s scripts/acceptance -p '*_test.py'` 与 `bash scripts/acceptance/acceptance-matrix_test.sh` 通过；允许 loopback 的 static matrix 为 19 通过、4 失败、0 跳过，失败项继续保留 migration/session、CRP activation/rollback 和 temporary-network 生产生命周期 blocker。
- 当前全仓 `go test ./... -count=1` 通过（semantic 约 340 秒）；全仓编译、`go vet ./...`、`gofmt -l cmd internal` 和 `git diff --check` 通过。
- Web 当前为 70 个测试文件、465 个测试通过；`npm run typecheck`、`bash scripts/ci/build-web.sh` 和 193 文件生产产物边界扫描通过。
- Get Started 的 `--static-contract` 与 `--smoke` 均通过，运行数据只写入临时目录并完成清理。

遗留风险：Approval 仍缺少生产 credential verifier、服务生命周期和 AI destructive consumer 接线；诊断运行时仍缺对象存储异步复制、签名目标回执、跨进程 replay guard 和主 `serve` 挂载；主服务的 migration、CRP、CWEDP/NetLease、Token/Approval 生产生命周期仍未全部接通。

下一步：先完成本轮全仓普通/race/vet、Web、Get Started、产物扫描和 static matrix 复验；随后以显式依赖注入方式实现 production Approval service，不能用 no-op verifier 或内存旁路换取启动成功。

### 2026-09-11 temporary-network、migration/session 与 CRP 服务端 transport 补强

范围：把 temporary-online 的本地实现从 CLI 私有编排提升为可复用的一次性 broker 生命周期，并补足迁移/session/fence 与 CRP 服务端 TLS 的仓内证据；不把外部控制面或 sidecar 部署状态写成已完成。

实际改动：

- 新增 `netlease.TemporaryHTTPExecutor` 与 `Broker.ExecuteTemporaryHTTP`，统一管理员 Session、再次密码确认、一次性 Socket Lease、TLS/HTTP 请求、结果审计和 lease/session 清理；CLI 已改用该入口。
- `Broker.Revoke` 将 terminal `revoked` 事件写入配置的 durable `AuditSink`，并对已成功落盘的撤销保持幂等；审计暂时失败时 lease 仍先撤销，后续调用可补写事件。
- 新增真实 loopback TLS 集成测试，验证一次 dial、`issued → connection_started → result → revoked` 审计顺序、完成/撤销状态和 Session 清理；新增撤销审计失败后的重试覆盖。
- migration/session 组合回归验证 invalidation 会递增 credential epoch、使旧 Session 失效、保留 pending fence，并在 rollback 后恢复 last-known-good；主 serve 仍要求完整 `ProductionDependencyFactory.WireServe`，缺依赖继续拒绝启动。
- CRP activation 增加 `NewControlPlaneServerTLSConfig`，强制显式 CA、服务证书链、TLS 1.3 和 `RequireAndVerifyClientCert`；补真实 loopback mTLS listener 测试和服务端挂载文档。CRP activation/rollback gate 仍因 durable AuthorizationState/provider/audit 与 sidecar launcher 未部署而 failed。
- acceptance temporary-network 正向证据纳入 `ExecuteTemporaryHTTP` 生命周期测试，但 `implemented:false` 保持不变；没有为追求分数而改 gate。

验证证据：

- `go test`、`go test -race`、`go vet` 覆盖 `internal/netlease`、`internal/cwedp`、`internal/cwedp/transport`、`internal/cli` 通过（loopback 在受控权限环境执行）。
- migration/session、CRP server TLS 的定向普通/race/vet 通过；全仓 Go 普通回归、编译、vet、gofmt 和 diff check 继续通过。
- 允许 loopback 的 acceptance static matrix 为 19 通过、4 失败、0 跳过；失败准确对应 migration/session 主服务接线、CRP activation、CRP rollback、temporary-network 生产生命周期。

遗留风险：主 `serve` 尚未注入可创建 broker、验证可撤销 Management Session、把 lease 传给 CWEDP 的生产插件控制器；CRP 仍缺 durable authorization provider/state/audit 和 sidecar launcher；temporary-to-production 完整启动单元、对象存储/外部回执和空网演练仍未完成。

下一步：在同一生产 launcher 内接入这些显式依赖，优先以隔离端到端演练证明 Session、lease、fence、sidecar、审计和回滚的共同生命周期，再考虑修改 acceptance implemented 状态。

### 2026-09-11 Approval runtime 与 Dependabot/CodeQL 复核

Approval runtime 的真实组合根为 `internal/approval/runtime`，覆盖 management store health、真实 approval PG ledger、epoch checkpoint/restore、bcrypt/TOTP、ApprovalHTTP 和 PolicyEpoch。生产依赖使用强类型 `ProductionApprovalDependency`；nil、zero 或 mismatch epoch 在 `WireServe` 前均 fail-closed。

Approval 写路径新增 epoch-guarded persistence；PG `Apply`/`ApplyBatch` 在同一事务内锁定 epoch。真实 PG ordinary/race 验证通过，使用临时 SSH 转发和临时 schema；DSN、密码等凭据不写入交接记录。

`TOTPStore` 新增原子 `ConsumeTOTP`，SQLite/PostgreSQL 以及登录/Approval 路径均使用该入口；真实 PG TOTP atomic test 通过。旧 `Mark`/`Is` 仅保留为兼容路径。

当前仍未解除主 serve 的 `WireServe`、CRP provider/state/audit/sidecar、temporary-network production lifecycle 等 blocker。Approval 已新增 canonical role helper 和显式 authority resolver：默认只允许 `admin` 普通审批，`security_admin` 和带精确 tenant scope 的 `tenant_owner` 只有在调用方显式配置后才可能获得 Break-glass 权限；主配置、持久角色和生产 consumer 仍未把这条能力接入。既有 acceptance implemented 标志保持不变。

Dependabot/CodeQL 复核结果：

- CheeseSec_Docs 无开放 PR。
- CheeseSec_Plugin 的 #1/#2/#3/#5/#6/#7 checks 通过并已完成仓库所有者 review，但受 main protected branch 的 strict/code-owner/status policy 阻止正常 merge；没有使用管理员权限绕过。#4 validate 失败，原因是 referencing `0.37.0` 引入未 hash-pinned 的 `typing-extensions`，已留言并标记需要修改。
- CheeseSec_Plugin_Docs 的 #1/#2/#5/#6 checks 通过并已 review，但同样受保护规则阻止正常 merge；#7 与 Plugin #4 相同，因未 hash-pinned `typing-extensions` 验证失败，已标记需要修改。
- 主 CheeseWAF 的 #422/#423/#424/#425/#428/#429 CodeQL+CI 全绿，可排队；#426/#427 因 Vitest peer/CI 失败 hold；#430 因 branch-flow 失败 hold，并已留言。
- 本轮没有声称任何 PR 已合并，也没有绕过保护规则。

验证证据：

- `GOCACHE=/private/tmp/cheesewaf-compile-after-approval-20260911 GOPROXY=off GOTOOLCHAIN=local GOWORK=off go test ./... -run '^$' -count=1` 通过。
- Approval/PG/TOTP real integration commands 通过。
- 沙箱 broad package run 中的 httptest IPv6/DNS 失败属于环境限制，不作为代码回归失败或生产完成证据。

### 2026-09-11 文档门禁与未初始化预览部署

文档和交接更新后重新触发门禁：

- 主仓 `python3 -m unittest discover -s scripts/acceptance -p '*_test.py'`、`bash scripts/acceptance/acceptance-matrix_test.sh`、`bash scripts/ci/verify-ci-static.sh` 和 `git diff --check` 通过。CI static 输出中的 `::error::` 行来自脚本自带的负向用例，最终门禁明确报告通过。
- 受控 static matrix 为 19 passed、4 failed、0 skipped；失败仍是 `switch_migration_session_invalidation`、`crp_activation`、`crp_rollback` 和 `temporary_network_confirmation`，没有修改 `implemented` 标志。
- Approval authority、role、Break-glass 相关普通测试、race 和 vet 通过；普通 `admin` 不会被提升为 emergency authority，未显式配置的 `security_admin`/`tenant_owner` 继续拒绝。
- 当前工作树在角色切片落地后重新执行 `go test ./... -run '^$' -count=1` 与 `go vet ./...`，全部包通过；`gofmt -l cmd internal` 和全仓 `git diff --check` 无输出。
- Web `npm test -- --run` 为 70 个测试文件、465 个测试通过；测试输出中的预期 ErrorBoundary `boom` 与 jsdom/localStorage 警告没有造成失败。
- CheeseSec_Docs Hugo 构建通过，EN 108 / ZH 106；CheeseSec_Plugin_Docs 的 workflow/schema/link/commercial/offline/test/secret-scan 门禁通过；CheeseSec_Plugin 的 workflow/schema/commercial/offline/15 项测试/secret-scan 门禁通过。
- 生产 Web 构建使用 `npm ci --ignore-scripts`，完整 dist 产物边界扫描与预算检查通过；随后生成 Linux amd64 preview 包，SHA-256 为 `4882c58abbd64d89005076de39180ea904f0b70a621ae1a6af577ae08df65279`。

隔离测试服务器此前没有 CheeseWAF 二进制、目录、systemd 单元或监听器。预览部署使用独立的 `cheesewaf-preview` 系统用户、`/opt/cheesewaf-preview`、`/etc/cheesewaf-preview`、`/var/lib/cheesewaf-preview`、`/var/log/cheesewaf-preview` 和 `cheesewaf-preview.service`；未修改现有 PostgreSQL 17.11 或 Redis 8.0.2，两者仍只监听 loopback。

在 2026-09-11 的受控 SSH 复核中，预览服务曾处于 active 且未启用开机自启。代理和管理端分别只监听服务器 `127.0.0.1:18080` 与 `127.0.0.1:19443`。当时 `GET /api/setup/status` 返回 `needs_setup: true`，`.setup_complete` 不存在，`setup.url` 权限为 `0600`，所以那次复核确认服务处于刚部署、尚未提交设置向导的状态。该状态依赖临时服务器进程，不代表进程会长期保留。本轮复核已恢复本机 SSH 隧道，`GET /api/setup/status` 再次返回 `needs_setup: true`，所以当前可以通过 `http://127.0.0.1:19443/setup` 查看设置向导。这个地址只在本机隧道存活时有效，不是公网预览地址；当前隧道没有转发数据面 `127.0.0.1:18080`。

回滚边界：停止并禁用（当前本就未启用）`cheesewaf-preview.service`，删除该独立 unit 与四个 preview 目录即可；正式 CheeseWAF 路径、数据库服务和其他系统服务不在本次预览部署范围内。

### 2026-09-11 安装档位与文档事实同步

范围：同步安装向导、资源档位、管理面默认监听、生产 profile 状态和 CheeseSec_Docs 的 Cloudflare Pages 构建参数。

已核对源码事实：探测最长 30 秒；逻辑核数不超过 2、内存不超过 2048 MB 或磁盘写入测试不通过时推荐 `low`；探测超时、取消或 Web 请求失败时回退 `low`。`medium` 需要至少 3 个逻辑核和 4096 MB 内存；`high` 还需要至少 4 个逻辑核、8192 MB 内存和至少 50 MB/s 的顺序写入速度。主 WAF 的管理面默认监听 `127.0.0.1:9443`，`storage.profile: production` 在完整生产启动接线完成前继续拒绝，不会回退到 SQLite。

CheeseSec_Docs 的 Pages 参数固定为生产分支 `main`、构建命令 `hugo --gc --minify`、输出目录 `public`、根目录 `/`、`HUGO_VERSION=0.165.0`、`GO_VERSION=1.26.6` 和 `SKIP_DEPENDENCY_INSTALL=1`；Preview 构建可显式传入 `--baseURL "$CF_PAGES_URL"`。

### 2026-09-11 安装向导 UI 与 Beta 版本准备

- 安装向导 Logo 改为透明无边框显示，保留原图比例；面板宽度和标题区间距已调整。
- 向导步骤改为 7 段鱼骨进度条。桌面端显示步骤名称，窄屏保留图标并显示当前步骤文字；320 px 视口无横向溢出。
- 环境检查行采用「状态与标签 / 数值」两列布局，避免 `MB/s` 和磁盘标签被拆开。
- 2 核 / 2 GB 主机推荐 `low`（轻量）；档位页提供「选择方案」按钮。选择高于或低于本机建议的档位只提示 warning，仍可继续。
- 前端 42 项定向测试、类型检查、生产构建和 marker scan 通过；1280 px、390 px、320 px 假数据浏览器验收通过。
- 产品版本源已更新为 `0.3.9`，并创建了指向 master 提交的 `v0.3.9` tag。稳定版 GitHub Release 尚未生成：tag 工作流在 Windows Authenticode 校验阶段因 `WINDOWS_CERT_P12` 未配置而失败。自动生成的 Alpha 预发布记录不等于稳定版发布。商业化架构中尚未接线的验收项继续按现状记录，不因创建 tag 改写状态。

### 2026-09-11 发布复核与外部依赖

范围：复核 master 晋升、`v0.3.9` tag、Dependabot 告警、插件文档 PR、Cloudflare Pages 构建和临时预览服务状态。

实际结果：

- CheeseWAF 已按 `dev → canary → master` 顺序晋升。master 提交为 `cc96e2d8bad9a1378a73711e3c3e5039d56bccd7`，`v0.3.9` tag 指向同一提交。
- master 的三平台测试、CodeQL、Web 构建、跨平台编译、发行物构建和 macOS DMG 构建均通过。
- tag 工作流 `34651525489` 的 `release-artifacts` 在验证 `cheesewaf-amd64-windows-0.3.9-setup.exe` 时报告 `No signature found`，同时记录 `WINDOWS_CERT_P12` 为空。该工作流没有创建稳定版 GitHub Release。
- Dependabot #23 和 #24 已变为 `fixed`。Hono `4.13.7` 已进入 master 的 `web/package-lock.json`；旧 PR #430 已关闭。
- CheeseSec_Plugin_Docs PR #7 的 `handbook-checks / validate` 已通过，但 main 分支仍要求独立 code-owner 审批。PR #8 与 #7 使用同一提交，已关闭为重复 PR。
- CheeseSec_pages 的 CI 构建已通过，但工作流因缺少 `CLOUDFLARE_API_TOKEN` 和 `CLOUDFLARE_ACCOUNT_ID` 跳过部署。当前不能把文档构建写成 Cloudflare 已发布。

验证证据：

- `gh run view 34649209066`：master CI 完成且成功。
- `gh run view 34649209055`：master CodeQL 完成且成功。
- `gh run view 34651525489 --job 103437836071 --log-failed`：稳定发行物校验因 Windows Authenticode 无签名失败。
- `git rev-parse v0.3.9^{}`：结果为 `cc96e2d8bad9a1378a73711e3c3e5039d56bccd7`。
- `gh api repos/LaokeQwQ/CheeseWAF/dependabot/alerts`：告警 #23、#24 均为 `fixed`。
- `gh pr view 7 --repo LaokeQwQ/CheeseSec_Plugin_Docs`：检查成功，状态仍为 `BLOCKED`。
- 临时服务器只读探测：本轮本机 SSH 隧道的 `http://127.0.0.1:19443/setup` 返回 HTTP 200，`GET /api/setup/status` 返回 `needs_setup: true`；公网端口探测仍未形成可用入口，没有执行远程修改。

历史结论（已被 2026-09-12 的服务器优先策略取代）：当时工作流仍把 Windows 和 macOS 签名凭据作为稳定发布条件。插件文档 PR 仍需要独立 code-owner 审批；Cloudflare Pages 部署仍需要 Cloudflare 凭据。阶段 1 至阶段 7 中列出的主服务生产接线、CRP 控制面、CWEDP 节点编排、对象复制和空网演练仍未完成，不能把当前 tag 或构建结果写成商业化架构全部交付。

历史行动项（已被取代）：不再补齐桌面签名凭据后重跑旧 tag。当前做法是先把服务器优先工作流晋升到 `master`，确认旧 tag 尚未产生 GitHub Release，再在受保护的 `master` 当前提交上重新创建 `v0.3.9`。插件文档和 Cloudflare Pages 的外部依赖，以及主服务生产接线和端到端演练，仍按各自未完成项继续处理。

### 2026-09-12 服务器版稳定发布策略修正

前一节记录的是 2026-09-11 当时的工作流状态。经过同类服务器 WAF 的发行方式复核，Windows Authenticode 和 macOS Developer ID 不再作为 CheeseWAF 服务器版稳定发布的前置条件。Windows 与 macOS 包仍可由完整档位的分支或手动工作流生成，但它们属于可选的操作端构建。

本次改动：

- 新增 `scripts/ci/release-targets.sh`，`CHEESEWAF_RELEASE_PROFILE=server` 默认只生成 Linux x86_64、Linux ARM64 和 Linux LoongArch64；`full` 继续保留原来的七个平台目标。
- `vMAJOR.MINOR.PATCH` 标签在 `.github/workflows/ci.yml` 中使用 `server` 档位，跳过 macOS DMG 任务，不再下载桌面产物。
- `scripts/ci/verify-release.sh` 新增 `CHEESEWAF_SIGNING_SCOPE=server`，继续检查归档、校验和、元数据和内容，不检查桌面平台证书。
- `scripts/ci/publish-prerelease.sh` 按实际存在的文件生成发布说明，不再列出不存在的 Windows 或 macOS 包。
- GitHub 和 Forgejo 的 actionlint 改用固定版本、带摘要校验的 `scripts/ci/run-actionlint.sh`。原来的 Go 包入口 `github.com/rhysd/actionlint/cmd/actionlint@v1.7.7` 在当前版本不存在，已一并修正。
- 标签、事件类型等 GitHub 上下文先通过环境变量传入 shell，稳定标签再按精确语义版本格式判断，避免把可控 ref 名直接插入 Bash。
- `server` 档位和稳定发布器都拒绝 Windows、macOS、DMG 等桌面发行物；Forgejo 的分支/手动构建不再接收 Windows 签名凭据。
- 稳定发布目录采用显式白名单，只允许三份 Linux 归档、校验和、SBOM 和对应的 Sigstore bundle；未知扩展名或远端已有的额外资产都会使发布失败。
- 三份 Linux 归档内的 `VERSION` 与 `release.json` 必须和发布清单使用相同的版本与 40 位提交 SHA。文件名正确但内部元数据错误时，检查会失败。
- 稳定标签必须同时匹配 `scripts/ci/product-version` 并指向受保护的 `master` 当前提交。发布前还会通过 GitHub API 解析远端标签；带注释的标签会继续解析到最终提交。标签缺失或提交不一致时，不会创建或上传 Release。
- 稳定版的 Sigstore 身份精确绑定当前标签。已有稳定 Release 只做下载和校验，不会重新生成 SBOM、替换文件或改写说明。
- GitHub `publish-release` 环境已配置必需审批和自定义部署策略，只允许 `v*` 标签进入。仓库目前只有一名管理员，因此暂时允许该管理员审批自己的发布；每次审批仍会留在 GitHub 的部署记录中。
- 中英文 README 与 `docs/acceptance-matrix.md` 已改为服务器优先的发行说明。前一节关于“稳定发布仍需要 Windows 和 macOS 签名凭据”的判断只保留为历史证据，不再作为当前服务器版发布条件。

验证证据：

- `bash scripts/ci/package-release_profile_test.sh` 通过。
- `bash scripts/ci/verify-stable-tag_test.sh` 通过，覆盖版本不符、非 `master` 当前提交和恶意 ref 名。
- `bash scripts/ci/verify-release_test.sh` 通过，包含 Windows/macOS 严格签名的原有负向用例，以及归档内部版本或提交不一致时必须失败的 `server` 用例。
- `bash scripts/ci/publish-prerelease_test.sh` 通过。Linux-only 稳定说明不再列出桌面包；远端标签缺失、标签提交变化、错误 Release 目标和额外远端文件都会失败。测试还会直接执行发布说明里的 Sigstore 命令，防止换行符错误。
- `bash scripts/ci/run-actionlint.sh -shellcheck= -pyflakes= -color .github/workflows/*.yml` 通过。
- `bash scripts/ci/verify-ci-static.sh` 通过。
- 使用 `CHEESEWAF_RELEASE_PROFILE=server CHEESEWAF_REF_NAME=v0.3.9` 实际打包，得到 3 个 Linux 归档，没有生成 Windows、macOS 或 DMG 文件；`CHEESEWAF_REQUIRE_SIGNING=1 CHEESEWAF_SIGNING_SCOPE=server` 的静态发行物检查通过。

2026-09-12 提交前交接状态：改动位于 `codex/beta-v0.3.9-ui-docs` 工作树，尚未晋升到 `master`，也没有重新创建稳定版 Release。执行时必须先提交并通过主仓库 CI、CodeQL 和发布检查，再按现有分支流程晋升并重新触发 `v0.3.9` 稳定发布。CRP、主服务生产接线、插件文档 code-owner 审批和 Cloudflare Pages 凭据等其他遗留项不因本次发布策略修正而自动完成。

### 2026-09-15 产品范围收敛与未来功能清单

共享建议用于调整实施顺序，不替代已经确认的 1–133 项架构决策。当前优先验证单节点的安装、站点接入和留观模式，再验证可解释日志、本地备份恢复、升级回滚和长期运行。生产模式继续要求 PostgreSQL 和 native-raft，不会改成 SQLite 或静默回退；没有部署验证的集群、CRP、CWEDP 和外部控制面继续记录为未完成。

以下能力列入未来功能，不作为当前版本的交付条件：

- 执行沙箱和独立留观区的工作流扩展。
- 整体快照、站点快照和按快照恢复。
- 自动任务的统一编排和定时巡检扩展。
- S3 兼容对象存储备份。
- AI 余额的持续检测与告警。
- 情报大屏优化。
- 通用回调和 Webhook。
- 飞书、微信、QQ、Telegram 机器人插件。

这份清单不移除已经实现的调度器、AI 余额查询或请求复核能力。未来功能必须复用现有的权限快照、审批、审计、加密和恢复约束。实现前先补需求、数据保留、失败恢复和验收证据，不能用占位接口替代可运行能力。`v0.3.9` 的非 Pre-release 属性和现有稳定标签保持不变。

### 2026-09-15 授权快照修复与部署检查

CRP 修复已应用到当前工作区，没有覆盖既有 AI 和 OTA 改动。`cloneDescriptor` 保留并复制 metadata；客户端 pending 授权和 `MemoryAuthorizationState` 的 Put/Get 复制 confirmation、capabilities 和 metadata。修改输入或返回值不能改变已保存的授权。被修改的授权在远程验证前拒绝，原始 confirmation 仍能一次性消费。

修复先在远端 `dev=12a24aa037bf8f5eb3d0df81a20a98bc8ecf68d6` 的独立副本完成。新增回归测试有 RED/GREEN 证据，独立 Sol 审阅没有 Critical/Important 问题。本地分支 `codex/crp-authorization-snapshots` 保存提交 `ac62f390712ee978617ee815d9e2a61e4faef102`。当前工作区的对应修改仍未提交，本轮没有推送或晋升。

当前工作区验证：

- `go test ./... -count=1 -timeout=600s` 通过，语义检测包耗时约 303 秒。
- CRP 和 CLI 普通回归、CRP race、`go vet` 与 `git diff --check` 通过。
- Get Started `--smoke` 通过。运行数据使用临时目录，生产模式拒绝不完整依赖，清理完成。
- `bash scripts/ci/verify-ci-static.sh` 通过。输出中的预期错误来自负向用例，没有实际发布资产。
- 当前 static matrix 为 19 通过、4 失败、0 跳过。失败仍为 `switch_migration_session_invalidation`、`crp_activation`、`crp_rollback` 和 `temporary_network_confirmation`；`implemented` 标志未修改。

Pages 验证：`npm ci --ignore-scripts`、51 项测试、typecheck、7 页静态构建和产物边界检查通过，npm audit 为 0。Cloudflare provider 已保存构建命令 `npm ci --ignore-scripts && npm run build && npm run check:artifacts`，并设置构建变量 `SKIP_DEPENDENCY_INSTALL=1`，未修改生产分支、API Token 或运行时 Secret。

Cloudflare build `f9bc2d3d-730c-4839-a094-4e838760cd68` 已验证新设置。静态构建和产物扫描成功，版本上传仍因 `cheesesec-publication-index-prod` 不存在返回 `10085`。R2 控制台要求开通按量计费订阅并接受条款，已交给账号持有人手动处理。执行代理没有点击订阅、创建凭据、开放公开访问或启用新的 Worker 版本，不能宣称线上接线已完成。

PR/发行状态复核：主仓库没有开放 PR；Plugin #8 和 Plugin_Docs #9 的 validate 通过，但仍要求独立 code-owner 审阅，未绕过保护规则。`v0.3.9` 仍是非 draft、非 Pre-release 的正式 Beta Release，本轮没有改写版本、标签或发行记录。

macOS DMG 生命周期修复也已应用到当前工作区，并接入 `verify-ci-static.sh`。完整 fake 打包回归、shell 语法和静态检查通过；在本机 `Darwin` 上用两个临时 Mach-O 包生成 UDZO 镜像，再用真实 `hdiutil imageinfo`、attach 和 detach 验证通过。测试使用 ad-hoc 签名和 stub Finder，不代表 Developer ID、Finder 布局或 notarization 已验证。

剩余工作：耐久 CRP 授权/provider/审计和 sidecar 部署、主 `serve` 的生产消费者绑定、临时联网生命周期及离线端到端演练。当前快照和 DMG 修复不提供这些能力，本轮也没有新的真实 PostgreSQL 集成证据。

### 2026-09-21 恢复额度后的生产接线审计与测试服务器验证

本轮先按 `verification-before-completion` 重新核对工作树、生产组合根和隔离预览，没有把测试 seam 误报为生产能力。当前分支 `codex/cloudflare-pages-workers-plan` 相对远端为 ahead 10、behind 8；工作树仍包含未提交的 CRP 授权快照、生产 contract、OTA/AI、CI 门禁和文档改动。本轮没有推送、晋升、改写远端 Release 或创建新凭据。

真实验证结果：

- `go test ./... -count=1 -timeout=900s` 完成，全仓包均通过；语义检测包约 310 秒。另有 controlplane、CRP/activation、CWEDP、NetLease、OTA、API/CLI 的 race/定向测试证据。
- `bash scripts/ci/verify-ci-static.sh` 通过。输出中的 `::error::` 来自脚本刻意构造的负向发布、签名、校验和、DMG 生命周期用例，最终状态为 `CI static regression checks passed.`
- `git diff --check`、目标 Go 文件 `gofmt` 检查通过。
- 主服务生产组合根仍按设计 fail-closed：默认 factory 没有 session-bound temporary-network provider，`runServe` 也尚未消费 `TemporaryHTTPExecutor`/CWEDP adapter；因此 CRP/CWEDP activation、rollback 和生产临时联网四个 static-matrix blocker 仍是真实缺口，不是测试噪声。不能复用 `temporary-online` CLI，因为它是 SQLite、固定 epoch 1、允许本地无 management session 的一次性路径。
- 隔离测试服务器 `124.221.149.182` 上新增的 `codex-current-20260921` 预览与既有 `cheesewaf-preview.service` 分离运行：管理端口仅监听 `127.0.0.1:19453`，代理端口仅监听 `127.0.0.1:18090`；`/health`、`/health/ready`、`/setup` 均返回 200，`/api/setup/status` 返回 `needs_setup: true`。通过 SSH 隧道可在本机打开 `http://127.0.0.1:19453/setup`，公网 `124.221.149.182:19453` 未开放。预览没有执行初始化向导或修改既有服务。

当前发布判断：`v0.3.9` 正式 Release 已存在但指向旧的 `dbdfc6fd`，当前工作树不满足“受保护 master 当前提交 + 稳定标签 + 三份 Linux server 归档 + CodeQL/发布门禁”的晋升条件；Pages/Workers 的本地构建和 dry-run 不能替代 Cloudflare R2、域名、Access ACL、Tunnel 和生产资源证据。待主服务真实接线、四项 static blocker、Cloudflare 资源和远端 CI/CodeQL 收口后，再执行远端晋升与 Beta 发布。

### 2026-09-21 主 serve session 生命周期接线

本轮完成一项可在仓库内真实验证的生产接线收敛：`ProductionServeWiring` 现在携带组合根验证过的 `SessionValidator`，`runServe` 保存并消费同一份 wiring；`api.NewRouterWithAPI` 的浏览器 session 与 management API 认证都使用注入的 validator，只有非 production/嵌入式调用才回退到 `Store` 兼容路径。生产组合根要求 ApprovalHTTP 的 validator 与管理 Store 是同一生命周期实例，并在不满足时 fail-closed。

新增路由回归测试证明：即使底层 Store 内存在有效 session，注入的拒绝 validator 也不能被静默绕过。`go test ./... -count=1 -timeout=900s`、`go test ./internal/api ./internal/cli ./internal/api/handler -count=1`、`bash scripts/ci/verify-ci-static.sh` 均通过。

这项接线不等于四项验收 blocker 已清零：CRP activation/rollback 仍缺真实 durable control-plane、授权审计和 sidecar；temporary-network 仍缺由生产 launcher 提供的 session-bound provider 和动态 lease 生命周期；迁移仍缺部署级 handoff/恢复证据。未推送、未晋升、未发行。

### 2026-09-25 Cloudflare 免费档位与验收矩阵复核

- Cloudflare Workers 计划保持 Free（US$0）；Workers Paid 的 `$5/月 + 用量` 结算尝试因银行拒付失败，没有创建 `prod_workers` 订阅。后续验证和部署不得把付费升级当成前置条件。
- R2 继续使用已有的 PAYGO 资源订阅；当前账单仪表板为 US$0.00，R2 资源有免费用量额度，不能把该订阅误写成固定月费。现有 staging/production R2 桶保留，不删除、不改变公开访问策略。
- 通过持久化 Chrome 读取账号订阅状态：`prod_workers` 结果为空；R2 订阅为 PAYGO。staging Worker `https://cheesesec-pages-staging.coqimax.workers.dev` 的 `/api/health` 返回 `UNKNOWN_EDGE_HOST`，原因是 staging Wrangler 环境没有自定义域名 routes，而 Worker 路由策略只接受 `www/docs/store/ota/res/api/console.cheesesec.com` 或本地资产 Host；这不是健康检查通过证据，也没有冒充线上接线完成。
- 重新运行 `python3 scripts/acceptance/matrix.py --static`：19 passed、4 failed、0 skipped。失败仍为 `switch_migration_session_invalidation`、`crp_activation`、`crp_rollback`、`temporary_network_confirmation`，保持真实外部/部署 blocker，不修改 `implemented` 标志。

本轮没有提交、推送、分支晋升或发行；Cloudflare Workers Paid 维持未开通状态。

### 2026-09-25 免费额度 staging Worker 实际部署

- 继续使用 Cloudflare Workers Free（US$0），没有创建或启用 Workers Paid；部署目标限定为 `staging` Wrangler 环境和 workers.dev 预览，不把生产自定义域名、Tunnel 或 Access 当作已配置。
- 在 `/Users/laoke/Dev/CheeseSec_pages` 执行 `npm ci --ignore-scripts`、`npm run build` 和 `npm run check:artifacts`，构建生成 7 个静态页面，产物边界检查通过。`npm audit` 报告 1 个 moderate 依赖告警，未使用 `npm audit fix` 改写锁文件。
- 使用已认证的 Wrangler OAuth 会话执行 `npx wrangler deploy --env staging`。部署成功：Worker `cheesesec-pages-staging`，100% 流量指向版本 `f0538a2f-0afb-43bf-9e15-3535f50675e2`，部署记录 ID 为 `1fbbdd17-dd0c-4284-b67a-cce557b742fe`。
- Worker 绑定复核通过：`cheesesec-publication-index-staging`、`cheesesec-public-resources-staging` 以及对应生产桶均存在；没有删除或改写任何 R2 桶。当前部署使用 `EDGE_POLICY_VERSION=store-ota-v1-staging` 和 staging origin 变量。
- 本机对 workers.dev 的 `GET /api/health` 与 `/en/` HTTPS 探测超时，不能据此宣称公网健康或路由验收通过；部署 API 和版本列表只证明上传、绑定解析和 100% 流量切换成功。staging 环境仍无自定义域名 routes，路由策略对 workers.dev Host 的 `UNKNOWN_EDGE_HOST`/网络不可达风险保持显式记录。
- 本轮没有启用付费方案、没有创建生产 Secret、没有绑定生产域名、没有开启 Tunnel/Access，也没有提交、推送、晋升或发行。四项验收 blocker 和远端 code-owner/CI 门禁状态不因 staging 部署而改变。

随后为可用的 staging 预览修正了 Pages 仓库（工作区 `/Users/laoke/Dev/CheeseSec_pages`）：`env.staging.workers_dev=true`，并仅把精确的 `cheesesec-pages-staging.coqimax.workers.dev` 加入静态页面/健康检查 Host 判定，不放宽生产 Host、API、发布物或资源路由。新增精确 Host 白名单与 Worker handler 回归测试。`npm ci --ignore-scripts`、`npm audit`（0 漏洞）、`npm test`（53 项）、`npm run typecheck`、7 页 `npm run build`、`npm run check:artifacts` 均通过。

Pages 锁文件原有 `devalue@5.9.0` moderate DoS 告警已通过只更新传递依赖锁定版本修到 `5.9.4`；没有运行宽泛的 `npm audit fix`，无直接依赖声明变化。修正后再次按 `npm ci --ignore-scripts` 重跑全部 Pages 门禁并部署。Cloudflare 返回 Worker URL `https://cheesesec-pages-staging.coqimax.workers.dev`；最终版本 `1b80f5b1-6bbe-482f-882e-2f1d7a35f534`、部署记录 `036bf118-c7f3-4d90-9de2-594966682848`，100% staging 流量指向该版本，仍绑定 staging R2 桶。

部署配置和单测已确认精确预览 Host 应走静态页面/健康检查，但当前执行环境对 workers.dev 的公网 HTTPS 请求仍超时，尚无真实 HTTP 200 响应证据；所以该地址是已部署预览入口，不宣称外部连通性已验收。Pages 仓库这 6 个源文件改动尚未提交或推送，尚未触发远端 PR/CI；主仓库仅更新本交接记录。未启用 Workers Paid、未新增 R2 上传、未改变生产 DNS/域名/Secret/Access/Tunnel，也未提交、晋升或发行主仓库。

### 2026-09-25 前三项真实生产验收与 CI 接线

范围：把迁移/session invalidation、CRP activation、精确 rollback 三项从仅有契约测试收敛为真实 PostgreSQL/Redis + production launcher/mTLS sidecar 集成验收，并固化到 GitHub Actions。这里只证明本地组合和 CI 门禁代码；不声称云实例、Cloudflare 生产环境或公网 egress 已部署。

实际改动：

- `scripts/acceptance/matrix.py` 的 `--full` 在三个依赖齐全时才执行真实 migration/recovery 与 production `runServe` session/CRP route 探针；static 或缺依赖仍保留 blocker，不会跳过或误标通过。
- 新增 `scripts/ci/run-production-acceptance-integration.sh`：要求 PostgreSQL DSN、Redis 地址和 CRP registry 环境变量齐全，并校验 registry 是权限 `0700` 的非符号链接目录，再运行两组 race 集成测试。
- `.github/workflows/ci.yml` 新增隔离 PostgreSQL/Redis 的 `production-acceptance-integration` job；`verify-ci-static.sh` 锁定该 job 和 runner 必须存在。
- 更新 `docs/acceptance-matrix.md` 与本阶段看板，区分静态 blocker、本机真实组合证据、远端 CI 状态和云端部署证据。

验证命令与结果：

- 本地真实依赖运行 `bash scripts/ci/run-production-acceptance-integration.sh`：`internal/cli/migration` race 集成通过；`internal/cli` 中 production `runServe` session invalidation、CRP activation/rollback race 集成通过（67.278 秒）。
- `python3 -m unittest scripts/acceptance/matrix_v2_test.py`：14 项通过；`bash scripts/acceptance/acceptance-matrix_test.sh`：contract tests 通过。
- `bash scripts/ci/verify-ci-static.sh`：退出码 0，含 workflow/actionlint 检查；其中预期 `::error::` 行来自负向发布验证用例。
- 2026-09-25 本机 full matrix：22 passed、1 failed、0 skipped；迁移/session、activation、rollback 均 pass。剩余失败为独立 `temporary_network_confirmation` 部署级公网 egress 证据，不纳入前三项结论。
- runner 缺失环境负向检查退出码 2，首个缺失项明确报告为 `CHEESEWAF_POSTGRES_TEST_DSN`；`git diff --check` 与 runner `bash -n` 通过。

遗留风险：GitHub Actions job 尚未在远端执行，需最终提交后检查 job 结果；full matrix 的临时公网出网 gate 仍未通过；本地 integration 不替代测试服务器/生产部署验收。本轮未提交、推送、晋升或发行。

### 2026-09-25 真实临时联网 egress 复核

范围：核对第四项 `temporary_network_confirmation` 是否只是未接线，还是仅缺部署级公网证据；实际运行主 `serve` 的 PostgreSQL/Redis 组合、浏览器登录/session 失效、一次性 HTTPS lease、证书 pin、审计与清理链路。

实际结果：

- `TestProductionLauncherPostgresCutoverAndSessionInvalidation` 在真实 PostgreSQL/Redis 上通过，并使用显式 `CHEESEWAF_PUBLIC_NETLEASE_TEST_PIN` 对 `example.com:443` 发起真实 HTTPS HEAD；撤销 PostgreSQL Session 后，下一次请求在发放 lease 前被拒绝，耐久审计未增加。
- `TestRunServeProductionTemporaryHTTPRoute` 在真实 `runServe` listener 上通过，覆盖登录、CSRF、session-bound provider、证书 pin、`issued → result → revoked` 审计顺序和注销后的拒绝。
- 这两条证据证明主服务临时联网 provider 已真实接入；此前 gate blocker 中“缺 runtime-owned registry、intent verifier、resume store、control-plane provider”的表述已修正为准确的部署证据缺口。
- `temporary_network_confirmation` 仍不能标记通过：`TestRunServeProductionCWEDPDownloadRoute` 要求一台可从测试端回连的公网 IPv4/IPv6、高端口 `49152..65535`、真实 mTLS peer、签名 CRP 包和 PostgreSQL resume store。当前没有可用的测试服务器登录/端口开放证据，因此没有伪造或放宽 `PublicAddressPolicy`。

验证命令与结果：

- `CHEESEWAF_POSTGRES_TEST_DSN=... CHEESEWAF_REDIS_RUNTIME_TEST_ADDR=... CHEESEWAF_CRP_SIDECAR_TEST_REGISTRY_DIR=... CHEESEWAF_PUBLIC_NETLEASE_TEST_PIN=sha256:... go test -race -count=1 -timeout=240s ./internal/cli -run '^(TestProductionLauncherPostgresCutoverAndSessionInvalidation|TestRunServeProductionTemporaryHTTPRoute)$'`：退出码 0。
- 本机 `python3 scripts/acceptance/matrix.py --full`：22 passed、1 failed、0 skipped；迁移/session、CRP activation/rollback 和本地 HTTPS egress 证据通过，唯一失败保持为缺少公网 CWEDP peer 的 deployment-level 证据。
- `python3 -m unittest scripts/acceptance/matrix_v2_test.py`、`bash scripts/ci/verify-ci-static.sh`、GitHub actionlint、`git diff --check`：通过。

下一步：若要把第四项闭环，需要重新开放测试服务器登录或提供一台免费额度的公网测试节点，并允许一个 `49152..65535` TCP 端口入站；随后运行 `TestRunServeProductionCWEDPDownloadRoute`，核对 signed intent、mTLS、Range/resume、CRP staging、审计和清理。未取得该外部条件前，不提交“全量验收完成”、不晋升、不发行。

### 2026-09-25 公网测试节点完整验收矩阵

范围：使用用户提供的 Debian 13 amd64 测试节点（2 vCPU、4 GB 内存、40 GB SSD、12 Mbps）补齐第四项公网证据，并复核完整 acceptance matrix；不写入密码、DSN 或证书 pin。

实际操作：

- 服务器仅安装 Go 1.26.6、PostgreSQL 17.11、Redis 8.0.2、Git 和编译工具；PostgreSQL 与 Redis 保持 loopback 监听，CRP registry 使用独立的 0700 非符号链接目录。
- 使用私有 Go 临时目录运行测试，避免 Debian `/tmp` 的 0777 父目录触发 process-sidecar 安全门禁；服务器测试目录只建立一次性本地 Git 基线，不连接或推送任何远端。
- 高位 TCP 端口 `49152` 仅供测试进程临时监听；测试在公网 IP 回连路径上启动 TLS 1.3、双向证书验证的 CWEDP peer，并使用签名 CRP 包和 PostgreSQL resume state。
- 修复 `internal/cli/serve_cwedp_real_route_integration_test.go` 的 JSON 字段标签，使 `job_id`、`stage_status` 和 `plugin_key` 按接口实际响应解码；没有放宽生产校验或改变公网地址策略。
- 修正 `scripts/acceptance/matrix.py`：在 `--full` 的真实依赖已经满足且 integration probe 通过时清除静态模式遗留 blocker；若正向、负向或真实 integration probe 失败，则写入明确 blocker。

验证命令与结果：

- 公网节点定向 race 验收：`go test -race -count=1 -timeout=240s ./internal/cli -run '^(TestRunServeProductionTemporaryHTTPRoute|TestRunServeProductionCWEDPDownloadRoute)$'`，退出码 0。
- 公网节点完整矩阵：`python3 scripts/acceptance/matrix.py --full --report /tmp/cheesewaf-acceptance-full-20260925.json --markdown /tmp/cheesewaf-acceptance-full-20260925.md`，结果 **23 passed、0 failed、0 skipped**；`temporary_network_confirmation` 已通过真实 HTTPS pin、Session/lease 撤销、审计和公网 CWEDP mTLS 下载。
- 报告已复制到本机 `/tmp/cheesewaf-acceptance-full-20260925.{json,md}` 供复核，未加入 Git；矩阵 cleanup 报告 `tracked_worktree_unchanged=true`、`source_template_unchanged=true`、`processes_stopped=true`、`runtime_removed=true`。
- 本地回归：`python3 -m unittest scripts/acceptance/matrix_v2_test.py` 和 `bash scripts/acceptance/acceptance-matrix_test.sh` 通过；`git diff --check` 待本轮文档更新后再执行。

遗留风险：该证据证明单台公网测试节点上的生产组合和公网 egress，不等于多节点长期部署、Cloudflare 生产资源、稳定发布或远端 CI/CodeQL 已完成。下一步先运行仓内全套静态/构建/产物门禁，再提交并检查 GitHub Actions/CodeQL；只有远端门禁与依赖 PR 收口后才晋升 `master` 和重建稳定版 `v0.3.9`。

### 2026-09-26 当前 HEAD 公网验收复核

本轮针对当前提交 `84ec2e43cee3f42bdd45830bfe22c1d28a6dd8f0`，重新使用用户提供的 Debian 13 amd64 公网测试节点（`156.239.4.159`）执行真实组合验收；服务器既有服务未替换，测试使用隔离 PostgreSQL 数据库、Redis 实例标识、`0700` CRP registry、权限为 `0700` 的私有临时目录和 TCP `49152` 临时监听。没有把密码、DSN、证书 pin 或运行时数据写入仓库。

首轮集成探针因 Debian `/tmp` 为 `0777` 被 process-sidecar 安全门禁拒绝；未修改生产校验，改用权限为 `0700` 的私有 `TMPDIR` 后重跑。Go 依赖使用服务器现有 Go `1.26.6`、PostgreSQL `17.11`、Redis `8.0.2`，目标源文件与本机 SHA-256 一致。

验证结果：`go test -race -count=1 -timeout=30m ./internal/cli/migration -run '^TestPostgres.*$'` 通过；`TestRunServeProductionRealListenerAndSessionRoute`、`TestRunServeProductionCRPActivationAndRollback`、`TestRunServeProductionTemporaryHTTPRoute`、`TestRunServeProductionCWEDPDownloadRoute` 全部通过。当前 HEAD 的 `python3 scripts/acceptance/matrix.py --full` 结果为 **23 passed、0 failed、0 skipped**；清理证据为 `processes_stopped=true`、`runtime_removed=true`、`source_template_unchanged=true`、`tracked_worktree_unchanged=true`。报告已拷回本机 `/tmp/cheesewaf-acceptance-full-84ec2e43.json`，SHA-256 为 `10a461e7bf393b62e1b17821dc9c161ec2283c0037c153339e0de201b0db2d3e`，未加入 Git。

边界仍明确：这证明单台公网节点上的当前 HEAD 生产组合、session/CRP/CWEDP 和临时 HTTPS 证据，不替代 GitHub 远端 required checks、CodeQL、Cloudflare 生产资源或多节点长期部署证据；远端 Git smart-HTTP 当前仍不可达，推送、PR、晋升和发行尚未发生。

### 2026-09-26 Dependabot 配对收口

- React 依赖按 peer 约束成对升级：`react`、`react-dom`、`@types/react`、`@types/react-dom` 统一到 `19.3.0`，同步锁文件中的 `scheduler` 和 React 类型依赖；`npm ci --ignore-scripts`、14 项 CAPTCHA contract、4 项脚本测试、470 项 Vitest、typecheck、96 个产物构建和 `npm-audit-gate` 均通过。
- React 19 回归修复：验证码拒绝结果测试改为在异步 `act` 中推进定时器；运维报表忽略 Select 初始化产生的空值，并按字段跟踪用户编辑，保存时以最新任务数据补齐未编辑字段。新 React 类型要求的可空 `useRef` 均已显式初始化。修复后 2 个定向测试文件（32 项）通过，完整 Web 门禁 470 项通过，typecheck、构建预算、96 个产物边界检查和 npm audit gate 均通过。
- Dependabot 配置移除仓库不存在的 `security` label，保留可用的 `dependencies`/`ci` 标签，避免后续更新 PR 反复出现标签错误。
- GitHub #460/#461 的半套 React 更新由上述统一变更覆盖；在统一变更进入 `dev` 并确认远端门禁前，不宣称这两个 PR 已关闭或已合并。

### 2026-09-26 GitHub PR 门禁复核

PR #466 的首轮 GitHub `ci-static` 检查发现 `scripts/ci/verify-forgejo-workflow.sh` 在本机文件系统为 `0755`，但 Git index 仍记录为 `100644`；本机 `core.filemode` 行为掩盖了该差异，CI checkout 因而拒绝执行 Forgejo workflow gate。已将 Git 跟踪模式修正为 `100755`；提交后需等待远端 CI 和 CodeQL 对新 head 重跑，再据结果决定合并与晋升。

同一轮 CI 暴露生产验收和 Go coverage 在 GitHub runner 上继承共享 `/tmp`（`0777`）的问题；process-sidecar 按设计拒绝该路径。本地已用私有 `TMPDIR` 复现并通过，现将 `scripts/ci/go-env.sh` 统一为每次 Go 命令创建并清理私有、可清理的 `0700` 临时根，确保 production acceptance、coverage 和其他 Go 门禁使用同一安全边界。

Windows runner 复核发现 POSIX 权限/目录 fsync 相关测试不能由 `chmod` 模拟：原补丁把 Windows 原生 TEMP 覆盖成无效的 POSIX 权限语义，导致 CRP runtime、materializer journal 和 CWEDP consumer 测试误报。已恢复 Windows 原生 TEMP，保留 Unix 私有临时根；Windows job 继续编译全部包，并显式排除依赖 Unix 权限/flush 语义的测试集合，不放宽生产校验。

随后 Ubuntu runner 的 `TestApplyCommittedTimeoutReleasesSequencerButRetainsOSLease` 在 1 秒启动观察窗内受并行/race 负载影响未见 callback；本地 `-race -count=20` 稳定通过。测试仅放宽启动观察窗至 5 秒，仍保留 10ms runtime timeout 与所有租约/补偿断言，不改变生产超时语义。

MacOS runner 继续暴露临时网络 provider 关闭竞态：存储 lookup 在 provider context 已取消后可能先返回旧的 session-denied 错误。`boundTTL` 现在优先返回 `ctx.Err()`，保证关闭/取消语义不被后端错误覆盖；网络权限、租约和会话校验逻辑未放宽。

随后 Ubuntu runner 捕获到同一关闭窗口在 broker 清理阶段返回 `invalid socket lease`；`ExecuteTemporaryHTTP` 现在也优先传播已取消的 operation context，避免把二次清理错误暴露给调用方。
