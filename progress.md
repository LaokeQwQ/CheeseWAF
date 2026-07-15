# CheeseWAF 项目阶段进度

更新时间：2026-07-15

## 项目定位

CheeseWAF 是一个基于 Go 的开源 Web 应用防火墙项目。当前目标是推进到可以公开分发的 V0.1 beta：服务能够部署运行，核心防护链路可验证，管理控制台、CLI/TUI、发布构建和基础运维能力具备持续迭代条件。

当前阶段的重点不是功能演示，而是把已有能力整理成可使用、可测试、可解释、可交付的产品形态。

本文件用于对外分享项目进度，已移除服务地址、账号密码、API Key、访问令牌、本地路径、临时部署目录等敏感信息。

## 当前能力概览

CheeseWAF 当前已经覆盖以下方向：

- HTTP 反向代理与 WAF 检测链路
- 多阶段语义检测引擎
- Web 控制台、TUI、CLI 三端管理入口
- 站点级与全局防护策略
- Bot / CC 防护、JS Challenge、PoW、人机验证与等待室
- IP 黑白名单、真实客户端 IP 解析、威胁情报导入与画像
- 请求头管理、压缩策略、缓存策略、响应泄露检测
- API 安全、规则管理、事件审计、日志与监控
- AI 事件分析与控制台助手
- 自定义拦截页、错误页与事件追踪 ID
- CI、分支保护和多平台发布构建规划

## 已完成的主要工作

### 1. 基础运行与配置

- 完成 Go 服务主入口、配置加载、配置校验、默认配置和初始化向导。
- 支持单二进制运行，主配置入口采用 YAML。
- 管理端支持 TLS、自签证书、安全入口、登录验证码和会话控制。
- CLI 已支持用户密码重置，并规划补齐用户名修改、服务恢复和本地维护能力。
- 默认配置已经从早期脚手架状态推进到可运行的预发布配置。

### 2. 三端管理入口

- Web 控制台已覆盖仪表盘、站点、规则、日志、IP 管理、防护策略、AI、监控、API 安全、用户、运维、更新、拦截页和系统设置等页面。
- TUI 和 CLI 作为运维入口，用于补齐 Web 控制台不可用时的恢复和配置修改能力。
- 后续 Windows 发行将拆成 CLI/bin 版和 GUI 安装器版：CLI/bin 版接近 nginx 的手动配置与启动方式；GUI 版只负责本地服务启停、服务状态、连接信息和开机自启。

### 3. 语义检测引擎

- 检测流程已经拆成请求解析、参数提取、深度解码、攻击类型初判、词法分析、语法分析、语义分析和处置决策。
- 已覆盖 SQLi、XSS、RCE、LFI、XXE、SSRF、NoSQL、SSTI 等主要方向。
- 已加入一批回归样本，覆盖编码绕过、SQL 函数型注入、错误型注入、PostgreSQL 延时注入、NoSQL 登录绕过、HTML 事件属性 XSS、`javascript:` 上下文误报控制等场景。
- 已引入外部攻击样式数据用于测试，但不会照单全收外部规则；新增样本需要经过误报、漏报和可解释性分析后再进入引擎或规则库。
- 当前可描述为「具备可运行、可解释、可回归验证的语义引擎」。在更多公开数据集、真实误报样本和 CRS / Coraza 对标测试完成前，不对外宣称已经等同或超过 ModSecurity / OWASP CRS。

### 4. 防护策略与站点级配置

- 支持全局和站点级防护等级。
- 防护方向包括 Web 攻击、API 安全、Bot / CC 和威胁情报。
- 默认策略偏向降低误报；站点未单独设置时继承全局配置。
- 路径级和 API 级细化策略规划为自定义 / 高级规则能力。
- 支持请求头增删改、压缩算法和策略、缓存策略、响应敏感信息检测、重写规则和健康检查。
- WAF 模式支持阻断、监控和记录等处置路径，避免低置信度命中直接阻断。

### 5. IP 管理与威胁情报

- 支持全局、站点级和目录级 IP 黑白名单，用于放行、加白和拦截。
- 支持从可信代理头解析真实客户端 IP，包括 `X-Forwarded-For`、`X-Real-IP`、`Forwarded` 以及常见 CDN 真实 IP 头。
- 真实 IP 解析依赖可信代理 CIDR 配置，避免未授权客户端伪造来源 IP。
- 支持威胁情报指标导入、同步、查询、画像和置信度展示。
- 威胁情报处置会结合严重性、置信度、来源数量和站点策略计算，不按单一命中直接拦截。

### 6. Bot、人机验证与等待室

- 已实现 PoW 验证、图像验证码基础能力、滑块拼图验证码、JS Challenge、等待室和 Bot / CC 处置策略。
- 登录控制台支持验证码开关和模式配置，默认启用验证码。
- 安全入口支持自定义路径；错误入口返回非正常登录页，减少管理端暴露面。
- WAF 侧挑战能力已经接入 Bot 防护策略，不再只是前端样式。

### 7. AI 事件分析与助手

- AI 配置支持 OpenAI 标准和 Anthropic 标准接口形式。
- OpenAI 兼容路径已接入官方 Go SDK，并支持流式 Chat Completions。
- AI 助手支持流式输出、工具调用轨迹、首包计时、总耗时、token 使用量和输出速度。
- 事件分析面向攻击事件和拦截事件，按事件 ID / trace ID 拉取上下文后再分析。
- 日志详情与 AI 事件分析页会展示 WAF 策略判定摘要，包括当前防护等级、最终动作、风险分、证据数量、阈值和检测器来源，便于解释“为什么记录、挑战或拦截”。
- Prompt 边界已经加入安全约束：日志、payload、运行时上下文和用户输入均按不可信数据处理，避免提示词注入、密钥泄露和未授权策略变更。
- 工具调用需要经过权限与审批边界；配置修改类操作不能由模型直接绕过审批执行。

### 8. 管理控制台 UI

- 已多轮修复 Web 控制台布局、移动端适配、菜单行为、图标尺寸、按钮对比度、事件详情、AI 助手、IP 管理、系统设置、拦截页和攻击地图等问题。
- 仪表盘已区分总计态势和实时态势，监控数据支持自动刷新和手动刷新。
- 资源占用展示覆盖 CPU、系统负载、内存、Swap、磁盘、服务状态和健康状态。
- AI 助手已从表单式交互改为对话式交互，并展示可公开的流式过程与工具轨迹。
- 登录页已去掉默认账号密码提示，支持验证码、安全入口和自定义背景配置。
- 攻击地图支持 2D、3D 和中国区域模式。中国区域模式已改为真实 GeoJSON 行政边界渲染：优先使用用户配置的合规 GeoJSON 数据源，缺省按需加载内置省/市/区县边界资源；缺少高精度 GeoIP 或情报定位时仍明确降级，不伪造街道级位置。

### 9. 拦截页与错误页

- 默认拦截页已改为更正式的边缘错误页风格，展示 CheeseWAF 品牌、HTTP 状态、事件类型、访问时间和 Event / Trace ID。
- 前端报错、后端 API 错误、WAF 拦截和上游错误尽量统一 Event / Trace ID，便于排查。
- 支持上传自定义 HTML 拦截页 / 报错页，并提供运行时预览。
- 默认拦截页支持按请求语言和时区进行本地化展示，基础覆盖中文、英文和日文场景。

### 10. 监控、运维与更新

- 已实现基础运行状态、资源占用、请求统计、拦截统计、告警和运维任务页面。
- 支持定时任务和安全报告方向规划，包括日报 / 周报生成与通知渠道发送。
- 更新与漏洞页面已加入版本、更新和漏洞信息展示能力。
- 仍需继续把紧急下发、自动更新、版本回滚和多平台发布制品做成稳定发布流程。

### 11. 构建、CI 与分支流程

- 项目采用受保护分支逐级合并流程：`feature -> dev -> canary -> master`。
- 不做越级 PR，不做强制推送。
- GitHub 与自建 Forgejo 双平台同步推进；Forgejo 作为主要构建平台，GitHub 作为辅助镜像和外部可见检查。
- CI 覆盖 Go 测试、Web 构建、交叉构建、`go mod` 检查和 release artifacts。
- 针对网络环境，CI 已减少对外部 Go 下载链路的直接依赖，优先使用本机或镜像工具链。

## 当前验证状态

最近一轮本地验证覆盖过以下项目：

- `git diff --check`
- `npm --prefix web run build`
- `go test ./cmd/... ./internal/... -count=1`
- Web 控制台桌面端与移动端全路由截图回归

最近一轮功能 smoke 覆盖过以下链路：

- 管理端安全入口跳转登录页
- 登录验证码、账号密码校验和 token 签发
- 数据面基础响应
- SQL 注入探测阻断
- AI 流式对话首包、reasoning delta、content delta 和工具调用 delta

这些验证结果用于说明当前工程状态。正式发布前仍需要按 release gate 重新执行完整验证，不能只复用历史结果。

### 2026-07-09 本地补充：IP 管理闭环与样式收口

- IP 访问名单从桌面表格压缩布局改为自适应规则卡片网格，桌面与移动端均避免备注、站点、路径和 IP/CIDR 被挤成竖排。
- 访问名单新增备注编辑，站点级和目录级规则保存前会校验站点选择，作用域切换会同步清理或保留站点 / 路径字段。
- 威胁情报源动作选项与后端情报引擎对齐为记录、挑战和拦截；不再在情报源里暴露实际会被归一化的监控动作。
- 情报源测试接口支持携带 `provider_id` 复用后端已保存的密钥和敏感请求头，同时允许当前表单里的端点、格式、认证方式和 Header 草稿参与测试。
- 情报源 UI 增加自定义请求头编辑入口，并明确说明 API 密钥留空会沿用后端已保存密钥。
- 样式上补充 IP 管理页面级 CSS，减少继续向全局样式堆补丁；轻量收口 light 主题默认 `:root` token 和拦截页预览背景变量。
- 本轮验证通过：`npm.cmd --prefix web run build`、`go test ./internal/api/handler -run "ThreatIntelProviderTestUsesSavedSecretByProviderID|ThreatIntelProviderRejectsUnsafeEndpoints|ApplyProviderAuthSupportsConfiguredAuthTypes|ProtectionSecretUpdatesPreserveExistingValuesWhenEmpty|ImportThreatIntelNotifiesProtectionReload|UpdateIPAccessRulesNotifiesProtectionReload" -count=1`、`git diff --check`，并完成 IP 管理访问名单桌面 / 移动端、情报源桌面截图复核。

### 2026-06-16 AI 输出与远端验收部署

- 修复 AI 助手最终回答的 Markdown 表格渲染，覆盖标题、说明和表格被模型压成同一行的情况。
- 最终回答不再展示内部工具名、工具结果、执行过程、系统提示词等实现细节；思考摘要、执行记录和工具执行结果分别展示，执行记录默认折叠。
- AI 事件分析页继续过滤内部实现词，并保留用户可读的 Markdown 表格、证据和处置建议。
- AI 设置新增“允许本地/私有模型网关”显式开关；默认拒绝后台访问 localhost、内网、链路本地和未指定地址，只有用户主动开启后才允许连接可信内网模型网关。
- 模型列表拉取支持使用当前表单中的 API 地址、Provider、API Key 和私网网关开关，地址合法时可从 OpenAI / Anthropic 标准接口拉取模型列表。
- 本轮验证通过：
  - `go test ./internal/ai ./internal/api/handler ./internal/config -count=1`
  - `npm run build`（Web）
  - AI 助手渲染检查脚本
  - AI 页面回归脚本
  - `git diff --check`
- 已部署到临时测试服务器并完成服务重启验证；管理端健康检查返回正常状态。
- 当前测试环境启用了管理端安全入口，直接访问根路径或错误入口会返回 Nginx 风格 `418 I'm a teapot`，需从安全入口进入登录页。

### 2026-07-09 Code Scanning 远端收口

- 已复核 GitHub Code Scanning 当前 16 条 open 告警，覆盖出站请求 SSRF、SQLite 测试路径边界、整数转换、查询 limit 上限、Bot 验证 cookie / 跳转和拦截页 HTML 预览净化。
- 本地已完成对应修复：统一出站请求 URL 校验入口，SQLite 测试路径限制在数据目录内，日志查询与 AI 工具参数增加上限保护，Bot 验证跳转限制为站内相对路径，拦截页预览移除脚本、事件属性和危险 URL 协议。
- 修复已通过 PR #205、#206、#207 合入 `dev`，再经 PR #208 合入 `canary`、PR #209 合入 `master`；GitHub 与 Forgejo 的 `dev` / `canary` / `master` 分支已同步到相同提交。
- GitHub CodeQL 已在 `master` 重新完成扫描，Code Scanning API 复核结果为 `master=0`、`all_open=0`。
- 本地工作区已快进到最新 `dev` 并恢复 Kimi / 本地后续改动，冲突只发生在 `monitor.go` 与 Bot 策略 cookie / 跳转逻辑，已保留 CodeQL 安全修复并重新验证。
- 本轮验证通过：`git diff --check`、`npm.cmd --prefix web run typecheck -- --pretty false`、`npm.cmd --prefix web run build`、`go test ./...`。

## 当前限制与风险

- UI 仍需要持续人工复核。截图检查可以发现溢出、窄列、横向滚动和控制台错误，但不能替代人工审美验收。
- 语义引擎已具备回归样本和多阶段分析，但仍需要继续扩充公开数据集、CRS / Coraza 对标样本和真实误报样本。
- 外部安全扫描链路已经规划接入 sqlmap、XSStrike、nuclei 和 ZAP 的执行入口；正式发布前仍需要在稳定 runner 上归档完整扫描证据。
- 威胁情报源、漏洞库订阅、AI Agent 规则生成、知识库管理等能力已有方向和部分实现，仍需继续补齐可视化管理、审批、回滚和误报反馈闭环。
- PostgreSQL、Redis、Elasticsearch 等外部存储配置已经进入系统设置模型，仍需要继续做端到端部署验证、连接测试和失败降级。
- Windows GUI 安装器仍处于规划阶段，尚未进入实现。

## 下一阶段计划

1. 继续打磨语义引擎，重点筛选语料、补充公开数据集、真实攻击样本和真实误报样本回归；默认策略坚持优先降低误报，低置信发现默认记录 / 监控，不直接拦截。
2. 完成威胁情报订阅、漏洞库同步、IP 画像人工修正、站点级处置策略和可视化管理。
3. 完成 AI Agent 工具调用审批、内置 WAF 知识库与知识库订阅、规则草稿生成、测试后 promotion 的闭环，并修复长推理流式保活和单事件实时思考输出。
4. 继续修复 Web 控制台 UI，形成统一的布局、动效、表单和图表规范。
5. 完善 Windows 发行：CLI/bin 包、GUI 服务控制器和 NSIS 安装器。
6. 补齐 PostgreSQL、Redis、Elasticsearch 等外部依赖的真实部署验证。
7. 固化 release gate：本地测试、Web 构建、截图回归、外部安全扫描、双平台 CI、逐级 PR 和发布制品归档。
8. 在 WAF 设置中补齐 API 令牌、权限矩阵、令牌生命周期、审计记录和帮助文档入口，覆盖大部分控制台能力但不绕过 RBAC / 审批边界。

## 对外说明口径

当前 CheeseWAF 适合描述为：

> CheeseWAF 是一个正在进入 V0.1 beta 收口阶段的开源 WAF 项目，已经具备可运行的代理、防护、管理控制台、语义检测、AI 分析、威胁情报和 CI / 发布链路。项目正在从功能完整的预发布原型继续推进到可公开分发的 beta 产品，当前重点是降低误报 / 漏报、提升 UI 质量、补齐外部依赖验证和完善发行体验。

不建议现阶段对外宣称：

- 已经达到商业 WAF 的完整稳定性。
- 语义引擎已经超过 ModSecurity / OWASP CRS。
- 所有外部威胁情报、漏洞库和 AI Agent 自动规则能力已经完全闭环。
- Windows GUI 安装器已经完成。

### 2026-06-18 CAPTCHA 行为轨迹与远端验收部署
- 管理端登录滑块新增行为轨迹校验，释放滑块时提交 down/move/up 采样、拖动耗时和最终位置；后端要求登录滑块必须携带轨迹，缺失轨迹会拒绝验证。
- WAF 数据面 Bot 验证新增滑块行为轨迹开关和移动端回退策略，手机/粗指针设备可回退 PoW 或图像验证码。
- Web 控制台的 Bot 验证设置已暴露移动端回退方式与“要求行为轨迹”选项，登录页和公共挑战页继续使用真实服务端签发的验证码 token。
- 已部署本地验收版到临时测试服务器并完成 smoke：健康检查、安全入口、静态资源 MIME、登录 CAPTCHA API、无轨迹验证拒绝、桌面/移动截图复核均通过。
- 当前未推送 GitHub/Forgejo；完整全量 Go 测试仍有语义语料与 HTTP/3 测试配置失败项，需要作为独立后续任务处理。

### 2026-06-18 登录 CAPTCHA 错误边界修复
- 登录页 CAPTCHA 点击链路增加恢复逻辑：验证码数据未准备好时先重新拉取 challenge，再打开弹窗。
- 控制台前端错误边界不再用“请求无法完成”这类误导文案，改为显示前端运行时异常、错误摘要和 Trace ID。
- 对部署后旧静态资源混用导致的动态模块加载失败增加一次自动刷新恢复。
- 已部署到临时测试环境并用浏览器自动化验证：登录入口、CAPTCHA API、验证码弹窗和控制台日志均正常。

### 2026-07-04 本地未提交：威胁情报 Provider 出站 SSRF 防护
- 阶段目标：处理安全审查中提出的威胁情报出站请求风险，避免管理员配置的情报源 endpoint 被用作访问本机、内网或云元数据地址的跳板。
- 后端实现：`fetchProvider` 与 `lookupProviderIP` 在请求前统一校验 provider URL，只允许 `http` / `https`，拒绝 URL userinfo、fragment、空 host，以及 IP 字面量指向 loopback/private/link-local/multicast/unspecified/metadata 地址。
- 连接层防护：默认威胁情报 HTTP client 改为专用 guarded client，禁用系统代理，连接前解析 DNS 并拒绝任何解析到非公网或 metadata IP 的结果；实际拨号使用已校验的解析 IP，降低 DNS rebinding 风险。
- 元数据地址覆盖：明确阻断 `169.254.169.254`、`169.254.170.2`、`100.100.100.200` 和 `fd00:ec2::254` 等常见云元数据地址。
- 测试处理：现有本地 `httptest` provider 测试通过测试专用 client 与 URL validator 注入保留覆盖，不放宽生产默认策略。
- 当前验证：`go test ./internal/api/handler -run "ThreatIntel|Provider" -count=1` 通过；`go test ./internal/api/handler -count=1` 通过。测试使用隔离的构建缓存，避免用户目录 build cache 权限问题。

### 2026-07-05 本地收口：地图、站点详情与安全加固复验

- 根目录计划文档已重新核对：当前可闭环项优先收口，语义引擎 CRS/FTW 对标、paranoia/anomaly scoring、Windows GUI 安装器和完整外部动态扫描继续作为后续路线图，不提前宣称完成。
- 站点详情页修复 ACME provider 数据异常时的运行时崩溃；当 `/api/acme/providers` 返回非数组或包装对象时，页面会安全归一化 provider 列表，不再白屏。
- 中国区域攻击地图完成真实浏览器专项复验：省/市/区县边界不再出现大矩形异常，浙江与西湖区定位框正常，滚轮缩放不会带动页面滚动。
- 高风险页面桌面/移动端 UI 回归覆盖 Dashboard、站点、站点详情、IP 管理、AI、用户、拦截页、攻击地图 2D/3D/中国区域和系统设置，自动检查 overflow、窄列、内部横向滚动和浏览器错误均为 0。
- 安全审查项复核：WebSocket Origin 校验、Admin Server header timeout、弱默认安全入口 secret、AI provider timeout 已闭环；威胁情报 provider 出站请求已加 SSRF guard。其它出站 sink 的 SSRF 专项复审仍需后续继续。
- 本轮验证命令包括：`npm.cmd --prefix web run typecheck -- --pretty false`、`npm.cmd --prefix web run build`、`go test ./internal/netguard ./internal/ai ./internal/apisec ./internal/blockpage ./internal/proxy ./internal/storage/log_sink ./internal/api/handler -count=1`、地图检查脚本和高风险页面 `full-ui-regression`。

### 2026-07-05 本地补充：语义引擎与协议检测小步加固

- 协议检测新增 HTTP/2 forbidden hop-by-hop / downgrade-smuggling 检查，以及 WebSocket upgrade 形态校验；有效 WebSocket upgrade 保持放行，异常方法、缺少 upgrade 语义或缺少 `Sec-WebSocket-Key` 会被识别为异常。
- 语义检测补充 Oracle / T-SQL 高风险 SQL 原语、scheme-relative 和 bare-host SSRF fetch 目标、MongoDB `$jsonSchema` 注入语义，并为相关文档文本补 benign 邻居，继续优先降低误报。
- 公开语义文档已同步说明新增覆盖和边界。当前仍不能宣称 ModSecurity / OWASP CRS parity；CRS/FTW 对标、异常评分模型和真实误报基线仍是后续路线图。
- 本地验证通过：`go test ./internal/engine ./internal/engine/semantic -count=1`、`go test ./cmd/... ./internal/... -count=1`、`git diff --check`。

### 2026-07-05 本地补充：监控外发 SSRF 防护

- `monitor.remote_write` 和告警通知 `monitor.notifiers[*].endpoint` 默认接入 `netguard` 出站客户端，只允许 `http` / `https`，拒绝 URL 凭据、fragment、回环、私网、链路本地和常见云元数据目标，并在拨号前复核 DNS 解析结果。
- 新增 `allow_private_endpoint` 显式开关，用于受信任的内网 VictoriaMetrics / Prometheus remote write / webhook 网关；默认仍为关闭，避免控制台配置被误用为内网探测跳板。
- 样例配置、首次安装默认 YAML 和运维文档已同步该字段。ClickHouse / VictoriaLogs / Elasticsearch 日志 sink 已进入后续专项处理；ACME 等其它可配置出站 sink 仍保留为后续复审，不冒充本轮全部完成。
- 本地验证通过：`go test ./internal/config ./internal/monitor ./internal/monitor/notifier ./internal/netguard -count=1`、`go test ./cmd/... ./internal/... -count=1`。

### 2026-07-05 本地补充：地图边界远程源 SSRF 防护

- `console.map.china_boundary` 新增 `allow_private` 显式开关；远程 GeoJSON URL 默认要求 HTTPS，并拒绝 URL 凭据、fragment、回环、私网、链路本地和常见云元数据地址。
- 运行时地图边界拉取使用 `netguard.NewHTTPClient`，在拨号前复核 DNS 解析结果，降低 DNS rebinding 风险；只有显式开启 `allow_insecure` 与 `allow_private` 时才允许受信任的内网 HTTP 地图源。
- 样例配置、首次安装默认 YAML、Web 类型模型、系统设置页和运维文档已同步该字段。
- 测试覆盖新增配置校验和 handler 回归：本机 `httptest` GeoJSON 源默认拒绝，显式允许后可读取合法 FeatureCollection。

### 2026-07-05 本地补充：外部日志存储 sink SSRF 防护

- ClickHouse、VictoriaLogs 和 Elasticsearch HTTP 日志 sink 新增 `allow_private_endpoint` 显式开关，默认关闭；配置层会拒绝 URL 凭据、fragment、回环、私网、链路本地和常见云元数据目标。
- 运行时写入与查询链路统一使用 `netguard.NewHTTPClient`，默认只允许 `http` / `https`，禁用系统代理，在拨号前复核 DNS 解析结果并校验重定向目标，降低 DNS rebinding 与内网探测风险。
- 样例配置、首次安装默认 YAML、Web 类型模型、系统设置页、中英文 i18n 和运维文档已同步该字段；受信任内网日志服务需要由运维显式开启 `allow_private_endpoint`。
- PostgreSQL 日志 sink 使用数据库驱动 DSN，不属于本轮 HTTP SSRF sink；ACME 等其它可配置出站能力仍保留为后续专项复审。
- 本地验证通过：`go test ./internal/config ./internal/storage/log_sink ./internal/api/handler ./internal/monitor ./internal/monitor/notifier ./internal/netguard -count=1`、`go test ./cmd/... ./internal/... -count=1`、`npm.cmd --prefix web run typecheck -- --pretty false`、`npm.cmd --prefix web run build`、`git diff --check`。

### 2026-07-05 本地补充：ACME 配置输入安全收口

- ACME 签发继续通过本地 `acme.sh` 子进程执行；本轮没有把它冒充为 Go 内置 ACME HTTP 客户端。
- 全局配置和单次站点签发请求都会校验 ACME server：允许 `letsencrypt`、`zerossl` 等内置别名，或公网 HTTPS directory URL；拒绝 HTTP、URL 凭据、fragment、回环、私网、链路本地和常见云元数据目标。
- ACME DNS API 名称新增 `dns_*` 格式校验；DNS 环境变量继续要求大写 shell 风格键名；`reload_command` 拒绝换行、回车和 NUL 字符，降低配置误用风险。
- 运维文档已同步 ACME 流水线边界；ACME 通知复用 monitor notifier 路径，因此继承 notifier endpoint 的 SSRF 防护。

### 2026-07-05 本地补充：OTA、漏洞源、安全报告和存储测试出站安全收口

- OTA 更新服务器配置新增安全校验：启用 OTA 或填写 server 时，默认只接受公网 HTTPS URL，拒绝 HTTP、URL 凭据、fragment、回环、私网、链路本地和常见云元数据目标；检查间隔限制为 1 小时到 30 天，通道限制为 `stable` / `canary` / `dev`。
- 漏洞库订阅源新增安全校验：启用的 feed 必须有 ID 和公网 HTTPS URL，订阅间隔限制为 1 小时到 30 天，格式和最低严重级别使用白名单校验，避免配置层写入不可控或含糊的外部源。
- 运维计划任务校验改为先按现有 API/调度器默认值归一化，再校验类型、频率和报告投递目标；旧配置中缺少 ID 的 cleanup 任务不会被误拒，`monthly` 周期已在校验、调度和安全报告统计窗口中保持一致。
- 安全报告 Webhook 发送改用 `netguard` 出站客户端，默认只允许公网 HTTPS，并在运行时禁用系统代理、校验重定向和 DNS 解析结果，避免报告投递 URL 被用作内网探测跳板。
- 系统设置中的 ClickHouse、VictoriaLogs、Elasticsearch “测试连接”也接入同一类 guarded HTTP client；默认拒绝本机/私网 endpoint，只有显式开启对应 `allow_private_endpoint` 后才允许测试受信任的内网日志服务。
- 本轮未声明 OTA/漏洞库完整业务闭环完成；当前完成的是配置入口和运行时出站安全边界，后续仍需要补齐更新源选择器、订阅拉取、签名验证、通知、回滚和端到端发布验证。
- 本地验证通过：`go test ./cmd/... ./internal/... -count=1`、`npm.cmd --prefix web run typecheck -- --pretty false`、`npm.cmd --prefix web run build`、`git diff --check`。

### 2026-07-05 本地补充：控制面稳定性与安全回归闭环

- 登录 CAPTCHA 签名密钥在 `Handler` 初始化时一次性确定；当管理端 auth secret 缺失且 Bot secret 仍是弱默认值时，会使用进程内随机临时密钥并保持挑战/验证一致，不再每次调用重新生成，也不再回退到固定字符串。若随机密钥不可用，签发和验证路径会 fail-closed。
- 调度任务更新 API 在无 `ConfigPath` 的测试或嵌入式场景下也会先跑完整 `config.Validate`，避免绕过安全报告 Webhook、频率、任务类型等配置校验后直接修改内存配置。
- AI 单事件流式分析在 provider 401、网络错误或不可用时，不再直接给前端 SSE `error` 让用户空等；会返回启发式分析的 `done` 事件，并标记 `ai_used=false` 与 provider 错误摘要。
- 健康检查 HTTP client 不再跟随 3xx 重定向，避免源站健康检查被重定向到无关公网、内网或元数据地址；健康状态仅反映原始 upstream 响应。
- WebSocket 实时通道新增同源 Origin 回归测试：同源 Origin 可升级，跨站 Origin 必须返回 403，防止后续误加 `InsecureSkipVerify` 类配置。
- 存储统计继续使用目录大小缓存，避免 Dashboard / 运维页并发刷新时重复遍历大型数据目录；新增缓存行为回归测试。
- 本轮没有触碰用户刚优化完的语义引擎业务逻辑，也没有进行服务器部署；新服务器未就绪前仅做本地可验证项。
- 本地验证通过：`go test ./cmd/... ./internal/... -count=1`、`npm.cmd --prefix web run typecheck -- --pretty false`、`npm.cmd --prefix web run build`、`git diff --check`。

### 2026-07-05 本地补充：认证随机数与关闭路径加固

- 管理端安全入口 cookie nonce 不再在安全随机源失败时退回时间戳；熵源不可用时直接拒绝签发入口 cookie，避免产生可预测入口凭据。
- API TokenManager 在缺少持久化 auth secret 且无法生成安全临时签名密钥时，会拒绝签发和验签，不再使用时间戳构造弱 HMAC secret；已有配置 secret 的生产部署不受影响。
- 拦截页和 API 错误 Trace ID 的极端 fallback 改为时间戳 + 原子计数，随机源不可用时仍保持排障 ID 不重复。
- 远程 JWKS 刷新源的 `Close()` 只等待已经启动过的后台任务，避免构造后未启动就关闭的边界卡死。
- 本地验证通过：`go test ./internal/blockpage ./internal/api/middleware ./internal/cli ./internal/apisec -count=1`、`go test ./cmd/... ./internal/... -count=1`、`npm.cmd --prefix web run typecheck -- --pretty false`、`npm.cmd --prefix web run build`、`git diff --check`。

### 2026-07-05 本地补充：解析边界与大请求体稳定性

- 管理 API 的 JSON 解析现在要求一个请求体只包含一个 JSON 文档；用户创建、登录 CAPTCHA 和威胁情报同步等入口不再接受尾随第二段 JSON，避免部分解析后继续执行写操作。
- 威胁情报 provider 和单 IP 查询的外部响应体超过限制时会明确失败，不再静默截断后解析半截情报。
- Nginx 配置导入超过 1MB 时明确拒绝，避免半截配置被误解析。
- 数据面请求体分析改为“预览不截流”：WAF 只预览前 8MB 用于检测，超出时标记预览截断，但转发给源站的请求体保持完整，避免大文件上传被控制面分析逻辑截断。
- 本轮仅做本地可验证的后端鲁棒性补强；UI 验收、远端部署和双仓库同步等待新服务器目标明确后继续。

### 2026-07-06 本地补充：登录 / WAF CAPTCHA 与拦截页语言回归

- 登录 CAPTCHA 复核：后端继续覆盖默认开启、滑块 proof、一次性 receipt、失败锁定、PoW 兼容和尾随 JSON 拒绝；本轮用浏览器静态预览加 mock API 验证登录页正常渲染、滑块弹窗可打开且控制台无错误。
- WAF Bot CAPTCHA 加固：弱默认 Bot secret 需要运行时生成安全随机密钥；若随机源不可用，不再回退历史固定字符串，而是 fail-closed 返回 `bot challenge unavailable`，Altcha/header proof 和已有 clearance 也不会在无密钥状态下误通过。
- WAF 滑块 challenge 跳转清理补齐 `cw_slider_track`，避免拖动轨迹 JSON 残留在用户 URL 中。
- 拦截 / 报错页补充 5xx 多语言回归：`Accept-Language` 为简体中文或日文时，502 页面会返回对应 `Content-Language`、本地化错误文案、可见 Event / Trace ID 和 HTTP 状态。
- 本地验证通过：`go test ./internal/protection/bot ./internal/blockpage ./internal/api ./internal/captcha -run "CAPTCHA|Captcha|captcha|Challenge|CleanChallenge|Block|ErrorTemplate|Template|Renderer" -count=1`、`go test ./cmd/... ./internal/... -count=1`、`npm.cmd --prefix web run typecheck -- --pretty false`、`npm.cmd --prefix web run build`；浏览器烟测截图已本地归档，公开进度不记录本机路径。

### 2026-07-06 本地补充：dev/canary 合并前安全筛查与语义小步加固

- 已将 `codex/local-md-followups-20260705` 合并到本地 `dev`，并在合并后继续做登录网关与语义引擎安全筛查；当前改动保持小步可回归，不引入演示逻辑。
- 登录网关 / 数据面 IP 边界：默认 `engine.ClientIP` 不再信任客户端可伪造的 `CF-Connecting-IP`、`X-Real-IP`、`X-Forwarded-For` 等请求头，只使用 socket peer；需要 CDN / 反代真实 IP 时继续走 `ClientIPWithTrustedProxies` 的可信代理链路。
- 语义引擎：独立 `SQLDetector` 的候选源从整条请求文本扩展到查询参数和 `application/x-www-form-urlencoded` 字段值，并对每个候选做 bounded decode / base64 变体检测；候选数量与超长字段扫描长度已设置硬上限，长字段保留头尾片段检测，避免参数洪泛把语义检测变成资源消耗点；补充 base64 SQLi、超长字段尾部 SQLi 和 benign encoded documentation 样本，继续以降低漏检且控制误报为优先。
- 已通过定向验证：`go test ./internal/engine ./internal/engine/semantic -count=1`、`go test ./internal/api/handler ./internal/api/middleware ./internal/cli -run "Login|CAPTCHA|Admin|Token|Session|Entrance|ClientIP" -count=1`。
- 收口前仍需重新执行全量 Go、Web typecheck/build、`git diff --check`，再提交、推送 `dev`，合并到 `canary` 并同步 Forgejo。


## 2026-07-07 后续规划：Mesh HA 集群

已完成集群方向设计梳理。CheeseWAF 后续仍默认以单机模式运行，用户可从控制台“集群”菜单扩展为多节点。目标是保持单 Go 二进制优先，不默认依赖 Nginx、HAProxy、etcd、Redis 或 PostgreSQL；外部组件只作为高级增强。规划中的集群形态包括单机模式、双节点负载均衡模式、双节点 + 监控节点的最小高可用模式，以及三台以上 WAF 节点的多节点高可用模式。

集群设计将采用产品化表达：防数据偏差、监控节点、多数确认、协调节点、保护模式、部署前检查、仅检查不应用、开发版/预览版/正式版。核心路线分为四步：集群配置与声明式对象模型、Ansible/临时 SSH 部署与安全加入、内置一致性和多链路心跳、生产级内置流量调度与滚动升级。详细规划见 `docs/superpowers/plans/2026-07-07-cheesewaf-mesh-ha-cluster.md`。

M1 已完成基础落地：配置层新增默认单机的 `deployment` / `cluster` 模型，校验会阻止“两台 WAF 节点被误标为完整高可用”；后端新增声明式对象模型和单机对象存储；CLI 新增 `cheesewaf cluster status/init/export`；API 新增集群状态与健康端点；Web 控制台新增“集群”菜单和状态页。

M2 后端 / CLI / Web 基础能力正在推进：已实现无明文凭据的 Ansible 部署包生成、临时 SSH 部署检查/固定动作执行、异步部署任务、任务基础审计时间线、一次性加入令牌、令牌驱动的节点加入 API、CSR 节点证书签发、节点登记、CLI `cluster join`、Web 令牌 / 节点 / 任务基础视图，以及基于管理审计与部署任务事件的集群操作记录。当前不能宣称 M2/M3/M4 完成；完整生产部署向导、`monitor-node` runtime、心跳 / 多数确认、滚动升级、生产流量调度仍是后续工作。现有 `restart-service` 失败后的处理是恢复尝试 / 补偿动作，不是回滚。

2026-07-08 追加：Web 集群页的部署区已从“任务提交器”推进为基础向导。Ansible 路径可填写集群 ID、开发版/预览版/正式版通道和节点清单，调用后端生成部署文件并支持预览、复制、下载单文件和下载 JSON 包；临时 SSH 路径拆分 SSH Agent、一次性密码、一次性私钥和主机密钥校验方式，并要求先完成部署前检查后才能执行固定动作。移动端布局补齐为单列和任务卡片，避免表格挤出。该能力仍是 M2 基础向导，不包含完整安装器、部署回滚 / 滚动升级、monitor-node runtime、心跳、多数确认或生产流量调度。

### 2026-07-08 本地补充：M2 集群部署与加入流后端基础

- 集群 M2 后端 / CLI / Web 基础能力继续推进：可生成无明文凭据的 Ansible 部署包；管理 API 新增部署包生成、部署检查和固定动作 SSH 部署入口；CLI 新增 `cluster token create/list/revoke`。固定动作中的 `install` 已具备基础安装能力：通过同一 SSH 会话上传当前控制端 CheeseWAF 二进制，或上传 `CHEESEWAF_DEPLOY_BINARY` 指向的二进制，在远端校验大小和 SHA-256，运行 `--version`，备份并替换 `/usr/local/bin/cheesewaf`，再校验安装后的版本；`rollback-install` 可验证并恢复最新 `/usr/local/bin/cheesewaf.bak.*` 备份，并在覆盖前保留当前二进制的 `pre-rollback` 备份。该能力仍是单节点二进制安装 / 更新 / 恢复基础，不等同于完整部署向导、自动加入集群或滚动升级。
- Web 部署向导基础增强：集群页新增部署方法选择、步骤条、Ansible 节点清单、部署包预览/复制/下载、临时 SSH 认证方式选择、主机密钥校验方式选择和部署任务卡片式移动端视图；所有数据走现有 API，不生成演示数据。
- 临时 SSH runner 通过 Go `x/crypto/ssh` 建立连接，支持单次请求内的一次性 SSH 密码和一次性私钥内容；凭据只在请求内存中使用，不持久化、不写入临时密钥文件、不进入 argv/env，请求结束后释放。API 不允许借用服务端任意本地私钥路径。runner 不接受任意远端命令字符串，只允许固定部署动作；执行有默认超时和输出上限，避免管理 API 被远端命令卡死或输出撑爆内存。
- 加入令牌使用随机值、哈希落盘、TTL、最大使用次数、一次性消费和撤销状态；API 创建令牌只返回一次明文，列表响应不暴露 token hash 或明文。
- 节点加入自举新增 `/api/cluster/join` 和 `cheesewaf cluster join`：新节点使用一次性令牌和本地 CSR 换取 CA / 节点证书，CLI 在本地生成并保存节点私钥和 cluster 配置；控制端登记已加入节点，Web 控制台可查看加入令牌和节点登记表。
- 2026-07-08 追加加固：节点加入改为 CSR 模式，新节点本地生成私钥和证书请求，控制端只签发 CA / 节点证书，不再默认生成或下发节点私钥；CLI 本地演练模式不联系控制端、不消耗令牌。配置保存改为临时文件写入后替换，并在 join 配置落盘失败时回滚节点登记和令牌使用次数。
- 节点证书签发与轮换已走 CSR：加入和轮换时均由节点本机生成私钥与 CSR，控制端要求 CSR 标识当前申请 / 已登记节点，只签发 CA / 节点证书并更新节点登记，不生成、不保存、不返回节点私钥。CLI `cluster cert rotate` 会在目标节点本机生成新私钥和 CSR，拿到签发结果后本机落地 CA / 证书 / 私钥，并在本机写入失败时回滚本机文件；Web 只提供 CSR 签发入口和证书/CA 返回，不承载私钥。
- 部署任务时间线基础已补齐：管理 API 新增异步部署任务创建、查询和列表；Web 集群页改为显示任务 ID、等待中 / 执行中 / 成功 / 失败状态、阶段、开始 / 更新 / 完成时间、脱敏命令 / 输出 / 错误摘要，形成可复核的任务审计时间线。任务事件按排队、本地校验、连接节点、检查完成、动作完成、失败、凭据清理记录；本地参数校验失败不会伪装成已经连接。一次性 SSH 密码和私钥内容不会出现在任务响应或任务列表中，任务结束后从内存请求对象清除；脱敏覆盖 password / private_key / privateKey / api_token / access_token / Authorization Token / Bearer 等常见形态。Web 当前任务不再在列表刷新窗口回退到旧任务，内置事件文案会按当前语言显示；旧同步检查 / 执行动作接口暂时保留兼容。
- 集群操作记录基础已补齐：管理 API 新增 `GET /api/cluster/audit`，聚合控制台审计日志中 `/api/cluster/*` 操作、公开自举 `/api/cluster/join` 的安全审计记录，以及异步部署任务事件；Web 集群页新增“集群操作记录”面板，展示时间、来源、动作、执行者、目标、状态、远端 IP 和消息。加入令牌明文、CSR、证书私钥、SSH 密码和私钥不会写入该审计响应。该能力是基础操作记录，不等同于 M3 后的节点心跳、多数确认或对象调和审计。
- M4 开始前新增语义引擎、AI 助手和 API 令牌收口门槛：语义置信度阈值要继续与防护等级联动，默认低置信不拦截；AI 助手要补齐内置 WAF 知识库、提示词加固、长推理流式保活和单事件实时思考输出；WAF API 令牌必须复用 RBAC / 审批边界，包含权限矩阵、生命周期、审计和帮助文档，不允许绕过控制台权限模型。
- Kimi UI 修复经只读复核：主题变量、z-index、reduced-motion、AI 状态色等主要项已落地；本轮额外补齐 `--border-strong`、`--border-color`、`--danger`、`--font-mono` 主题变量，减少灰字/边框回退风险。
- 当前仍不能宣称 M2/M3/M4 完成：完整 Web 部署向导、`monitor-node` runtime、多链路心跳、多数确认、保护模式写冻结、Raft/etcd、一致性对象调和、滚动升级和生产流量调度仍是后续工作。`restart-service` 失败后的 `systemctl start cheesewaf` 仅是恢复尝试 / 补偿动作，不是回滚能力；`rollback-install` 只是单节点二进制备份恢复动作，不是滚动升级编排。

### 2026-07-09 本地补充：集群运行态心跳与保护模式基础

- 集群状态从单纯配置推导推进为“配置节点 + 运行态心跳”聚合：新增 `HeartbeatRegistry`、运行态节点状态、心跳 TTL、在线投票节点统计、多数确认计算，以及 `POST /api/cluster/nodes/{id}/heartbeat`。心跳接口已改为节点 mTLS 证书绑定：请求必须携带由集群 CA 验证过的节点客户端证书，证书序列号和 `cluster/role/node` 身份必须匹配已登记节点与 URL 中的 node_id；普通管理会话或管理 API 令牌不能伪造节点心跳。接口拒绝未知节点和已撤销节点，且不进入常规集群操作审计列表，避免心跳噪声淹没人工操作。
- `GET /api/cluster/status` 和 `/health/cluster` 已读取运行态聚合结果；Web 集群页节点表新增运行状态、最后心跳和配置版本显示。本机节点会作为在线节点参与运行态显示；远端节点超出心跳 TTL 后显示为超时，并会影响最小高可用 / 多节点高可用模式下的多数确认。多数确认现在只统计在线且可参与配置写入的投票节点，远端节点若明确声明 `can_write_config=false`，不会解除写冻结。
- 保护模式写冻结进入基础阶段：当 HA 模式没有多数节点心跳且启用 `freeze_writes_without_majority` 时，系统设置、站点、规则、防护/IP/威胁情报、AI 设置、管理 API 令牌、运维任务、边缘策略、拦截页和 ACME 签发等主要配置写入口会返回 `423 CLUSTER_PROTECTION_MODE`。该能力仍是单进程内运行态基础，不等同于多链路心跳、Raft/etcd、对象调和或跨节点写事务。
- 当前仍不能宣称 M2/M3 完成：`monitor-node` 常驻进程、多链路心跳、节点维护/隔离、保护模式下跨节点一致性仲裁、对象调和、滚动升级、生产流量调度和故障转移仍需继续推进。

### 2026-07-08 本地补充：M4-0 API 令牌与 AI 流式保活收口

- AI 助手内置知识库补齐 M4-0 关键主题：管理 API 令牌权限边界、语义置信度与防护等级联动、AI 流式推理、工具审批和安全默认值。知识库内容用于回答和引导操作，不把配置密钥、日志 payload 或系统提示词当可信上下文。
- AI provider 长推理首包慢时新增持续进度事件：在 provider 尚未返回首个 delta 前，后端会定期推送等待状态，前端和单事件分析页不再把 30 秒内没有最终回答误判为 network error；真正的 provider 错误仍会被明确标注。
- 管理 API 令牌能力已进入控制台与后端：默认关闭，启用后支持 `cwapi_` Bearer token、scope 复用 RBAC、创建 / 列表 / 撤销、TTL、备注、一次性明文展示和只保存 `sha256:` hash。禁用、过期、撤销、格式错误或全局关闭时均 fail-closed 返回 401。
- 管理 API token 不刷新浏览器会话，不绕过 AI 工具审批，也不绕过现有路由权限；自动化访问继续进入审计中间件，审计记录新增稳定 `subject=api-token:<id>`，排查时不依赖可改名的 token 显示名。
- 管理 API token 创建与控制台开关保持一致：功能关闭时后端拒绝创建新 token，避免出现“页面显示关闭但接口仍能生成凭据”的半启用状态。
- 运维文档新增 `docs/management-api.md`，`docs/phase4-operations.md` 已同步安全模型、RBAC / 审计边界和控制台使用流程。
- 当前仍不能宣称整个 M4-0 完成：语义语料筛选、误报 / 漏报基线、性能基线、AI 知识库订阅和审批策略可视化仍需继续推进。

### 2026-07-09 本地补充：语义策略评分与防护等级联动

- 本轮按减少 CI 消耗的原则只做本地开发与验证，暂不提交、不推远端。
- 语义检测流水线不再在 semantic 组第一个 block 结果处立即返回，而是保留并比较同组检测结果，选择动作、严重度和置信度更高的主结果，同时保留 `RequestContext.Results` 供策略层使用。
- Web 攻击策略决策新增内部防护强度级别、聚合风险分、风险阈值和证据数量；后续 UI 可以用这些字段解释“智能模式 / 保守模式 / 严格模式”的决策原因。
- 默认智能模式仍按业务优先，单条证据继续先看严重度与置信度阈值；多条证据会进入聚合评分，只有达到当前防护等级阈值才升级为拦截或验证。
- 低防护等级保持保守：低于阈值的聚合证据仍只记录日志，避免把可疑但不确定的业务请求误拦截。
- 服务启动时的 WAF 检测流水线不再只使用第一个站点的语义开关和自定义规则；每个站点的语义 detector 与自定义规则会按站点 ID 作用域执行，避免多站点场景下漏检或误把其它站点规则套到当前站点。
- AI 批量事件分析新增 SSE 流式接口，前端会随 `item` 事件逐条展示分析结果，避免用户点击“分析最近事件”后长时间干等；普通放行访问日志不再混入攻击 / 可疑事件分析。
- AI 事件流式分析仍保留 provider 错误边界和启发式降级，后续还需要继续做审批恢复、知识库订阅和长推理 UI 细节打磨。
- 本地验证通过：`go test ./internal/cli -run "BuildPipeline" -count=1`、`go test ./internal/ai ./internal/api/handler ./internal/engine ./internal/proxy -count=1`、`npm.cmd --prefix web run typecheck -- --pretty false`、`npm.cmd --prefix web run build`、`git diff --check`；AI 页面桌面 / 移动端截图复核已本地归档。

### 2026-07-09 本地补充：Kimi UI 复核后的 AI 页排版收口

- 已按 UTF-8 重新读取最新 `kimi_found.md`，确认新增重点包括 AI 页 CSS 碎片化、中文界面黑话、主题硬编码颜色和攻击地图专项问题；本轮只收口 AI 页可独立验证的问题，暂不提交、不推远端。
- AI 页样式新增独立 `web/src/styles/ai-page.css` 并在 `main.tsx` 中后置加载，用于承接 AI 页最终布局层；事件列表移除旧移动端重复 DOM，改为一套响应式事件行，路径显示从裸代码蓝字调整为可截断的路径胶囊。
- AI 页布局回到左侧“安全事件 + 连接配置”、右侧“事件分析详情”的稳定结构；连接配置中的助手模型和推理模型改为纵向卡片，避免桌面左栏内字段被挤碎。移动端保持单列，按钮与路径不横向溢出。
- 单事件流式分析完成后会清理当前实时流状态和 AbortController，避免“分析过程”卡片在完成后长期占位并挤压最终结果。
- 中文文案继续去掉 Kimi 点名的 AI 黑话：`LLM`、`深度思考`、`思考摘要`、`总览态势`、`总计态势`、`实时态势` 等不再出现在中文前端文案中；`URI` 等硬编码字段已改走日志路径本地化。
- 主题层补充并接入部分变量：3D 地图背景、登录媒体背景、登录遮罩和拦截页预览背景改用主题变量，降低浅色 / 暗色 / 黑金 / 蓝白主题割裂。
- 本地验证通过：`npm.cmd --prefix web run typecheck -- --pretty false`、`go test ./internal/ai ./internal/api/handler -run "Approval|Assistant|AITool|Continue|Analyze" -count=1`、`npm.cmd --prefix web run build`、`git diff --check`、`node .\tmp\check-ai-page-ui.cjs`。AI 页桌面 / 移动端截图复核已本地归档。
- 仍未完成且不能写成完成：`global.css` 中旧 AI 页规则仍需要逐步迁出，大量 `!important` 和硬编码颜色仍需继续消化；攻击地图专项中的 Three 场景增量更新、地图 / 大屏 CSS 拆分、按容器尺寸计算平移边界、Arco 大 chunk 拆分仍是下一批结构任务。

### 2026-07-09 本地补充：攻击地图资源懒加载与大 chunk 收敛

- 已按最新 `kimi_found.md` 复查攻击地图专项问题，并先处理对首屏性能和稳定性影响最大的资源加载路径；本轮继续不提交、不推远端，降低无效 CI 消耗。
- 将攻击地图聚合、世界地图投影、国家风险分级和共享类型从 `AttackMapPage.tsx` 抽到 `web/src/pages/AttackMap/attackMapData.ts`，避免 `GlobeMap`、攻击大屏和中国边界模块继续反向依赖页面组件。
- 将中国行政边界模块改为 `mode=china` 时动态加载；普通 2D 攻击地图不会提前加载中国边界处理逻辑。
- 将 `china-map-echarts` 行政边界 JSON 和 `@province-city-china` 省 / 市 / 区索引改为运行时静态资源读取，由 Vite 插件在 dev / build 中通过白名单路径服务和复制；`dist/assets` 不再输出地图 JSON，通用 vendor chunk 从约 576KB 降到约 294KB。
- 新增内置 adcode manifest 过滤：内置包缺少区县级 JSON 时不再用 404 探测，前端会静默降级到可用的市 / 省边界与真实地理坐标点，避免中国模式控制台红错。
- 本轮验证通过：`npm.cmd --prefix web run typecheck -- --pretty false`、`npm.cmd --prefix web run build`、`git diff --check`、Playwright 攻击地图桌面 2D / 中国模式 / 移动 2D / 攻击大屏截图检查均为 0 issues；截图写入 `output/playwright/attack-map-*.png`。
- 后续仍需继续：`GlobeMap` 日志刷新导致场景重建的问题、地图 / 大屏 CSS 从 `global.css` 拆分并消除重复覆盖、按容器尺寸计算平移边界、低端移动设备真实性能采样。

### 2026-07-09 本地补充：3D 攻击地图运行时优化

- 继续按最新 `kimi_found.md` 攻击地图专项建议推进，本轮仍保持本地开发，不提交、不推远端，减少无效 CI 消耗。
- `GlobeMap` 已拆分 Three.js 生命周期：场景、相机、渲染器、云层、星场、光照和交互事件只在挂载 / 主题切换时创建；日志刷新时只更新世界风险贴图、攻击标记、脉冲圈和飞线，不再销毁并重建整套 WebGL 场景。
- 3D 地图的动画循环补齐暂停逻辑：页面隐藏时取消 `requestAnimationFrame`，恢复可见后再继续；系统启用减少动态效果时停止自动旋转和流动动画，仅在交互或数据更新时渲染。
- 3D 地图新增基础可访问性标签，tooltip 和命中检测读取运行时最新标记集合，避免数据更新后 hover 命中旧对象。
- 地图卡片排版做了小步收敛：普通地图高度按视口收敛，3D 默认相机位置后退并居中，减少地球被卡片底部裁切；2D / 中国地图宽度减少左右空边。
- 本轮验证通过：`npm.cmd --prefix web run typecheck -- --pretty false`、`npm.cmd --prefix web run build`、`git diff --check`、Playwright 攻击地图桌面 2D / 中国模式 / 3D / 攻击大屏 / 移动 2D 截图检查均为 0 issues；截图与报告写入 `output/playwright/attack-map-runtime-*`。
- 后续仍需继续：`vendor-three-webgl`、`vendor-arco` 和 CSS 大包拆分，地图 / 大屏 CSS 从 `global.css` 迁出，平移边界按容器动态计算，真实低端设备性能采样，以及 Kimi 点名的全局 CSS 重复覆盖治理。

### 2026-07-09 本地补充：首屏 chunk 与地图样式懒加载收口

- 按最新 `kimi_found.md` 重新复查前端排版、主题和攻击地图专项建议后，先处理对首屏加载和白屏风险影响最大的部分；本轮仍保持本地开发，不提交、不推远端，避免每个小修都触发 CI。
- `MainLayout` 已改为受保护路由下的懒加载 chunk，并在 `ProtectedLayout` 外层补齐 `Suspense`，避免登录 / 设置等公开页面提前携带侧栏、通知、AI 助手和监控查询逻辑，同时避免布局 chunk 首次加载时白屏。
- Arco `ConfigProvider` 改为直接入口导入；二维码库从 lucide 图标工具包中拆为独立 `vendor-qrcode`；AI 页样式和攻击地图最终层样式改为随页面懒加载，不再从 `main.tsx` 全局入口加载。
- `GlobeMap` 继续保持独立懒加载，并将 Three.js 相关产物拆成 core / webgl / renderer / scene 等 chunk；生产构建恢复 500KB 体积警戒线后，JS chunk 已无超限警告：最大 JS chunk 为 `vendor-arco` 约 496KB，`vendor-three-webgl` 约 342KB，入口 `index` 约 153KB。
- Playwright 回归覆盖登录页和 3D 攻击地图：登录页未白屏，加载耗时仍在卡片下方；3D 地图浅色主题下实际渲染地球、飞线和控件，报告为 0 issues。
- 中国区域地图补齐边界资源降级提示：当内置 / 外部行政区边界资源不可用时，页面不再无限显示加载中，而是明确提示边界数据不可用，并保留可用的定位点 / 统计数据展示路径。已用生产构建的 `vite preview` 模拟静态边界资源 404，截图验证无白屏、无无限转圈，报告为 0 issues。
- 攻击地图可访问性与加载体验继续收口：2D / 中国地图 SVG 改为可读的 `role="img"` 和本地化 `aria-label`，攻击点补齐 `aria-pressed` 并移除原生 `title` 悬浮提示；攻击大屏当前页导航补齐 `aria-current`，时间轴滑杆补齐本地化 `aria-label`。`/attack-map` 导航 hover / focus 和页面空闲时会预加载地图与 3D 地球相关 chunk，切 3D 时用静态地图 fallback 替代空 spinner，降低首次打开的空白感。
- 本轮追加验证通过：`npm.cmd --prefix web run typecheck -- --pretty false`、`npm.cmd --prefix web run build`、`git diff --check`；生产构建 `vite preview` 下完成 2D / 3D / 攻击大屏截图回归，确认地图 ARIA、无原生 marker title、3D 地球渲染和大屏时间轴可用。
- 仍不能宣称“大 chunk / CSS 治理完成”：Arco 官方 CSS 约 555KB、历史 `global.css` 构建后约 321KB，且 `kimi_found.md` 点名的全局选择器重复覆盖、硬编码颜色和 AI / 地图旧样式迁移仍需分批治理。Three 当前使用 `three/src/*` 子模块导入以降低 chunk 体积，已通过本地构建和浏览器回归，但长期仍需在“稳定入口导入”和“体积控制”之间做一次更完整的技术取舍。

### 2026-07-09 本地补充：Kimi 复核后的 AI 审批与主题兜底

- 重新读取最新 `kimi_found.md` 后，先处理低风险但影响明显的问题：AI 助手审批按钮在流式执行或拒绝请求进行中会进入统一禁用状态，避免重复点击导致同一审批并发执行或状态回退。
- AI 助手补齐 `approved` / `executing` 工具状态和审批卡片样式，审批通过、执行中、已执行、已拒绝状态在 UI 上不再共用默认灰色标签。
- AI 助手、AI 分析页和日志详情页均补齐 `tool_call_delta` 的可见展示：工具参数流式片段不会再被过滤掉，用户能看到“正在规划工具 / 已收到参数片段”的过程反馈；助手线程在用户发送消息或继续审批后会跟随最新消息，并增加双帧与短延迟滚动兜底，避免工具卡片被折叠区高度变化挤出视野。
- 全局样式补充主题变量兜底，包括文本强弱、成功色、等宽字体、阴影 / 高光和 3D 地图背景变量；后置的 3D 地图深蓝硬编码背景已改为读取 `--map-canvas-3d-bg`，避免浅色 / 黑金主题被旧规则覆盖。
- 中文文案继续小步清理残留 AI 味：运维任务中的“AI 自学习”改为“自动规则学习”，攻击地图“区域态势图”改为“区域分布图”；后端 AI 错误与 trace 中的 `AI provider` 混写改为“AI 服务商 / AI service provider”。
- 本轮验证通过：`npm.cmd --prefix web run typecheck -- --pretty false`、`npm.cmd --prefix web run build`、`go test ./internal/ai ./internal/api/handler -run "Approval|Assistant|AITool|Continue|Analyze|Provider" -count=1`、`git diff --check`、`node tmp\assistant-tool-ui-smoke.cjs`。AI 助手审批局部截图已复核：`tmp/screenshots/assistant-tools/approval-thread.png` 可见执行轨迹、参数片段、审批按钮和 diff 预览。本轮未提交、不推送；Arco / Three 大 chunk、攻击地图运行时性能和 `global.css` 重复覆盖治理仍按后续批次处理。

### 2026-07-09 本地补充：攻击大屏刷新策略与中文术语收口

- 按 `kimi_found.md` 与子代理复核建议继续收口攻击地图：攻击大屏时间轴停在历史范围（小于 100%）或正在拖动时会暂停 `/api/logs` 与 `/api/monitor` 自动轮询，避免用户回看历史时 3 秒刷新导致时间窗口漂移；回到 100% 后恢复实时刷新。
- 攻击大屏顶部状态会随时间轴切换为“实时 / 历史视图”，减少“看历史数据但仍显示实时”的误导。3D 地球输入限制为攻击数最高的前 80 个可定位区域，国家/地区着色仍按全量区域计算，降低 Three marker 重建成本。
- 中文界面继续去掉低价值英文术语：API 安全的 Schema 改为“接口结构”，管理 API 的 Bearer / RBAC / Scope / Audience 等文案改为访问令牌、角色权限、权限范围、受众；站点可信 CIDR、PoW / Altcha 改为带中文说明的术语。
- 本轮追加验证通过：`npm.cmd --prefix web run typecheck -- --pretty false`、`npm.cmd --prefix web run build`、`git diff --check`、`node tmp\local-map-ai-block-check.cjs`。浏览器回归确认 3D 地图与攻击大屏仍可自动旋转 / 拖拽，页面滚动不被地图滚轮带动，中国区域边界仍加载 47 条 path，AI 页与拦截页预览无横向溢出；新增断言确认历史视图停留 3.8 秒不再继续轮询，回到 100% 后恢复刷新。
- 仍未完成：`GlobeMap` marker 增量更新、攻击地图 / 大屏旧 CSS 从 `global.css` 继续迁出、Arco / Three / CSS 大包治理、真实低端设备性能采样，以及系统页更多专业术语的逐项说明。

### 2026-07-09 本地补充：3D 地球 marker 刷新抖动收敛

- 继续处理 `kimi_found.md` 点名的 3D 地图刷新跳动：`GlobeMap` 的 marker 重建签名不再包含原始攻击数，日志刷新只导致攻击数变化时不会清空并重建整组 marker、脉冲圈和飞线，降低动画相位重置与瞬时抖动。
- 新增运行时 region 对象索引：当区域结构未变但攻击数、事件摘要等数据变化时，只更新已有 Three 对象的 `userData.region`；hover tooltip 继续读取最新 region 数据，不需要为了更新数字而重建几何对象。
- 本轮浏览器回归通过：`node tmp\local-map-ai-block-check.cjs` 确认普通 3D 地图和攻击大屏仍可自动旋转 / 拖拽，页面滚轮不被地图带动，中国区域边界仍为 47 条 path，AI 页和拦截页预览无横向溢出，攻击大屏历史视图暂停轮询断言继续通过。
- 仍未完成：当区域新增 / 删除 / 坐标 / 风险级别 / marker 尺寸变化时仍会重建 marker；后续若要进一步降抖，需要按 `region.key` 做对象复用、增删补丁和材质颜色/scale 原地更新。攻击地图 / 大屏旧 CSS 迁出、Arco / Three / CSS 大包治理和低端设备性能采样仍在后续批次。

### 2026-07-09 本地补充：语义引擎低误报优先小步加固

- 按低误报优先原则，本轮没有堆宽泛规则，而是补 SSTI 的 OGNL / Struts 危险语义识别：`%{...}` 只有同时出现 OGNL 上下文逃逸、Java Runtime 静态方法或类似执行原语时才命中；普通 `%{ user.name }` 占位符保持放行。
- `NoSQLiDetector` 与 `SSTIDetector` 的独立调用路径已复用 `Analyzer` 的结构化输入、深度解码和语义门控，避免直接调用时绕过文档文本 / CMS 模板正文等良性上下文判断；日志侧仍保留原 detector ID。
- SSRF 数字主机解析补齐 inet_aton 短 IPv4 绕过形态，包括 `127.1`、`0177.1`、`0x7f.1`、`10.1`，但仍严格要求 fetch sink，不对普通文档文本泛匹配。
- readiness 与 curated corpus 新增 SSTI OGNL 攻击样本和 benign 邻居；direct detector 新增攻击 / 良性回归测试，确保增强不会变成误报扩大。
- 当前验证通过：`go test ./internal/engine/semantic -run "TestAnalyzerReadinessMatrix|TestAnalyzerReadinessBenignMatrix|TestAnalyzerCuratedExternalCorpus|TestPhase2SemanticDetectors" -count=1`、`go test ./internal/engine/semantic -run "TestNoSQLiDetectorUsesAnalyzerGate|TestSSTIDetectorUsesAnalyzerGate|TestSSRFDetectorBlocksNumericHostVariants|TestSSRFDetectorRequiresFetchSink" -count=1`。
- 仍未完成：XXE direct detector 误报面收窄、异常评分 / 防护等级联动的完整模型、CRS FTW 对标、真实误报基线、内存分配 profile，以及 Kimi 点名的前端布局 / 大 chunk 专项。

### 2026-07-09 本地补充：Kimi 点名 UI 回归修复

- 按最新 `kimi_found.md` 复查后，修复 IP 管理访问名单的响应式切换：桌面 / 笔记本恢复表格视图，窄屏继续使用规则卡片，避免页面级 CSS 把桌面表格永久隐藏。
- AI 助手流式输出的滚动策略改为“在底部则跟随，用户手动上滚则停止跟随”；发送新消息或继续审批时只强制滚动一次，避免长回答 / 工具审批时把用户持续拉回底部。
- `SafeMarkdown` 增加空值兜底，日志详情页和 AI 分析结果即使遇到后端未返回 summary / reasoning 也不会因 `undefined.replace` 崩溃。
- AI 页事件列表修复时间 + IP 被标签挤压导致的内部横向溢出，中等宽度下不再出现 30px 窄列。
- 本轮验证通过：`npm.cmd --prefix web run typecheck -- --pretty false`、`npm.cmd --prefix web run build`、`node tmp\full-ui-regression.cjs`（112 个页面 / 视口组合，0 failures）、`node tmp\assistant-tool-ui-smoke.cjs`、`git diff --check`。已抽查 `desktop-ip-access`、`mobile-ip-access`、`laptop-ai`、`desktop-log-detail` 截图。
- 大 chunk 治理仍作为后续专项：当前构建最大块仍为 Arco CSS / Arco JS / Three WebGL，短期不在本轮混入结构性拆包改动。

### 2026-07-09 本地补充：XXE 误报收窄与首屏资源懒加载

- 继续按低误报优先原则收敛语义引擎：`XXEDetector` 的独立调用路径已复用 `Analyzer` 的结构化输入、深度解码和语义门控，并保留 `semantic.xxe` detector ID；文档说明字段中的 XXE 样例不会再被直接正则误拦。
- `analyzeXXE` 增加 XML / 载荷语境判断：只有 XML 文档或明确的 `xml/body/payload/document/soap/saml/metadata` 等载荷字段，同时具备 DTD/entity、SYSTEM/PUBLIC 外部解析和文件 / 网络 / 敏感目标时才命中。
- 首屏资源加载按 `kimi_found.md` 与子代理建议收口：全局 AI 助手改为轻量入口，首次点击后才加载完整 `AIAssistant` chunk；完整助手的工具 / 监控 / 日志轮询只在面板打开或关闭动画期间启用。
- `MainLayout` 去掉登录后无条件 idle 预加载 AI 页和 API 安全页；`/attack-map` 导航预加载不再提前拉 `GlobeMap` 与 Three，默认 2D 地图只在切换 3D 或进入攻击大屏时加载 3D 相关资源。
- 本轮验证通过：`go test ./internal/engine/semantic -run "TestXXEDetectorUsesAnalyzerGate|TestPhase2SemanticDetectors|TestAnalyzerReadinessMatrix|TestAnalyzerReadinessBenignMatrix|TestAnalyzerCuratedExternalCorpus" -count=1`、`go test ./internal/engine ./internal/engine/semantic -count=1`、`npm.cmd --prefix web run typecheck -- --pretty false`、`npm.cmd --prefix web run build`。生产构建 `vite preview` + Chrome Canary 资源检查确认：首页不加载 `AIAssistant` / Three，默认 2D 地图不加载 Three，点击助手和 3D 模式才加载对应 chunk；截图写入 `tmp/screenshots/lazy-loading/`。
- 仍未完成：Arco JS / CSS 大包、`global.css` 重复覆盖和攻击地图样式迁出仍需分批治理；Three 场景更细粒度对象复用和真实低端设备性能采样也仍在后续批次。

### 2026-07-09 本地补充：Arco JS 大包拆分

- 继续处理大 chunk 专项，但只做构建层低风险调整：`vite.config.ts` 中的 Arco JS 手动分块从单一 `vendor-arco` 拆为 `vendor-arco-core`、`vendor-arco-data`、`vendor-arco-form`、`vendor-arco-overlay`。
- 生产构建结果：原 `vendor-arco` JS 约 496KB；拆分后最大 Arco JS chunk 为 `vendor-arco-core` 约 307KB，`vendor-arco-data` 约 104KB，`vendor-arco-form` 约 52KB，`vendor-arco-overlay` 约 35KB。`index.html` 只预加载 core，没有提前预加载 data/form/overlay。
- Chrome Canary 回归确认：Dashboard 首屏加载 core/data，不加载 AI 助手和 Three；点击 AI 悬浮入口后才加载 `AIAssistant`；默认 2D 攻击地图仍不加载 Three，3D 模式才加载 `GlobeMap` 和 Three。运行时 console/pageerror 为 0，截图写入 `tmp/screenshots/chunk-split/`。
- 本轮验证通过：`npm.cmd --prefix web run typecheck -- --pretty false`、`npm.cmd --prefix web run build`、`git diff --check`。
- 仍未完成：Arco CSS 仍约 555KB，`index.css` / `global.css` 仍偏大；后续需要继续拆页面级 CSS、评估 Arco 样式按需方案，并做真实网络瀑布与低端设备采样。

### 2026-07-09 本地补充：AI 助手与 IP 管理样式按需加载

- 继续按 `kimi_found.md` 的 CSS 治理建议推进，仍保持本地开发，不提交、不推远端，避免每个小修都触发 CI。
- AI 助手面板的空状态、快捷问题、深度推理开关、输入框和发送按钮样式已迁入 `web/src/components/AIAssistant/AIAssistant.css`，由完整助手组件按需加载；全局只保留 FAB、基础面板和共享 Markdown 等必要样式。
- 修复助手输入框圆角实际未生效的问题：当前 Arco 输入框渲染为 `.assistant-input .arco-input`，已与 `.arco-input-inner-wrapper` 一起覆盖，发送按钮和输入框均为圆角体系。
- IP 管理页的 `.ip-*`、`.provider-*`、`.intel-*`、`.tag-token*`、`.duration-input-group` 残留样式已从 `global.css` 迁入 `web/src/styles/ip-manage.css`，并统一加上 `.ip-manage-page` 作用域，避免 provider / intel 这类泛命名继续污染全局。
- 构建结果：入口 CSS 从约 322KB 降到约 302KB；IP 管理样式变为按路由加载的 `IPManagePage` CSS chunk，约 30KB。Arco CSS 仍约 555KB，不能写成已完成。
- 本轮验证通过：`npm.cmd --prefix web run typecheck -- --pretty false`、`npm.cmd --prefix web run build`、`git diff --check`。Chrome Canary + 生产构建 `vite preview` 复核确认：首页点击前不加载 `AIAssistant` JS/CSS，点击后才加载；IP 管理条目 / 访问名单 / 情报源 / 导入页在桌面和移动端均无横向溢出，访问名单桌面为表格、移动端为卡片。
- 后续仍需继续：攻击地图 / 攻击大屏旧样式从 `global.css` 迁入 `attack-map.css`，AI 页旧样式继续拆分，`global.css` 重复选择器和硬编码颜色继续收敛，以及 Arco CSS 按需加载方案评估。

### 2026-07-09 本地补充：攻击地图 / 大屏样式按路由加载

- 继续按最新 `kimi_found.md` 和子代理只读复核推进 CSS 治理，本轮仍保持本地开发，不提交、不推远端，减少 CI 空转。
- 攻击地图与攻击大屏相关的 `.attack-map-*`、`.attack-screen-*`、`.map-canvas`、`.flat-map-stage`、`.globe-stage`、`.world-map-svg`、`.china-*`、`.map-marker`、`.attack-region-*` 等旧规则已从 `global.css` 迁入 `web/src/styles/attack-map.css`，并补上 `.attack-map-page` / `.attack-screen` 作用域；`console-map-*` 系统设置样式和 `--map-canvas-3d-bg` 主题变量保留在全局。
- 迁移过程中清理了两段历史半截注释导致的 CSS 语法残留；生产构建由 Lightning CSS 校验通过，避免“浏览器吞掉后半段样式”的隐性风险。
- 构建结果：入口 `index.css` 从约 302KB 继续降到约 240KB，地图样式变为按路由加载的 `attack-map` CSS chunk，约 59KB；Arco 官方 CSS 仍约 555KB，不能写成完成。
- 本轮验证通过：`npm.cmd --prefix web run typecheck -- --pretty false`、`npm.cmd --prefix web run build`、`git diff --check`、`node tmp\local-map-ai-block-check.cjs`。浏览器截图复核确认 3D 地图 / 攻击大屏 canvas 非空、可自动旋转和拖拽，地图滚轮不带动页面，中国区域边界仍加载 47 条 path，AI 页和拦截页预览无横向溢出。
- 剩余风险：攻击大屏浅色模式地球视觉仍偏小且位置偏上，属于后续视觉打磨项；AI 页、拦截页、API 安全页和登录验证码样式仍有较多全局残留，后续按页面继续拆分。

### 2026-07-09 本地补充：拦截页样式懒加载与运行时模板小修

- 已重新读取最新 `kimi_found.md`，并用子代理只读复核当前 CSS 治理状态；确认已缓解的内容包括未定义 CSS 变量、登录面板职责混杂、攻击地图样式初步拆分和 Arco JS 分块，但 AI 页旧样式、攻击地图内部重复覆盖、Arco CSS 大包仍未完成。
- 拦截/报错页样式已从 `global.css` 迁入 `web/src/styles/block-pages.css`，并通过 `.block-pages-page` 作用域隔离；独立预览路由的 `.block-preview-standalone*` 保持全局可用，避免新窗口预览丢样式。
- Dashboard 增加接口返回形状兜底：周期日志、实时日志、站点列表和资源回收动作会先确认数组再 `.filter` / 统计，避免异常响应或测试 mock 返回对象时触发白屏。
- 默认拦截页运行时模板微调移动端标题排版：中文标题在窄预览卡片中不再被硬拆成“拦 / 截”式断行，同时保留用户端语言自适应脚本和事件 ID 展示能力。
- 本轮验证通过：`go test ./internal/blockpage`、`npm.cmd --prefix web run typecheck -- --pretty false`、`npm.cmd --prefix web run build`、`git diff --check`、`node tmp\verify-block-pages-css.cjs`。生产预览下确认首页未提前加载 `BlockPagesPage` CSS，进入拦截页后才加载；桌面浅色 / 黑金、移动浅色和新窗口预览均无横向溢出、无浏览器错误。
- 构建结果：拦截页样式输出为独立 `BlockPagesPage` CSS chunk 约 13.7KB，入口 CSS 约 229KB。Arco 官方 CSS 仍约 555KB，是当前最大样式资源，后续需作为单独回归批次处理。

### 2026-07-09 本地补充：AI 页旧样式迁出 global.css

- 继续按 `kimi_found.md` 点名的 P0 问题处理 AI 页样式所有权：`.ai-page`、`.ai-config-*`、`.ai-model-*`、`.ai-events-*`、`.ai-event-row-*`、`.ai-analysis-*`、`.ai-detail-*`、`.ai-knowledge-*`、`.ai-self-learning-*` 等 AI 页独有规则已从 `global.css` 迁入 `web/src/styles/ai-page.css`，并统一补 `.ai-page` 作用域。
- 共享样式没有误搬：日志详情页仍使用的 `.analysis-live-trace` / `.analysis-result` 保留在 `global.css`；右下角 AI 助手共享的 `.assistant-approval*` 主体仍保留在全局 / 助手样式体系，避免破坏助手审批卡片。
- 迁移后清理了两处历史半截注释导致的 CSS 语法错误，生产构建由 Lightning CSS minify 通过。
- 构建结果：入口 `index.css` 从约 229KB 降到约 177KB，AI 页样式输出为独立 `AIPage` CSS chunk 约 67KB。Arco 官方 CSS 仍约 555KB，不能写成已完成。
- 本轮验证通过：`npm.cmd --prefix web run typecheck -- --pretty false`、`npm.cmd --prefix web run build`、`git diff --check`、`node tmp\ai-page-regression.cjs`。生产 `dist` 静态服务下 AI 页桌面 / 1200px 回归无控制台错误、无横向溢出，事件分析 Markdown 表格可渲染，最终回答没有泄露内部工具过程词。
- 剩余风险：`ai-page.css` 内部仍有多轮历史覆盖和局部 `!important`，需要下一批做页内去重；现有截图脚本 fullPage 模式会重复固定顶栏，后续应补 viewport 截图；Arco CSS 大包与攻击地图内部重复覆盖仍按后续专项处理。

### 2026-07-09 本地补充：AI 助手审批样式按组件加载

- 继续收敛 `global.css` 的组件职责：`.assistant-approval*` 审批卡片、审批按钮、审批状态和移动端补丁已从 `global.css` / `ai-page.css` 迁入 `web/src/components/AIAssistant/AIAssistant.css`。
- 迁移后 `global.css` 与 `ai-page.css` 不再持有 `assistant-approval` 选择器；审批卡片样式随完整 AI 助手 chunk 加载，不污染首屏和 AI 分析页样式所有权。
- 构建结果：入口 `index.css` 从约 177KB 降到约 174KB；`AIAssistant` CSS chunk 增至约 6.1KB，符合组件按需加载预期。Arco 官方 CSS 仍约 555KB，仍需后续专项处理。
- 本轮验证通过：`npm.cmd --prefix web run typecheck -- --pretty false`、`npm.cmd --prefix web run build`、`git diff --check`、`node tmp\assistant-tool-ui-smoke.cjs`。验证脚本已修正为分别统计“执行前审批卡片”和“执行后结果状态”，确认执行前存在审批卡片，批准后转为工具执行结果，面板无横向溢出且可正常关闭。
- 剩余风险：`AIAssistant.css` 仍可继续整理顺序和减少重复，但当前样式边界已经从全局迁到组件；下一步建议处理攻击地图 `attack-map.css` 内部重复覆盖和 AI 页 `ai-page.css` 页内去重。

### 2026-07-09 本地补充：攻击地图颜色变量别名

- 按只读审计建议，先做无视觉变化的攻击地图颜色变量化，为后续主题和大屏收口打底；本轮没有改拖拽、缩放、边界层级或 Three.js 逻辑。
- `attack-map.css` 新增局部变量：`--attack-risk-high`、`--attack-on-risk`、`--attack-highlight-white`，并把高风险橙色、marker 前景色和白色高光改为同值变量引用。
- 攻击大屏新增局部变量：`--attack-screen-text`、`--attack-screen-cyan`、`--attack-screen-live`、`--attack-screen-blue`、`--attack-screen-warn`、`--attack-screen-track-*`、`--attack-screen-glow`，并替换现有同值霓虹色硬编码。变量值保持原字面量，避免改变当前视觉。
- 本轮验证通过：`npm.cmd --prefix web run typecheck -- --pretty false`、`npm.cmd --prefix web run build`、`git diff --check`、`node tmp\local-map-ai-block-check.cjs`。回归确认 3D 地图和攻击大屏 canvas 非空、自动旋转和拖拽仍可用，滚轮不带动页面，中国区域边界仍为 47 条 path，攻击大屏历史视图暂停 / 恢复轮询断言继续通过。
- 剩余风险：`attack-map.css` 内部 `.map-canvas`、`.map-workbench-header`、`.attack-screen-grid` 等重复覆盖仍未整理；2D / 中国拖拽边界、Three.js 主题色和区县边界层级仍需要代码层处理。

### 2026-07-09 本地补充：攻击地图拖拽边界与中国标签密度

- 继续按最新 `kimi_found.md` 和子代理只读审查推进攻击地图专项，本轮仍不提交、不推远端，减少每个小修触发 CI 的开销。
- 2D / 中国区域地图拖拽边界从固定 `420 / 260` 像素改为按 `map-canvas` 可视尺寸和 `flat-map-stage` 实际尺寸动态计算；缩放回默认、切换模式或窗口尺寸变化时会自动回收到合法视野内。
- 中国区域地图标签改为随缩放逐级展开：默认只显示命中区域和必要上级，放大后再逐步显示城市 / 区县标签，避免浙江等高密度区域在默认视图下重叠成团。
- 地图 marker、桌面表格行和移动卡片共用 `selectedRegionKey`：点击地图点后表格行会高亮，点击表格行 / 移动卡片也会更新选中态；选中样式使用主题变量，不写死突兀底色。
- 本轮验证通过：`npm.cmd --prefix web run typecheck -- --pretty false`、`npm.cmd --prefix web run build`、`git diff --check`、`node tmp\local-map-ai-block-check.cjs`。截图复核 `tmp/screenshots/local-map-ai-block-check/attack-map-china.png`：中国边界完整、页面无横向溢出，默认标签从 14 个降到 7 个，点击 marker 后 `selectedMarkers=1`、`selectedRows=1`，3D 地图和攻击大屏仍可自动旋转、拖拽，滚轮不带动页面滚动。
- 剩余风险：861-1180px 攻击大屏左右浮层仍需专项复核；3D 地图在轮询时仍可能重绘纹理和 marker / arc，后续需要性能录制和对象复用优化；移动卡片选中态已接入代码与样式，但还需要补到自动化截图断言。

### 2026-07-09 本地补充：攻击大屏中宽度布局

- 按子代理只读复核继续处理攻击大屏：861-1180px 不再使用左右绝对浮层压住地球，改为地球完整占上方一行，统计 / 来源 / 等级 / 时间轴面板在下方两列排列。
- 侧栏展开状态已提升到根节点 class：`.attack-screen-rail-expanded` 会同步调整根 grid 宽度，避免 rail 自身展开后覆盖 main、topbar、globe 或左侧信息面板。
- 本轮验证通过：`npm.cmd --prefix web run typecheck -- --pretty false`、`npm.cmd --prefix web run build`、`git diff --check`、`node tmp\local-map-ai-block-check.cjs`。中宽度截图复核：`tmp/screenshots/attack-screen-mid/screen-1180.png`、`screen-1024.png`、`screen-900.png`、`screen-861.png`，以及 rail 展开态 `screen-900-rail-open.png`；900px / 861px 下地球不再被面板遮挡，rail 展开态断言 `rail.right <= main.left + 1` 通过。
- 剩余风险：中宽度截图脚本当前仍是临时脚本，后续应整理成稳定回归脚本；3D 地图轮询时的纹理 / marker / arc 更新性能还需要继续采样；Arco CSS 与历史全局布局重复覆盖仍需单独治理。

### 2026-07-09 本地补充：Kimi UI 审计低风险收口

- 已重新读取最新 `kimi_found.md`，并通过子代理只读复核当前 CSS / 主题状态。确认未定义 CSS 变量、登录面板职责混杂、攻击地图样式拆分等旧项多数已修；本轮只处理低风险且可验证的主题 / 文案 / 指标项，不做 `.workspace` / `.page-header` 大范围重构。
- 中文界面继续清理用户可见术语：仪表盘 “95% 请求快于此值” 改为“大部分请求快于此值”；资源与监控页不再把 Go 协程直接展示给用户，监控页优先显示 `process_count` 作为“服务进程”，缺省时兜底为当前服务实例。
- AI / 助手文案继续去黑话和中英混杂：`AI provider` / “模型思考摘要” / “执行轨迹” / “仅试运行” 等用户侧文案统一为“AI 服务 / 推理摘要 / 执行记录 / 仅模拟运行”等更明确表达。
- 主题与按钮对比修复：Arco 主按钮、页面主按钮和 AI 页面事件按钮改用 `--accent-contrast`，黑金主题不再被白字覆盖；dark 主题 `--color-primary-6` 与 `--accent` 对齐；攻击地图高风险色改为 `--accent-warning`，局部高光 / 阴影和等宽字体继续改用主题变量。
- 验证通过：`npm.cmd --prefix web run typecheck -- --pretty false`、`npm.cmd --prefix web run build`、`git diff --check`、`node tmp\dashboard-ui-regression.cjs`、`node tmp\check-ai-page-ui.cjs`、`node tmp\local-map-ai-block-check.cjs`。截图复核：`tmp/screenshots/dashboard-refined-desktop.png`、`tmp/screenshots/dashboard-refined-mobile.png`、`output/playwright/ai-page-desktop.png`、`output/playwright/ai-page-mobile.png`、`tmp/screenshots/local-map-ai-block-check/attack-map-china.png`。
- 仍未完成：Arco 全量 CSS 仍约 555KB，需要单独评估按组件样式导入并做全页面截图回归；仪表盘移动端仍偏竖向密集，资源卡 “服务进程 / 服务内存” 可以进一步做横向视觉重排；攻击地图图例和 marker label 仍需专项打磨；`global.css` 的历史重复覆盖和验证码内部高光硬编码仍需分批治理。

### 2026-07-09 本地补充：Kimi 低风险交互与可访问性收口

- 继续按最新 `kimi_found.md` 和子代理只读审计推进，本轮保持本地开发，不提交、不推远端，避免小步提交触发重复 CI。
- 仪表盘图表 hover 次级文字不再写死白色透明，改为跟随主题的 75% 文本色；资源运行状态卡片改为更明确的轻强调胶囊，移动端资源行和统计工具条增加 620px 内兜底，避免控件挤压或文本误读。
- AI 分析事件行补齐键盘可选能力：事件卡片支持 `Enter` / `Space` 选中，并避免影响内部详情 / 分析按钮；减少动画模式下事件行不再瞬移上浮。
- 通知面板补齐 `dialog` / `tab` 语义，通知触发按钮关联面板；通知描述从单行省略改为最多两行，避免 380px 面板内关键信息被切掉。
- 右下角 AI 助手按钮补齐 `aria-expanded` / `aria-controls`，助手面板补 `dialog` 语义；攻击地图普通空状态补 `role=status`，3D 地球 tooltip 补 `aria-live` / `aria-atomic`。
- 中国区域地图 marker 标签禁止拆字，并提高标签底色遮罩，避免底图地名穿透到 marker 标签内。
- 本轮验证通过：`npm.cmd --prefix web run typecheck -- --pretty false`、`npm.cmd --prefix web run build`、`git diff --check`、`node tmp\dashboard-ui-regression.cjs`、`node tmp\check-ai-page-ui.cjs`、`node tmp\local-map-ai-block-check.cjs`。截图复核：`tmp/screenshots/dashboard-refined-desktop.png`、`tmp/screenshots/dashboard-refined-mobile.png`、`output/playwright/ai-page-desktop.png`、`output/playwright/ai-page-mobile.png`、`tmp/screenshots/local-map-ai-block-check/attack-map-china.png`。
- 仍未完成：Arco CSS 大 chunk 仍约 555KB；仪表盘移动端工具条仍偏高但不溢出；攻击地图标签避让、攻击大屏视觉、Three.js 对象复用和 `global.css` 历史重复覆盖仍需作为后续专项处理。

### 2026-07-09 本地补充：防护策略局部更新与站点热重载

- 按 `engine_upgrade.md` 与子代理审计继续推进 M4 语义引擎 / 策略联动：当前 Web 攻击防护等级已具备 0-4 级策略层级、严重级别 / 置信度阈值和跨检测器聚合风险分，后续重点转为可解释展示、真实误报基线和 CRS FTW 对标。
- 修复全局防护策略局部更新问题：`PUT /api/protection/policy` 现在以当前策略为默认值合并请求体，前端只切换一个方向时不会把其他三个方向重置为默认智能模式。
- 新增 `TestUpdateProtectionPolicyMergesPartialPayload`，覆盖单字段更新、响应体保留其他字段、运行时 reload 回调拿到合并后策略。
- 修复站点配置热生效链路：`OnSitesChanged` 回调改为返回错误，站点同步和系统设置更新会在保存后重建 WAF pipeline 并通过 `proxy.Server.UpdatePipeline` 热替换；如果自定义规则或检测器配置导致管线重建失败，API 会返回错误，不再静默显示成功。
- `proxy.Server` 增加 pipeline 读写锁和快照读取，避免并发请求与热替换之间产生数据竞争。
- 本轮验证通过：`go test ./internal/api/handler -count=1`、`go test ./internal/proxy -count=1`、`go test ./internal/cli -run "BuildPipeline|Service|Password|Username" -count=1`。
- 仍未完成：策略决策 metadata 仍需要在日志详情 / AI 分析中更清晰展示；前端 `SiteProtectionConfig` 里的 `bot/ratelimit/acl/apisec` 布尔项与后端存储结构仍不一致，需要后续清理或补后端字段。

## 2026-07-15 商业级运维语义与文档面收口

- 检测预算失败模式已与 Web 攻击等级联动（open / observe / closed），站点可配置路径与参数放行列表。
- 管理端站点详情可配置语义运维策略；事件详情展示预算耗尽、预算策略、语义跳过与异常分等运维信号。
- 仓库 Markdown 策略：仅保留根目录 README.md、README_CN.md、progress.md；其它 .md 不再入库，避免敏感规划与运维笔记外泄。
- 说明：历史提交中的 Markdown 仍可能存在于 git history，如需彻底清除应另做 history rewrite（本轮仅从当前树取消跟踪）。


## 2026-07-15 语义引擎：筛选外部语料打磨

- 参考本地 外部语料参考 做漏报补强，**未盲信**其 label：将读取 shadow/元数据/回环 health 等错误标记为 benign 的样本明确剔除，不反向削弱检测。
- 已补：multipart 文件名扫描、PowerShell WebClient/TCPClient、data:// 与 RFI include、docker.sock、Mongo $eval/mapReduce 字段、ObjectSpace/classLoader SSTI、guessCategories 对 RCE/LFI 开窗。
- 刻意不补：纯 DNS rebind 无内网地址 SSRF、损坏的 UTF-16 转义样本（语料非真实字节）。
- 回归：go test ./internal/engine/semantic；精选 筛选子集 attack 检出约 94/96。


## 2026-07-15 语义引擎：语料漏报补全 + RCE/SSTI/XXE 扩展 + IO 基准

- 原 94/96 攻击漏报：DNS rebind（已补 rebind 标签与 rbndr/localtest 等助手域，仅 fetch sink）；真 UTF-16 XXE（BOM + charset=utf-16 + \xNN 转义）已补。
- 剩余 损坏 UTF-16 样本 样本体为**损坏的混排转义**（非整洁 UTF-16），不是引擎能力缺口；自建真 UTF-16 回归已通过。
- 原 13 个 “benign 被拦”：shadow/元数据/路径穿越等为 **外部语料错误标签**，保持拦截并加回归，不当作误报去放宽。
- 扩展：node child_process、LD_PRELOAD、FreeMarker ObjectConstructor、XInclude、参数实体 OOB XXE；0day 向动态加载/反射原语（无 CVE 号）。
- IO 向基准（本机）：FullPipeline ~520µs/op；PipelineWithRules ~226µs；PipelineConcurrent ~143µs；Analyzer ~28µs；HealthProbe ~1.2µs。

