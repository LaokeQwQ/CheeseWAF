# CheeseWAF 项目阶段进度

更新时间：2026-07-08

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

### 2026-07-08 本地补充：M4-0 API 令牌与 AI 流式保活收口

- AI 助手内置知识库补齐 M4-0 关键主题：管理 API 令牌权限边界、语义置信度与防护等级联动、AI 流式推理、工具审批和安全默认值。知识库内容用于回答和引导操作，不把配置密钥、日志 payload 或系统提示词当可信上下文。
- AI provider 长推理首包慢时新增持续进度事件：在 provider 尚未返回首个 delta 前，后端会定期推送等待状态，前端和单事件分析页不再把 30 秒内没有最终回答误判为 network error；真正的 provider 错误仍会被明确标注。
- 管理 API 令牌能力已进入控制台与后端：默认关闭，启用后支持 `cwapi_` Bearer token、scope 复用 RBAC、创建 / 列表 / 撤销、TTL、备注、一次性明文展示和只保存 `sha256:` hash。禁用、过期、撤销、格式错误或全局关闭时均 fail-closed 返回 401。
- 管理 API token 不刷新浏览器会话，不绕过 AI 工具审批，也不绕过现有路由权限；自动化访问继续进入审计中间件，审计记录新增稳定 `subject=api-token:<id>`，排查时不依赖可改名的 token 显示名。
- 管理 API token 创建与控制台开关保持一致：功能关闭时后端拒绝创建新 token，避免出现“页面显示关闭但接口仍能生成凭据”的半启用状态。
- 运维文档新增 `docs/management-api.md`，`docs/phase4-operations.md` 已同步安全模型、RBAC / 审计边界和控制台使用流程。
- 当前仍不能宣称整个 M4-0 完成：语义语料筛选、误报 / 漏报基线、性能基线、AI 知识库订阅和审批策略可视化仍需继续推进。
