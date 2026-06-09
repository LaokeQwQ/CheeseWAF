# CheeseWAF

[English](README.md) | [简体中文](README_CN.md)

CheeseWAF 是一个基于 Go 的 Web 应用防火墙项目，目标是提供单二进制部署、统一管理 API，以及 Web 控制台、移动浏览器和 `waf-cli` TUI 共用的运维入口。

## 当前状态

当前仓库已经包含：

- 反向代理 WAF 主流程：分阶段语义分析（输入提取、深度解码、词法/语法/行为评分）、自定义规则、IP/ACL/限流/Bot 防护、威胁情报导入与订阅、签名 JS 工作量证明挑战、Altcha 风格 PoW CAPTCHA、排队室、边缘缓存/请求头/压缩策略，以及响应体检测。
- 语义回归覆盖：function-based 和 error-based SQLi、MySQL 可执行版本注释、PostgreSQL 延迟 payload、hex tautology、`ORDER BY`/`HAVING` 推断、regex 值探测、`PROCEDURE ANALYSE`、`xp_cmdshell` 与 `into outfile` SQLi 形态，control-character/HTML entity/data URI/srcdoc/meta-refresh/CSS-expression/formaction/srcset XSS 上下文，`${IFS}`/PowerShell/Pwsh/`cmd /c`/download-to-shell RCE 变体，LFI Kubernetes token、进程环境泄露和超长 traversal，SSRF IPv6/IPv4-mapped IPv6/dotted-hex/dotted-octal/单整数十六进制/dynamic-DNS/file-scheme 形式，登录/查询上下文中的 Mongo/NoSQL 操作符、`$expr`、`$function` 注入，SSTI 对象图/runtime/Twig/ERB 执行链、直接 detector 绕过样本，以及用于压低误报的成对 benign 样本。成熟度和基准细节见 `docs/semantic-readiness.md`，公开 corpus 来源策略见 `docs/semantic-corpus-sources.md`。
- 可重复语义验证已经有独立的 `cheesewaf-corpus` runner，可将精选 JSONL corpus 跑在进程内 analyzer 或已部署 WAF 数据面上，并输出包含检出率、误报率、逐 case 延迟和失败证据的 JSON 报告。早于新增语义引擎的旧站点 YAML 会把缺失的引擎开关补为安全默认值，除非运维显式写成 `false`。发行门禁流程见 `docs/security-validation.md`。
- 共享 Web/API/TUI 管理模型：RBAC、审计日志、监控、API 安全、生产部署文件，以及单二进制 admin listener，可同时提供 REST API 和已构建的 Web 控制台。站点工作台覆盖域名、上游、TLS 材料、源站调优、健康检查、包含 NoSQLi/SSTI 在内的站点级语义开关、响应检测、访问控制和重写规则。
- 管理 API 授权已经细化到路由级：所有非公开管理 API 都必须携带 Bearer token，实时流不再公开；读接口需要 `read:*` 类权限，所有写接口按 system、users、sites、rules、protection、threat intel、edge、AI、storage、ops 等方向使用明确的 `write:*` 权限保护。路由回归测试覆盖无 token、cookie-only 类 CSRF 请求和 readonly 角色写操作。
- 管理端 token 带唯一 token ID，并由服务端可撤销 session 支撑。登录会创建 session，`/api/auth/refresh` 会原子撤销旧 token ID 并签发新 token，`/api/auth/logout` 会在 Web 控制台清理本地状态前撤销当前 session。密码/角色和 2FA 变更会撤销受影响用户的既有会话，过期/已撤销 session 会在登录时清理。控制台会在请求前自动刷新仍有效但接近过期的 token；过期或无效 token 仍走正常 401 登出流程。
- 管理端登录使用可配置的控制台登录配置：`/api/auth/captcha` 默认下发服务端生成的图形滑块验证码；浏览器 PoW 保留为独立模式，也可作为滑块的可选增强开关。滑块目标保存在加密且绑定客户端的 token 中，登录提交必须先通过服务端滑块位置、过期时间和拖动耗时校验，才会进入密码/2FA 检查；启用辅助 PoW 时同一路径会追加校验。系统设置可开关验证码模式，调整滑块误差、最短拖动耗时、可选辅助 PoW 上限，并可配置安全入口路径；开启后直接访问管理端口或错误入口会返回 Nginx 风格 `418 I'm a teapot` 页面，正确入口会下发与登录会话同寿命的 HttpOnly cookie。登录页不再提示默认用户名/密码，登录卡片下方以弱提示显示加载耗时，并支持通过 `console.login.background` 配置图片或动态视频 URL 作为自定义背景。
- Web 控制台加固：安全/类别/严重级别本地化标签，仪表盘总计态势与实时态势分离，1/3/5/10 秒实时刷新控制，总计统计周期可选，图表坐标轴、图例、缩放按钮与滑动缩放尺，事件/资源卡片弹性布局，IP 管理页签支持 URL 定位，API 安全表格布局隔离，路由级懒加载，以及基于 Natural Earth/world-atlas 的 2D/中国大陆/交互式 Three.js 3D 攻击地图。地图支持缩放/拖拽、按攻击强度着色、国家级 GeoIP 兜底、精确位置 metadata、WebGL 兜底、响应式表格和真实日志数据；中国大陆模式已改为独立大陆投影、真实参考城市锚点、大陆范围过滤和悬停/放大详情标签，不再裁切世界地图凑视图。3D 地球渲染器已拆到按需 chunk，普通控制台页面和 2D 地图不会提前加载 Three.js。
- Dashboard 资源面板现在读取 monitor snapshot 的真实主机指标：CPU 占用、带 CPU 核数上下文的 1 分钟 system load、主机内存、Swap、磁盘占用，并把 goroutines/heap 移到单独的进程运行时信息行。实时态势和资源占用会按 1/3/5/10 秒自动刷新，支持手动刷新；无 Swap 设备时明确显示“未启用”，并通过受保护系统 API 提供真实内存/Swap 回收操作。
- 攻击/拦截事件现在有独立 `/logs/:traceId` 详情页，可从 Dashboard、攻击日志表和 AI 事件表进入；详情页展示请求证据、检测器 metadata、payload/User-Agent 上下文，并对真实日志执行单事件 AI 分析。
- 计划安全报告可以按日报或周报从真实 WAF 日志生成 Markdown/JSON，并投递到本地报告目录或 Webhook。报告包含时间窗口、总日志与安全事件数量、拦截/挑战/仅记录计数、唯一来源 IP、动作/严重级别/攻击类型/站点/国家分布、风险来源 IP、被攻击 URI、检测器排行和最近高风险事件；普通放行流量不会污染风险排行。
- 前端构建输出使用稳定的 Vite/Rolldown vendor chunks，将 React、Arco、Three.js、可视化、运行时和 UI 工具依赖分组。生产构建默认不输出 source map，只有显式设置 `VITE_SOURCEMAP=true` 才保留调试 map，从而减小发布版 Web 控制台体积；较大的 Three.js 依赖只在攻击地图路径按需加载。
- 最新管理后台 UI 品控已修复 Rules、IP Control、Protection Policy、Operations、Updates & Vulnerability Feeds、Block Pages、Dashboard、AI Operations 和 System Settings 在接口失败、搜索框挤压、标签溢出、受控选择器空值、操作按钮压缩、假在线状态、设置布局混杂时的问题。控制台现在优先使用明确的加载/错误/空态、局部 action footer、响应式 token/chip 组、分组设置区域、移动端 IP 画像卡片与真实加白/拉黑/信誉分操作、AI 助手安全避让、可点击健康重连状态、独立通知/账号菜单和浏览器验证过的布局，而不是占位或纯装饰 UI。
- GeoIP 防护支持用户自定义国家 CIDR 覆盖和 MaxMind 兼容 `.mmdb` 数据库；代理日志会写入 `metadata.geo` 的 country/city/region/lat/lon/accuracy/ASN 字段，让攻击地图和报告在配置有效 City 数据库或威胁情报位置源时可以使用真实位置。
- 威胁情报指标带有 action 和 confidence，并根据严重级别、置信度和来源数量评分，在代理热路径中按全局/站点 `threat_intel` 等级执行。控制台导入、provider sync、查询和防护设置更新都会刷新运行时策略，无需重启服务。
- IP 访问控制现在支持全局、站点级、目录/路径级 allow/block 规则，并兼容旧的全局白名单/黑名单。allow 规则沿用现有白名单对 IP 相关防护的旁路语义，block 规则会在转发到源站前拦截；IP 画像可手动覆盖 0-100 信誉分。站点访问控制可配置可信代理/CDN CIDR；只有可信来源代理才会采信 `CF-Connecting-IP`、`True-Client-IP`、`Fastly-Client-IP`、`Fly-Client-IP`、`DO-Connecting-IP`、`Ali-CDN-Real-IP`、`CDN-Src-IP`、`X-CDN-Src-IP`、`X-Azure-ClientIP`、`X-Vercel-Forwarded-For`、`X-Original-Forwarded-For`、`X-Real-IP`、`X-Forwarded-For` 和 RFC `Forwarded` 等真实客户端 IP 头。
- 安全的管理端默认值：CLI 会在 `./data` 下引导运行时配置，管理端默认监听 localhost；公开绑定管理端需要同时设置 `server.admin_public: true` 和 `server.admin_tls`；首次设置可选择本地/隧道/反向代理访问，或使用生成的本地 CA 签发管理证书公开 HTTPS。
- 单二进制 admin handler 会为 API、SPA fallback 和静态资源统一加基础浏览器安全头：强制 `Content-Security-Policy`、`Cross-Origin-Opener-Policy`、`Cross-Origin-Resource-Policy`、`X-Frame-Options: DENY`、`X-Content-Type-Options: nosniff`、`Referrer-Policy: no-referrer`、收紧的 `Permissions-Policy`，并在 HTTPS 管理端响应上发送 HSTS。管理端静态资源支持 immutable cache 和 gzip 压缩，SPA 入口保持 `no-cache`。
- 智能防护策略：全局与站点级 Web 攻击、API 安全、Bot/CC、威胁情报支持 `off`、`low`、`smart`、`high`、`strict` 等级，站点为空时继承全局默认。Web 攻击运行路径已接入严重级别/置信度阈值（`low`: critical/0.90，`smart`: high/0.85，`high`: medium/0.78，`strict`: low/0.65），同时尊重 `waf.mode=monitor` 和 detector log-only 模式，并保留 detector 要求的 JS challenge。API Schema 校验、端点限流 finding 和 JWT claims 画像异常也使用同一等级模型；低等级可记录并放行低置信 API finding，smart 模式默认阻断可验证的 Schema/限流/认证问题；系统 APISec 设置保存后会热重建代理 Validator、RateLimiter 和 AuthChecker。
- Bot/CC 防护等级同样已在运行时生效：可疑 Bot 检测和 CC/限流超限会按严重级别/置信度阈值裁决，低信号命中可记录不阻断，显式启用的排队室仍作为流量控制生效。
- API 认证可以执行 WAF 侧 Bearer JWT 签名校验，支持配置 HMAC secret、PEM 公钥/证书、本地 JWKS JSON/file，或带缓存文件与后台刷新的远端 JWKS 订阅，然后通过同一智能防护策略模型执行 issuer、audience、expiry 和 scope 检查。端点级认证策略可按 method 和 path regex 覆盖 issuer/audience/scope 要求。运行时 APISec 更新会重建 Schema 校验、端点限流和 JWT Auth，无需重启代理；API Auth 关闭时会跳过 JWT/JWKS 初始化，避免可选 cache 路径缺失阻塞服务启动；Web 控制台的系统设置提供 JWT 签名、远端 JWKS 和端点策略配置入口。
- AI 运维界面支持真实攻击/拦截/challenge 事件分析、可选时间窗口的批量分析、单事件建议，以及基于近期 WAF 事件和监控快照的聊天式控制台助手。单事件分析和助手回复都会展示 provider/model 元信息以及 provider 返回的 token usage；助手回复还会显示安全过程摘要、思考中实时计时、响应耗时、输出 token 速度和时间戳，但不会暴露隐藏思维链。AI provider 已改为 OpenAI 标准或 Anthropic 标准端点，认证头由 provider 固定采用对应官方格式，已保存的 API Key 不会回显给 Web 控制台。AI prompt 会把日志、payload、运行时上下文和运维问题都视为不可信数据，并显式约束提示词注入、密钥泄露、工具执行和未授权策略变更。
- 首次设置向导和 REST setup API 共用一个完成服务，负责校验、管理员创建、SQLite 迁移、默认配置/证书生成和 setup 完成锁。生成的管理端证书包使用 ECDSA P-256 本地 CA（`CN=CheeseWAF Sign SSL CA`，`O=CheeseCloud Technology Ltc.`）和 server-auth leaf chain。
- Prometheus 指标、告警评估、remote write，以及可查询的多 sink 日志：本地文件、ClickHouse、VictoriaLogs、PostgreSQL 和 Elasticsearch。指标默认通过带认证的 `/api/metrics` 访问；裸抓取路径（例如 `/metrics`）只有在显式设置 `monitor.prometheus.public: true` 后才会公开。
- Forgejo Actions CI 是主要构建目标，GitHub Actions 作为辅助镜像检查，覆盖 PR 流程校验、Go 测试、Web 构建、跨平台构建和分支渠道发行包。推送到 `dev`、`canary`、`master` 时，两个平台都会分别构建 `dev`、`canary`、`stable` 渠道包。Forgejo 使用 `scripts/ci/setup-go-mirror.sh` 与 `scripts/ci/setup-node-mirror.sh` 引导本地/镜像 Go 和 Node 工具链，避免自托管 runner 访问 GitHub tool-cache 超时。

运行时 Bot challenge secret 会按安装生成。如果旧配置仍包含空值或 `change-me-in-production`，CheeseWAF 会在启动时轮换并保存修复后的运行时配置。

## 开发

```bash
go test ./cmd/... ./internal/...
# 在受限 Windows shell 中，将 Go build cache 放在工作区内：
# PowerShell: $env:GOCACHE="$PWD\tmp\go-build-cache"; go test ./cmd/... ./internal/...
go test -race -count=1 ./cmd/... ./internal/...
go run ./cmd/cheesewaf-corpus --mode analyzer
# 对已部署的数据面监听执行回放：
# go run ./cmd/cheesewaf-corpus --mode http --base-url http://127.0.0.1:8080
go build -trimpath -o bin/cheesewaf ./cmd/cheesewaf/
cd web && npm ci && npm run build
```

`task.md` 和 `implementation_plan.md` 等本地私有计划文件会被 Git 故意忽略。

语义引擎成熟度记录在 `docs/semantic-readiness.md`；可重复 security corpus 门禁见 `docs/security-validation.md`。当前只能声明“可用且可解释”，不能声明已经达到 ModSecurity/OWASP CRS 等价。

## 分支发行产物

GitHub Actions 和 Forgejo Actions 会在受保护分支链推送成功后同步打包分支专属产物：

| 分支 | 渠道 | 版本格式 |
| --- | --- | --- |
| `dev` | `dev` | `0.1.0-dev.<run>+<commit>` |
| `canary` | `canary` | `0.1.0-canary.<run>+<commit>` |
| `master` | `stable` | `0.1.0-beta.<run>+<commit>` |

每个 artifact bundle 包含 `cheesewaf` 二进制、`waf-cli` alias/copy、已构建的 Web 控制台、README、`LICENSE`、`VERSION`、`release.json` 和顶层 `SHA256SUMS`。共享打包脚本位于 `scripts/ci/package-release.sh`，确保 GitHub 和 Forgejo 构建同一套 payload。

## 阶段快照

截至 2026-06-09，最新硬化发行链批次已在 GitHub 完成受保护的向上晋级：PR #49 合并 `fix/login-slider-performance -> dev`，PR #50 晋级 `dev -> canary`，PR #51 晋级 `canary -> master`。`git.laoker.cc/Laoke/CheeseWAF` 上的 Forgejo 是主要 forge/构建目标，GitHub 保持辅助镜像/检查角色；GitHub 合并完成后已触发 Forgejo mirror-sync，并在该快照上与 GitHub 对应分支 head 一致：`dev`（`9c1ba54`）、`canary`（`4eda681`）、`master`（`ebc62ae`）。这三个受保护分支当时的代码树内容一致，同时保留各自按规则向上 PR 产生的 merge commit。Forgejo workflow 位于 `.forgejo/workflows/ci.yml`，并使用 `scripts/ci/setup-go-mirror.sh` 和 `scripts/ci/setup-node-mirror.sh` 支持自托管 runner 友好的工具链设置。

当前硬化重点包括基于公开 corpus 思路精选的语义样本、真实仪表盘计数、实时/总计态势分离、Dashboard 图表 scoped 尺寸修复、真实主机 CPU/load/内存/Swap/磁盘资源指标、资源回收操作、单事件日志详情与 AI 分析、可通过 URL 定位的 IP 威胁情报/访问名单页签、全局/站点/目录级 IP allow/block 规则、可信代理/CDN 真实客户端 IP 解析、手动 IP 信誉分覆盖、真实健康重连状态、更清晰的 2D/中国大陆/3D 攻击地图模式、APISec JWT 签名/audience/远端 JWKS/端点策略控制、路由级管理 API RBAC、可投递的日报/周报安全报告，以及 GitHub/Forgejo 为 `dev`、`canary`、`stable` 三个渠道同步生成分支 artifact。已晋级的 `master` 快照 `ebc62ae` 已部署到远端验收主机并完成 smoke 测试：管理端 health/index 返回 200，代理首页返回 200，SQLi probe 返回 403，部署态 HTTP corpus 40/40 通过（30/30 攻击拦截、10/10 benign 未拦截），HTTPS 管理端响应包含 frame、nosniff、referrer、permissions 与 HSTS 安全头。下一步发行工作需要补齐外部动态扫描证据，再标记 V0.1 beta。

## 发布前缺口

- 管理平面必须被视为生产安全边界：应保持在 TLS 或可信反向代理之后，默认绑定 localhost/私有网络，避免通过明文 HTTP 暴露浏览器 token。
- 裸 Prometheus 抓取默认不公开。优先使用带认证的 `/api/metrics`，或仅在可信监听面上暴露 `monitor.prometheus.path`；需要外部 scraper 直接抓取时必须有意识地设置 `monitor.prometheus.public: true`。
- 公开发布前，需要跑可重复的 sqlmap、XSStrike、nuclei、OWASP ZAP、CRS/Coraza 或 ModSecurity 对比，以及 `cheesewaf-corpus` analyzer 与已部署 HTTP 回放。管理面路由级认证/RBAC 测试已自动化，但 V0.1 beta 打标前仍需对已部署管理端复跑动态扫描。
- Web 攻击、API 安全、Bot/CC 和威胁情报防护等级已接入运行时严重级别/置信度或评分阈值。默认 `smart` 模式偏向降低误报，但 GA 前仍需基于 corpus 继续迭代阈值。
- API auth 当前支持配置化 JWT 签名校验、audience 校验、端点级 issuer/audience/scope 策略，以及带 HTTPS-only/SSRF 防护和缓存兜底的远端 JWKS 刷新。它仍不能替代源站应用认证，并且 CheeseWAF 有意不在代理请求热路径中抓取远端 JWKS URL。
- 城市/区县级地图精度依赖有效的 GeoIP City `.mmdb` 或外部威胁情报位置源。缺少这些数据时，CheeseWAF 会有意降级到国家/CIDR 级归因，而不是伪造坐标；中国大陆视图只显示大陆范围内的真实位置或安全的 CN 国家级兜底点。
- Web 控制台已有路由级懒加载、地图数据瘦身和稳定 vendor chunk 分组。剩余的大 chunk 主要是按需 Three.js 3D 地图依赖；GA 前需在低端移动浏览器上测量冷启动。
- 浏览器级视觉回归已有本地 Chrome Canary headless smoke 路径，包含桌面/移动截图和 DOM overflow 断言。标记 V0.1 beta 前，需要在已部署的管理控制台上复跑，并补充 tablet viewport。
