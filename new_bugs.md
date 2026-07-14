# CheeseWAF 全仓审计与修复台账

> 建立时间：2026-07-11  
> 基线：`dev@7a89f49`  
> 原则：只记录有源码、测试或运行证据的问题；完成勾选必须有新鲜验证证据。长期规划不伪装成已交付功能。

## 状态定义

- `[ ]` 待修复
- `[~]` 修复中
- `[x]` 已修复并完成对应验收
- 严重度：`P0` 可直接破坏安全边界或数据完整性；`P1` 高风险生产缺陷；`P2` 功能、性能或运维缺陷；`P3` 质量与可维护性问题。

## 当前基线证据

- [x] `GOTELEMETRY=off` 且使用可写 `GOCACHE` 后，`go test ./...` 通过。
- [x] `web` 的 `npm.cmd run build` 通过，但项目目前没有前端测试脚本。
- [x] `git diff --check` 通过，建立台账前工作区干净。
- [ ] `go vet ./...`、竞态测试、前端测试、Docker/发布物/Ansible 冒烟、浏览器桌面与移动端验收尚未形成完整门禁。

## A. 安全与权限边界

### [x] BUG-001 P0 CI 分支名可注入 Shell

- 证据：`.github/workflows/ci.yml:28-30`、`.forgejo/workflows/ci.yml:26-28` 将 PR head/base ref 直接插入 Bash 源码。
- 影响：攻击者可构造恶意分支名，在受影响 runner 上执行命令。
- 修复：通过 workflow `env` 传值，并在脚本中对 `HEAD_REF`、`BASE_REF` 使用双引号；增加恶意分支名静态回归检查。
- 验收：workflow lint 通过；脚本对包含空格、分号、命令替换字符的 ref 只当普通数据处理。
- 所有权：CI/发布批次。

### [x] BUG-002 P1 CI 工具链来源未固定且校验可降级

- 证据：`scripts/ci/setup-node-mirror.sh:32` 使用可变 Node 下载地址；`scripts/ci/setup-go-mirror.sh:31,88` 接受镜像侧校验和，并可在没有权威校验时继续安装；workflow 使用 `govulncheck@latest`。
- 影响：镜像或上游漂移可改变构建输入，供应链遭污染时缺少 fail-closed 保证。
- 修复：固定工具版本和仓库内权威 SHA-256；无法校验立即失败；固定 `govulncheck` 版本。
- 验收：篡改归档或缺失 checksum 时安装脚本非零退出；CI 中不存在 `@latest`。
- 所有权：CI/发布批次。

### [x] BUG-003 P0 AI 审批未绑定请求用户与会话

- 证据：`internal/ai/approval.go:23-32,44-86,111-134` 的审批对象仅保存 tool/args，知道 ID 且有 `write:ai` 的主体可操作其他用户的审批；状态仅在内存中。
- 影响：跨用户批准/拒绝敏感工具调用；重启后审批丢失或执行状态无法审计。
- 修复：审批绑定 requester user/session/tenant、过期时间和参数摘要；审批者必须满足同用户或显式管理权限；使用持久化状态和单次消费。
- 验收：跨用户审批返回 403；过期、重复、参数变更审批失败；重启恢复待审批状态；完整审计记录。
- 所有权：AI/RBAC 批次。

### [x] BUG-004 P0 用户管理可越权授予管理员且可锁死最后管理员

- 证据：`internal/api/router.go:136-141` 与 `internal/api/handler/user.go:36-63,144-193` 只检查 `write:users`，没有角色授予边界；允许降级最后一个管理员。
- 影响：自定义角色/API token 可创建或提升管理员；系统可能失去任何可管理账号。
- 修复：增加 `manage:roles`/管理员边界；禁止授予超过调用者的权限；事务内保护最后一个有效管理员；拒绝自我锁死。
- 验收：低权限主体无法创建/提升 admin；并发降级/删除仍至少保留一个可登录管理员。
- 所有权：AI/RBAC 批次。

### [x] BUG-005 P1 2FA 启用/关闭缺少用户绑定与二次确认

- 证据：`internal/api/handler/user.go:65-125` 未保存服务端 pending challenge；启用接受任意有效 secret/code；关闭不要求当前密码或 TOTP。
- 影响：2FA 状态容易被错误绑定或被持有会话的攻击者关闭。
- 修复：服务端保存短期、一次性、用户绑定的 pending secret；启用消费 challenge；关闭要求当前密码和当前 TOTP/恢复码，并记录审计。
- 验收：他人/过期 secret 无法启用；无二次凭据无法关闭；成功后 challenge 不可重放。
- 所有权：AI/RBAC 批次。

### [x] BUG-006 P1 登录端点缺少独立限流

- 证据：公共登录路由位于 `internal/api/router.go:84-88`；关闭 CAPTCHA 后没有账号/IP 双维度暴力破解限制。
- 影响：配置允许关闭验证码时可高速撞库，验证码自身也不应是唯一防线。
- 修复：对 socket peer/可信真实 IP、用户名和全局并发分别限流，指数退避且不泄露账号存在性；成功登录后安全重置。
- 验收：达到阈值返回统一 429；不同伪造转发头不能绕过；合法用户在窗口后恢复。
- 所有权：AI/RBAC 批次。

### [x] BUG-007 P1 SSH 首次连接默认 TOFU 不适合无人值守部署

- 证据：`internal/cluster/deploy/ssh.go:519-555` 在未提供 fingerprint 时默认首次信任；UI 预检查结果未与 host/user/port/fingerprint 加密绑定。
- 影响：首次部署可遭中间人攻击，后续批量执行扩大影响。
- 修复：后端默认要求指纹确认；预检查签发短期、单次、绑定目标身份和指纹的部署授权；前端移除失效的 known_hosts 首次信任入口并强制填写 SHA256 指纹；目标变化必须重新确认。
- 验收：无确认令牌不能部署；变更任一目标字段令牌失效；主机密钥变化强制阻断。
- 所有权：集群/部署批次。

### [x] BUG-025 P0 API Token 可授予超过调用者的权限

- 证据：`internal/api/router.go:115-117`、`internal/api/handler/api_tokens.go:46-106,172-187` 创建令牌只要求 `write:system`；请求 scopes 未限制为调用者权限子集；`internal/config/validator.go:444-489` 接受 `*`，`internal/api/middleware/rbac.go:44-50` 将其视为任意权限。
- 影响：只有系统配置权限的主体可铸造管理员等效令牌，绕过原角色边界。
- 修复：拆分 `manage:api_tokens` 与 `grant:permissions`；scope 必须是调用者有效权限的子集；仅管理员可授予 `*`；认证/RBAC 配置不能归入宽泛 `write:system`。
- 验收：非管理员申请 `*` 或超出自身的 scope 返回 403；权限子集令牌可用；所有创建、撤销和拒绝均审计。
- 所有权：AI/RBAC 批次。

### [x] BUG-026 P0 登录 CAPTCHA 可被客户端降级、重放且管理登录不限流

- 证据：`internal/api/handler/handler.go:245-355,470-493` 允许客户端指定 `mode: pow`；`internal/captcha/altcha.go:71-87` 只校验签名/答案/有效期，不记录消费；管理 API 未接入代理侧 `login-api` 限流器。
- 影响：一次 PoW 可在有效期内反复尝试密码并反复触发 bcrypt，造成撞库和 CPU 消耗；默认 Slider 策略可被客户端降级。
- 修复：服务端决定允许的模式；所有证明换取一次性、用户/IP/会话绑定 receipt；管理登录增加 IP、用户名、全局并发三层限流与统一错误。
- 验收：同一证明第二次使用失败；默认 Slider 拒绝 PoW；阈值后返回 429，伪造转发头不能规避。
- 所有权：AI/RBAC 批次。

### [x] BUG-027 P1 可信代理配置可能接受客户端残留的任意单值 IP 头

- 证据：`internal/engine/context.go:73-99` 只要 socket peer 命中 `trusted_cidrs`，就按固定优先级接受 `CF-Connecting-IP`、`X-Real-IP`、`X-Client-IP` 等头，未按代理提供商限制来源头。
- 影响：若前置代理没有清洗所有候选头，客户端可注入高优先级头，绕过 ACL、限流和威胁情报。
- 修复：可信代理配置明确声明 provider/header；默认只接受一个已配置且由代理覆盖的头；对 XFF 从右向左剥离可信跳点；冲突头记录安全事件。
- 验收：CDN 未配置的头不会影响客户端 IP；多跳链只取第一个不可信地址；伪造高优先级头无法绕过策略。
- 所有权：引擎/代理批次。

### [x] BUG-031 P1 反向代理把源站 Host 错写进 `X-Forwarded-Host`

- 证据：修复前 `internal/proxy/reverse_proxy.go:25-30` 先把 `r.Host` 改成 target host，再将该值写入 `X-Forwarded-Host`。
- 影响：源站无法获知客户端访问域名，可能生成错误跳转/绝对链接，或做出错误的租户与安全决策。
- 修复：Director 改写前保存原始 Host，源站 Host 只用于上游路由，`X-Forwarded-Host` 传原始值。
- 验收：回归测试同时断言上游 `Host=origin`、`X-Forwarded-Host=client host`。
- 所有权：引擎/代理批次。

## B. 配置、数据与业务完整性

### [x] BUG-008 P0 配置并发写存在竞态、丢更新和运行态分叉

- 证据：`internal/api/handler/handler.go:48` 的锁通常只包裹保存；`site.go:176-198`、`ip.go:100,121,141,164,201`、`ai.go:167`、`system.go:147` 在锁外修改共享配置；运行时 callback 常在落盘后执行且失败不回滚。`internal/proxy/server.go:118-230` 多个运行字段缺少统一并发保护。
- 影响：并发 API 更新互相覆盖；磁盘、Handler 内存、代理运行态出现不同版本；竞态可引发崩溃。
- 修复：建立 clone-validate-persist-apply 的串行配置事务；失败回滚；运行时使用不可变快照/原子替换；统一版本号和冲突检测。
- 验收：相关包 `go test -race` 通过；并发更新不丢字段；callback 失败后磁盘与运行态保持旧版本。
- 结果：2026-07-12 已将站点、IP、AI、系统、Management API Token、调度任务、边缘策略、拦截页、CAPTCHA 资源和 AI 防护工具配置写入统一到同一事务锁与候选配置提交边界；CAPTCHA Store 在锁内基于最新配置构造并原子发布。handler 全包、定向 race、vet 与静态直接写扫描通过。跨节点一致性、多数确认和配置版本冲突协议继续归 M3 集群路线。
- 所有权：配置事务批次。

### [x] BUG-009 P0 备份导出/恢复 API 返回假成功

- 证据：`internal/api/handler/ops.go:494-503` 的导出只返回元数据，恢复丢弃请求体后直接返回 `restored: true`。
- 影响：用户误以为已有可恢复备份，灾难恢复时才发现数据不存在。
- 修复：实现版本化、校验和、加密敏感字段策略、原子导出/导入、预览 diff、兼容性校验和失败回滚；未实现前必须显式返回 501。
- 验收：真实 round-trip 后配置/用户可恢复；损坏、越权、版本不兼容备份拒绝且不改状态。
- 所有权：配置/运维批次。

### [x] BUG-010 P1 首次设置可能留下半完成状态

- 证据：`internal/setup/service.go:104-123` 依次保存配置、创建用户、写 setup lock，后续失败不回滚前序步骤。
- 影响：安装失败后既无法正常重试，也可能暴露部分配置或管理员状态。
- 修复：用暂存配置和数据库事务，最后原子写完成标记；启动时识别并恢复未完成安装。
- 验收：在每个步骤注入失败均可安全重试；完成标记仅在全部步骤成功后出现。
- 所有权：配置/运维批次。

### [~] BUG-011 P1 Ansible Region 可注入且生成剧本并未完成部署

- 证据：`internal/cluster/deploy/ansible.go:91,154-157` 将未验证 Region 插入 inventory；`:193-224` 的 playbook 未安装、启动并健康检查 WAF。
- 影响：恶意输入可破坏 inventory；UI 宣称部署成功但目标机没有可用服务。
- 修复：Region 使用严格枚举/字符集并通过结构化模板生成；剧本执行安装、配置、服务启动、就绪探测和补偿回滚。
- 验收：恶意 Region 被拒；干净 Ubuntu 节点执行后 `/health/ready` 成功；任一步失败返回真实失败并回滚。
- 所有权：集群/部署批次。

### [x] BUG-012 P1 同一节点可并发安装导致回滚互相破坏

- 证据：`internal/cluster/deploy/ssh.go:755+` 无 per-target lease，备份名只有秒级时间戳。
- 影响：同一节点的并发部署覆盖备份、错误回滚到另一次任务状态。
- 修复：按规范化目标身份加租约/互斥；备份使用任务 UUID；补偿操作校验所有权。
- 验收：同一节点第二个部署返回冲突；不同节点可并发；回滚只触碰自己的备份。
- 所有权：集群/部署批次。

### [x] BUG-013 P2 集群任务无限保留且完整输出被轮询返回

- 证据：`internal/cluster/deploy/tasks.go:80,133-136,295-303` 没有 TTL/容量清理；`internal/api/handler/cluster.go:182` 返回完整任务；Web 每 3 秒轮询。
- 影响：长期运行内存增长、敏感输出反复传输、控制面负载随任务数增加。
- 修复：任务容量/TTL、分页摘要、按需详情、输出脱敏、并发上限和结束任务清理。
- 验收：压力测试后内存有界；列表不返回完整日志；分页与 TTL 行为有测试。
- 所有权：集群/部署批次。

## C. WAF 数据平面与性能

### [x] BUG-014 P0 请求体只检查前缀但完整转发，可绕过检测

- 证据：`internal/engine/context.go:14,35-45,62-66` 只读前 8 MiB 后重放完整 body；`internal/engine/semantic/analyzer.go:22,266-272` 聚合分析仅看前 256 KiB；配置 `MaxBodyBytes` 未用于入站请求硬限制。
- 影响：攻击载荷放在检查窗口之后即可到达源站；超大 body 消耗带宽和资源。
- 修复：在 listener/代理入口强制站点配置的 body 上限；超限拒绝或按明确策略完整流式检测，绝不能“未检查但继续转发”。
- 验收：载荷位于 256 KiB 与 8 MiB 边界后仍被检测或请求被 413 拒绝；源站不收到未检查尾部。
- 所有权：引擎/代理批次。

### [x] BUG-015 P1 检测超时不取消工作并造成 goroutine 放大

- 证据：`internal/engine/pipeline.go:40-42,97-116`、`sandbox.go:149-182` 的 timeout 只让外层返回，detector 多数不观察 context，`wg.Wait` 与额外 goroutine 继续运行；`BoundedRegex` 也为 RE2 匹配创建超时 goroutine。
- 影响：构造慢请求可持续占用 CPU/goroutine，超时保护形同虚设。
- 修复：detector 接口原生接收 context/预算；移除无效包装 goroutine；对输入长度和总检测成本做同步界限。
- 验收：超时/取消后 goroutine 数恢复；压力与 race 测试通过；结果不在取消后写共享状态。
- 所有权：引擎/代理批次。

### [x] BUG-016 P1 大响应 fallback 会重复请求源站

- 证据：`internal/proxy/server.go:465-492` 与 `internal/edge/capture.go:43-54` 在捕获过大时重新请求；`internal/proxy/server_test.go:85-126` 甚至断言源站命中两次。
- 影响：双倍延迟/带宽，并可能重复触发有副作用的错误 GET 实现。
- 修复：单次流式 tee，捕获前 N 字节用于检查并将同一响应继续转发；超限时按策略跳过缓存而非重放请求。
- 验收：任意响应大小源站只命中一次；首字节延迟和内存受控；缓存/响应检测语义保持。
- 所有权：引擎/代理批次。

### [x] BUG-017 P1 每个代理请求创建新 Transport

- 证据：`internal/proxy/reverse_proxy.go:13-24` 每次构造 Transport，调用点在 `server.go:416,433,466,533`。
- 影响：连接池无法复用、TLS/连接开销上升、idle connection 泄漏并降低吞吐。
- 修复：按上游/TLS 策略维护可复用 transport 池，配置变更时有界回收旧 transport。
- 验收：连续请求复用连接；配置刷新不泄漏；基准吞吐与分配量有回归阈值。
- 所有权：引擎/代理批次。

## D. 发布、容器与测试门禁

### [x] BUG-018 P1 Docker 构建上下文污染且基础镜像可漂移

- 证据：仓库无 `.dockerignore`；`deploy/docker/Dockerfile:5` 使用 `COPY . .`，`:11-12` 可让本机 `web/node_modules` 覆盖 `npm ci`；基础镜像未固定 digest。
- 影响：密钥/缓存/本地构建物进入上下文，依赖不可复现，镜像输入可被本地目录污染。
- 修复：严格 `.dockerignore`；分阶段只复制 manifest/lock/source；固定基础镜像 digest；使用非 root runtime 和只读文件系统兼容布局。
- 验收：包含诱饵 secret/node_modules 的上下文不会进入镜像；两次构建依赖一致；容器健康检查通过。
- 所有权：CI/发布批次。

### [x] BUG-019 P1 GoReleaser 注入变量错误且发布包缺前端

- 证据：`.goreleaser.yaml:27` 注入不存在的 CLI 变量，实际版本变量在 `internal/version/version.go:5`；archives 未包含 `web/dist`，运行时依赖外部 UI。
- 影响：发布版本信息错误，解压后的二进制无法独立提供管理界面。
- 修复：修正 ldflags 路径；明确 embed UI 或将版本匹配的 dist 纳入包；增加解包启动 smoke。
- 验收：构建物报告正确版本；空目录解包即可启动并返回真实 JS/CSS MIME。
- 所有权：CI/发布批次。

### [x] BUG-020 P2 发布门禁覆盖不足

- 证据：CI 未验证 Docker build、GoReleaser snapshot、Ansible syntax、解包运行、管理入口与静态资源 MIME；前端 `package.json` 无 test script。
- 影响：构建通过仍可发布白屏、坏镜像、假部署或 UI 状态回归。
- 修复：增加前端测试框架与关键路由/表单/SSE 测试；CI 增加发布物和部署 smoke。
- 验收：上述门禁均在 GitHub/Forgejo 执行；人为破坏静态资源路径会使 CI 失败。
- 所有权：CI/前端测试批次。

### [x] BUG-021 P2 地图数据重复打包且缺总发布物预算

- 证据：`web/vite.config.ts:172` 与 `scripts/ci/package-release.sh:68` 均处理地图数据，当前无总 artifact size budget。
- 影响：发布物持续膨胀，首次加载和升级带宽不可控。
- 修复：地图数据建立单一来源与按需加载；CI 检查关键 chunk 和总压缩包预算。
- 验收：地图资源不重复；超预算时 CI 明确失败并列出最大文件。
- 所有权：CI/前端性能批次。

## E. 前端产品逻辑

### [x] BUG-022 P1 通知并非服务端通知系统

- 证据：`web/src/layouts/MainLayout.tsx:86,209-240,792-814` 从日志/审计/告警临时拼通知；已读、清空、置顶只存在全局 localStorage，未按用户隔离或服务端持久化。
- 影响：换浏览器/设备后状态丢失，多用户互相污染，本地清空并未清除真实通知。
- 修复：服务端通知实体、用户级已读/置顶/清空状态、分页与实时推送；前端只渲染 API 数据。
- 验收：同用户跨设备同步；用户间隔离；实时通知、批量已读/清空/置顶均有 API 与测试。
- 所有权：通知/前端批次。

### [x] BUG-023 P2 前端没有自动化交互回归测试

- 证据：`web/package.json` 只有 dev/build/preview/typecheck；仓库没有 `.test.ts(x)`/`.spec.ts(x)` 前端测试。
- 影响：站点页 hooks 崩溃、popover 重叠、AI 审批按钮失效、响应式溢出等只能靠人工发现。
- 修复：引入轻量单元/组件测试与 Playwright 关键旅程；覆盖登录/CAPTCHA、导航、站点、日志详情、AI SSE/审批、通知和核心表单。
- 验收：测试脚本本地与两平台 CI 通过；关键缺陷有先失败后通过的回归用例。
- 所有权：前端测试批次。

### [ ] BUG-024 P2 现有待验收页面仍缺真实端到端证明

- 证据：`fix_task.md:1471-1502` 明确保留 #7-#25 多项未完成/待复验，包括规则生成器、IP 情报/访问名单、保护策略、Bot CAPTCHA、GeoIP/CC、ACL、边缘策略、监控、API 安全、用户、运维、更新、AI 与拦截页。
- 影响：仅有可编译 UI 不能证明功能可用，部分路径可能仍是不可操作或前后端未闭环。
- 修复：逐项核对真实 API、权限、错误态、空态、加载态、响应式和持久化；发现的独立缺陷追加为新 BUG，不以本项笼统关闭。
- 验收：桌面/移动、浅色/深色截图；关键操作刷新后仍保存；后端失败不显示成功；无 console error。
- 2026-07-13 进展：通知面板已覆盖读/未读、置顶、全部已读、清空确认、筛选分页和移动安全区；新增通知 Handler 集成测试验证用户隔离、过滤分页、PATCH、批量已读、清空、未认证、无效筛选与跨用户 404，存储层刷新查询证明变更持久化。用户管理移动端增加用户/审计分页、加载/空态和 2FA 陈旧响应隔离，截图位于 `output/playwriter/bug024-*`。本项仍不关闭，其他高风险页面写操作尚待逐项证明。
- 2026-07-14 第二批进展：站点列表/向导、站点详情、保护策略、运维任务和拦截页已补加载/失败/空态、写入锁定、失败保留草稿和移动布局；ACL 开关、Bot 时长换算、站点 inline PEM、任务时间校验等关键提交均有交互断言。5 页面桌面浅色与移动深色矩阵无横向溢出、console/page error，34 个前端测试文件 179 项、类型检查、构建预算均通过，截图位于 `output/playwright/bug024-batch2/`。本项继续保留，用于后续页面批次。
- 所有权：前端产品批次。

### [x] BUG-028 P1 AI 流式请求遇到 401 不会清理失效会话

- 证据：`web/src/api/client.ts:29,49` 的 Axios 拦截器会处理 401，但 `:927` 等 AI SSE 使用原生 `fetch`，非成功响应只抛异常；过期 token 仍留在 localStorage，路由守卫继续判断为已登录。
- 影响：会话过期后用户停留在失效界面，所有流式操作持续失败，普通 API 与 SSE 行为不一致。
- 修复：所有 authenticated fetch/SSE 共用 401 处理；原子清除 token 并跳登录；避免多个并发流重复导航。
- 验收：mock 任一 AI SSE 返回 401 后 token 被清除并只跳转一次登录页；其他 HTTP 错误保留原错误信息。
- 所有权：前端逻辑批次。

### [x] BUG-029 P2 AI 自学习 `max_events` 是不可编辑的隐藏配置

- 证据：`web/src/pages/AI/AIPage.tsx:141,347` 读取并提交 `selfLearningMaxEvents`，但 `:404` 附近表单没有对应控件；类型 `web/src/types/api.ts:384` 明确定义该字段。
- 影响：用户无法查看或修正真实生效值，保存时仍携带隐藏状态。
- 修复：增加带后端一致范围与说明的 `InputNumber`，加载、验证、保存闭环一致。
- 验收：后端返回值正确回显；修改后 payload 正确；越界值不能提交。
- 所有权：前端逻辑批次。

### [x] BUG-030 P1 OTA 自定义服务器把 UI 哨兵值写入配置

- 证据：`web/src/pages/Updates/UpdatesPage.tsx:112-119` 选择自定义项时把 `__custom__` 写进 `system.update.ota.server`，随后保存或同步公钥会把它当 URL。
- 影响：持久化非法更新源并向错误地址发起请求，更新功能失效。
- 修复：预设/自定义模式使用独立 UI 状态；配置中只能出现真实、验证过的 HTTPS URL；空值禁用保存和公钥同步。
- 验收：请求体永不出现 `__custom__`；合法 URL 可保存；空值、HTTP、非法 URL 明确拒绝。
- 所有权：前端逻辑批次。

### [x] BUG-032 P0 配置查询失败时前端仍允许保存 fallback

- 证据：`web/src/pages/AI/AIPage.tsx:88-95`、`UpdatesPage.tsx:21`、`SystemPage.tsx:39` 在查询失败时保留默认配置，保存控件仍可操作。
- 影响：一次 403/500 或短暂断网可把真实服务端配置覆盖成默认值，更新页还会覆盖整段 update/vulnerability。
- 修复：区分 loading/error/loaded；仅成功加载后允许编辑与保存；更新使用窄 DTO/PATCH。
- 验收：初次查询 500 时 mutation 不可触发；重试成功后才开放。
- 所有权：前端逻辑批次。

### [x] BUG-033 P1 AI 工具审批前端没有真实 pending -> approve -> continue 闭环

- 证据：`web/src/components/AIAssistant/AIAssistant.tsx:369` 对 pending 直接调用 continue；后端 `ai_tools.go:147` 会拒绝 pending；前端已有 approve API 却未调用，后端也缺审批列表/详情入口。
- 影响：用户收到审批卡后无法完成工具执行，长流程停在 pending。
- 修复：增加审批 list/get；审批卡显式调用 approve/reject；批准成功后仅原 requester/session 可 continue；删除后端不可达分支。
- 验收：组件与双会话集成测试覆盖完整状态机。
- 所有权：AI 审批产品批次。

### [x] BUG-034 P1 AI 审批 `failed` 状态与前端契约漂移

- 证据：后端 `internal/ai/approval.go` 定义 `failed`，前端 `types/api.ts:486` 和 `AIAssistant.tsx:205,551` 未将其视为终态，错误时还可能强制回退 approved。
- 影响：失败/过期/已消费审批反复显示可执行并产生 400。
- 修复：同步状态联合类型、标签与按钮；只在服务端仍为 approved 的网络断流场景允许重试。
- 验收：工具失败、过期、已消费、断流四类测试。
- 所有权：AI 审批产品批次。

### [x] BUG-035 P2 单事件 AI 分析存在 AbortController 竞态

- 证据：`AIPage.tsx:200,233` 的旧请求 onSettled 无条件清空共享 ref，可清掉新请求 controller。
- 影响：快速切换事件后多个 SSE 并发，状态互相覆盖且无法取消。
- 修复：按 request ID/controller 身份条件清理，或按事件 key 管理 controller。
- 验收：A abort 后 settle 不得清除 B；启动 C 必须取消 B。
- 所有权：前端逻辑批次。

### [x] BUG-036 P2 批量 SSE 断流后半成品被当成完整结果

- 证据：`AIPage.tsx:242` 与 `client.ts:888` 在 item 到达时立即提交，error/断流只 toast。
- 影响：用户无法区分完成和不完整分析。
- 修复：按 batch ID 暂存，done 后提交；或显式标记 incomplete 并支持重试。
- 验收：两个 item 后断流不污染正式缓存。
- 所有权：前端逻辑批次。

### [x] BUG-037 P2 401 跳转丢失登录前路由

- 证据：`client.ts:42` 直接跳 `/login`，`LoginPage.tsx:50` 无法恢复来源。
- 影响：深层页面会话过期后登录只能回首页。
- 修复：带经严格同源路径校验的 `from` 参数并恢复 path/search/hash。
- 验收：站点 TLS Tab 登录后原路返回，外部 URL 被拒绝。
- 所有权：前端逻辑批次。

### [x] BUG-038 P1 通知状态跨用户共享且请求失败伪装为空

- 证据：`MainLayout.tsx:86,98,792` 使用固定 localStorage key，聚合 query 忽略 error。
- 影响：用户间已读/清空/置顶状态串号；后端失败显示“无通知/健康”。
- 修复：用户 subject 命名空间；显示降级与重试；长期迁移到服务端通知实体。
- 验收：两个用户状态隔离，任一通知源失败不显示健康空态。
- 所有权：通知/前端批次。

### [x] BUG-039 P2 首屏 CSS 和公共 preload 体积过大

- 证据：生产构建首屏静态载入约 555KB Arco CSS、177KB 全局 CSS；宽泛 manualChunks 使多个公共 JS 被 modulepreload。
- 影响：登录/控制台首屏下载、解析和样式计算偏重。
- 修复：组件级样式、主题按需加载、根据 Vite manifest 拆分只属于懒页面的依赖；建立 gzip 与 preload 预算。
- 验收：登录首屏 CSS gzip < 50KB，preload 总量受 CI 门禁。
- 所有权：前端性能批次。

### [x] BUG-040 P1 调度配置保存后运行中调度器不热更新

- 证据：`ops.go:66` 只改配置；`scheduler/engine.go:19` 仅 Start 时复制任务，没有 replace/reload。
- 影响：UI 显示保存成功但任务仍按旧计划运行，重启后才变化。
- 修复：注入版本化 scheduler manager，原子替换并取消旧 context。
- 验收：新增/禁用/改时间/删除无需重启且不重复执行。
- 所有权：调度/运维批次。

### [x] BUG-041 P1 未知调度任务被 Noop 当成成功

- 证据：`scheduler/task.go:91,108` 未知 type 返回 Noop nil，历史记录 Success=true。
- 影响：无效任务显示成功，掩盖配置错误。
- 修复：配置与运行时都拒绝未知类型。
- 验收：PUT 返回 400，历史不出现未知类型成功。
- 所有权：调度/运维批次。

### [x] BUG-042 P1 计划备份/清理缺少互斥、原子成品和目标边界

- 证据：`scheduler/engine.go:32`、`backup.go:12`、`cleanup.go:23` 无 per-task lease；直接写最终文件；清理按目录全部普通文件 mtime 删除。
- 影响：并发冲突、截断备份被当成有效、无关文件被删除。
- 修复：任务租约；临时文件 sync+校验+rename；只清理 manifest 标识的受管文件且限制 canonical root。
- 验收：并发只执行一次；崩溃无正式残片；无关文件不删除。
- 所有权：调度/运维批次。

### [x] BUG-043 P2 调度历史 API 永远返回空数组

- 证据：`ops.go:192` 固定返回 `[]`，未连接 `scheduler.Engine.History()`。
- 影响：用户无法查看成功、失败、运行中记录。
- 修复：注入调度管理器并分页返回真实持久历史。
- 验收：手动/定时成功失败均可查询，保留策略生效。
- 所有权：调度/运维批次。

### [x] BUG-044 P1 ACME 签发与站点提交不是事务

- 证据：`handler/acme.go:81,120` 先写正式证书/可能 reload，再更新站点与同步；后续失败不恢复。
- 影响：孤儿证书、旧配置与新文件分裂。
- 修复：run-ID staging，验证匹配后提交站点，再原子切换并可回滚 reload。
- 验收：UpdateSite/sync/reload 注入失败时旧证书继续生效。
- 所有权：ACME/运维批次。

### [x] BUG-045 P2 通知扇出首个失败会阻止后续目标

- 证据：`internal/monitor/notifier/notifier.go:35` 遇首错立即返回，无重试、幂等或投递状态。
- 影响：一个坏 webhook 阻断其他渠道和后续告警。
- 修复：独立投递并聚合错误；持久重试队列、event ID、dead-letter。
- 验收：首目标 500 时第二目标仍收到；恢复后补投且不重复。
- 所有权：通知后端批次。

### [x] BUG-046 P1 大响应超过检查上限时连已读前缀也不检查

- 证据：`engine/response/inspector.go:77-81` 超限立即返回 nil。
- 影响：敏感信息置于开头并填充响应即可绕过泄漏检测。
- 修复：始终检查有界前缀并标记 truncated；流式匹配保留跨块 overlap。
- 验收：敏感值在开头和跨边界均命中；不可检尾部有明确降级事件。
- 所有权：引擎/代理批次。

### [x] BUG-047 P2 响应已直通后下游写错未记录

- 证据：`edge/capture.go:63` committed 分支直接返回 destination.Write，未保存 writeErr；代理可能记录 pass。
- 影响：客户端断连与部分响应被误报为成功。
- 修复：保存首次下游写错，日志区分 upstream/downstream/partial。
- 验收：第二次 Write 失败后 Err 非空，且不尝试二次 502。
- 所有权：引擎/代理批次。

### [x] BUG-048 P2 Transport 活动连接没有上限

- 证据：`reverse_proxy.go` 只设置 idle 上限，`MaxConnsPerHost=0`。
- 影响：慢上游并发可耗尽 FD、端口和源站连接。
- 修复：配置 MaxConnsPerHost、dial/TLS/expect-continue timeout，并管理池生命周期。
- 验收：慢上游压力下活动连接有界，驱逐池最终释放。
- 所有权：引擎/代理批次。

### [x] BUG-049 P1 公网 Bot/等待室页面没有语言自适应

- 证据：`protection/bot/policy.go:1123-1241` 固定 `lang=en` 和英文文案。
- 影响：中文等用户和屏幕阅读器语言错误，与拦截页不一致。
- 修复：服务端解析 Accept-Language，结构化本地化所有可见/ARIA/运行时文案。
- 验收：至少 zh-CN/en，DOM lang 和文案一致。
- 所有权：Bot/CAPTCHA 批次。

### [x] BUG-050 P1 公网滑块验证码无法键盘操作

- 证据：`policy.go:1242,1336` 有 slider role 但无 tabindex/键盘事件，只监听 pointer。
- 影响：键盘与辅助技术用户被完全阻断。
- 修复：焦点、方向键/Home/End/Enter/Space、aria-valuenow，并保留替代验证。
- 验收：仅键盘可完成，NVDA 正确播报。
- 所有权：Bot/CAPTCHA 批次。

### [x] BUG-051 P2 公网验证码页忽略 reduced-motion

- 证据：`policy.go:1176-1211` 无限动画/transition 无 reduced-motion 媒体查询。
- 影响：违反用户系统辅助偏好。
- 修复：reduce 下停无限动画并缩短过渡。
- 验收：Playwright reducedMotion=reduce 仍可完成挑战。
- 所有权：Bot/CAPTCHA 批次。

### [x] BUG-052 P2 防护页重复表单 ID 与无名称删除按钮

- 证据：`ProtectionPage.tsx:265,732` 多 Form 重用 field=enabled；图标删除按钮无 aria-label/tooltip。
- 影响：label/自动化/辅助技术关联错误。
- 修复：唯一字段前缀；上下文化 aria-label 与 Tooltip。
- 验收：页面非空 ID 唯一，axe button-name 通过。
- 所有权：前端可访问性批次。

### [x] BUG-053 P2 中文 locale 缺少验证码相关键

- 证据：zh-CN 缺 `protection.sliderCaptchaPreview*`、宽高提示与 `login.sliderReloading`，中文界面回退英文。
- 修复：补键并加入 locale 叶子键集合一致性测试。
- 验收：zh/en 键集合一致，中文不出现上述英文 fallback。
- 所有权：前端 i18n 批次。

### [x] BUG-054 P2 CI 未执行前端测试、Go 格式和 vet 门禁

- 证据：workflow 仅 build 前端；仓库已有 Vitest；5 个 Go 文件 gofmt -l 非空；无 go vet job。
- 影响：测试和静态回归可进入发布。
- 修复：两平台执行 npm test/typecheck/build、gofmt check、go vet；固定工具版本。
- 验收：故意破坏测试/格式/vet 均阻断 CI。
- 所有权：CI/发布批次。

### [x] BUG-055 P2 前端 coverage 配置缺 provider

- 证据：`npm test -- --coverage` 报缺 `@vitest/coverage-v8`。
- 修复：固定匹配版本并设置渐进阈值。
- 验收：本地/CI 生成 coverage 且阈值生效。
- 所有权：前端测试批次。

### [x] BUG-056 P2 GoReleaser 与分支发布包格式分裂

- 证据：文件名、checksum、VERSION/release.json/waf-cli 内容不同。
- 影响：用户、自动升级与校验脚本不能统一消费。
- 修复：确定唯一发行规范并让两条流水线复用同一打包器。
- 验收：两类产物均通过同一 verify-release。
- 所有权：CI/发布批次。

### [~] BUG-057 P3 README 与根目录历史报告混入易过期运行状态

- 证据：README 含特定旧 commit/build/running 状态；kimi/progress 为历史快照但位于根目录。
- 影响：用户把历史证据误认为当前状态，事实来源不唯一。
- 修复：README 只保留稳定流程；历史材料迁移 `docs/audits/<date>` 或归档。
- 验收：README 不再包含一次性 waiting/latest 快照。
- 进展：2026-07-14 已移除 README 中特定 commit、远端部署版本和下一步快照，并将三份 Kimi 审计/交接材料归档到 `docs/audits/2026-07/`。`progress.md` 仍需从按轮次追加的运行日志收敛为对外阶段进度后再关闭本项。
- 所有权：文档整理批次。

### [x] BUG-058 P1 登录限流允许匿名者定向锁死任意用户名

- 证据：`internal/api/handler/handler.go` 的登录限流同时使用 IP 与纯用户名键，现有测试允许多个来源累计锁定同一账户。
- 影响：攻击者无需凭据即可持续令管理员账户返回 429，形成低成本拒绝服务。
- 修复：取消匿名纯用户名硬锁，使用 IP 与 IP+用户名维度、渐进退避；正确凭据从新来源不得被他人失败记录阻断。
- 验收：同 IP 撞库仍限流；多个不同 IP 的错误尝试不会锁死合法用户从新 IP 登录。
- 所有权：认证状态批次。

### [x] BUG-059 P1 CAPTCHA 与登录限流状态仅存在单进程

- 证据：`internal/api/handler/login_captcha_state.go` 将 proof、receipt 与失败计数保存在每个 Handler 的内存 map。
- 影响：多节点可重复消费同一 proof、轮询绕过限流；节点 A 签发的 receipt 落到节点 B 又会被错误拒绝。
- 修复：抽象可共享且原子的一次性状态后端，单机默认内存实现，多 Handler/集群可共享实例；保留后续外部一致性存储扩展点。
- 验收：两个 Handler 共享状态时 proof/receipt 全局只消费一次，失败计数跨 Handler 累计且无竞态。
- 结果：`AuthState` 统一承载登录 CAPTCHA 与 2FA 临时状态，多个 Handler 可注入同一生命周期；2026-07-12 新增定向测试证明 proof/receipt 跨 Handler 只能消费一次、失败锁跨 Handler 生效，普通与 race 测试均通过。跨进程/多节点外部原子状态后端继续归 M3 集群一致性路线。
- 所有权：认证状态/集群批次。

### [x] BUG-060 P1 2FA enrollment 输错一次即销毁且无法跨节点完成

- 证据：`internal/api/handler/user.go` 在校验 TOTP 前消费 pending secret，pending 状态仅保存在单 Handler。
- 影响：一次误输便必须重新扫码；多节点 setup/enable 会随机失败。
- 修复：先校验后原子消费，增加 TTL 与失败次数上限，并允许注入共享 enrollment 状态。
- 验收：限额内错误后可用正确 TOTP 完成；成功后不可重放；两个 Handler 共享状态可完成 enrollment。
- 结果：2026-07-12 定向复核 `internal/api/handler/user_test.go` 覆盖错误后成功、失败次数耗尽与两个 Handler 共享 `AuthState`，`go test ./internal/api/handler` 通过。
- 所有权：认证状态批次。

### [x] BUG-061 P1 AI 审批参数以明文持久化

- 证据：`internal/ai/approval.go` 将 `ApprovalRequest.Args` 原样写入 `ai_approvals.json`，展示层脱敏不影响落盘内容。
- 影响：未来包含 token、密码或 API key 的工具参数会泄露到运行目录；Windows `chmod` 不等价于服务账户 ACL。
- 修复：禁止敏感参数进入持久审批或使用服务密钥认证加密封装；递归识别嵌套敏感键；Windows 显式保护文件 ACL。
- 验收：持久化文件不含敏感明文，重启后非敏感审批仍可继续，Windows 权限测试通过。
- 结果：嵌套敏感参数和 diff 在持久化前递归脱敏，salt/digest 保持原参数绑定；Windows DACL 仅允许当前服务用户、SYSTEM 与 Administrators，并在后续原子替换后保持受保护状态。2026-07-12 Windows 定向测试通过。
- 所有权：AI 审批安全批次。

### [x] BUG-062 P2 2FA 路由权限不支持本人自助且可由宽权限角色操作他人

- 证据：`internal/api/router.go` 的 2FA 路由统一要求 `write:users`，handler 未形成“本人/管理员恢复”两套明确契约。
- 影响：普通用户不能保护自己的账户，拥有用户写权限的角色又可能替他人建立自己控制的 TOTP。
- 修复：本人会话可管理本人 2FA；他人操作仅限管理员恢复流程；API token 禁止获取个人 enrollment secret。
- 验收：本人成功、他人 403、管理员恢复有独立确认和审计、API token 无法发起 enrollment。
- 所有权：认证/RBAC 批次。

### [x] BUG-063 P2 shell-health 查询偶发返回 undefined

- 浏览器证据：防护页真实验收时 React Query 报 Query data cannot be undefined，query key 为 shell-health。
- 影响：控制台健康状态可能误判离线并产生无意义重试。
- 修复：查询函数必须始终返回结构化健康状态或显式抛错，禁止正常路径返回 undefined；补断连/恢复测试。
- 完成：fetchHealth 明确返回 Promise<HealthStatus>，有效响应返回结构化状态，断连沿请求错误显式拒绝，空或非法成功响应抛出 HEALTH_RESPONSE_INVALID；已覆盖断连、恢复与空响应测试。

### [~] BUG-064 P0 CAPTCHA 平台题型、状态机与风控编排不符合生产要求

- 证据：旧 `BehaviorCaptcha.tsx` 将多种题型耦合在单一状态机中，曲线、旋转、角度、滑动还原仍未接入已实现的独立组件；旧 Lab 存在坐标映射、图片拉伸、重复提交、失败后不换题、成功后仍可操作等问题；登录滑块与 WAF 质询尚未统一使用同一图像引擎和轮廓池。
- 影响：题面与后端答案协议可能错位，验证码可出现不可完成、误判、重放、视觉失真或前端假功能；对所有请求一律质询还会显著降低站点性能。
- 修复范围：
  - [x] 从前后端协议、签发器、Lab 与配置中彻底移除 `sequence_click` 和 `scramble_jigsaw`。
  - [x] 建立受限图像引擎，支持抗锯齿、安全边距、随机背景及 puzzle/circle/triangle/square/diamond/trapezoid/shield 同源 mask。
  - [x] 建立本地私有资源存储与 S3 兼容抽象，校验格式、尺寸、像素、路径与一次性短期引用。
  - [x] 实现曲线绘制、滑动曲线的服务端题面与轨迹校验，并建立独立前端交互组件。
  - [x] 第一批真实位图题面已完成：轮廓滑块使用同源 mask 的 PNG piece/slot，旋转使用完整底图中心圆裁片，角度使用独立 1:1 圆图，滑动还原使用同图上下半幅；显示元数据与密封答案分离，并通过 `internal/captcha` 测试及 `go vet`。
  - [x] 实现人机验证运行期指标 API 与正式侧栏页面基础结构；页面必须明确当前数据是节点运行期统计，不伪装成长期全局数据。
  - [x] 将曲线、旋转、角度、滑动还原组件接入统一 CAPTCHA 状态机和真实后端协议；公开展示参数由后端签发，答案仍只存在于密封 token。
  - [x] 实现统一 `CaptchaShell`：可配置 Logo、刷新、可选关闭回调、失败冻结并延迟一秒换题、成功冻结、重复提交锁、统一状态/圆角/阴影/焦点/动效及 reduced-motion。
  - [x] 登录层与 WAF 质询层统一迁移到同一轮廓滑块图像引擎，piece/slot 同 mask 且描边清晰不裁边。
  - [x] 产品化文字点选、图标点选、刮刮乐、旋转、角度、滑动还原的服务端图像生成和密封答案；原始坐标、排版秘密不得下发客户端。
  - [x] 接入资源管理 API、RBAC、内置文件管理和 S3 配置/连通性测试；凭据仅使用文件引用，API 不回显，前端默认掩码。
  - [x] 建立风险自适应编排：可信放行、低风险后台自动校验、中风险基础题型、高风险升级题型、极高风险直接拦截；低风险 clearance 最长五分钟，风险信号升高后自动失效并重新质询。
  - [x] 建立服务端 Clearance：Cookie 仅作不可读传输载体，校验签名、过期、站点、路径、策略版本、令牌 ID、撤销状态与多信号绑定，并提供 API 专用 Header。
  - [x] 建立隐式且版本化的 PoW：AEAD 不透明 `p3` token、算法白名单、风险自适应难度与硬上限、防预计算/重放/跨站和跨路径复用；新页面仅通过同源 POST 提交，GET query 不接受新 token，用户界面使用中性安全校验文案。
  - [x] 修复 Lab 错误答案被 HTTP 422 当作服务异常的问题：错误答案现在返回正常验证结果，前端显示失败并冻结，一秒后换题；过期和重放仍返回 410。
  - [x] 修复独立路由语言不同步：主题与语言均在应用根层同步，CAPTCHA Lab、登录等不经过主布局的页面可遵循当前语言。
  - [x] 修复 CAPTCHA 资源空列表返回 null 导致页面崩溃：服务端固定返回空数组，前端 API 边界继续做防御性归一化。
  - [x] 修复 CAPTCHA Lab 深色主题硬编码和移动端无意义空白：页面、控件、状态与底栏改用主题变量，移动端自然排布。
  - [x] 修复点选题旋转插值产生的黑色边缘：图像变换采用预乘透明度插值，图形无显式描边，保留低对比噪点和纤维状干扰纹理。
  - [x] 修复登录滑块连续刷新后弹窗定位被覆盖和题面几何塌缩：移除破坏 Modal 定位的 transform 覆盖，固定题面纵横比并完成桌面连续 30 次刷新几何采样。
  - [x] 登录滑块统一服务端坐标与渲染比例、取消废弃网络请求，并在图片解码后原子切换；已完成移动端、0.8/1.25 设备缩放、700–1200ms CAPTCHA API 延迟和连续五次换题矩阵，题面尺寸稳定且无 console/network 错误。
  - [x] 修复滑动还原正偏移题目无法到达正确位置，补正负偏移端到端契约测试。
  - [x] 统一三版滑动曲线的前后端曲线公式，保证白线视觉重合位置就是服务端验证目标。
  - [x] 统一刮刮乐前端可见笔刷与服务端覆盖半径，避免画面已刮开但服务端仍判失败。
  - [x] 为旋转和角度题补操作时长、轨迹与瞬时提交约束。
  - [x] 将 Behavior 未完成题目状态改为带 TTL、全局/客户端容量和摊销清理的有界状态，覆盖并发与十万次不验证签发测试。
  - [x] Windows 本地资源存储已拒绝符号链接、目录联接和 reparse point，并用卷根逐级句柄相对打开关闭祖先目录 TOCTOU；Windows 专项测试与 race 通过。
  - [x] Linux 本地资源存储使用 `openat2(RESOLVE_NO_SYMLINKS)` 打开完整根路径链，后续使用 `openat`/`O_NOFOLLOW`/目录 fd 相对操作；已有目录会通过句柄收紧到 `0700`，原子替换与删除后同步父目录。2026-07-14 已在 Ubuntu x86_64 使用原生 Go 1.26.5、CGO 与 GCC 完成普通测试及 `go test -race ./internal/captcha/assets -count=1 -v`，临时源码、工具链与测试目录均由脚本清理。
  - [x] S3 预览重新验证实际长度、SHA-256、MIME、图片格式和像素，响应使用隔离 CSP；metadata 使用独立 HMAC 信任根。
  - [x] CAPTCHA 资源运行时配置改为不可变快照原子切换，避免 Store、引用管理器和限制跨版本错配；旧 Store 在在途请求归零后退役关闭，保存失败与连通性测试创建的 Store 也会释放，并通过 race 并发切换测试。
  - [x] 登录 proof/receipt、一次性预览引用增加客户端分层配额和有界清理，单一客户端不能耗尽全局容量。
  - [x] Behavior token 在 Base64 解码与解密前增加协议级长度上限和畸形输入/fuzz 覆盖。
  - [x] 修复生产 WAF Behavior 质询页的 `rotate`、`angle`、`restore_slider` 提交契约；失败或过期后冻结旧 token，延迟一秒获取新题，并增加页面契约测试。
  - [x] 登录 CAPTCHA 配额使用服务端签名的稳定匿名客户端标识隔离共享代理后的不同浏览器，同时保留 peer/global 上限，禁止清 Cookie或轮换标识绕过容量控制。
  - [x] 登录 challenge、proof、receipt 与最终登录统一绑定 socket peer、User-Agent 和签名匿名客户端标识；缺失、篡改或其他合法客户端 Cookie 均不能提前消耗原客户端 proof/receipt，receipt 状态层再次校验 owner/peer。
  - [x] Clearance 状态增加全局与客户端/站点绑定分区容量；单一来源不能耗尽其他客户端的签发能力。
  - [x] CAPTCHA 失败记录容量饱和时 fail-closed，并通过有界淘汰继续记录当前失败。
  - [x] Behavior Pending 使用服务端签名匿名客户端 owner 隔离共享 NAT 浏览器，并保留 peer/global 上限限制轮换标识绕过；错误或缺失身份不能占用他人的 pending。
  - [x] CAPTCHA 资源预览引用在消费时重新绑定当前登录主体，并增加 `Referrer-Policy: no-referrer`。
  - [x] S3 资源 metadata 已建立独立 HMAC 信任根，密钥通过独立文件配置且 API 仅返回配置状态；正文、metadata、长度与摘要同时替换时仍会被拒绝。
  - [x] Windows 本地资源从卷根或共享根句柄逐级打开并验证目录，后续读写、替换和删除均在父目录句柄下相对执行；覆盖祖先 reparse、根路径替换、嵌套目录、关闭生命周期和失败清理测试。
  - [x] 普通挑战、Behavior、等待室和音频响应统一补齐按资源类型约束的 nonce CSP、防嵌入、`nosniff` 与 `no-referrer` 安全头，并增加响应测试。
  - [x] AI 助手面板打开/关闭取消尺寸缩放；关闭保持位置与尺寸不变，仅做 160ms 透明度淡出，并且只响应面板自身动画结束，避免子元素动画冒泡提前卸载；减少动态效果时立即关闭。2026-07-12 Playwriter 复核尺寸始终为 520×620、`transform: none`，截图为 `output/playwriter/ai-assistant-open-close-check.png`。
  - [x] CAPTCHA Lab 13 种入口已完成桌面浅色中文、移动深色英文和窄屏 reduced-motion 视觉矩阵，均无横向溢出、console error 或 request failure；2026-07-12 再次轮换复核旋转、角度、滑动还原、曲线绘制、滑动曲线、文字点选和图标点选，截图保存在 `output/playwriter/`。
  - [x] CAPTCHA 共享底栏统一为清晰的 22px 品牌图标与 `CheeseWAF` 字标；面向用户的 PoW 标题、提示和无脚本文案统一改为中性的“后台安全校验”，不展示算法概念。
  - [x] 登录页改为用户名满足基础格式并稳定输入 300ms 后才签发 CAPTCHA；空用户名不请求、不显示内部 i18n 键，修改或清空用户名会取消旧发题、校验、PoW 与延迟任务。
  - [x] 登录 slider/PoW proof 第一次进入答案验证后即永久消费；错误答案不能复用同一题，畸形请求、身份缺失和缺少轨迹等前置错误不会误消费。
  - [x] 登录与通用 CAPTCHA 的失败换题统一为 1000ms；关闭弹窗会取消在途工作并在关闭动画结束后卸载题面，移动端仅请求后台安全校验模式。
  - [x] 通用 CAPTCHA 的发题与校验协议已透传 `AbortSignal`，手动刷新、关闭和组件卸载会中止底层 HTTP 请求，不再只忽略陈旧响应。
  - [x] 修复轮廓滑块漏绑样式导致浏览器渲染为 16px 原生控件；所有滑动题型统一为 40px 圆角矩形轨道与匹配滑钮，并使用主题变量适配深浅色。
  - [x] CAPTCHA token 增加编码前后长度与字段上限，所有签发器在空密钥时 fail closed；资源引用 reservation 增加随机租约标识，阻止旧 reservation 对新 reservation 的 ABA 提交或释放。
  - [x] 2026-07-13 本地新二进制复核 13 种 Lab 入口：曲线 PNG 等题面无缺图、横向溢出、console error 或 4xx/5xx；登录桌面用户名门控与弹窗卸载、移动端后台安全校验、滑块桌面/移动/深色截图已保存到 `output/playwriter/`。
  - [x] 2026-07-13 修复 AI 助手关闭过渡和移动安全区：关闭中间帧保持 `520×620`、`transform: none`，160ms 淡出后卸载；移动端面板位置与高度纳入 `safe-area-inset-*`，关闭触控区为 44×44px，并增加 CSS 回归测试禁止关闭动画重新引入缩放。证据为 `output/playwriter/ai-assistant-close-midframe.png`。
  - [x] 2026-07-13 修复 `/apisec` 被 Vite `/api` 前缀代理误吞导致白屏和旧哈希资源 404：代理边界收紧为 `^/api(?:/|$)`，8 项回归测试覆盖匹配与排除路径；端点列表桌面完整展示，移动端改为字段卡片，无横向溢出。证据为 `output/playwriter/apisec-layout-fixed-desktop.png` 与 `output/playwriter/apisec-layout-mobile-final.png`。
  - [x] 2026-07-13 修复人机验证总览主题与响应式问题：替换未定义主题变量，趋势柱支持触屏、键盘与 Escape 收起；移动端质询事件由 980px 表格改为完整卡片/空状态。证据为 `output/playwriter/bot-challenge-mobile-dark-final-2.png`。
  - [x] 2026-07-13 修复 CAPTCHA 题型内部深色模式固定浅底和低对比问题，移动端刷新、关闭、验证、辅助按钮及滑动控制区域达到至少 44px；16 个相关测试文件共 91 项通过。
  - [x] 2026-07-13 在 Ubuntu 7.0.0 x86_64 上执行交叉编译的 `internal/captcha/assets` 原生测试二进制，目录权限收紧、openat2 符号链接防护、内容/metadata 篡改、并发单次消费、S3 SSRF 与完整性用例全部通过；测试二进制和临时文件已从服务器 `/tmp` 清理。
  - [x] 2026-07-14 测试服务器安装原生 GCC/`libc` 开发组件后执行 Linux CGO `-race`；本地资源、引用租约与并发单次消费、S3 完整性和 HTTP 对象客户端边界测试全部通过，无竞态报告。
  - [x] 2026-07-13 新增与发布二进制物理隔离的固定场景 Harness 第一阶段：独立 Go 子进程使用临时随机密钥、固定时钟和确定性随机源，覆盖 `rotate`、`restore_slider`、`shape_slider` 的错误拒绝、正确通过和重放拒绝；答案只存在子进程内存，公开报告仅包含题型和生命周期布尔结果。Node runner 默认在浏览器矩阵前执行该门禁，`go test -race`、vet 和连续运行通过。该证据只证明算法/状态机层，完整 HTTP/浏览器链路仍由 handler 测试和后续全题型 E2E 补齐。
  - [x] 2026-07-13 固定场景 Harness 第二阶段覆盖注册表中的全部非 PoW 题型：曲线描绘、曲线滑块 v1/v2/v3、轮廓滑块、旋转、滑动还原、角度、刮擦、文字点选和图标点选；注册表覆盖测试保证新增题型未加入 Harness 时门禁失败。隐藏答案仅在 `internal/captcha` 的 `_test.go` 进程内读取，Node 只解析题型名和四个布尔状态；正式 API、路由和发布二进制无解题入口。全题型 runner 与 `-race` 已通过。
  - [x] 2026-07-13 Playwright 正式 Lab API 代表矩阵覆盖旋转、角度和滑动还原的桌面/移动、浅色/深色、中英文共 24 个场景；每项执行错误提交、约一秒换题、重放 410、正确提交和成功冻结。修复 runner 的失败路由提前卸载竞态、初始随机题响应索引竞态、range 滑钮边界/起点计算及物理像素量化误差，完整矩阵全绿。
  - [x] 新增 `scripts/e2e/captcha-lab` Playwright 代表矩阵框架，默认覆盖可由公开参数求解的旋转、角度和滑动还原；支持桌面/移动、深浅色、中英、失败后约一秒换题、旧 token 重放 410、成功冻结及 console/pageerror/requestfailed/非预期 HTTP 错误收集。`--help`、去敏 `--dry-run` 与脚本语法检查已通过。
  - [ ] 2026-07-14 已完成 11 种非 PoW 题型在桌面/移动、浅色/深色、中英文共 88 个 Playwright 场景；每项均通过错误物理交互、约一秒换题、旧 token 重放 410、正确物理交互、正确 token 重放 410和成功冻结，私有控制计划仅存在 `_test.go` 子进程与 Node 管道，未进入正式 API、DOM、日志或发布二进制。仍需关闭登录接入、WAF 质询放行以及显式刷新/关闭取消的浏览器链路后勾选本项。
- 验收：全量 Go/前端测试、竞态/静态检查和生产构建通过；Playwriter/Playwright 对每种题型执行成功与失败流程，覆盖桌面/移动、浅色/深色、中文/英文、reduced-motion，检查截图、console、network 与布局；未满足上述证据不得标记完成。
- 所有权：Bot/CAPTCHA 产品化批次。

### [x] BUG-065 P1 站点运行时同步失败后 SQLite 与配置状态分叉

- 证据：站点更新原先先写 SQLite，再调用 `syncSites`；`OnSitesChanged` 拒绝候选配置时，运行时、YAML 和内存回滚到旧值，但 SQLite 保留新值。回归测试稳定复现 `sqlite="runtime-rejected-site"`、`yaml="site-test"`、`memory="site-test"`。
- 影响：API 返回失败后，下次重启或重新同步可能加载用户以为没有保存的站点配置，运行中状态与持久状态不一致。
- 修复：站点新建、更新和删除使用独立串行锁；同步失败时分别执行删除、恢复旧记录和重建旧记录。SQLite 增加不推进 `updated_at` 的精确恢复路径；补偿失败时冻结后续配置写入并保留组合错误。
- 验收：新建/更新/删除运行时失败均恢复 SQLite、YAML 和内存；更新时间戳保持不变；补偿失败进入冻结状态；正常持久化、存储错误和集群保护模式测试继续通过。
- 所有权：配置一致性批次。

### [x] BUG-066 P1 点选与刮擦题存在固定位置解法

- 证据：`internal/captcha/visual_selection.go` 将图标点选答案固定在第一个格子，`visual_scratch.go` 将目标固定为行优先的前 N 格；客户端不理解提示也可按固定位置提交。
- 修复：答案位置和目标子集使用独立安全随机排列，保持展示顺序、提示和密封 token 一致；增加多随机种子与位置分布测试。
- 验收：连续样本覆盖不同答案索引和非前缀目标组合，固定点击左上或固定刮前 N 格不能稳定通过。
- 结果：2026-07-14 图标语义角色和刮擦目标均通过安全随机排列映射到物理格位；64 种子分布、固定位置失败、密封 token 正误、PNG 尺寸、边距及不重叠测试通过，相关 `-race` 无报告。

### [ ] BUG-067 P1 WAF 质询的站点绑定、JS Challenge 与返回地址契约不一致

- 证据：代理以 `site.ID` 签发，验证和 Clearance 部分路径却使用 Host；仅启用 JS Challenge 时页面仍提交未签发的空 PoW；部分返回地址未统一经过 `safeChallengeReturnURL`。
- 影响：站点 ID 与域名不同会持续质询；默认 JS Challenge 组合可能永久循环；异常 `//host` 或反斜杠路径可能跨站提交或跳转。
- 修复：站点 ID 贯穿签发、验证、Clearance 与后续评估；JS Challenge 独立签发有效 PoW；所有返回地址在服务端统一归一化为站内路径。
- 验收：`site.ID != Host`、JS-only、Behavior 和异常返回路径均有代理级闭环测试。

### [ ] BUG-068 P1 发题成本配额和 PoW 全局容量可被单一客户端耗尽

- 证据：登录滑块与 Behavior 在昂贵图片/页面生成后才登记 pending；PoW owner 配额只统计未消费项，而已消费 tombstone 继续占用全局容量。
- 修复：渲染前获取 owner、peer、全局并发与速率 reservation，失败可回滚；已消费项立即移除或继续计入 owner 配额并有界淘汰。
- 验收：并发刷新和连续求解压力下 CPU/内存有界，单一 owner 不能阻止其他 owner 发题，取消和生成失败不泄漏槽位。

### [ ] BUG-069 P1 Unix/Darwin 本地 CAPTCHA 资源根在验证前可能跟随链接创建目录

- 证据：Unix 路径先调用 `MkdirAll`；Darwin 仅阻止末级链接，祖先符号链接可把创建和资源操作导向根外。
- 修复：从可信目录句柄逐级校验并创建目录，拒绝祖先链接；失败前后外部目标目录零变化。
- 验收：Linux 与 Darwin 原生测试覆盖祖先/末级链接、并发替换、首次创建和失败清理。

### [~] BUG-070 P2 S3 CAPTCHA 资源配置与列表不完整

- 证据：后端支持 `allow_private_endpoint`，前端类型和回写遗漏；`ListObjectsV2` 未处理 continuation token，资源超过 1000 条后静默缺失。
- 修复：前端完整回显并提交私有端点开关及风险提示；S3 列表循环分页并设置总量、页数和响应字节上限。
- 验收：保存其他字段不改变该开关；1001+ 项可完整分页且恶意无限 continuation 被终止。
- 进展：2026-07-14 前端已补 `allow_private_endpoint` 类型、回显、测试连接、保存与中英文风险提示，组件测试证明修改其他 S3 字段不会清零该开关；后端 continuation 分页与边界测试进行中。

### [x] BUG-071 P2 Bot 总览将事件权限错误显示为空数据

- 证据：总览允许 `read:protection`，事件 API 需要 `read:logs`，前端把 403 当作无事件。
- 修复：按权限隐藏事件区或显示明确权限状态，保留指标访问；不得将鉴权、网络或服务错误归一化为空数组。
- 验收：仅保护读取、完整日志读取、401/403/5xx 四类场景均有组件测试。
- 结果：2026-07-14 指标与事件独立查询；缺 `read:logs` 或服务端 403 显示权限状态，401、网络异常和 5xx 显示错误与重试。相关前端与 locale 测试通过。

### [ ] BUG-072 P2 CAPTCHA 私有 Harness 超时后可能残留进程与临时二进制

- 证据：Lab 私有 Harness 与登录/WAF 集成 fixture 的编译、启动和关闭超时仅结束当前 Promise，Windows 子进程树未被可靠终止并等待退出。
- 修复：统一进程生命周期管理；超时/异常/关闭时终止进程树、等待退出后再删除临时目录，清理失败显式报错。
- 验收：故意卡住编译和运行进程后无残留 PID、句柄或临时二进制，连续运行通过。

### [~] BUG-073 P1 登录成功 Hook 顺序崩溃且滑块键盘目标不可达

- 证据：token 条件返回位于后续 `useCallback` 之前，登录成功写 token 后触发 `Rendered fewer hooks than expected`；键盘步长约为轨道十分之一，明显大于默认 6px 容差。
- 结果：2026-07-14 已将 token 跳转移到全部 Hook 之后；方向键提供 1px 细调，PageUp/PageDown 粗调，Home/End 到达边界，并保持 ARIA 数值同步。
- 验收：浏览器登录成功无 React 崩溃；仅使用键盘可通过任意合法目标位置。

## F. 非本轮缺陷的长期路线

以下来自 `task.md`、`implementation_plan.md`、`engine_upgrade.md`，属于大版本功能而非可以一次补丁关闭的 bug：

- M2 生产安装器、自动加入编排和滚动升级。
- M3 内置 Raft/可选 etcd、一致性、多数确认、保护模式与集群健康端点。
- M4 生产级流量调度、健康降权、熔断、滚动升级和回滚。
- 语义引擎真实业务误报基线、CRS FTW 对标、持续 corpus 筛选和分配 profile 优化。
- Windows CLI/GUI/NSIS 发行形态。

这些项目继续在原计划中跟踪；只有实现、测试、文档和真实部署验收全部完成后才可标记完成。

## 修复顺序与依赖

1. **安全止血**：BUG-001、003、004、006、014。
2. **数据一致性**：BUG-008、009、010。
3. **代理稳定性**：BUG-015、016、017。
4. **集群部署**：BUG-007、011、012、013。
5. **供应链与发布**：BUG-002、018、019、020、021。
6. **产品前端**：BUG-005、022、023、024，并追加细分问题。

## 全量完成门禁

- [x] `go test ./...`（2026-07-12 当前工作树通过）
- [x] `go vet ./...`（2026-07-12 当前工作树通过）
- [ ] 共享状态相关包 `go test -race`（Linux 环境）
- [x] 语义 corpus/readiness/benchmark 当前预算（2026-07-12：readiness 与 curated corpus 测试通过；analyzer corpus 26,610 条、检测率 100%、误报率 0、失败 0；`BenchmarkAnalyzerReadinessCorpus` 130127 ns/op、10567 B/op、177 allocs/op，`BenchmarkSemanticAnalyzer` 144101 ns/op，`BenchmarkFullPipeline` 160554 ns/op。真实业务误报基线和 CRS FTW 对标继续在 `engine_upgrade.md` 跟踪）
- [x] 前端 typecheck、22 个测试文件 106 项测试、production build 与 build budget（2026-07-12 当前工作树通过）
- [ ] Playwright：桌面/移动、浅色/深色、登录/CAPTCHA/站点/地图/AI/通知/设置截图与 console/network 检查
- [ ] Docker build/run
- [x] GoReleaser 六平台 snapshot、校验和、发布包解压启动与静态资源 MIME smoke（2026-07-12 `scripts/ci/verify-release.sh dist` 通过；纯 HTTP 配置不再错误加载未启用的默认证书，TLS/HTTP3 与站点显式证书仍严格校验）
- [ ] Ansible syntax-check 与隔离 Ubuntu 节点部署/回滚 smoke
- [ ] `git diff --check` 与敏感信息扫描
- [ ] 未经上述证据，不提交、不推送、不部署、不宣称全部完成
