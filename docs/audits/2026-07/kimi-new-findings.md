# CheeseWAF 代码与文档审查报告（新发现）

> 审查时间：2026-07-11  
> 审查范围：`web/src/` 前端、`internal/` 与 `cmd/` Go 后端、`README.md` / `README_CN.md`、配置与规划文档  
> 审查方式：只读静态审查，多子代理并行检查 UI/UX、代码安全、AI 黑话、业务逻辑  
> 竞品参考：[雷池 SafeLine](https://github.com/chaitin/SafeLine)、[南墙 uuWAF](https://github.com/Safe3/uuWAF)

---

## 目录

1. [执行摘要](#1-执行摘要)
2. [UI / UX / 动画 / 配色问题](#2-ui--ux--动画--配色问题)
3. [AI 黑话、营销腔与生产级语料问题](#3-ai-黑话营销腔与生产级语料问题)
4. [代码安全问题](#4-代码安全问题)
5. [业务逻辑问题](#5-业务逻辑问题)
6. [README 修改意见（对比 SafeLine / 南墙）](#6-readme-修改意见对比-safeline--南墙)
7. [修复优先级总览](#7-修复优先级总览)

---

## 1. 执行摘要

本次审查共发现 **约 80 条** 具体问题，按大类分布如下：

| 大类 | 数量 | 最高严重级别 |
|------|------|--------------|
| UI/UX/动画/配色 | 22 | High |
| AI 黑话 / 营销腔 / 生产级语料 | 17 | High |
| 代码安全（前端 + 后端） | 27 | Critical |
| 业务逻辑 | 25 | Critical |
| README 结构与表达 | 12 | Medium |

**最需立即处理的问题**：

1. 后端 JWT 认证在缺少密钥配置时会被完全跳过（认证绕过，Critical）。
2. ACME 证书签发流程的 `--reloadcmd` 存在命令注入 / RCE 风险（High）。
3. 自定义拦截页使用 Go `html/template` 解析管理员上传的模板，存在 SSTI 与信息泄露风险（High）。
4. 配置变更先 applyRuntime 再持久化，失败时无法保证一致性（Critical）。
5. Bot challenge secret 在每次配置变更/初始化时都会被重新生成，导致已签发票据失效（Critical）。
6. AI 自学习 `dry_run` 与 `auto_apply` 语义互相覆盖，且 LLM 审核失败时仍可能自动写规则（High）。
7. 前端 AI 助手占位符、自动生成的规则名称存在明显 AI 营销腔（High）。

---

## 2. UI / UX / 动画 / 配色问题

### 2.1 高严重级别

| # | 类别 | 位置 | 问题 | 建议 |
|---|------|------|------|------|
| U1 | 首屏阻塞 | `web/src/main.tsx` | 主题 CSS 通过 `loadThemeStyles` 同步 `await` 加载，首屏渲染被阻塞。 | 改为异步加载，先渲染占位/默认主题，主题就绪后再切换；加超时 fallback。 |
| U2 | 可访问性 / 动画 | `web/src/styles/global.css:1782-1817`、`:2148-2162`、`:7176-7201` | 骨架屏 `background-position` shimmer 在 `prefers-reduced-motion` 下仅把 `animation-duration` 压到 `1ms`，仍会闪烁。 | reduced-motion 下显式 `animation: none`，骨架屏改为静态色块。 |
| U3 | 可访问性 / 状态可见性 | `web/src/pages/Dashboard/DashboardPage.tsx:378,385,392,399,406` | 资源面板 `Progress` 全部 `showText={false}`，仅依赖色块表示负载。 | 增加 `aria-label`/`aria-valuenow` 或显示百分比，避免颜色为唯一信息通道。 |
| U4 | 响应式 / 3D 性能 | `web/src/pages/AttackMap/AttackMapPage.tsx`、`web/src/pages/AttackMap/GlobeMap.tsx:143` | 3D Globe 在 mount 内直接 `new WebGLRenderer(...)`，默认高功耗模式，260 颗星 + cloud texture + 112 分段。 | 低端/省电/移动模式默认 2D；首次进入 3D 时再加载 Three.js；增加降级确认。 |

### 2.2 中严重级别

| # | 类别 | 位置 | 问题 | 建议 |
|---|------|------|------|------|
| U5 | 响应式 / 搜索框 | `web/src/styles/global.css:7551-7553` | `.topbar-search` 在 `max-width: 520px` 下固定 `max-width: 176px`，在 320–375px 设备上严重挤压。 | 使用 `clamp()` 或更细断点；375px 以下折叠为图标按钮。 |
| U6 | 响应式 / 表格 | `web/src/styles/global.css` `.table-code` | `max-width: min(42vw, 520px)`，小屏下内容溢出或横向滚动。 | 改为 `max-width: 100%` 或容器 `minmax(0, 1fr)`。 |
| U7 | CSS 可维护性 | `web/src/styles/ai-page.css` | 全文件 872 处 `!important`，大量重复媒体查询，网格列强制 `repeat(3, ...)`。 | 重构为 CSS 变量/容器查询，减少 `!important`，窄屏统一 `1fr`。 |
| U8 | 主题一致性 | `web/src/features/captcha/BehaviorCaptcha.module.css`、`CaptchaShell.module.css` | 验证码组件大量使用硬编码十六进制色值，未使用主题变量。 | 抽取 `--captcha-bg`、`--captcha-text` 等变量，按主题赋值。 |
| U9 | 主题一致性 | `web/src/themes/*.css`、`global.css:7215-7216` | 多处 `color-mix(in srgb, ... #000000 / #ffffff)` 用绝对黑白混合，破坏 dark/black-gold 主题色相。 | 混合时使用当前主题色 `--surface`/`--text`。 |
| U10 | 主题一致性 | `web/src/styles/attack-map.css:2358`、`:3511` 等 | 大屏/3D 模式硬编码 `#24cfff`、`#28f1d3`、`#ff7256` 等高饱和霓虹色。 | 迁移到主题变量或提供暗色专用模式。 |
| U11 | 文案 / 国际化 | `web/src/pages/AI/AIPage.tsx:384` | 表单 label 用 `i18n.language.startsWith('zh')` 硬编码切换，未走 i18n key。 | 提取为 `t('ai.selfLearningMaxEventsLabel')`。 |
| U12 | 文案 / 国际化 | `web/src/pages/CaptchaLab/CaptchaLabPage.tsx:11-15` | 页面标题固定为 `Captcha Lab`，其余文案通过本地 `zh` 布尔值硬编码。 | 全部使用 `useTranslation` 与 i18n key。 |
| U13 | 可访问性 | `web/src/layouts/MainLayout.tsx:513-516` | 账户按钮用户名 `max-width: 110px` 省略，无 `title` 或 Tooltip。 | 为 `<span>` 增加 `title={account.username}`。 |
| U14 | 动画过度 | `web/src/layouts/MainLayout.tsx`、`.status-breathe` | 侧边栏状态指示灯 1.8s infinite 呼吸动画，强视觉刺激。 | 降低幅度或改为静态色点；reduced-motion 下静止。 |
| U15 | 触控目标 | `web/src/pages/Login/LoginPage.tsx` | 滑块拇指 38px，轨道高 40px。 | 拇指目标至少 44×44px，可扩展透明 hit area。 |

### 2.3 低严重级别

| # | 类别 | 位置 | 问题 | 建议 |
|---|------|------|------|------|
| U16 | 布局 | `web/src/components/AIAssistant/AIAssistant.tsx` | 面板固定 `width: min(520px, calc(100vw - 32px))`，小屏占满。 | 增加 `env(safe-area-inset-top)`；<360px 使用全屏抽屉。 |
| U17 | 布局 | `web/src/components/AIAssistant/AIAssistant.tsx`、`.AIAssistant.css` | 助手消息固定 `width: min(100%, 456px)`，长内容可能撑开。 | `max-width: 100%` + `word-break: break-word` + `overflow-wrap: anywhere`。 |
| U18 | 布局 | `web/src/pages/Dashboard/DashboardPage.tsx` `.traffic-chart` | 图表高度 `clamp(280px, 31vw, 420px)`，超宽屏占用过多垂直空间。 | 使用 `aspect-ratio` 或 `max-height` 限制。 |
| U19 | 动画营销感 | `web/src/components/AIAssistant/AIAssistant.css` `.ai-fab::before` | AI 助手入口 2.8s infinite halo 脉冲，过度吸引注意。 | 减弱透明度或仅首次触发；reduced-motion 停止。 |
| U20 | 动画干扰 | `web/src/styles/attack-map.css` 2D 标记 | 攻击地图标记 `map-marker-pulse 1.9s ease-out infinite`。 | 降低频率或悬停/选中才脉冲；reduced-motion 停止。 |
| U21 | 代码可读性 | `web/src/pages/BotChallenge/BotChallengePage.tsx:102` | `EventTable` 单行 JSX 过长。 | 拆分为子组件或多行格式化。 |
| U22 | 外部媒体配置 | `web/src/pages/Login/LoginPage.tsx` | 登录背景 URL 由后端下发，前端未校验协议/白名单。 | 校验 `https:` 或受信任相对路径，拒绝 `javascript:`/`data:`；CSP 限制媒体来源。 |

### 2.4 正面实践（值得保留）

- `web/src/styles/global.css` 已有全局 `@media (prefers-reduced-motion: reduce)` 兜底。
- `web/src/pages/AttackMap/GlobeMap.tsx:413` 监听 `prefers-reduced-motion` 并禁用自动旋转/云层动画。
- `web/src/components/AIAssistant/AIAssistantEntry.tsx` 对助手组件做懒加载 + hover/focus 预加载。
- `web/src/styles/global.css:7547-7573` 对 520px 以下断点有较完整的按钮/网格/标题降级。

---

## 3. AI 黑话、营销腔与生产级语料问题

### 3.1 高严重级别

| # | 类别 | 位置 | 原文 / 问题 | 建议 |
|---|------|------|------------|------|
| A1 | 聊天机器人 demo 腔 | `web/src/i18n/locales/zh-CN.ts:1133` | 助手占位符：`"查安全、找漏洞、写规则，我都可以帮你"` | 改为 `"输入与 WAF 事件分析、漏洞排查或规则编写相关的问题。"` |
| A2 | 夸大实现能力 | `internal/ai/self_learning.go:119-120` | 自动生成规则名 `"AI self-learned " + Category`，描述 `"Created by CheeseWAF self-learning..."` | 实际为重复事件统计 + 可选 LLM 审核，并非模型自主学习。改为 `"auto-generated: " + Category`，描述改为 `"Generated from repeated high-confidence blocked events and reviewed by local policy."` |
| A3 | 隐私 / 数据外发 | `internal/ai/analyzer.go:832-851` | 单事件分析把 `client_ip`、`uri`、`payload`（2048 字符）、`user_agent` 等直接发给第三方 AI provider。 | 默认脱敏/截断，提供配置项让用户显式选择字段；UI 与文档明确告知数据会离开本地。 |

### 3.2 中严重级别

| # | 类别 | 位置 | 原文 / 问题 | 建议 |
|---|------|------|------------|------|
| A4 | 夸大宣称 | `web/src/i18n/locales/zh-CN.ts:931-943` | `"自动规则学习"`、`"由推理模型和本地安全策略审核后，仅在确实可疑时生成规则"` | 实现为基于历史事件生成候选规则。改为 `"自动规则生成"`，提示中突出 `"候选"` 与 `"生成"`。 |
| A5 | 管理黑话 | `web/src/i18n/locales/zh-CN.ts:708` | `"控制自动化访问验证链路"` | `"链路"` 是内部黑话。改为 `"流程"` 或 `"机制"`。 |
| A6 | 中英混杂 | `internal/ai/types.go:90-91`、`:122-124`；`internal/ai/tools.go:61` | 中文注释中突兀使用 `LLM tool description`、`ListForLLM`、`LLM API` | 中文注释统一用 `"模型工具描述"`、`"模型 API"`；方法名可重命名为 `ListToolDefinitions()`。 |
| A7 | 内部文档黑话密度高 | `progress.md:177`、`:185`、`:202`；`implementation_plan.md:37`、`:171`、`:199`、`:583`、`:869`；`task.md:331`、`:371`；`fix_task.md:524` | 大量 `AI Agent`、`LLM`、`闭环`、`AI 大模型`、`AI 核心完成` 等词汇 | 统一术语：`AI Agent` → `"模型助手/自动规则建议"`；`LLM` → `"模型/大语言模型"`；`闭环` → `"流程/机制/完成"`。`progress.md:202` 的夸张句式应作为反面示例。 |
| A8 | 包装普通功能 | `internal/ai/knowledge.go:117` | 知识片段标题 `"AI self-learning guardrails"` | 改为 `"Automatic rule generation guardrails"` 或 `"自动规则生成约束"`。 |
| A9 | 命名营销化 | `internal/ai/types.go:43-45` | 注释 `"assistant agent loop"` | 实际只是工具调用/审批跟踪。改为 `"assistant tool loop"`。 |
| A10 | 文案与实现不一致 | `web/src/i18n/locales/zh-CN.ts:931-932` | `"由推理模型和本地安全策略审核后，仅在确实可疑时生成规则"` | `internal/ai/self_learning.go:89-93` 在 LLM 失败时仍可能自动写规则。文案改为 `"优先由推理模型审核；模型不可用时按本地安全阈值处理"`，或在代码里强制 LLM 失败时禁止 auto-apply。 |
| A11 | 权限分离不足 | `internal/api/handler/ai_tools.go:76-91` | 修改类 AI 工具可由发起者自己批准。 | 危险工具强制要求 `approve:ai` 且不能自批；`write:ai` 只能创建审批请求。 |
| A12 | 流式输出未过滤 | `internal/ai/client.go:982-988`、`:1087-1092` | `reasoning_delta` / `content_delta` 直接 SSE 推送，未经过与最终答案一致的过滤。 | 流式 assembler 中对每个 delta 应用 `sanitizeAssistantFinalAnswer` 同等过滤。 |
| A13 | 前端实时渲染 | `web/src/pages/AI/AIPage.tsx:663-672`、`web/src/components/AIAssistant/AIAssistant.tsx:99-100` | 直接显示从 SSE 接收的 `reasoning` / `content` 增量。 | 前端复用 `stripInternalProcessPhrases` 清洗逻辑。 |

### 3.3 低严重级别

| # | 类别 | 位置 | 原文 / 问题 | 建议 |
|---|------|------|------------|------|
| A14 | 聊天机器人腔 | `web/src/i18n/locales/en-US.ts:1135` | 空状态标题 `"Hi, what do you want to check today?"` | 改为 `"What would you like to analyze?"` 或 `"Ask about a WAF event, rule, or setting."` |
| A15 | 聊天机器人腔 | `web/src/i18n/locales/zh-CN.ts:1135` | 空状态标题 `"今天想问我什么？"` | 改为 `"欢迎使用 AI 助手"` 或 `"可询问安全事件分析、规则建议或 WAF 设置。"` |
| A16 | 乱码字符 | `internal/api/handler/ai.go:1662` | `normalizeAITarget` 的 switch case 含 `"鎺ㄧ悊"`（"推理" 编码损坏） | 修正为 `"推理"`，并检查文件编码一致性。 |
| A17 | 透明度不足 | `internal/ai/knowledge.go:35-78`、`internal/ai/tools.go:419-428` | 知识库工具把用户问题直接用于检索并送入 LLM prompt，UI 未说明数据流向。 | 在 AI 助手空状态或提示中增加数据去向说明；提供关闭知识库引用的开关。 |

### 3.4 不属于问题但需保持克制的观察

- README 中 `"当前只能声明'可用且可解释'，不能声明 ModSecurity/OWASP CRS 等价"` 是克制表述，应保留。
- 技术术语如 `"User-Agent"`、 `"验证链路"`（滑块视觉描述）、`"链路本地地址"`（Link-local）属于正常网络/安全用语，不纳入黑话。

---

## 4. 代码安全问题

### 4.1 后端安全（Critical / High）

| # | 严重 | 类别 | 位置 | 问题 | 建议 |
|---|------|------|------|------|------|
| S1 | Critical | 认证绕过 | `internal/apisec/auth.go:161-165`、`internal/config/validator.go:441-443`、`internal/apisec/jwt.go:115-126` | `APISec.Auth.Enabled=true` 但未配置密钥时，`verifier.configured()` 返回 false，签名检查被跳过。 | 启用认证时强制至少配置一种验证密钥；未配置时直接返回认证失败。 |
| S2 | High | 命令注入 / RCE | `internal/acme/issuer.go:42-49`、`:159-165`、`:182-186`；`internal/config/validator.go:1482-1490` | `ACMESHPath` 仅校验非空；`ReloadCmd` 原样作为 `--reloadcmd` 传给 acme.sh 执行，未限制 `;`、`&`、`|`、`$()`。 | 对 `ACMESHPath` 白名单校验；`ReloadCmd` 拆分为命令白名单 + 固定参数，禁止直接 shell 字符串。 |
| S3 | High | SSTI / 存储型 XSS / 信息泄露 | `internal/blockpage/renderer.go:85-92`、`:125-157`；`internal/api/handler/ops.go:593-638` | 管理员上传的 `CustomHTML` 直接作为 Go `html/template` 解析并 Execute，传入 EventID/TraceID/ClientIP/Message。 | 模板使用沙箱化最小函数集；剥离敏感字段；上传/预览时给出安全警告并静态扫描。 |
| S4 | Medium | 弱加密 | `internal/setup/defaults.go:614-620` | `subjectKeyID` 使用 `crypto/sha1` 生成 Subject Key Identifier。 | 改为 `sha256.Sum256`（或前 160 位）。 |
| S5 | Medium | 路径遍历 / 任意文件读取 | `internal/api/handler/site.go:39-102`；`internal/proxy/tls_manager.go:151-157`；`internal/config/validator.go:1493-1512` | `CertFile`/`KeyFile` 未限制必须位于可信证书目录。 | 强制绝对路径且在 `Setup.DataDir/certs` 下；拒绝符号链接跳出目录。 |
| S6 | Medium | 业务逻辑 / 自动阻断 | `internal/ai/self_learning.go:104-134`、`:146-168`、`:341-368` | `AutoApply=true && !DryRun` 时直接写规则；LLM 审核可选且可失败跳过。 | 默认 `AutoApply=false`；LLM 审核失败时禁止 auto-apply；新规则初始 `Enabled=false` 或 `Action=log`。 |
| S7 | Medium | SSRF / 内网越界 | `internal/proxy/loadbalancer.go:58-80`；`internal/proxy/reverse_proxy.go:22-37` | 上游 `upstream.Address` 直接交给反向代理，未限制私有 IP / localhost / metadata 地址。 | 解析并拒绝私有/回环/链路本地/metadata 地址，除非显式开启允许私有上游。 |
| S8 | Low | 密钥管理 | `internal/config/runtime.go:25-37`；`internal/api/handler/site.go:199-227`；`internal/config/loader.go:382-394` | 自动生成的 Bot Secret 被写回主配置及 versions/ 备份，权限 0o640。 | 独立运行时密钥文件 0o600；配置保存时排除敏感字段。 |
| S9 | Low | 缓存键污染 | `internal/edge/cache.go:139-141` | `cacheKey` 直接拼接 `r.Host`（来自客户端 Host 头）。 | 使用校验后的 `site.ID`；规范化 Host（小写、去端口）。 |
| S10 | Low | 配置注入 | `internal/storage/log_sink/clickhouse.go:32-34`、`:59-62` | `cfg.Database` 未做标识符白名单校验（Table 已校验）。 | 对 Database 应用与 Table 相同的标识符白名单。 |
| S11 | Low | 高权限操作 | `internal/api/handler/ops.go:461-515` | `reclaimResources` 调用 `sync`、写入 `/proc/sys/vm/drop_caches`、执行 `swapoff -a` / `swapon -a`。 | 增加细粒度权限检查；记录审计日志；生产环境默认禁用或需二次确认。 |

### 4.2 前端安全（High / Medium）

| # | 严重 | 类别 | 位置 | 问题 | 建议 |
|---|------|------|------|------|------|
| S12 | High | XSS / HTML 注入 | `web/src/pages/BlockPages/BlockPagesPage.tsx:341-388`、`:268`、`:136-152` | `sanitizeBlockPreviewHTML` 是手写净化器，仍保留 `<form>`、`<input>`、`<a>`、`<style>`、`<link>`、`<base>`；弹窗预览用 blob URL 打开无 sandbox。 | 使用 DOMPurify 等成熟库并删除上述标签；iframe 用 `sandbox=""`；弹窗预览走独立路由。 |
| S13 | Medium | 安全响应头缺失 | `web/index.html:1-14` | 未设置 CSP meta 标签。 | 添加 CSP，限制 script/style/connect/img/frame/object/base-uri/form-action。 |
| S14 | Medium | 凭据存储 | `web/src/api/client.ts:14,25,109`；`web/src/pages/Login/LoginPage.tsx:290`；`web/src/layouts/MainLayout.tsx:272`；`web/src/routes/index.tsx:48` | `cheesewaf-token` 存于 `localStorage`。 | 改为 `HttpOnly`、`Secure`、`SameSite=Strict` Cookie；前端通过 `withCredentials` 自动携带。 |
| S15 | Medium | 客户端认证绕过 | `web/src/routes/index.tsx:46-66` | 路由守卫仅检查 token 是否存在。 | 启动时向 `/api/auth/verify` 验证；过期/无效 token 立即清理并重定向。 |
| S16 | Medium | 权限显示错误 | `web/src/layouts/MainLayout.tsx:805-822`；`web/src/pages/Users/UsersPage.tsx:553-566` | token 缺失或解码失败时回退为 `{ username: 'admin', role: 'admin' }`。 | 回退为空角色并触发登出。 |
| S17 | Medium | XSS（配置污染） | `web/src/pages/Login/LoginPage.tsx:260-262`、`:527-530`、`:970-971` | `backgroundURL` 来自后端，直接用于 `<video src>` 和 CSS `background-image`；仅去除引号/反斜杠/换行。 | 校验协议为 `https:` 或受信任相对路径，拒绝 `javascript:`/`data:`/`vbscript:`。 |
| S18 | Medium | 供应链 / 信任锚 | `web/src/pages/Updates/UpdatesPage.tsx:74-98`、`:298-314` | OTA 公钥从任意 HTTPS 源拉取，`validateOTAServer` 只要求 `https:` + hostname 非空。 | 官方源公钥硬编码/固定；自定义源要求手动粘贴公钥或证书指纹。 |
| S19 | Medium | 存储型 XSS（前后端衔接） | `web/src/pages/BlockPages/BlockPagesPage.tsx:90-98`；`web/src/api/client.ts:747-756` | `.html/.htm` 文件上传直接发送到 `/block-pages/upload`。 | 后端保存/渲染拦截页时执行与前端同等或更严格净化，并设置独立 CSP。 |
| S20 | Low | 不安全的窗口打开 | `web/src/pages/BotChallenge/BotChallengePage.tsx:58`；`web/src/pages/Protection/ProtectionPage.tsx:203` | `window.open(..., '_blank', 'noopener,noreferrer')` 将 rel 写在 windowFeatures。 | 显式设置 `win.opener = null` 或改用 `<a rel="noopener noreferrer">`。 |
| S21 | Low | 敏感信息泄露 | `web/src/components/AppErrorBoundary.tsx:130-164` | 错误上报携带 `error.stack`、完整 URL（含 query）、`Authorization: Bearer <token>`。 | 过滤 query string（删除 token、code、password 等），服务端日志脱敏。 |
| S22 | Low | XSS（数据源污染） | `web/src/features/captcha/protocol.ts:85-89` | `safeImageDataUri` 允许 SVG data URI。 | 验证码图片禁用 SVG data URI 或对 SVG 内容额外净化。 |
| S23 | Low | 开发环境配置风险 | `web/vite.config.ts:18-23` | `VITE_DEV_API_TARGET` 可指向任意地址。 | 开发环境保持可信；生产构建不依赖该配置。 |

### 4.3 已核实安全实践（值得保留）

- 登录接口实现并发槽位限制、按 IP/账号失败次数限流、锁定窗口（`internal/api/handler/handler.go:373-389` 等）。
- 存储迁移使用静态 DDL，无 SQL 拼接（`internal/storage/migration.go`）。
- 管理 API 路由级 RBAC 与回归测试已覆盖未授权访问、CSRF、readonly 写操作。
- 管理平面默认 localhost，公开绑定需 `admin_public + admin_tls`。

---

## 5. 业务逻辑问题

### 5.1 Critical

| # | 位置 | 问题 | 建议 |
|---|------|------|------|
| B1 | `internal/api/handler/site.go:292-309` | `commitConfigMutation` 先 `applyRuntime(candidate)`，再 `persistConfigCandidateLocked`。持久化失败时仅尝试 `applyRuntime(previous)` 回滚，但运行时可能已变更；回滚失败则系统冻结配置写入且状态不一致。 | 先持久化配置，成功后再 applyRuntime；或使用两阶段提交。 |
| B2 | `internal/config/runtime.go:25-38`；调用点 `site.go:286`、`setup/service.go:356`、`handler.go:203` | `EnsureRuntimeSecrets` 只要 Bot Secret 为空/占位就重新生成随机 secret，无稳定化逻辑。 | Secret 只应在首次需要时生成并稳定持久化；后续从持久化存储或环境变量读取。 |
| B3 | `internal/api/handler/site.go:310` | 配置保存成功后 `*h.Config = *candidate` 是浅拷贝，内部 map/slice 共享底层内存。 | 使用 `config.Clone` 深拷贝回 `h.Config`。 |
| B4 | `internal/api/handler/ai.go:670-699`；`internal/ai/self_learning.go:96-104`、`:165-168` | `dry_run` 与 `auto_apply` 语义互相覆盖：`DryRun = cfg.DryRun || !cfg.AutoApply`。 | 二选一或在配置校验层强制 `dry_run => !auto_apply`；报告里明确标注实际执行模式。 |

### 5.2 High

| # | 位置 | 问题 | 建议 |
|---|------|------|------|
| B5 | `internal/scheduler/engine.go:143-162` | `timer.Reset(task.Every)` 未排空通道，长任务执行期间可能丢失 tick。 | 改用 `time.Ticker`，或 Reset 前 `if !timer.Stop() { <-timer.C }`。 |
| B6 | `internal/proxy/loadbalancer.go:38-56` | 未匹配 Host 时回退到第一个启用站点。 | 增加“严格 Host 匹配”配置；默认无匹配时返回空配置或阻断。 |
| B7 | `internal/proxy/server.go:33-40`、`:52-115`、`:283-299` | `Server` 持有独立的 `blacklist`/`whitelist` 字段但请求路径只使用 `AccessPolicy`。 | 删除未使用字段，或显式调用并 documented 优先级。 |
| B8 | `internal/proxy/health_check.go:138` | 健康检查把 4xx 也视为健康（`StatusCode < 500`）。 | 默认只接受 200-399 为健康，或把成功状态码范围做成可配置。 |
| B9 | `web/src/api/client.ts:78-124` | Token 刷新失败后 `catch` 里仍 `return token`，外层请求会继续使用可能已失效的 token。 | 刷新失败返回 rejected Promise，请求拦截器直接拒绝并跳转登录。 |
| B10 | `web/src/routes/index.tsx:46-66` | 路由守卫只检查 token 存在性，不校验是否过期。 | 解析 token claims，过期则清理并跳转 `/login`。 |

### 5.3 Medium

| # | 位置 | 问题 | 建议 |
|---|------|------|------|
| B11 | `internal/api/handler/system.go:136-141` | `applySystemPayload` 对空 AI 密钥回退为 previous；而 `UpdateAIConfig` 对空字段忽略。两条路径语义不一致。 | 统一使用“空字符串表示不修改”，或用 `api_key_set + api_key` 区分清空与保留。 |
| B12 | `internal/config/validator.go:1017-1111` | Bot 保护未启用时仍强制校验阈值。 | Bot 未启用时跳过或放宽阈值校验。 |
| B13 | `web/src/pages/Protection/ProtectionPage.tsx:740-750` | Duration 输入对小于 1 秒的值会向上取整为 1 秒。 | 默认单位加入 `'ms'`，或小于最小单位时原样返回纳秒/毫秒。 |
| B14 | `internal/proxy/loadbalancer.go:64-68` | IP Hash 负载均衡对 IP 字符串 rune 求和，分布性差。 | 使用 `hash/fnv` 或 `xxhash` 对 IP 字节做哈希。 |
| B15 | `internal/scheduler/cleanup.go:136-144` | 清理任务按文件名含 `backup` 即按 `.backup` 后缀匹配，容易误删。 | 使用精确前缀如 `cheesewaf-backup-*.tar.gz`，配置中显式声明保留模式。 |
| B16 | `internal/setup/wizard.go:23` | `DefaultDataDir = "/var/lib/cheesewaf"` 在所有平台生效，Windows 无效。 | 按 `runtime.GOOS` 区分默认值，Windows 使用 `%ProgramData%\CheeseWAF` 或 `./data`。 |
| B17 | `internal/setup/service.go:114-128`、`:252-271` | `setup.CompleteSetup` 回滚时 `*cfg = *previousConfig` 是浅拷贝，且不恢复运行时状态。 | 回滚后让 `cfg` 指向深拷贝；setup 失败应整体退出或重启进程。 |
| B18 | `internal/proxy/server.go:551-563` | `requestIsHTTPS` 对 IPv6 规范化处理不足。 | 统一使用 `net.SplitHostPort` + `net.ParseIP` 标准化后再做 CIDR 匹配。 |
| B19 | `internal/api/handler/handler.go:783-789` | `pruneExpiredSessions` 使用 `now - 24h` 作为删除阈值，会话 TTL 也是 24h。 | 清理阈值应基于 `expires_at < now` 或 `now - smallGracePeriod`。 |
| B20 | `web/src/pages/Sites/SiteDetailPage.tsx:71-79` | 删除成功后 `invalidateQueries` 后立即 `navigate`，列表可能仍显示被删站点。 | `await queryClient.invalidateQueries(...)` 后再跳转，或乐观更新移除缓存项。 |

### 5.4 Low

| # | 位置 | 问题 | 建议 |
|---|------|------|------|
| B21 | `internal/api/handler/handler.go:266-286` | `LoginOptions` 返回的 `max_number` 未在 handler 层校验范围。 | 视图层做 clamp，返回合理客户端上限。 |
| B22 | `internal/api/handler/ops.go:220-236` | `UpdateEdgePolicy` 只保存配置，未调用运行时回调。 | 增加 `OnEdgeChanged` 回调并触发，实现热重载。 |
| B23 | `web/src/pages/Protection/ProtectionPage.tsx:468-471` | ACL `path_prefix` 前端未校验必须以 `/` 开头。 | 前端校验：为空或以 `/` 开头且不含 `..`、`?`、`#`。 |
| B24 | `internal/api/handler/handler.go:739-759` | `RefreshToken` 未先显式验证旧会话 active 状态。 | 刷新前显式检查会话 active，非 active 返回 401。 |
| B25 | `internal/api/handler/ops.go:91-108` | `UpdateTasks` 回滚持久化失败后 scheduler engine 中任务未回滚。 | `engine.Replace` 在持久化成功后调用；失败时调用 `engine.Replace(previousTasks)`。 |

---

## 6. README 修改意见（对比 SafeLine / 南墙）

### 6.1 当前 README 的主要问题

1. **功能清单过长，缺少一句核心卖点**  
   当前 README 的“当前状态”用 30+ 条长句罗列功能，更像变更日志或内部验收文档，而不是面向潜在用户的项目介绍。SafeLine 和南墙都在首屏用一句话讲清楚产品是什么、能解决什么问题。

2. **缺少工作原理图 / 架构图**  
   SafeLine 用一张反向代理工作原理图帮助用户 10 秒理解部署方式；CheeseWAF 当前 README 没有任何图示。

3. **缺少项目截图 / 演示环境链接**  
   SafeLine 在 README 中放了 4 张截图和演示环境链接；南墙也有功能截图。CheeseWAF 仅文字描述，对新用户吸引力不足。

4. **“当前状态”与“阶段快照”过于内部化**  
   阶段快照包含 PR 编号、commit hash、GitHub Actions run ID、Forgejo mirror 状态等，属于内部会议纪要，不应放在 README 中。可移至 `docs/phase4-operations.md` 或 release notes。

5. **安装/部署命令不突出**  
   SafeLine 和南墙都在 README 首屏下方提供“一键安装”命令。CheeseWAF 的安装说明分散在 Development 段落末尾，且默认是源码构建，对普通用户门槛高。

6. **防护效果数据缺失**  
   SafeLine 和南墙都提供与 ModSecurity/CloudFlare 对比的检出率/误报率表格。CheeseWAF 提到 corpus gate 和 semantic readiness，但没有给出易读的数据表格。

7. **不自信/过度克制的表达影响第一印象**  
   `"当前只能声明'可用且可解释'，不能声明 ModSecurity/OWASP CRS 等价"` 这种表述虽然诚实，但作为项目首屏会削弱用户信心。可保留在 `docs/` 中，README 中改为更积极的定位，同时用“pre-release / beta”标签提示成熟度。

8. **AI 描述仍有包装感**  
   虽然 README 本身较克制，但“AI 运维界面”“自动规则学习”“聊天式控制台助手”等描述仍容易让读者觉得 AI 是核心卖点。建议改为“可选的 LLM 辅助分析”，把 AI 定位为增强功能而非产品定义。

### 6.2 具体修改建议

#### 6.2.1 结构调整

建议 README 采用如下结构：

```markdown
# CheeseWAF

[English](README.md) | [简体中文](README_CN.md)

<p align="center">
  <img src="docs/images/banner.png" width="400" />
</p>

<h4 align="center">
  CheeseWAF - 单二进制、可自托管的 Web 应用防火墙
</h4>

<p align="center">
  <a href="https://cheesewaf.example.com">🏠 官网</a> |
  <a href="https://docs.cheesewaf.example.com">📖 文档</a> |
  <a href="https://demo.cheesewaf.example.com">🔍 演示环境</a> |
  <a href="https://github.com/LaokeQwQ/CheeseWAF">GitHub</a>
</p>

## 👋 项目介绍

CheeseWAF 是一款基于 Go 的单二进制 Web 应用防火墙，提供反向代理、语义检测、Bot 防护、IP/ACL/限流、威胁情报、边缘缓存与压缩、管理控制台等能力。目标是让中小团队能在几分钟内部署一套可自托管的 WAF。

## 🛡️ 核心能力

- **Web 攻击防护**：SQL 注入、XSS、RCE、LFI、SSRF、NoSQL、SSTI 等语义检测。
- **Bot 与 CC 防护**：JS Challenge、PoW、图像/滑块验证码、排队室。
- **访问控制**：IP 黑白名单、ACL、信誉分、GeoIP、可信代理识别。
- **API 安全**：Schema 校验、JWT 验证、端点级限流。
- **可观测性**：Prometheus 指标、多 sink 日志、攻击地图、安全报告。
- **管理控制台**：Web / API / TUI 统一入口，RBAC、审计日志。

## 🚀 快速开始

### 安装

```bash
# Docker Compose（推荐）
curl -fsSL https://cheesewaf.example.com/install.sh | bash

# 或下载单二进制
curl -LO https://github.com/LaokeQwQ/CheeseWAF/releases/latest/download/cheesewaf-linux-amd64
```

### 配置站点

见 [快速配置文档](docs/quick-start.md)。

## 📊 防护效果

| 指标 | ModSecurity L1 | CloudFlare Free | CheeseWAF smart | CheeseWAF strict |
|------|---------------|-----------------|-----------------|------------------|
| 样本数量 | 33,669 | 33,669 | 33,669 | 33,669 |
| 检出率 | 69.74% | 10.70% | 待填入 | 待填入 |
| 误报率 | 17.58% | 0.07% | 待填入 | 待填入 |
| 准确率 | 82.20% | 98.40% | 待填入 | 待填入 |

> 测试方法与完整 corpus 见 [docs/security-validation.md](docs/security-validation.md)。

## 📸 截图

（建议放 2-4 张控制台截图，或链接到演示环境）

## 📋 更多信息

- 架构与部署：[docs/cluster-ha.md](docs/cluster-ha.md)
- 语义引擎成熟度：[docs/semantic-readiness.md](docs/semantic-readiness.md)
- 管理 API：[docs/management-api.md](docs/management-api.md)
- 开发与构建：见 [Development](#development) 段落
```

#### 6.2.2 内容修改点

| 当前表达 | 问题 | 建议 |
|---------|------|------|
| `CheeseWAF is a Go-based Web Application Firewall scaffold focused on a single-binary deployment model...` | `scaffold` 暗示未完成/骨架 | 改为 `CheeseWAF is a Go-based, single-binary Web Application Firewall...` |
| 30+ 条“当前状态”长列表 | 像变更日志 | 压缩为 6-8 条核心能力，其余移入 `docs/features.md` |
| `The current claim is "working and explainable", not "ModSecurity/OWASP CRS parity"` | 首屏不自信 | 移至 `docs/semantic-readiness.md`，README 中用 `Beta` badge 提示成熟度 |
| 阶段快照（PR #55/#56/#57、run ID、commit hash） | 内部会议纪要 | 删除或移入 release notes / `.github/CHANGELOG.md` |
| Development 段落在底部且只有源码构建 | 普通用户找不到安装方式 | 首屏增加“快速开始”，Development 保留源码构建说明 |
| 缺少 Docker / 二进制下载链接 | 部署门槛高 | 提供 `docker-compose.yml` 示例或一键安装脚本 |
| `AI 运维界面` 作为一级功能 | AI 被过度包装 | 改为 `可选的 LLM 辅助分析`，放在“可观测性/分析”子项中 |

#### 6.2.3 从 SafeLine 借鉴的优点

- **一句话卖点 + 表情符号标题**：降低阅读门槛。
- **工作原理图**：帮助用户快速理解反向代理接入方式。
- **核心能力表格/截图对比**：合法用户 vs 恶意用户，直观展示防护效果。
- **生产数据背书**：装机量、防护网站数、清洗请求数，增强可信度。
- **演示环境链接**：降低试用成本。

#### 6.2.4 避免南墙的缺点

南墙 README 存在以下问题，CheeseWAF 应避免：

- 过度营销腔：如 `"工业级免费、高性能、高扩展顶级 Web 应用和 API 安全防护产品"`、`"全方位"`、 `"率先实现"`、 `"伟大产品"`。这类形容词空洞，应改为具体指标。
- 过度包装 AI：如 `"智能的 0day 防御"`、 `"无需添加规则即可拦截攻击"`。CheeseWAF 应保持克制，避免把规则/阈值包装成 AI。
- 默认密码明文展示：南墙 README 直接写出默认用户名密码 `#Passw0rd`。CheeseWAF 已避免此问题，应继续保持。

#### 6.2.5 新增 README 内容建议

1. **架构图**：单二进制 admin + proxy 的部署示意图。
2. **系统要求**：CPU/内存/磁盘/Docker 版本。
3. **版本状态 badge**：`Beta` / `Pre-release`，明确项目阶段。
4. **Roadmap 链接**：指向 `docs/phase4-operations.md` 或 GitHub Projects。
5. **社区支持**：Discord/微信群/Discussions 链接。

---

## 7. 修复优先级总览

### 7.1 P0（立即修复）

| 编号 | 问题 | 位置 |
|------|------|------|
| S1 | API 认证绕过：未配置密钥时跳过签名验证 | `internal/apisec/auth.go` |
| B1 | 配置变更先 applyRuntime 再持久化，状态不一致 | `internal/api/handler/site.go:292-309` |
| B2 | Bot challenge secret 每次配置变更都重新生成 | `internal/config/runtime.go:25-38` |
| B3 | 配置保存后浅拷贝导致共享内存 | `internal/api/handler/site.go:310` |
| B4 | AI 自学习 `dry_run` 与 `auto_apply` 语义冲突 | `internal/api/handler/ai.go`、`internal/ai/self_learning.go` |
| S12 | 手写 HTML 净化器可被绕过，block page 预览存在 XSS | `web/src/pages/BlockPages/BlockPagesPage.tsx` |

### 7.2 P1（高优先级）

| 编号 | 问题 | 位置 |
|------|------|------|
| S2 | ACME `--reloadcmd` 命令注入 / RCE | `internal/acme/issuer.go` |
| S3 | 自定义拦截页 SSTI / 信息泄露 | `internal/blockpage/renderer.go` |
| S6 | AI 自动写规则缺少强制审批 | `internal/ai/self_learning.go` |
| S7 | 上游目标未做 SSRF 限制 | `internal/proxy/loadbalancer.go` |
| A1 | AI 助手占位符聊天机器人腔 | `web/src/i18n/locales/zh-CN.ts:1133` |
| A2 | 自动生成规则名夸大 AI 能力 | `internal/ai/self_learning.go:119-120` |
| A3 | 完整 payload/IP/UA 外发第三方 AI | `internal/ai/analyzer.go:832-851` |
| A11 | AI 工具审批可由发起者自批 | `internal/api/handler/ai_tools.go:76-91` |
| U2 | 骨架屏 reduced-motion 下仍闪烁 | `web/src/styles/global.css` |
| U4 | 3D 攻击地图在移动/省电模式未降级 | `web/src/pages/AttackMap/GlobeMap.tsx` |

### 7.3 P2（中优先级）

| 编号 | 问题 | 位置 |
|------|------|------|
| S4 | SHA-1 生成证书 SKID | `internal/setup/defaults.go:614-620` |
| S5 | 站点证书路径未限制 | `internal/api/handler/site.go` |
| S13-S19 | 前端 CSP、localStorage token、路由守卫、OTA 公钥等 | `web/src/` |
| B5-B10 | 调度器、Host 路由、健康检查、token 刷新等 | `internal/`、`web/src/` |
| U7-U10 | `ai-page.css` 可维护性、验证码硬编码色、攻击地图霓虹色 | `web/src/styles/` |
| A4-A10 | AI 黑话、中英混杂、内部文档黑话密度 | 全仓库 |
| README | 结构重构、增加卖点/截图/安装命令 | `README.md`、`README_CN.md` |

### 7.4 P3（低优先级）

| 编号 | 问题 | 位置 |
|------|------|------|
| S8-S11 | Bot Secret 存储、缓存键污染、ClickHouse database 校验、资源回收权限 | `internal/` |
| B21-B25 | 视图校验、热重载、ACL 校验、会话刷新、任务回滚 | `internal/`、`web/src/` |
| U16-U22 | 面板布局、动画、营销感等 | `web/src/` |
| A14-A17 | 空状态标题、乱码字符、知识库透明度 | `web/src/`、`internal/` |

---

## 附录：竞品 README 参考来源

- [雷池 SafeLine README_CN.md](https://raw.githubusercontent.com/chaitin/SafeLine/main/README_CN.md)
- [南墙 uuWAF README_CN.md](https://raw.githubusercontent.com/Safe3/uuWAF/main/README_CN.md)

---

*报告生成方式：只读静态审查，多子代理并行检查；所有文件路径与行号均来自代码仓库当前状态。*
