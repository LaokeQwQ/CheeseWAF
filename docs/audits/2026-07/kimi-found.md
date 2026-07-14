# CheeseWAF 前端 UI 审查发现（布局 / 动画 / 排版 / 主题）

> 静态代码审计结果，引用行号来自 `web/src/styles/global.css` 与 `web/src/themes/*.css` 当前版本。

---

## 总体数据

| 指标 | 数值 |
|---|---|
| `global.css` 总行数 | 17,358 行 |
| `!important` 数量 | 1,134 个 |
| `@media` 数量 | 80 处 |
| `prefers-reduced-motion` 块 | 3 处 |

---

## 高影响

### 1. CSS 变量被使用但从未定义

以下变量在 `global.css` 中被大量使用，但四个主题文件均未定义：

- `--accent-success`：`3563-3564`, `4495-4496`, `7750`, `8056-8063`, `8142-8143`, `8377`, `8495-8497`, `13378-13379`
- `--text-strong`：`8764`, `8788`, `8801`, `8852`, `8937`, `9057`, `9148`, `9173`, `9212`, `9244`
- `--text-subtle`：`16496`
- `--text-primary`：`16837`
- `--text-secondary`：`17147`

### 2. 同一选择器被多次覆写

- `.page-header`：定义于 `1108`、`11247`、`12214`、`12862` 等位置
- `.page-header h1`：定义于 `1117`、`11251`、`12220`、`12872`
- `.page-header p`：定义于 `1126`、`12227`、`12877`
- `.metric-card svg`：`1256` 设为 `display: none;`，`12953` 又设 `width/height`
- `.dashboard-grid`：`1299`、`12958`、`15041`、`15217`
- `.settings-grid`：`1293`、`1303`、`3953`、`9848`
- `.policy-level-grid`：`5048`、`9476`、`9848`

### 3. 响应式断点互相覆盖

多个网格布局在不同断点被反复改写，导致中间宽度行为不可预测：

- `.site-wizard-grid`：桌面 `2732` 两列 → 移动端 `9848` 一列
- `.protection-form-grid`：两列 `5220` → 三列 `5301` → 一列 `9848`
- `.policy-level-grid`：`repeat(2, minmax(360px, 1fr))` → `repeat(2, minmax(0, 1fr))` → `1fr`

---

## 中影响

### 4. 硬编码颜色破坏暗色/主题

- AI 工具状态标签：`9096-9131`
- AI 错误结果代码块：`9183-9187`
- AI 审批卡片边框：`9189-9195`
- 防护等级选中按钮：`5165-5175`
- 验证码预览舞台：`14376-14386`

### 5. 布局隐患

- `.policy-level-card p` 固定 `min-height: 40px`（`5092`）
- `.protection-level-picker` 5 等分列（`5106`）在窄屏下易截断
- `.endpoint-policy-head` 三列布局（`5750`）在小宽度下可能贴边
- `.site-wizard-grid` 最小宽度合计 540px，在 1024-1180px 区间可能过窄

### 6. 动画可访问性策略零散

- `prefers-reduced-motion: reduce` 仅 3 处：`8218`（仅验证码）、`11997`（全局 `!important`）、`12008`（仅 AI）
- `.status-breathe`、`.map-marker-pulse` 等依赖全局粗暴覆盖

### 7. z-index 缺乏统一尺度

| 元素 | 行号 | z-index |
|---|---|---|
| `.notification-panel` | `701` | 1200 |
| 验证码 modal | `7771/7781/7785/7821/7826` | 1001-1002 |
| `.ai-assistant-panel` | `8622` | 70 |
| `.ai-fab` | `8525` | 22 |
| 移动端侧边栏/蒙层 | `9492/9531` | 26/25 |

---

## 低影响

### 8. 排版细节

- `code { display: inline-block; vertical-align: bottom; }`（`2133`）导致基线错位
- `.page-header h1` 的 `letter-spacing`/`font-size`/`line-height` 多处不一致
- 多处固定 `min-height` / `px` 尺寸可能造成小视口留白

### 9. 可维护性

- `global.css` 单文件 17k+ 行，按组件/页面混排
- 大量 `color-mix(in srgb, #ffffff, ...)` / `#000000` 写死
- 主题变量命名不统一：`--text` / `--text-main` / `--color-text-1` / `--text-muted`

---

## 建议修复顺序

1. 补齐未定义 CSS 变量
2. 清理 `.metric-card svg` 等自相矛盾的选择器
3. 收敛 `.page-header` 重复定义
4. 用主题变量替换关键硬编码颜色
5. 统一 `z-index` 尺度
6. 规范化 `prefers-reduced-motion` 处理
7. 长期拆分 `global.css`


---

## 追加分析（2026-07-09）

基于当前 `web/src/styles/global.css`（18,548 行，1,138 个 `!important`，83 处 `@media`/`prefers-reduced-motion`）与相关页面组件的二次审计。

### 1. 布局系统选择器仍被多处覆写

核心布局类在 `global.css` 中出现多次，后出现的规则会覆盖前面的规则，导致同一组件在不同位置被反复调整：

| 选择器 | 出现位置（行号） | 影响 |
|---|---|---|
| `.workspace` | 1049, 9488, 9643, 10000, 12213, 12838, 16043, 16212 | padding、宽度、背景被多次改写，移动端安全区处理在 12684 行才最终确定 |
| `.page-surface` | 1058, 10046, 11262, 12038, 12207, 12217, 12688, 12842 | 最大宽度在 1420px / 1360px 之间反复切换，gap 在 24px / 18px / 16px / 14px 之间变化 |
| `.page-header` | 1108, 11247, 12214, 12862, 16051, 16221 等 | 标题字号、对齐、间距不一致 |
| `.metric-grid` | 1204, 9919, 10163, 12366, 12639, 13973 | 列数在 auto-fit / 1fr / 单列之间多次切换 |
| `.dashboard-grid` | 1269, 9864, 10163, 12091, 12193, 12643, 12708, 13988, 14215, 14884 | 桌面端列数定义分散，响应式行为不可预测 |
| `.topbar-left` / `.topbar-right` / `.topbar-actions` | 多至 7-8 处 | 搜索框、操作区在不同断点被反复重排 |

### 2. AI 页面 CSS 碎片化最严重

AI 页面的子选择器被重复定义次数遥遥领先，说明该页面的样式是以“补丁”形式逐步追加的，维护风险最高：

- `.ai-page .ai-config-form`：25 处定义
- `.ai-page .ai-config-panel`：20 处定义
- `.ai-page .ai-detail-grid`：14 处定义
- `.ai-page .ai-config-summary`：13 处定义
- `.ai-page .ai-events-list-row`：12 处定义

这些选择器在 11300-18300 行之间反复出现，极容易出现“改一处、破另一处”的问题。

### 3. 登录页 `auth-panel` 样式职责混杂

`.auth-panel` 同时出现在两处：

- 第 1213 行：与 `.metric-card`、`.panel`、`.table-panel` 一起被定义为通用面板（背景、边框、圆角）。
- 第 7641 行：被定义为登录专用面板（宽度、padding、backdrop-filter）。

实际登录页组件使用了该 class，因此它同时受通用面板和登录面板两套规则影响。后一条规则会覆盖前者，但通用面板规则的维护者很容易在不知情时破坏登录页外观。

### 4. 仍有一个未定义 CSS 变量

`var(--mono-font)` 在 `global.css:5776` 被使用，但 `global.css` 与四个主题文件中均未定义 `--mono-font`。当前会回退到浏览器默认等宽字体，渲染结果不一致。

### 5. 响应式断点交叉覆盖

- `.workspace` 在 1049 行定义 `padding: 28px clamp(24px, 3vw, 48px) 112px`，在 12214 行又被改为 `padding-inline: clamp(24px, 3vw, 44px)`，在 12684 行再次加入 `env(safe-area-inset-bottom)`。
- `.page-surface` 在 1058 行定义 `width: min(100%, 1420px)`，在 12218 行被改为 `width: min(100%, 1360px)`，在 12688 行又被改为 `width: 100%`。
- 断点 1024px、860px、640px、520px、480px 之间的规则互相嵌套，部分页面在 860px-1024px 区间没有得到明确处理。

### 6. 硬编码尺寸与布局截断风险

- `AIPage.tsx:449`：`style={{ width: 132 }}` 硬编码时间范围选择器宽度，在小屏或长翻译文本下可能截断。
- `global.css:5092` `.policy-level-card p` 仍固定 `min-height: 40px`。
- `global.css:5106` `.protection-level-picker` 5 等分列在窄屏下仍可能溢出。
- 多个页面在 `@media (max-width: 640px)` 下使用 `display: none !important` 隐藏桌面表格，切换到移动卡片，但 640px-860px 之间的平板视图处理不足。

### 7. z-index 已部分统一，但尺度间隙偏小

`global.css:5-18` 现在集中定义了 z-index 变量：

```css
--z-base: 1;
--z-dropdown: 10;
--z-sticky: 20;
--z-ai-fab: 22;
--z-mobile-nav-backdrop: 25;
--z-mobile-nav: 26;
--z-ai-panel: 70;
--z-modal: 100;
--z-modal-backdrop: 99;
--z-captcha-modal: 102;
--z-captcha-modal-backdrop: 101;
--z-notification: 200;
```

已比之前清晰，但 `--z-ai-panel: 70` 与 `--z-modal: 100` 之间只有 30 的间隙，未来若插入新层级容易冲突；验证码 modal（102）紧挨普通 modal（100），也没有留出扩展空间。

### 8. 可访问性动画仍不完善

`prefers-reduced-motion` 在全局只有 3 处左右，且 `global.css:11997` 使用 `!important` 粗暴覆盖所有 transition/animation。新的 `.status-breathe`、地图 marker pulse、登录滑块动画等尚未全部被 reduced-motion 保护。

### 9. 构建状态

当前 `npm run build` 可通过，`tsc -b` 无报错。但 `AIPage.tsx:591` 调用的 `displayRisk` 直到第 997 行才定义，虽然函数提升在 TypeScript 中合法，但跨这么远的距离使用局部函数增加了阅读和维护成本，建议将其提取到 `utils/display.ts` 与 `riskColor` 一起复用（`LogDetailPage.tsx` 已经单独实现了一份）。

### 10. 建议修复优先级

1. 将 `.ai-page` 相关样式按模块拆出到独立 CSS 文件（如 `pages/AI/ai-page.css`），大幅减少 `global.css` 中同一选择器的重复定义。
2. 统一 `.workspace`、`.page-surface`、`.page-header` 的定义，只保留一处基础规则 + 必要的媒体查询覆盖。
3. 把 `.auth-panel` 从通用面板分组中移出，或重命名为 `.login-panel`，避免职责混杂。
4. 补齐 `--mono-font` 变量（建议与 `--font-mono` 对齐或统一命名）。
5. 收紧响应式断点：1024px、860px、640px、520px 的处理应互不重叠，明确每个区间的布局策略。
6. 将 `displayRisk` / `riskColor` 提取到公共 utils，避免 `AIPage.tsx` 与 `LogDetailPage.tsx` 重复实现。


---

## 追加分析二：AI 黑话 / 文案 / 用词问题（2026-07-09）

通过子代理对 `web/src/i18n/locales/zh-CN.ts`、`en-US.ts` 及核心页面组件进行专项扫描后的结果。

### 1. AI 味 / 黑话文案（中文 locale 重灾区）

| 键名 | 当前中文 | 问题 | 建议 |
|---|---|---|---|
| `navGroup.posture` | 态势 | 安全/军事报告黑话，普通用户不常用 | 概览 / 总览 |
| `dashboard.title` | 总览态势 | 堆砌“态势”，像 PPT/AI 生成 | 总览 |
| `dashboard.totals` | 总计态势 | 抽象空洞 | 流量统计 |
| `dashboard.realtime` | 实时态势 | 同上 | 实时监控 |
| `ai.subtitle` | LLM 连接、攻击日志分析和建议动作 | “LLM”+“建议动作”像 AI 产品宣传语 | AI 连接、攻击日志分析与建议 |
| `ai.reasoningModel` | 推理大模型 | 典型 AI 黑话 | 推理模型 |
| `ai.reasoningModelHint` | 用于深度思考、自学习规则复核… | “深度思考”“自学习”“复核”堆叠 | 用于复杂分析、自学习规则审核和高风险事件研判 |
| `ai.selfLearning` | 自学习规则 | 对普通用户偏抽象 | 自动规则学习 |
| `ai.selfLearningHint` | 定时读取拦截/挑战/检测事件，经推理模型和本地护栏复核后… | “推理模型”“护栏”“复核”AI 味重 | 定时分析拦截、挑战和检测事件，由推理模型和本地安全策略审核后生成规则 |
| `ai.actions` | 处置建议 | “处置”偏运维/安全报告用语 | 建议动作 / 处理建议 |
| `ai.reasoningSummary` | 模型思考摘要 | “思考摘要”抽象，且暗示模型像人一样“思考” | 推理摘要 |
| `ai.liveReasoning` | 实时思考 | 同上 | 实时推理 |
| `ai.streamConnected` | 流式分析连接已建立 | “流式分析”偏技术黑话 | 分析连接已建立 |
| `assistant.deepThink` | 深度思考 | 典型 AI 营销术语 | 深度推理 |
| `assistant.quickToday` | 帮我分析今天的安全态势 | “安全态势”黑话 | 帮我分析今天的安全情况 |
| `assistant.reasoningSummary` | 模型思考摘要：{{summary}} | 同 `ai.reasoningSummary` | 推理摘要：{{summary}} |
| `assistant.reasoningLive` | 模型正在返回可展示思考摘要 | 啰嗦、AI 味 | 正在返回可展示的推理摘要 |
| `assistant.reasoningStreaming` | 模型正在返回可展示的思考摘要 | 同上 | 正在生成推理摘要 |

### 2. 中英文混杂

| 键名/位置 | 当前文案 | 问题 | 建议 |
|---|---|---|---|
| `ai.subtitle` | LLM 连接… | 中文界面突兀出现 LLM | AI 大模型连接… |
| `ai.apiKey` | API Key | 未本地化 | API 密钥 |
| `ai.outputTokens` / `assistant.outputTokens` | 输出 {{value}} tokens | tokens 未译 | 输出 {{value}} 个 token |
| `ai.totalTokens` | 总计 {{value}} tokens | 同上 | 共 {{value}} 个 token |
| `ai.reasoningUnavailable` | 当前 AI provider 未返回… | “AI provider”整段英文混入 | 当前 AI 服务商未返回… |
| `assistant.processLocal` | AI provider 未参与… | 英文混入 | 未调用 AI 服务商… |
| `assistant.reasoningUnavailable` | 当前 AI provider 未返回… | 同上 | 当前 AI 服务商未返回… |
| `assistant.reasoningLocal` | AI provider 未参与… | 同上 | 未调用 AI 服务商… |
| `system.requiredScopes` | 必需 Scope | 中文中夹 scope | 必需权限范围 |
| `system.jwtAuthHint` | …签发方和 scope 校验 | scope 未译 | …签发方和权限范围校验 |
| `system.jwtVerificationKeysHint` | HMAC Secret、PEM 公钥、本地 JWKS… | 大写英文未解释 | HMAC 共享密钥、PEM 公钥、本地 JWKS 文件或远端 JWKS 地址 |
| `system.jwtSharedSecret` | HMAC Secret | 未本地化 | HMAC 共享密钥 |
| `protection.captchaTypePow` | PoW / Altcha | 对普通用户难懂 | 工作量证明 / Altcha |
| `sites.trustedCidrs` | 可信 CIDR | CIDR 对非网络用户不友好 | 可信 CIDR 网段 |
| `ip.providerTypeSTIX` | STIX/TAXII | 未解释 | STIX/TAXII 威胁情报协议 |

### 3. 硬编码文案（未走 i18n）

| 位置 | 当前文案 | 影响 | 建议 |
|---|---|---|---|
| `AIPage.tsx:466` | `<span>URI</span>` 列表表头 | 中 | 使用 `t('logs.path')` 或新增 `ai.eventUri` |
| `LogDetailPage.tsx:86` | `<DetailKV label="URI" ...>` | 中 | 使用 `t('logs.path')` |
| `MainLayout.tsx:884, 897` | `'版本信息不可用'` fallback | 中 | 使用 `t('shell.versionUnavailable')` |
| `ClusterPage.tsx:1754` | 硬编码中文替换 `['回','滚']` → `'恢复尝试'` | 中 | 移到 locale 或让后端统一术语 |

### 4. 翻译不一致

| 中文键/文案 | 英文键/文案 | 问题 | 建议 |
|---|---|---|---|
| `ai.provider` = 服务商 | `ai.provider` = Provider | 同一词在 AI 模块与情报源模块译法不同 | AI 模块统一为“AI 服务商”，英文统一为 “AI Provider” |
| `ai.apiBase` = API 地址 | `ai.apiBase` = API Base | 英文未完整表达 | 英文改为 “API Base URL” |
| `dashboard.title` = 总览态势 | `dashboard.title` = Posture Overview | 二者都使用 posture/态势 | 中文“总览”，英文“Overview” |
| `assistant.processTitle` = 思考摘要 | `assistant.processTitle` = Reasoning Summary | 中文“思考” vs 英文 Reasoning | 统一为“推理摘要”/“Reasoning Summary” |
| `assistant.deepThink` = 深度思考 | `assistant.deepThink` = Deep Think | 二者均为 AI 黑话 | 中文“深度推理”，英文“Deep Reasoning” |
| `system.managementAPI` = 控制台 API 令牌 | `system.managementAPI` = Console API Tokens | 单复数/用词不一致 | 统一单复数，英文改为 “Management API Tokens” |
| `system.apiTokenScopes` = 权限范围 | `system.apiTokenScopes` = Scopes | 英文过短 | 英文改为 “Permission Scopes” |
| `ai.selfLearningDryRun` = 仅试运行 | `ai.selfLearningDryRun` = Dry Run Only | 语序不同 | 中文可改为“仅模拟运行” |

### 5. 标点 / 语气问题

| 键名 | 当前中文 | 问题 | 建议 |
|---|---|---|---|
| `assistant.placeholder` | 查安全、找漏洞、写规则，这些我都会~ | 波浪号，卖萌 | 查安全、找漏洞、写规则，我都可以帮你 |
| `assistant.emptyTitle` | Hi👋 今天想问点什么? | emoji + 中英文混杂 | 今天想问我什么？ |
| `assistant.emptyHint` | 我会基于 WAF 事件、监控快照和可审批工具回答，不会编造运行结果 | 像 AI 免责声明 | 基于 WAF 事件、监控快照和需要审批的工具作答，不臆造结果 |
| `ai.providerSlow` | AI 服务商暂未开始返回，连接会继续保持 | 生硬、像机翻 | AI 服务商尚未开始响应，连接保持中 |
| `assistant.providerSlow` | AI 服务商 10 秒内没有开始返回，将继续保持连接 | 同上 | AI 服务商 10 秒内未开始响应，连接保持中 |

### 6. 术语对普通用户不友好（首次出现未解释）

- `system.dsn`：建议说明 DSN（Data Source Name）含义
- `system.jwtVerificationKeysHint` / `jwtSharedSecret` / `jwksFile`：HMAC / JWKS 首次出现应解释
- `protection.captchaTypePow`：PoW / Altcha 应加括号说明
- `sites.trustedCidrs`：CIDR 应说明是“网段”
- `ip.providerTypeSTIX`：STIX/TAXII 应说明是威胁情报协议
- `system.requiredScopes`：Scope 应说明是“权限范围”

### 7. 建议修复顺序

1. 重写 `ai` 与 `assistant` 命名空间中文键，清除“态势”“深度思考”“推理大模型”“自学习”“处置建议”“模型思考摘要”等黑话。
2. 清除 `ai.*` / `assistant.*` 中的英文混入（LLM、provider、tokens、AI provider）。
3. 统一中英文术语对照表（provider、token、scope、self-learning、reasoning 等）。
4. 为首次出现的专业术语增加 hint/tooltip 解释（JWT/JWKS/HMAC、PoW/Altcha、CIDR、STIX/TAXII、DSN）。
5. 将 `AIPage.tsx:466`、`LogDetailPage.tsx:86` 等硬编码文案纳入 i18n。
6. 清理 `assistant.placeholder`、`assistant.emptyTitle` 的 emoji 和波浪号。


---

## 追加分析三：UI / 配色 / 主题问题（2026-07-09）

### 1. 硬编码颜色未随主题变化

`global.css` 中仍存在大量未使用 CSS 变量的硬编码颜色，切换 `light` / `dark` / `black-gold` / `blue-white` 主题时不会跟随变化：

| 颜色 | 出现次数 | 典型位置 | 问题 |
|---|---|---|---|
| `#ffffff` | 82 | 多处高光、内阴影、渐变、背景 | 暗色主题下出现不应有的白色高光或白色背景 |
| `#000000` | 15 | 阴影、遮罩 | 暗色主题下黑色阴影过重 |
| `#0f2740` | 10 | 卡片阴影 color-mix | 深蓝阴影在 black-gold / blue-white 主题下不协调 |
| `#07111d`, `#0a1725`, `#050b14` | 各 2-3 | 3D 地图暗色背景 | black-gold 主题下出现突兀蓝色 |
| `#071015` | 1 | 登录页 media 背景 | 登录背景固定深色，不随主题变化 |
| `#f97316` | 7 | 风险等级高亮 | 与 `var(--accent-warning)` 不一致 |
| `#28f1d3`, `#24cfff`, `#ff7256` 等 | 多处 | 攻击大屏霓虹色 | 大屏风格固定，但 `attack-screen-light` 与 dark 主题两套样式并行维护 |

具体问题位置：

- `global.css:6437-6444`：`dark` / `black-gold` 主题下 `.map-canvas.map-mode-3d` 背景使用硬编码深蓝渐变 `#07111d → #0a1725 → #050b14`，在 `black-gold` 主题下极不协调。
- `global.css:7602-7630`：登录页背景 media 固定 `#071015`，遮罩固定 `rgba(5,12,18,…)`，登录页始终呈现暗色，与 light / blue-white 主题割裂。
- `global.css:12482-12485`：`.block-preview-frame` 使用 `#ffffff 58%` 渐变背景，暗色主题下预览框是一块白色。
- `global.css:17147-17149`：`.block-preview-frame iframe` 强制 `background: #ffffff !important`，暗色主题下 iframe 白底刺眼。
- `global.css:4207`：2FA QR 码容器 `background: #fff`，暗色主题下 QR 白底正常但可用更优雅的方式处理。
- `global.css:181`：`.brand-mark` 使用白色渐变高光，在 `black-gold` 主题下金色/深色 Logo 背景上出现白渐变可能不协调。

### 2. color-mix 滥用 #ffffff / #000000

大量 `color-mix(in srgb, ..., #ffffff)` 或 `#000000` 用于内阴影、高光、边框。这些在暗色主题下应该对应 `--text` 或 `--surface` 的变体，而不是固定白/黑：

- `global.css:726` `box-shadow: 0 1px 0 color-mix(in srgb, #ffffff 64%, transparent) inset`
- `global.css:1427` `box-shadow: 0 1px 0 color-mix(in srgb, #ffffff 72%, transparent) inset`
- `global.css:613` `box-shadow: 0 22px 70px color-mix(in srgb, #000 18%, transparent)`
- `global.css:6555` `box-shadow: 0 12px 28px color-mix(in srgb, #000000 24%, transparent)`
- `global.css:9523` 移动端侧边栏阴影使用 `#000000 22%`

### 3. 主题切换逻辑的限制

`web/src/themes/index.ts` 只切换了 `:root` 的 `data-theme`、`color-scheme`、`arco-theme` 和 `theme-color` meta。Three.js Canvas、SVG 地图、攻击大屏等渲染路径没有监听主题变化并重新取色，导致：

- 3D 地球仪颜色全部硬编码，主题切换不生效。
- 攻击大屏 `AttackScreenPage.tsx:20` 仅将 `dark/blackGold` 映射为 dark，其余都视为 light，不支持系统主题或未来新增主题。
- `global.css:14201-14202` 通过 `:root:not([data-theme='dark']):not([data-theme='black-gold'])` 回退到 light 样式，逻辑分散且难以维护。

### 4. 阴影颜色单一化

几乎所有卡片阴影都基于 `#0f2740` 或 `#000000` 做 color-mix，没有区分亮/暗主题：

- 亮色主题下阴影应偏冷灰/中性色。
- 暗色主题下阴影应偏深且更透明，避免 `#0f2740` 在暖色主题（black-gold）中发蓝。

### 5. 未定义 CSS 变量

`--mono-font` 在 `global.css:5776` 被使用但从未定义，应补充或统一为 `--font-mono`。

### 6. 建议修复顺序

1. 为暗色/亮色主题分别定义 `--shadow-color`、`--highlight-color`、`--map-canvas-3d-bg` 等变量。
2. 将 `#0f2740`、3D 地图深蓝渐变、登录页深色背景改为变量或按主题分别定义。
3. 将 `block-preview-frame iframe` 的 `#ffffff !important` 改为跟随主题，或提供“预览背景色”设置。
4. 让 `GlobeMap` 通过 `getComputedStyle` 读取 CSS 变量并更新 Three.js 材质颜色。
5. 补齐 `--mono-font` 变量定义。

---

## 追加分析四：攻击地图专项问题（2026-07-09）

### 1. 布局问题

| 问题 | 位置 | 影响 | 建议 |
|---|---|---|---|
| 地图容器高度使用 `clamp(500px, 50vw, 690px)`，超宽屏可能超过视口 | `global.css:6072` | 中 | 改用基于视口剩余高度的计算 |
| 攻击大屏左右浮层面板在中等宽度（860-1024px）可能侵入地球仪 | `global.css:15720-15742` | 中 | 提前切换为上下堆叠或提供收起按钮 |
| 攻击大屏地球仪 `min-height: calc(100dvh - 90px)` 叠加 topbar 后可能溢出 | `global.css:15710-15714` | 中 | 使用 `height: calc(100dvh - 56px)` |
| 2D/中国模式拖拽边界 `clampPan` 使用固定像素 420/260，未按容器尺寸动态计算 | `AttackMapPage.tsx:1300-1307` | 中 | 根据 `clientWidth/Height` 和 zoom 动态计算 |
| `map-workbench-header` 三列最小宽度之和约 800px，1180-1280px 容器可能触发横向滚动 | `global.css:15582` | 中 | 前移断点或压缩列最小宽度 |
| Marker 标签 `max-width: min(240px, 34vw)` 在超宽屏可能超出地图容器 | `global.css:6615` | 低 | 改为相对于容器宽度或 popper 定位 |
| 移动端攻击大屏将浮层变为 static，地球仪被推到下方 | `global.css:11196-11207` | 低 | 给浮层增加可折叠标题 |

### 2. 性能问题（高优先级）

| 问题 | 位置 | 影响 | 建议 |
|---|---|---|---|
| 每 5 秒重新 fetch 并全量执行 `aggregateRegions`，生成新数组引用导致下游 `useMemo` 失效 | `AttackMapPage.tsx:237-239` | 高 | 服务端聚合或增量更新，稳定引用 |
| 攻击大屏每 3 秒 refetch，`visibleEntries` 重新生成导致 `aggregateRegions`、`buildCountryLevelMap` 全部重算 | `AttackScreenPage.tsx:23-52` | 高 | 稳定引用或降低刷新频率 |
| `GlobeMap` 依赖 `regionsSignature`/`countryLevelsSignature`，数据变化时销毁并重建整个 Three.js 场景 | `GlobeMap.tsx:78-529` | 高 | 将场景创建与数据更新分离，只更新 marker/arc/颜色 |
| `createWorldTexture` 每次重建都绘制 1536×768 贴图，遍历 worldFeatures 两次 | `GlobeMap.tsx:656-746` | 高 | 离线预生成或缓存底图，数据变化时只重绘 overlay |
| `createCloudTexture` 每次重建生成 768×384 云层贴图 | `GlobeMap.tsx:748-782` | 中 | clouds 与数据无关，应一次性创建并复用 |
| `createGridSphere` 每次重建生成 3329 个顶点的线条 | `GlobeMap.tsx:565-596` | 中 | 网格静态，应复用；可降级低分段数 |
| Raycaster 34ms 节流对大量 markerMeshes 做相交检测 | `GlobeMap.tsx:390-426` | 中 | 使用 BVH/八叉树，仅检测可见半球 marker，节流到 80-100ms |
| `requestAnimationFrame` 页面隐藏时仍持续调度 | `GlobeMap.tsx:465-500` | 低 | hidden/reducedMotion 时取消 rAF |

### 3. 主题 / 配色问题

| 问题 | 位置 | 影响 | 建议 |
|---|---|---|---|
| `GlobeMap.tsx` 中风险等级、海洋、大气、光照、云层等大量硬编码十六进制颜色 | `GlobeMap.tsx` 多处 | 高 | 抽取到主题 token 或用 `getComputedStyle` 读 CSS 变量 |
| `map-risk-high` 使用硬编码 `#f97316`，与 `--accent-warning` 不一致 | `global.css:6575` | 中 | 统一使用主题变量 |
| 攻击大屏默认深色写死 `#c8f7ff`、`#06101e`、`#28f1d3` 等赛博色；`.attack-screen-light` 虽变量化但两套并行 | `global.css:6808-7569` | 中 | 深色版也迁移到 CSS 变量 |
| 3D 地图背景逻辑分散：dark/black-gold 特殊处理，其余 `:root:not(...)` 回退 | `global.css:14201-14202` | 低 | 为所有主题定义 `--map-canvas-3d-bg` |
| 中国区域边界可能同时显示 province/city/district 三层轮廓，颜色叠加混乱 | `chinaBoundaries.ts:183-196` | 中 | 明确边界层级优先级 |

### 4. 可访问性问题

| 问题 | 位置 | 影响 | 建议 |
|---|---|---|---|
| `GlobeMap` canvas 没有 `role`、`aria-label` 或键盘操作说明 | `GlobeMap.tsx:535` | 高 | 添加 `role="img"` 和 `aria-label` |
| `WorldMapSVG` / `ChinaAdministrativeMapSVG` 设置 `aria-hidden="true"` | `AttackMapPage.tsx:642, 660` | 高 | 为 SVG 添加 `role="img"` 和 `aria-label` |
| Globe tooltip 是动态创建的 div，未关联 aria-live | `GlobeMap.tsx:141-143, 420-425` | 中 | 使用 `aria-live="polite"` 容器 |
| `map-marker` 有 `role="button"` 但没有 `aria-pressed` 表示选中 | `AttackMapPage.tsx:457-478` | 中 | 根据选中状态设置 `aria-pressed` |
| Marker 同时渲染 `title` 属性和样式化 label，双重提示 | `AttackMapPage.tsx:466, 506` | 低 | 移除 title，依赖可聚焦 label |
| 攻击大屏导航展开/折叠没有 `aria-expanded`，激活页没有 `aria-current` | `AttackScreenPage.tsx:60-83` | 中 | 补充 ARIA 属性 |
| 时间轴 `<input type="range">` 缺少 `aria-label` | `AttackScreenPage.tsx:143` | 低 | 添加 `aria-label` |
| `reducedMotion` 只降低动画速度，未停止自动旋转和脉冲 | `GlobeMap.tsx:455-497` | 中 | reducedMotion 时完全停止动画 |
| `.map-marker i::after` pulse 动画无 reduced-motion 媒体查询 | `global.css:6658-6664` | 中 | 添加 `@media (prefers-reduced-motion: reduce)` |

### 5. 代码质量问题

| 问题 | 位置 | 影响 | 建议 |
|---|---|---|---|
| 攻击地图 CSS 高度分散，`.map-canvas`、`.attack-screen` 等多处重复定义；深色/浅色两套规则超过 700 行 | `global.css` 多处 | 高 | 抽到独立 `attack-map.css`、`attack-screen.css` |
| `AttackMapPage.tsx` 单文件超过 1300 行 | `AttackMapPage.tsx` | 中 | 拆分为聚合、格式化、SVG、Marker 等模块 |
| `countryCoordinates` 仅含 50 个国家，未知国家 fallback 到 UNLOCATED | `AttackMapPage.tsx:99-161` | 中 | 引入完整国家中心点数据集 |
| `inferCountryFromIP` 仅通过 IPv4 A 段推断，误报率高 | `AttackMapPage.tsx:978-997` | 中 | 信任后端 GeoIP，删除前端推断 |
| `GlobeMap.tsx` 大量使用 `any`（renderer、markerMeshes、material 等） | `GlobeMap.tsx` 多处 | 中 | 使用 Three.js 具体类型 |
| `chinaBoundaries.ts` 的 `boundaryAdcodesFromRegions` 最多 12 个 adcode，超出静默丢弃 | `chinaBoundaries.ts:268-288` | 中 | 增加提示或聚合/降级 |

### 6. UI/UX 问题

| 问题 | 位置 | 影响 | 建议 |
|---|---|---|---|
| 选中 region 后下方表格未同步高亮当前行 | `AttackMapPage.tsx:289, 538-568` | 中 | 同步 `selectedRegionKey` 到 Table `rowClassName` |
| Detailed labels 只在 zoom ≥ 1.25 且选中/第一个 region 显示 | `AttackMapPage.tsx:287-289, 461-484` | 中 | 显示前 N 高风险 marker 简要 label |
| 3D 地球仪没有“重置视角”按钮 | `GlobeMap.tsx` | 低 | 暴露 reset 按钮或双击还原 |
| 中国模式没有独立 loading 态 | `AttackMapPage.tsx:388-396, 447-451` | 低 | map-canvas 中央显示 spinner overlay |
| 攻击大屏时间轴拖动时不会暂停数据刷新 | `AttackScreenPage.tsx:142-149` | 中 | slider 拖动时暂停 refetch |
| Marker tooltip 信息密度过高 | `AttackMapPage.tsx:1137-1139` | 低 | 拆分为多行小标签 |
| 空状态区分不清晰：2D/中国/3D 模式共用或缺失专门空状态 | `AttackMapPage.tsx:530-534` | 低 | 区分 loading、no-data、filter-empty |

---

## 本轮处理状态（2026-07-09，Codex）

### 已复核并处理

- 未定义 CSS 变量：当前 `--mono-font`、`--accent-success`、`--text-*`、`--shadow-color`、`--highlight-color`、`--map-canvas-3d-bg` 已在全局或主题变量中存在。
- 登录面板职责混杂：当前 `.auth-panel` 未再和通用 `.panel` / `.metric-card` 同组定义。
- AI / 助手中文文案：已清理“态势”“深度思考”“推理大模型”“模型思考摘要”“处置建议”“AI provider”“仅试运行”等用户侧表达；改为“总览 / 深度推理 / 推理模型 / 推理摘要 / 处理建议 / AI 服务 / 仅模拟运行”等。
- 监控指标：监控页不再把 Go 协程作为主指标展示，优先使用 `process_count` 显示“服务进程”；仪表盘资源运行状态保留“服务进程 / 服务内存”。
- 主按钮对比：全局主按钮、页面主按钮和 AI 页事件按钮已改用 `--accent-contrast`，避免黑金主题金色按钮白字对比不足。
- 主题一致性：dark 主题 `--color-primary-6` 已对齐 `--accent`；攻击地图高风险色改用 `--accent-warning`；局部高光 / 阴影 / 等宽字体继续迁移到主题变量。
- 验证码状态：invalid 与 error 图标颜色拆分为 warning / danger；验证码处理中图标加入 reduced-motion 明确禁用。
- 攻击地图：2D / 中国拖拽边界、标签密度、marker 与表格选中同步、攻击大屏中宽度布局已在前序批次处理并通过截图回归。

### 本轮验证

- `npm.cmd --prefix web run typecheck -- --pretty false`
- `npm.cmd --prefix web run build`
- `git diff --check`
- `node tmp\dashboard-ui-regression.cjs`
- `node tmp\check-ai-page-ui.cjs`
- `node tmp\local-map-ai-block-check.cjs`

### 仍需后续专项

- Arco 全量 CSS 仍约 555KB，需要单独评估按组件样式导入，并做全页面截图回归。
- `global.css` 仍有历史重复覆盖和不少验证码 / 表单局部高光硬编码，需要继续分批收口。
- 仪表盘移动端仍偏竖向密集，资源运行状态可进一步重排。
- 攻击地图图例、marker label 和攻击大屏霓虹主题仍需视觉专项打磨。
- `GlobeMap` 仍需要更细粒度对象复用、主题 token 注入和低端设备性能采样。

## 本轮补充处理状态（2026-07-09，Codex）

### 已继续处理

- 仪表盘 hover 提示次级文字改为跟随主题的 75% 文本色；资源运行状态卡片加强底色和边界，移动端资源行 / 统计工具条加 620px 内布局兜底。
- AI 分析事件行补齐键盘选中能力，并在减少动画模式下禁用 hover 位移。
- 通知面板补齐 `dialog` / `tab` 语义，通知按钮关联面板；通知描述支持最多两行展示。
- 右下角 AI 助手按钮与面板补齐 `aria-expanded` / `aria-controls` / `dialog` 语义。
- 攻击地图普通空状态补 `role=status`，3D 地球 tooltip 补 `aria-live` / `aria-atomic`。
- 中国区域地图 marker 标签禁止拆字，并提高标签底色遮罩，减少底图地名穿透。

### 本轮验证

- `npm.cmd --prefix web run typecheck -- --pretty false`
- `npm.cmd --prefix web run build`
- `git diff --check`
- `node tmp\dashboard-ui-regression.cjs`
- `node tmp\check-ai-page-ui.cjs`
- `node tmp\local-map-ai-block-check.cjs`

### 继续保留为后续专项

- Arco CSS 大 chunk 仍约 555KB，暂不在本轮拆分。
- 仪表盘移动端工具条仍偏高，只保证不溢出和可操作，后续需要视觉重排。
- 攻击地图标签避让、攻击大屏视觉体系、Three.js 对象复用和 `global.css` 历史覆盖仍需继续分批处理。
