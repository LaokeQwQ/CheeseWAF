# Kimi 修复工作记录（CheeseWAF 前端 UI）

## 1. 补齐缺失的 CSS 变量 ✅

**完成时间**：进行中
**涉及文件**：
- `web/src/themes/light.css`
- `web/src/themes/dark.css`
- `web/src/themes/black-gold.css`
- `web/src/themes/blue-white.css`

**操作内容**：
在四个主题文件中都新增了以下变量定义，避免 `global.css` 中引用未定义变量导致颜色回退异常：
- `--text-strong: var(--text)`
- `--text-subtle: var(--text-muted)`
- `--text-primary: var(--text)`
- `--text-secondary: var(--text-muted)`
- `--accent-success`：light/blue-white 使用 `#16a34a`，dark/black-gold 使用 `#4ade80`

**说明**：这些变量原先在 `global.css` 中被大量使用（如 `--accent-success` 用于成功状态徽章、`--text-strong` 用于 AI 助手结果标题等），但任何主题文件和 `:root` 中都没有定义，浏览器会回退到初始值。

---

## 2. 修复 `.metric-card svg` 规则冲突 ✅

**涉及文件**：`web/src/styles/global.css`

**操作内容**：
- 删除了 `1256-1258` 行的 `.metric-card svg { display: none; }` 规则。
- 保留 `12953-12956` 行的 `width: 18px; height: 18px;` 尺寸规则。

**说明**：`.metric-card` 在 `12949` 行已声明为 `grid-template-columns: 22px minmax(0, 1fr)`，说明卡片设计本就包含图标列。`DashboardPage` 也实际渲染了 Lucide SVG 图标，原先 `display: none` 会导致图标列空白且布局意图自相矛盾。

---

## 3. 收敛 `.page-header` 重复定义 ✅

**涉及文件**：`web/src/styles/global.css`

**操作内容**：
- 删除了原先分散在 `11243-11250`、`12201-12218` 的 `.page-header` / `.page-header h1` / `.page-header p` 重复定义。
- 删除了 `1108-1140` 的基础 `.page-header` 定义块。
- 在文件后部（现 `12796` 附近）保留了唯一的全局 `.page-header` 规范，合并了：
  - `display: flex; align-items: flex-end; justify-content: space-between; gap: 16px; min-width: 0;`
  - `padding-bottom: 4px; margin-bottom: 2px;`
  - `.page-header h1` 统一为 `clamp(24px, 2vw, 28px)` / `font-weight: 760` / `line-height: 1.18` / `letter-spacing: 0`
  - `.page-header p` 统一为 `max-width: 68ch` / `line-height: 1.55`
  - 保留 `.page-header .table-identity` 的 `flex: 0 0 auto` 与 `.attack-map-toolbar` 的 `align-self: center`

**说明**：去除了同一选择器被多次覆写导致的级联不可预测问题，页面标题的字号、字重、行高现在只有一处来源。

---

## 4. 替换 AI 助手硬编码颜色为主题变量 ✅

**涉及文件**：`web/src/styles/global.css`

**操作内容**：
将 AI 助手中写死的十六进制色替换为语义化主题变量或 `color-mix`：

| 原选择器 | 原硬编码色 | 替换后 |
|---|---|---|
| `.assistant-tool-sensitivity-read_only` | `#0b63c7` / `#eef6ff` / `#b7d9ff` | `var(--accent-info)` + `color-mix` |
| `.assistant-tool-sensitivity-modify` | `#255fd6` / `#f0f6ff` / `#b9d4ff` | `var(--accent-info)` + `color-mix` |
| `.assistant-tool-status-pending` | `#a55200` / `#fff7e6` / `#ffd591` | `var(--accent-warning)` + `color-mix` |
| `.assistant-tool-sensitivity-destructive` | `#b42318` / `#fff1f0` / `#ffccc7` | `var(--accent-danger)` + `color-mix` |
| `.assistant-tool-status-executed` | `#0f766e` / `#e8fff8` / `#99f6e4` | `var(--accent-success)` + `color-mix` |
| `.assistant-tool-status-rejected` | `#9f1239` / `#fff1f2` / `#fecdd3` | `var(--accent-danger)` + `color-mix` |
| `.assistant-tool-result-error pre` | `#b42318` / `#fff1f0` / `#ffccc7` | `var(--accent-danger)` + `color-mix` |
| `.assistant-approval` 边框 | `#ffd591` | `var(--accent-warning)` + `color-mix` |

**说明**：去除了暗色/黑金主题下可能过曝或不可读的硬编码浅色背景，现在状态色会随主题 accent 变化。

---

## 5. 修复 `code` 元素基线错位 ✅

**涉及文件**：`web/src/styles/global.css`

**操作内容**：
将 `code { vertical-align: bottom; }`（原 `2102` 行附近）改为 `vertical-align: baseline;`。

**说明**：行内代码块使用 `display: inline-block` 时，`vertical-align: bottom` 会让它与周围文本基线不一致，表格或列表里容易出现上下错位。改为 `baseline` 后保持 inline-block 的截断/省略能力，同时与父级文本基线对齐。

---

## 6. 统一 `prefers-reduced-motion` 处理策略 ✅

**涉及文件**：`web/src/styles/global.css`

**操作内容**：
- 删除了原先分散在 `8180-8196`（仅验证码）和 `11960-11979`（仅 AI 助手）的两个局部 `prefers-reduced-motion` 块。
- 保留了全局统一的媒体查询块（现位于 `11949` 附近），并扩展其显式声明：
  - 全局 `* { animation-duration: 1ms !important; animation-iteration-count: 1 !important; transition-duration: 1ms !important; scroll-behavior: auto !important; }`
  - 显式 `animation: none` 覆盖 `.status-breathe`、`.map-marker-pulse`、`.ai-fab::before`、验证码伪元素等关键动画类
  - 保留 `.assistant-quick-prompts button:hover { transform: none; }`

**说明**：原先三处分散块容易遗漏新动画；合并后只有一处来源，新增动画默认会被全局 `*` 规则抑制，关键类也做了兜底。

---

## 7. 建立并使用统一的 z-index 变量尺度 ✅

**涉及文件**：`web/src/styles/global.css`

**操作内容**：
- 在文件顶部 `:root` 中新增 `--z-*` 变量：
  ```css
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
- 将以下硬编码 `z-index` 替换为变量：
  - `.notification-panel` `1200` → `var(--z-notification)`
  - `.ai-fab` `22` → `var(--z-ai-fab)`
  - `.ai-assistant-panel` `70` → `var(--z-ai-panel)`
  - `.auth-captcha-modal` 及其 wrapper/mask `1001/1002` → `var(--z-captcha-modal)` / `var(--z-captcha-modal-backdrop)`
  - 全局 `.arco-modal-wrapper` / `.arco-modal-mask` `1002/1001` → `var(--z-modal)` / `var(--z-modal-backdrop)`
  - 移动端 `.app-sidebar` `26` / `.mobile-nav-backdrop` `25` → `var(--z-mobile-nav)` / `var(--z-mobile-nav-backdrop)`

**说明**：原先关键层级数值跨度大且无命名，新增弹层时极易回归。现在层级关系集中在一处，且相对顺序（fab < sidebar < ai-panel < modal < notification）保持不变。

---

## 8. 清理部分重复响应式网格覆盖 ✅

**涉及文件**：`web/src/styles/global.css`

**操作内容**：
- 移除了 `.settings-grid` 在 `3930-3935` 分组中的重复 `grid-template-columns: repeat(auto-fit, minmax(360px, 1fr))` 声明（`1280` 已存在相同定义）。
- 将 `.policy-level-grid` 基础定义从 `repeat(2, minmax(360px, 1fr))` 改为 `repeat(2, minmax(0, 1fr))`，并删除了 `@media (max-width: 1240px)` 中针对 `.policy-level-grid` 的冗余覆盖，保留同一媒体查询中对 `.protection-subsection-grid` 的处理。
- 删除了 `.dashboard-grid` 的两个重复桌面定义（原 `1276` 与 `12318-12321`），只保留最后的全局桌面规范（`1.08fr / 0.74fr`）。

**说明**：这些改动减少了“同一选择器被多次改写”的情况，同时保持了响应式回退行为。`dashboard-grid` 仍保留媒体查询中的 `.dashboard-page` 特定覆盖，因为那些是页面级窄屏适配。

---

## 9. 验证：typecheck + build ✅

**命令**：
```bash
cd web
npm run typecheck
npm run build
```

**结果**：
- `tsc -b` 通过，无类型错误。
- `vite build` 成功完成，生成 `dist/` 产物，所有页面 chunk 正常打包。

**说明**：所有改动仅涉及 CSS/主题变量，未改动 TSX 逻辑，因此类型检查无异常；Vite 构建也验证了 CSS 语法正确。

---

## 变更文件清单

- `kimi_found.md`（新增：问题清单）
- `kimi_work.md`（新增：本修复记录）
- `web/src/themes/light.css`
- `web/src/themes/dark.css`
- `web/src/themes/black-gold.css`
- `web/src/themes/blue-white.css`
- `web/src/styles/global.css`

## 备注 / 交接提示

- `--accent-success` 与文本强调色取值目前为“安全兜底”，若设计有专门的 success/strong 色值，可直接在四个主题文件中替换。
- `global.css` 仍有大量 `!important` 与重复媒体查询，本次只处理了审查报告中列出的高风险点；若后续继续清理，建议先拆分文件，再逐步收敛。
- 所有修改均已通过 `npm run build` 验证，但视觉回归仍需在浏览器中按各主题/各断点人工抽查。
