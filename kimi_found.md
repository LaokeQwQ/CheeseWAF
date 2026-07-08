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
