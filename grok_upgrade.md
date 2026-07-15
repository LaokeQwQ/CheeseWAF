# CheeseWAF — Grok 升级与变更记录

> 编码 UTF-8 | 与 `implementation_plan.md` / `engine_upgrade.md` 互补：本文件记录 **Grok 会话落地的工程变更**，面向商业级 WAF 运维面对齐。

---

## 2026-07-15 — Sprint A：商业级运维语义（预算 fail + allowlist）

### 目标

把“检测超时怎么办 / 误报字段怎么放行”从隐式放行，升级为 **可配置、与 `web_attack` 等级联动、可观测** 的商业级行为。  
原则不变：**宁可漏报不可误报**；预算 `closed` 优先 **challenge**，不做静默硬 block 未完成分析。

### 配置

| 字段 | 位置 | 说明 |
|------|------|------|
| `budget_exhausted_policy` | `waf.semantic_policy` | `auto`（默认）\|`open`\|`observe`\|`closed` |
| `path_allowlist` | 同上 | 路径精确 / 目录前缀 / `*` 前缀 → 整请求跳过语义 |
| `param_allowlist` | 同上 | 参数名（query/form/json/cookie/multipart）跳过扫描 |

**等级默认映射**（`auto`）：

- `off`/`low` → `open`
- `smart`/`high` → `observe`
- `strict` → `closed`

### 代码变更

| 文件 | 变更 |
|------|------|
| `internal/config/policy.go` | `BudgetPolicy*`、`BudgetExhaustedPolicyFromWebAttack`、`ResolveBudgetExhaustedPolicy`、`IsBudgetExhaustedPolicy` |
| `internal/config/policy_test.go` | 映射与 resolve 单测 |
| `internal/config/config.go` | `SemanticPolicyConfig` 挂到 `WAFConfig` |
| `internal/engine/pipeline.go` | `finalizeBudgetExhausted`：open 放行 / observe log / closed challenge；真实 block 优先 |
| `internal/engine/pipeline_test.go` | 预算策略与 block 优先回归 |
| `internal/proxy/server.go` | Detect 前注入 `budget_exhausted_policy`；`detection_budget` 绕过严重度门闩 |
| `internal/proxy/server_test.go` | budget challenge 门闩绕过单测 |
| `internal/engine/semantic/analyzer.go` | `SetAllowlists`、path/param 过滤、`semantic_skipped` metadata |
| `internal/engine/semantic/allowlist_test.go` | path/param allowlist 单测 |
| `internal/engine/semantic/metrics.go` | `AllowlistPathSkips` / `AllowlistParamSkips` |
| `internal/monitor/prometheus.go` | allowlist 两个 counter |
| `internal/cli/service.go` | `buildPipeline` 挂载站点 allowlist |
| `implementation_plan.md` | 商业级差距表 + Sprint A/B/C/D |

### 行为摘要

1. **预算耗尽（100ms pipeline）**  
   - metadata：`detection_budget_exhausted=true`、`budget_exhausted_policy=<effective>`  
   - 指标：`cheesewaf_semantic_budget_exhausted_total`  
   - `observe`：`category=detection_budget` + `ActionLog`（经 writeLog 记为 log）  
   - `closed`：`ActionChallenge`（策略层不因 confidence 0.55 降级）  
   - 已有 `ActionBlock`/`ActionChallenge` 真实命中：**不覆盖**

2. **Allowlist**  
   - path 命中：Detect 直接 pass，`semantic_skipped=path_allowlist`  
   - param 命中：字段不进入语义；path/header/uri 仍扫  
   - 指标：`cheesewaf_semantic_allowlist_{path,param}_skips_total`

### 验证

```text
GOCACHE=... go test ./internal/config ./internal/engine ./internal/engine/semantic \
  ./internal/proxy ./internal/cli ./internal/monitor -count=1
# 全部 ok（本轮）
```

### 提交 / 推送

- Commit: `e58e9da feat: commercial budget fail-mode and semantic allowlists`
- Branch: `feature/security-captcha-ui-hardening-20260714` → GitHub origin 已推送
- `implementation_plan.md` 本地已更新商业级对照（该文件在 `.gitignore` 中，不进仓；以本文件为可追踪变更记录）

### 明确未做（避免过度宣称）

- Web UI 编辑 semantic_policy
- 按事件一键加入 allowlist / TTL 临时例外
- 将 budget closed 改为硬 403 block
- CRS 全量对标或准确率营销数字

---

## 2026-07-14 ~ 2026-07-15 — 语义热路径 / CAPTCHA / Windows（摘要）

> 完整语义设计见 `engine_upgrade.md`；此处仅列近期 Grok 会话相关收口。

### 语义引擎（FP-first + 纯 Go perf）

- `blockableHit` 门闩；clean ASCII / 敏感文件名短路；path vs query merge + `raw_query`
- FNV 分片 TTL candidate cache；process metrics + Prometheus
- pipeline：pre-filter 串行 + priority≥290 semantic 组并发 fork/merge
- multi-field worker pool（atomic work index）
- curated FP/attack corpus 持续扩；健康探针零抽取

### CAPTCHA

- 曲线滑块：放宽方差硬拒绝（真实 Chromium 轨迹 FP → BUG-074）
- lab-page / e2e 与 sealed target 加固方向保留

### Windows

- `cmd/cheesewaf-gui` + `internal/winctl` loopback GUI 控制器
- `deploy/windows/nsis` 骨架；无 secrets 进安装器

### 远程

- 主推 GitHub `origin`；Forgejo 多为只读 mirror，direct push 常 403
- 变更记录与 SHA 以 GitHub feature 分支为准，mirror-sync 另触发

---

## 商业级对齐路线图（活文档）

| Sprint | 主题 | 状态 |
|--------|------|------|
| A | 预算 fail ↔ 等级 + path/param allowlist + 指标 | **已落地** |
| B | 控制台 allowlist / 事件放行 / TTL exception | 待做 |
| C | 事件可解释（semantic + budget + policy） | 待做 |
| D | 发布 corpus/external gate 硬门槛 | 部分已有工具，流程待钉死 |
| ∥ | CAPTCHA 抗 bot、Windows 安装验收、Mesh HA | 并行 |

**产品原则（不退让）**

1. 0 FP on labeled gate 优先于追 FN  
2. 纯 Go，无 CGO 检测热路径  
3. 不宣称 ModSecurity/CRS 等价，直到有对标证据  
4. fail-closed 时优先 challenge，避免“分析没做完就静默 403”

---

## 如何续写本文件

每完成一个可验证冲刺，追加一节：

1. 目标与原则  
2. 配置/API 表面  
3. 文件级变更表  
4. 验证命令与结果  
5. 明确未做项  

同步在 `implementation_plan.md` 追加对应阶段条目。
