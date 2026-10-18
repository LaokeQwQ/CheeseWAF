# Detector 语义增强交接：2022-2026 增量

状态：2 条高置信语义已落地；25 条仍在 `research-quarantine`；6 条曾在第一版落地，红队复核发现真实误报后已退出 blocking path。
基线：`3cd54cbd`。工作区另有大量未提交改动，不是本任务产生的；不要整体回滚。
范围：只覆盖 `internal/engine/semantic` 的语义检测与语料；不覆盖代理/协议/管理面。

## 1. 改动文件

新增：

- `internal/engine/semantic/contextual_semantics_2026.go`
- `internal/engine/semantic/contextual_semantics_2026_test.go`
- `internal/engine/semantic/testdata/contextual_2026_shapes.jsonl`

修改：

- `internal/engine/semantic/analyzer.go`
  - `scanAttackHints` / `longCandidateStrongHints` / `longCandidateStrongHintsASCII` 接入 `ssti2026Hint`，修复 256 字节长值门丢弃新规则的问题。
  - `guessCategoriesForSource` 用 `ssti2026Direct` 打开 `ssti` score。
  - `analyzeSSTI` 先调用 `analyzeSSTI2026`。
  - 整数 SSTI 算术探针只接受“整个值就是表达式”，修复 `${7*7} in documentation` 这类搜索词误报。
  - LFI wrapper 只在真的带 resource/filter chain/path 时命中，修复 `php://filter is documented here` 误报。
- `internal/engine/semantic/corpus_test.go`
- `internal/engine/semantic/fp_gate_report_test.go`
  - 普通 corpus/FPR 报告纳入 `contextual_2026_shapes.jsonl` 的 attack/benign 回归。
  - 这不代表正式 governed semantic gate 覆盖该 fixture；`scripts/ci/run-governed-semantic-gate.sh` 只治理三份固定语料，不含 contextual fixture。

外部候选（不在仓库）：

- 外部候选数据集（仅本地研究材料，不纳入仓库）
  - 60 条；`implemented=2`、`already-covered=33`、`deferred=25`。

## 2. 已落地的 2 条

| 语义 | 规则 | 测试 |
|---|---|---|
| Velocity `#set` 反射到 `java.lang.Runtime` / `ProcessBuilder`，再 `getMethod/invoke/exec/start` | `ssti2026Direct` 第一分支 | `velocity-reflection`、`velocity-classloader`、`fullwidth`、`long-value` |
| SpEL/Thymeleaf `*{...}` / `@{...}` 中 `T(java.lang.Runtime|ProcessBuilder)` / `getRuntime()` 后 `.exec` / `.start` | `ssti2026Direct` 第二分支 | `spel-star-selector`、`spel-at-selector` |

规则刻意要求“类加载/反射原语 + 执行 sink”同时出现，而不是只匹配 `getClass`、`Runtime`、`@ognl` 等公开 token。

## 3. 第一版落地后又撤下的 6 条

红队用公开 API/规范/Javadoc/CVE 公告形状实测，以下规则会把正常文档判 critical，已退出 blocking path：

| 撤销规则 | 误报样例 |
|---|---|
| `@ognl.Ognl@applyExpressionMaxLength` | OGNL 公开 API 文档本身就会写 `@ognl.Ognl@applyExpressionMaxLength(10000)` |
| `#request[...].internalGet('ognl')` | OGNL Context Map / CVE 分析文档 |
| Spring4Shell `class.module.classLoader...` | Spring/JDK 文档和 CVE-2022-22965 公告正文 |
| `ReflectUtils.defineClass(...)` | 公开工具类 API 文档/源码 |
| `ServletRequestListener...requestInitialized(...)` | Servlet 规范 Javadoc 的标准接口实现 |
| HTML entity `javascript:` | HTML entity/XSS 教程必然包含 `javascript&colon;alert(1)` |

这些语义不是没价值，而是当前只有 regex，无法区分“文档里的代码”和“请求里的代码”；应等 parser/上下文设计，不能靠继续加正则。

## 4. 开源仓库前提下的绕过模型

攻击者能读规则、测试、fixture 和阈值。已封堵/已验证：

- 长值 256 字节门：把 `ssti2026Hint` 接进 `longCandidateStrongHints`，300 字节填充后的 Velocity 链仍命中。
- 全角/兼容字符：`normalize` 后 `＃ｓｅｔ` 命中。
- 无害反射：`getClassLoader()`、`forName("java.lang.String")`、`getMethod("toString")` 放行。
- 类型/链接表达式：`*{T(java.lang.ProcessBuilder)}`、`@{/docs(java.lang.Runtime)}` 放行。
- 文档词硬丢弃：已删除 `analyzeSSTI2026` 里“命中 example/tutorial 就 return false”的分支，攻击者不能再加一行注释绕过。
- 距离上界：`#set`/`*{`/`@{` 的中间片段改为无上界（RE2 线性），1001 空格填充不再天然绕过。
- 规则接线：`hint -> score -> analyzer` 三层必须同时改；第一版只改 analyzer 时全部 positive miss，测试已锁住。

仍未封堵（按优先级）：

1. 12 层以上嵌套编码（decoder 上限 12，超深仍不标 incomplete）。
2. 跨字段拼接（多个 query/form 字段在应用侧拼成模板/OGNL）。
3. Content-Type 互换、charset best-fit、multipart 同名 part。
4. Java token 间注释、参数改名、同义类加载入口。
5. XSS scheme 的 WHATWG 归一化（新 XSS 规则已撤下，旧规则仍在）。
6. Assistant 的 tool result/知识库间接注入；日志分析主路径已跳过可疑输入，但 tool 路径仍需单独边界。

结论：这些规则只能提高成本，不是安全边界；下一阶段优先做解析器一致性，不要继续堆单条 regex。

## 5. 验证证据

命令：

```bash
go test ./internal/engine/semantic -run \
'TestContextualSemantics2026|TestAnalyzerCuratedExternalCorpus|TestFPGateReport' -count=1
```

本次结果（已删除与 OGNL quarantine 决定矛盾的 attack fixture 后）：

```text
ok github.com/LaokeQwQ/CheeseWAF/internal/engine/semantic
```

FPR gate：

```text
benign_total: 9695
benign_fp: 0
fp_rate_percent: 0
attack_total: 17072
attack_hit: 17072
attack_miss: 0
```

Fixture：27 条（8 条 attack、19 条 benign）。OGNL Context Map 形状仍由 `ognl-context-runtime-remains-quarantined` 单测锁定为不检测，未作为已实现 attack 能力计入 fixture 或 attack hit 率。

门禁范围：普通 corpus/FPR 测试会加载该 contextual fixture；正式 governed gate 不会。正式 gate 的来源、hash 和基线固定在 `scripts/ci/run-governed-semantic-gate.sh`，没有经过治理审查前不要把 contextual fixture 加入该快照。上述 FPR 报告是合并语料上的回归结果，不是 governed snapshot 结果，也不代表生产误报率。

全量 semantic 套件：

```bash
go test ./internal/engine/semantic -count=1
```

约 5 分钟；提交前必须重跑并记录结果。

## 6. 未落地候选（25 条）

按优先级：

1. **JSON 结构差异**：重复 key 已通过 `jsonHasDuplicateKeys` + raw-body candidate 检查首/末值（标记 incomplete）；`__proto__`/`\u0000` 仍需 parser 层。
2. **PHP wrapper/CGI**：`php://filter` 长 iconv 链、`%ADd`/CVE-2024-4577。简单 wrapper 已有；长链和 best-fit 要 parser/规范化。
3. **SQLi 语义**：PostgreSQL JSON 操作符、`$$`、`COPY PROGRAM`、`ATTACH`、`X-siLock-Comment`。`COPY PROGRAM`/`OPENROWSET` 已有；`ATTACH` 正常文档会命中，不能裸加。
4. **反序列化 magic bytes**：Java `rO0AB`/`aced0005`、PHP `O:`、.NET ViewState、Python pickle；需要 body 入口分类和端点上下文。
5. **协议层**：Content-Type 互换、重复 CL/TE、multipart filename；属于 `protocol_enforcement.go`/body parser，不塞进 semantic analyzer。
6. **SSRF**：IPv4-mapped、十进制、`100.100.100.200`、`metadata.google.internal` 已有；补 AWS IPv6 `fd00:ec2::254` 和重定向链测试。
7. **AI prompt injection**：应在 AI 输入/工具边界，不是 WAF semantic。
8. 其余见外部 JSONL 的 `deferred_reason`。

## 7. 给下一个 Agent 的操作清单

1. 先读：
   - `internal/engine/semantic/contextual_semantics_2026.go`
   - `internal/engine/semantic/contextual_semantics_2026_test.go`
   - `internal/engine/semantic/testdata/contextual_2026_shapes.jsonl`
   - `analyzer.go` 的 `scanAttackHints`、`longCandidateStrongHints`、`guessCategoriesForSource`、`analyzeSSTI`。
2. 新增语义必须同时改：
   - `ssti2026Direct`/新的 parser 函数；
   - `ssti2026Hint`（短值和长值都要）；
   - `guessCategoriesForSource` 的 score；
   - `longCandidateStrongHints`/`longCandidateStrongHintsASCII`；
   - Go test positive/negative；
   - `contextual_2026_shapes.jsonl` attack/benign。
3. 每条规则至少 1 attack + 2 benign；benign 要来自真实框架文档/API/Javadoc 形态，不要只写 `safe`。
4. 跑 targeted 和全量；任何 benign FP 必须解释或修掉，不要用“攻击者不会这么写”糊过去。
5. 不要整体 `git checkout`/回滚工作区：本任务开始时已有大量未提交改动；只改你负责的文件。
6. 不要把已撤销的 6 条规则直接加回；先解决文档上下文/parser 区分。
7. 假定攻击者能读代码：优先做规范化、解析器一致性、协议层拒绝歧义、多信号组合。

## 8. 残余风险

- 规则是公开 regex，仍可被同义 API、注释、跨 `#set` 拆分、嵌套编码绕过。
- FPR 0 只覆盖 9,695 条现有 fixture，不等于生产 FPR；发布前需独立盲测（至少 576 条 benign 才能证明 <0.8% 的 99% 上界）。
- `research-quarantine` 的 25 条未完成许可证/PII/标签/盲测审查。
- 未做端到端 HTTP 攻击测试；上线按 shadow → log → challenge → block 灰度。
- 代理/协议/JSON 解析差异仍未修；它们可能比 semantic regex 更容易绕过。

## 9. 参考

- 候选数据：外部本地研究材料，未纳入仓库。
- 审计报告：外部本地审计材料，相关结论已归纳于本文第 3、4 节。
- 语料治理：`docs/semantic-corpus-governance.md`、`docs/open-corpus-catalog.md`
- 红队发现的 10 类绕过/5 类误报：已并入本文件第 3、4 节；完整测试清单在先前 red-team 报告中。

## 10. AI 日志分析的提示词注入防线

新增：

- `internal/ai/prompt_injection.go`
  - `ScanPromptInjection(entry)`：扫描 URI/Payload/Message/User-Agent 的角色 token、指令覆盖、角色冒充、工具请求、关闭安全控制。
  - `NeutralizePromptRoleMarkers`：提示词里的 `<|im_start|>`、`[INST]`、`<<SYS>>` 等替换为 inert marker。
- `internal/ai/analyzer.go`
  - `AttackAnalysis` 增加 `prompt_injection_suspected` / `prompt_injection_signals`。
  - `AnalyzeLogWithLanguage` / `AnalyzeLogWithLanguageStream`：疑似注入时不调用 provider，直接返回确定性分析；日志分析只走 completion API，不接 tool registry。
  - `safePromptText` 调用角色 marker 净化。
- `internal/review/queue.go`
  - `maybeAutoAgree` 在 `PromptInjectionSuspected` 时直接跳过自动写规则。
  - `formatVerdict` 记录注入标记。
- `internal/ai/self_learning.go`
  - 候选 pattern/reason 命中注入标记时跳过 AI review，`AIReviewed=false`，AutoApply 不会消费。

测试：

- `internal/ai/prompt_injection_test.go`：扫描正/负例、恶意日志下 provider 调用次数为 0。
- `internal/review/apply_test.go`：`TestAutoAgreeSkipsPromptInjectionSuspectedAnalysis`。

需要注意：

- 这是“检测到就降级为确定性分析 + 禁止自动写”，不是“模型绝对不会被注入”。
- 日志分析读路径没有工具/写权限；assistant 工具路径仍走 ApprovalGate。
- `AutoApply` 仍建议默认关闭；AI-only 结论不能直接写生产规则。
- 间接注入（tool result、知识库、图片/文件）仍需在 tool gateway 层做同样的 untrusted-data 边界。
