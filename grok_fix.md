# CheeseWAF 审查复核与修复结果

**日期：** 2026-07-14  
**分支 / 工作区：** `dev`（含未提交改动）  
**方法：** 静态复核当前树 → 4 路并行子代理修复 → 统一测试验证  
**报告文件：** `grok_fix.md`（本文件）

---

## 1. 复核总表

图例：

| 状态 | 含义 |
|------|------|
| **已修复** | 代码中已落地，测试通过 |
| **部分修复** | 核心路径已修，残留设计债或可选加固 |
| **未修 / 延后** | 本轮未改或产品债排期 |
| **误报/设计** | 有意行为或风险可接受 |

### 1.1 安全 / 正确性（原 P0 Batch A）

| ID | 问题 | 复核结果 | 修复说明 |
|----|------|----------|----------|
| S1 | ACME `dns_env` 注入 PATH/LD_PRELOAD | **已修复** | `blockedDNSEnvKeys` + `mergeChildEnv` + issue 校验 |
| S2 | APISec JWT 无密钥跳过验签 | **已修复** | Auth 启用必须有密钥材料；运行时 fail-closed |
| S3 | PUT `/system` 种 token / 改 RBAC | **已修复** | 强制保留旧 Permissions 与 Tokens |
| S4 | ACME `reload_command` shell 注入 | **已修复** | 禁元字符 + 绝对路径（含 Unix `/` 在 Windows 上校验） |
| S5 | image/slider 非一次性 | **已修复** | `Reserve/Start/Commit` + 成功 `Consume` |
| S6 | image/slider 签发无限流 | **已修复** | 与 ChallengeStore 租约/速率对齐 |
| S7 | AI Modify 自批 | **已修复** | 自批禁止 + 需 `approve:ai`；路由 RBAC |
| S8 | Self-learning 评审失败仍 AutoApply | **已修复** | `reviewOK` 门闩 |
| S9 | Redis/PG storage test SSRF | **已修复** | `dialStorageEndpoint` / DSN host 公网策略 |
| S10 | 集群 join 换 Config 指针 | **已修复** | `config.Clone` + 原地 `*h.Config` + 失败回滚 |
| S11 | AI target 乱码 `鎺ㄧ悊` | **已修复** | 改为 `推理` |
| S12 | 通知 `navigate(target)` 开放导航 | **已修复** | `sanitizeInternalReturnPath` |

### 1.2 数据面 Bot / Captcha / Proxy（深审新增）

| ID | 问题 | 复核结果 | 修复说明 |
|----|------|----------|----------|
| P1 | 路径 `..` 绕过豁免 / clearance 范围 | **已修复** | `engine.NormalizeRequestPath` + `PathMatchesPrefix`；proxy 早清洗；`pathWithinScope` 清洗后匹配 |
| P2 | UA/ECT/Save-Data 强制降级 PoW | **已修复** | `adaptiveCAPTCHAType` 仅高风险 escalation，不再因 mobile/弱网降级 |
| P3 | 默认豁免 `/api/` | **已修复** | 默认仅 `/health`（段边界匹配） |
| P4 | 图像 7 段数码 / 小字母表 OCR 弱 | **部分修复** | 一次性 Consume 已限重放；字体/噪声增强未做（延后） |
| P5 | 默认 `ip_prefix_ua` /24 共享 | **未修 / 延后** | 配置默认策略，高价值站点可改 `strict_ip_ua` |
| P6 | Allowed UA 子串绕过 | **已修复** | 整词/精确匹配，非裸 `Contains` |
| P7 | behavior verify 在限流/ACL 前 | **未修 / 延后** | 仍有 body/method 限制；可再移到策略后 |
| P8 | 未知 Host 回落首站点 | **已修复** | 无匹配 → 421 Misdirected Request |
| P9 | 风险分可伪造头 | **设计债** | 误报控制与对抗权衡；未改评分模型 |
| P10 | clearance path=`/` 全站 | **设计债** | 声明路径 `/` 即全站通行凭证 |
| C1 | Behavior owner cookie Secure 仅 `r.TLS` | **已修复** | `cookieSecure`：TLS 或 `X-Forwarded-Proto: https` |
| C2 | 登录 CAPTCHA cookie 同问题 | **已修复** | `loginCaptchaCookieSecure` |
| C3 | 等候室 `document.cookie` | **已修复** | 服务端 `Set-Cookie`（Secure+HttpOnly） |
| C4 | image/slider 默认 secret 回落 | **已修复** | 空 secret 不再用硬编码常量 |

### 1.3 后端额外

| ID | 问题 | 复核结果 | 修复说明 |
|----|------|----------|----------|
| N1 | Self-learning / 助手绕过 freeze | **已修复** | `CanWriteRules` + `selfLearningRuleWriteAllowed`；助手写配置认本地 freeze |
| N2 | 登录限流任意 private peer 信 XFF | **已修复** | 仅 **loopback peer** 信 XFF |

### 1.4 前端 UI / 安全 UX

| ID | 问题 | 复核结果 | 修复说明 |
|----|------|----------|----------|
| F1 | 登出/401 不清 React Query | **已修复** | `queryClient` 单例；logout/401 `clear()` |
| F2 | 全局 `placeholderData` 串页 | **已修复** | 移除全局默认 |
| F3 | 拦截页新窗 blob 同源可执行 | **已修复** | 走 `/block-pages/preview` + `sandbox=""`；消毒补 `action`/`base` 等 |
| F4 | JWT 在 localStorage | **未修 / 延后** | 架构级 HttpOnly 会话未改 |
| F5 | 登录背景 cssURL 注入 | **已修复** | 拒绝 `);{}` 等并限制 scheme |
| F6 | 路由只看 token 非空 | **未修 / 延后** | 仍依赖 API 401 |
| F7 | 前端无 route RBAC | **未修 / 延后** | 后端 RBAC 仍为准 |
| F8 | 配置表单 refetch 覆盖编辑 | **未修 / 延后** | 脏表单守卫未做 |
| F9 | `/setup` SPA 公开 | **未修 / 延后** | 依赖后端拒绝二次 setup |
| F10 | 通知 z-index 压 Modal | **已修复** | `--z-notification: 90`（&lt; modal 100） |
| F11 | account fallback 显示 admin | **已修复** | 空 username/role |
| U2 | Protection 保存无 toast | **已修复** | success toast + i18n |
| U3 | 清空通知误用删除文案 | **已修复** | 专用确认文案 |
| U4 | Updates/AI 硬编码英文错误 | **已修复** | i18n keys |
| U5 | health 1s 轮询 | **已修复** | 健康 15s；心跳 effect 依赖稳定化 |
| U13 | BotChallenge tooltip 裁切 | **未修 / 延后** | 布局 |
| U14 | Login video 无视 reduced-motion | **未修 / 延后** | 动画 a11y |
| T* | 文案黑话 / 题型三套命名 | **未修 / 延后** | Batch D 产品债 |
| D* | 主题 token / megafile | **未修 / 延后** | Batch E |

---

## 2. 本轮并行修复批次

| 子代理 | 范围 | 结果 |
|--------|------|------|
| path normalize bot | P1 路径 / 豁免 / clearance | PASS |
| captcha cookies | P2 降级、C1–C3、P6 UA | PASS |
| frontend cache preview | F1–F3、F5、F10–F11 | PASS |
| freeze XFF host | N1、N2、P8、P3 | PASS |

（Batch A 的 S1–S12 在本会话更早落地，已纳入上表「已修复」。）

---

## 3. 关键代码落点

### 3.1 数据面路径

| 文件 | 要点 |
|------|------|
| `internal/engine/path.go` | `NormalizeRequestPath` / `PathMatchesPrefix` |
| `internal/proxy/server.go` | 早清洗；未知 Host → 421 |
| `internal/protection/bot/policy.go` | applies、adaptiveCAPTCHA、cookieSecure、waiting Set-Cookie、image/slider Consume |
| `internal/protection/bot/challenge_security.go` | `pathWithinScope` 清洗 |

### 3.2 管理面 / 配置

| 文件 | 要点 |
|------|------|
| `internal/acme/issuer.go` | env 黑名单、reloadcmd 校验 |
| `internal/apisec/auth.go` / `jwt.go` | 验签 fail-closed |
| `internal/config/validator.go` | Auth 必须有密钥；reloadcmd |
| `internal/api/handler/system.go` | 禁种 token；storage netguard |
| `internal/api/handler/cluster.go` | Config 指针契约 |
| `internal/api/handler/ai.go` / `ai_tools.go` | freeze + 禁自批 |
| `internal/ai/self_learning.go` | reviewOK + CanWriteRules |
| `internal/config/loader.go` | 默认 bot 豁免仅 `/health` |

### 3.3 前端

| 文件 | 要点 |
|------|------|
| `web/src/queryClient.ts` | 共享 QueryClient |
| `web/src/App.tsx` | 无全局 placeholderData |
| `web/src/api/client.ts` | 401 clear cache |
| `web/src/layouts/MainLayout.tsx` | logout clear、通知消毒、account fallback |
| `web/src/pages/BlockPages/BlockPagesPage.tsx` | 安全预览 + 消毒 |
| `web/src/pages/Login/LoginPage.tsx` | cssURL 收紧 |
| `web/src/styles/global.css` | z-notification 90 |
| `web/src/i18n/locales/*` | saved / requestFailed / 通知确认 / updates.invalidCustomServer / ai.invalidConfig |

---

## 4. 验证命令与结果

```text
go test ./internal/engine/... ./internal/protection/bot/... ./internal/proxy/... \
        ./internal/api/handler/... ./internal/ai/... ./internal/apisec/... \
        ./internal/acme/... ./internal/config/... -count=1
# 全部 ok

cd web && npm test -- --run \
  src/i18n/locales/locales.test.ts \
  src/api/client.test.ts \
  src/layouts/MainLayout.test.tsx \
  src/pages/BlockPages/BlockPagesPage.test.tsx
# 4 files / 24 tests passed
```

---

## 5. 仍建议后续处理（按优先级）

1. **P4** 图像 CAPTCHA 字体/字母表/噪声（OCR 强度）  
2. **F4** HttpOnly 会话（XSS 爆炸半径）  
3. **P7** behavior verify 接入 IP/限流链路  
4. **F6/F7** 前端会话校验 + route RBAC 提示  
5. **F8** 配置页 dirty 守卫  
6. **U13/U14/T\*** 布局、减动效、文案去黑话  
7. **P5/P9/P10** 绑定模式默认与评分文档化  

---

## 6. 结论

| 维度 | 结论 |
|------|------|
| 原 P0 管理面 / ACME / JWT / token / AI 自批 / 通知导航 | **已关闭** |
| 数据面 Critical 路径 `..` 绕过 | **已关闭** |
| CAPTCHA 可伪造降级 + cookie Secure + 默认 `/api/` 豁免 + Host 回落 | **已关闭** |
| 前端跨会话缓存 / placeholder / 预览 XSS / cssURL / z-index | **已关闭** |
| freeze 与登录 XFF | **已关闭** |
| 可合并性 | **显著改善**；剩余多为产品债与架构级会话模型，不再阻塞「止血」合入 |

**本文件即修复结果交付物：`grok_fix.md`。**

---

## 7. CAPTCHA 专项复核 + 编译（2026-07-14 追加）

### 编译 / 测试

| 命令 | 结果 |
|------|------|
| `go build ./...` | **PASS** (exit 0) |
| `go test ./internal/captcha/... bot/... proxy/... handler/` | **PASS** |
| `npm run build` (tsc + vite + budget) | **PASS** |
| frontend captcha tests (features + BotChallenge + assets) | **96 passed** |

### CAPTCHA 复核：仍存在 / 刚修

| 优先级 | 问题 | 状态 |
|--------|------|------|
| High | 经典 image/slider/PoW 成功后 clearance 写死 `Secure: true`，纯 HTTP 数据面 cookie 被浏览器丢弃 → 过关后无限重挑战 | **已修** → `cookieSecure(r)` |
| High | 缺 image/slider「Issue→正确作答→Consume→clearance」E2E 单测 | **仍缺**（测试债） |
| Med | image/slider 曾接受 GET query 答案（日志泄露） | **已修** → 仅 POST body |
| Med | `legacy-pow` Consume 无对应 Add（死路径 fail-closed） | **仍在** |
| Med | track 可选时空 track 恒 true；键盘合成最小合法 track | **仍在**（a11y/强度权衡） |
| Med | Lab Consume-before-Verify 错答也烧 token | **仍在**（防重放取向） |
| Low | `newImageChallenge` 非 ForSite 不 Commit 的 footgun API | **仍在** |
| Low | CaptchaLab 硬编码 i18n / 非主题色 | **仍在** |

### 扎实部分（CAPTCHA）

- Behavior + PoW：Reserve/Start/Commit、Claim 单次、owner cookie、路径绑定  
- image/slider：已 Commit+Consume+限流+POST 表单  
- Login captcha：receipt、配额 cookie、滑块必须 track  
- Lab：admin-only、opaque token、前端 abort/竞态测试较全  
- Proxy：路径清洗、verify path 固定、未知 Host 421  

### 建议下一批（CAPTCHA）— 已在后续提交处理

1. ~~补 image/slider 全链路成功单测~~ → `TestImageCAPTCHAFullCycleIssueAnswerConsume`  
2. ~~删除或真正接线 `legacy-pow`~~ → 退役 query-param legacy PoW  
3. ~~WAF 强制 track~~ → `sliderTrackRequired` 恒 true；空 track 失败  
4. 图像 0–9 字母表已补；7 段字体/更强噪声仍可继续增强  

### 推送 / 镜像（2026-07-14）

| 项 | 值 |
|----|-----|
| 分支 | `feature/security-captcha-ui-hardening-20260714` |
| HEAD | `94f3194ebb1a7a030d6e1cca82d9c7e45a69f132` |
| GitHub PR | https://github.com/LaokeQwQ/CheeseWAF/pull/222 （base: `dev`，MERGEABLE） |
| Forgejo mirror-sync | HTTP 200；`forgejo` 与 `origin` 同 SHA |

---

## 2. 续作纪要（2026-07-15）— 语义 / Cache / 语料 / 滑块 / AI / 计划缺口

> 语气故意偏「神秘」一点：下面写的是**证据**，不是愿景海报。

### 2.1 语义引擎：误报优先 + 纯 Go Cache

| 项 | 证据 |
|----|------|
| FP 门禁 | `TestFPGateReport`：**9650 benign / 0 FP**，**17037 attack / 0 miss**，`fp_gate_pass=true` |
| 热路径 Cache | 新增 `internal/engine/semantic/cache.go`：32-shard TTL+近似 LRU、FNV-1a 无 `hash.Hash` 堆分配、类别指纹预计算、`get` 零拷贝返回 |
| 进程指标 | `metrics.go`：`cache_hits/misses`、按类别 block、延迟桶；Prometheus 已挂 |
| 预过滤 | `looksCleanASCIIField`：仅单 token 标识符（禁止空格/前导点），避免 `.env` / `pwsh -EncodedCommand` 被误短路 |
| LFI FP 修复 | 裸 `%2f/%5c`（正常 URL 编码）不再当穿越；OAuth `redirect_uri`、IANA timezone 等生产形状通过 |
| Bench | `BenchmarkSemanticAnalyzer` 约 **10.1µs/op · 5804 B · 76 allocs**（相对此前 ~19µs/83allocs 的暖路径） |
| 约束 | **仍 100% Go**，无 CGO / 无第三方缓存依赖 |

### 2.2 误报案例数据集与攻击邻居（精筛）

写入 `testdata/`，**不是**盲导 SecLists 全量：

| 文件 | 规模（约） | 内容 |
|------|------------|------|
| `benign_production_shapes.jsonl` | **60** | OData `$filter`、GraphQL、JWT、OAuth/PKCE、ES match、Slack webhook、data:image、Handlebars、中文购物车、JSON:API、CORS、session cookie… |
| `handcrafted_attack_neighbors.jsonl` | **18** | 与上述 benign **成对**的 SQLi/XSS/RCE/LFI/SSRF/NoSQLi/SSTI/XXE |
| `curated_external_shapes.jsonl` | ~2.6 万行 | 既有 bulk+curated 混合语料（仍经 label/gate 回归） |

导入原则：每个高风险族至少有一个生产形状邻居；宁可漏拦也不允许「文档/业务 JSON」被 block。

### 2.3 CAPTCHA 曲线滑块：抗图灵 / 黑产轨迹

`verifyVisualCurveSlider` 加固（目标仍 V3 位图对齐，服务端密封 offset）：

- 最少 **8** 个轨迹点、时长 **≥280ms**
- 拒绝恒步长线性 ramp（经典脚本）
- 拒绝高平均速度 / 单步 teleport / 过大瞬时速度
- 要求空间或时间方差（`sliderTrackHasHumanVariance`）
- 测试：linear bot、fast drag、teleport、folded 均 reject；合法人机夹具仍 accept
- harness 改为 `harnessCurveSliderTrack`  dense+jitter 轨迹

### 2.4 AI 助手 / 流式 / 知识库 / 提示词 / 注入 / MCP / 自学习 / 审批

本轮**加固边界与知识**，未重写整条链路（原链路已具备 stream + tool plan + approval）：

| 面 | 状态 |
|----|------|
| 系统安全提示词 | 扩展 jailbreak/DAN/MCP 参数/自学习 apply 等不可信边界（`aiSafetySystemPrompt`） |
| 知识库内置条目 | 增补 prompt-injection、MCP+审批、语义 FP-first、curve_slider 抗自动化 |
| 流式对话 | 既有 provider delta / reasoning / tool_call / heartbeat（本轮未改协议） |
| MCP Tools | Registry + sensitivity；改配仍走 ApprovalStore fail-closed |
| 自学习 | 既有 `reviewOK` 门闩 + `CanWriteRules`；LLM 评审失败禁止 AutoApply |
| 审批 | 自批禁止 + `approve:ai` RBAC（历史已修，本轮回归 `./internal/ai` PASS） |

### 2.5 `implementation_plan.md` 缺口速览（空壳 / 未完 / 不可用）

| 能力 | 判断 | 说明 |
|------|------|------|
| Windows **GUI 服务控制器** | **未实现** | 计划有；代码无 WinForms/WPF/webview 控制器 |
| Windows **NSIS 安装器** | **未实现** | 仅规划；发行现状是 zip/bin CLI |
| CRS/FTW / Coraza 对标 | **未宣称完成** | 有 curated corpus + external gate 证据，非 CRS 等价 |
| Paranoia / anomaly scoring | **路线图** | 未做 CRS 式 anomaly 累计 |
| 集群 M2–M4 完整 HA | **部分** | mTLS/join 等有基础；Raft/etcd/写冻结/流量调度未齐 |
| CLI / TUI / Web 管理 | **可用** | `cmd/cheesewaf` + panel + embed web |
| 语义引擎生产 block | **可用** | FP-first + gate 0 FP（标注集） |
| AI 助手全链路 | **可用（需配置 Provider）** | 无 key 时降级；有 key 时 tool+stream+审批 |
| CAPTCHA behavior / login | **可用** | 滑块轨迹门槛本轮加严 |

### 2.6 验证命令（本轮）

```text
go test ./internal/engine/semantic/ -count=1
go test ./internal/captcha/ -count=1
go test ./internal/ai/ -count=1
go test ./internal/engine/semantic/ -bench=BenchmarkSemanticAnalyzer -benchmem -benchtime=200ms
```

### 2.7 推送

| 项 | 值 |
|----|-----|
| 分支 | `feature/security-captcha-ui-hardening-20260714` |
| 提交 | `579464d0abadfbbb92aec46a4c68bddebf30030e` |
| GitHub `origin` | **已 push** `ffc5350..579464d` |
| Forgejo | **只读 pull mirror**：direct push 403；本机无 `FORGEJO_TOKEN`，未触发 mirror-sync API。待环境有 token 后 `POST /api/v1/repos/Laoke/CheeseWAF/mirror-sync` 对齐，或等定时 pull |
