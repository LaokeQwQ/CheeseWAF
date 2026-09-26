# CheeseWAF acceptance matrix v2

这是 CheeseWAF 控制面、数据面边界和交付产物的端到端验收入口。`--static` 不启动 PostgreSQL 或 Redis；`--full` 仅在显式提供真实测试依赖时运行生产组合探针。报告写入仓库外路径；矩阵不改写 configs/cheesewaf.yaml、tasks.md 或 README。

## 稳定版发行物

稳定标签 `vMAJOR.MINOR.PATCH` 使用服务器档位。必须验收 Linux 发行包、`SHA256SUMS`、Sigstore 签名和 SBOM。每个归档内的 `VERSION`、`release.json` 和顶层发布清单必须使用相同的版本与 40 位提交 SHA。发布脚本还要解析 GitHub 上的标签对象，并把 Sigstore 身份限定到当前标签。Windows 与 macOS 构建属于可选的操作端产物；只有在对应文件实际存在时，才执行平台签名检查。平台签名缺失不会阻塞服务器版稳定发布。

分支和手动工作流仍可以使用完整档位生成 Windows 与 macOS 构建，用于操作端测试。它们不能改变稳定版的服务器交付范围。

运行完整矩阵：

    bash scripts/acceptance/matrix.sh --full

在没有启动 WAF 进程的情况下运行同一套契约：

    bash scripts/acceptance/matrix.sh --static

列出 gate：

    bash scripts/acceptance/matrix.sh --list

默认报告是 /tmp/acceptance_e2e_matrix_v2_report.json 和 /tmp/acceptance_e2e_matrix_v2_report.md。也可以用 --report PATH 与 --markdown PATH 指定仓库外路径；脚本拒绝仓库内报告路径，避免把运行结果写进工作区。报告文件使用私有权限。

每个 gate 都执行一条预期成功的正向命令和一条预期拒绝或边界的负向命令。两侧都保存命令、断言、退出状态和输出证据。代码或运行时尚未接线的能力使用 implemented: false、status: failed 和 blockers 字段表示；没有 skipped 状态。

`--full` 的部署级 gate 只有在提供真实依赖后才执行探针并动态转为 implemented：`CHEESEWAF_POSTGRES_TEST_DSN`、`CHEESEWAF_REDIS_RUNTIME_TEST_ADDR`；CRP 激活/回滚还需要 `CHEESEWAF_CRP_SIDECAR_TEST_REGISTRY_DIR` 指向权限为 `0700` 的测试目录。临时联网/CWEDP 还必须提供规范的 `CHEESEWAF_PUBLIC_NETLEASE_TEST_PIN`、公网 `CHEESEWAF_CWEDP_REAL_ROUTE_HOST` 和 `49152..65535` 高端口 `CHEESEWAF_CWEDP_REAL_ROUTE_PORT`，由真实 mTLS peer 提供签名包。缺少变量不会跳过测试或升级状态，仍按 blocker 失败。GitHub Actions 的 `production-acceptance-integration` job 使用隔离 PostgreSQL/Redis 服务和相同测试 runner，锁住迁移/session、CRP 激活及精确回滚的生产组合回归；job 通过只证明可复跑的本地 production wiring 集成验收，不等同于云端部署或公网 egress 验收。

| Gate | 覆盖范围 | 正向证据 | 负向证据 | 当前状态 |
| --- | --- | --- | --- | --- |
| temporary_get_started | temporary Get Started 初始化与清理 | 就绪、运行时目录隔离 | 模板不变、清理信息 | 通过即算 |
| control_health_ready_status | cheesewaf-control healthz、readyz、status | 未就绪时 health/status 可诊断、写入 503 | 非 GET 返回 405 | 通过即算 |
| control_postgres_dsn | PG DSN 必填与脱敏 | status 不暴露 DSN | 缺 DSN、非法身份在后端打开前拒绝 | 通过即算 |
| native_raft_single_node_restart | native-raft 单节点、重启、fence | bootstrap、持久化 term/fence | temporary profile 或隐式 mode 拒绝 | 通过即算 |
| native_raft_join_only | join-only 节点 | 显式 leader join 与提交复制 | join-only 不静默 bootstrap | 通过即算 |
| production_serve_fail_closed | 主 serve 的生产存储边界 | 不回退 SQLite | nil/不可用生产 store 拒绝 | 通过即算 |
| production_fail_closed | 生产 profile fail-closed smoke | 生产配置契约 | 不创建 cheesewaf.db fallback | 通过即算 |
| switch_migration_session_invalidation | temporary 到 production 切换 | `--full` 使用真实 PostgreSQL/Redis，执行 PG recovery/cutover 分类与 production `runServe` 登录、旧 Session 失效集成探针 | 缺任一依赖时保留 blocker；不完整或歧义 cutover 被拒绝 | 通过；公网测试节点完整矩阵已复核；缺依赖的 `--static` 仍报告 blocker |
| crp_verify | CRP 离线 verify | manifest、来源、时间和摘要校验 | 缺信任根/来源/时间/摘要拒绝 | 通过即算 |
| crp_stage | CRP 离线 stage | verified 包只进入 staged slot | 高风险确认和 bypass 拒绝 | 通过即算 |
| crp_activation | CRP observe/canary/active | `--full` 真实 production `runServe` route 使用 PostgreSQL approval/audit 与 mTLS control-plane/sidecar 执行 activation | 缺 PostgreSQL、Redis 或受限 sidecar registry 时保留 blocker；拒绝无效授权与 sidecar 请求 | 通过；公网测试节点完整矩阵已复核；多节点长期部署仍另行验收 |
| crp_rollback | CRP last-known-good rollback | 同一真实 route 探针验证精确 previous 版本回滚、fence、授权和持久审计 | 不允许任意目标、重放或绕过审批；缺依赖时保留 blocker | 通过；公网测试节点完整矩阵已复核；多节点长期部署仍另行验收 |
| approval_http | approval request/confirm/replay HTTP | server warning、绑定、并发单提交 | spoof、scope 变化、replay、无 verifier、坏 JSON 拒绝 | 通过即算 |
| token_strict_identity | Token/Session 严格身份 | canonical identity、epoch、opaque secret | 空白、控制、不可见字符拒绝且不 TrimSpace | 通过即算 |
| diagnostics_encryption | 诊断 envelope | 独立 DEK、AAD、key 擦除与 rewrap | replay、未知字段、旧 key、非法 identity 拒绝 | 通过即算 |
| diagnostics_queue | 本地加密诊断队列 | 重启、密文、幂等、单 worker | 容量、过期、损坏、unsafe identity、重试边界 | 通过即算 |
| diagnostics_runtime_delivery | 诊断组合运行时 | broker→canonical envelope→持久队列→失败重试→metadata-only 审计 | 损坏/篡改拒绝；replay commit 不确定性只审计，不重复外部上传 | 通过即算；不代表对象存储或外部回执已上线 |
| offline_no_egress | 离线模式与外连策略 | offline/registered source 可用 | 未登记目标和网络外连拒绝 | 通过即算 |
| temporary_network_confirmation | 显式 local temporary-online broker 与生产 provider | 一次性确认、密码复核、直连 IP/TLS pin、结果与 revoke 耐久元数据审计、session/lease 清理；主 `serve` 已接入 session-bound provider、runtime-owned CWEDP registry/intent verifier/PG resume store 和动态 lease 生命周期 | 缺任一真实依赖或公网回连条件时保留 blocker；无效签名、pin、Session 和租约必须拒绝 | 通过；2026-09-25 公网测试节点完成真实 HTTPS 与 CWEDP mTLS 演练 |
| digest_resume | CWEDP 三摘要与断点续传 | HELLO、Range、切源、quarantine | digest、offset、chunk、budget 边界拒绝 | 通过即算 |
| audit_recovery_rollback | audit/recovery/rollback contract | 哈希链、耐久通道、阈值恢复 | replay、stale、corrupt、regression 拒绝 | 通过即算 |
| production_artifact_scan | Web/release 产物门禁 | 扫描实际产物，构建使用 `npm ci --ignore-scripts` | 依赖目录、源码目录、符号链接、不安全归档路径或缺失产物均 fail-closed | 通过即算 |
| cleanup_no_tracked_pollution | 清理与工作区污染 | 子进程结束、临时根删除、源模板和 git status 不变 | 任一差异导致失败 | 通过即算 |

JSON 报告的 schema_version 为 2，summary 包含 total、passed、failed、skipped（固定为 0）。每个 gate 至少包含：

在 2026-09-11 允许本机 loopback 的受控环境中，static matrix 得到 19 项通过、4 项失败、0 项跳过；四项失败仍是明确未接线的 migration/session、CRP activation、CRP rollback 和 temporary-network production lifecycle。桌面 sandbox 若禁止 loopback，native-raft、TLS transport、offline/no-egress 和 digest/resume 测试仍会保留环境失败证据；不能因此修改 `implemented` 状态或把失败改成 skipped。

2026-09-25 本机 `--full` 使用真实 PostgreSQL、Redis、production `runServe` 与 mTLS sidecar 完成迁移/session、CRP activation/rollback 探针；矩阵结果为 22 passed、1 failed、0 skipped。随后在公网测试节点 `156.239.4.159` 上以 Go 1.26.6、PostgreSQL 17.11、Redis 8.0.2 和私有 Go 临时目录运行同一 `--full` 矩阵，结果为 **23 passed、0 failed、0 skipped**。该运行包含公网 IP 回连、高端口 `49152`、真实 TLS 1.3 双向证书、签名 CRP 包、PostgreSQL resume store、example.com HTTPS pin、Session/lease 撤销和清理门禁；报告已保存为测试节点外部临时产物，未写入源码树。缺少变量时 `--static`/`--full` 仍按 blocker 失败，不能用本地成功替代部署条件。

    id, title, status, implemented, scope, blockers
    positive: status, command, assertion, evidence
    negative: status, command, assertion, evidence

cleanup 对象记录 runtime_removed、processes_stopped、source_template_unchanged 和 tracked_worktree_unchanged。每条 probe 都在独立进程组中执行；直接子进程退出后还会检查该进程组是否残留成员，发现后台子进程时终止进程组并把 probe 与 cleanup gate 标记为失败。产物扫描检查目录、tar.gz/zip 成员、符号链接与路径边界；不存在可扫描产物时也失败，避免空目录假绿。

矩阵退出码为：所有 gate 通过且 skipped 为 0 时返回 0；任一 gate failed 时返回 1。已知未接线能力的失败是发布和迁移决策输入，不得改写成 skipped。
