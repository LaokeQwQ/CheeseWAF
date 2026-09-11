# CheeseWAF acceptance matrix v2

这是 CheeseWAF 控制面、数据面边界和交付产物的端到端验收入口。脚本只把运行时状态写入系统临时目录，报告写入仓库外路径；不启动 PostgreSQL 或 Redis，也不改写 configs/cheesewaf.yaml、tasks.md 或 README。

运行完整矩阵：

    bash scripts/acceptance/matrix.sh --full

在没有启动 WAF 进程的情况下运行同一套契约：

    bash scripts/acceptance/matrix.sh --static

列出 gate：

    bash scripts/acceptance/matrix.sh --list

默认报告是 /tmp/acceptance_e2e_matrix_v2_report.json 和 /tmp/acceptance_e2e_matrix_v2_report.md。也可以用 --report PATH 与 --markdown PATH 指定仓库外路径；脚本拒绝仓库内报告路径，避免把运行结果写进工作区。报告文件使用私有权限。

每个 gate 都执行一条预期成功的正向命令和一条预期拒绝或边界的负向命令。两侧都保存命令、断言、退出状态和输出证据。代码或运行时尚未接线的能力使用 implemented: false、status: failed 和 blockers 字段表示；没有 skipped 状态。

| Gate | 覆盖范围 | 正向证据 | 负向证据 | 当前状态 |
| --- | --- | --- | --- | --- |
| temporary_get_started | temporary Get Started 初始化与清理 | 就绪、运行时目录隔离 | 模板不变、清理信息 | 通过即算 |
| control_health_ready_status | cheesewaf-control healthz、readyz、status | 未就绪时 health/status 可诊断、写入 503 | 非 GET 返回 405 | 通过即算 |
| control_postgres_dsn | PG DSN 必填与脱敏 | status 不暴露 DSN | 缺 DSN、非法身份在后端打开前拒绝 | 通过即算 |
| native_raft_single_node_restart | native-raft 单节点、重启、fence | bootstrap、持久化 term/fence | temporary profile 或隐式 mode 拒绝 | 通过即算 |
| native_raft_join_only | join-only 节点 | 显式 leader join 与提交复制 | join-only 不静默 bootstrap | 通过即算 |
| production_serve_fail_closed | 主 serve 的生产存储边界 | 不回退 SQLite | nil/不可用生产 store 拒绝 | 通过即算 |
| production_fail_closed | 生产 profile fail-closed smoke | 生产配置契约 | 不创建 cheesewaf.db fallback | 通过即算 |
| switch_migration_session_invalidation | temporary 到 production 切换 | 迁移、恢复、Session、credential epoch 契约 | 主 `serve` 生命周期仍未挂载迁移和 Session 失效 | failed，待主服务接线 |
| crp_verify | CRP 离线 verify | manifest、来源、时间和摘要校验 | 缺信任根/来源/时间/摘要拒绝 | 通过即算 |
| crp_stage | CRP 离线 stage | verified 包只进入 staged slot | 高风险确认和 bypass 拒绝 | 通过即算 |
| crp_activation | CRP observe/canary/active | activation service、mTLS transport 和 TLS 1.3/RequireAndVerifyClientCert 服务端构造的原子晋级，CLI 在适配器不可用时保持 staged/current 不变 | 已部署的 control-plane/sidecar 服务及持久授权/审计不在本仓库 | failed，待部署交接 |
| crp_rollback | CRP last-known-good rollback | 精确 previous、fence 与目标校验，CLI 不接受旧 authority/bypass 参数；mTLS rollback transport 有独立测试 | 已部署的 control-plane/sidecar 服务及持久授权/审计不在本仓库 | failed，待部署交接 |
| approval_http | approval request/confirm/replay HTTP | server warning、绑定、并发单提交 | spoof、scope 变化、replay、无 verifier、坏 JSON 拒绝 | 通过即算 |
| token_strict_identity | Token/Session 严格身份 | canonical identity、epoch、opaque secret | 空白、控制、不可见字符拒绝且不 TrimSpace | 通过即算 |
| diagnostics_encryption | 诊断 envelope | 独立 DEK、AAD、key 擦除与 rewrap | replay、未知字段、旧 key、非法 identity 拒绝 | 通过即算 |
| diagnostics_queue | 本地加密诊断队列 | 重启、密文、幂等、单 worker | 容量、过期、损坏、unsafe identity、重试边界 | 通过即算 |
| diagnostics_runtime_delivery | 诊断组合运行时 | broker→canonical envelope→持久队列→失败重试→metadata-only 审计 | 损坏/篡改拒绝；replay commit 不确定性只审计，不重复外部上传 | 通过即算；不代表对象存储或外部回执已上线 |
| offline_no_egress | 离线模式与外连策略 | offline/registered source 可用 | 未登记目标和网络外连拒绝 | 通过即算 |
| temporary_network_confirmation | 显式本地 temporary-online broker | 一次性确认、密码复核、直连 IP/TLS pin、结果与 revoke 耐久元数据审计、session/lease 清理 | 主 `serve`、插件控制面和持久租约生命周期尚未接入该本地探针；CWEDP 使用独立 broker-bound transport，生产控制面尚无可创建该 broker 并传递可撤销管理 Session 的适配器 | failed，保留未接线 blocker |
| digest_resume | CWEDP 三摘要与断点续传 | HELLO、Range、切源、quarantine | digest、offset、chunk、budget 边界拒绝 | 通过即算 |
| audit_recovery_rollback | audit/recovery/rollback contract | 哈希链、耐久通道、阈值恢复 | replay、stale、corrupt、regression 拒绝 | 通过即算 |
| production_artifact_scan | Web/release 产物门禁 | 扫描实际产物且 build 设置 CHEESEWAF_AGENT_EYES=0、npm ci --ignore-scripts | marker 或缺失产物 fail-closed | 通过即算 |
| cleanup_no_tracked_pollution | 清理与工作区污染 | 子进程结束、临时根删除、源模板和 git status 不变 | 任一差异导致失败 | 通过即算 |

JSON 报告的 schema_version 为 2，summary 包含 total、passed、failed、skipped（固定为 0）。每个 gate 至少包含：

在 2026-09-11 允许本机 loopback 的受控环境中，static matrix 得到 19 项通过、4 项失败、0 项跳过；四项失败仍是明确未接线的 migration/session、CRP activation、CRP rollback 和 temporary-network production lifecycle。桌面 sandbox 若禁止 loopback，native-raft、TLS transport、offline/no-egress 和 digest/resume 测试仍会保留环境失败证据；不能因此修改 `implemented` 状态或把失败改成 skipped。

    id, title, status, implemented, scope, blockers
    positive: status, command, assertion, evidence
    negative: status, command, assertion, evidence

cleanup 对象记录 runtime_removed、processes_stopped、source_template_unchanged 和 tracked_worktree_unchanged。产物扫描使用二进制内容、tar.gz/zip 成员和文本文件扫描 agent-eyes、code-inspector、codex-acp；不存在可扫描产物时也失败，避免空目录假绿。

矩阵退出码为：所有 gate 通过且 skipped 为 0 时返回 0；任一 gate failed 时返回 1。已知未接线能力的失败是发布和迁移决策输入，不得改写成 skipped。
