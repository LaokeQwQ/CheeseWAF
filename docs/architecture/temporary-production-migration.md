# 从 temporary 迁移到 production

主程序已经注册以下两个命令：

```text
cheesewaf migration temporary-to-production
cheesewaf migration recover
```

第一个命令把管理数据从 temporary 模式的 SQLite 迁入 production 模式的 PostgreSQL。第二个命令处理迁移期间的进程崩溃或提交结果不明。只要恢复记录或迁移标记仍在，`cheesewaf serve` 就会拒绝启动管理服务。

迁移不会直接修改 WAF 数据面的已提交防护状态。迁移失败时，数据面继续使用原来的 last-known-good 状态。

当前主 `cheesewaf serve` 的 production 消费者和生产 Approval 服务仍未全部接好。迁移命令和恢复路径已经存在，但在这部分接线完成前，不应把它当成可直接迁移线上主服务的发布能力。

## 已接线的本地生命周期边界

当前仓库已经把 temporary 侧的安全生命周期接成一个可验证的最小纵切片：

1. 迁移源先写入 `temporary-to-production.recovery.json` 和 `temporary-to-production.pending`，随后在同一 SQLite 连接上提升所有用户的 `credential_epoch` 并撤销全部 admin Session。
2. `cheesewaf serve` 在创建运行目录、PID lease 或任何 listener/backend 之前检查 recovery 记录和 pending fence；任一文件缺失、损坏、权限不安全或处于未完成状态都保持 fail-closed。
3. 迁移回滚从快照恢复用户 epoch、Session 和 temporary 文件，并只在恢复成功后删除 fence；因此旧 Session 只能在明确回滚后重新有效。

`internal/cli/migration/recovery_test.go` 的
`TestTemporaryInvalidationBindsSessionEpochToServeFenceAndRollback` 覆盖这条链路：失效后旧 Session 不活跃且 serve 被 fence 阻止；恢复后 Session 和 fence 同时回到 last-known-good。该测试是本地 SQLite/文件边界证据，不代表真实 PostgreSQL、Redis、native-raft 或审批 consumer 已部署。

## 迁移前准备

迁移前必须满足以下条件：

1. `--config` 指向运行时配置副本，例如 `data/config/cheesewaf.yaml`。命令拒绝修改仓库中的 `configs/cheesewaf.yaml` 模板。
2. 当前配置的 `storage.profile` 为 `temporary`，SQLite 路径可读写。
3. production 配置已经填写两个不同的 PostgreSQL DSN：`storage.management_postgresql.dsn` 和 `storage.control_postgresql.dsn`。
4. Redis 已启用，并设置严格的 `storage.redis.instance_id`。
5. native-raft 已明确设置 `data_dir`、`listen` 和 `mode`。`mode` 只能是 `bootstrap` 或 `join`。
6. 集群互联已经配置 CA、证书和私钥。管理地址默认仍应监听 loopback。
7. PostgreSQL、Redis 和 native-raft 都可用。生产依赖缺失时，命令会直接失败，不会回退到 SQLite。
8. 操作者持有当前本地管理员 Session，并能再次输入管理员密码或一次性 TOTP。

身份字段必须保持原样。命令会拒绝前后空格、控制字符和不可见空白，不会通过 `TrimSpace` 修改管理员、Session、集群或节点身份。

## 执行迁移

下面的例子使用中文确认短语和密码复核。Shell 变量不需要导出：

```bash
read -r -s CHEESEWAF_MIGRATION_SECRET
printf '%s\n确认\nyes\n' "$CHEESEWAF_MIGRATION_SECRET" |
  ./cheesewaf \
    --config ./data/config/cheesewaf.yaml \
    --data-dir ./data \
    migration temporary-to-production \
    --actor admin-id \
    --session-id session-id \
    --language zh-CN \
    --password-stdin
unset CHEESEWAF_MIGRATION_SECRET
```

使用 TOTP 时，把 `--password-stdin` 改为 `--totp-stdin`。英文确认短语是精确的 `CONFIRM`。简体中文是“确认”，繁体中文是“確認”。普通迁移的第二次确认可输入 `yes` 或 `y`。

命令会依次显示两条警告。每条警告都由服务端等待至少 10 秒，然后才读取确认短语。提前把输入写进管道不会跳过这段等待。

## 提交顺序

迁移严格按以下顺序执行：

1. 进程取得独占运行锁，再重新读取配置。锁等待期间配置发生变化时，迁移终止。
2. 命令验证管理员 Session、密码或 TOTP，并创建一次性确认 ID。
3. SQLite 导出有序、不可变的管理快照。快照包含用户、站点、规则、通知、复核记录、临时升档、TOTP 消费记录和用户名修复审计。
4. 命令先写恢复记录，再写迁移标记。恢复目录权限为 `0700`，恢复文件权限为 `0600`。
5. 命令使 temporary 管理员 Session、setup URL、join token、CAPTCHA 状态和进程内锁失效。
6. 管理 PostgreSQL 以可串行化事务取得迁移锁，并确认目标管理表为空。
7. 同一事务导入管理快照。用户的 `credential_epoch` 会增加 1，使迁移前凭据失效。
8. 同一事务保存旧管理 API Token 的非秘密元数据，并把状态固定为 `revoked`。旧 Token 散列不会写入生产表。
9. 同一事务写入 `cheesewaf_migration_cutovers`，其中包含 Token 元数据摘要。管理数据、Token 元数据和提交记录要么一起提交，要么一起回滚。
10. 提交前，本地迁移标记改为 `commit-attempted`。这个标记只用于诊断，不能替代 PostgreSQL 的实际状态。
11. PostgreSQL 提交成功后，命令初始化或修复 control PostgreSQL 与 native-raft 的 revision 1 状态。
12. 命令保存 production 配置，最后删除恢复记录和迁移标记。

如果 PostgreSQL 可能已经提交，命令不会自动恢复 temporary 凭据。恢复方向必须由后续的 `migration recover` 根据数据库状态重新判断。

## 处理中断的迁移

先停止所有 CheeseWAF 管理进程，保留 `data/migration/` 中的文件，不要手工修改或删除。然后执行恢复命令：

```bash
read -r -s CHEESEWAF_RECOVERY_SECRET
printf '%s\n确认\nyes\n' "$CHEESEWAF_RECOVERY_SECRET" |
  ./cheesewaf \
    --config ./data/config/cheesewaf.yaml \
    --data-dir ./data \
    migration recover \
    --actor admin-id \
    --language zh-CN \
    --password-stdin
unset CHEESEWAF_RECOVERY_SECRET
```

恢复命令不接受 `--session-id`。迁移已经使旧 Session 失效，因此恢复会直接在 SQLite 或 PostgreSQL 中验证管理员密码或 TOTP。TOTP 只能使用一次。

恢复命令的第二次确认必须输入完整的 `yes`，不能简写为 `y`。

恢复方向只由 PostgreSQL ledger 和实际管理表决定：

- ledger 不存在，且所有目标管理表都为空：恢复 temporary 状态。
- ledger 与恢复记录一致，目标管理表逐表、逐行匹配迁移快照，并且旧 Token 元数据完整：继续完成 production 配置和控制面初始化。
- ledger 不一致、表中出现多余或缺失数据、快照不匹配，或数据库不可读：状态不明确，命令停止，不做自动恢复。

本地 `pending` 或 `commit-attempted` 标记只提供崩溃位置线索。进程可能在写完 `commit-attempted` 后、调用 PostgreSQL 提交前崩溃，因此标记不能否决数据库已经证明的回滚方向。

如果当前配置已经是 production，恢复命令还会确认配置内容与私有恢复记录完全一致。production 配置发生漂移时，命令拒绝继续。数据库证明应回滚时，当前配置必须仍是 temporary。

## 状态不明确时怎么处理

`ErrCutoverAmbiguous` 表示自动恢复无法证明安全方向。此时不要删除恢复记录，也不要使用手工 SQL 补行后重试。按以下步骤处理：

1. 保持主服务停止，并备份运行时配置、`data/migration/`、SQLite、两个 PostgreSQL 数据库、Redis 和 native-raft 数据目录。
2. 只读检查 `cheesewaf_migration_cutovers` 中对应 `snapshot_id` 的记录，以及所有迁移管理表的行数。
3. 确认所有组件来自同一次备份或同一个已验证的提交点。不能确认时，恢复整套管理 PostgreSQL、control PostgreSQL、Redis 和 native-raft 备份，不要只恢复一个组件。
4. 在隔离环境运行 `migration recover`。确认恢复方向和数据后，再恢复生产流量。

当前命令没有 `--force`、`--skip-confirmation` 或客户端“已确认”开关。状态不明确时必须修复底层数据或从一致备份恢复，不能绕过检查。

## v1 ledger 的升级边界

当前管理 PostgreSQL schema 版本为 v2。v1 只记录了迁移 ledger，没有记录旧管理 API Token 的非秘密元数据。升级 v1 表时，`token_metadata_digest` 会填入全零哨兵值；恢复命令会把它识别为 `unverified-v1`，返回 `ErrCutoverTokenMetadataUnverified`（同时属于 `ErrCutoverAmbiguous`），不会自动完成 production，也不会选择回滚。

这是一条有意的停止路径，不是可以手工补摘要的兼容模式。支持的处理顺序是：

1. 停止主服务，保留恢复记录、迁移标记和原始数据库，不删除或改写 ledger。
2. 为 temporary SQLite、management PostgreSQL、control PostgreSQL、Redis 和 native-raft 保存经过校验的备份，并记录各自的备份时间和校验值。
3. 如果有迁移前的一致备份，先在隔离环境恢复整套 temporary 状态和目标数据库，确认目标没有残留后，使用当前版本重新执行完整迁移。
4. 如果没有一致备份，停止自动恢复并交由人工取证；不得直接把全零哨兵更新成猜测的摘要，也不得只恢复其中一个数据库后重试。

当前版本没有提供把 v1 ledger 原地提升为已验证 v2 ledger 的命令。只有重新生成完整的旧 Token 元数据快照、在同一事务中写入审计行并重新建立摘要证明后，才可以增加这样的迁移工具；在此之前，`unverified-v1` 必须保持 fail-closed。

## 恢复记录中的敏感数据

恢复记录包含一份完整的 production YAML，因此可能包含 PostgreSQL DSN、API Key、JWT 密钥和其他运行秘密。它只保存在本机 `0600` 文件中，不应复制到日志、工单或源码仓库。

写入 control PostgreSQL 和 native-raft 的不是完整 YAML，而是一个不含秘密的 JSON 描述。描述只包含配置摘要、profile、集群和节点身份、后端类型及 Redis 实例身份。读取本地恢复记录时只做结构校验，不解析 AI 服务域名，也不发起 DNS 或 HTTP 请求。

## 验证

聚焦测试：

```bash
go test ./internal/setup/migration ./internal/cli/migration ./internal/controlplane ./internal/controlplane/postgres -count=1
go test -race ./internal/setup/migration ./internal/cli/migration ./internal/controlplane ./internal/controlplane/postgres -count=1
go vet ./internal/setup/migration ./internal/cli/migration ./internal/controlplane ./internal/controlplane/postgres

# 有隔离的真实 PostgreSQL 时，再运行 v1→v2 与 exact-match 集成测试
CHEESEWAF_POSTGRES_TEST_DSN='postgres://<user>:<password>@<host>/<db>?sslmode=verify-full' \
  go test ./internal/cli/migration -run 'TestPostgres' -count=1
```

没有设置真实数据库测试 DSN 时，包级测试只能证明事务顺序、失败处理和恢复判断，不能当成真实数据库演练记录。集成测试必须使用隔离 schema 和最小权限账号，不得把生产数据库作为测试目标。

迁移会撤销配置文件中的旧管理 API Token，并清除其散列。旧 Token 的 ID、名称、前缀、权限范围、时间和原启用状态会写入 `cheesewaf_migration_legacy_tokens`，用于审计和恢复核对。当前代码还没有把这些 Token 接入独立的生产 Token 服务；迁移完成后应重新签发，而不是尝试恢复旧 Token。
