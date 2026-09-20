# Migration → production hand-off contract

临时模式迁移到 production 的启动器必须把一次迁移的元数据证明显式交给
production composition root。该证明不携带密码、Token 或数据库快照内容，只包含：

- 配置和候选配置的 64 位十六进制摘要；
- cluster ID、snapshot ID、snapshot proof 和 durable ledger proof；
- 已验证的 token metadata 摘要；
- `Sessions`、`Setup`、`Join`、`CAPTCHA`、`Locks` 五项 temporary invalidation 回执。

`internal/setup/migration.ValidateProductionHandoffProof` 负责结构校验和 cluster 绑定，
`ProductionHandoffVerifier` 负责访问具体 durable ledger 并拒绝过期或不可验证的证明。
`internal/cli` 的 production temporary-network provider 必须显式注入该 verifier；缺少
provider、verifier、durable audit sink 或管理会话时，启动保持 fail-closed。

这个 seam 不证明真实 PostgreSQL、ledger provider、CRP 或 production 网络已经部署；它只
保证这些外部证据在进入 serving layer 前不能被省略或用本地状态替代。
