# native-raft 传输和数据目录安全边界

native-raft 的生产 transport 必须使用双向 TLS。调用方通过 `nativeraft.Options.TLS` 提供 CA、节点证书和私钥文件；CA、证书和私钥必须是运行用户拥有的常规文件，私钥权限必须为 `0600`，CA/证书权限只能为 `0600` 或 `0644`。节点证书必须在 SAN 中包含配置的 `NodeID`，否则启动失败。Raft transport 使用 `RequireAndVerifyClientCert`，对端证书链必须由配置 CA 验证。

`InsecureTestMode` 是测试专用旁路，只接受 loopback bind address。它不会因为 `Profile=production` 而自动放行；生产进程必须提供 TLS/mTLS 配置。未识别的平台没有安全文件实现，会 fail-closed。

fresh TLS join 必须配置至少一个受信任 seed voter，格式为节点 ID 与 native-raft peer `host:port`。主服务和迁移恢复从 `cluster.consensus.native_raft.initial_voters` 读取；独立 `cheesewaf-control` 使用可重复的 `--initial-voter node-id=host:port`。这些 voter 是节点尚无持久 Raft membership 时的入站证书身份 allowlist，不会从普通集群节点清单推导。持久 membership 已存在的节点重启不要求重复配置 seed voter。ID、地址或端口缺失、重复或无效时启动拒绝。

native-raft 数据目录及其新建的目录组件使用 `0700`。启动逐级使用 `Lstat` 检查路径，拒绝符号链接和非目录；最终数据目录必须由运行用户拥有且权限精确为 `0700`。`node-id`、`address` 和 Raft Bolt 数据库使用 `0600`，身份和地址通过临时文件写入、`fsync`、原子 rename 及父目录同步持久化。已有身份、地址或数据库文件若为符号链接、非普通文件、非当前用户所有或权限不正确，启动立即失败。

standalone `cheesewaf-control` 入口必须显式提供 CA/cert/key；缺少映射时 native-raft 会拒绝启动，而不会回退到明文 TCP。
