# 更新记录

## 未发布

- 增加 SQLite 版本化迁移和过新数据库版本保护。
- 修复语义评测的分片一致性、缓存 TTL 抖动和在线/离线 paranoia parity。
- 将 Prometheus remote-write 改为 protobuf 加 Snappy 协议。
- 加强 AI 审批的预览状态校验、角色权限和日志读取权限。

## 版本约定

正式版本使用 `vMAJOR.MINOR.PATCH` 标签。发布前请阅读 [`docs/release.md`](docs/release.md)。
