# 独立控制面运行时

`cheesewaf-control` 是独立的控制面进程。它负责打开 PostgreSQL 控制状态、native-raft 和 fencing 合约，并提供本机状态接口。它不处理 WAF 请求，也不在请求线程中访问数据库或 Raft。

## 启动条件

进程只接受 `production` profile。必须提供：

- 严格的 `cluster-id` 和可选 `node-id`；
- 独立的 loopback 管理 HTTP 地址和 native-raft 地址；
- PostgreSQL management DSN；远程 DSN 必须启用证书校验；
- 明确的 `bootstrap` 或 `join` 模式；
- native-raft 数据目录。

启动顺序固定为：PG 迁移和健康检查、读取 durable snapshot、Raft 迁移和健康检查、比较两份 snapshot、建立 fencing、再次确认 leader/epoch 没有变化，最后才进入 ready。任何一步失败都会冻结写入，并保留 last-known-good。DSN、密码和后端原始错误不会写入状态响应。

双方都为空时必须走受保护的 `InitialStateRequest`，携带管理员确认对象；没有确认
或外部 `InitialStateAuthorizer` 拒绝时，进程保持 frozen。已有 payload 只允许通过
`LeadershipCheckpointStore` 记录 term/epoch/leader 变化，不能把 PG 旧快照直接替换成
native-raft 新快照。

首次初始化不能靠“空快照自动生成”绕过确认。初始 desired state 导入、临时模式迁移和生产切换需要单独的受保护流程；当前独立进程只接受双方已有且一致的状态，未满足条件时启动失败并保持 fail-closed。

## 状态接口

默认监听 `127.0.0.1`：

- `GET /healthz`：进程存活；frozen 状态也可以返回 200。
- `GET /readyz`：只有 snapshot、leader 和 fencing 全部有效时返回 200，否则返回 503。
- `GET /status`：返回 phase、leader、term、epoch、revision 和冻结原因，不返回凭据或 DSN。
- `POST /proposals`：未进入 write-ready 前固定返回 503；当前二进制尚未挂载完整 proposal transport，ready 后仍返回明确的 501，而不是接受未授权写入。

远程暴露必须另行配置 TLS、mTLS、ACL、审计和回滚。不能把 loopback 状态接口当作集群 API。

## 节点角色

`bootstrap` 节点可以在 native-raft 建立初始成员；`join` 节点不会自行 bootstrap，只能由已有 leader 显式加入。follower 可以同步状态，但不能使用本机身份伪造 leader fence。
follower 的状态接口可以报告 ready/read-only：它能够读取和复制已提交快照，但
`Propose`、`Join` 和 `Establish` 仍要求本机是当前 leader。失去 leader、成员关系
丢失、重启后 fencing 未重新建立，均降为 frozen/read-only，直到再次完成双快照
校验和当前 fence。

`cheesewaf serve` 仍使用原有 temporary SQLite 路径。它的 production profile 在完整 management `storage.Store`、控制面生命周期、Redis、审批和数据面接线完成前继续拒绝启动。独立 `cheesewaf-control` 的可运行性不等于主 WAF 已完成 HA。

## 命令示例

```text
cheesewaf-control --help
cheesewaf-control --profile production --cluster-id cluster-a \
  --data-dir /var/lib/cheesewaf/control \
  --listen 127.0.0.1:9450 --raft-listen 127.0.0.1:9451 \
  --mode join --postgres-dsn '<由受保护服务配置提供>'
```

生产环境不要把 DSN 写入 shell 历史或公开日志。建议由 systemd credential、受保护环境文件或外部密钥管理器提供。
