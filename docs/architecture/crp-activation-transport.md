# CRP Activation and Rollback Transport

状态：客户端 transport boundary、控制面授权 handler 和服务端 TLS 配置边界已实现并有真实 TLS 集成测试；生产 provider、持久授权/审计状态和 sidecar launcher 的部署接线不在本文交付范围内

协议版本：`crp-activation-transport.v1`

## 边界

`internal/crp/activation` 负责把已经写入 `RuntimeStore` 的 CRP 从 `staged` 推进为
`observe -> canary -> active`，或者把 `previous` 指向的 last-known-good 版本作为新的
revision 回滚。它不接受调用方提供的 fence 或 confirmation，也不负责 CRP 下载、导入、
迁移、netlease 或 WAF 请求线程内执行。

`cheesewaf crp activate` 和 `cheesewaf crp rollback` 是当前 CLI 挂载入口。两者先从运行时目录
读取目标记录，重新执行 manifest、artifact、签名、信任根、来源注册和吊销检查，再读取
sidecar descriptor。descriptor 的 plugin、version、namespace、source、source root、manifest
identity 和 artifact identity 必须与已签名记录精确一致。只有本地准入通过后才构造网络客户端。

`--now` 仅是可复现的包验证时间。control-plane 授权、authorization TTL、fence TTL 和异步
operation timeout 使用实时系统时钟，不能用历史 `--now` 延长授权。

## mTLS 身份

control-plane 和 sidecar launcher 只接受 HTTPS origin。客户端固定 TLS 1.3 最低版本、系统外的
显式 CA、禁止代理、禁止 redirect，并限制单个 JSON 响应为 64 KiB。两个 endpoint 分别建立
client，但必须从同一证书导出完全相同的 `TransportIdentity`：

- `cluster_id`：CLI 的显式 cluster identity；
- `node_id`：客户端证书必须包含完全相同的 DNS SAN；
- `role`：activation 固定为 `waf`；
- `certificate_sha256`：leaf certificate DER 的 SHA-256；
- leaf subject CN：必须精确等于 `<cluster_id>/waf/<node_id>`。

CA 和 certificate 必须是 mode `0600` 或 `0644` 的普通非符号链接文件；private key 必须是
mode `0600` 的普通非符号链接文件。证书链、client-auth EKU、SAN、CN、角色或文件权限任一不符，
都会在建立网络连接和改变 RuntimeStore 前失败。

CLI 必需的 transport 参数是：

```text
--cluster-id --node-id
--control-plane --sidecar
--tls-ca --tls-cert --tls-key
--transport-timeout --operation-timeout
```

`--control-plane-server-name` 和 `--sidecar-server-name` 可显式指定各自的 server SAN；省略时按
HTTPS endpoint hostname 校验证书。CLI 不暴露 `--fence-token`、epoch、fence revision、
confirmation ID 或 confirmation actor 等原始授权输入。

## Control-plane 协议

所有请求使用 `POST`、`Content-Type: application/json` 和
`X-CheeseWAF-Transport-Schema: crp-activation-transport.v1`。响应必须是严格 JSON：未知字段、
尾随值、错误 content type、redirect、非 200 状态和超限 body 都失败关闭。

| Endpoint | 请求 | 成功响应 |
| --- | --- | --- |
| `/v1/crp/activation/authorize` | `AuthorizationRequest` | operation-bound `Authorization` |
| `/v1/crp/activation/validate` | authorization envelope | `valid` acknowledgement |
| `/v1/crp/activation/consume` | authorization envelope | `consumed` acknowledgement |

## 服务端挂载边界

控制面可以把 `ControlPlaneHandler` 作为受保护 HTTPS listener 的 handler，并使用
`NewControlPlaneServerTLSConfig(ServerTLSOptions{CAFile, CertFile, KeyFile})` 构造
TLS 配置。该配置固定要求 TLS 1.3、服务端证书链验证和
`RequireAndVerifyClientCert`；handler 还会逐请求验证 client certificate 的 cluster、role、
NodeID SAN 和证书指纹。服务端必须把 `ControlPlaneHandlerOptions.State` 注入跨进程可恢复的
持久实现，并把 `Provider` 注入真实的 permission、fence、confirmation 和审计适配器。

示意挂载（不包含 provider 或密钥来源）：

```go
handler, err := activation.NewControlPlaneHandler(activation.ControlPlaneHandlerOptions{
    ClusterID: "cluster-a", ClientCA: clientRoots, State: durableState, Provider: provider,
})
tlsConfig, err := activation.NewControlPlaneServerTLSConfig(activation.ServerTLSOptions{
    CAFile: caFile, CertFile: certFile, KeyFile: keyFile,
})
server := &http.Server{Addr: listen, Handler: handler, TLSConfig: tlsConfig}
```

这只是可注入的服务端 endpoint，不等同于 `cheesewaf-control` 已经拥有 CRP provider、持久
authorization state、sidecar launcher 或生产审计部署。缺少任一真实依赖时，调用方必须保持
CRP staged/current/previous 不变并报告 activation/rollback 未接线。

`AuthorizationRequest` 绑定随机 request ID、完整 `TransportIdentity`、action、对应的精确
permission、目标 record、CAS revision、完整 descriptor 及其 SHA-256、canary policy 和请求时间。
permission 映射固定为：

| Runtime action | Permission |
| --- | --- |
| `promote` | `crp.activate` |
| `rollback` | `crp.rollback` |

activation 的 target revision 必须等于 expected revision。rollback 的 target 是
`RuntimeStore.Previous`，其 revision 必须早于 expected revision；expected revision 始终是
当前 active record 的 revision，供 RuntimeStore 做 CAS，不能错误地使用 previous revision。

control plane 返回的 authorization 必须逐字段回显原请求，并携带最多 5 分钟的 fence 和
confirmation。fence 必须属于同一 cluster；confirmation 必须绑定 action、plugin key、manifest
identity 和 expected revision。acknowledgement 必须回显 authorization ID、request ID、node ID
及精确状态。

客户端在 sidecar start 前验证一次 authorization，随后在 start、observe probes、canary mode、
canary probes、active mode 和最终 RuntimeStore 提交之间反复调用 `validate`。任何一次验证拒绝、
超时或 transport 故障都会停止新 sidecar，并保持 staged/current/previous 不变。

confirmation 在客户端进程内是一次性的。`RuntimeStore` 的最终 authorizer 通过同一个 mTLS
control-plane client 调用 `consume`；本地 pending entry 在发出请求前即删除，因此网络结果不明
时也不能重放原 confirmation，重试必须获取新的 authorization。只有 consume 成功、RuntimeStore
再次完成 revalidation/health check 且 CAS 仍成立时，才原子写入新的 revision。

## Sidecar launcher 协议

| Endpoint | 用途 |
| --- | --- |
| `/v1/crp/sidecars/start` | 以 `observe` 模式启动精确 descriptor/target |
| `/v1/crp/sidecars/{handle}/probe` | 探测当前模式健康状态 |
| `/v1/crp/sidecars/{handle}/mode` | 只允许 `observe -> canary -> active` |
| `/v1/crp/sidecars/{handle}/stop` | 失败清理或替换旧 sidecar |

每个 launcher 请求都携带完整 control-plane authorization。launcher response 必须回显同一
authorization ID、request ID、node ID、handle、plugin key、manifest identity、mode 和操作状态；
后续操作的 handle 必须与 start 返回的 handle 完全相同。客户端不会接受跨 handle、跨 node、
跨 plugin 或跨 manifest 的成功回执。

stop 是清理路径，即使原 authorization 刚刚过期，客户端仍会通过已认证 mTLS 尝试 stop；launcher
应允许凭历史 authorization 对同一 handle 做收缩权限的停止操作，不得允许扩大流量模式。

## 异步执行

`SubmitAsync` 使用固定大小的 channel 和固定 worker 数，不为每个请求创建无界 goroutine。
队列已满立即返回 `ErrAsyncQueueFull`。每个 receipt 支持显式取消，并继承提交方 context；排队时间
计入 operation timeout。关闭 Service 会停止接收新请求、取消 queued/in-flight context，并等待
worker 收口。取消、关闭或超时都不直接修改 RuntimeStore。

旧的 `Install`、带原始 fence/confirmation 的 `Activate`/`Rollback`，以及在 `AsyncRequest` 中
注入这两类值的调用，保留源码兼容但恒定返回 `ErrAuthorizationInjection`。

## 失败不变量

- 本地信任、来源或 descriptor 校验失败时不建立 transport；
- authorize response 被篡改时不启动 sidecar；
- fence/authorization 在任一阶段失效时停止新 sidecar；
- observe/canary probe 或 mode transition 失败时停止新 sidecar；
- confirmation consume、fresh revalidation、health check 或 CAS 失败时不提交 runtime revision；
- rollback 只使用 RuntimeStore 保存的 exact previous，不接受任意降级目标；
- revoked manifest 和 blocked version 在申请 rollback authorization 前拒绝。

## 验证范围与剩余责任

`transport_integration_test.go` 使用 `internal/cluster/identity.MemoryIdentityService` 生成同一
cluster CA 下的 server/client certificate，并通过真实 IPv4 loopback TLS 1.3 server 验证完整
authorize、重复 validate、sidecar lifecycle、consume 和 RuntimeStore promotion/rollback 路径。
测试还覆盖 authorization 篡改、进程中 fence 拒绝、sidecar stop、NodeID/SAN 不匹配、private-key
权限和非 HTTPS endpoint。

这些测试证明客户端 wire behavior 和本地状态不变量，不等同于已部署的生产 control-plane 或
sidecar launcher。生产服务仍必须独立验证 client certificate、证书吊销、permission、NodeID、
source/source-root、descriptor/content identity、fence 单调性和 confirmation 一次性消费，并把
授权与审计状态持久化；还需要在部署环境验证 HA、证书轮换、超时、重试、审计和回滚运维流程。
