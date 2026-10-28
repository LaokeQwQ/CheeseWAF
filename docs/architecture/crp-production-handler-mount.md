# CRP Production Handler Mount and Authorization Durability

状态：运行时的显式 CRP handler 挂载边界和授权耐久性 contract 已接入；真实
control-plane provider、持久授权/审计后端、sidecar launcher 与部署交接仍未完成。
本文不把 activation/rollback 验收标记为已完成。

## 目的和边界

`internal/crp/activation` 提供 `/v1/crp/activation/authorize`、`validate` 和
`consume` transport。`internal/controlplane/runtime` 只负责把一个由生命周期拥有者
显式提供的 `ControlPlaneHandler` 挂到控制面 HTTP mux；它不创建默认 handler，不从
`MemoryAuthorizationState` 或普通回调自动拼出生产授权服务。

这项接线解决的是“生产 runtime 是否能明确接收并暴露 CRP authorization handler”的
组合根问题，不解决 handler 背后的生产依赖。CRP 包导入、RuntimeStore、TLS/mTLS
身份校验和本地 activation/rollback contract 仍由各自模块负责；生产 provider、
授权耐久性、审计、sidecar 生命周期和跨节点部署仍需单独验收。

## 显式挂载 contract

生产 launcher 通过 `runtime.Dependencies.CRPActivationHandler` 传入已经构造好的
`*activation.ControlPlaneHandler`，再调用 `runtime.OpenWithDependencies`。runtime
保存同一个 handler 实例，并仅在该字段非空时注册：

```text
/v1/crp/activation/ -> ControlPlaneHandler
```

当字段为空时，CRP activation 路径保持不可达（返回 404）；runtime 不会隐式创建
内存状态、空 provider 或允许所有请求的 no-op handler。`Runtime.CRPActivationHandler`
只用于观察当前是否存在显式挂载，不能被解释为 handler 已经具备生产授权能力。

控制面启动成功也不等于 CRP activation 已就绪。launcher 必须在把 handler 注入
runtime 前完成授权依赖校验；缺少依赖时应保持 CRP staged/current/previous 不变，
并让 activation/rollback 继续 fail-closed。

## 授权耐久性 contract

`ControlPlaneHandler` 的 transport contract 分成两类依赖：

| 依赖 | 最低接口 | 生产要求 |
| --- | --- | --- |
| 待确认授权状态 | `AuthorizationState` | 实现 `DurableAuthorizationState`，且 `Durable()` 返回 `true` |
| 授权与权限 authority | `AuthorizationProvider` | 实现 `DurableAuthorizationProvider`，且 `Durable()` 返回 `true` |

生产挂载前应调用 `activation.ValidateProductionControlPlaneHandler`。它拒绝 nil
handler、缺失 state/provider、仅实现普通接口的测试 double、`MemoryAuthorizationState`
以及任何 `Durable()` 返回 false 的实现。

耐久 state 至少必须保证：

- authorize 写入的完整 authorization binding 可在进程重启后恢复；
- `Get` 与 `Consume` 对 request、cluster、node、role、descriptor、revision、
  confirmation 和 expiry 做精确绑定校验；
- `Consume` 对并发重试原子化，已消费 authorization 不能重放；
- 授权状态与 durable epoch、permission、fence、confirmation 和审计记录使用同一
  个生产一致性边界，失败时不能留下可继续使用的旧代次授权。

耐久 provider 至少必须把 permission、cluster/node 身份、目标插件和 manifest
identity、expected revision、fence、confirmation TTL/一次性消费以及审计结果绑定到
同一个 operation。provider 返回成功不应只代表内存回调执行成功；必须代表这些状态
已经在其声明的 durable backend 中提交或明确拒绝。

`NewControlPlaneHandler` 仍允许使用 memory state 和 callback fields，以便本地 contract
测试和受控嵌入使用。这是构造器的兼容能力，不是生产准入；生产组合根必须在挂载前
执行上述验证，不能用测试实现替代 durable provider。

## 启动顺序

生产 launcher 的责任顺序如下：

1. 打开并验证 PostgreSQL/控制面授权与审计后端，确认 durable epoch 和 cluster identity。
2. 构造 `DurableAuthorizationState` 与 `DurableAuthorizationProvider`，并绑定同一生产
   cluster、权限、fence、confirmation 和审计上下文。
3. 构造 `ControlPlaneHandler`，配置显式 client CA、cluster ID 和 `waf` role。
4. 调用 `ValidateProductionControlPlaneHandler`；失败时不注入 runtime，不绑定 CRP
   activation listener。
5. 将已验证 handler 放入 `runtime.Dependencies`，完成 control-plane bootstrap 和
   readiness/fencing 检查。
6. 仅在上述依赖和控制面状态均 ready 后启动 listener；关闭时由同一生命周期拥有者
   先停止接收新授权，再关闭 provider/state/backend。

TLS 1.3、client certificate、SAN/CN、cluster/role 绑定和严格 JSON schema 仍遵循
[CRP activation transport contract](crp-activation-transport.md)。本文的 handler
mount 不放宽任何 transport 层认证条件。

## 当前证据和未完成责任

当前仓内切片覆盖显式 handler 的保留、挂载与未挂载路径，以及 durable state/provider
类型边界；`MemoryAuthorizationState` 明确标记为非 durable。已有 transport 测试继续
覆盖 mTLS、authorization binding、validate/consume replay 和本地 RuntimeStore
promotion/rollback 不变量。

以下证据仍缺失，不能由本 contract 推断：

- 真实 PostgreSQL-backed authorization state/provider 的重启恢复和跨进程 replay guard；
- 生产 approval/permission/fence/audit provider 的部署回执；
- `cheesewaf-control` 与主 `cheesewaf serve` 的完整 launcher、sidecar 生命周期和
  stop/cleanup 证据；
- CRP activation/rollback 在真实部署环境中的 end-to-end 验收、HA、证书轮换和故障恢复。

production handler 挂载、durable authorization 与 sidecar 生命周期接线已经落地，
acceptance matrix 中 `crp_activation` 与 `crp_rollback` 记录为 passed。仍未覆盖的是
真实部署环境下的 HA、证书轮换和故障恢复演练；这些证据不能由本地或单节点测试替代。
