# CheeseWAF Cluster And High Availability Roadmap

CheeseWAF remains a single-node WAF by default. The cluster work is being delivered in milestones so every shipped step is usable and does not overstate high availability before the required safety mechanisms exist.

## Current Status

M1 is implemented as the cluster foundation:

- `deployment.mode` and `cluster` configuration are available, with standalone as the default.
- Configuration validation prevents unsafe HA claims. Two WAF nodes are treated as load balancing, not full high availability.
- Declarative cluster objects exist for `Node`, `ClusterPolicy`, `JoinToken`, `ClusterCA`, and `NodeCertificate`.
- A standalone object store is available for local object snapshots.
- CLI commands are available:
  - `cheesewaf cluster status`
  - `cheesewaf cluster init`
  - `cheesewaf cluster export`
  - `cheesewaf cluster monitor-node` exists but intentionally refuses to run before M2/M3 runtime support.
- API endpoints are available:
  - `GET /api/cluster/status`
  - `GET /health/live`
  - `GET /health/ready`
  - `GET /health/cluster`
- The Web console has a Cluster entry and a standalone/cluster status page.

M1 does not include real node interconnect, majority confirmation, monitor-node runtime, Raft/etcd coordination, join-token consumption, node certificate issuance, object reconciliation, or production traffic scheduling.

## Product Modes

- Standalone mode: one node, all features remain usable.
- Dual-node load-balancing mode: two WAF nodes can share traffic, but the product must not call this full HA.
- Minimum HA mode: two WAF nodes plus one monitor node.
- Multi-node HA mode: three or more WAF nodes after majority confirmation is implemented.

## Product Language

The console and public docs should use user-facing product wording:

- 防数据偏差 / data divergence protection
- 监控节点 / monitor node
- 多数确认 / majority confirmation
- 协调节点 / coordinator node
- 保护模式 / protection mode
- 部署前检查 / deployment check
- 仅检查不应用 / check only
- 开发版 / 预览版 / 正式版

Avoid exposing implementation jargon in the normal UI.

## Milestones

### M1: Foundation

Implemented. This milestone gives CheeseWAF a truthful cluster configuration surface, declarative object model, CLI/API/Web status entry, and safety validation.

### M2: Deployment And Join Flow

Planned next. This milestone will generate Ansible deployment packages, support temporary SSH deployment from an existing WAF node, create one-time join tokens, issue node certificates, and support node revocation. Temporary SSH credentials must not be stored by default.

### M3: Consistency And Protection Mode

Planned. This milestone will add real node interconnect, multi-path heartbeat, built-in consistency service, optional external etcd, majority confirmation, write freezing in protection mode, and cluster-aware health decisions.

### M4: Traffic Scheduling And Rolling Upgrade

Planned. This milestone will add built-in production traffic scheduling and rolling upgrade/rollback. The scheduler should aim to cover common professional load-balancer needs while still allowing external load balancers.
