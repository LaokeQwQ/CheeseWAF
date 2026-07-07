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

M2 backend foundations are now partially implemented:

- Ansible deployment package generation with no raw SSH password, private key, API token, or join token in generated files.
- Temporary SSH deployment checks and fixed deployment actions from the management API. The runner uses Go's `x/crypto/ssh` and supports request-scoped one-time SSH password or one-time `private_key` content. It does not persist credentials or pass them through argv, environment variables, generated files, or temporary key files. It does not allow API callers to borrow arbitrary server-side key paths, does not accept arbitrary remote command strings, uses a timeout, and limits returned output.
- One-time join token creation, listing, and revocation through API and CLI. Token values are shown only once; persisted state stores hashes, not raw token values.
- Token-authenticated node enrollment through `POST /api/cluster/join`. The endpoint consumes a join token, checks the requested node role, signs a node-generated CSR, returns the CA and node certificate, and records the node. Node private keys stay local to the joining node.
- CLI self-bootstrap through `cheesewaf cluster join`. The command can read the one-time token from a flag, file, or environment variable, generates the node private key and CSR locally, then writes local certificate files and cluster config.
- Cluster identity state with a persistent cluster CA, registered node metadata, and real CSR-signed node certificates suitable for later mTLS wiring.

M2 does not yet mean a node can fully join a running multi-node control plane. M3 is still required for real node interconnect, majority confirmation, monitor-node runtime, Raft/etcd coordination, object reconciliation, protection-mode write freezing, and cluster-aware traffic decisions.

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

Backend foundation and bootstrap enrollment implemented. This milestone now has deployment package generation, temporary SSH deployment checks/fixed actions, one-time join tokens, token-authenticated CSR-based node enrollment, persistent cluster CA, local-key certificate issuance, local CLI bootstrap, Web token/node views, and token/node revocation primitives. The full guided Web deployment wizard, certificate rotation UI, job progress, audit visualization, rollback, and monitor-node runtime still need follow-up work before this can be presented as a complete cluster expansion experience.

### M3: Consistency And Protection Mode

Planned. This milestone will add real node interconnect, multi-path heartbeat, built-in consistency service, optional external etcd, majority confirmation, write freezing in protection mode, and cluster-aware health decisions.

### M4-0: Semantic Engine And AI Assistant Readiness Gate

Planned before production traffic scheduling. The semantic engine and AI assistant must be tightened before traffic is distributed across nodes:

- Curate corpus samples instead of blindly importing datasets.
- Add realistic attack samples and realistic false-positive samples.
- Keep protection levels tied to semantic confidence thresholds.
- Default to low-confidence log/monitor behavior rather than blocking; business-impacting false positives are treated as worse than controlled misses.
- Add performance and resource ceilings for semantic analysis.
- Complete the AI assistant's built-in WAF knowledge base, prompt hardening, long reasoning stream keepalive, and real-time single-event analysis trace.
- Add WAF settings API token management, permission matrices, lifecycle/audit records, and help documentation.

### M4: Traffic Scheduling And Rolling Upgrade

Planned. This milestone will add built-in production traffic scheduling and rolling upgrade/rollback. The scheduler should aim to cover common professional load-balancer needs while still allowing external load balancers.
