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
- Temporary SSH deployment checks and fixed deployment actions from the management API. The runner uses Go's `x/crypto/ssh` and supports request-scoped one-time SSH password or one-time `private_key` content. It does not persist credentials or pass them through argv, environment variables, generated files, or temporary key files. It does not allow API callers to borrow arbitrary server-side key paths, does not accept arbitrary remote command strings, uses a timeout, and limits returned output. The current `install` action only checks the remote CheeseWAF binary version; it is not a real installer. If `restart-service` fails, the follow-up `systemctl start cheesewaf` is a recovery attempt / compensation action, not rollback.
- Trackable deployment tasks are available through `POST /api/cluster/deploy/tasks`, `GET /api/cluster/deploy/tasks/{id}`, and `GET /api/cluster/deploy/tasks`. Tasks expose product states, stages, started/updated/finished timestamps, redacted command previews, redacted output, and safe error summaries, giving operators a basic audit timeline for each real asynchronous deployment task. Events now record queueing, local validation, remote connection, check/deploy completion, failure, and credential cleanup. Local request validation failures are not reported as remote connection attempts. One-time SSH passwords and private keys are not returned in task responses or task lists, and are cleared from the in-memory request record after task completion. Redaction covers common password, private key, API token, access token, bearer token, and authorization token forms before API/Web display.
- The cluster audit page/API foundation is available through `GET /api/cluster/audit` and the Web Cluster page. It is backed by real management API audit records under `/api/cluster/*`, safe records for the public node enrollment endpoint, and deployment task events. It shows timestamp, source, action, actor, target, status, remote IP, and message. Raw join tokens, token hashes, CSRs, node private keys, SSH passwords, and SSH private keys are not returned.
- One-time join token creation, listing, and revocation through API and CLI. Token values are shown only once; persisted state stores hashes, not raw token values.
- Token-authenticated node enrollment through `POST /api/cluster/join`. The endpoint consumes a join token, checks the requested node role, requires the node-generated CSR to identify the requested node, returns the CA and node certificate, and records the node. Node private keys stay local to the joining node.
- CLI self-bootstrap through `cheesewaf cluster join`. The command can read the one-time token from a flag, file, or environment variable, generates the node private key and CSR locally, then writes local certificate files and cluster config.
- Foundational node certificate rotation through `POST /api/cluster/nodes/{id}/rotate-certificate`, the Web CSR signing panel, and `cheesewaf cluster cert rotate`. Rotation signs a node-generated CSR only when the CSR identifies the enrolled node, and returns only the CA and node certificate. The CLI generates the new private key and CSR on the target node, writes the CA, certificate, and private key locally, and restores local files if the local write fails. The controller does not generate, store, or return node private keys.
- Cluster identity state with a persistent cluster CA, registered node metadata, and real CSR-signed node certificates suitable for later mTLS wiring.

M2 foundations do not yet mean a node can fully join a running multi-node control plane. The full Web deployment wizard, production-grade deployment rollback / rolling upgrade, real `monitor-node` runtime, real heartbeat, majority confirmation, Raft/etcd coordination, object reconciliation, protection-mode write freezing, and production traffic scheduling are still follow-up work. The current audit view is a real management/deployment record view, not a substitute for M3 runtime consensus or object reconciliation audit.

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

Backend, CLI, and Web foundations are advancing, but M2 as a whole is not complete. This milestone now has deployment package generation, temporary SSH deployment checks/fixed actions, real asynchronous deployment tasks with a basic audit timeline, a cluster audit page/API backed by real management audit and deployment task events, one-time join tokens, token-authenticated CSR-based node enrollment, persistent cluster CA, local-key certificate issuance, CSR-based certificate rotation foundations, local CLI bootstrap, Web token/node/task/certificate signing views, and token/node revocation primitives. The full guided Web deployment wizard, production-grade deployment rollback / rolling upgrade, real `monitor-node` runtime, real heartbeat, majority confirmation, Raft/etcd coordination, object reconciliation, and production traffic scheduling still need follow-up work before this can be presented as a complete cluster expansion experience.

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
