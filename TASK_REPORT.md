# R2-1 Consensus Task Report

Status: `DONE_WITH_CONCERNS`

Implementation commits: `2ef5064`, `6605e10`

## Requirement Disposition

1. `builtin` is valid only for a single-node local deployment: implemented. Config validation rejects `builtin` when the HA mode is shared or more than one node is configured. Cluster join is treated as shared configuration and requires `etcd` on both controller and joining node.
2. Multi-node/shared clusters require `etcd` and fail clearly otherwise: implemented in full config validation and rechecked at cluster runtime initialization. Blank etcd endpoint entries are rejected.
3. Defaults/status/coordinator must not silently degrade etcd to builtin: implemented. The standalone default remains intentionally `builtin`; enabled clusters report `unconfigured` instead of inventing a provider. Invalid status objects fail closed, nil/unconfigured coordinators are non-writable, etcd selections never run heartbeat leader election, and cached coordinators refresh provider/endpoints after config changes.
4. Deployment templates must be safe: implemented. Generated Ansible config selects `etcd` whenever more than one host is present, exposes `cheesewaf_etcd_endpoints`, and fails preflight before host mutation when endpoints are missing.
5. Focused config/startup/coordinator regressions: implemented, with additional status, join propagation, and deployment-template coverage.
6. Audit finding 2: not implemented, as required. `deepseek_822_tasks.md` was not edited.

The final commit adds fail-closed status/join coverage for a configured etcd
provider when no etcd-backed coordinator is present, and counts an omitted
local node when deciding whether configuration is shared.

## Changed Files

- `configs/cheesewaf.yaml`
- `internal/api/handler/cluster.go`
- `internal/api/handler/cluster_orchestrate.go`
- `internal/api/handler/cluster_orchestrate_test.go`
- `internal/api/handler/cluster_test.go`
- `internal/cli/cluster.go`
- `internal/cli/cluster_join.go`
- `internal/cli/cluster_runtime.go`
- `internal/cli/cluster_runtime_test.go`
- `internal/cli/cluster_test.go`
- `internal/cluster/consensus/builtin.go`
- `internal/cluster/consensus/builtin_test.go`
- `internal/cluster/deploy/ansible.go`
- `internal/cluster/deploy/ansible_test.go`
- `internal/cluster/runtime_test.go`
- `internal/cluster/status.go`
- `internal/config/cluster_test.go`
- `internal/config/validator.go`

## Commands And Results

TDD red run:

```text
env GOCACHE=/private/tmp/cw-r2-consensus-gocache go test ./internal/config ./internal/cli ./internal/cluster/... -run 'TestClusterConsensus|TestInitializeClusterRuntimeRejectsBuiltin|TestBuiltinCoordinatorRejectsShared|TestEtcdSelectionNeverUsesBuiltin|TestAnsiblePackageRequiresEtcd' -count=1
```

Exit `1`, expected before implementation. The new config, startup, coordinator, and deployment regressions all failed on the prior permissive behavior.

Final focused regressions:

```text
go test ./internal/config ./internal/cluster/... ./internal/cli ./internal/api/handler -run 'TestClusterConsensus|TestInitializeClusterRuntimeRejectsBuiltin|TestBuiltinCoordinatorRejectsShared|TestEtcdSelectionNeverUsesBuiltin|TestAnsiblePackageRequiresEtcd|TestClusterStatus|TestApplyClusterJoinConfigRejects|TestJoinedClusterNodeConfigRejectsBuiltin|TestClusterJoinWritesCertificatesAndConfig|TestClusterJoinEnrollsNode' -count=1
```

Exit `0`; all selected packages passed.

Complete affected-package suites:

```text
go test ./internal/config ./internal/cluster/... ./internal/cli ./internal/api/handler -short -count=1
```

Exit `0`; all config, cluster, CLI, and API handler packages passed.

Required suite from the brief:

```text
go test ./internal/cluster/... ./internal/config/... -short
```

Exit `0`; all cluster and config packages passed.

Diff validation:

```text
git diff --check
```

Exit `0`; no whitespace errors. The complete source/test diff was reviewed before commit.

## Concerns

- The repository has no etcd-backed coordinator implementation or etcd client dependency. This change deliberately makes an `etcd` selection non-writable with a clear reason instead of silently using heartbeat election. Multi-node configuration is now safe and correctly requires etcd, but consensus-backed config proposals remain unavailable until a real etcd coordinator is integrated.
