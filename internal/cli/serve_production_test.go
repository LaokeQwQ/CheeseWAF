package cli

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/api/handler"
	"github.com/LaokeQwQ/CheeseWAF/internal/approval"
	"github.com/LaokeQwQ/CheeseWAF/internal/cluster/redis"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/controlplane"
	"github.com/LaokeQwQ/CheeseWAF/internal/controlplane/nativeraft"
	"github.com/LaokeQwQ/CheeseWAF/internal/cwedp"
	"github.com/LaokeQwQ/CheeseWAF/internal/cwedp/transport"
	"github.com/LaokeQwQ/CheeseWAF/internal/netlease"
	setupmigration "github.com/LaokeQwQ/CheeseWAF/internal/setup/migration"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

func TestOpenProductionDependenciesRejectsMissingFactoryBeforeIO(t *testing.T) {
	opts := ProductionStartupOptions{
		Profile:              config.StorageProfileProduction,
		ClusterID:            "cluster-a",
		ManagementPostgreSQL: config.ManagementPostgreSQLConfig{DSN: "postgres://management.invalid/db"},
		ControlPostgreSQL:    config.ManagementPostgreSQLConfig{DSN: "postgres://control.invalid/db"},
		NativeRaft:           nativeraft.Options{Profile: config.StorageProfileProduction, ClusterID: "cluster-a", DataDir: t.TempDir(), BindAddress: "127.0.0.1:0", Mode: nativeraft.ModeBootstrap},
		RedisEnabled:         true,
	}
	_, err := OpenProductionDependencies(context.Background(), opts, ProductionDependencyFactory{})
	if !errors.Is(err, config.ErrProductionStorageUnavailable) {
		t.Fatalf("missing factory error = %v, want ErrProductionStorageUnavailable", err)
	}
}

func TestOpenProductionDependenciesRejectsConflictingServeWiringCallbacksBeforeIO(t *testing.T) {
	opts := testProductionStartupOptions(t)
	factory := ProductionDependencyFactory{
		OpenManagement: func(context.Context, config.ManagementPostgreSQLConfig) (storage.Store, error) {
			return nil, nil
		},
		OpenControl: func(context.Context, config.ManagementPostgreSQLConfig) (ProductionControlDependency, error) {
			return nil, nil
		},
		OpenConsensus: func(context.Context, nativeraft.Options) (ProductionConsensusDependency, error) {
			return nil, nil
		},
		OpenRedis: func(context.Context, redis.Config) (ProductionHealthDependency, error) {
			return nil, nil
		},
		OpenApproval: func(context.Context, ProductionStartupOptions) (ProductionApprovalDependency, error) {
			return nil, nil
		},
		WireServe:           func(context.Context, *ProductionDependencies) error { return nil },
		WireServeWithWiring: func(context.Context, ProductionServeWiring) error { return nil },
	}
	_, err := OpenProductionDependencies(context.Background(), opts, factory)
	if !errors.Is(err, ErrProductionServeWiringConflict) {
		t.Fatalf("conflicting serve wiring error = %v, want ErrProductionServeWiringConflict", err)
	}
}

func TestOpenProductionDependenciesRequiresExplicitRedisInstanceID(t *testing.T) {
	opts := testProductionStartupOptions(t)
	opts.Redis.InstanceID = ""
	factory := ProductionDependencyFactory{
		OpenManagement: func(context.Context, config.ManagementPostgreSQLConfig) (storage.Store, error) { return nil, nil },
		OpenControl: func(context.Context, config.ManagementPostgreSQLConfig) (ProductionControlDependency, error) {
			return nil, nil
		},
		OpenConsensus: func(context.Context, nativeraft.Options) (ProductionConsensusDependency, error) { return nil, nil },
		OpenRedis:     func(context.Context, redis.Config) (ProductionHealthDependency, error) { return nil, nil },
		OpenApproval:  func(context.Context, ProductionStartupOptions) (ProductionApprovalDependency, error) { return nil, nil },
	}
	err := validateProductionStartupOptions(opts, factory)
	if !errors.Is(err, config.ErrProductionStorageUnavailable) || !strings.Contains(err.Error(), "instance") {
		t.Fatalf("missing Redis instance identity error=%v, want explicit identity rejection", err)
	}
}

func TestProductionStartupOptionsFromConfigKeepsManagementAndControlDSNsSeparate(t *testing.T) {
	cfg := config.Default()
	cfg.Storage.Profile = config.StorageProfileProduction
	cfg.Storage.ManagementPostgreSQL.DSN = "postgres://management.example.invalid/management"
	cfg.Storage.ControlPostgreSQL.DSN = "postgres://control.example.invalid/control"
	cfg.Storage.ManagementPostgreSQL.Timeout = 3 * time.Second
	cfg.Storage.ControlPostgreSQL.Timeout = 7 * time.Second
	cfg.Cluster.ClusterID = "cluster-a"
	cfg.Cluster.Consensus.NativeRaft.DataDir = "./data/cluster/native-raft"
	cfg.Cluster.Consensus.NativeRaft.Listen = "127.0.0.1:9451"
	cfg.Cluster.Consensus.NativeRaft.Mode = "bootstrap"
	cfg.Storage.Redis.Enabled = true
	cfg.Storage.Redis.Address = "127.0.0.1:6379"
	cfg.Setup.DataDir = t.TempDir()

	opts, err := productionStartupOptionsFromConfig(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	if opts.ManagementPostgreSQL.DSN == opts.ControlPostgreSQL.DSN || opts.ManagementPostgreSQL.DSN == "" || opts.ControlPostgreSQL.DSN == "" {
		t.Fatalf("production DSNs were aliased or lost: management=%q control=%q", opts.ManagementPostgreSQL.DSN, opts.ControlPostgreSQL.DSN)
	}
	if opts.ControlPostgreSQL.Timeout != 7*time.Second {
		t.Fatalf("control PostgreSQL timeout=%s, want 7s", opts.ControlPostgreSQL.Timeout)
	}
	if opts.NativeRaft.DataDir == "./data/cluster/native-raft" || !filepath.IsAbs(opts.NativeRaft.DataDir) {
		t.Fatalf("native-raft data directory was not rebased under runtime data dir: %q", opts.NativeRaft.DataDir)
	}
}

func TestProductionStartupOptionsFromConfigRejectsDirtyIdentityWithoutRewriting(t *testing.T) {
	for _, tc := range []struct {
		name  string
		apply func(*config.Config)
	}{
		{name: "cluster id", apply: func(cfg *config.Config) { cfg.Cluster.ClusterID = " cluster-a" }},
		{name: "node id", apply: func(cfg *config.Config) { cfg.Cluster.NodeID = "node-a\u200b" }},
		{name: "redis instance id", apply: func(cfg *config.Config) { cfg.Storage.Redis.InstanceID = "instance-a\u2060" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := productionConfigFixture(t)
			tc.apply(&cfg)
			if _, err := productionStartupOptionsFromConfig(&cfg); !errors.Is(err, config.ErrProductionStorageUnavailable) {
				t.Fatalf("dirty identity error=%v, want production-unavailable rejection", err)
			}
		})
	}
}

func TestOpenProductionDependenciesAppliesControlPostgreSQLTimeoutToOpener(t *testing.T) {
	manager, err := storage.OpenSQLite(filepath.Join(t.TempDir(), "manager.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	opts := testProductionStartupOptions(t)
	opts.ControlPostgreSQL.Timeout = 20 * time.Millisecond
	var gotDeadline bool
	factory := ProductionDependencyFactory{
		OpenManagement: func(context.Context, config.ManagementPostgreSQLConfig) (storage.Store, error) { return manager, nil },
		OpenControl: func(ctx context.Context, _ config.ManagementPostgreSQLConfig) (ProductionControlDependency, error) {
			_, gotDeadline = ctx.Deadline()
			return nil, context.DeadlineExceeded
		},
		OpenConsensus: func(context.Context, nativeraft.Options) (ProductionConsensusDependency, error) {
			t.Fatal("consensus opener must not run after control timeout")
			return nil, nil
		},
		OpenRedis: func(context.Context, redis.Config) (ProductionHealthDependency, error) {
			t.Fatal("redis opener must not run after control timeout")
			return nil, nil
		},
		OpenApproval: func(context.Context, ProductionStartupOptions) (ProductionApprovalDependency, error) {
			t.Fatal("approval opener must not run after control timeout")
			return nil, nil
		},
	}
	if _, err := OpenProductionDependencies(context.Background(), opts, factory); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("control timeout error=%v, want context deadline", err)
	}
	if !gotDeadline {
		t.Fatal("control opener did not receive a deadline")
	}
}

func productionConfigFixture(t *testing.T) config.Config {
	t.Helper()
	cfg := config.Default()
	cfg.Storage.Profile = config.StorageProfileProduction
	cfg.Storage.ManagementPostgreSQL.DSN = "postgres://management.example.invalid/management"
	cfg.Storage.ControlPostgreSQL.DSN = "postgres://control.example.invalid/control"
	cfg.Cluster.ClusterID = "cluster-a"
	cfg.Cluster.NodeID = "node-a"
	cfg.Cluster.Consensus.NativeRaft.DataDir = filepath.Join(t.TempDir(), "raft")
	cfg.Cluster.Consensus.NativeRaft.Listen = "127.0.0.1:9451"
	cfg.Cluster.Consensus.NativeRaft.Mode = "bootstrap"
	cfg.Storage.Redis.Enabled = true
	cfg.Storage.Redis.Address = "127.0.0.1:6379"
	cfg.Storage.Redis.InstanceID = "instance-a"
	cfg.Setup.DataDir = t.TempDir()
	return cfg
}

func TestOpenProductionDependenciesClosesEveryOpenedResourceOnRedisFailure(t *testing.T) {
	manager, err := storage.OpenSQLite(filepath.Join(t.TempDir(), "manager.db"))
	if err != nil {
		t.Fatal(err)
	}
	control := &productionControlFake{}
	consensus := newProductionConsensusFake(t)
	opts := testProductionStartupOptions(t)
	opts.RedisEnabled = true
	factory := ProductionDependencyFactory{
		OpenManagement: func(context.Context, config.ManagementPostgreSQLConfig) (storage.Store, error) { return manager, nil },
		OpenControl: func(context.Context, config.ManagementPostgreSQLConfig) (ProductionControlDependency, error) {
			return control, nil
		},
		OpenConsensus: func(context.Context, nativeraft.Options) (ProductionConsensusDependency, error) {
			return consensus, nil
		},
		OpenRedis: func(context.Context, redis.Config) (ProductionHealthDependency, error) {
			return nil, errors.New("redis unavailable")
		},
		OpenApproval: func(context.Context, ProductionStartupOptions) (ProductionApprovalDependency, error) {
			t.Fatal("approval opener must not run after Redis failure")
			return nil, nil
		},
	}

	deps, err := OpenProductionDependencies(context.Background(), opts, factory)
	if deps != nil {
		t.Fatal("failed production open returned dependencies")
	}
	if err == nil || !errors.Is(err, config.ErrProductionStorageUnavailable) {
		t.Fatalf("Redis failure = %v, want production unavailable", err)
	}
	if !control.closed || !consensus.closed {
		t.Fatalf("partial production resources were not closed: control=%t consensus=%t", control.closed, consensus.closed)
	}
	if closeErr := manager.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
}

func TestOpenProductionDependenciesBootstrapsAndRequiresExplicitServeWire(t *testing.T) {
	manager, err := storage.OpenSQLite(filepath.Join(t.TempDir(), "manager.db"))
	if err != nil {
		t.Fatal(err)
	}
	control := &productionControlFake{state: testProductionState(t)}
	consensus := newProductionConsensusFake(t)
	consensus.state = control.state
	consensus.machine, err = controlplane.NewStateMachine("cluster-a", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := consensus.machine.InstallLeadership(control.state.Term, control.state.LeaderID); err != nil {
		t.Fatal(err)
	}
	if err := consensus.machine.LoadSnapshot(control.state); err != nil {
		t.Fatal(err)
	}
	if err := consensus.machine.ResumeWrites(controlplane.FenceToken{ClusterID: control.state.ClusterID, LeaderID: control.state.LeaderID, Epoch: control.state.Epoch, Revision: control.state.Revision, Digest: control.state.Desired.Digest, Nonce: "nonce-a"}); err != nil {
		t.Fatal(err)
	}
	control.state = consensus.machine.Snapshot()
	consensus.state = control.state
	opts := testProductionStartupOptions(t)
	opts.ManagementSessionID = "management-session"
	opts.AuditSink = durableTestAuditSink(t)
	var wired bool
	var order []string
	factory := ProductionDependencyFactory{
		OpenManagement: func(context.Context, config.ManagementPostgreSQLConfig) (storage.Store, error) {
			order = append(order, "management")
			return manager, nil
		},
		OpenControl: func(context.Context, config.ManagementPostgreSQLConfig) (ProductionControlDependency, error) {
			order = append(order, "control")
			return control, nil
		},
		OpenConsensus: func(context.Context, nativeraft.Options) (ProductionConsensusDependency, error) {
			order = append(order, "consensus")
			return consensus, nil
		},
		OpenRedis: func(context.Context, redis.Config) (ProductionHealthDependency, error) {
			order = append(order, "redis")
			return &productionHealthFake{}, nil
		},
		OpenApproval: func(_ context.Context, opts ProductionStartupOptions) (ProductionApprovalDependency, error) {
			order = append(order, "approval")
			return newProductionApprovalFake(opts.ApprovalEpoch, manager), nil
		},
		OpenTemporaryNetwork: func(_ context.Context, options ProductionTemporaryNetworkOptions) (*ProductionTemporaryNetworkWiring, error) {
			if options.ManagementStore != manager || options.PolicyEpoch == 0 || options.ManagementSessionID != opts.ManagementSessionID || options.AuditSink != opts.AuditSink {
				t.Fatalf("temporary network options were not bound: %+v", options)
			}
			return testTemporaryNetworkWiring(t), nil
		},
		WireServeWithWiring: func(_ context.Context, wiring ProductionServeWiring) error {
			order = append(order, "wire")
			if wiring.ManagementStore != manager || wiring.SessionValidator != manager || wiring.PolicyEpoch != uint64(wiring.Startup.State.Epoch) || wiring.ApprovalHTTP == nil || wiring.TemporaryHTTPExecutor == nil || wiring.CWEDPAdapter == nil {
				t.Fatalf("serve wiring lost lifecycle-bound dependencies: %+v", wiring)
			}
			wired = true
			return nil
		},
	}
	deps, err := OpenProductionDependencies(context.Background(), opts, factory)
	if err != nil {
		t.Fatalf("production bootstrap failed: %v", err)
	}
	if deps == nil || !deps.Ready || !wired || deps.Startup.Stage != controlplane.StartupStageReady {
		t.Fatalf("production dependencies not ready: deps=%+v wired=%t", deps, wired)
	}
	if deps.Management != manager {
		t.Fatal("management store was not retained as storage.Store")
	}
	if deps.Control == nil || deps.Consensus == nil {
		t.Fatal("control dependencies were not retained")
	}
	if strings.Join(order, ",") != "management,control,consensus,redis,approval,wire" {
		t.Fatalf("production startup order=%v, want management/control/consensus/redis/approval/wire", order)
	}
	if deps.Serve.Startup.Fence.ClusterID != opts.ClusterID || uint64(deps.Serve.Startup.Fence.Epoch) != deps.Serve.PolicyEpoch {
		t.Fatalf("serve wiring lost startup fence: fence=%+v epoch=%d", deps.Serve.Startup.Fence, deps.Serve.PolicyEpoch)
	}
	if err := deps.Close(); err != nil {
		t.Fatal(err)
	}
	if !control.closed || !consensus.closed {
		t.Fatalf("ready production resources were not closed: control=%t consensus=%t", control.closed, consensus.closed)
	}
}

func durableTestAuditSink(t *testing.T) netlease.DurableAuditSink {
	t.Helper()
	sink, err := netlease.NewFileAuditSink(filepath.Join(t.TempDir(), "audit", "netlease.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	return sink
}

func testTemporaryNetworkWiring(t *testing.T) *ProductionTemporaryNetworkWiring {
	t.Helper()
	adapter := transport.NewHTTPAdapter(&netlease.Broker{}, "lease-1", netlease.RequestScope{})
	wiring, err := NewProductionTemporaryNetworkWiring(testTemporaryHTTPExecutor{}, adapter, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	return wiring
}

type testTemporaryHTTPExecutor struct{}

func (testTemporaryHTTPExecutor) ExecuteTemporaryHTTP(context.Context, netlease.TemporaryHTTPExecution) (netlease.HTTPResponse, error) {
	return netlease.HTTPResponse{}, nil
}

func TestOpenProductionDependenciesRejectsUnwiredServeEvenWhenBackendsHealthy(t *testing.T) {
	manager, err := storage.OpenSQLite(filepath.Join(t.TempDir(), "manager.db"))
	if err != nil {
		t.Fatal(err)
	}
	control := &productionControlFake{state: testProductionState(t)}
	consensus := newProductionConsensusFake(t)
	consensus.state = control.state
	consensus.machine, err = controlplane.NewStateMachine("cluster-a", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := consensus.machine.InstallLeadership(control.state.Term, control.state.LeaderID); err != nil {
		t.Fatal(err)
	}
	if err := consensus.machine.LoadSnapshot(control.state); err != nil {
		t.Fatal(err)
	}
	if err := consensus.machine.ResumeWrites(controlplane.FenceToken{ClusterID: control.state.ClusterID, LeaderID: control.state.LeaderID, Epoch: control.state.Epoch, Revision: control.state.Revision, Digest: control.state.Desired.Digest, Nonce: "nonce-a"}); err != nil {
		t.Fatal(err)
	}
	opts := testProductionStartupOptions(t)
	factory := ProductionDependencyFactory{
		OpenManagement: func(context.Context, config.ManagementPostgreSQLConfig) (storage.Store, error) { return manager, nil },
		OpenControl: func(context.Context, config.ManagementPostgreSQLConfig) (ProductionControlDependency, error) {
			return control, nil
		},
		OpenConsensus: func(context.Context, nativeraft.Options) (ProductionConsensusDependency, error) {
			return consensus, nil
		},
		OpenRedis: func(context.Context, redis.Config) (ProductionHealthDependency, error) {
			return &productionHealthFake{}, nil
		},
		OpenApproval: func(_ context.Context, opts ProductionStartupOptions) (ProductionApprovalDependency, error) {
			return newProductionApprovalFake(opts.ApprovalEpoch, manager), nil
		},
	}
	deps, err := OpenProductionDependencies(context.Background(), opts, factory)
	if deps != nil || !errors.Is(err, ErrProductionTemporaryNetworkUnavailable) {
		t.Fatalf("unwired production result = deps:%v err:%v", deps, err)
	}
	if !control.closed || !consensus.closed {
		t.Fatalf("unwired resources were not closed: control=%t consensus=%t", control.closed, consensus.closed)
	}
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestValidateProductionApprovalDependencyRejectsWeakFake(t *testing.T) {
	weak := &weakApprovalFake{}
	if _, err := validateProductionApprovalDependency(weak, 1); !errors.Is(err, ErrProductionApprovalUnavailable) {
		t.Fatalf("weak approval dependency error=%v, want ErrProductionApprovalUnavailable", err)
	}
}

func TestOpenProductionDependenciesRejectsInvalidApprovalCapabilityBeforeWire(t *testing.T) {
	for _, tc := range []struct {
		name  string
		apply func(*productionApprovalFake)
		want  error
	}{
		{name: "nil handler", apply: func(f *productionApprovalFake) { f.approvalHTTP = nil }, want: ErrProductionApprovalHTTPUnavailable},
		{name: "zero epoch", apply: func(f *productionApprovalFake) { f.epoch = 0 }, want: ErrProductionApprovalEpochUnavailable},
		{name: "mismatched epoch", apply: func(f *productionApprovalFake) { f.epoch = 2 }, want: ErrProductionApprovalEpochMismatch},
		{name: "handler gate epoch mismatch", apply: func(f *productionApprovalFake) {
			f.approvalHTTP = handler.NewApprovalHTTPHandler(handler.ApprovalHTTPOptions{Gate: approval.NewGate(2)})
		}, want: ErrProductionServeWiringUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			manager, err := storage.OpenSQLite(filepath.Join(t.TempDir(), "manager.db"))
			if err != nil {
				t.Fatal(err)
			}
			control := &productionControlFake{state: testProductionState(t)}
			consensus := newProductionConsensusFake(t)
			consensus.state = control.state
			consensus.machine, err = controlplane.NewStateMachine("cluster-a", nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := consensus.machine.InstallLeadership(control.state.Term, control.state.LeaderID); err != nil {
				t.Fatal(err)
			}
			if err := consensus.machine.LoadSnapshot(control.state); err != nil {
				t.Fatal(err)
			}
			if err := consensus.machine.ResumeWrites(controlplane.FenceToken{ClusterID: control.state.ClusterID, LeaderID: control.state.LeaderID, Epoch: control.state.Epoch, Revision: control.state.Revision, Digest: control.state.Desired.Digest, Nonce: "nonce-a"}); err != nil {
				t.Fatal(err)
			}
			control.state = consensus.machine.Snapshot()
			consensus.state = control.state
			approval := newProductionApprovalFake(uint64(control.state.Epoch))
			tc.apply(approval)
			var wired bool
			opts := testProductionStartupOptions(t)
			factory := ProductionDependencyFactory{
				OpenManagement: func(context.Context, config.ManagementPostgreSQLConfig) (storage.Store, error) { return manager, nil },
				OpenControl: func(context.Context, config.ManagementPostgreSQLConfig) (ProductionControlDependency, error) {
					return control, nil
				},
				OpenConsensus: func(context.Context, nativeraft.Options) (ProductionConsensusDependency, error) {
					return consensus, nil
				},
				OpenRedis: func(context.Context, redis.Config) (ProductionHealthDependency, error) {
					return &productionHealthFake{}, nil
				},
				OpenApproval: func(context.Context, ProductionStartupOptions) (ProductionApprovalDependency, error) {
					return approval, nil
				},
				WireServeWithWiring: func(context.Context, ProductionServeWiring) error {
					wired = true
					return nil
				},
			}
			deps, err := OpenProductionDependencies(context.Background(), opts, factory)
			if deps != nil || !errors.Is(err, tc.want) || (tc.want != ErrProductionServeWiringUnavailable && !errors.Is(err, ErrProductionApprovalUnavailable)) {
				t.Fatalf("invalid approval result = deps:%v err:%v, want approval and %v", deps, err, tc.want)
			}
			if wired {
				t.Fatal("WireServe ran for invalid approval capability")
			}
			if !control.closed || !consensus.closed || !approval.closed {
				t.Fatalf("invalid approval resources were not closed: control=%t consensus=%t approval=%t", control.closed, consensus.closed, approval.closed)
			}
			if err := manager.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestProductionDependenciesCloseInReverseOrder(t *testing.T) {
	manager, err := storage.OpenSQLite(filepath.Join(t.TempDir(), "manager.db"))
	if err != nil {
		t.Fatal(err)
	}
	events := make([]string, 0, 5)
	deps := &ProductionDependencies{
		Management: &recordingStore{Store: manager, events: &events},
		Control:    &productionControlFake{closeEvents: &events},
		Consensus:  &productionConsensusFake{closeEvents: &events},
		Redis:      &productionHealthFake{closeEvents: &events},
		Approval:   &productionApprovalFake{closeEvents: &events},
	}
	if err := deps.Close(); err != nil {
		t.Fatal(err)
	}
	want := []string{"approval", "redis", "consensus", "control", "management"}
	if strings.Join(events, ",") != strings.Join(want, ",") {
		t.Fatalf("close order=%v, want %v", events, want)
	}
}

func TestProductionDependenciesServeWiringRejectsDetachedSessionValidator(t *testing.T) {
	manager, err := storage.OpenSQLite(filepath.Join(t.TempDir(), "manager.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	other, err := storage.OpenSQLite(filepath.Join(t.TempDir(), "other.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	state := testProductionState(t)
	deps := &ProductionDependencies{
		Management: manager,
		Approval:   &productionApprovalFake{epoch: uint64(state.Epoch)},
		Startup:    controlplane.StartupResult{Stage: controlplane.StartupStageReady, Ready: true, State: state},
		ApprovalHTTP: handler.NewApprovalHTTPHandler(handler.ApprovalHTTPOptions{
			SessionValidator: other,
		}),
	}
	if _, err := deps.ServeWiring(); !errors.Is(err, ErrProductionServeWiringUnavailable) || !strings.Contains(err.Error(), "session validator") {
		t.Fatalf("detached validator error=%v, want lifecycle binding rejection", err)
	}
}

func TestValidateProductionTemporaryNetworkOptionsRejectsMissingProviderSessionAndAudit(t *testing.T) {
	manager, err := storage.OpenSQLite(filepath.Join(t.TempDir(), "manager.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	audit := durableTestAuditSink(t)
	open := func(context.Context, ProductionTemporaryNetworkOptions) (*ProductionTemporaryNetworkWiring, error) {
		return testTemporaryNetworkWiring(t), nil
	}
	base := ProductionStartupOptions{ManagementSessionID: "management-session", AuditSink: audit}
	tests := []struct {
		name string
		opts ProductionStartupOptions
		open func(context.Context, ProductionTemporaryNetworkOptions) (*ProductionTemporaryNetworkWiring, error)
		want error
	}{
		{name: "missing provider", opts: base, want: ErrProductionTemporaryNetworkUnavailable},
		{name: "missing management session", opts: ProductionStartupOptions{AuditSink: audit}, open: open, want: ErrProductionTemporaryNetworkSession},
		{name: "non durable audit", opts: ProductionStartupOptions{ManagementSessionID: "management-session", AuditSink: netlease.NewMemoryAuditSinkForTesting()}, open: open, want: ErrProductionTemporaryNetworkAudit},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateProductionTemporaryNetworkOptions(tc.opts, manager, 7, tc.open)
			if !errors.Is(err, tc.want) {
				t.Fatalf("validation error=%v, want %v", err, tc.want)
			}
		})
	}
}

func TestValidateProductionTemporaryNetworkOptionsRequiresVerifiedMigrationHandoff(t *testing.T) {
	manager, err := storage.OpenSQLite(filepath.Join(t.TempDir(), "manager.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	opts := testProductionStartupOptions(t)
	opts.ManagementSessionID = "management-session"
	opts.AuditSink = durableTestAuditSink(t)
	opts.MigrationHandoffVerifier = nil
	open := func(context.Context, ProductionTemporaryNetworkOptions) (*ProductionTemporaryNetworkWiring, error) {
		return testTemporaryNetworkWiring(t), nil
	}
	if err := validateProductionTemporaryNetworkOptions(opts, manager, 7, open); !errors.Is(err, ErrProductionMigrationHandoffUnavailable) {
		t.Fatalf("missing handoff verifier error=%v, want ErrProductionMigrationHandoffUnavailable", err)
	}
	opts.MigrationHandoffVerifier = productionHandoffVerifierFunc{}
	if err := validateProductionTemporaryNetworkOptions(opts, manager, 7, open); err != nil {
		t.Fatalf("valid migration handoff rejected: %v", err)
	}
}

func TestProductionTemporaryNetworkWiringRejectsUnboundAdapterAndClosesOnce(t *testing.T) {
	_, err := NewProductionTemporaryNetworkWiring(testTemporaryHTTPExecutor{}, transport.AdapterFunc(func(context.Context, transport.Endpoint, cwedp.DistributionIntent, cwedp.Hello, cwedp.Capabilities, int64) (io.ReadCloser, error) {
		return nil, nil
	}), func() error { return nil })
	if !errors.Is(err, ErrProductionTemporaryNetworkAdapter) {
		t.Fatalf("unbound adapter error=%v, want ErrProductionTemporaryNetworkAdapter", err)
	}
	closed := 0
	wiring := testTemporaryNetworkWiring(t)
	wiring.closeFn = func() error {
		closed++
		return nil
	}
	if err := wiring.Close(); err != nil {
		t.Fatal(err)
	}
	if err := wiring.Close(); err != nil {
		t.Fatal(err)
	}
	if closed != 1 {
		t.Fatalf("provider cleanup calls=%d, want one", closed)
	}
}

func testProductionStartupOptions(t *testing.T) ProductionStartupOptions {
	t.Helper()
	return ProductionStartupOptions{
		Profile:              config.StorageProfileProduction,
		ClusterID:            "cluster-a",
		ManagementPostgreSQL: config.ManagementPostgreSQLConfig{DSN: "postgres://management.invalid/db"},
		ControlPostgreSQL:    config.ManagementPostgreSQLConfig{DSN: "postgres://control.invalid/db"},
		NativeRaft:           nativeraft.Options{Profile: config.StorageProfileProduction, ClusterID: "cluster-a", NodeID: "node-a", DataDir: t.TempDir(), BindAddress: "127.0.0.1:0", Mode: nativeraft.ModeBootstrap},
		Redis:                redis.Config{InstanceID: "instance-a", Addr: "127.0.0.1:6379"},
		RedisEnabled:         true,
		MigrationHandoff: setupmigration.ProductionHandoffProof{
			ConfigDigest: strings.Repeat("a", 64), CandidateDigest: strings.Repeat("b", 64),
			ClusterID: "cluster-a", SnapshotID: "snapshot-a", SnapshotProof: "snapshot-proof-a", LedgerProof: "ledger-proof-a",
			TokenMetadataDigest: strings.Repeat("c", 64), TokenMetadataVerified: true,
			Invalidated: setupmigration.InvalidationReceipt{Sessions: true, Setup: true, Join: true, CAPTCHA: true, Locks: true},
		},
		MigrationHandoffVerifier: productionHandoffVerifierFunc{},
	}
}

type productionHandoffVerifierFunc struct{}

func (productionHandoffVerifierFunc) VerifyProductionHandoff(context.Context, setupmigration.ProductionHandoffProof) error {
	return nil
}

func testProductionState(t *testing.T) controlplane.State {
	t.Helper()
	machine, err := controlplane.NewStateMachine("cluster-a", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := machine.InstallLeadership(1, "leader-a"); err != nil {
		t.Fatal(err)
	}
	commit, err := machine.Propose(controlplane.Proposal{LeaderID: "leader-a", ExpectedEpoch: 1, ExpectedRevision: 0, Version: "v1", Payload: []byte("{\"sites\":[]}"), Nonce: "nonce-a"})
	if err != nil {
		t.Fatal(err)
	}
	if err := machine.InstallCommit(commit); err != nil {
		t.Fatal(err)
	}
	if err := machine.ResumeWrites(commit.Fence); err != nil {
		t.Fatal(err)
	}
	return commit.State
}

type productionControlFake struct {
	state       controlplane.State
	closed      bool
	closeEvents *[]string
}

func (*productionControlFake) Backend() string               { return controlplane.DurableBackendPostgreSQL }
func (*productionControlFake) Prepare(context.Context) error { return nil }
func (*productionControlFake) Health(context.Context) error  { return nil }
func (f *productionControlFake) LoadState(context.Context, string) (controlplane.State, error) {
	return f.state, nil
}
func (*productionControlFake) AppendCommit(context.Context, controlplane.Commit) error { return nil }
func (f *productionControlFake) Close() error {
	f.closed = true
	if f.closeEvents != nil {
		*f.closeEvents = append(*f.closeEvents, "control")
	}
	return nil
}

type productionConsensusFake struct {
	state       controlplane.State
	machine     *controlplane.StateMachine
	closed      bool
	closeEvents *[]string
}

func newProductionConsensusFake(t *testing.T) *productionConsensusFake {
	t.Helper()
	machine, err := controlplane.NewStateMachine("cluster-a", nil)
	if err != nil {
		t.Fatal(err)
	}
	return &productionConsensusFake{machine: machine}
}
func (*productionConsensusFake) Backend() string               { return controlplane.ConsensusBackendNativeRaft }
func (*productionConsensusFake) Prepare(context.Context) error { return nil }
func (*productionConsensusFake) Health(context.Context) error  { return nil }
func (f *productionConsensusFake) Current(context.Context, string) (controlplane.State, error) {
	return f.state, nil
}
func (*productionConsensusFake) Propose(context.Context, controlplane.Commit) error { return nil }
func (f *productionConsensusFake) Establish(context.Context, controlplane.State) (controlplane.FenceToken, error) {
	return controlplane.FenceToken{ClusterID: f.state.ClusterID, LeaderID: f.state.LeaderID, Epoch: f.state.Epoch, Revision: f.state.Revision, Digest: f.state.Desired.Digest, Nonce: "nonce-a"}, nil
}
func (f *productionConsensusFake) Machine() *controlplane.StateMachine { return f.machine }
func (f *productionConsensusFake) Close() error {
	f.closed = true
	if f.closeEvents != nil {
		*f.closeEvents = append(*f.closeEvents, "consensus")
	}
	return nil
}

type productionHealthFake struct {
	closeEvents *[]string
}

func (*productionHealthFake) Health(context.Context) error { return nil }
func (f *productionHealthFake) Close() error {
	if f.closeEvents != nil {
		*f.closeEvents = append(*f.closeEvents, "redis")
	}
	return nil
}

type productionApprovalFake struct {
	approvalHTTP *handler.ApprovalHTTPHandler
	epoch        uint64
	closed       bool
	closeEvents  *[]string
}

func newProductionApprovalFake(epoch uint64, validator ...interface {
	IsSessionActive(context.Context, string, string, time.Time) (bool, error)
}) *productionApprovalFake {
	var sessionValidator interface {
		IsSessionActive(context.Context, string, string, time.Time) (bool, error)
	}
	if len(validator) > 0 {
		sessionValidator = validator[0]
	}
	return &productionApprovalFake{
		approvalHTTP: handler.NewApprovalHTTPHandler(handler.ApprovalHTTPOptions{Gate: approval.NewGate(epoch), SessionValidator: sessionValidator}),
		epoch:        epoch,
	}
}

func (f *productionApprovalFake) Health(context.Context) error { return nil }
func (f *productionApprovalFake) Close() error {
	f.closed = true
	if f.closeEvents != nil {
		*f.closeEvents = append(*f.closeEvents, "approval")
	}
	return nil
}
func (f *productionApprovalFake) ApprovalHTTP() *handler.ApprovalHTTPHandler { return f.approvalHTTP }
func (f *productionApprovalFake) PolicyEpoch() uint64                        { return f.epoch }

type weakApprovalFake struct{}

func (*weakApprovalFake) Health(context.Context) error { return nil }
func (*weakApprovalFake) Close() error                 { return nil }

type recordingStore struct {
	storage.Store
	events *[]string
}

func (s *recordingStore) Close() error {
	*s.events = append(*s.events, "management")
	return s.Store.Close()
}
