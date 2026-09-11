package cli

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/api/handler"
	"github.com/LaokeQwQ/CheeseWAF/internal/cluster/redis"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/controlplane"
	"github.com/LaokeQwQ/CheeseWAF/internal/controlplane/nativeraft"
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
	opts := testProductionStartupOptions(t)
	var wired bool
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
			return newProductionApprovalFake(opts.ApprovalEpoch), nil
		},
		WireServe: func(context.Context, *ProductionDependencies) error {
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
	if err := deps.Close(); err != nil {
		t.Fatal(err)
	}
	if !control.closed || !consensus.closed {
		t.Fatalf("ready production resources were not closed: control=%t consensus=%t", control.closed, consensus.closed)
	}
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
			return newProductionApprovalFake(opts.ApprovalEpoch), nil
		},
	}
	deps, err := OpenProductionDependencies(context.Background(), opts, factory)
	if deps != nil || !errors.Is(err, ErrProductionServeWiringUnavailable) {
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
				WireServe: func(context.Context, *ProductionDependencies) error {
					wired = true
					return nil
				},
			}
			deps, err := OpenProductionDependencies(context.Background(), opts, factory)
			if deps != nil || !errors.Is(err, ErrProductionApprovalUnavailable) || !errors.Is(err, tc.want) {
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
	}
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

func newProductionApprovalFake(epoch uint64) *productionApprovalFake {
	return &productionApprovalFake{
		approvalHTTP: handler.NewApprovalHTTPHandler(handler.ApprovalHTTPOptions{}),
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
