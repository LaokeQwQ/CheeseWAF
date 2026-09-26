package cli

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/api/handler"
	"github.com/LaokeQwQ/CheeseWAF/internal/api/middleware"
	"github.com/LaokeQwQ/CheeseWAF/internal/approval"
	"github.com/LaokeQwQ/CheeseWAF/internal/cluster/redis"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/controlplane"
	"github.com/LaokeQwQ/CheeseWAF/internal/controlplane/nativeraft"
	"github.com/LaokeQwQ/CheeseWAF/internal/crp"
	"github.com/LaokeQwQ/CheeseWAF/internal/crp/activation"
	"github.com/LaokeQwQ/CheeseWAF/internal/cwedp/consumer"
	"github.com/LaokeQwQ/CheeseWAF/internal/cwedp/transport"
	"github.com/LaokeQwQ/CheeseWAF/internal/netlease"
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
	if opts.DataDir != cfg.Setup.DataDir || !filepath.IsAbs(opts.DataDir) {
		t.Fatalf("temporary-network runtime data directory=%q, want %q", opts.DataDir, cfg.Setup.DataDir)
	}
}

func TestProductionStartupOptionsFromConfigCarriesNativeRaftTLS(t *testing.T) {
	cfg := config.Default()
	cfg.Storage.Profile = config.StorageProfileProduction
	cfg.Storage.ManagementPostgreSQL.DSN = "postgres://management.example.invalid/management"
	cfg.Storage.ControlPostgreSQL.DSN = "postgres://control.example.invalid/control"
	cfg.Storage.Redis.Enabled = true
	cfg.Storage.Redis.Address = "127.0.0.1:6379"
	cfg.Storage.Redis.InstanceID = "redis-a"
	cfg.Cluster.ClusterID = "cluster-a"
	cfg.Cluster.NodeID = "node-a"
	cfg.Cluster.Consensus.NativeRaft.DataDir = filepath.Join(t.TempDir(), "raft")
	cfg.Cluster.Consensus.NativeRaft.Listen = "127.0.0.1:9451"
	cfg.Cluster.Consensus.NativeRaft.Mode = "bootstrap"
	cfg.Cluster.Interconnect.CAFile = "/run/cheesewaf/cluster/ca.pem"
	cfg.Cluster.Interconnect.CertFile = "/run/cheesewaf/cluster/node.crt"
	cfg.Cluster.Interconnect.KeyFile = "/run/cheesewaf/cluster/node.key"
	cfg.Setup.DataDir = t.TempDir()

	opts, err := productionStartupOptionsFromConfig(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	if opts.NativeRaft.TLS == nil {
		t.Fatal("production native-raft TLS was dropped by startup option conversion")
	}
	if opts.NativeRaft.TLS.CAFile != cfg.Cluster.Interconnect.CAFile ||
		opts.NativeRaft.TLS.CertFile != cfg.Cluster.Interconnect.CertFile ||
		opts.NativeRaft.TLS.KeyFile != cfg.Cluster.Interconnect.KeyFile {
		t.Fatalf("native-raft TLS=%+v, want interconnect material", opts.NativeRaft.TLS)
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
	control, consensus := newProductionControlPlaneFixture(t)
	opts := testProductionStartupOptions(t)
	var wired bool
	runtime := testProductionCRPRuntime(t)
	download := testCWEDPDownloadExecutor{runtime: runtime}
	crpDependency := &testProductionCRPDependency{runtime: runtime, executor: testCRPActivationExecutor{}}
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
			return newProductionApprovalFake(opts.ApprovalEpoch, opts.ManagementStore), nil
		},
		OpenTemporaryNetwork: func(_ context.Context, options ProductionTemporaryNetworkOptions) (*ProductionTemporaryNetworkWiring, error) {
			if options.ManagementStore != manager || options.PolicyEpoch == 0 || options.DataDir != opts.DataDir {
				t.Fatalf("temporary network options were not bound: %+v", options)
			}
			return testTemporaryNetworkWiring(t), nil
		},
		OpenCWEDPDownload: func(_ context.Context, wiring ProductionServeWiring) (consumer.Executor, error) {
			if wiring.TemporaryNetwork == nil || wiring.PolicyEpoch == 0 {
				t.Fatalf("CWEDP opener received incomplete production wiring: %+v", wiring)
			}
			return download, nil
		},
		OpenCRP: func(_ context.Context, options ProductionCRPCompositionOptions) (ProductionCRPDependency, error) {
			if options.Runtime != runtime || options.Consensus != consensus || options.ApprovalClaimResolver == nil || options.ActivationPolicy.VerifyRecord == nil {
				t.Fatalf("CRP opener received incomplete production composition: %+v", options)
			}
			return crpDependency, nil
		},
		WireServeWithWiring: func(_ context.Context, wiring ProductionServeWiring) error {
			if wiring.CWEDPDownload != download {
				t.Fatal("CWEDP download consumer was not propagated to serve wiring")
			}
			if wiring.CRPActivation != crpDependency.executor {
				t.Fatal("CRP activation executor was not propagated to serve wiring")
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
	if deps.CWEDPDownload != download {
		t.Fatal("CWEDP download consumer was not retained by production dependencies")
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

type testCWEDPDownloadExecutor struct {
	runtime *crp.RuntimeStore
}

func (testCWEDPDownloadExecutor) DownloadCWEDP(context.Context, consumer.Request) (consumer.Result, error) {
	return consumer.Result{}, nil
}

func (e testCWEDPDownloadExecutor) CRPRuntime() *crp.RuntimeStore { return e.runtime }

func (e testCWEDPDownloadExecutor) CRPActivationPolicy() activation.Policy {
	return activation.Policy{VerifyRecord: func(context.Context, crp.RuntimeRecord) error { return nil }}
}

type testCRPActivationExecutor struct{}

func (testCRPActivationExecutor) ExecuteCRPActivation(context.Context, activation.AsyncRequest) (activation.ActivationResult, error) {
	return activation.ActivationResult{}, nil
}

type testProductionCRPDependency struct {
	runtime  *crp.RuntimeStore
	executor handler.CRPActivationExecutor
	events   *[]string
}

func (*testProductionCRPDependency) Start() error { return nil }
func (*testProductionCRPDependency) Wait(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}
func (*testProductionCRPDependency) Shutdown(context.Context) error { return nil }
func (d *testProductionCRPDependency) Close() error {
	if d.events != nil {
		*d.events = append(*d.events, "crp")
	}
	return nil
}
func (d *testProductionCRPDependency) Runtime() *crp.RuntimeStore { return d.runtime }
func (d *testProductionCRPDependency) ActivationExecutor() handler.CRPActivationExecutor {
	return d.executor
}

func testProductionCRPRuntime(t *testing.T) *crp.RuntimeStore {
	t.Helper()
	runtime, err := crp.NewRuntimeStore(filepath.Join(t.TempDir(), "runtime"), crp.RuntimeStoreOptions{
		Clock:       time.Now,
		HealthCheck: crp.HealthCheckFunc(func(crp.RuntimeRecord) error { return nil }),
		Revalidate:  crp.RuntimeRevalidateFunc(func(crp.RuntimeRecord) error { return nil }),
	})
	if err != nil {
		t.Fatal(err)
	}
	return runtime
}

type managedCWEDPDownloadExecutor struct {
	events   *[]string
	closeErr error
}

func (managedCWEDPDownloadExecutor) DownloadCWEDP(context.Context, consumer.Request) (consumer.Result, error) {
	return consumer.Result{}, nil
}

func (f *managedCWEDPDownloadExecutor) Close() error {
	if f.events != nil {
		*f.events = append(*f.events, "cwedp")
	}
	return f.closeErr
}

func testTemporaryNetworkWiring(t *testing.T) *ProductionTemporaryNetworkWiring {
	t.Helper()
	provider := &testTemporaryNetworkProvider{}
	wiring, err := NewProductionTemporaryNetworkWiring(provider, provider.Close)
	if err != nil {
		t.Fatal(err)
	}
	return wiring
}

type testTemporaryNetworkProvider struct {
	closed int
}

func (*testTemporaryNetworkProvider) ExecuteTemporaryHTTP(context.Context, netlease.TemporaryHTTPExecution) (netlease.HTTPResponse, error) {
	return netlease.HTTPResponse{}, nil
}

func (*testTemporaryNetworkProvider) CWEDPAdapter(context.Context, ProductionCWEDPLeaseRequest) (transport.LeaseBoundAdapter, error) {
	return nil, ErrProductionTemporaryNetworkUnavailable
}

func (p *testTemporaryNetworkProvider) Close() error {
	p.closed++
	return nil
}

func (*testTemporaryNetworkProvider) productionTemporaryNetworkBinding(storage.Store, uint64) bool {
	return true
}

func TestOpenProductionDependenciesRejectsUnwiredServeEvenWhenBackendsHealthy(t *testing.T) {
	manager, err := storage.OpenSQLite(filepath.Join(t.TempDir(), "manager.db"))
	if err != nil {
		t.Fatal(err)
	}
	control, consensus := newProductionControlPlaneFixture(t)
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
			return newProductionApprovalFake(opts.ApprovalEpoch, opts.ManagementStore), nil
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

func TestOpenProductionServeDependenciesBindsMainLauncherHandoff(t *testing.T) {
	manager, err := storage.OpenSQLite(filepath.Join(t.TempDir(), "manager.db"))
	if err != nil {
		t.Fatal(err)
	}
	control, consensus := newProductionControlPlaneFixture(t)
	cfg := productionConfigFixture(t)
	originalFactory := productionServeDependencyFactory
	t.Cleanup(func() { productionServeDependencyFactory = originalFactory })
	productionServeDependencyFactory = ProductionDependencyFactory{
		OpenManagement: func(context.Context, config.ManagementPostgreSQLConfig) (storage.Store, error) {
			return manager, nil
		},
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
			return newProductionApprovalFake(opts.ApprovalEpoch, opts.ManagementStore), nil
		},
		OpenTemporaryNetwork: func(_ context.Context, _ ProductionTemporaryNetworkOptions) (*ProductionTemporaryNetworkWiring, error) {
			return testTemporaryNetworkWiring(t), nil
		},
	}

	deps, err := openProductionServeDependencies(context.Background(), &cfg)
	if err != nil {
		_ = manager.Close()
		t.Fatalf("main launcher production open failed: %v", err)
	}
	if deps == nil || !deps.Ready || deps.Serve.ManagementStore != manager || deps.Serve.SessionValidator != manager {
		_ = deps.Close()
		t.Fatalf("main launcher did not receive the validated in-process handoff: %+v", deps)
	}
	if err := deps.Close(); err != nil {
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
			control, consensus := newProductionControlPlaneFixture(t)
			approval := newProductionApprovalFake(uint64(control.state.Epoch), manager)
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
	events := make([]string, 0, 8)
	temporary, err := NewProductionTemporaryNetworkWiring(&testTemporaryNetworkProvider{}, func() error {
		events = append(events, "temporary")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	deps := &ProductionDependencies{
		Management:       &recordingStore{Store: manager, events: &events},
		Control:          &productionControlFake{closeEvents: &events},
		Consensus:        &productionConsensusFake{closeEvents: &events},
		Redis:            &productionHealthFake{closeEvents: &events},
		Approval:         &productionApprovalFake{closeEvents: &events},
		TemporaryNetwork: temporary,
		CWEDPDownload:    &managedCWEDPDownloadExecutor{events: &events},
		CRP:              &testProductionCRPDependency{events: &events},
	}
	if err := deps.Close(); err != nil {
		t.Fatal(err)
	}
	want := []string{"crp", "cwedp", "temporary", "approval", "redis", "consensus", "control", "management"}
	if strings.Join(events, ",") != strings.Join(want, ",") {
		t.Fatalf("close order=%v, want %v", events, want)
	}
}

func TestProductionDependenciesCloseManagedCWEDPErrorContinuesAndIsIdempotent(t *testing.T) {
	manager, err := storage.OpenSQLite(filepath.Join(t.TempDir(), "manager.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	events := make([]string, 0, 2)
	wantErr := errors.New("CWEDP close failed")
	deps := &ProductionDependencies{
		Management:    &recordingStore{Store: manager, events: &events},
		CWEDPDownload: &managedCWEDPDownloadExecutor{events: &events, closeErr: wantErr},
	}
	if got := deps.Close(); !errors.Is(got, wantErr) {
		t.Fatalf("Close() error=%v, want %v", got, wantErr)
	}
	if got, want := strings.Join(events, ","), "cwedp,management"; got != want {
		t.Fatalf("close events=%q, want %q", got, want)
	}
	if got := deps.Close(); !errors.Is(got, wantErr) {
		t.Fatalf("second Close() error=%v, want original %v", got, wantErr)
	}
	if got, want := strings.Join(events, ","), "cwedp,management"; got != want {
		t.Fatalf("second Close() repeated resources: %q, want %q", got, want)
	}
}

func TestValidateProductionTemporaryNetworkOptionsRejectsMissingProviderManagementBindingAndFence(t *testing.T) {
	manager, err := storage.OpenSQLite(filepath.Join(t.TempDir(), "manager.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	open := func(context.Context, ProductionTemporaryNetworkOptions) (*ProductionTemporaryNetworkWiring, error) {
		return testTemporaryNetworkWiring(t), nil
	}
	base := ProductionStartupOptions{DataDir: t.TempDir()}
	tests := []struct {
		name       string
		opts       ProductionStartupOptions
		management storage.Store
		epoch      uint64
		open       func(context.Context, ProductionTemporaryNetworkOptions) (*ProductionTemporaryNetworkWiring, error)
		want       error
	}{
		{name: "missing provider", opts: base, management: manager, epoch: 7, want: ErrProductionTemporaryNetworkUnavailable},
		{name: "relative runtime data directory", opts: ProductionStartupOptions{DataDir: "data"}, management: manager, epoch: 7, open: open, want: ErrProductionTemporaryNetworkUnavailable},
		{name: "unbound management store", opts: ProductionStartupOptions{ManagementStore: &recordingStore{}}, management: manager, epoch: 7, open: open, want: ErrProductionTemporaryNetworkUnavailable},
		{name: "zero policy fence", opts: base, management: manager, open: open, want: ErrProductionTemporaryNetworkUnavailable},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateProductionTemporaryNetworkOptions(tc.opts, tc.management, tc.epoch, tc.open)
			if !errors.Is(err, tc.want) {
				t.Fatalf("validation error=%v, want %v", err, tc.want)
			}
		})
	}
}

func TestProductionTemporaryNetworkWiringRejectsMissingProviderAndClosesOnce(t *testing.T) {
	_, err := NewProductionTemporaryNetworkWiring(nil, func() error { return nil })
	if !errors.Is(err, ErrProductionTemporaryNetworkUnavailable) {
		t.Fatalf("missing provider error=%v, want ErrProductionTemporaryNetworkUnavailable", err)
	}
	provider := &testTemporaryNetworkProvider{}
	wiring, err := NewProductionTemporaryNetworkWiring(provider, provider.Close)
	if err != nil {
		t.Fatal(err)
	}
	if err := wiring.Close(); err != nil {
		t.Fatal(err)
	}
	if err := wiring.Close(); err != nil {
		t.Fatal(err)
	}
	if provider.closed != 1 {
		t.Fatalf("provider cleanup calls=%d, want one", provider.closed)
	}
}

func TestProductionServeWiringRequiresManagementSessionValidatorIdentity(t *testing.T) {
	manager, err := storage.OpenSQLite(filepath.Join(t.TempDir(), "manager.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	otherManager, err := storage.OpenSQLite(filepath.Join(t.TempDir(), "other-manager.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer otherManager.Close()

	state := testProductionState(t)
	for _, tc := range []struct {
		name      string
		validator middleware.SessionValidator
		wantErr   bool
	}{
		{name: "nil validator", wantErr: true},
		{name: "different management store", validator: otherManager, wantErr: true},
		{name: "same management store", validator: manager},
	} {
		t.Run(tc.name, func(t *testing.T) {
			approval := newProductionApprovalFake(uint64(state.Epoch), tc.validator)
			deps := &ProductionDependencies{
				Management:       manager,
				Startup:          controlplane.StartupResult{Ready: true, Stage: controlplane.StartupStageReady, State: state},
				Approval:         approval,
				ApprovalHTTP:     approval.ApprovalHTTP(),
				TemporaryNetwork: testTemporaryNetworkWiring(t),
			}
			wiring, err := deps.ServeWiring()
			if tc.wantErr {
				if !errors.Is(err, ErrProductionServeWiringUnavailable) {
					t.Fatalf("ServeWiring error=%v, want ErrProductionServeWiringUnavailable", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if wiring.SessionValidator != manager {
				t.Fatalf("SessionValidator=%T %p, want management store %T %p", wiring.SessionValidator, wiring.SessionValidator, manager, manager)
			}
		})
	}
}

func TestProductionConsensusFakeRetainsExactCommitAndValidatesFenceState(t *testing.T) {
	t.Run("current commit is not reconstructed from mutable state", func(t *testing.T) {
		commit := testProductionCommit(t)
		consensus := newProductionConsensusFake(t)
		if err := consensus.Propose(context.Background(), commit); err != nil {
			t.Fatal(err)
		}
		consensus.state.UpdatedAt = consensus.state.UpdatedAt.Add(time.Hour)

		got, err := consensus.CurrentCommit(context.Background(), commit.State.ClusterID)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, commit) {
			t.Fatalf("CurrentCommit()=%+v, want exact proposed commit %+v", got, commit)
		}
	})

	t.Run("propose defensively copies commit", func(t *testing.T) {
		commit := testProductionCommit(t)
		consensus := newProductionConsensusFake(t)
		input := commit
		if err := consensus.Propose(context.Background(), input); err != nil {
			t.Fatal(err)
		}
		input.State.Desired.Payload[0] = 'X'

		got, err := consensus.CurrentCommit(context.Background(), commit.State.ClusterID)
		if err != nil {
			t.Fatal(err)
		}
		if string(got.State.Desired.Payload) != `{"sites":[]}` {
			t.Fatalf("CurrentCommit payload=%q, want defensive copy", got.State.Desired.Payload)
		}
	})

	t.Run("establish rejects a non-current snapshot", func(t *testing.T) {
		commit := testProductionCommit(t)
		consensus := newProductionConsensusFake(t)
		if err := consensus.Propose(context.Background(), commit); err != nil {
			t.Fatal(err)
		}
		mismatch := commit.State
		mismatch.Revision++
		if _, err := consensus.Establish(context.Background(), mismatch); !errors.Is(err, nativeraft.ErrFenceStale) {
			t.Fatalf("Establish error=%v, want ErrFenceStale", err)
		}
		token, err := consensus.Establish(context.Background(), commit.State)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(token, commit.Fence) {
			t.Fatalf("Establish token=%+v, want %+v", token, commit.Fence)
		}
	})
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
		DataDir:              t.TempDir(),
	}
}

func testProductionState(t *testing.T) controlplane.State {
	return testProductionCommit(t).State
}

func testProductionCommit(t *testing.T) controlplane.Commit {
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
	return commit
}

func newProductionControlPlaneFixture(t *testing.T) (*productionControlFake, *productionConsensusFake) {
	t.Helper()
	commit := testProductionCommit(t)
	return &productionControlFake{state: cloneProductionState(commit.State)}, newProductionConsensusFakeWithCommit(t, commit)
}

func cloneProductionState(state controlplane.State) controlplane.State {
	state.Desired.Payload = append([]byte(nil), state.Desired.Payload...)
	if state.NonceLedger != nil {
		ledger := make(map[string]controlplane.Revision, len(state.NonceLedger))
		for nonce, revision := range state.NonceLedger {
			ledger[nonce] = revision
		}
		state.NonceLedger = ledger
	}
	return state
}

func cloneProductionCommit(commit controlplane.Commit) controlplane.Commit {
	commit.State = cloneProductionState(commit.State)
	return commit
}

func sameProductionCommitPayload(left, right controlplane.State) bool {
	if left.ClusterID != right.ClusterID || left.Revision != right.Revision ||
		left.Desired.Version != right.Desired.Version || left.Desired.Digest != right.Desired.Digest ||
		string(left.Desired.Payload) != string(right.Desired.Payload) || len(left.NonceLedger) != len(right.NonceLedger) {
		return false
	}
	for nonce, revision := range left.NonceLedger {
		if right.NonceLedger[nonce] != revision {
			return false
		}
	}
	return true
}

func productionNonceForRevision(ledger map[string]controlplane.Revision, revision controlplane.Revision) string {
	var found string
	for nonce, candidate := range ledger {
		if candidate != revision {
			continue
		}
		if found != "" {
			return ""
		}
		found = nonce
	}
	return found
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
	lastCommit  controlplane.Commit
	hasCommit   bool
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

func newProductionConsensusFakeWithCommit(t *testing.T, commit controlplane.Commit) *productionConsensusFake {
	t.Helper()
	fake := newProductionConsensusFake(t)
	if _, err := fake.machine.InstallLeadership(commit.State.Term, commit.State.LeaderID); err != nil {
		t.Fatal(err)
	}
	if err := fake.machine.LoadSnapshot(commit.State); err != nil {
		t.Fatal(err)
	}
	fake.state = cloneProductionState(commit.State)
	fake.lastCommit = cloneProductionCommit(commit)
	fake.hasCommit = true
	return fake
}

func (*productionConsensusFake) Backend() string               { return controlplane.ConsensusBackendNativeRaft }
func (*productionConsensusFake) Prepare(context.Context) error { return nil }
func (*productionConsensusFake) Health(context.Context) error  { return nil }
func (f *productionConsensusFake) Current(context.Context, string) (controlplane.State, error) {
	return cloneProductionState(f.state), nil
}
func (f *productionConsensusFake) Propose(ctx context.Context, commit controlplane.Commit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	f.lastCommit = cloneProductionCommit(commit)
	f.hasCommit = true
	f.state = cloneProductionState(commit.State)
	return nil
}
func (f *productionConsensusFake) CurrentCommit(ctx context.Context, clusterID string) (controlplane.Commit, error) {
	if err := ctx.Err(); err != nil {
		return controlplane.Commit{}, err
	}
	if !f.hasCommit || clusterID != f.lastCommit.State.ClusterID || !sameProductionCommitPayload(f.lastCommit.State, f.state) {
		return controlplane.Commit{}, controlplane.ErrStateNotFound
	}
	return cloneProductionCommit(f.lastCommit), nil
}
func (f *productionConsensusFake) Establish(ctx context.Context, state controlplane.State) (controlplane.FenceToken, error) {
	if err := ctx.Err(); err != nil {
		return controlplane.FenceToken{}, err
	}
	if !reflect.DeepEqual(state, f.state) || state.Revision == 0 {
		return controlplane.FenceToken{}, nativeraft.ErrFenceStale
	}
	nonce := productionNonceForRevision(state.NonceLedger, state.Revision)
	if nonce == "" || f.state.NonceLedger[nonce] != state.Revision {
		return controlplane.FenceToken{}, nativeraft.ErrFenceStale
	}
	return controlplane.FenceToken{
		ClusterID: state.ClusterID,
		LeaderID:  state.LeaderID,
		Epoch:     state.Epoch,
		Revision:  state.Revision,
		Digest:    state.Desired.Digest,
		Nonce:     nonce,
	}, nil
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

func newProductionApprovalFake(epoch uint64, validator middleware.SessionValidator) *productionApprovalFake {
	return &productionApprovalFake{
		approvalHTTP: handler.NewApprovalHTTPHandler(handler.ApprovalHTTPOptions{Gate: approval.NewGate(epoch), SessionValidator: validator}),
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
func (f *productionApprovalFake) ApprovalClaimResolver() activation.ApprovalClaimResolver {
	return func(context.Context, activation.AuthorizationRequest) (activation.ApprovalClaim, error) {
		return activation.ApprovalClaim{}, activation.ErrApprovalClaimUnavailable
	}
}

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
