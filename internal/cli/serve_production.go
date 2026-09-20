package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/api/handler"
	approvalruntime "github.com/LaokeQwQ/CheeseWAF/internal/approval/runtime"
	"github.com/LaokeQwQ/CheeseWAF/internal/cluster/redis"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/controlplane"
	"github.com/LaokeQwQ/CheeseWAF/internal/controlplane/nativeraft"
	controlpostgres "github.com/LaokeQwQ/CheeseWAF/internal/controlplane/postgres"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
	storagepostgres "github.com/LaokeQwQ/CheeseWAF/internal/storage/postgres"
)

var (
	// ErrProductionServeWiringUnavailable means the adapters passed their
	// health probes but the request-serving layer did not explicitly bind them.
	// A healthy backend is not sufficient evidence that cheesewaf serve can
	// safely consume it.
	ErrProductionServeWiringUnavailable   = errors.New("production serve wiring is unavailable")
	ErrProductionRedisUnavailable         = errors.New("production Redis dependency is unavailable")
	ErrProductionApprovalUnavailable      = errors.New("production approval dependency is unavailable")
	ErrProductionApprovalHTTPUnavailable  = errors.New("production approval HTTP handler is unavailable")
	ErrProductionApprovalEpochUnavailable = errors.New("production approval policy epoch is unavailable")
	ErrProductionApprovalEpochMismatch    = errors.New("production approval policy epoch does not match control-plane epoch")
	ErrProductionServeWiringConflict      = errors.New("production serve wiring callbacks are mutually exclusive")
)

// ProductionStartupOptions is deliberately separate from the serializable
// Config. It prevents an incomplete production startup contract from being
// enabled merely by adding a YAML key. A deployment launcher must provide both
// PostgreSQL roles, explicit native-raft options, and a Redis identity.
type ProductionStartupOptions struct {
	Profile              string
	ClusterID            string
	ManagementPostgreSQL config.ManagementPostgreSQLConfig
	ControlPostgreSQL    config.ManagementPostgreSQLConfig
	NativeRaft           nativeraft.Options
	Redis                redis.Config
	RedisEnabled         bool
	// ManagementStore and ApprovalEpoch are populated only after the
	// control-plane Bootstrap succeeds. They keep the production approval
	// opener explicitly bound to the same management store and current durable
	// fencing generation; they are not serialized configuration fields.
	ManagementStore storage.Store
	ApprovalEpoch   uint64
}

// ProductionControlDependency is the control-plane PostgreSQL adapter. It is
// intentionally not storage.Store: control-plane desired-state commits have a
// different contract from management sites, users, sessions, and reviews.
type ProductionControlDependency interface {
	controlplane.DurableBootstrap
	Close() error
}

// ProductionConsensusDependency combines native-raft consensus and fencing.
// Machine is required so Bootstrap can install the verified snapshot into the
// exact state machine owned by the consensus runtime.
type ProductionConsensusDependency interface {
	controlplane.ConsensusBootstrap
	controlplane.FenceBootstrap
	Machine() *controlplane.StateMachine
	Close() error
}

// ProductionHealthDependency is the common boundary for short-lived runtime
// dependencies such as Redis and the approval service.
type ProductionHealthDependency interface {
	Health(context.Context) error
	Close() error
}

// ProductionApprovalDependency is the complete production approval boundary.
// The handler and policy epoch are part of the contract so a healthy but
// incomplete approval fake cannot reach the request-serving layer.
type ProductionApprovalDependency interface {
	ProductionHealthDependency
	ApprovalHTTP() *handler.ApprovalHTTPHandler
	PolicyEpoch() uint64
}

// ProductionServeWiring is the validated composition-root handoff consumed by
// the request-serving layer. It binds the management store, control-plane
// readiness snapshot, and approval HTTP transport to one policy epoch.
type ProductionServeWiring struct {
	ManagementStore storage.Store
	Startup         controlplane.StartupResult
	ApprovalHTTP    *handler.ApprovalHTTPHandler
	PolicyEpoch     uint64
}

// ProductionDependencyFactory opens each production dependency. Every opener
// is injected so tests and embedding launchers can prove ordering and cleanup
// without pretending that a fake backend is a production deployment.
type ProductionDependencyFactory struct {
	OpenManagement func(context.Context, config.ManagementPostgreSQLConfig) (storage.Store, error)
	OpenControl    func(context.Context, config.ManagementPostgreSQLConfig) (ProductionControlDependency, error)
	OpenConsensus  func(context.Context, nativeraft.Options) (ProductionConsensusDependency, error)
	OpenRedis      func(context.Context, redis.Config) (ProductionHealthDependency, error)
	OpenApproval   func(context.Context, ProductionStartupOptions) (ProductionApprovalDependency, error)
	// WireServe is the legacy production composition hook. Keep it for
	// embedding launchers compiled against the original API.
	WireServe func(context.Context, *ProductionDependencies) error
	// WireServeWithWiring is the preferred hook. It receives a validated,
	// lifecycle-bound handoff and cannot be configured together with WireServe.
	WireServeWithWiring func(context.Context, ProductionServeWiring) error
}

// ProductionDependencies owns every resource opened by one production
// startup attempt. Close is idempotent and always runs in reverse dependency
// order, including when Bootstrap or final serve wiring fails.
type ProductionDependencies struct {
	Management   storage.Store
	Control      ProductionControlDependency
	Consensus    ProductionConsensusDependency
	Redis        ProductionHealthDependency
	Approval     ProductionApprovalDependency
	ApprovalHTTP *handler.ApprovalHTTPHandler
	Startup      controlplane.StartupResult
	Serve        ProductionServeWiring
	Ready        bool

	closeOnce sync.Once
	closeErr  error
}

// productionServeDependencyFactory is the process-level seam. The default
// factory opens the real adapters but deliberately leaves WireServe unset until
// Redis, approval, and every management consumer have an explicit binding.
var productionServeDependencyFactory = NewProductionDependencyFactory()

func openProductionServeDependencies(ctx context.Context, cfg *config.Config) (*ProductionDependencies, error) {
	opts, err := productionStartupOptionsFromConfig(cfg)
	if err != nil {
		return nil, err
	}
	return OpenProductionDependencies(ctx, opts, productionServeDependencyFactory)
}

func (d *ProductionDependencies) Close() error {
	if d == nil {
		return nil
	}
	d.closeOnce.Do(func() {
		close := func(fn func() error) {
			if fn == nil {
				return
			}
			if err := fn(); err != nil && d.closeErr == nil {
				d.closeErr = err
			}
		}
		close(func() error {
			if d.Approval == nil {
				return nil
			}
			return d.Approval.Close()
		})
		close(func() error {
			if d.Redis == nil {
				return nil
			}
			return d.Redis.Close()
		})
		close(func() error {
			if d.Consensus == nil {
				return nil
			}
			return d.Consensus.Close()
		})
		close(func() error {
			if d.Control == nil {
				return nil
			}
			return d.Control.Close()
		})
		close(func() error {
			if d.Management == nil {
				return nil
			}
			return d.Management.Close()
		})
	})
	return d.closeErr
}

// ServeWiring returns the validated handoff for the request-serving layer.
// It fails closed if the provider, handler Gate, or control-plane snapshot
// disagree about the policy epoch.
func (d *ProductionDependencies) ServeWiring() (ProductionServeWiring, error) {
	if d == nil || isNilProductionDependency(d.Management) || isNilProductionDependency(d.Approval) {
		return ProductionServeWiring{}, ErrProductionServeWiringUnavailable
	}
	if !d.Startup.Ready || d.Startup.Stage != controlplane.StartupStageReady || d.Startup.State.Epoch == 0 {
		return ProductionServeWiring{}, fmt.Errorf("%w: control-plane startup is not ready", ErrProductionServeWiringUnavailable)
	}
	if d.ApprovalHTTP == nil {
		return ProductionServeWiring{}, fmt.Errorf("%w: approval HTTP handler is unavailable", ErrProductionServeWiringUnavailable)
	}
	controlEpoch := uint64(d.Startup.State.Epoch)
	providerEpoch := d.Approval.PolicyEpoch()
	handlerEpoch := d.ApprovalHTTP.PolicyEpoch()
	if providerEpoch == 0 || handlerEpoch == 0 || controlEpoch == 0 {
		return ProductionServeWiring{}, fmt.Errorf("%w: provider=%d handler=%d control-plane=%d", ErrProductionServeWiringUnavailable, providerEpoch, handlerEpoch, controlEpoch)
	}
	if providerEpoch != controlEpoch || handlerEpoch != providerEpoch {
		return ProductionServeWiring{}, fmt.Errorf("%w: provider=%d handler=%d control-plane=%d", ErrProductionServeWiringUnavailable, providerEpoch, handlerEpoch, controlEpoch)
	}
	return ProductionServeWiring{
		ManagementStore: d.Management,
		Startup:         d.Startup,
		ApprovalHTTP:    d.ApprovalHTTP,
		PolicyEpoch:     controlEpoch,
	}, nil
}

// OpenProductionDependencies executes the complete production startup unit.
// It never returns a partially initialized dependency set. In particular, a
// control-plane store is never returned as a management storage.Store.
func OpenProductionDependencies(ctx context.Context, opts ProductionStartupOptions, factory ProductionDependencyFactory) (*ProductionDependencies, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := validateProductionStartupOptions(opts, factory); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("%w: production startup context canceled: %w", config.ErrProductionStorageUnavailable, err)
	}

	deps := &ProductionDependencies{}
	fail := func(stage string, err error) (*ProductionDependencies, error) {
		_ = deps.Close()
		switch {
		case errors.Is(err, ErrProductionServeWiringUnavailable):
			return nil, fmt.Errorf("%w: %w: %s", config.ErrProductionStorageUnavailable, ErrProductionServeWiringUnavailable, stage)
		case errors.Is(err, ErrProductionRedisUnavailable):
			return nil, fmt.Errorf("%w: %w: %s", config.ErrProductionStorageUnavailable, ErrProductionRedisUnavailable, stage)
		case errors.Is(err, ErrProductionApprovalUnavailable):
			return nil, fmt.Errorf("%w: %w: %s: %w", config.ErrProductionStorageUnavailable, ErrProductionApprovalUnavailable, stage, err)
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			return nil, fmt.Errorf("%w: %s: %w", config.ErrProductionStorageUnavailable, stage, err)
		default:
			return nil, fmt.Errorf("%w: %s", config.ErrProductionStorageUnavailable, stage)
		}
	}

	managementCtx, cancelManagement := dependencyContext(ctx, opts.ManagementPostgreSQL.Timeout)
	management, err := factory.OpenManagement(managementCtx, opts.ManagementPostgreSQL)
	if !isNilProductionDependency(management) {
		deps.Management = management
	}
	if err == nil && !isNilProductionDependency(management) {
		err = management.Migrate(managementCtx)
	}
	cancelManagement()
	if err != nil || isNilProductionDependency(management) {
		return fail("management PostgreSQL could not be opened", err)
	}
	if err := ctx.Err(); err != nil {
		return fail("production startup context canceled after management PostgreSQL", err)
	}
	if err := ctx.Err(); err != nil {
		return fail("production startup context canceled before control PostgreSQL", err)
	}

	controlCtx, cancelControl := dependencyContext(ctx, opts.ControlPostgreSQL.Timeout)
	control, err := factory.OpenControl(controlCtx, opts.ControlPostgreSQL)
	cancelControl()
	if !isNilProductionDependency(control) {
		deps.Control = control
	}
	if err != nil || isNilProductionDependency(control) {
		return fail("control PostgreSQL could not be opened", err)
	}

	consensus, err := factory.OpenConsensus(ctx, opts.NativeRaft)
	if !isNilProductionDependency(consensus) {
		deps.Consensus = consensus
	}
	if err != nil || isNilProductionDependency(consensus) {
		return fail("native-raft could not be opened", err)
	}
	if consensus.Machine() == nil {
		return fail("native-raft state machine is unavailable", nil)
	}
	if err := ctx.Err(); err != nil {
		return fail("production startup context canceled before control-plane Bootstrap", err)
	}

	startup, err := controlplane.Bootstrap(ctx, controlplane.StartupOptions{
		Profile:   config.StorageProfileProduction,
		ClusterID: opts.ClusterID,
		Machine:   consensus.Machine(),
		Durable:   control,
		Consensus: consensus,
		Fencer:    consensus,
	})
	if err != nil || startup.Stage != controlplane.StartupStageReady || !startup.Ready {
		return fail("control-plane Bootstrap did not reach ready", err)
	}
	deps.Startup = startup

	if !opts.RedisEnabled {
		return fail("Redis is not enabled for production", ErrProductionRedisUnavailable)
	}
	redisCtx, cancelRedis := dependencyContext(ctx, opts.Redis.DialTimeout)
	redisDep, err := factory.OpenRedis(redisCtx, opts.Redis)
	if !isNilProductionDependency(redisDep) {
		deps.Redis = redisDep
	}
	if err != nil || isNilProductionDependency(redisDep) {
		cancelRedis()
		return fail("Redis could not be opened", err)
	}
	if err := redisDep.Health(redisCtx); err != nil {
		cancelRedis()
		return fail("Redis health check failed", err)
	}
	cancelRedis()
	if err := ctx.Err(); err != nil {
		return fail("production startup context canceled before approval dependency", err)
	}

	approvalOpts := opts
	approvalOpts.ManagementStore = management
	approvalOpts.ApprovalEpoch = uint64(startup.State.Epoch)
	approvalDep, err := factory.OpenApproval(ctx, approvalOpts)
	if !isNilProductionDependency(approvalDep) {
		deps.Approval = approvalDep
	}
	if err != nil || isNilProductionDependency(approvalDep) {
		if err == nil {
			err = ErrProductionApprovalUnavailable
		}
		return fail("approval dependency could not be opened", err)
	}
	if err := approvalDep.Health(ctx); err != nil {
		return fail("approval dependency health check failed", err)
	}
	provider, err := validateProductionApprovalDependency(approvalDep, uint64(startup.State.Epoch))
	if err != nil {
		return fail("approval dependency contract is incomplete", err)
	}
	deps.ApprovalHTTP = provider.ApprovalHTTP()
	wiring, err := deps.ServeWiring()
	if err != nil {
		return fail("production serve wiring contract is incomplete", err)
	}
	deps.Serve = wiring

	if factory.WireServe != nil && factory.WireServeWithWiring != nil {
		return fail("both legacy and typed serve wiring callbacks are configured", ErrProductionServeWiringConflict)
	}
	if factory.WireServe == nil && factory.WireServeWithWiring == nil {
		return fail("management, control, Redis and approval consumers are not wired into serve", ErrProductionServeWiringUnavailable)
	}
	if factory.WireServeWithWiring != nil {
		if err := factory.WireServeWithWiring(ctx, wiring); err != nil {
			return fail("serve consumers rejected production dependencies", err)
		}
	} else if err := factory.WireServe(ctx, deps); err != nil {
		return fail("serve consumers rejected production dependencies", err)
	}
	deps.Ready = true
	return deps, nil
}

// validateProductionApprovalDependency enforces the approval capability
// contract immediately before serve wiring. The any input keeps this helper
// able to prove that a weak implementation is rejected even though the
// ProductionDependencyFactory itself only accepts the strong return type.
func validateProductionApprovalDependency(value any, expectedEpoch uint64) (ProductionApprovalDependency, error) {
	if isNilProductionDependency(value) {
		return nil, fmt.Errorf("%w: nil dependency", ErrProductionApprovalUnavailable)
	}
	provider, ok := value.(ProductionApprovalDependency)
	if !ok {
		return nil, fmt.Errorf("%w: weak dependency does not expose ApprovalHTTP and PolicyEpoch", ErrProductionApprovalUnavailable)
	}
	if provider.ApprovalHTTP() == nil {
		return nil, fmt.Errorf("%w: %w", ErrProductionApprovalUnavailable, ErrProductionApprovalHTTPUnavailable)
	}
	policyEpoch := provider.PolicyEpoch()
	if policyEpoch == 0 || expectedEpoch == 0 {
		return nil, fmt.Errorf("%w: %w: approval=%d control-plane=%d", ErrProductionApprovalUnavailable, ErrProductionApprovalEpochUnavailable, policyEpoch, expectedEpoch)
	}
	if policyEpoch != expectedEpoch {
		return nil, fmt.Errorf("%w: %w: approval=%d control-plane=%d", ErrProductionApprovalUnavailable, ErrProductionApprovalEpochMismatch, policyEpoch, expectedEpoch)
	}
	return provider, nil
}

func dependencyContext(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		return parent, func() {}
	}
	return context.WithTimeout(parent, timeout)
}

func validateProductionStartupOptions(opts ProductionStartupOptions, factory ProductionDependencyFactory) error {
	if strings.ToLower(strings.TrimSpace(opts.Profile)) != config.StorageProfileProduction {
		return fmt.Errorf("%w: production profile is required", config.ErrProductionStorageUnavailable)
	}
	if !controlplane.ValidIdentity(opts.ClusterID) {
		return fmt.Errorf("%w: cluster ID is required", config.ErrProductionStorageUnavailable)
	}
	if strings.TrimSpace(opts.ManagementPostgreSQL.DSN) == "" || strings.TrimSpace(opts.ControlPostgreSQL.DSN) == "" {
		return fmt.Errorf("%w: independent management and control PostgreSQL DSNs are required", config.ErrProductionStorageUnavailable)
	}
	if opts.NativeRaft.Profile == "" {
		opts.NativeRaft.Profile = config.StorageProfileProduction
	}
	if strings.ToLower(strings.TrimSpace(opts.NativeRaft.Profile)) != config.StorageProfileProduction || !controlplane.ValidIdentity(opts.NativeRaft.ClusterID) || opts.NativeRaft.ClusterID != opts.ClusterID {
		return fmt.Errorf("%w: native-raft production options are invalid", config.ErrProductionStorageUnavailable)
	}
	if opts.NativeRaft.DataDir == "" || opts.NativeRaft.BindAddress == "" || opts.NativeRaft.Mode == "" {
		return fmt.Errorf("%w: native-raft data directory, bind address and explicit mode are required", config.ErrProductionStorageUnavailable)
	}
	if !opts.RedisEnabled {
		return fmt.Errorf("%w: Redis must be enabled for production", config.ErrProductionStorageUnavailable)
	}
	if strings.TrimSpace(opts.Redis.Addr) == "" && strings.TrimSpace(opts.Redis.URL) == "" && strings.TrimSpace(opts.Redis.RedisURL) == "" {
		return fmt.Errorf("%w: Redis address is required", config.ErrProductionStorageUnavailable)
	}
	if !controlplane.ValidIdentity(opts.Redis.InstanceID) {
		return fmt.Errorf("%w: Redis instance identity is required", config.ErrProductionStorageUnavailable)
	}
	if factory.OpenManagement == nil || factory.OpenControl == nil || factory.OpenConsensus == nil || factory.OpenRedis == nil || factory.OpenApproval == nil {
		return fmt.Errorf("%w: all production dependency openers are required", config.ErrProductionStorageUnavailable)
	}
	if factory.WireServe != nil && factory.WireServeWithWiring != nil {
		return fmt.Errorf("%w: %w", config.ErrProductionStorageUnavailable, ErrProductionServeWiringConflict)
	}
	return nil
}

func isNilProductionDependency(value any) bool {
	if value == nil {
		return true
	}
	rv := reflect.ValueOf(value)
	switch rv.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return rv.IsNil()
	default:
		return false
	}
}

func consensusNodeID(consensus ProductionConsensusDependency) string {
	if provider, ok := consensus.(interface{ NodeID() string }); ok {
		if nodeID := strings.TrimSpace(provider.NodeID()); nodeID != "" {
			return nodeID
		}
	}
	return "node"
}

func newDefaultProductionDependencyFactory() ProductionDependencyFactory {
	return ProductionDependencyFactory{
		OpenManagement: func(ctx context.Context, cfg config.ManagementPostgreSQLConfig) (storage.Store, error) {
			store, err := storagepostgres.Open(ctx, cfg.DSN)
			if err != nil {
				return nil, err
			}
			if err := store.Migrate(ctx); err != nil {
				_ = store.Close()
				return nil, err
			}
			if err := store.Health(ctx); err != nil {
				_ = store.Close()
				return nil, err
			}
			return store, nil
		},
		OpenControl: func(ctx context.Context, cfg config.ManagementPostgreSQLConfig) (ProductionControlDependency, error) {
			return controlpostgres.Open(ctx, cfg.DSN)
		},
		OpenConsensus: func(_ context.Context, opts nativeraft.Options) (ProductionConsensusDependency, error) {
			return nativeraft.New(opts)
		},
		OpenRedis: func(ctx context.Context, cfg redis.Config) (ProductionHealthDependency, error) {
			adapter, err := redis.Open(ctx, cfg)
			if err != nil {
				return nil, err
			}
			return productionRedisDependency{RuntimeAdapter: adapter}, nil
		},
		OpenApproval: func(ctx context.Context, opts ProductionStartupOptions) (ProductionApprovalDependency, error) {
			if opts.ManagementStore == nil || opts.ApprovalEpoch == 0 || strings.TrimSpace(opts.ControlPostgreSQL.DSN) == "" {
				return nil, ErrProductionApprovalUnavailable
			}
			return approvalruntime.Open(ctx, approvalruntime.Options{
				Management:  opts.ManagementStore,
				ApprovalDSN: opts.ControlPostgreSQL.DSN,
				PolicyEpoch: opts.ApprovalEpoch,
			})
		},
	}
}

// NewProductionDependencyFactory returns the real adapter openers. Callers
// that need deterministic tests should replace individual callbacks and keep
// WireServe explicit.
func NewProductionDependencyFactory() ProductionDependencyFactory {
	return newDefaultProductionDependencyFactory()
}

// DefaultProductionDependencyFactory is an explicit alias for launchers that
// prefer factory terminology over constructor terminology.
func DefaultProductionDependencyFactory() ProductionDependencyFactory {
	return NewProductionDependencyFactory()
}

// productionRedisDependency adapts the Redis runtime probe name (Ping) to the
// generic dependency health boundary used by the serve lifecycle.
type productionRedisDependency struct {
	*redis.RuntimeAdapter
}

func (d productionRedisDependency) Health(ctx context.Context) error {
	if d.RuntimeAdapter == nil {
		return ErrProductionRedisUnavailable
	}
	return d.RuntimeAdapter.Ping(ctx)
}

func productionStartupOptionsFromConfig(cfg *config.Config) (ProductionStartupOptions, error) {
	if cfg == nil {
		return ProductionStartupOptions{}, fmt.Errorf("%w: config is nil", config.ErrProductionStorageUnavailable)
	}
	clusterID := cfg.Cluster.ClusterID
	if !controlplane.ValidIdentity(clusterID) {
		return ProductionStartupOptions{}, fmt.Errorf("%w: cluster.cluster_id is required for production", config.ErrProductionStorageUnavailable)
	}
	controlDSN := strings.TrimSpace(cfg.Storage.ControlPostgreSQL.DSN)
	if controlDSN == "" {
		controlDSN = strings.TrimSpace(os.Getenv("CHEESEWAF_CONTROL_POSTGRES_DSN"))
	}
	nodeID := cfg.Cluster.NodeID
	if nodeID != "" && !controlplane.ValidIdentity(nodeID) {
		return ProductionStartupOptions{}, fmt.Errorf("%w: cluster.node_id must not contain whitespace or invisible characters", config.ErrProductionStorageUnavailable)
	}
	raft := cfg.Cluster.Consensus.NativeRaft
	raftDir := strings.TrimSpace(raft.DataDir)
	if raftDir == "" {
		raftDir = filepath.Join(cfg.Setup.DataDir, "cluster", "native-raft")
	}
	if !filepath.IsAbs(raftDir) {
		raftDir = rebaseUnderDataDir(raftDir, cfg.Setup.DataDir)
	}
	instanceID := cfg.Storage.Redis.InstanceID
	if instanceID == "" {
		instanceID = os.Getenv("CHEESEWAF_REDIS_INSTANCE_ID")
	}
	if instanceID != "" && !controlplane.ValidIdentity(instanceID) {
		return ProductionStartupOptions{}, fmt.Errorf("%w: storage.redis.instance_id must not contain whitespace or invisible characters", config.ErrProductionStorageUnavailable)
	}
	controlTimeout := cfg.Storage.ControlPostgreSQL.Timeout
	if controlTimeout <= 0 {
		controlTimeout = cfg.Storage.ManagementPostgreSQL.Timeout
	}
	return ProductionStartupOptions{
		Profile:              config.StorageProfileProduction,
		ClusterID:            clusterID,
		ManagementPostgreSQL: cfg.Storage.ManagementPostgreSQL,
		ControlPostgreSQL:    config.ManagementPostgreSQLConfig{DSN: controlDSN, Timeout: controlTimeout},
		NativeRaft:           nativeraft.Options{Profile: config.StorageProfileProduction, ClusterID: clusterID, NodeID: nodeID, DataDir: raftDir, BindAddress: raft.Listen, Mode: nativeraft.StartMode(raft.Mode)},
		Redis:                redis.Config{Addr: cfg.Storage.Redis.Address, InstanceID: instanceID, DialTimeout: cfg.Storage.ManagementPostgreSQL.Timeout},
		RedisEnabled:         cfg.Storage.Redis.Enabled,
	}, nil
}
