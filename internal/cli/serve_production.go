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
	"github.com/LaokeQwQ/CheeseWAF/internal/api/middleware"
	approvalruntime "github.com/LaokeQwQ/CheeseWAF/internal/approval/runtime"
	"github.com/LaokeQwQ/CheeseWAF/internal/cluster/redis"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/controlplane"
	"github.com/LaokeQwQ/CheeseWAF/internal/controlplane/nativeraft"
	controlpostgres "github.com/LaokeQwQ/CheeseWAF/internal/controlplane/postgres"
	"github.com/LaokeQwQ/CheeseWAF/internal/crp"
	"github.com/LaokeQwQ/CheeseWAF/internal/crp/activation"
	"github.com/LaokeQwQ/CheeseWAF/internal/cwedp/consumer"
	cwedppostgres "github.com/LaokeQwQ/CheeseWAF/internal/cwedp/postgres"
	"github.com/LaokeQwQ/CheeseWAF/internal/cwedp/transport"
	"github.com/LaokeQwQ/CheeseWAF/internal/netlease"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
	storagepostgres "github.com/LaokeQwQ/CheeseWAF/internal/storage/postgres"
)

var (
	// ErrProductionServeWiringUnavailable means the adapters passed their
	// health probes but the request-serving layer did not explicitly bind them.
	// A healthy backend is not sufficient evidence that cheesewaf serve can
	// safely consume it.
	ErrProductionServeWiringUnavailable      = errors.New("production serve wiring is unavailable")
	ErrProductionRedisUnavailable            = errors.New("production Redis dependency is unavailable")
	ErrProductionApprovalUnavailable         = errors.New("production approval dependency is unavailable")
	ErrProductionApprovalHTTPUnavailable     = errors.New("production approval HTTP handler is unavailable")
	ErrProductionApprovalEpochUnavailable    = errors.New("production approval policy epoch is unavailable")
	ErrProductionApprovalEpochMismatch       = errors.New("production approval policy epoch does not match control-plane epoch")
	ErrProductionServeWiringConflict         = errors.New("production serve wiring callbacks are mutually exclusive")
	ErrProductionTemporaryNetworkUnavailable = errors.New("production temporary network provider is unavailable")
	ErrProductionTemporaryNetworkSession     = errors.New("production temporary network management session is invalid")
	ErrProductionTemporaryNetworkAudit       = errors.New("production temporary network audit sink is unavailable")
	ErrProductionTemporaryNetworkAdapter     = errors.New("production temporary network adapter is not lease-bound")
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
	// DataDir is the runtime-owned root for durable temporary-network audit
	// records. It is never read from or written to the tracked config template.
	DataDir string
	// CWEDP carries only runtime-owned paths and the control PostgreSQL DSN
	// needed by the production download composition. It is never serialized in
	// the tracked YAML config; missing admission files fail closed.
	CWEDP ProductionCWEDPOptions
	// CRP contains runtime-only transport endpoints and certificate paths. The
	// composition root fills durable authority, the exact CWEDP runtime, live
	// consensus fence and approval resolver after bootstrap.
	CRP ProductionCRPOptions
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
	ApprovalClaimResolver() activation.ApprovalClaimResolver
}

// ProductionServeWiring is the validated composition-root handoff consumed by
// the request-serving layer. It binds the management store, control-plane
// readiness snapshot, and approval HTTP transport to one policy epoch.
type ProductionServeWiring struct {
	ManagementStore       storage.Store
	Startup               controlplane.StartupResult
	ApprovalHTTP          *handler.ApprovalHTTPHandler
	SessionValidator      middleware.SessionValidator
	PolicyEpoch           uint64
	TemporaryHTTPExecutor netlease.TemporaryHTTPExecutor
	TemporaryNetwork      ProductionTemporaryNetworkProvider
	CWEDPDownload         consumer.Executor
	CRPActivation         handler.CRPActivationExecutor
	CWEDP                 ProductionCWEDPOptions
}

// ProductionTemporaryNetworkOptions is the narrow input contract for the
// production temporary-network provider. The provider receives the durable
// management store and current fence, then obtains identity/session/lease
// state from each request rather than startup options.
type ProductionTemporaryNetworkOptions struct {
	ManagementStore storage.Store
	PolicyEpoch     uint64
	DataDir         string
}

// ProductionCWEDPLeaseRequest is the request-scoped capability needed to
// obtain one CWEDP HTTP adapter. The caller supplies the authenticated
// management identity and fresh password confirmation; no identity, session,
// lease, or adapter is retained in production startup state.
type ProductionCWEDPLeaseRequest struct {
	Identity       netlease.AdministratorIdentity
	Password       string
	PluginID       string
	PluginVersion  string
	Target         netlease.Target
	TLSFingerprint string
	PolicyEpoch    uint64
	TTL            time.Duration
	MaxBytes       int64
}

// ProductionTemporaryNetworkProvider is the request-level temporary-egress
// boundary. ExecuteTemporaryHTTP and CWEDPAdapter must independently validate
// the current management session, confirmation, fence, expiry, and cleanup.
type ProductionTemporaryNetworkProvider interface {
	netlease.TemporaryHTTPExecutor
	CWEDPAdapter(context.Context, ProductionCWEDPLeaseRequest) (transport.LeaseBoundAdapter, error)
	Close() error
}

// productionTemporaryNetworkBinder is intentionally package-private. The
// production composition root requires a proof from the provider's concrete
// lifetime owner that its session gate uses the exact management store and
// policy fence, rather than trusting an exported, forgeable reported value.
type productionTemporaryNetworkBinder interface {
	productionTemporaryNetworkBinding(storage.Store, uint64) bool
}

// ProductionTemporaryNetworkWiring owns the only network capabilities that
// production serve may receive. It exposes neither a broker, socket, nor a
// reusable HTTP client. Close is idempotent and owned by ProductionDependencies.
type ProductionTemporaryNetworkWiring struct {
	Provider ProductionTemporaryNetworkProvider

	closeOnce sync.Once
	closeErr  error
	closeFn   func() error
}

// NewProductionTemporaryNetworkWiring validates and wraps a provider that
// mints one temporary session and one lease per request.
func NewProductionTemporaryNetworkWiring(provider ProductionTemporaryNetworkProvider, closeFn func() error) (*ProductionTemporaryNetworkWiring, error) {
	if isNilProductionDependency(provider) || closeFn == nil {
		return nil, ErrProductionTemporaryNetworkUnavailable
	}
	return &ProductionTemporaryNetworkWiring{Provider: provider, closeFn: closeFn}, nil
}

// Close releases provider-owned resources exactly once, including when later
// serve wiring or startup cancellation rejects the composition.
func (w *ProductionTemporaryNetworkWiring) Close() error {
	if w == nil {
		return nil
	}
	w.closeOnce.Do(func() {
		if w.closeFn != nil {
			w.closeErr = w.closeFn()
		}
	})
	return w.closeErr
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
	// OpenTemporaryNetwork creates the session-bound provider used by the main
	// serve composition root. Callers embedding this factory may replace it,
	// but must preserve the same management-store and policy-epoch binding.
	OpenTemporaryNetwork func(context.Context, ProductionTemporaryNetworkOptions) (*ProductionTemporaryNetworkWiring, error)
	// OpenCWEDPDownload supplies the complete durable CWEDP/CRP consumer. If it
	// is omitted the corresponding management route remains absent; if present,
	// startup rejects a failed or nil consumer rather than exposing a partial
	// download path.
	OpenCWEDPDownload func(context.Context, ProductionServeWiring) (consumer.Executor, error)
	// The following openers are the runtime-owned CWEDP composition seams used
	// by the default download opener. They are separate so deployment launchers
	// can bind durable control-plane adapters without weakening admission.
	OpenCWEDPAdmission   func(context.Context, ProductionCWEDPOptions) (ProductionCWEDPAdmission, error)
	OpenCWEDPResumeStore func(context.Context, ProductionCWEDPOptions) (*cwedppostgres.ResumeStore, error)
	OpenCWEDPRuntime     func(context.Context, ProductionCWEDPOptions, ProductionCWEDPAdmission) (*crp.RuntimeStore, error)
	OpenCRP              func(context.Context, ProductionCRPCompositionOptions) (ProductionCRPDependency, error)
	// WireServe is the legacy production composition hook. Keep it for
	// embedding launchers compiled against the original API.
	WireServe func(context.Context, *ProductionDependencies) error
	// WireServeWithWiring is the preferred hook. It receives a validated,
	// lifecycle-bound handoff and cannot be configured together with WireServe.
	WireServeWithWiring func(context.Context, ProductionServeWiring) error
}

// ProductionCWEDPDownloadCloser is the optional lifecycle contract for an
// explicitly injected CWEDP consumer. The factory keeps returning the
// consumer.Executor compatibility interface, while composition roots that
// open durable resources (for example a PostgreSQL ResumeStore) can return a
// consumer that releases those resources here.
type ProductionCWEDPDownloadCloser interface {
	consumer.Executor
	Close() error
}

type productionCWEDPCRPRuntimeOwner interface {
	consumer.Executor
	CRPRuntime() *crp.RuntimeStore
	CRPActivationPolicy() activation.Policy
}

// ProductionDependencies owns every resource opened by one production
// startup attempt. Close is idempotent and always runs in reverse dependency
// order, including when Bootstrap or final serve wiring fails.
type ProductionDependencies struct {
	Management       storage.Store
	Control          ProductionControlDependency
	Consensus        ProductionConsensusDependency
	Redis            ProductionHealthDependency
	Approval         ProductionApprovalDependency
	ApprovalHTTP     *handler.ApprovalHTTPHandler
	TemporaryNetwork *ProductionTemporaryNetworkWiring
	CWEDPDownload    consumer.Executor
	CRP              ProductionCRPDependency
	Startup          controlplane.StartupResult
	CWEDP            ProductionCWEDPOptions
	Serve            ProductionServeWiring
	Ready            bool

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
	// The main serve command is itself the production composition root. Keep
	// OpenProductionDependencies fail-closed for embedded callers that forget
	// to bind a serving layer, but provide the real in-process handoff here so
	// the launcher can consume the validated wiring when it builds the router
	// and listeners below.
	factory := productionServeDependencyFactory
	if factory.WireServe == nil && factory.WireServeWithWiring == nil {
		factory.WireServeWithWiring = func(_ context.Context, wiring ProductionServeWiring) error {
			if isNilProductionDependency(wiring.ManagementStore) || wiring.ApprovalHTTP == nil ||
				isNilProductionDependency(wiring.SessionValidator) || isNilProductionDependency(wiring.TemporaryNetwork) {
				return fmt.Errorf("%w: main serve received incomplete production wiring", ErrProductionServeWiringUnavailable)
			}
			if factory.OpenCRP != nil && isNilProductionDependency(wiring.CRPActivation) {
				return fmt.Errorf("%w: main serve received no CRP activation executor", ErrProductionServeWiringUnavailable)
			}
			return nil
		}
	}
	return OpenProductionDependencies(ctx, opts, factory)
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
			if isNilProductionDependency(d.CRP) {
				return nil
			}
			return d.CRP.Close()
		})
		close(func() error {
			managed, ok := d.CWEDPDownload.(ProductionCWEDPDownloadCloser)
			if !ok || isNilProductionDependency(managed) {
				return nil
			}
			return managed.Close()
		})
		close(func() error {
			if d.TemporaryNetwork == nil {
				return nil
			}
			return d.TemporaryNetwork.Close()
		})
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
	validator := d.ApprovalHTTP.SessionValidator()
	if validator == nil || !sameProductionDependency(validator, d.Management) {
		return ProductionServeWiring{}, fmt.Errorf("%w: approval session validator is not bound to management store", ErrProductionServeWiringUnavailable)
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
	if d.TemporaryNetwork == nil || isNilProductionDependency(d.TemporaryNetwork.Provider) {
		return ProductionServeWiring{}, fmt.Errorf("%w: %w", ErrProductionServeWiringUnavailable, ErrProductionTemporaryNetworkUnavailable)
	}
	binder, ok := d.TemporaryNetwork.Provider.(productionTemporaryNetworkBinder)
	if !ok || !binder.productionTemporaryNetworkBinding(d.Management, controlEpoch) {
		return ProductionServeWiring{}, fmt.Errorf("%w: temporary-network provider is not bound to management store and policy epoch", ErrProductionServeWiringUnavailable)
	}
	var crpActivation handler.CRPActivationExecutor
	if !isNilProductionDependency(d.CRP) {
		crpActivation = d.CRP.ActivationExecutor()
		if isNilProductionDependency(crpActivation) {
			return ProductionServeWiring{}, fmt.Errorf("%w: CRP activation executor is unavailable", ErrProductionServeWiringUnavailable)
		}
	}
	return ProductionServeWiring{
		ManagementStore:       d.Management,
		Startup:               d.Startup,
		ApprovalHTTP:          d.ApprovalHTTP,
		SessionValidator:      validator,
		PolicyEpoch:           controlEpoch,
		TemporaryHTTPExecutor: d.TemporaryNetwork.Provider,
		TemporaryNetwork:      d.TemporaryNetwork.Provider,
		CWEDPDownload:         d.CWEDPDownload,
		CRPActivation:         crpActivation,
		CWEDP:                 d.CWEDP,
	}, nil
}

// sameProductionDependency compares the concrete lifetime owner behind two
// interface values. Production session validation must use the exact same
// management-store instance as approval and the request-serving layer; a
// second store connected to the same database is not an equivalent lifetime.
func sameProductionDependency(left, right any) bool {
	if isNilProductionDependency(left) || isNilProductionDependency(right) {
		return false
	}
	leftValue := reflect.ValueOf(left)
	rightValue := reflect.ValueOf(right)
	if leftValue.Type() != rightValue.Type() {
		return false
	}
	if leftValue.Type().Comparable() {
		return leftValue.Interface() == rightValue.Interface()
	}
	if leftValue.Kind() == reflect.Pointer {
		return leftValue.Pointer() == rightValue.Pointer()
	}
	return false
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
		case errors.Is(err, ErrProductionTemporaryNetworkUnavailable),
			errors.Is(err, ErrProductionTemporaryNetworkSession),
			errors.Is(err, ErrProductionTemporaryNetworkAudit),
			errors.Is(err, ErrProductionTemporaryNetworkAdapter):
			return nil, fmt.Errorf("%w: %s: %w", config.ErrProductionStorageUnavailable, stage, err)
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			return nil, fmt.Errorf("%w: %s: %w", config.ErrProductionStorageUnavailable, stage, err)
		default:
			if err != nil {
				return nil, fmt.Errorf("%w: %s: %w", config.ErrProductionStorageUnavailable, stage, err)
			}
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

	// A restarted native-raft leader may have a newer term/epoch than the
	// PostgreSQL snapshot while retaining the exact same desired payload.
	// Bootstrap only accepts that mismatch through this constrained capability;
	// unsupported adapters and changed payloads still fail closed.
	checkpoint, _ := consensus.(controlplane.LeadershipCheckpointStore)
	startup, err := controlplane.Bootstrap(ctx, controlplane.StartupOptions{
		Profile:              config.StorageProfileProduction,
		ClusterID:            opts.ClusterID,
		Machine:              consensus.Machine(),
		Durable:              control,
		Consensus:            consensus,
		Fencer:               consensus,
		LeadershipCheckpoint: checkpoint,
	})
	if err != nil || startup.Stage != controlplane.StartupStageReady || !startup.Ready {
		if err == nil {
			err = fmt.Errorf("control-plane Bootstrap returned stage=%q ready=%t", startup.Stage, startup.Ready)
		}
		return fail("control-plane Bootstrap did not reach ready", err)
	}
	deps.Startup = startup
	deps.CWEDP = productionCWEDPOptions(opts)

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
	if err := validateProductionApprovalHTTPBinding(provider, deps.ApprovalHTTP, uint64(startup.State.Epoch)); err != nil {
		return fail("approval HTTP binding is incomplete", err)
	}
	if err := validateProductionTemporaryNetworkOptions(opts, management, uint64(startup.State.Epoch), factory.OpenTemporaryNetwork); err != nil {
		return fail("production temporary network contract is incomplete", err)
	}
	temporaryNetwork, err := factory.OpenTemporaryNetwork(ctx, ProductionTemporaryNetworkOptions{
		ManagementStore: management,
		PolicyEpoch:     uint64(startup.State.Epoch),
		DataDir:         opts.DataDir,
	})
	if temporaryNetwork != nil {
		deps.TemporaryNetwork = temporaryNetwork
	}
	if err != nil || temporaryNetwork == nil {
		if err == nil {
			err = ErrProductionTemporaryNetworkUnavailable
		}
		return fail("production temporary network provider could not be opened", err)
	}
	wiring, err := deps.ServeWiring()
	if err != nil {
		return fail("production serve wiring contract is incomplete", err)
	}
	if factory.OpenCWEDPDownload != nil {
		download, openErr := factory.OpenCWEDPDownload(ctx, wiring)
		if openErr != nil || download == nil {
			if openErr == nil {
				openErr = ErrProductionServeWiringUnavailable
			}
			return fail("production CWEDP download consumer could not be opened", openErr)
		}
		deps.CWEDPDownload = download
		wiring.CWEDPDownload = download

		owner, ok := download.(productionCWEDPCRPRuntimeOwner)
		if !ok || isNilProductionDependency(owner) || owner.CRPRuntime() == nil || owner.CRPActivationPolicy().VerifyRecord == nil {
			return fail("production CWEDP consumer does not expose its CRP runtime and verification policy", ErrProductionCRPUnavailable)
		}
		resolver := approvalDep.ApprovalClaimResolver()
		if resolver == nil {
			return fail("production approval dependency does not expose a CRP claim resolver", ErrProductionApprovalUnavailable)
		}
		crpOptions := opts.CRP
		if crpOptions.ClusterID != "" && crpOptions.ClusterID != opts.ClusterID {
			return fail("production CRP cluster identity differs from startup", ErrProductionCRPConfig)
		}
		crpOptions.ClusterID = opts.ClusterID
		nodeID := consensusNodeID(consensus)
		if crpOptions.NodeID != "" && crpOptions.NodeID != nodeID {
			return fail("production CRP node identity differs from consensus", ErrProductionCRPConfig)
		}
		crpOptions.NodeID = nodeID
		crpDependency, openErr := factory.OpenCRP(ctx, ProductionCRPCompositionOptions{
			CRP:                   crpOptions,
			AuthorizationDSN:      opts.ControlPostgreSQL.DSN,
			Consensus:             consensus,
			Runtime:               owner.CRPRuntime(),
			ApprovalClaimResolver: resolver,
			ActivationPolicy:      owner.CRPActivationPolicy(),
		})
		if !isNilProductionDependency(crpDependency) {
			deps.CRP = crpDependency
		}
		if openErr != nil || isNilProductionDependency(crpDependency) {
			if openErr == nil {
				openErr = ErrProductionCRPUnavailable
			}
			return fail("production CRP composition could not be opened", openErr)
		}
		if crpDependency.Runtime() != owner.CRPRuntime() || isNilProductionDependency(crpDependency.ActivationExecutor()) {
			return fail("production CRP composition did not retain the exact CWEDP runtime and executor", ErrProductionCRPUnavailable)
		}
		wiring.CRPActivation = crpDependency.ActivationExecutor()
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
	if provider.ApprovalClaimResolver() == nil {
		return nil, fmt.Errorf("%w: CRP approval claim resolver is unavailable", ErrProductionApprovalUnavailable)
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

func validateProductionApprovalHTTPBinding(provider ProductionApprovalDependency, approvalHTTP *handler.ApprovalHTTPHandler, expectedEpoch uint64) error {
	if provider == nil || approvalHTTP == nil || expectedEpoch == 0 {
		return ErrProductionServeWiringUnavailable
	}
	providerEpoch := provider.PolicyEpoch()
	handlerEpoch := approvalHTTP.PolicyEpoch()
	if providerEpoch == 0 || handlerEpoch == 0 || providerEpoch != expectedEpoch || handlerEpoch != providerEpoch {
		return fmt.Errorf("%w: provider=%d handler=%d control-plane=%d", ErrProductionServeWiringUnavailable, providerEpoch, handlerEpoch, expectedEpoch)
	}
	return nil
}

func validateProductionTemporaryNetworkOptions(opts ProductionStartupOptions, management storage.Store, epoch uint64, opener func(context.Context, ProductionTemporaryNetworkOptions) (*ProductionTemporaryNetworkWiring, error)) error {
	if opener == nil {
		return ErrProductionTemporaryNetworkUnavailable
	}
	if opts.DataDir == "" || !filepath.IsAbs(opts.DataDir) {
		return fmt.Errorf("%w: runtime data directory is not absolute", ErrProductionTemporaryNetworkUnavailable)
	}
	if isNilProductionDependency(management) || (opts.ManagementStore != nil && opts.ManagementStore != management) {
		return fmt.Errorf("%w: management store is not bound", ErrProductionTemporaryNetworkUnavailable)
	}
	if epoch == 0 || (opts.ApprovalEpoch != 0 && opts.ApprovalEpoch != epoch) {
		return fmt.Errorf("%w: control-plane policy epoch is not bound", ErrProductionTemporaryNetworkUnavailable)
	}
	return nil
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
	if (factory.OpenCWEDPDownload == nil) != (factory.OpenCRP == nil) {
		return fmt.Errorf("%w: CWEDP download and CRP lifecycle openers must be configured together", config.ErrProductionStorageUnavailable)
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
	factory := ProductionDependencyFactory{
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
		OpenTemporaryNetwork: func(ctx context.Context, opts ProductionTemporaryNetworkOptions) (*ProductionTemporaryNetworkWiring, error) {
			provider, err := newProductionTemporaryNetworkProvider(ctx, opts)
			if err != nil {
				return nil, err
			}
			return NewProductionTemporaryNetworkWiring(provider, provider.Close)
		},
	}
	factory.OpenCWEDPAdmission = openProductionCWEDPAdmission
	factory.OpenCWEDPResumeStore = openProductionCWEDPResumeStore
	factory.OpenCWEDPRuntime = openProductionCWEDPRuntime
	factory.OpenCWEDPDownload = func(ctx context.Context, wiring ProductionServeWiring) (consumer.Executor, error) {
		return openProductionCWEDPDownload(ctx, wiring, factory.OpenCWEDPAdmission, factory.OpenCWEDPResumeStore, factory.OpenCWEDPRuntime)
	}
	factory.OpenCRP = openProductionCRPComposition
	return factory
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
		NativeRaft: nativeraft.Options{
			Profile: config.StorageProfileProduction, ClusterID: clusterID, NodeID: nodeID,
			DataDir: raftDir, BindAddress: raft.Listen, Mode: nativeraft.StartMode(raft.Mode),
			TLS: &nativeraft.TLSOptions{
				CAFile: cfg.Cluster.Interconnect.CAFile, CertFile: cfg.Cluster.Interconnect.CertFile,
				KeyFile: cfg.Cluster.Interconnect.KeyFile,
			},
		},
		Redis:        redis.Config{Addr: cfg.Storage.Redis.Address, InstanceID: instanceID, DialTimeout: cfg.Storage.ManagementPostgreSQL.Timeout},
		RedisEnabled: cfg.Storage.Redis.Enabled,
		DataDir:      cfg.Setup.DataDir,
		CRP:          ProductionCRPOptions{ClusterID: clusterID, NodeID: nodeID},
	}, nil
}
