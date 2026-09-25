package cli

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/cluster/redis"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/controlplane/nativeraft"
	"github.com/LaokeQwQ/CheeseWAF/internal/crp"
	"github.com/LaokeQwQ/CheeseWAF/internal/crp/activation"
	"github.com/LaokeQwQ/CheeseWAF/internal/cwedp/consumer"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

func TestOpenProductionCRPCompositionRejectsMissingRuntimeResolverAndPolicyBeforePostgreSQL(t *testing.T) {
	_, consensus := newProductionControlPlaneFixture(t)
	base := ProductionCRPCompositionOptions{
		AuthorizationDSN: "postgres://must-not-be-opened.invalid/control",
		Consensus:        consensus,
		Runtime:          testProductionCRPRuntime(t),
		ApprovalClaimResolver: func(context.Context, activation.AuthorizationRequest) (activation.ApprovalClaim, error) {
			return activation.ApprovalClaim{}, nil
		},
		ActivationPolicy: activation.Policy{VerifyRecord: func(context.Context, crp.RuntimeRecord) error { return nil }},
	}
	tests := []struct {
		name   string
		mutate func(*ProductionCRPCompositionOptions)
	}{
		{name: "runtime", mutate: func(opts *ProductionCRPCompositionOptions) { opts.Runtime = nil }},
		{name: "approval resolver", mutate: func(opts *ProductionCRPCompositionOptions) { opts.ApprovalClaimResolver = nil }},
		{name: "activation policy", mutate: func(opts *ProductionCRPCompositionOptions) { opts.ActivationPolicy = activation.Policy{} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			opts := base
			test.mutate(&opts)
			dependency, err := openProductionCRPComposition(context.Background(), opts)
			if dependency != nil || !errors.Is(err, ErrProductionCRPUnavailable) {
				t.Fatalf("openProductionCRPComposition() = dependency:%v error:%v, want fail-closed CRP unavailable", dependency, err)
			}
			if strings.Contains(err.Error(), "must-not-be-opened") || strings.Contains(err.Error(), "ping") {
				t.Fatalf("invalid composition reached PostgreSQL before dependency validation: %v", err)
			}
		})
	}
}

func TestOpenProductionDependenciesRejectsIncompleteCWEDPCRuntimeOwner(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*productionCWEDPOwnerFixture)
	}{
		{name: "nil CRP runtime", mutate: func(owner *productionCWEDPOwnerFixture) { owner.runtime = nil }},
		{name: "missing CRP activation policy", mutate: func(owner *productionCWEDPOwnerFixture) { owner.policy = activation.Policy{} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			events := make([]string, 0, 8)
			owner := &productionCWEDPOwnerFixture{
				runtime: testProductionCRPRuntime(t),
				policy:  activation.Policy{VerifyRecord: func(context.Context, crp.RuntimeRecord) error { return nil }},
				events:  &events,
			}
			test.mutate(owner)
			var crpOpened, serveWired bool
			deps, err := openCRPCompositionDependencyFixture(t, &events, func(opts ProductionStartupOptions) ProductionApprovalDependency {
				return newProductionApprovalFake(opts.ApprovalEpoch, opts.ManagementStore)
			}, owner, func(context.Context, ProductionCRPCompositionOptions) (ProductionCRPDependency, error) {
				crpOpened = true
				return nil, errors.New("must not open CRP")
			}, func(context.Context, ProductionServeWiring) error {
				serveWired = true
				return nil
			})
			if deps != nil || !errors.Is(err, ErrProductionCRPUnavailable) {
				t.Fatalf("OpenProductionDependencies() = deps:%v error:%v, want ErrProductionCRPUnavailable", deps, err)
			}
			if crpOpened || serveWired {
				t.Fatalf("incomplete CWEDP owner escaped validation: crpOpened=%t serveWired=%t", crpOpened, serveWired)
			}
			want := []string{"cwedp", "temporary", "approval", "redis", "consensus", "control", "management"}
			assertCRPCloseEvents(t, events, want)
		})
	}
}

func TestOpenProductionDependenciesRejectsMissingApprovalClaimResolverBeforeCWEDP(t *testing.T) {
	events := make([]string, 0, 6)
	var crpOpened, serveWired bool
	deps, err := openCRPCompositionDependencyFixture(t, &events, func(opts ProductionStartupOptions) ProductionApprovalDependency {
		return &productionApprovalWithoutResolver{productionApprovalFake: newProductionApprovalFake(opts.ApprovalEpoch, opts.ManagementStore)}
	}, productionCWEDPExecutorFunc(func(context.Context, consumer.Request) (consumer.Result, error) {
		return consumer.Result{}, nil
	}), func(context.Context, ProductionCRPCompositionOptions) (ProductionCRPDependency, error) {
		crpOpened = true
		return nil, errors.New("must not open CRP")
	}, func(context.Context, ProductionServeWiring) error {
		serveWired = true
		return nil
	})
	if deps != nil || !errors.Is(err, ErrProductionApprovalUnavailable) {
		t.Fatalf("OpenProductionDependencies() = deps:%v error:%v, want ErrProductionApprovalUnavailable", deps, err)
	}
	if crpOpened || serveWired {
		t.Fatalf("missing approval resolver escaped validation: crpOpened=%t serveWired=%t", crpOpened, serveWired)
	}
	want := []string{"approval", "redis", "consensus", "control", "management"}
	assertCRPCloseEvents(t, events, want)
}

func TestOpenProductionDependenciesRejectsCRPRuntimePointerDrift(t *testing.T) {
	events := make([]string, 0, 8)
	owner := &productionCWEDPOwnerFixture{
		runtime: testProductionCRPRuntime(t),
		policy:  activation.Policy{VerifyRecord: func(context.Context, crp.RuntimeRecord) error { return nil }},
		events:  &events,
	}
	drifted := testProductionCRPRuntime(t)
	partial := &testProductionCRPDependency{runtime: drifted, executor: testCRPActivationExecutor{}, events: &events}
	var serveWired bool
	deps, err := openCRPCompositionDependencyFixture(t, &events, func(opts ProductionStartupOptions) ProductionApprovalDependency {
		return newProductionApprovalFake(opts.ApprovalEpoch, opts.ManagementStore)
	}, owner, func(context.Context, ProductionCRPCompositionOptions) (ProductionCRPDependency, error) {
		return partial, nil
	}, func(context.Context, ProductionServeWiring) error {
		serveWired = true
		return nil
	})
	if deps != nil || !errors.Is(err, ErrProductionCRPUnavailable) {
		t.Fatalf("OpenProductionDependencies() = deps:%v error:%v, want runtime identity rejection", deps, err)
	}
	if serveWired {
		t.Fatal("serve wiring ran after CRP runtime pointer drift")
	}
	want := []string{"crp", "cwedp", "temporary", "approval", "redis", "consensus", "control", "management"}
	assertCRPCloseEvents(t, events, want)
}

func TestOpenProductionDependenciesOpenCRPFailureClosesReturnedDependencyAndPrecedingResourcesInReverseOrder(t *testing.T) {
	events := make([]string, 0, 8)
	owner := &productionCWEDPOwnerFixture{
		runtime: testProductionCRPRuntime(t),
		policy:  activation.Policy{VerifyRecord: func(context.Context, crp.RuntimeRecord) error { return nil }},
		events:  &events,
	}
	wantErr := errors.New("CRP composition failed after allocation")
	partial := &testProductionCRPDependency{runtime: owner.runtime, executor: testCRPActivationExecutor{}, events: &events}
	deps, err := openCRPCompositionDependencyFixture(t, &events, func(opts ProductionStartupOptions) ProductionApprovalDependency {
		return newProductionApprovalFake(opts.ApprovalEpoch, opts.ManagementStore)
	}, owner, func(context.Context, ProductionCRPCompositionOptions) (ProductionCRPDependency, error) {
		return partial, wantErr
	}, func(context.Context, ProductionServeWiring) error {
		t.Fatal("serve wiring ran after OpenCRP failure")
		return nil
	})
	if deps != nil || !errors.Is(err, wantErr) {
		t.Fatalf("OpenProductionDependencies() = deps:%v error:%v, want wrapped OpenCRP failure", deps, err)
	}
	want := []string{"crp", "cwedp", "temporary", "approval", "redis", "consensus", "control", "management"}
	assertCRPCloseEvents(t, events, want)
}

func TestOpenProductionDependenciesServeWiringExecutesRealCRPAdapter(t *testing.T) {
	events := make([]string, 0, 8)
	fixture := newCRPActivationAdapterFixture(t, crpActivationAdapterFixtureOptions{})
	executor, err := NewProductionCRPActivationExecutor(fixture.service)
	if err != nil {
		t.Fatal(err)
	}
	owner := &productionCWEDPOwnerFixture{
		runtime: fixture.store,
		policy:  activation.Policy{VerifyRecord: func(context.Context, crp.RuntimeRecord) error { return nil }},
		events:  &events,
	}
	dependency := &testProductionCRPDependency{runtime: fixture.store, executor: executor, events: &events}
	var result activation.ActivationResult
	deps, err := openCRPCompositionDependencyFixture(t, &events, func(opts ProductionStartupOptions) ProductionApprovalDependency {
		return newProductionApprovalFake(opts.ApprovalEpoch, opts.ManagementStore)
	}, owner, func(_ context.Context, options ProductionCRPCompositionOptions) (ProductionCRPDependency, error) {
		if options.Runtime != fixture.store {
			t.Fatal("CRP opener did not receive the CWEDP-owned runtime")
		}
		return dependency, nil
	}, func(ctx context.Context, wiring ProductionServeWiring) error {
		var executeErr error
		result, executeErr = wiring.CRPActivation.ExecuteCRPActivation(ctx, fixture.request)
		return executeErr
	})
	if err != nil {
		t.Fatalf("OpenProductionDependencies() error=%v", err)
	}
	if deps == nil || !deps.Ready || result.Phase != activation.PhaseActive || result.Record.Key != fixture.record.Key {
		if deps != nil {
			_ = deps.Close()
		}
		t.Fatalf("real CRP adapter was not executed through serve wiring: deps=%+v result=%+v", deps, result)
	}
	if err := deps.Close(); err != nil {
		t.Fatal(err)
	}
}

type productionCWEDPOwnerFixture struct {
	runtime *crp.RuntimeStore
	policy  activation.Policy
	events  *[]string
}

func (*productionCWEDPOwnerFixture) DownloadCWEDP(context.Context, consumer.Request) (consumer.Result, error) {
	return consumer.Result{}, nil
}

func (f *productionCWEDPOwnerFixture) CRPRuntime() *crp.RuntimeStore { return f.runtime }

func (f *productionCWEDPOwnerFixture) CRPActivationPolicy() activation.Policy { return f.policy }

func (f *productionCWEDPOwnerFixture) Close() error {
	if f.events != nil {
		*f.events = append(*f.events, "cwedp")
	}
	return nil
}

type productionCWEDPExecutorFunc func(context.Context, consumer.Request) (consumer.Result, error)

func (f productionCWEDPExecutorFunc) DownloadCWEDP(ctx context.Context, request consumer.Request) (consumer.Result, error) {
	return f(ctx, request)
}

type productionApprovalWithoutResolver struct {
	*productionApprovalFake
}

func (*productionApprovalWithoutResolver) ApprovalClaimResolver() activation.ApprovalClaimResolver {
	return nil
}

func openCRPCompositionDependencyFixture(
	t *testing.T,
	events *[]string,
	openApproval func(ProductionStartupOptions) ProductionApprovalDependency,
	download consumer.Executor,
	openCRP func(context.Context, ProductionCRPCompositionOptions) (ProductionCRPDependency, error),
	wire func(context.Context, ProductionServeWiring) error,
) (*ProductionDependencies, error) {
	t.Helper()
	manager, err := storage.OpenSQLite(filepath.Join(t.TempDir(), "manager.db"))
	if err != nil {
		t.Fatal(err)
	}
	control, consensus := newProductionControlPlaneFixture(t)
	control.closeEvents = events
	consensus.closeEvents = events
	managed := &recordingStore{Store: manager, events: events}
	opts := testProductionStartupOptions(t)
	factory := ProductionDependencyFactory{
		OpenManagement: func(context.Context, config.ManagementPostgreSQLConfig) (storage.Store, error) {
			return managed, nil
		},
		OpenControl: func(context.Context, config.ManagementPostgreSQLConfig) (ProductionControlDependency, error) {
			return control, nil
		},
		OpenConsensus: func(context.Context, nativeraft.Options) (ProductionConsensusDependency, error) {
			return consensus, nil
		},
		OpenRedis: func(context.Context, redis.Config) (ProductionHealthDependency, error) {
			return &productionHealthFake{closeEvents: events}, nil
		},
		OpenApproval: func(_ context.Context, options ProductionStartupOptions) (ProductionApprovalDependency, error) {
			dependency := openApproval(options)
			if fake, ok := dependency.(*productionApprovalFake); ok {
				fake.closeEvents = events
			}
			if fake, ok := dependency.(*productionApprovalWithoutResolver); ok {
				fake.closeEvents = events
			}
			return dependency, nil
		},
		OpenTemporaryNetwork: func(context.Context, ProductionTemporaryNetworkOptions) (*ProductionTemporaryNetworkWiring, error) {
			return NewProductionTemporaryNetworkWiring(&testTemporaryNetworkProvider{}, func() error {
				*events = append(*events, "temporary")
				return nil
			})
		},
		OpenCWEDPDownload: func(context.Context, ProductionServeWiring) (consumer.Executor, error) {
			return download, nil
		},
		OpenCRP:             openCRP,
		WireServeWithWiring: wire,
	}
	return OpenProductionDependencies(context.Background(), opts, factory)
}

func assertCRPCloseEvents(t *testing.T, got, want []string) {
	t.Helper()
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("close events=%v, want %v", got, want)
	}
}
