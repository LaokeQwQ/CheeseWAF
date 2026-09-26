package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/LaokeQwQ/CheeseWAF/internal/api/handler"
	"github.com/LaokeQwQ/CheeseWAF/internal/crp"
	"github.com/LaokeQwQ/CheeseWAF/internal/crp/activation"
	activationpostgres "github.com/LaokeQwQ/CheeseWAF/internal/crp/activation/postgres"
)

// ProductionCRPCompositionOptions joins the already-bootstrapped consensus,
// durable approval runtime and exact CWEDP RuntimeStore with runtime-only mTLS
// transport configuration. None of these values are serialized into the
// tracked YAML template.
type ProductionCRPCompositionOptions struct {
	CRP                   ProductionCRPOptions
	AuthorizationDSN      string
	Consensus             ProductionConsensusDependency
	Runtime               *crp.RuntimeStore
	ApprovalClaimResolver activation.ApprovalClaimResolver
	ActivationPolicy      activation.Policy
}

// ProductionCRPDependency is the process-owned CRP lifecycle exposed to the
// main serve loop. The management API receives only ActivationExecutor; it
// cannot reach the authorization store, fence source or mTLS transports.
type ProductionCRPDependency interface {
	Start() error
	Wait(context.Context) error
	Shutdown(context.Context) error
	Close() error
	Runtime() *crp.RuntimeStore
	ActivationExecutor() handler.CRPActivationExecutor
}

// productionCRPComposition owns the CRP listener/service before the durable
// authorization store. Close preserves that dependency order so workers and
// transports cannot touch a closed PostgreSQL handle.
type productionCRPComposition struct {
	bundle         *ProductionCRP
	authorization  *activationpostgres.Store
	sidecarBackend productionSidecarBackendCloser
	executor       handler.CRPActivationExecutor

	closeOnce sync.Once
	closeErr  error
}

type productionSidecarBackendCloser interface {
	Close(context.Context) error
}

func openProductionCRPComposition(ctx context.Context, opts ProductionCRPCompositionOptions) (ProductionCRPDependency, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if strings.TrimSpace(opts.AuthorizationDSN) == "" || isNilProductionDependency(opts.Consensus) || opts.Runtime == nil || opts.ApprovalClaimResolver == nil || opts.ActivationPolicy.VerifyRecord == nil {
		return nil, fmt.Errorf("%w: authorization DSN, consensus, runtime, approval resolver and verification policy are required", ErrProductionCRPUnavailable)
	}
	crpOptions := ProductionCRPOptionsFromEnvironment(opts.CRP)
	var sidecarBackendCloser productionSidecarBackendCloser
	if isNilProductionCRPDependency(crpOptions.SidecarBackend) {
		backend, err := openProductionProcessSidecarBackend(crpOptions.SidecarRegistryFile)
		if err != nil {
			return nil, err
		}
		crpOptions.SidecarBackend = backend
		sidecarBackendCloser = backend
	} else if closer, ok := crpOptions.SidecarBackend.(productionSidecarBackendCloser); ok && !isNilProductionCRPDependency(closer) {
		sidecarBackendCloser = closer
	}
	closeSidecarBackend := func() {
		if sidecarBackendCloser != nil {
			_ = sidecarBackendCloser.Close(context.Background())
		}
	}
	fenceSource, err := NewProductionCRPFenceSource(opts.Consensus)
	if err != nil {
		closeSidecarBackend()
		return nil, err
	}
	authorization, err := activationpostgres.OpenWithFenceSource(ctx, opts.AuthorizationDSN, fenceSource)
	if err != nil {
		closeSidecarBackend()
		return nil, fmt.Errorf("%w: open durable authorization store: %v", ErrProductionCRPUnavailable, err)
	}
	fail := func(err error) (ProductionCRPDependency, error) {
		_ = authorization.Close()
		closeSidecarBackend()
		return nil, err
	}
	if err := authorization.Migrate(ctx); err != nil {
		return fail(fmt.Errorf("%w: migrate durable authorization store: %v", ErrProductionCRPUnavailable, err))
	}
	provider, err := authorization.Provider()
	if err != nil {
		return fail(fmt.Errorf("%w: open durable authorization provider: %v", ErrProductionCRPUnavailable, err))
	}

	crpOptions.Runtime = opts.Runtime
	crpOptions.State = authorization
	crpOptions.Provider = provider
	crpOptions.Audit = authorization
	crpOptions.FenceSource = fenceSource
	crpOptions.ApprovalClaimResolver = opts.ApprovalClaimResolver
	crpOptions.Policy = opts.ActivationPolicy
	if crpOptions.NodeID == "" {
		crpOptions.NodeID = consensusNodeID(opts.Consensus)
	}
	bundle, err := OpenProductionCRP(ctx, crpOptions)
	if err != nil {
		return fail(err)
	}
	if bundle.Runtime() != opts.Runtime {
		_ = bundle.Close()
		return fail(fmt.Errorf("%w: CRP and CWEDP runtime instances differ", ErrProductionCRPUnavailable))
	}
	executor, err := NewProductionCRPActivationExecutor(bundle.Service())
	if err != nil {
		_ = bundle.Close()
		return fail(err)
	}
	return &productionCRPComposition{bundle: bundle, authorization: authorization, sidecarBackend: sidecarBackendCloser, executor: executor}, nil
}

func (c *productionCRPComposition) Start() error {
	if c == nil || c.bundle == nil {
		return ErrProductionCRPLifecycle
	}
	return c.bundle.Start()
}

func (c *productionCRPComposition) Wait(ctx context.Context) error {
	if c == nil || c.bundle == nil {
		return ErrProductionCRPLifecycle
	}
	return c.bundle.Wait(ctx)
}

func (c *productionCRPComposition) Shutdown(ctx context.Context) error {
	if c == nil {
		return nil
	}
	var shutdownErr error
	if c.bundle != nil {
		shutdownErr = errors.Join(shutdownErr, c.bundle.Shutdown(ctx))
	}
	if c.sidecarBackend != nil {
		shutdownErr = errors.Join(shutdownErr, c.sidecarBackend.Close(ctx))
	}
	return shutdownErr
}

func (c *productionCRPComposition) Close() error {
	if c == nil {
		return nil
	}
	c.closeOnce.Do(func() {
		if c.bundle != nil {
			c.closeErr = errors.Join(c.closeErr, c.bundle.Close())
		}
		if c.sidecarBackend != nil {
			c.closeErr = errors.Join(c.closeErr, c.sidecarBackend.Close(context.Background()))
		}
		if c.authorization != nil {
			c.closeErr = errors.Join(c.closeErr, c.authorization.Close())
		}
	})
	return c.closeErr
}

func (c *productionCRPComposition) Runtime() *crp.RuntimeStore {
	if c == nil || c.bundle == nil {
		return nil
	}
	return c.bundle.Runtime()
}

func (c *productionCRPComposition) ActivationExecutor() handler.CRPActivationExecutor {
	if c == nil {
		return nil
	}
	return c.executor
}

var _ ProductionCRPDependency = (*productionCRPComposition)(nil)
