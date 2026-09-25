package cli

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/cwedp/transport"
	"github.com/LaokeQwQ/CheeseWAF/internal/netlease"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

// productionTemporaryNetworkProvider owns only shared production plumbing.
// Administrator session and password confirmation are supplied afresh by each
// request, and each CWEDP adapter receives a separate one-shot lease.
type productionTemporaryNetworkProvider struct {
	broker      *netlease.Broker
	sessions    *netlease.TemporarySessionManager
	management  storage.SessionLookupStore
	policyEpoch uint64

	ctx    context.Context
	cancel context.CancelFunc

	mu     sync.Mutex
	active map[string]*temporaryNetworkCapability
	issues sync.WaitGroup

	closeOnce sync.Once
	closed    atomic.Bool
	closeErr  error
}

type temporaryNetworkCapability struct {
	leaseID   string
	sessionID string
	cancel    context.CancelFunc

	once sync.Once
}

func newProductionTemporaryNetworkProvider(ctx context.Context, opts ProductionTemporaryNetworkOptions) (*productionTemporaryNetworkProvider, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if isNilProductionDependency(opts.ManagementStore) || opts.PolicyEpoch == 0 || opts.DataDir == "" || !filepath.IsAbs(opts.DataDir) {
		return nil, ErrProductionTemporaryNetworkUnavailable
	}
	audit, err := netlease.NewFileAuditSink(filepath.Join(opts.DataDir, "audit", temporaryOnlineAuditFile))
	if err != nil {
		return nil, fmt.Errorf("production temporary network audit: %w", err)
	}
	sessionStore, ok := opts.ManagementStore.(storage.SessionLookupStore)
	if !ok || sessionStore == nil {
		return nil, ErrProductionTemporaryNetworkUnavailable
	}
	sessions, err := netlease.NewTemporarySessionManager(netlease.TemporarySessionManagerOptions{
		Authenticator: netlease.StoreAdministratorAuthenticator{Store: opts.ManagementStore},
	})
	if err != nil {
		return nil, fmt.Errorf("production temporary network sessions: %w", err)
	}
	providerCtx, cancel := context.WithCancel(ctx)
	provider := &productionTemporaryNetworkProvider{
		sessions:    sessions,
		management:  sessionStore,
		policyEpoch: opts.PolicyEpoch,
		ctx:         providerCtx,
		cancel:      cancel,
		active:      make(map[string]*temporaryNetworkCapability),
	}
	broker, err := netlease.NewBroker(netlease.BrokerConfig{
		Enabled:     true,
		Production:  true,
		Policy:      netlease.NewOfflinePolicyWithEpoch(nil, opts.PolicyEpoch),
		Sessions:    sessions,
		Transport:   netlease.NewStandardTransport(),
		Addresses:   netlease.PublicAddressPolicy{},
		Audit:       audit,
		PreDialGate: provider.preDialGate,
	})
	if err != nil {
		cancel()
		return nil, fmt.Errorf("production temporary network broker: %w", err)
	}
	provider.broker = broker
	return provider, nil
}

func (p *productionTemporaryNetworkProvider) ExecuteTemporaryHTTP(ctx context.Context, req netlease.TemporaryHTTPExecution) (netlease.HTTPResponse, error) {
	if p == nil || p.broker == nil {
		return netlease.HTTPResponse{}, ErrProductionTemporaryNetworkUnavailable
	}
	if !p.beginIssue() {
		return netlease.HTTPResponse{}, ErrProductionTemporaryNetworkUnavailable
	}
	defer p.issues.Done()

	opCtx, cancel := p.operationContext(ctx)
	defer cancel()
	ttl, managementExpiry, err := p.boundTTL(opCtx, req.Identity, req.TTL)
	if err != nil {
		return netlease.HTTPResponse{}, err
	}
	req.TTL = ttl
	req.ManagementSessionExpiresAt = managementExpiry
	return p.broker.ExecuteTemporaryHTTP(opCtx, req)
}

func (p *productionTemporaryNetworkProvider) CWEDPAdapter(ctx context.Context, req ProductionCWEDPLeaseRequest) (transport.LeaseBoundAdapter, error) {
	if p == nil || p.broker == nil || p.sessions == nil || p.management == nil || p.isClosed() {
		return nil, ErrProductionTemporaryNetworkUnavailable
	}
	if !p.beginIssue() {
		return nil, ErrProductionTemporaryNetworkUnavailable
	}
	defer p.issues.Done()

	opCtx, cancel := p.operationContext(ctx)
	issued := false
	defer func() {
		if !issued {
			cancel()
		}
	}()
	ttl, managementExpiry, err := p.boundTTL(opCtx, req.Identity, req.TTL)
	if err != nil {
		return nil, err
	}
	session, err := p.broker.BeginTemporarySession(opCtx, netlease.BeginTemporarySessionRequest{
		Identity:  req.Identity,
		TTL:       ttl,
		ExpiresAt: managementExpiry,
	})
	if err != nil {
		return nil, fmt.Errorf("CWEDP temporary network session: %w", err)
	}
	lease, err := p.broker.IssueTemporary(opCtx, netlease.ConfirmationInput{
		SessionID:      session.ID,
		Password:       req.Password,
		PluginID:       req.PluginID,
		PluginVersion:  req.PluginVersion,
		Target:         req.Target,
		TLSFingerprint: req.TLSFingerprint,
		PolicyEpoch:    req.PolicyEpoch,
		TTL:            ttl,
		MaxBytes:       req.MaxBytes,
	})
	if err != nil {
		return nil, errors.Join(
			fmt.Errorf("CWEDP temporary network lease: %w", err),
			p.sessions.Revoke(session.ID),
		)
	}
	scope := netlease.RequestScope{
		PluginID:        req.PluginID,
		PluginVersion:   req.PluginVersion,
		Target:          req.Target,
		TLSFingerprint:  req.TLSFingerprint,
		PolicyEpoch:     req.PolicyEpoch,
		OperatorID:      req.Identity.ID,
		TemporaryEgress: true,
	}
	capability := &temporaryNetworkCapability{leaseID: lease.ID, sessionID: session.ID, cancel: cancel}
	if !p.registerCapability(capability) {
		return nil, errors.Join(
			ErrProductionTemporaryNetworkUnavailable,
			p.releaseCapability(capability),
		)
	}
	issued = true
	return transport.NewHTTPAdapterWithRelease(p.broker, lease.ID, scope, func() error {
		return p.releaseCapability(capability)
	}), nil
}

func (p *productionTemporaryNetworkProvider) Close() error {
	if p == nil {
		return nil
	}
	p.closeOnce.Do(func() {
		p.closed.Store(true)
		if p.cancel != nil {
			p.cancel()
		}
		p.mu.Lock()
		capabilities := make([]*temporaryNetworkCapability, 0, len(p.active))
		for _, capability := range p.active {
			capabilities = append(capabilities, capability)
			if capability.cancel != nil {
				capability.cancel()
			}
		}
		p.mu.Unlock()
		p.issues.Wait()
		for _, capability := range capabilities {
			p.closeErr = errors.Join(p.closeErr, p.releaseCapability(capability))
		}
	})
	return p.closeErr
}

func (p *productionTemporaryNetworkProvider) isClosed() bool {
	return p.closed.Load()
}

// productionTemporaryNetworkBinding is intentionally unexported: production
// composition accepts only a provider that can prove its concrete store and
// policy fence, not a caller-supplied getter or reported ID.
func (p *productionTemporaryNetworkProvider) productionTemporaryNetworkBinding(store storage.Store, epoch uint64) bool {
	return p != nil && p.policyEpoch == epoch && sameProductionDependency(p.management, store)
}

func (p *productionTemporaryNetworkProvider) beginIssue() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed.Load() {
		return false
	}
	p.issues.Add(1)
	return true
}

func (p *productionTemporaryNetworkProvider) operationContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	child, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(p.ctx, cancel)
	return child, func() {
		stop()
		cancel()
	}
}

func (p *productionTemporaryNetworkProvider) boundTTL(ctx context.Context, identity netlease.AdministratorIdentity, requestedTTL time.Duration) (time.Duration, time.Time, error) {
	if requestedTTL <= 0 {
		return 0, time.Time{}, netlease.ErrTemporarySessionUnavailable
	}
	session, err := p.management.GetSession(ctx, identity.ManagementSessionID, identity.ID)
	if err != nil {
		return 0, time.Time{}, fmt.Errorf("load management session: %w", err)
	}
	if session == nil {
		return 0, time.Time{}, netlease.ErrAdministratorSessionDenied
	}
	remaining := time.Until(session.ExpiresAt)
	if remaining <= 0 {
		return 0, time.Time{}, netlease.ErrAdministratorSessionDenied
	}
	if remaining < requestedTTL {
		return remaining, session.ExpiresAt, nil
	}
	return requestedTTL, session.ExpiresAt, nil
}

func (p *productionTemporaryNetworkProvider) registerCapability(capability *temporaryNetworkCapability) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed.Load() {
		return false
	}
	p.active[capability.leaseID] = capability
	return true
}

func (p *productionTemporaryNetworkProvider) releaseCapability(capability *temporaryNetworkCapability) error {
	if capability == nil {
		return nil
	}
	var releaseErr error
	capability.once.Do(func() {
		if capability.cancel != nil {
			capability.cancel()
		}
		p.mu.Lock()
		delete(p.active, capability.leaseID)
		p.mu.Unlock()
		releaseErr = errors.Join(p.broker.Revoke(capability.leaseID), p.sessions.Revoke(capability.sessionID))
	})
	return releaseErr
}

func (p *productionTemporaryNetworkProvider) preDialGate(ctx context.Context, lease netlease.Lease) error {
	p.mu.Lock()
	capability, active := p.active[lease.ID]
	closed := p.closed.Load()
	p.mu.Unlock()
	if closed || ctx.Err() != nil {
		return ErrProductionTemporaryNetworkUnavailable
	}
	sessionID := ""
	if active && capability != nil {
		sessionID = capability.sessionID
	} else if confirmation, ok := p.sessions.Confirmation(lease.ConfirmationID); ok {
		// ExecuteTemporaryHTTP owns its session and lease inside Broker, so it
		// has no externally retained capability to register. The consumed
		// confirmation remains the exact, immutable bridge back to that
		// request's temporary session for this use-time check.
		sessionID = confirmation.SessionID
	}
	if sessionID == "" {
		return ErrProductionTemporaryNetworkUnavailable
	}
	if _, err := p.sessions.ValidateActive(ctx, sessionID); err != nil {
		return err
	}
	p.mu.Lock()
	_, stillActive := p.active[lease.ID]
	closed = p.closed.Load()
	p.mu.Unlock()
	if closed || ctx.Err() != nil || active && !stillActive {
		return ErrProductionTemporaryNetworkUnavailable
	}
	return nil
}
