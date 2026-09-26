package activation

import (
	"context"
	"crypto/x509"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/crp"
)

type productionContractState struct{ durable bool }

func (s productionContractState) Put(context.Context, Authorization) error { return nil }
func (s productionContractState) Get(context.Context, string) (Authorization, error) {
	return Authorization{}, ErrAuthorizationNotFound
}
func (s productionContractState) Consume(context.Context, Authorization) error { return nil }
func (s productionContractState) Durable() bool                                { return s.durable }

type productionContractProvider struct {
	durable   bool
	liveFence bool
}

func (p productionContractProvider) Authorize(context.Context, TransportIdentity, AuthorizationRequest) (Authorization, error) {
	return Authorization{}, errors.New("provider test failure")
}
func (p productionContractProvider) Validate(context.Context, TransportIdentity, Authorization) error {
	return nil
}
func (p productionContractProvider) Consume(context.Context, TransportIdentity, Authorization) error {
	return nil
}
func (p productionContractProvider) Durable() bool        { return p.durable }
func (p productionContractProvider) LiveFenceBound() bool { return p.liveFence }

type productionContractCoalescingProvider struct {
	state        AuthorizationState
	providerErr  error
	consumeCalls int
	afterCalls   int
}

func (*productionContractCoalescingProvider) Authorize(context.Context, TransportIdentity, AuthorizationRequest) (Authorization, error) {
	return Authorization{}, errors.New("provider test failure")
}
func (*productionContractCoalescingProvider) Validate(context.Context, TransportIdentity, Authorization) error {
	return nil
}
func (p *productionContractCoalescingProvider) Consume(context.Context, TransportIdentity, Authorization) error {
	p.consumeCalls++
	return p.providerErr
}
func (p *productionContractCoalescingProvider) UsesAuthorizationState(state AuthorizationState) bool {
	return state == p.state
}
func (p *productionContractCoalescingProvider) ConsumeAfterState(context.Context, TransportIdentity, Authorization) error {
	p.afterCalls++
	return p.providerErr
}
func (*productionContractCoalescingProvider) Durable() bool        { return true }
func (*productionContractCoalescingProvider) LiveFenceBound() bool { return true }

type productionContractAudit struct {
	durable    bool
	idempotent bool
	events     []AuthorizationAuditEvent
	err        error
}

func (a *productionContractAudit) Append(_ context.Context, event AuthorizationAuditEvent) error {
	if a.err != nil {
		return a.err
	}
	if a.idempotent {
		for _, prior := range a.events {
			if prior.EventID != event.EventID {
				continue
			}
			if reflect.DeepEqual(prior, event) {
				return nil
			}
			return errors.New("conflicting audit payload for EventID")
		}
	}
	a.events = append(a.events, event)
	return nil
}
func (a *productionContractAudit) Durable() bool { return a != nil && a.durable }
func (a *productionContractAudit) Idempotent() bool {
	return a != nil && a.idempotent
}

type productionContractDurableOnlyAudit struct{}

func (productionContractDurableOnlyAudit) Append(context.Context, AuthorizationAuditEvent) error {
	return nil
}
func (productionContractDurableOnlyAudit) Durable() bool { return true }

type productionContractTransport struct{ identity TransportIdentity }

func (t productionContractTransport) TransportIdentity() TransportIdentity { return t.identity }
func (productionContractTransport) Authorize(context.Context, AuthorizationRequest) (Authorization, error) {
	return Authorization{}, ErrControlPlaneUnavailable
}
func (productionContractTransport) Validate(context.Context, Authorization) error {
	return ErrControlPlaneUnavailable
}
func (productionContractTransport) Consume(context.Context, crp.Confirmation) error {
	return ErrControlPlaneUnavailable
}
func (productionContractTransport) Discard(Authorization) {}

type productionContractSidecars struct{ identity TransportIdentity }

func (s productionContractSidecars) TransportIdentity() TransportIdentity { return s.identity }
func (productionContractSidecars) Start(context.Context, SidecarDescriptor, crp.RuntimeRecord, StartOptions) (Sidecar, error) {
	return nil, ErrSidecarUnavailable
}

func TestNewProductionContractRejectsNonDurableDependencies(t *testing.T) {
	identity := testTransportIdentity
	base := ProductionContractOptions{
		ClusterID:    identity.ClusterID,
		ClientCA:     x509.NewCertPool(),
		State:        productionContractState{durable: true},
		Provider:     productionContractProvider{durable: true, liveFence: true},
		Audit:        &productionContractAudit{durable: true, idempotent: true},
		ControlPlane: productionContractTransport{identity: identity},
		Sidecars:     productionContractSidecars{identity: identity},
	}
	for name, mutate := range map[string]func(*ProductionContractOptions){
		"memory state":          func(opts *ProductionContractOptions) { opts.State = productionContractState{} },
		"memory provider":       func(opts *ProductionContractOptions) { opts.Provider = productionContractProvider{} },
		"missing live fence":    func(opts *ProductionContractOptions) { opts.Provider = productionContractProvider{durable: true} },
		"missing audit":         func(opts *ProductionContractOptions) { opts.Audit = &productionContractAudit{} },
		"non-idempotent audit":  func(opts *ProductionContractOptions) { opts.Audit = &productionContractAudit{durable: true} },
		"durable-only audit":    func(opts *ProductionContractOptions) { opts.Audit = productionContractDurableOnlyAudit{} },
		"missing control plane": func(opts *ProductionContractOptions) { opts.ControlPlane = nil },
		"missing sidecar":       func(opts *ProductionContractOptions) { opts.Sidecars = nil },
	} {
		t.Run(name, func(t *testing.T) {
			opts := base
			mutate(&opts)
			if _, err := NewProductionContract(opts); err == nil {
				t.Fatal("NewProductionContract unexpectedly accepted an unsafe dependency")
			}
		})
	}
}

func TestNewProductionContractRejectsTypedNilDependencies(t *testing.T) {
	identity := testTransportIdentity
	base := ProductionContractOptions{
		ClusterID:    identity.ClusterID,
		ClientCA:     x509.NewCertPool(),
		State:        productionContractState{durable: true},
		Provider:     productionContractProvider{durable: true, liveFence: true},
		Audit:        &productionContractAudit{durable: true, idempotent: true},
		ControlPlane: productionContractTransport{identity: identity},
		Sidecars:     productionContractSidecars{identity: identity},
	}

	var typedNilState *productionContractState
	var typedNilProvider *productionContractProvider
	var typedNilAudit *productionContractAudit
	var typedNilControl *productionContractTransport
	var typedNilSidecars *productionContractSidecars
	tests := []struct {
		name   string
		mutate func(*ProductionContractOptions)
	}{
		{name: "state", mutate: func(opts *ProductionContractOptions) { opts.State = typedNilState }},
		{name: "provider", mutate: func(opts *ProductionContractOptions) { opts.Provider = typedNilProvider }},
		{name: "audit", mutate: func(opts *ProductionContractOptions) { opts.Audit = typedNilAudit }},
		{name: "control plane", mutate: func(opts *ProductionContractOptions) { opts.ControlPlane = typedNilControl }},
		{name: "sidecar", mutate: func(opts *ProductionContractOptions) { opts.Sidecars = typedNilSidecars }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			opts := base
			test.mutate(&opts)
			if _, err := NewProductionContract(opts); !errors.Is(err, ErrProductionContract) && !errors.Is(err, ErrProductionDurability) && !errors.Is(err, ErrProductionAuditUnavailable) {
				t.Fatalf("typed-nil dependency error = %v, want a fail-closed production contract error", err)
			}
		})
	}
}

func TestNewProductionContractRejectsIdentityMismatch(t *testing.T) {
	identity := testTransportIdentity
	other := identity
	other.NodeID = "other-node"
	opts := ProductionContractOptions{
		ClusterID:    identity.ClusterID,
		ClientCA:     x509.NewCertPool(),
		State:        productionContractState{durable: true},
		Provider:     productionContractProvider{durable: true, liveFence: true},
		Audit:        &productionContractAudit{durable: true, idempotent: true},
		ControlPlane: productionContractTransport{identity: identity},
		Sidecars:     productionContractSidecars{identity: other},
	}
	if _, err := NewProductionContract(opts); err == nil {
		t.Fatal("identity mismatch was accepted")
	}
}

func TestAuditedAuthorizationProviderFailsClosedOnAuditFailure(t *testing.T) {
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	identity := testTransportIdentity
	audit := &productionContractAudit{durable: true, idempotent: true, err: errors.New("disk full")}
	provider := auditedAuthorizationProvider{
		delegate: productionContractProvider{durable: true}, audit: audit, clock: func() time.Time { return now },
	}
	request := AuthorizationRequest{
		RequestID: "request-1", Identity: identity, Action: crp.RuntimeActionPromote,
		Permission: PermissionActivate, Target: RuntimeTarget{Key: "demo"}, RequestedAt: now,
	}
	_, err := provider.Authorize(context.Background(), identity, request)
	if !errors.Is(err, ErrProductionAuditUnavailable) {
		t.Fatalf("Authorize error=%v, want audit failure", err)
	}
	if len(audit.events) != 0 {
		t.Fatalf("audit sink unexpectedly retained an event after failure: %+v", audit.events)
	}
}

func TestAuditedAuthorizationProviderDeduplicatesRepeatedEventID(t *testing.T) {
	audit := &productionContractAudit{durable: true, idempotent: true}
	provider := auditedAuthorizationProvider{
		delegate: productionContractProvider{durable: true},
		audit:    audit,
		clock:    time.Now,
	}
	event := AuthorizationAuditEvent{
		EventID:   "authorize:request-retry",
		Operation: "authorize",
		Outcome:   "denied",
	}

	if err := provider.record(context.Background(), event); err != nil {
		t.Fatalf("first audit append error=%v", err)
	}
	if err := provider.record(context.Background(), event); err != nil {
		t.Fatalf("same EventID retry error=%v", err)
	}
	if len(audit.events) != 1 {
		t.Fatalf("same EventID retry appended %d records, want exactly one", len(audit.events))
	}

	conflict := event
	conflict.Outcome = "allowed"
	if err := provider.record(context.Background(), conflict); !errors.Is(err, ErrProductionAuditUnavailable) {
		t.Fatalf("conflicting EventID append error=%v, want ErrProductionAuditUnavailable", err)
	}
	if len(audit.events) != 1 {
		t.Fatalf("conflicting EventID retry changed retained records: %+v", audit.events)
	}
}

func TestAuditedAuthorizationProviderRecordsRepeatedValidateAttempts(t *testing.T) {
	now := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	audit := &productionContractAudit{durable: true, idempotent: true}
	provider := auditedAuthorizationProvider{
		delegate: productionContractProvider{durable: true},
		audit:    audit,
		clock: func() time.Time {
			at := now
			now = now.Add(time.Nanosecond)
			return at
		},
	}
	authorization := Authorization{
		ID: "authorization-repeated-validate",
		Request: AuthorizationRequest{
			RequestID: "request-repeated-validate", Identity: testTransportIdentity,
			Action: crp.RuntimeActionPromote, Permission: PermissionActivate,
			Target: RuntimeTarget{Key: "demo"},
		},
	}

	if err := provider.Validate(context.Background(), testTransportIdentity, authorization); err != nil {
		t.Fatalf("first Validate() error=%v", err)
	}
	if err := provider.Validate(context.Background(), testTransportIdentity, authorization); err != nil {
		t.Fatalf("second Validate() error=%v", err)
	}
	if len(audit.events) != 2 {
		t.Fatalf("repeated Validate() audit events=%d, want 2", len(audit.events))
	}
	if audit.events[0].EventID == audit.events[1].EventID {
		t.Fatalf("repeated Validate() reused EventID %q", audit.events[0].EventID)
	}
	for _, event := range audit.events {
		if event.Operation != "validate" || event.Outcome != "allowed" || event.AuthorizationID != authorization.ID {
			t.Fatalf("unexpected repeated Validate() audit event: %+v", event)
		}
	}
}

func TestAuditedAuthorizationProviderPreservesCoalescedConsumeAuditSemantics(t *testing.T) {
	now := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	identity := testTransportIdentity
	authorization := Authorization{
		ID: "authorization-coalesced-audit",
		Request: AuthorizationRequest{
			RequestID: "request-coalesced-audit", Identity: identity, Action: crp.RuntimeActionPromote,
			Permission: PermissionActivate, Target: RuntimeTarget{Key: "demo"},
		},
	}

	t.Run("provider error is audited once and returned", func(t *testing.T) {
		state := &productionContractState{durable: true}
		providerErr := errors.New("post-consume provider failure")
		delegate := &productionContractCoalescingProvider{state: state, providerErr: providerErr}
		audit := &productionContractAudit{durable: true, idempotent: true}
		provider := auditedAuthorizationProvider{delegate: delegate, audit: audit, clock: func() time.Time { return now }}
		if !provider.UsesAuthorizationState(state) {
			t.Fatal("audit wrapper did not preserve shared authorization state capability")
		}

		err := provider.ConsumeAfterState(context.Background(), identity, authorization)
		if !errors.Is(err, providerErr) {
			t.Fatalf("ConsumeAfterState error=%v, want provider error", err)
		}
		if delegate.consumeCalls != 0 || delegate.afterCalls != 1 {
			t.Fatalf("delegate calls consume=%d after=%d, want 0/1", delegate.consumeCalls, delegate.afterCalls)
		}
		if len(audit.events) != 1 || audit.events[0].Operation != "consume" || audit.events[0].Outcome != "denied" {
			t.Fatalf("provider failure audit=%+v, want one denied consume event", audit.events)
		}
	})

	t.Run("audit failure is fail closed after provider success", func(t *testing.T) {
		state := &productionContractState{durable: true}
		delegate := &productionContractCoalescingProvider{state: state}
		audit := &productionContractAudit{durable: true, idempotent: true, err: errors.New("audit unavailable")}
		provider := auditedAuthorizationProvider{delegate: delegate, audit: audit, clock: func() time.Time { return now }}

		err := provider.ConsumeAfterState(context.Background(), identity, authorization)
		if !errors.Is(err, ErrProductionAuditUnavailable) {
			t.Fatalf("ConsumeAfterState error=%v, want ErrProductionAuditUnavailable", err)
		}
		if delegate.consumeCalls != 0 || delegate.afterCalls != 1 {
			t.Fatalf("delegate calls consume=%d after=%d, want 0/1", delegate.consumeCalls, delegate.afterCalls)
		}
		if len(audit.events) != 0 {
			t.Fatalf("failed audit unexpectedly retained events: %+v", audit.events)
		}
	})
}

func TestAuditedAuthorizationProviderDoesNotRepeatConsumeAuditOnReplay(t *testing.T) {
	now := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	state, err := NewMemoryAuthorizationState(1, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	identity := testTransportIdentity
	authorization := Authorization{
		ID:        "authorization-audit-replay",
		ExpiresAt: now.Add(time.Minute),
		Request: AuthorizationRequest{
			RequestID: "request-audit-replay", Identity: identity, Action: crp.RuntimeActionPromote,
			Permission: PermissionActivate, Target: RuntimeTarget{Key: "demo"},
		},
	}
	if err := state.Put(context.Background(), authorization); err != nil {
		t.Fatal(err)
	}
	delegate := &productionContractCoalescingProvider{state: state}
	audit := &productionContractAudit{durable: true, idempotent: true}
	provider := auditedAuthorizationProvider{delegate: delegate, audit: audit, clock: func() time.Time { return now }}
	h := &ControlPlaneHandler{state: state, provider: provider, consume: provider.Consume}

	if err := state.Consume(context.Background(), authorization); err != nil {
		t.Fatal(err)
	}
	if err := h.consumeAfterState(context.Background(), identity, authorization); err != nil {
		t.Fatal(err)
	}
	if err := state.Consume(context.Background(), authorization); !errors.Is(err, ErrAuthorizationReplay) {
		t.Fatalf("second state consume error=%v, want ErrAuthorizationReplay", err)
	}

	if delegate.consumeCalls != 0 || delegate.afterCalls != 1 {
		t.Fatalf("delegate calls consume=%d after=%d, want 0/1", delegate.consumeCalls, delegate.afterCalls)
	}
	if len(audit.events) != 1 || audit.events[0].Operation != "consume" || audit.events[0].Outcome != "allowed" {
		t.Fatalf("consume replay audit=%+v, want exactly one allowed consume event", audit.events)
	}
}

func TestProductionContractBuildsProtectedHandlerOnlyAfterValidation(t *testing.T) {
	identity := testTransportIdentity
	contract, err := NewProductionContract(ProductionContractOptions{
		ClusterID:    identity.ClusterID,
		ClientCA:     x509.NewCertPool(),
		State:        productionContractState{durable: true},
		Provider:     productionContractProvider{durable: true, liveFence: true},
		Audit:        &productionContractAudit{durable: true, idempotent: true},
		ControlPlane: productionContractTransport{identity: identity},
		Sidecars:     productionContractSidecars{identity: identity},
	})
	if err != nil {
		t.Fatalf("NewProductionContract() error=%v", err)
	}
	if _, err := contract.NewControlPlaneHandler(); err != nil {
		t.Fatalf("NewControlPlaneHandler() error=%v", err)
	}
	handler, err := contract.NewControlPlaneHandler()
	if err != nil {
		t.Fatalf("NewControlPlaneHandler() second call error=%v", err)
	}
	if err := ValidateProductionControlPlaneHandler(handler); err != nil {
		t.Fatalf("validated production handler rejected by runtime mount check: %v", err)
	}
}

func TestNewProductionControlPlaneHandlerNeedsNoOutboundTransports(t *testing.T) {
	identity := testTransportIdentity
	handler, err := NewProductionControlPlaneHandler(ProductionControlPlaneHandlerOptions{
		ClusterID: identity.ClusterID,
		ClientCA:  x509.NewCertPool(),
		State:     productionContractState{durable: true},
		Provider:  productionContractProvider{durable: true, liveFence: true},
		Audit:     &productionContractAudit{durable: true, idempotent: true},
	})
	if err != nil {
		t.Fatalf("NewProductionControlPlaneHandler() error=%v", err)
	}
	if err := ValidateProductionControlPlaneHandler(handler); err != nil {
		t.Fatalf("production handler validation error=%v", err)
	}
}

func TestNewProductionControlPlaneHandlerRejectsMemoryFallbacks(t *testing.T) {
	state, err := NewMemoryAuthorizationState(4, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewProductionControlPlaneHandler(ProductionControlPlaneHandlerOptions{
		ClusterID: testTransportIdentity.ClusterID,
		ClientCA:  x509.NewCertPool(),
		State:     state,
		Provider:  productionContractProvider{durable: true},
		Audit:     &productionContractAudit{durable: true, idempotent: true},
	})
	if !errors.Is(err, ErrProductionDurability) {
		t.Fatalf("memory state error=%v, want ErrProductionDurability", err)
	}
}

func TestValidateProductionControlPlaneHandlerRejectsUnwrappedDurableProvider(t *testing.T) {
	identity := testTransportIdentity
	state, err := NewMemoryAuthorizationState(4, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	// Use a small test-only handler fixture and replace the provider with a
	// durable-looking implementation after construction. The runtime mount
	// check must reject it because it bypasses the durable audit decorator.
	h, err := NewControlPlaneHandler(ControlPlaneHandlerOptions{
		ClusterID: identity.ClusterID,
		Role:      identity.Role,
		ClientCA:  x509.NewCertPool(),
		State:     state,
		Provider:  productionContractProvider{durable: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	// The in-memory state is deliberately non-durable, so replace it with a
	// minimal durable fixture to isolate the audit-wrapper assertion.
	h.state = productionContractState{durable: true}
	if err := ValidateProductionControlPlaneHandler(h); !errors.Is(err, ErrProductionAuditUnavailable) {
		t.Fatalf("ValidateProductionControlPlaneHandler() error=%v, want ErrProductionAuditUnavailable", err)
	}
}

func TestValidateProductionControlPlaneHandlerRejectsAuditedProviderWithoutLiveFence(t *testing.T) {
	identity := testTransportIdentity
	h, err := NewControlPlaneHandler(ControlPlaneHandlerOptions{
		ClusterID: identity.ClusterID,
		Role:      identity.Role,
		ClientCA:  x509.NewCertPool(),
		State:     productionContractState{durable: true},
		Provider: auditedAuthorizationProvider{
			delegate: productionContractProvider{durable: true},
			audit:    &productionContractAudit{durable: true, idempotent: true},
			clock:    time.Now,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateProductionControlPlaneHandler(h); !errors.Is(err, ErrProductionContract) {
		t.Fatalf("ValidateProductionControlPlaneHandler() error=%v, want ErrProductionContract", err)
	}
}

func TestValidateProductionControlPlaneHandlerRejectsDurableOnlyAudit(t *testing.T) {
	identity := testTransportIdentity
	state := productionContractState{durable: true}
	provider := auditedAuthorizationProvider{
		delegate: productionContractProvider{durable: true},
		audit:    productionContractDurableOnlyAudit{},
		clock:    time.Now,
	}
	h, err := NewControlPlaneHandler(ControlPlaneHandlerOptions{
		ClusterID: identity.ClusterID,
		Role:      identity.Role,
		ClientCA:  x509.NewCertPool(),
		State:     state,
		Provider:  provider,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateProductionControlPlaneHandler(h); err == nil {
		t.Fatal("ValidateProductionControlPlaneHandler() accepted an audit that only declared durability")
	}
}
