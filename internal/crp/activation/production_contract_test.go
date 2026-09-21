package activation

import (
	"context"
	"crypto/x509"
	"errors"
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

type productionContractProvider struct{ durable bool }

func (p productionContractProvider) Authorize(context.Context, TransportIdentity, AuthorizationRequest) (Authorization, error) {
	return Authorization{}, errors.New("provider test failure")
}
func (p productionContractProvider) Validate(context.Context, TransportIdentity, Authorization) error {
	return nil
}
func (p productionContractProvider) Consume(context.Context, TransportIdentity, Authorization) error {
	return nil
}
func (p productionContractProvider) Durable() bool { return p.durable }

type productionContractAudit struct {
	durable bool
	events  []AuthorizationAuditEvent
	err     error
}

func (a *productionContractAudit) Append(_ context.Context, event AuthorizationAuditEvent) error {
	if a.err != nil {
		return a.err
	}
	a.events = append(a.events, event)
	return nil
}
func (a *productionContractAudit) Durable() bool { return a != nil && a.durable }

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
		Provider:     productionContractProvider{durable: true},
		Audit:        &productionContractAudit{durable: true},
		ControlPlane: productionContractTransport{identity: identity},
		Sidecars:     productionContractSidecars{identity: identity},
	}
	for name, mutate := range map[string]func(*ProductionContractOptions){
		"memory state":          func(opts *ProductionContractOptions) { opts.State = productionContractState{} },
		"memory provider":       func(opts *ProductionContractOptions) { opts.Provider = productionContractProvider{} },
		"missing audit":         func(opts *ProductionContractOptions) { opts.Audit = &productionContractAudit{} },
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
		Provider:     productionContractProvider{durable: true},
		Audit:        &productionContractAudit{durable: true},
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
		Provider:     productionContractProvider{durable: true},
		Audit:        &productionContractAudit{durable: true},
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
	audit := &productionContractAudit{durable: true, err: errors.New("disk full")}
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

func TestProductionContractBuildsProtectedHandlerOnlyAfterValidation(t *testing.T) {
	identity := testTransportIdentity
	contract, err := NewProductionContract(ProductionContractOptions{
		ClusterID:    identity.ClusterID,
		ClientCA:     x509.NewCertPool(),
		State:        productionContractState{durable: true},
		Provider:     productionContractProvider{durable: true},
		Audit:        &productionContractAudit{durable: true},
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
