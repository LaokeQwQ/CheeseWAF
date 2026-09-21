package activation

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/crp"
)

var (
	// ErrProductionContract is the stable fail-closed sentinel for a missing
	// or inconsistent CRP production dependency graph.
	ErrProductionContract = errors.New("CRP production contract is not satisfied")
	// ErrProductionDurability is returned when a test/local in-memory adapter
	// is offered for a state which must survive process restart.
	ErrProductionDurability = errors.New("CRP production dependency is not durable")
	// ErrProductionAuditUnavailable means an activation decision could not be
	// durably recorded. A grant is never returned without its audit record.
	ErrProductionAuditUnavailable = errors.New("CRP production authorization audit is unavailable")
)

// DurableAuthorizationState marks an authorization state implementation that
// has a restart-safe, cross-process backing store. MemoryAuthorizationState
// intentionally does not implement this interface.
type DurableAuthorizationState interface {
	AuthorizationState
	Durable() bool
}

// DurableAuthorizationProvider marks the control-plane authority that owns
// permission, fence, confirmation and replay decisions in durable storage.
// A provider's in-process cache is not sufficient for this contract.
type DurableAuthorizationProvider interface {
	AuthorizationProvider
	Durable() bool
}

// AuthorizationAuditEvent contains only metadata. Fence tokens, confirmation
// actors, request/response payloads and CRP bytes must never be copied into an
// activation audit stream.
type AuthorizationAuditEvent struct {
	EventID          string            `json:"event_id"`
	Operation        string            `json:"operation"`
	Outcome          string            `json:"outcome"`
	At               time.Time         `json:"at"`
	Identity         TransportIdentity `json:"identity"`
	RequestID        string            `json:"request_id"`
	AuthorizationID  string            `json:"authorization_id,omitempty"`
	Action           crp.RuntimeAction `json:"action"`
	Permission       Permission        `json:"permission"`
	PluginKey        string            `json:"plugin_key"`
	ManifestIdentity string            `json:"manifest_identity"`
	ExpectedRevision uint64            `json:"expected_revision"`
}

// DurableAuthorizationAudit is the append-only metadata audit boundary used
// by the production control-plane provider. Append must be idempotent for an
// EventID so transport retries cannot create ambiguous audit history.
type DurableAuthorizationAudit interface {
	Append(context.Context, AuthorizationAuditEvent) error
	Durable() bool
}

// ProductionContractOptions is the complete CRP activation dependency graph.
// There is intentionally no constructor that fills any field with an
// in-memory default.
type ProductionContractOptions struct {
	ClusterID    string
	ClientCA     *x509.CertPool
	State        AuthorizationState
	Provider     AuthorizationProvider
	Audit        DurableAuthorizationAudit
	ControlPlane ControlPlaneClient
	Sidecars     SidecarManager
	Clock        func() time.Time
}

// ProductionContract is a validated, immutable composition-root seam. It
// does not open listeners or mutate RuntimeStore; the launcher owns those
// lifecycle operations after it has supplied this contract.
type ProductionContract struct {
	clusterID string
	clientCA  *x509.CertPool
	state     AuthorizationState
	provider  AuthorizationProvider
	control   ControlPlaneClient
	sidecars  SidecarManager
	clock     func() time.Time
}

// NewProductionContract validates every dependency before a production CRP
// handler or activation service can be constructed. In particular, memory
// state, non-durable providers/audits and mismatched node identities are
// rejected instead of being silently accepted as a local substitute.
func NewProductionContract(opts ProductionContractOptions) (*ProductionContract, error) {
	if !validTransportField(opts.ClusterID, 128) || opts.ClientCA == nil {
		return nil, fmt.Errorf("%w: cluster ID and client CA are required", ErrProductionContract)
	}
	state, ok := opts.State.(DurableAuthorizationState)
	if !ok || isNilActivationDependency(state) || !state.Durable() {
		return nil, fmt.Errorf("%w: %w: authorization state", ErrProductionContract, ErrProductionDurability)
	}
	provider, ok := opts.Provider.(DurableAuthorizationProvider)
	if !ok || isNilActivationDependency(provider) || !provider.Durable() {
		return nil, fmt.Errorf("%w: %w: authorization provider", ErrProductionContract, ErrProductionDurability)
	}
	if isNilActivationDependency(opts.Audit) || !opts.Audit.Durable() {
		return nil, fmt.Errorf("%w: %w: durable authorization audit is required", ErrProductionContract, ErrProductionAuditUnavailable)
	}
	if isNilActivationDependency(opts.ControlPlane) || isNilActivationDependency(opts.Sidecars) {
		return nil, fmt.Errorf("%w: control-plane and sidecar transports are required", ErrProductionContract)
	}
	controlIdentity := opts.ControlPlane.TransportIdentity()
	if err := validateTransportIdentity(controlIdentity); err != nil || controlIdentity.ClusterID != opts.ClusterID {
		return nil, fmt.Errorf("%w: invalid control-plane identity", ErrProductionContract)
	}
	if sidecarIdentity := opts.Sidecars.TransportIdentity(); !sameTransportIdentity(controlIdentity, sidecarIdentity) {
		return nil, fmt.Errorf("%w: control-plane and sidecar identities differ", ErrProductionContract)
	}
	if opts.Clock == nil {
		opts.Clock = time.Now
	}
	return &ProductionContract{
		clusterID: opts.ClusterID,
		clientCA:  opts.ClientCA,
		state:     state,
		provider:  auditedAuthorizationProvider{delegate: provider, audit: opts.Audit, clock: opts.Clock},
		control:   opts.ControlPlane,
		sidecars:  opts.Sidecars,
		clock:     opts.Clock,
	}, nil
}

// ValidateProductionControlPlaneHandler checks the same non-negotiable
// dependency boundary used by the production composition root. It is kept as
// a standalone check so runtimes that receive an already-built handler can
// reject memory-backed state or non-durable providers before mounting it.
func ValidateProductionControlPlaneHandler(h *ControlPlaneHandler) error {
	if h == nil || isNilActivationDependency(h.state) || isNilActivationDependency(h.provider) {
		return ErrProductionContract
	}
	state, ok := h.state.(DurableAuthorizationState)
	if !ok || isNilActivationDependency(state) || !state.Durable() {
		return fmt.Errorf("%w: %w: authorization state is not durable", ErrProductionContract, ErrProductionDurability)
	}
	provider, ok := h.provider.(DurableAuthorizationProvider)
	if !ok || isNilActivationDependency(provider) || !provider.Durable() {
		return fmt.Errorf("%w: %w: authorization provider is not durable", ErrProductionContract, ErrProductionDurability)
	}
	return nil
}

// isNilActivationDependency catches both a nil interface and an interface
// containing a typed-nil pointer. The latter is easy for composition roots to
// produce when an optional adapter is returned through an interface; calling
// Durable or TransportIdentity on it can otherwise panic before fail-closed
// validation gets a chance to reject the graph.
func isNilActivationDependency(value any) bool {
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

// NewControlPlaneHandler returns the protected handler using the durable
// state/provider and audit wrapper validated by NewProductionContract.
func (c *ProductionContract) NewControlPlaneHandler() (*ControlPlaneHandler, error) {
	if c == nil || c.state == nil || c.provider == nil || c.clientCA == nil {
		return nil, ErrProductionContract
	}
	return NewControlPlaneHandler(ControlPlaneHandlerOptions{
		ClusterID: c.clusterID,
		Role:      "waf",
		ClientCA:  c.clientCA,
		Clock:     c.clock,
		State:     c.state,
		Provider:  c.provider,
	})
}

// ControlPlane and Sidecars expose only the already-validated transport
// adapters for the activation service constructor.
func (c *ProductionContract) ControlPlane() ControlPlaneClient {
	if c == nil {
		return nil
	}
	return c.control
}

func (c *ProductionContract) Sidecars() SidecarManager {
	if c == nil {
		return nil
	}
	return c.sidecars
}

type auditedAuthorizationProvider struct {
	delegate AuthorizationProvider
	audit    DurableAuthorizationAudit
	clock    func() time.Time
}

// Durable preserves the admission property of the wrapped provider. The
// audit decorator must not make an otherwise durable provider look like an
// in-memory test double to the runtime composition root.
func (p auditedAuthorizationProvider) Durable() bool {
	provider, ok := p.delegate.(DurableAuthorizationProvider)
	return ok && provider != nil && provider.Durable() && p.audit != nil && p.audit.Durable()
}

func (p auditedAuthorizationProvider) Authorize(ctx context.Context, identity TransportIdentity, request AuthorizationRequest) (Authorization, error) {
	authorization, providerErr := p.delegate.Authorize(ctx, identity, request)
	auditErr := p.record(ctx, authorizationAuditEvent("authorize", providerErr == nil, p.clock().UTC(), identity, request, authorization))
	if providerErr != nil {
		if auditErr != nil {
			return Authorization{}, errors.Join(providerErr, auditErr)
		}
		return Authorization{}, providerErr
	}
	if auditErr != nil {
		return Authorization{}, auditErr
	}
	return authorization, nil
}

func (p auditedAuthorizationProvider) Validate(ctx context.Context, identity TransportIdentity, authorization Authorization) error {
	providerErr := p.delegate.Validate(ctx, identity, authorization)
	auditErr := p.record(ctx, authorizationAuditEventFromAuthorization("validate", providerErr == nil, p.clock().UTC(), identity, authorization))
	if providerErr != nil {
		if auditErr != nil {
			return errors.Join(providerErr, auditErr)
		}
		return providerErr
	}
	return auditErr
}

func (p auditedAuthorizationProvider) Consume(ctx context.Context, identity TransportIdentity, authorization Authorization) error {
	providerErr := p.delegate.Consume(ctx, identity, authorization)
	auditErr := p.record(ctx, authorizationAuditEventFromAuthorization("consume", providerErr == nil, p.clock().UTC(), identity, authorization))
	if providerErr != nil {
		if auditErr != nil {
			return errors.Join(providerErr, auditErr)
		}
		return providerErr
	}
	return auditErr
}

func (p auditedAuthorizationProvider) record(ctx context.Context, event AuthorizationAuditEvent) error {
	if p.audit == nil || !p.audit.Durable() {
		return ErrProductionAuditUnavailable
	}
	if err := p.audit.Append(ctx, event); err != nil {
		return fmt.Errorf("%w: %v", ErrProductionAuditUnavailable, err)
	}
	return nil
}

func authorizationAuditEvent(operation string, allowed bool, at time.Time, identity TransportIdentity, request AuthorizationRequest, authorization Authorization) AuthorizationAuditEvent {
	status := "denied"
	if allowed {
		status = "allowed"
	}
	eventID := operation + ":" + request.RequestID
	if authorization.ID != "" {
		eventID += ":" + authorization.ID
	}
	return AuthorizationAuditEvent{
		EventID: eventID, Operation: operation, Outcome: status, At: at,
		Identity: identity, RequestID: request.RequestID, AuthorizationID: authorization.ID,
		Action: request.Action, Permission: request.Permission, PluginKey: request.Target.Key,
		ManifestIdentity: request.Target.ManifestIdentity, ExpectedRevision: request.ExpectedRevision,
	}
}

func authorizationAuditEventFromAuthorization(operation string, allowed bool, at time.Time, identity TransportIdentity, authorization Authorization) AuthorizationAuditEvent {
	return authorizationAuditEvent(operation, allowed, at, identity, authorization.Request, authorization)
}
