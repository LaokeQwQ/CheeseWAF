package activation

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"sync"
	"time"
)

var (
	ErrAuthorizationState       = errors.New("CRP authorization state is unavailable")
	ErrAuthorizationNotFound    = errors.New("CRP authorization was not found")
	ErrAuthorizationReplay      = errors.New("CRP authorization was already consumed")
	ErrPeerCertificateRequired  = errors.New("CRP transport requires a verified client certificate")
	ErrPeerCertificateBinding   = errors.New("CRP client certificate identity binding failed")
	ErrAuthorizationProviderNil = errors.New("CRP authorization provider is not configured")
)

const (
	maxHandlerPendingAuthorizations = maxPendingAuthorizations
	maxHandlerBodyBytes             = maxTransportBodyBytes
)

// AuthorizationProvider is the control-plane authority behind the protected
// activation transport. It is intentionally injectable: production uses the
// durable control-plane/approval adapter, while tests may provide a contract
// implementation without creating credentials or package material.
type AuthorizationProvider interface {
	Authorize(context.Context, TransportIdentity, AuthorizationRequest) (Authorization, error)
	Validate(context.Context, TransportIdentity, Authorization) error
	Consume(context.Context, TransportIdentity, Authorization) error
}

// AuthorizationState is the durable pending-authorization boundary. Store
// implementations must preserve the exact authorization binding and make
// Consume atomic with respect to retries and concurrent callers.
type AuthorizationState interface {
	Put(context.Context, Authorization) error
	Get(context.Context, string) (Authorization, error)
	Consume(context.Context, Authorization) error
}

// MemoryAuthorizationState is bounded state for local embedding and tests.
// Production control-plane processes should inject a durable implementation;
// this type does not claim crash recovery or cross-process durability.
type MemoryAuthorizationState struct {
	mu      sync.Mutex
	clock   func() time.Time
	limit   int
	pending map[string]Authorization
	used    map[string]time.Time
}

func NewMemoryAuthorizationState(limit int, clock func() time.Time) (*MemoryAuthorizationState, error) {
	if limit == 0 {
		limit = maxHandlerPendingAuthorizations
	}
	if limit < 1 || limit > maxHandlerPendingAuthorizations {
		return nil, fmt.Errorf("%w: pending limit must be between 1 and %d", ErrAuthorizationState, maxHandlerPendingAuthorizations)
	}
	if clock == nil {
		clock = time.Now
	}
	return &MemoryAuthorizationState{clock: clock, limit: limit, pending: make(map[string]Authorization), used: make(map[string]time.Time)}, nil
}

func (s *MemoryAuthorizationState) Put(ctx context.Context, authorization Authorization) error {
	if s == nil {
		return ErrAuthorizationState
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if authorization.ID == "" {
		return ErrAuthorizationBinding
	}
	now := s.clock().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	if _, used := s.used[authorization.ID]; used {
		return ErrAuthorizationReplay
	}
	if prior, exists := s.pending[authorization.ID]; exists {
		if canonicalIdentity(prior) == canonicalIdentity(authorization) {
			return nil
		}
		return ErrAuthorizationBinding
	}
	if len(s.pending) >= s.limit {
		return ErrAuthorizationState
	}
	s.pending[authorization.ID] = authorization
	return nil
}

func (s *MemoryAuthorizationState) Get(ctx context.Context, id string) (Authorization, error) {
	if s == nil {
		return Authorization{}, ErrAuthorizationState
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return Authorization{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(s.clock().UTC())
	authorization, ok := s.pending[id]
	if !ok {
		if _, used := s.used[id]; used {
			return Authorization{}, ErrAuthorizationReplay
		}
		return Authorization{}, ErrAuthorizationNotFound
	}
	return authorization, nil
}

func (s *MemoryAuthorizationState) Consume(ctx context.Context, authorization Authorization) error {
	if s == nil {
		return ErrAuthorizationState
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	now := s.clock().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	prior, ok := s.pending[authorization.ID]
	if !ok {
		if _, used := s.used[authorization.ID]; used {
			return ErrAuthorizationReplay
		}
		return ErrAuthorizationNotFound
	}
	if canonicalIdentity(prior) != canonicalIdentity(authorization) {
		return ErrAuthorizationBinding
	}
	delete(s.pending, authorization.ID)
	s.used[authorization.ID] = now
	return nil
}

func (s *MemoryAuthorizationState) pruneLocked(now time.Time) {
	for id, authorization := range s.pending {
		if !authorization.ExpiresAt.After(now) {
			delete(s.pending, id)
		}
	}
	for id, at := range s.used {
		if !at.Add(maxAuthorizationTTL).After(now) {
			delete(s.used, id)
		}
	}
}

// ControlPlaneHandlerOptions configures the authorization endpoint handler.
// ClientCA is used for an additional leaf verification even when the HTTP
// server has already performed TLS client-auth verification.
type ControlPlaneHandlerOptions struct {
	ClusterID string
	Role      string
	ClientCA  *x509.CertPool
	Clock     func() time.Time
	State     AuthorizationState
	Provider  AuthorizationProvider
	Authorize func(context.Context, AuthorizationRequest, TransportIdentity) (Authorization, error)
	Validate  func(context.Context, TransportIdentity, Authorization) error
	Consume   func(context.Context, TransportIdentity, Authorization) error
}

// ControlPlaneHandler serves authorize, validate and consume. It performs the
// transport-level identity and schema checks before invoking the provider.
type ControlPlaneHandler struct {
	clusterID string
	role      string
	clientCA  *x509.CertPool
	clock     func() time.Time
	state     AuthorizationState
	provider  AuthorizationProvider
	authorize func(context.Context, AuthorizationRequest, TransportIdentity) (Authorization, error)
	validate  func(context.Context, TransportIdentity, Authorization) error
	consume   func(context.Context, TransportIdentity, Authorization) error
}

// NewControlPlaneHandler constructs the protected control-plane handler.
func NewControlPlaneHandler(opts ControlPlaneHandlerOptions) (*ControlPlaneHandler, error) {
	if !validTransportField(opts.ClusterID, 128) {
		return nil, fmt.Errorf("%w: cluster id is required", ErrTransportConfig)
	}
	if opts.Role == "" {
		opts.Role = "waf"
	}
	if opts.Role != "waf" || !validTransportField(opts.Role, 32) {
		return nil, fmt.Errorf("%w: role must be waf", ErrTransportConfig)
	}
	if opts.ClientCA == nil {
		return nil, fmt.Errorf("%w: client CA is required", ErrTransportTLS)
	}
	if opts.Clock == nil {
		opts.Clock = time.Now
	}
	if opts.State == nil {
		var err error
		opts.State, err = NewMemoryAuthorizationState(maxHandlerPendingAuthorizations, opts.Clock)
		if err != nil {
			return nil, err
		}
	}
	if opts.Provider == nil && (opts.Authorize == nil || opts.Validate == nil || opts.Consume == nil) {
		return nil, ErrAuthorizationProviderNil
	}
	h := &ControlPlaneHandler{clusterID: opts.ClusterID, role: opts.Role, clientCA: opts.ClientCA, clock: opts.Clock, state: opts.State, provider: opts.Provider, authorize: opts.Authorize, validate: opts.Validate, consume: opts.Consume}
	if opts.Provider != nil {
		h.authorize = func(ctx context.Context, request AuthorizationRequest, identity TransportIdentity) (Authorization, error) {
			return opts.Provider.Authorize(ctx, identity, request)
		}
		h.validate = opts.Provider.Validate
		h.consume = opts.Provider.Consume
	}
	return h, nil
}

// NewHTTPControlPlaneHandler is a descriptive constructor alias.
func NewHTTPControlPlaneHandler(opts ControlPlaneHandlerOptions) (*ControlPlaneHandler, error) {
	return NewControlPlaneHandler(opts)
}

func (h *ControlPlaneHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h == nil || r == nil {
		writeTransportStatus(w, http.StatusServiceUnavailable)
		return
	}
	switch r.URL.Path {
	case controlAuthorizePath:
		h.handleAuthorize(w, r)
	case controlValidatePath:
		h.handleValidate(w, r)
	case controlConsumePath:
		h.handleConsume(w, r)
	default:
		writeTransportStatus(w, http.StatusNotFound)
	}
}

func (h *ControlPlaneHandler) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeTransportStatus(w, http.StatusMethodNotAllowed)
		return
	}
	identity, err := h.peerIdentity(r)
	if err != nil {
		h.writeAuthError(w, err)
		return
	}
	var request AuthorizationRequest
	if !decodeStrictTransportJSON(w, r, &request) {
		return
	}
	if err := validateAuthorizationRequest(request, identity); err != nil || request.Identity.ClusterID != h.clusterID || request.Identity.Role != h.role {
		h.writeAuthError(w, ErrAuthorizationBinding)
		return
	}
	authorization, err := h.authorize(r.Context(), request, identity)
	if err != nil {
		h.writeAuthError(w, err)
		return
	}
	if err := validateAuthorization(authorization, request, h.clock().UTC()); err != nil {
		h.writeAuthError(w, err)
		return
	}
	if err := h.state.Put(r.Context(), authorization); err != nil {
		h.writeAuthError(w, err)
		return
	}
	writeTransportJSON(w, authorization)
}

func (h *ControlPlaneHandler) handleValidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeTransportStatus(w, http.StatusMethodNotAllowed)
		return
	}
	identity, err := h.peerIdentity(r)
	if err != nil {
		h.writeAuthError(w, err)
		return
	}
	var envelope authorizationEnvelope
	if !decodeStrictTransportJSON(w, r, &envelope) {
		return
	}
	if envelope.SchemaVersion != TransportSchemaVersion {
		h.writeAuthError(w, ErrAuthorizationBinding)
		return
	}
	authorization := envelope.Authorization
	if err := h.validateIncomingAuthorization(authorization, identity, false); err != nil {
		h.writeAuthError(w, err)
		return
	}
	if err := h.validate(r.Context(), identity, authorization); err != nil {
		h.writeAuthError(w, err)
		return
	}
	writeTransportJSON(w, transportAcknowledgement{SchemaVersion: TransportSchemaVersion, AuthorizationID: authorization.ID, RequestID: authorization.Request.RequestID, NodeID: identity.NodeID, Status: "valid"})
}

func (h *ControlPlaneHandler) handleConsume(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeTransportStatus(w, http.StatusMethodNotAllowed)
		return
	}
	identity, err := h.peerIdentity(r)
	if err != nil {
		h.writeAuthError(w, err)
		return
	}
	var envelope authorizationEnvelope
	if !decodeStrictTransportJSON(w, r, &envelope) {
		return
	}
	if envelope.SchemaVersion != TransportSchemaVersion {
		h.writeAuthError(w, ErrAuthorizationBinding)
		return
	}
	authorization := envelope.Authorization
	if err := h.validateIncomingAuthorization(authorization, identity, false); err != nil {
		h.writeAuthError(w, err)
		return
	}
	// Burn the capability before invoking the durable provider. If the
	// provider response is lost or ambiguous, the caller must obtain a new
	// authorization instead of replaying this confirmation.
	if err := h.state.Consume(r.Context(), authorization); err != nil {
		h.writeAuthError(w, err)
		return
	}
	if err := h.consume(r.Context(), identity, authorization); err != nil {
		h.writeAuthError(w, err)
		return
	}
	writeTransportJSON(w, transportAcknowledgement{SchemaVersion: TransportSchemaVersion, AuthorizationID: authorization.ID, RequestID: authorization.Request.RequestID, NodeID: identity.NodeID, Status: "consumed"})
}

func (h *ControlPlaneHandler) validateIncomingAuthorization(authorization Authorization, identity TransportIdentity, allowExpired bool) error {
	if authorization.Request.Identity != identity || authorization.Request.Identity.ClusterID != h.clusterID || authorization.Request.Identity.Role != h.role {
		return ErrAuthorizationBinding
	}
	if allowExpired {
		if authorization.SchemaVersion != TransportSchemaVersion || !validTransportField(authorization.ID, 128) {
			return ErrAuthorizationBinding
		}
	} else if err := validateAuthorization(authorization, authorization.Request, h.clock().UTC()); err != nil {
		return err
	}
	stored, err := h.state.Get(context.Background(), authorization.ID)
	if err != nil {
		return err
	}
	if canonicalIdentity(stored) != canonicalIdentity(authorization) {
		return ErrAuthorizationBinding
	}
	return nil
}

func (h *ControlPlaneHandler) peerIdentity(r *http.Request) (TransportIdentity, error) {
	if r == nil || r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return TransportIdentity{}, ErrPeerCertificateRequired
	}
	leaf := r.TLS.PeerCertificates[0]
	now := h.clock().UTC()
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return TransportIdentity{}, ErrPeerCertificateBinding
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: h.clientCA, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return TransportIdentity{}, ErrPeerCertificateBinding
	}
	identity, err := transportIdentityFromCertificate(leaf, h.clusterID, h.role)
	if err != nil {
		return TransportIdentity{}, err
	}
	if len(r.TLS.VerifiedChains) == 0 {
		return TransportIdentity{}, ErrPeerCertificateBinding
	}
	return identity, nil
}

func transportIdentityFromCertificate(cert *x509.Certificate, clusterID, role string) (TransportIdentity, error) {
	if cert == nil || !validTransportField(clusterID, 128) || role != "waf" {
		return TransportIdentity{}, ErrPeerCertificateBinding
	}
	parts := strings.Split(cert.Subject.CommonName, "/")
	if len(parts) != 3 || parts[0] != clusterID || parts[1] != role || !validTransportField(parts[2], 64) {
		return TransportIdentity{}, ErrPeerCertificateBinding
	}
	hasSAN := false
	for _, name := range cert.DNSNames {
		if name == parts[2] {
			hasSAN = true
			break
		}
	}
	if !hasSAN {
		return TransportIdentity{}, ErrPeerCertificateBinding
	}
	digest := sha256.Sum256(cert.Raw)
	return TransportIdentity{ClusterID: clusterID, NodeID: parts[2], Role: role, CertificateSHA256: hex.EncodeToString(digest[:])}, nil
}

func (h *ControlPlaneHandler) writeAuthError(w http.ResponseWriter, err error) {
	status := http.StatusForbidden
	switch {
	case errors.Is(err, ErrPeerCertificateRequired), errors.Is(err, ErrPeerCertificateBinding), errors.Is(err, ErrTransportTLS):
		status = http.StatusUnauthorized
	case errors.Is(err, ErrAuthorizationNotFound), errors.Is(err, ErrAuthorizationReplay), errors.Is(err, ErrConfirmationBinding):
		status = http.StatusConflict
	case errors.Is(err, ErrAuthorizationDenied), errors.Is(err, ErrFenceExpired):
		status = http.StatusGone
	case errors.Is(err, ErrAuthorizationState), errors.Is(err, ErrControlPlaneUnavailable):
		status = http.StatusServiceUnavailable
	}
	writeTransportStatus(w, status)
}

func decodeStrictTransportJSON(w http.ResponseWriter, r *http.Request, target any) bool {
	if r.Header.Get("X-CheeseWAF-Transport-Schema") != TransportSchemaVersion {
		writeTransportStatus(w, http.StatusBadRequest)
		return false
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeTransportStatus(w, http.StatusUnsupportedMediaType)
		return false
	}
	if r.ContentLength > maxHandlerBodyBytes {
		writeTransportStatus(w, http.StatusRequestEntityTooLarge)
		return false
	}
	defer r.Body.Close()
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxHandlerBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		if errors.As(err, new(*http.MaxBytesError)) {
			writeTransportStatus(w, http.StatusRequestEntityTooLarge)
		} else {
			writeTransportStatus(w, http.StatusBadRequest)
		}
		return false
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		writeTransportStatus(w, http.StatusBadRequest)
		return false
	}
	return true
}

// writeTransportJSON and writeTransportStatus are production helpers shared
// by every control-plane and sidecar transport handler. Keeping them in a
// non-test file ensures the activation package also builds when imported by a
// real control-plane binary (test-only helpers must not satisfy production
// symbols).
func writeTransportJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(value)
}

func writeTransportStatus(w http.ResponseWriter, status int) {
	w.WriteHeader(status)
}
