package activation

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/crp"
)

const (
	TransportSchemaVersion   = "crp-activation-transport.v2"
	controlAuthorizePath     = "/v1/crp/activation/authorize"
	controlValidatePath      = "/v1/crp/activation/validate"
	controlConsumePath       = "/v1/crp/activation/consume"
	maxTransportBodyBytes    = int64(64 << 10)
	maxPendingAuthorizations = 128
	maxAuthorizationTTL      = 5 * time.Minute
	transportClockSkew       = 30 * time.Second
)

var (
	ErrTransportConfig      = errors.New("invalid CRP activation transport configuration")
	ErrTransportTLS         = errors.New("CRP activation transport TLS validation failed")
	ErrTransportProtocol    = errors.New("invalid CRP activation transport response")
	ErrAuthorizationDenied  = errors.New("CRP activation authorization was denied")
	ErrAuthorizationBinding = errors.New("CRP activation authorization binding mismatch")
	ErrConfirmationBinding  = errors.New("CRP activation confirmation is not bound to a pending authorization")
)

type Permission string

const (
	PermissionStage    Permission = "crp.stage"
	PermissionActivate Permission = "crp.activate"
	PermissionRollback Permission = "crp.rollback"
)

// TransportIdentity is derived from the configured client certificate. Both
// the control-plane client and sidecar manager must report the same identity.
type TransportIdentity struct {
	ClusterID         string `json:"cluster_id"`
	NodeID            string `json:"node_id"`
	Role              string `json:"role"`
	CertificateSHA256 string `json:"certificate_sha256"`
}

// MTLSOptions configures one authenticated endpoint. ServerName is optional;
// when omitted, Go verifies the endpoint hostname against the server SAN.
type MTLSOptions struct {
	CAFile     string
	CertFile   string
	KeyFile    string
	ClusterID  string
	NodeID     string
	Role       string
	ServerName string
	Timeout    time.Duration
}

// MTLSClient is deliberately opaque. Callers cannot replace its transport
// with a plaintext or InsecureSkipVerify client after validation.
type MTLSClient struct {
	client   *http.Client
	identity TransportIdentity
}

func NewMTLSClient(opts MTLSOptions) (*MTLSClient, error) {
	if !validTransportField(opts.ClusterID, 128) || !validTransportField(opts.NodeID, 64) || opts.Role != "waf" {
		return nil, fmt.Errorf("%w: cluster, node and waf role are required", ErrTransportConfig)
	}
	if opts.ServerName != "" && !validTransportField(opts.ServerName, 255) {
		return nil, fmt.Errorf("%w: server name", ErrTransportConfig)
	}
	if opts.Timeout == 0 {
		opts.Timeout = 15 * time.Second
	}
	if opts.Timeout < time.Second || opts.Timeout > time.Minute {
		return nil, fmt.Errorf("%w: timeout must be between 1s and 1m", ErrTransportConfig)
	}
	if err := validateTLSFile(opts.CAFile, false); err != nil {
		return nil, fmt.Errorf("%w: CA: %v", ErrTransportTLS, err)
	}
	if err := validateTLSFile(opts.CertFile, false); err != nil {
		return nil, fmt.Errorf("%w: certificate: %v", ErrTransportTLS, err)
	}
	if err := validateTLSFile(opts.KeyFile, true); err != nil {
		return nil, fmt.Errorf("%w: private key: %v", ErrTransportTLS, err)
	}
	certificate, err := tls.LoadX509KeyPair(opts.CertFile, opts.KeyFile)
	if err != nil || len(certificate.Certificate) == 0 {
		return nil, fmt.Errorf("%w: client certificate is invalid", ErrTransportTLS)
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("%w: parse client certificate", ErrTransportTLS)
	}
	caPEM, err := os.ReadFile(opts.CAFile)
	if err != nil {
		return nil, fmt.Errorf("%w: read CA", ErrTransportTLS)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("%w: CA contains no certificates", ErrTransportTLS)
	}
	intermediates := x509.NewCertPool()
	for _, raw := range certificate.Certificate[1:] {
		candidate, parseErr := x509.ParseCertificate(raw)
		if parseErr != nil {
			return nil, fmt.Errorf("%w: client certificate chain", ErrTransportTLS)
		}
		intermediates.AddCert(candidate)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return nil, fmt.Errorf("%w: client certificate chain", ErrTransportTLS)
	}
	if !certificateHasDNSIdentity(leaf, opts.NodeID) {
		return nil, fmt.Errorf("%w: client certificate SAN is not bound to node id", ErrTransportTLS)
	}
	if leaf.Subject.CommonName != opts.ClusterID+"/"+opts.Role+"/"+opts.NodeID {
		return nil, fmt.Errorf("%w: client certificate subject is not bound to cluster, role and node", ErrTransportTLS)
	}
	fingerprint := sha256.Sum256(leaf.Raw)
	identity := TransportIdentity{ClusterID: opts.ClusterID, NodeID: opts.NodeID, Role: opts.Role, CertificateSHA256: hex.EncodeToString(fingerprint[:])}
	certificate.Leaf = leaf
	tlsConfig := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate},
		RootCAs:      roots,
		ServerName:   opts.ServerName,
	}
	httpTransport := &http.Transport{
		Proxy:                 nil,
		TLSClientConfig:       tlsConfig,
		TLSHandshakeTimeout:   opts.Timeout,
		ResponseHeaderTimeout: opts.Timeout,
		ExpectContinueTimeout: time.Second,
		MaxIdleConns:          4,
		MaxIdleConnsPerHost:   2,
		IdleConnTimeout:       30 * time.Second,
		ForceAttemptHTTP2:     true,
		DisableCompression:    true,
	}
	return &MTLSClient{
		client: &http.Client{
			Transport: httpTransport,
			Timeout:   opts.Timeout,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return errors.New("CRP activation transport refuses redirects")
			},
		},
		identity: identity,
	}, nil
}

func (c *MTLSClient) TransportIdentity() TransportIdentity {
	if c == nil {
		return TransportIdentity{}
	}
	return c.identity
}

type RuntimeTarget struct {
	Key              string `json:"key"`
	PluginID         string `json:"plugin_id"`
	Namespace        string `json:"namespace"`
	Version          string `json:"version"`
	ReleaseSequence  uint64 `json:"release_sequence"`
	ManifestIdentity string `json:"manifest_identity"`
	ArtifactIdentity string `json:"artifact_identity"`
	Revision         uint64 `json:"revision"`
}

// ApprovalClaim is metadata issued by the management approval workflow. It
// is intentionally opaque to the activation transport: no password, TOTP,
// credential or other proof material may cross this boundary. The claim is
// bound to the exact operation by IntentDigest and Scope and is echoed by
// both the request and authorization response.
type ApprovalClaim struct {
	ApprovalID     string        `json:"approval_id"`
	ConfirmationID string        `json:"confirmation_id"`
	Actor          string        `json:"actor"`
	Scope          string        `json:"scope"`
	PolicyEpoch    uint64        `json:"policy_epoch"`
	TTL            time.Duration `json:"ttl"`
	IssuedAt       time.Time     `json:"issued_at"`
	ExpiresAt      time.Time     `json:"expires_at"`
	WorkflowDigest string        `json:"workflow_digest,omitempty"`
	IntentDigest   string        `json:"intent_digest"`
	Nonce          string        `json:"nonce"`
	SessionID      string        `json:"session_id"`
}

type AuthorizationRequest struct {
	SchemaVersion      string            `json:"schema_version"`
	RequestID          string            `json:"request_id"`
	Identity           TransportIdentity `json:"identity"`
	Action             crp.RuntimeAction `json:"action"`
	Permission         Permission        `json:"permission"`
	Target             RuntimeTarget     `json:"target"`
	ExpectedRevision   uint64            `json:"expected_revision"`
	Descriptor         SidecarDescriptor `json:"descriptor"`
	DescriptorIdentity string            `json:"descriptor_identity"`
	Canary             CanaryPolicy      `json:"canary"`
	RequestedAt        time.Time         `json:"requested_at"`
	ApprovalClaim      ApprovalClaim     `json:"approval_claim"`
}

type WireConfirmation struct {
	ID               string            `json:"id"`
	Actor            string            `json:"actor"`
	Action           crp.RuntimeAction `json:"action"`
	PluginKey        string            `json:"plugin_key"`
	ManifestIdentity string            `json:"manifest_identity"`
	ExpectedRevision uint64            `json:"expected_revision"`
	AuthorizedAt     time.Time         `json:"authorized_at"`
	ExpiresAt        time.Time         `json:"expires_at"`
}

func (c WireConfirmation) RuntimeConfirmation() crp.Confirmation {
	return crp.Confirmation{
		ID: c.ID, Actor: c.Actor, Action: c.Action, PluginKey: c.PluginKey,
		ManifestIdentity: c.ManifestIdentity, ExpectedRevision: c.ExpectedRevision,
		AuthorizedAt: c.AuthorizedAt, ExpiresAt: c.ExpiresAt,
	}
}

func wireConfirmation(c crp.Confirmation) WireConfirmation {
	return WireConfirmation{
		ID: c.ID, Actor: c.Actor, Action: c.Action, PluginKey: c.PluginKey,
		ManifestIdentity: c.ManifestIdentity, ExpectedRevision: c.ExpectedRevision,
		AuthorizedAt: c.AuthorizedAt, ExpiresAt: c.ExpiresAt,
	}
}

type Authorization struct {
	SchemaVersion string               `json:"schema_version"`
	ID            string               `json:"id"`
	Request       AuthorizationRequest `json:"request"`
	ApprovalClaim ApprovalClaim        `json:"approval_claim"`
	Fence         Fence                `json:"fence"`
	Confirmation  *WireConfirmation    `json:"confirmation,omitempty"`
	IssuedAt      time.Time            `json:"issued_at"`
	ExpiresAt     time.Time            `json:"expires_at"`
}

func cloneAuthorization(authorization Authorization) Authorization {
	authorization.Request.Descriptor = cloneDescriptor(authorization.Request.Descriptor)
	if authorization.Confirmation != nil {
		confirmation := *authorization.Confirmation
		authorization.Confirmation = &confirmation
	}
	return authorization
}

// ControlPlaneClient obtains, continuously revalidates, and finally consumes
// one authorization. Implementations must fail closed when transport proof is
// unavailable.
type ControlPlaneClient interface {
	TransportIdentity() TransportIdentity
	Authorize(context.Context, AuthorizationRequest) (Authorization, error)
	Validate(context.Context, Authorization) error
	Consume(context.Context, crp.Confirmation) error
	Discard(Authorization)
}

type HTTPControlPlaneClient struct {
	endpoint  *url.URL
	transport *MTLSClient
	clock     func() time.Time

	mu      sync.Mutex
	pending map[string]Authorization
}

func NewHTTPControlPlaneClient(endpoint string, transport *MTLSClient, clock func() time.Time) (*HTTPControlPlaneClient, error) {
	base, err := parseTransportEndpoint(endpoint)
	if err != nil {
		return nil, err
	}
	if transport == nil || transport.client == nil {
		return nil, fmt.Errorf("%w: mTLS client is required", ErrTransportConfig)
	}
	if clock == nil {
		clock = time.Now
	}
	return &HTTPControlPlaneClient{endpoint: base, transport: transport, clock: clock, pending: make(map[string]Authorization)}, nil
}

func (c *HTTPControlPlaneClient) TransportIdentity() TransportIdentity {
	if c == nil || c.transport == nil {
		return TransportIdentity{}
	}
	return c.transport.TransportIdentity()
}

func (c *HTTPControlPlaneClient) Authorize(ctx context.Context, request AuthorizationRequest) (Authorization, error) {
	if c == nil {
		return Authorization{}, ErrControlPlaneUnavailable
	}
	if err := validateAuthorizationRequest(request, c.TransportIdentity()); err != nil {
		return Authorization{}, err
	}
	var authorization Authorization
	if err := c.post(ctx, controlAuthorizePath, request, &authorization); err != nil {
		return Authorization{}, mapControlPlaneError("authorize", err)
	}
	now := c.clock().UTC()
	if err := validateAuthorization(authorization, request, now); err != nil {
		return Authorization{}, err
	}
	if authorization.Confirmation != nil {
		c.mu.Lock()
		c.prunePendingLocked(now)
		if len(c.pending) >= maxPendingAuthorizations {
			c.mu.Unlock()
			return Authorization{}, fmt.Errorf("%w: pending authorization limit reached", ErrControlPlaneUnavailable)
		}
		if _, exists := c.pending[authorization.Confirmation.ID]; exists {
			c.mu.Unlock()
			return Authorization{}, fmt.Errorf("%w: duplicate confirmation id", ErrTransportProtocol)
		}
		c.pending[authorization.Confirmation.ID] = cloneAuthorization(authorization)
		c.mu.Unlock()
	}
	return authorization, nil
}

func (c *HTTPControlPlaneClient) Validate(ctx context.Context, authorization Authorization) error {
	if c == nil {
		return ErrControlPlaneUnavailable
	}
	if err := validateAuthorization(authorization, authorization.Request, c.clock().UTC()); err != nil {
		return err
	}
	if authorization.Confirmation != nil {
		c.mu.Lock()
		pending, exists := c.pending[authorization.Confirmation.ID]
		c.mu.Unlock()
		if !exists || canonicalIdentity(pending) != canonicalIdentity(authorization) {
			return ErrConfirmationBinding
		}
	}
	request := authorizationEnvelope{SchemaVersion: TransportSchemaVersion, Authorization: authorization}
	var response transportAcknowledgement
	if err := c.post(ctx, controlValidatePath, request, &response); err != nil {
		return mapControlPlaneError("validate", err)
	}
	return validateAcknowledgement(response, authorization, "valid")
}

func (c *HTTPControlPlaneClient) Consume(ctx context.Context, confirmation crp.Confirmation) error {
	if c == nil {
		return ErrControlPlaneUnavailable
	}
	c.mu.Lock()
	authorization, exists := c.pending[confirmation.ID]
	if !exists || authorization.Confirmation == nil || wireConfirmation(confirmation) != *authorization.Confirmation {
		c.mu.Unlock()
		return ErrConfirmationBinding
	}
	// A confirmation is one-shot locally even when the remote response is
	// ambiguous. A retry must obtain a new authorization and confirmation ID.
	delete(c.pending, confirmation.ID)
	c.mu.Unlock()
	if err := validateAuthorization(authorization, authorization.Request, c.clock().UTC()); err != nil {
		return err
	}
	request := authorizationEnvelope{SchemaVersion: TransportSchemaVersion, Authorization: authorization}
	var response transportAcknowledgement
	if err := c.post(ctx, controlConsumePath, request, &response); err != nil {
		return mapControlPlaneError("consume", err)
	}
	if err := validateAcknowledgement(response, authorization, "consumed"); err != nil {
		return err
	}
	return nil
}

func (c *HTTPControlPlaneClient) Discard(authorization Authorization) {
	if c == nil || authorization.Confirmation == nil {
		return
	}
	c.mu.Lock()
	delete(c.pending, authorization.Confirmation.ID)
	c.mu.Unlock()
}

func (c *HTTPControlPlaneClient) prunePendingLocked(now time.Time) {
	for id, authorization := range c.pending {
		if !authorization.ExpiresAt.After(now) {
			delete(c.pending, id)
		}
	}
}

func (c *HTTPControlPlaneClient) post(ctx context.Context, endpointPath string, input, output any) error {
	return c.transport.postJSON(ctx, resolveTransportPath(c.endpoint, endpointPath), input, output)
}

// NewRuntimeAuthorizer connects RuntimeStore's final authorization gate to the
// same mTLS client that issued the pending grant.
func NewRuntimeAuthorizer(client ControlPlaneClient) (crp.RuntimeAuthorizer, error) {
	if client == nil {
		return nil, ErrControlPlaneUnavailable
	}
	if err := validateTransportIdentity(client.TransportIdentity()); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTransportConfig, err)
	}
	return controlPlaneRuntimeAuthorizer{client: client}, nil
}

type controlPlaneRuntimeAuthorizer struct{ client ControlPlaneClient }

func (a controlPlaneRuntimeAuthorizer) Authorize(confirmation crp.Confirmation) error {
	return a.client.Consume(context.Background(), confirmation)
}

type authorizationEnvelope struct {
	SchemaVersion string        `json:"schema_version"`
	Authorization Authorization `json:"authorization"`
}

type transportAcknowledgement struct {
	SchemaVersion   string `json:"schema_version"`
	AuthorizationID string `json:"authorization_id"`
	RequestID       string `json:"request_id"`
	NodeID          string `json:"node_id"`
	Status          string `json:"status"`
}

func validateAcknowledgement(response transportAcknowledgement, authorization Authorization, status string) error {
	if response.SchemaVersion != TransportSchemaVersion || response.AuthorizationID != authorization.ID || response.RequestID != authorization.Request.RequestID || response.NodeID != authorization.Request.Identity.NodeID || response.Status != status {
		return ErrAuthorizationBinding
	}
	return nil
}

// ApprovalIntentDigest returns the stable digest of the operation protected
// by an approval claim. Request IDs and wall-clock timestamps are deliberately
// excluded so the digest describes the requested operation rather than one
// transport attempt. The claim itself is never included in its own digest.
func ApprovalIntentDigest(request AuthorizationRequest) string {
	type intent struct {
		Identity           TransportIdentity `json:"identity"`
		Action             crp.RuntimeAction `json:"action"`
		Permission         Permission        `json:"permission"`
		Target             RuntimeTarget     `json:"target"`
		ExpectedRevision   uint64            `json:"expected_revision"`
		Descriptor         SidecarDescriptor `json:"descriptor"`
		DescriptorIdentity string            `json:"descriptor_identity"`
		Canary             CanaryPolicy      `json:"canary"`
	}
	raw, err := json.Marshal(intent{
		Identity: request.Identity, Action: request.Action, Permission: request.Permission,
		Target: request.Target, ExpectedRevision: request.ExpectedRevision,
		Descriptor: request.Descriptor, DescriptorIdentity: request.DescriptorIdentity,
		Canary: request.Canary,
	})
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

// ApprovalScope is the canonical scope string used by the management
// approval workflow for one CRP operation.
func ApprovalScope(request AuthorizationRequest) string {
	return "crp:" + string(request.Action) + ":" + request.Target.Key
}

func validateApprovalClaim(claim ApprovalClaim, request AuthorizationRequest) error {
	if !validTransportField(claim.ApprovalID, 128) || !validTransportField(claim.ConfirmationID, 128) || !validTransportField(claim.Actor, 128) || !validTransportField(claim.Scope, 512) || !validTransportField(claim.Nonce, 256) || !validTransportField(claim.SessionID, 256) {
		return ErrAuthorizationBinding
	}
	if claim.PolicyEpoch == 0 || claim.TTL <= 0 || claim.TTL > maxAuthorizationTTL || claim.IssuedAt.IsZero() || claim.ExpiresAt.IsZero() || !claim.ExpiresAt.After(claim.IssuedAt) || claim.ExpiresAt.Sub(claim.IssuedAt) != claim.TTL {
		return ErrAuthorizationBinding
	}
	if !validHexDigest(claim.IntentDigest) || claim.IntentDigest != ApprovalIntentDigest(request) || claim.Scope != ApprovalScope(request) {
		return ErrAuthorizationBinding
	}
	if claim.WorkflowDigest != "" && !validHexDigest(claim.WorkflowDigest) {
		return ErrAuthorizationBinding
	}
	if request.RequestedAt.Before(claim.IssuedAt.Add(-transportClockSkew)) || request.RequestedAt.After(claim.ExpiresAt) {
		return ErrAuthorizationBinding
	}
	return nil
}

func validateAuthorizationRequest(request AuthorizationRequest, identity TransportIdentity) error {
	if request.SchemaVersion != TransportSchemaVersion || !sameTransportIdentity(request.Identity, identity) || !validTransportField(request.RequestID, 128) || request.RequestedAt.IsZero() {
		return ErrAuthorizationBinding
	}
	permission, err := permissionForAction(request.Action)
	if err != nil || request.Permission != permission {
		return ErrAuthorizationBinding
	}
	if !validRuntimeTarget(request.Target) || request.ExpectedRevision == 0 {
		return ErrAuthorizationBinding
	}
	if request.Action == crp.RuntimeActionPromote && request.Target.Revision != request.ExpectedRevision || request.Action == crp.RuntimeActionRollback && request.Target.Revision >= request.ExpectedRevision {
		return ErrAuthorizationBinding
	}
	normalizedCanary, err := normalizeCanaryPolicy(request.Canary)
	if err != nil || normalizedCanary != request.Canary {
		return ErrAuthorizationBinding
	}
	identityDigest, err := descriptorIdentity(request.Descriptor)
	if err != nil || identityDigest != request.DescriptorIdentity {
		return ErrAuthorizationBinding
	}
	if request.Descriptor.PluginID != request.Target.PluginID || request.Descriptor.Version != request.Target.Version || request.Descriptor.Namespace != request.Target.Namespace || request.Descriptor.ManifestIdentity != request.Target.ManifestIdentity || request.Descriptor.ArtifactIdentity != request.Target.ArtifactIdentity || !validTransportField(request.Descriptor.Source, 128) || !validTransportField(request.Descriptor.SourceRoot, 128) {
		return ErrAuthorizationBinding
	}
	if err := validateApprovalClaim(request.ApprovalClaim, request); err != nil {
		return err
	}
	return nil
}

func validateAuthorization(authorization Authorization, request AuthorizationRequest, now time.Time) error {
	if err := validateAuthorizationRequest(request, request.Identity); err != nil {
		return err
	}
	if authorization.SchemaVersion != TransportSchemaVersion || !validTransportField(authorization.ID, 128) || canonicalIdentity(authorization.Request) != canonicalIdentity(request) || canonicalIdentity(authorization.ApprovalClaim) != canonicalIdentity(request.ApprovalClaim) {
		return ErrAuthorizationBinding
	}
	if request.RequestedAt.After(now.Add(transportClockSkew)) || request.RequestedAt.Before(now.Add(-maxAuthorizationTTL-transportClockSkew)) || authorization.IssuedAt.IsZero() || authorization.IssuedAt.Before(request.RequestedAt.Add(-transportClockSkew)) || authorization.IssuedAt.After(now.Add(transportClockSkew)) || !authorization.ExpiresAt.After(now) || !authorization.ExpiresAt.After(authorization.IssuedAt) || authorization.ExpiresAt.Sub(authorization.IssuedAt) > maxAuthorizationTTL {
		return ErrAuthorizationDenied
	}
	if authorization.IssuedAt.Before(request.ApprovalClaim.IssuedAt.Add(-transportClockSkew)) || authorization.ExpiresAt.After(request.ApprovalClaim.ExpiresAt) {
		return ErrAuthorizationBinding
	}
	fence := authorization.Fence
	if fence.ClusterID != request.Identity.ClusterID || !validTransportField(fence.Token, 512) || fence.Epoch == 0 || fence.Revision == 0 || !fence.ExpiresAt.After(now) || fence.ExpiresAt.After(authorization.ExpiresAt) {
		return ErrAuthorizationBinding
	}
	if request.Action == crp.RuntimeActionPromote || request.Action == crp.RuntimeActionRollback {
		if authorization.Confirmation == nil {
			return ErrAuthorizationDenied
		}
		confirmation := authorization.Confirmation
		if !validTransportField(confirmation.ID, 128) || !validTransportField(confirmation.Actor, 128) || confirmation.ID != request.ApprovalClaim.ConfirmationID || confirmation.Actor != request.ApprovalClaim.Actor || confirmation.Action != request.Action || confirmation.PluginKey != request.Target.Key || confirmation.ManifestIdentity != request.Target.ManifestIdentity || confirmation.ExpectedRevision != request.ExpectedRevision || confirmation.AuthorizedAt.Before(authorization.IssuedAt.Add(-transportClockSkew)) || confirmation.AuthorizedAt.Before(request.ApprovalClaim.IssuedAt.Add(-transportClockSkew)) || confirmation.AuthorizedAt.After(now.Add(transportClockSkew)) || !confirmation.ExpiresAt.After(now) || confirmation.ExpiresAt.After(authorization.ExpiresAt) || confirmation.ExpiresAt.After(request.ApprovalClaim.ExpiresAt) || !confirmation.ExpiresAt.After(confirmation.AuthorizedAt) {
			return ErrAuthorizationBinding
		}
	} else if authorization.Confirmation != nil {
		return ErrAuthorizationBinding
	}
	return nil
}

func permissionForAction(action crp.RuntimeAction) (Permission, error) {
	switch action {
	case crp.RuntimeActionStage:
		return PermissionStage, nil
	case crp.RuntimeActionPromote:
		return PermissionActivate, nil
	case crp.RuntimeActionRollback:
		return PermissionRollback, nil
	default:
		return "", ErrAsyncAction
	}
}

func runtimeTarget(record crp.RuntimeRecord) RuntimeTarget {
	pluginID := record.PluginID
	if pluginID == "" {
		pluginID = record.Name
	}
	return RuntimeTarget{
		Key: record.Key, PluginID: pluginID, Namespace: record.Namespace,
		Version: record.Version, ReleaseSequence: record.ReleaseSequence,
		ManifestIdentity: record.ManifestIdentity, ArtifactIdentity: record.ArtifactIdentity,
		Revision: record.Revision,
	}
}

func validRuntimeTarget(target RuntimeTarget) bool {
	return validTransportField(target.Key, 128) && validTransportField(target.PluginID, 128) && validTransportField(target.Namespace, 256) && validTransportField(target.Version, 128) && target.ReleaseSequence > 0 && target.Revision > 0 && validHexDigest(target.ManifestIdentity) && validHexDigest(target.ArtifactIdentity)
}

func descriptorIdentity(descriptor SidecarDescriptor) (string, error) {
	raw, err := json.Marshal(descriptor)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), nil
}

func canonicalIdentity(value any) string {
	raw, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func newRequestID() (string, error) {
	raw := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

func validateTransportIdentity(identity TransportIdentity) error {
	if !validTransportField(identity.ClusterID, 128) || !validTransportField(identity.NodeID, 64) || identity.Role != "waf" || !validHexDigest(identity.CertificateSHA256) {
		return ErrTransportConfig
	}
	return nil
}

func sameTransportIdentity(left, right TransportIdentity) bool {
	return left == right
}

func validTransportField(value string, maximum int) bool {
	if maximum < 1 || len(value) == 0 || len(value) > maximum || value != strings.TrimSpace(value) {
		return false
	}
	for _, r := range value {
		if r < '!' || r > '~' {
			return false
		}
	}
	return true
}

func validHexDigest(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(decoded) == value
}

func certificateHasDNSIdentity(certificate *x509.Certificate, identity string) bool {
	if certificate == nil {
		return false
	}
	for _, candidate := range certificate.DNSNames {
		if candidate == identity {
			return true
		}
	}
	return false
}

func validateTLSFile(name string, private bool) error {
	if name == "" || name != strings.TrimSpace(name) {
		return errors.New("path is required")
	}
	info, err := os.Lstat(name)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("path is not a regular non-symlink file")
	}
	permissions := info.Mode().Perm()
	if private {
		if permissions != 0o600 {
			return fmt.Errorf("mode is %04o; want 0600", permissions)
		}
	} else if permissions != 0o600 && permissions != 0o644 {
		return fmt.Errorf("mode is %04o; want 0600 or 0644", permissions)
	}
	return nil
}

func parseTransportEndpoint(raw string) (*url.URL, error) {
	if raw == "" || raw != strings.TrimSpace(raw) {
		return nil, fmt.Errorf("%w: endpoint is required", ErrTransportConfig)
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return nil, fmt.Errorf("%w: endpoint must be an HTTPS origin without credentials, path, query or fragment", ErrTransportConfig)
	}
	parsed.Path = ""
	return parsed, nil
}

func resolveTransportPath(base *url.URL, endpointPath string) string {
	resolved := *base
	resolved.Path = path.Clean("/" + strings.TrimPrefix(endpointPath, "/"))
	return resolved.String()
}

func (c *MTLSClient) postJSON(ctx context.Context, endpoint string, input, output any) error {
	if c == nil || c.client == nil {
		return ErrTransportConfig
	}
	if ctx == nil {
		ctx = context.Background()
	}
	body, err := json.Marshal(input)
	if err != nil {
		return fmt.Errorf("%w: encode request", ErrTransportProtocol)
	}
	if int64(len(body)) > maxTransportBodyBytes {
		return fmt.Errorf("%w: request exceeds size limit", ErrTransportProtocol)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("%w: build request", ErrTransportConfig)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("X-CheeseWAF-Transport-Schema", TransportSchemaVersion)
	response, err := c.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return httpStatusError(response.StatusCode)
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return fmt.Errorf("%w: response content type", ErrTransportProtocol)
	}
	limited := io.LimitReader(response.Body, maxTransportBodyBytes+1)
	raw, err := io.ReadAll(limited)
	if err != nil || int64(len(raw)) > maxTransportBodyBytes {
		return fmt.Errorf("%w: response size", ErrTransportProtocol)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return fmt.Errorf("%w: decode response", ErrTransportProtocol)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("%w: trailing response data", ErrTransportProtocol)
	}
	return nil
}

type httpStatusError int

func (e httpStatusError) Error() string { return fmt.Sprintf("HTTP status %d", int(e)) }

func mapControlPlaneError(operation string, err error) error {
	var status httpStatusError
	if errors.As(err, &status) {
		if status == http.StatusUnauthorized || status == http.StatusForbidden || status == http.StatusConflict || status == http.StatusGone {
			return fmt.Errorf("%w: %s", ErrAuthorizationDenied, operation)
		}
	}
	if errors.Is(err, ErrTransportProtocol) || errors.Is(err, ErrTransportConfig) {
		return err
	}
	return fmt.Errorf("%w: %s transport", ErrControlPlaneUnavailable, operation)
}
