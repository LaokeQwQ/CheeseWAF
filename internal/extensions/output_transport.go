package extensions

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"time"
)

const (
	// OutputTransportSchemaVersion describes the WAF host-normalized envelope.
	// It is intentionally not the raw CheeseSec_Plugin risk-hint,
	// analysis-record, or audit-parquet wire schema; those DTO adapters must
	// validate and normalize their own fields before this boundary.
	OutputTransportSchemaVersion = "cheesewaf-extension-output-transport.v1"
	OutputTransportPath          = "/v1/extensions/outputs"
	MaxOutputTransportBodyBytes  = 1 << 20
)

var (
	ErrOutputTransportConfig   = errors.New("invalid extension output transport configuration")
	ErrOutputPeerRequired      = errors.New("extension output transport requires a verified peer certificate")
	ErrOutputPeerBinding       = errors.New("extension output transport peer binding failed")
	ErrOutputBodyTooLarge      = errors.New("extension output transport body is too large")
	ErrOutputTransportRejected = errors.New("extension output transport rejected")
)

// PeerIdentity is derived from the authenticated client certificate. The
// resolver is host-owned and must never take values from request headers.
type PeerIdentity struct {
	PluginID          string
	TenantRef         string
	SiteRef           string
	CertificateSHA256 string
}

// PeerIdentityResolver maps a verified certificate to the plugin scope that
// the control plane granted to it. It is deliberately separate from the HTTP
// handler so deployments can use their existing certificate registry.
type PeerIdentityResolver func(*x509.Certificate) (PeerIdentity, error)

// MTLSPeerAuthenticator verifies the complete client certificate chain on each
// request. The HTTP server should also use RequireAndVerifyClientCert; this
// second check keeps the handler safe when mounted under a shared server.
type MTLSPeerAuthenticator struct {
	ClientCA *x509.CertPool
	Clock    func() time.Time
	Resolve  PeerIdentityResolver
}

func (a MTLSPeerAuthenticator) Authenticate(r *http.Request) (PeerIdentity, error) {
	if r == nil || r.TLS == nil || len(r.TLS.PeerCertificates) == 0 || len(r.TLS.VerifiedChains) == 0 {
		return PeerIdentity{}, ErrOutputPeerRequired
	}
	if a.ClientCA == nil || a.Resolve == nil {
		return PeerIdentity{}, ErrOutputTransportConfig
	}
	leaf := r.TLS.PeerCertificates[0]
	if leaf == nil {
		return PeerIdentity{}, ErrOutputPeerBinding
	}
	now := time.Now().UTC()
	if a.Clock != nil {
		now = a.Clock().UTC()
	}
	if now.IsZero() || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return PeerIdentity{}, ErrOutputPeerBinding
	}
	var verified []*x509.Certificate
	for _, chain := range r.TLS.VerifiedChains {
		if len(chain) > 0 && bytes.Equal(chain[0].Raw, leaf.Raw) {
			verified = chain
			break
		}
	}
	if len(verified) == 0 {
		return PeerIdentity{}, ErrOutputPeerBinding
	}
	intermediates := x509.NewCertPool()
	for _, certificate := range verified[1:] {
		if certificate == nil {
			return PeerIdentity{}, ErrOutputPeerBinding
		}
		intermediates.AddCert(certificate)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         a.ClientCA,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return PeerIdentity{}, ErrOutputPeerBinding
	}
	identity, err := a.Resolve(leaf)
	if err != nil || !validID(identity.PluginID) || !validID(identity.TenantRef) || !validID(identity.SiteRef) {
		return PeerIdentity{}, ErrOutputPeerBinding
	}
	digest := sha256.Sum256(leaf.Raw)
	identity.CertificateSHA256 = hex.EncodeToString(digest[:])
	return identity, nil
}

type OutputHTTPHandlerOptions struct {
	Ingress      *Ingress
	Peer         MTLSPeerAuthenticator
	Path         string
	PluginID     string
	TenantRef    string
	SiteRef      string
	MaxBodyBytes int64
}

// OutputHTTPHandler accepts only the host-normalized envelope described by
// OutputTransportSchemaVersion. It authenticates and binds the peer, then
// submits an entire bounded message to Ingress. It has no ACL, policy, or
// request-path side effects.
type OutputHTTPHandler struct {
	ingress      *Ingress
	peer         MTLSPeerAuthenticator
	path         string
	pluginID     string
	tenant       string
	site         string
	maxBodyBytes int64
}

func NewOutputHTTPHandler(options OutputHTTPHandlerOptions) (*OutputHTTPHandler, error) {
	if options.Ingress == nil || options.Peer.ClientCA == nil || options.Peer.Resolve == nil || !validID(options.PluginID) || !validID(options.TenantRef) || !validID(options.SiteRef) {
		return nil, ErrOutputTransportConfig
	}
	if options.Path == "" {
		options.Path = OutputTransportPath
	}
	if options.Path != OutputTransportPath {
		return nil, ErrOutputTransportConfig
	}
	if options.MaxBodyBytes == 0 {
		options.MaxBodyBytes = MaxOutputTransportBodyBytes
	}
	if options.MaxBodyBytes < 1 || options.MaxBodyBytes > MaxOutputTransportBodyBytes {
		return nil, ErrOutputTransportConfig
	}
	if options.Peer.Clock == nil {
		options.Peer.Clock = time.Now
	}
	return &OutputHTTPHandler{ingress: options.Ingress, peer: options.Peer, path: options.Path, pluginID: options.PluginID, tenant: options.TenantRef, site: options.SiteRef, maxBodyBytes: options.MaxBodyBytes}, nil
}

func (h *OutputHTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h == nil || r == nil {
		writeOutputTransportStatus(w, http.StatusServiceUnavailable)
		return
	}
	if r.URL == nil || r.URL.Path != h.path || r.URL.RawQuery != "" || r.URL.Fragment != "" || r.URL.RawPath != "" {
		writeOutputTransportStatus(w, http.StatusNotFound)
		return
	}
	if r.Method != http.MethodPost {
		writeOutputTransportStatus(w, http.StatusMethodNotAllowed)
		return
	}
	if mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mediaType != "application/json" {
		writeOutputTransportStatus(w, http.StatusUnsupportedMediaType)
		return
	}
	if r.Header.Get("X-CheeseWAF-Extension-Schema") != OutputTransportSchemaVersion {
		writeOutputTransportStatus(w, http.StatusBadRequest)
		return
	}
	identity, err := h.peer.Authenticate(r)
	if err != nil {
		writeOutputTransportPeerError(w, err)
		return
	}
	wire, err := readOutputTransportBody(r, h.maxBodyBytes)
	if err != nil {
		if errors.Is(err, ErrOutputBodyTooLarge) {
			writeOutputTransportStatus(w, http.StatusRequestEntityTooLarge)
		} else {
			writeOutputTransportStatus(w, http.StatusBadRequest)
		}
		return
	}
	parsed, err := Parse(wire)
	if err != nil {
		writeOutputTransportStatus(w, http.StatusBadRequest)
		return
	}
	claims, err := decodeOutputClaims(parsed.Payload)
	if err != nil || claims.PluginID != h.pluginID || claims.TenantRef != h.tenant || claims.SiteRef != h.site || identity.PluginID != claims.PluginID || identity.TenantRef != claims.TenantRef || identity.SiteRef != claims.SiteRef {
		writeOutputTransportStatus(w, http.StatusForbidden)
		return
	}
	receipt, err := h.ingress.Submit(r.Context(), wire)
	if err != nil {
		writeOutputTransportSubmitError(w, err)
		return
	}
	writeOutputTransportReceipt(w, receipt)
}

func readOutputTransportBody(r *http.Request, limit int64) ([]byte, error) {
	if r == nil || r.Body == nil {
		return nil, ErrOutputTransportRejected
	}
	defer r.Body.Close()
	if r.ContentLength > limit {
		return nil, ErrOutputBodyTooLarge
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil {
		return nil, ErrOutputTransportRejected
	}
	if int64(len(raw)) > limit {
		return nil, ErrOutputBodyTooLarge
	}
	return raw, nil
}

type outputTransportReceipt struct {
	EventID       string `json:"event_id"`
	Sequence      uint64 `json:"sequence"`
	PluginID      string `json:"plugin_id"`
	PluginVersion string `json:"plugin_version"`
	Duplicate     bool   `json:"duplicate"`
}

func writeOutputTransportReceipt(w http.ResponseWriter, receipt Receipt) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = jsonEncode(w, outputTransportReceipt{EventID: receipt.EventID, Sequence: receipt.Sequence, PluginID: receipt.PluginID, PluginVersion: receipt.PluginVersion, Duplicate: receipt.Duplicate})
}

func writeOutputTransportPeerError(w http.ResponseWriter, err error) {
	if errors.Is(err, ErrOutputTransportConfig) {
		writeOutputTransportStatus(w, http.StatusServiceUnavailable)
		return
	}
	writeOutputTransportStatus(w, http.StatusUnauthorized)
}

func writeOutputTransportSubmitError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrIngressQueueFull), errors.Is(err, ErrIngressBacklogFull):
		writeOutputTransportStatus(w, http.StatusTooManyRequests)
	case errors.Is(err, ErrIngressClosed), errors.Is(err, ErrIngressAuditFailed):
		writeOutputTransportStatus(w, http.StatusServiceUnavailable)
	case errors.Is(err, ErrIngressReplay), errors.Is(err, ErrIngressSequenceGap), errors.Is(err, ErrIngressSequenceOld):
		writeOutputTransportStatus(w, http.StatusConflict)
	case errors.Is(err, ErrOutputRejected):
		writeOutputTransportStatus(w, http.StatusUnprocessableEntity)
	default:
		writeOutputTransportStatus(w, http.StatusBadRequest)
	}
}

func writeOutputTransportStatus(w http.ResponseWriter, status int) { w.WriteHeader(status) }

func jsonEncode(w http.ResponseWriter, value any) error {
	return json.NewEncoder(w).Encode(value)
}

var _ http.Handler = (*OutputHTTPHandler)(nil)
