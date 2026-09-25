// Package transport implements the I/O side of CWEDP. The protocol package
// remains pure: this package is the only layer that resolves an authorized
// endpoint, performs TLS/HTTP or local-file I/O, and feeds bytes to Broker.
package transport

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/LaokeQwQ/CheeseWAF/internal/crp"
	"github.com/LaokeQwQ/CheeseWAF/internal/cwedp"
	"github.com/LaokeQwQ/CheeseWAF/internal/netlease"
)

const (
	HeaderHello        = "X-CWEDP-Hello"
	HeaderCapabilities = "X-CWEDP-Capabilities"
	HeaderIntent       = "X-CWEDP-Intent"
	HeaderProtocol     = "X-CWEDP-Protocol"
	HeaderNodeID       = "X-CWEDP-Node-ID"
	HeaderPeerHello    = "X-CWEDP-Peer-Hello"
	HeaderPeerCaps     = "X-CWEDP-Peer-Capabilities"
)

var (
	ErrRegistryConfig         = errors.New("invalid CWEDP transport registry")
	ErrUnauthorizedSource     = errors.New("CWEDP source endpoint is not authorized")
	ErrEndpointScheme         = errors.New("unsupported CWEDP endpoint scheme")
	ErrEndpointPath           = errors.New("invalid CWEDP endpoint path")
	ErrHTTPStatus             = errors.New("CWEDP source returned unexpected HTTP status")
	ErrResumeUnsupported      = errors.New("CWEDP source did not honor range resume")
	ErrCertificateFingerprint = errors.New("CWEDP certificate fingerprint mismatch")
	ErrNetleaseRequired       = errors.New("CWEDP online source requires a netlease broker and lease")
	ErrNetleaseBinding        = errors.New("CWEDP netlease binding does not match the selected endpoint")
	ErrPeerHandshake          = errors.New("invalid CWEDP peer handshake")
	ErrPeerIdentity           = errors.New("CWEDP peer identity does not match registration")
	ErrReaderTooLarge         = errors.New("CRP reader input exceeds configured limit")
	ErrPullConfig             = errors.New("invalid CWEDP puller configuration")
	ErrIntentSignature        = cwedp.ErrIntentSignature
	ErrCRPAdmissionConfig     = errors.New("CRP admission configuration is required")
	ErrCRPSourceBinding       = errors.New("CRP manifest source does not match the transport source")
	errSourceChanged          = errors.New("CWEDP source changed during transfer")
)

// ValidateLeaseBoundAdapter verifies the production online-adapter capability
// without exposing the broker, socket, or HTTP client to the caller. Offline
// file adapters and arbitrary Adapter implementations are intentionally not
// accepted at a production temporary-network composition boundary.
func ValidateLeaseBoundAdapter(adapter Adapter) error {
	if !isLeaseBoundHTTPAdapter(adapter) {
		return ErrNetleaseRequired
	}
	return nil
}

// Endpoint is a trusted control-plane registration. URL is data only after
// the source ID and kind have been matched against this immutable record.
// A caller cannot make an arbitrary URL downloadable by placing it in an
// untrusted DistributionIntent.
type Endpoint struct {
	Source                 cwedp.Source
	URL                    string
	Root                   string
	IndependenceGroup      string
	NodeID                 string
	CertificateFingerprint string
	TLSConfig              *tls.Config
	CertificateVerifier    CertificateVerifier
	// HTTPClient is deprecated and ignored. Online CWEDP traffic must use a
	// broker-bound adapter; this field remains only so older control-plane
	// configuration can be rejected at the adapter boundary without silently
	// switching back to direct HTTP.
	HTTPClient *http.Client
	Adapter    Adapter
}

// SourceEndpoint is a descriptive alias for Endpoint.
type SourceEndpoint = Endpoint

// Adapter opens a registered source at a specific verified prefix. Online
// endpoints accept only the capability minted by NewHTTPAdapter; arbitrary
// implementations are limited to the offline transport boundary.
type Adapter interface {
	Open(context.Context, Endpoint, cwedp.DistributionIntent, cwedp.Hello, cwedp.Capabilities, int64) (io.ReadCloser, error)
}

// AdapterFunc adapts a function to Adapter for tests and specialized local
// transports.
type AdapterFunc func(context.Context, Endpoint, cwedp.DistributionIntent, cwedp.Hello, cwedp.Capabilities, int64) (io.ReadCloser, error)

func (f AdapterFunc) Open(ctx context.Context, endpoint Endpoint, intent cwedp.DistributionIntent, hello cwedp.Hello, caps cwedp.Capabilities, offset int64) (io.ReadCloser, error) {
	return f(ctx, endpoint, intent, hello, caps, offset)
}

func NewFileAdapter() Adapter { return FileAdapter{} }

// AdapterProvider supplies a fresh, releasable adapter for one external pull
// attempt. Production rejects static endpoint adapters and ordinary
// NewHTTPAdapter values: every online attempt must own a LeaseBoundAdapter so
// rejected provider output and abandoned pulls revoke their capability.
// The provider is never used for file sources.
type AdapterProvider func(context.Context, Endpoint, cwedp.DistributionIntent, cwedp.Hello, cwedp.Capabilities, int64) (LeaseBoundAdapter, error)

type onlineAdapterCapability struct{}

var httpAdapterCapability = &onlineAdapterCapability{}

// NewHTTPAdapter creates the only HTTP(S) adapter permitted for online CWEDP
// sources. The lease must already have been issued from a fresh administrator
// confirmation; this transport never receives a password or TOTP value.
func NewHTTPAdapter(broker *netlease.Broker, leaseID string, scope netlease.RequestScope) Adapter {
	return HTTPAdapter{Broker: broker, LeaseID: leaseID, Scope: scope, capability: httpAdapterCapability}
}

// LeaseBoundAdapter is an online adapter that owns a temporary NetLease
// cleanup action. Call Close if a caller abandons the adapter before Open;
// Open also closes it before returning so one transfer attempt cannot retain
// a lease or its temporary management session.
type LeaseBoundAdapter interface {
	Adapter
	Close() error
}

type adapterRelease struct {
	once sync.Once
	fn   func() error
	err  error
}

// NewHTTPAdapterWithRelease creates the production adapter form used by a
// request-scoped lease provider. The release callback is supplied by the
// capability owner and is not exposed to ordinary CWEDP callers.
func NewHTTPAdapterWithRelease(broker *netlease.Broker, leaseID string, scope netlease.RequestScope, release func() error) LeaseBoundAdapter {
	return HTTPAdapter{
		Broker:     broker,
		LeaseID:    leaseID,
		Scope:      scope,
		capability: httpAdapterCapability,
		release:    &adapterRelease{fn: release},
	}
}

// CertificateVerifier permits deployments to plug in an mTLS policy in
// addition to the mandatory endpoint fingerprint pin.
type CertificateVerifier interface {
	Verify(cwedp.Source, *x509.Certificate) error
}

type CertificateVerifierFunc func(cwedp.Source, *x509.Certificate) error

func (f CertificateVerifierFunc) Verify(source cwedp.Source, cert *x509.Certificate) error {
	return f(source, cert)
}

// IntentSignatureVerifier is kept as a transport alias for callers that build
// their verifier beside the HTTP adapter. The protocol package owns the
// actual admission contract.
type IntentSignatureVerifier = cwedp.IntentSignatureVerifier
type IntentSignatureVerifierFunc = cwedp.IntentSignatureVerifierFunc

// FingerprintVerifier compares the leaf certificate's SHA-256 fingerprint.
// Expected may be raw lowercase hex, sha256:<hex>, or the conventional
// colon-separated SHA-256 representation.
type FingerprintVerifier struct{ Expected string }

func (v FingerprintVerifier) Verify(_ cwedp.Source, cert *x509.Certificate) error {
	return VerifyCertificateFingerprint(cert, v.Expected)
}

// Registry is an immutable set of authorized source endpoints plus the
// protocol-level provenance registry used by Broker.
type Registry struct {
	endpoints map[string]Endpoint
	protocol  cwedp.SourceRegistry
}

type SourceRegistry = Registry

func NewRegistry(endpoints []Endpoint) (Registry, error) {
	if len(endpoints) == 0 {
		return Registry{}, fmt.Errorf("%w: no endpoints", ErrRegistryConfig)
	}
	registrations := make([]cwedp.SourceRegistration, 0, len(endpoints))
	result := Registry{endpoints: make(map[string]Endpoint, len(endpoints))}
	for _, endpoint := range endpoints {
		if err := validateEndpoint(endpoint); err != nil {
			return Registry{}, err
		}
		key := sourceKey(endpoint.Source)
		if _, exists := result.endpoints[key]; exists {
			return Registry{}, fmt.Errorf("%w: duplicate source %s", ErrRegistryConfig, key)
		}
		registrations = append(registrations, cwedp.SourceRegistration{ID: endpoint.Source.ID, Kind: endpoint.Source.Kind, Root: endpoint.Root, IndependenceGroup: endpoint.IndependenceGroup})
		result.endpoints[key] = cloneEndpoint(endpoint)
	}
	protocol, err := cwedp.NewSourceRegistry(registrations)
	if err != nil {
		return Registry{}, fmt.Errorf("%w: %v", ErrRegistryConfig, err)
	}
	result.protocol = protocol
	return result, nil
}

// NewEndpointRegistry is an explicit spelling for callers that want to avoid
// confusing this registry with crp.SourceRegistry.
func NewEndpointRegistry(endpoints []Endpoint) (Registry, error) { return NewRegistry(endpoints) }
func NewSourceRegistry(endpoints []Endpoint) (Registry, error)   { return NewRegistry(endpoints) }

func (r Registry) ProtocolRegistry() cwedp.SourceRegistry { return r.protocol }

func (r Registry) Endpoint(source cwedp.Source) (Endpoint, bool) {
	endpoint, ok := r.endpoints[sourceKey(source)]
	if !ok {
		return Endpoint{}, false
	}
	return cloneEndpoint(endpoint), true
}

// Endpoints returns a defensive snapshot of the trusted registry. It exists
// for production composition checks; callers still have to use Endpoint when
// selecting a source for a transfer.
func (r Registry) Endpoints() []Endpoint {
	endpoints := make([]Endpoint, 0, len(r.endpoints))
	for _, endpoint := range r.endpoints {
		endpoints = append(endpoints, cloneEndpoint(endpoint))
	}
	return endpoints
}

// AuthorizeIntent verifies every candidate source before any adapter is
// called. This is the no-implicit-download boundary.
func (r Registry) AuthorizeIntent(intent cwedp.DistributionIntent) error {
	if err := intent.Validate(); err != nil {
		return err
	}
	for _, source := range intent.Sources {
		endpoint, ok := r.Endpoint(source)
		if !ok || endpoint.Source.Kind != source.Kind {
			return fmt.Errorf("%w: %s/%s", ErrUnauthorizedSource, source.Kind, source.ID)
		}
	}
	return nil
}

func sourceKey(source cwedp.Source) string { return string(source.Kind) + "\x00" + source.ID }

func validateEndpoint(endpoint Endpoint) error {
	if _, err := cwedp.NewSourceRegistry([]cwedp.SourceRegistration{{ID: endpoint.Source.ID, Kind: endpoint.Source.Kind, Root: endpoint.Root, IndependenceGroup: endpoint.IndependenceGroup}}); err != nil {
		return fmt.Errorf("%w: source registration: %v", ErrRegistryConfig, err)
	}
	if endpoint.URL == "" || endpoint.URL != strings.TrimSpace(endpoint.URL) || hasControl(endpoint.URL) {
		return fmt.Errorf("%w: URL", ErrRegistryConfig)
	}
	parsed, err := url.Parse(endpoint.URL)
	if err != nil || parsed.Scheme == "" {
		return fmt.Errorf("%w: URL: %v", ErrRegistryConfig, ErrEndpointScheme)
	}
	switch strings.ToLower(parsed.Scheme) {
	case "file":
		if parsed.Host != "" || parsed.RawQuery != "" || parsed.Fragment != "" || !filepath.IsAbs(parsed.Path) {
			return fmt.Errorf("%w: file URL", ErrRegistryConfig)
		}
	case "http", "https":
		if parsed.Host == "" || parsed.User != nil {
			return fmt.Errorf("%w: HTTP URL", ErrRegistryConfig)
		}
	default:
		return fmt.Errorf("%w: %s", ErrEndpointScheme, parsed.Scheme)
	}
	if endpoint.Source.Kind == cwedp.SourceOffline && strings.ToLower(parsed.Scheme) != "file" {
		return fmt.Errorf("%w: offline-crp sources require a local file URL", cwedp.ErrOfflineSource)
	}
	if endpoint.Source.Kind != cwedp.SourceOffline && strings.ToLower(parsed.Scheme) != "https" {
		return fmt.Errorf("%w: online sources require HTTPS", ErrRegistryConfig)
	}
	if endpoint.Source.Kind == cwedp.SourceOffline && endpoint.Adapter != nil {
		if _, ok := endpoint.Adapter.(interface{ OfflineOnly() }); !ok {
			return fmt.Errorf("%w: offline-crp source requires a local-only adapter", cwedp.ErrOfflineSource)
		}
	}
	if endpoint.Source.Kind != cwedp.SourceOffline && endpoint.Adapter != nil && !isBoundHTTPAdapter(endpoint.Adapter) {
		return fmt.Errorf("%w: online source adapter is not netlease-bound", ErrRegistryConfig)
	}
	if endpoint.NodeID != "" {
		if err := (cwedp.Hello{NodeID: endpoint.NodeID, Protocol: cwedp.ProtocolVersion}).Validate(); err != nil {
			return fmt.Errorf("%w: peer NodeID", ErrRegistryConfig)
		}
	}
	if endpoint.CertificateFingerprint != "" {
		if strings.EqualFold(parsed.Scheme, "http") {
			return fmt.Errorf("%w: certificate fingerprints require HTTPS", ErrRegistryConfig)
		}
		if err := netlease.ValidateTLSFingerprint(endpoint.CertificateFingerprint); err != nil {
			return fmt.Errorf("%w: fingerprint: %v", ErrRegistryConfig, err)
		}
	}
	if strings.EqualFold(parsed.Scheme, "https") && endpoint.Source.Kind != cwedp.SourceOffline && endpoint.CertificateFingerprint == "" {
		return fmt.Errorf("%w: HTTPS online sources require a canonical certificate fingerprint", ErrRegistryConfig)
	}
	return nil
}

func hasControl(value string) bool {
	for _, r := range value {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return true
		}
	}
	return false
}

func cloneEndpoint(endpoint Endpoint) Endpoint {
	if endpoint.TLSConfig != nil {
		endpoint.TLSConfig = endpoint.TLSConfig.Clone()
	}
	return endpoint
}

// FileAdapter is a deterministic local source adapter. The registered URL is
// the only path it will open, and Puller has already authorized its source ID.
type FileAdapter struct{}

// OfflineOnly marks an adapter as a local package reader. The marker prevents
// a custom adapter from silently turning an offline-crp registration into a
// network fetch.
func (FileAdapter) OfflineOnly() {}

func (FileAdapter) Open(ctx context.Context, endpoint Endpoint, intent cwedp.DistributionIntent, hello cwedp.Hello, _ cwedp.Capabilities, offset int64) (io.ReadCloser, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if hello.Offline && endpoint.Source.Kind != cwedp.SourceOffline {
		return nil, cwedp.ErrOfflineSource
	}
	parsed, err := url.Parse(endpoint.URL)
	if err != nil || parsed.Scheme != "file" || parsed.Host != "" || !filepath.IsAbs(parsed.Path) {
		return nil, fmt.Errorf("%w: file endpoint", ErrEndpointPath)
	}
	info, err := os.Lstat(parsed.Path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() != intent.Size {
		return nil, cwedp.ErrInvalid
	}
	if offset < 0 || offset > info.Size() {
		return nil, cwedp.ErrChunkOverlap
	}
	file, err := os.Open(parsed.Path)
	if err != nil {
		return nil, err
	}
	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

// HTTPAdapter is the only online CWEDP adapter. NewHTTPAdapter stamps an
// unexported capability into it, so a struct literal cannot become an online
// transport. It deliberately contains no http.Client or net.Conn. The broker
// consumes the configured one-shot lease, resolves the endpoint once, dials
// the approved address, and returns the bounded response body to the puller.
type HTTPAdapter struct {
	Broker  *netlease.Broker
	LeaseID string
	Scope   netlease.RequestScope

	capability *onlineAdapterCapability
	release    *adapterRelease
}

func isBoundHTTPAdapter(adapter Adapter) bool {
	switch bound := adapter.(type) {
	case HTTPAdapter:
		return bound.capability == httpAdapterCapability && bound.Broker != nil && validLeaseID(bound.LeaseID)
	case *HTTPAdapter:
		return bound != nil && bound.capability == httpAdapterCapability && bound.Broker != nil && validLeaseID(bound.LeaseID)
	default:
		return false
	}
}

func isLeaseBoundHTTPAdapter(adapter Adapter) bool {
	switch bound := adapter.(type) {
	case HTTPAdapter:
		return isBoundHTTPAdapter(bound) && bound.release != nil && bound.release.fn != nil
	case *HTTPAdapter:
		return bound != nil && isBoundHTTPAdapter(bound) && bound.release != nil && bound.release.fn != nil
	default:
		return false
	}
}

func (a HTTPAdapter) Close() error {
	if a.release == nil || a.release.fn == nil {
		return nil
	}
	a.release.once.Do(func() { a.release.err = a.release.fn() })
	return a.release.err
}

func (a HTTPAdapter) Open(ctx context.Context, endpoint Endpoint, intent cwedp.DistributionIntent, hello cwedp.Hello, caps cwedp.Capabilities, offset int64) (body io.ReadCloser, retErr error) {
	defer func() {
		if closeErr := a.Close(); closeErr != nil {
			retErr = errors.Join(retErr, fmt.Errorf("release CWEDP lease: %w", closeErr))
		}
	}()
	if ctx == nil {
		ctx = context.Background()
	}
	parsed, err := url.Parse(endpoint.URL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil {
		if endpoint.Source.Kind == cwedp.SourceOffline {
			return nil, cwedp.ErrOfflineSource
		}
		return nil, fmt.Errorf("%w: HTTP endpoint", ErrEndpointPath)
	}
	if endpoint.Source.Kind == cwedp.SourceOffline {
		return nil, cwedp.ErrOfflineSource
	}
	if hello.Offline {
		return nil, cwedp.ErrOfflineSource
	}
	if a.Broker == nil || a.LeaseID == "" {
		return nil, ErrNetleaseRequired
	}
	if err := validateOnlineTLSIdentity(endpoint); err != nil {
		return nil, err
	}
	if parsed.Scheme != "https" {
		return nil, fmt.Errorf("%w: online CWEDP sources require HTTPS", ErrEndpointScheme)
	}
	if offset < 0 || offset > intent.Size {
		return nil, cwedp.ErrChunkOverlap
	}
	if err := a.validateBinding(endpoint, parsed); err != nil {
		return nil, err
	}
	requestHeader := make(http.Header)
	requestHeader.Set("Accept-Encoding", "identity")
	requestHeader.Set(HeaderProtocol, cwedp.ProtocolVersion)
	requestHeader.Set(HeaderHello, encodeHeaderMessage(hello))
	requestHeader.Set(HeaderCapabilities, encodeHeaderMessage(caps))
	intentJSON, _ := json.Marshal(intent)
	requestHeader.Set(HeaderIntent, base64.RawURLEncoding.EncodeToString(intentJSON))
	requestHeader.Set("Range", fmt.Sprintf("bytes=%d-", offset))
	path := parsed.EscapedPath()
	if path == "" {
		path = "/"
	}
	if parsed.RawQuery != "" {
		path += "?" + parsed.RawQuery
	}
	response, err := a.Broker.DoHTTP(ctx, netlease.HTTPRequest{
		LeaseID:          a.LeaseID,
		Scope:            a.Scope,
		TLSPolicy:        endpointTLSPolicy(endpoint),
		Method:           http.MethodGet,
		Path:             path,
		Header:           requestHeader,
		MaxResponseBytes: intent.Size - offset,
	})
	if err != nil {
		return nil, err
	}
	expected := intent.Size - offset
	if response.StatusCode != http.StatusPartialContent && !(offset == 0 && response.StatusCode == http.StatusOK) {
		return nil, fmt.Errorf("%w: status %d", ErrHTTPStatus, response.StatusCode)
	}
	if offset > 0 && response.StatusCode != http.StatusPartialContent {
		return nil, ErrResumeUnsupported
	}
	if rawLength := response.Header.Get("Content-Length"); rawLength != "" {
		contentLength, parseErr := strconv.ParseInt(rawLength, 10, 64)
		if parseErr != nil || contentLength != expected {
			return nil, fmt.Errorf("%w: content length %q, want %d", cwedp.ErrInvalid, rawLength, expected)
		}
	}
	if response.StatusCode == http.StatusPartialContent {
		start, end, total, rangeErr := parseContentRange(response.Header.Get("Content-Range"))
		if rangeErr != nil || start != offset || end < start || total != intent.Size || end-start+1 != expected {
			return nil, ErrResumeUnsupported
		}
	}
	if err := validatePeerHandshake(response.Header, true, endpoint.NodeID); err != nil {
		return nil, err
	}
	return io.NopCloser(bytes.NewReader(response.Body)), nil
}

func endpointTLSPolicy(endpoint Endpoint) *netlease.TLSPolicy {
	if endpoint.TLSConfig == nil && endpoint.NodeID == "" && endpoint.CertificateVerifier == nil {
		return nil
	}
	policy := &netlease.TLSPolicy{}
	if endpoint.TLSConfig != nil {
		policy.Config = endpoint.TLSConfig.Clone()
	}
	source := endpoint.Source
	nodeID := endpoint.NodeID
	verifier := endpoint.CertificateVerifier
	if nodeID != "" || verifier != nil {
		policy.VerifyLeaf = func(cert *x509.Certificate) error {
			if nodeID != "" && !certificateMatchesNodeID(cert, nodeID) {
				return ErrPeerIdentity
			}
			if verifier != nil {
				return verifier.Verify(source, cert)
			}
			return nil
		}
	}
	return policy
}

func validateOnlineTLSIdentity(endpoint Endpoint) error {
	if endpoint.Source.Kind == cwedp.SourceOffline {
		return nil
	}
	parsed, err := url.Parse(endpoint.URL)
	if err != nil || strings.ToLower(parsed.Scheme) != "https" || endpoint.NodeID == "" || endpoint.CertificateFingerprint == "" || endpoint.TLSConfig == nil || endpoint.TLSConfig.InsecureSkipVerify || endpoint.TLSConfig.RootCAs == nil || len(endpoint.TLSConfig.Certificates) == 0 || len(endpoint.TLSConfig.Certificates[0].Certificate) == 0 || endpoint.TLSConfig.Certificates[0].PrivateKey == nil {
		return ErrPullConfig
	}
	if err := (cwedp.Hello{NodeID: endpoint.NodeID, Protocol: cwedp.ProtocolVersion}).Validate(); err != nil {
		return ErrPullConfig
	}
	if _, err := normalizedFingerprint(endpoint.CertificateFingerprint); err != nil {
		return ErrPullConfig
	}
	return nil
}

func (a HTTPAdapter) validateBinding(endpoint Endpoint, parsed *url.URL) error {
	if !validLeaseID(a.LeaseID) || !validTransportRequestScope(a.Scope) {
		return ErrNetleaseBinding
	}
	port := 443
	if parsed.Port() != "" {
		parsedPort, err := strconv.Atoi(parsed.Port())
		if err != nil {
			return ErrNetleaseBinding
		}
		port = parsedPort
	}
	if parsed.Hostname() != a.Scope.Target.Host || port != a.Scope.Target.Port || a.Scope.Target.Protocol != "https" {
		return ErrNetleaseBinding
	}
	if endpoint.CertificateFingerprint == "" || netlease.ValidateTLSFingerprint(endpoint.CertificateFingerprint) != nil || netlease.ValidateTLSFingerprint(a.Scope.TLSFingerprint) != nil {
		return ErrNetleaseBinding
	}
	registered, err := normalizedFingerprint(endpoint.CertificateFingerprint)
	if err != nil {
		return ErrNetleaseBinding
	}
	scopePin, err := normalizedFingerprint(a.Scope.TLSFingerprint)
	if err != nil || !bytes.Equal(registered, scopePin) {
		return ErrNetleaseBinding
	}
	return nil
}

func validLeaseID(id string) bool {
	return id != "" && len(id) <= 256 && !hasControl(id) && strings.TrimSpace(id) == id
}

func validTransportRequestScope(scope netlease.RequestScope) bool {
	return validLeaseID(scope.PluginID) && validLeaseID(scope.PluginVersion) &&
		scope.Target.Validate() == nil && netlease.ValidateTLSFingerprint(scope.TLSFingerprint) == nil &&
		scope.PolicyEpoch != 0 && validLeaseID(scope.OperatorID) && scope.TemporaryEgress && scope.ResourceID == ""
}

func certificateMatchesNodeID(cert *x509.Certificate, nodeID string) bool {
	if cert == nil || nodeID == "" {
		return false
	}
	if cert.Subject.CommonName == nodeID {
		return true
	}
	for _, name := range cert.DNSNames {
		if name == nodeID {
			return true
		}
	}
	for _, ip := range cert.IPAddresses {
		if ip.String() == nodeID {
			return true
		}
	}
	for _, uri := range cert.URIs {
		if uri.String() == nodeID || uri.Host == nodeID || uri.Path == nodeID {
			return true
		}
	}
	return false
}

// CertificateFingerprint returns a stable SHA-256 leaf certificate pin.
func CertificateFingerprint(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	digest := sha256.Sum256(cert.Raw)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func VerifyCertificateFingerprint(cert *x509.Certificate, expected string) error {
	if cert == nil {
		return ErrCertificateFingerprint
	}
	normalized, err := normalizedFingerprint(expected)
	if err != nil {
		return ErrCertificateFingerprint
	}
	actual := sha256.Sum256(cert.Raw)
	if subtle.ConstantTimeCompare(actual[:], normalized) != 1 {
		return ErrCertificateFingerprint
	}
	return nil
}

func normalizedFingerprint(value string) ([]byte, error) {
	value = strings.ToLower(value)
	if strings.HasPrefix(value, "sha256:") {
		value = strings.TrimPrefix(value, "sha256:")
	}
	value = strings.ReplaceAll(value, ":", "")
	if len(value) != sha256.Size*2 {
		return nil, ErrCertificateFingerprint
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size {
		return nil, ErrCertificateFingerprint
	}
	return decoded, nil
}

// EncodeHello and EncodeCapabilities produce compact JSON wire messages.
func EncodeHello(hello cwedp.Hello) (string, error) {
	if err := hello.Validate(); err != nil {
		return "", err
	}
	b, err := json.Marshal(hello)
	return string(b), err
}

func EncodeCapabilities(caps cwedp.Capabilities) (string, error) {
	if err := caps.Validate(); err != nil {
		return "", err
	}
	b, err := json.Marshal(caps)
	return string(b), err
}

// EncodeHelloHeader and EncodeCapabilitiesHeader produce the base64url wire
// values used by the HTTP adapter's response handshake headers.
func EncodeHelloHeader(hello cwedp.Hello) (string, error) {
	if err := hello.Validate(); err != nil {
		return "", err
	}
	return encodeHeaderMessage(hello), nil
}

func EncodeCapabilitiesHeader(caps cwedp.Capabilities) (string, error) {
	if err := caps.Validate(); err != nil {
		return "", err
	}
	return encodeHeaderMessage(caps), nil
}

// Handshake is the node-to-node HELLO/CAPABILITIES pair carried by an HTTP
// request or response.
type Handshake struct {
	Hello        cwedp.Hello
	Capabilities cwedp.Capabilities
}

func (h Handshake) Validate() error {
	if err := h.Hello.Validate(); err != nil {
		return err
	}
	if err := h.Capabilities.Validate(); err != nil {
		return err
	}
	if h.Hello.NodeID != h.Capabilities.NodeID {
		return ErrPeerHandshake
	}
	return nil
}

func NewHandshake(hello cwedp.Hello, caps cwedp.Capabilities) (Handshake, error) {
	handshake := Handshake{Hello: hello, Capabilities: caps}
	if err := handshake.Validate(); err != nil {
		return Handshake{}, err
	}
	return handshake, nil
}

func ParsePeerHandshake(headers http.Header) (Handshake, error) {
	if headers == nil {
		return Handshake{}, ErrPeerHandshake
	}
	hello, err := DecodeHelloHeader(headers.Get(HeaderPeerHello))
	if err != nil {
		return Handshake{}, err
	}
	caps, err := DecodeCapabilitiesHeader(headers.Get(HeaderPeerCaps))
	if err != nil {
		return Handshake{}, err
	}
	handshake := Handshake{Hello: hello, Capabilities: caps}
	if err := handshake.Validate(); err != nil {
		return Handshake{}, err
	}
	return handshake, nil
}

func encodeHeaderMessage(value any) string {
	b, _ := json.Marshal(value)
	return base64.RawURLEncoding.EncodeToString(b)
}

// DecodeHelloHeader and DecodeCapabilitiesHeader decode the safe base64 JSON
// representation sent by HTTPAdapter.
func DecodeHelloHeader(raw string) (cwedp.Hello, error) {
	b, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return cwedp.Hello{}, ErrPeerHandshake
	}
	var hello cwedp.Hello
	if err := json.Unmarshal(b, &hello); err != nil || hello.Validate() != nil {
		return cwedp.Hello{}, ErrPeerHandshake
	}
	return hello, nil
}

func DecodeCapabilitiesHeader(raw string) (cwedp.Capabilities, error) {
	b, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return cwedp.Capabilities{}, ErrPeerHandshake
	}
	var caps cwedp.Capabilities
	if err := json.Unmarshal(b, &caps); err != nil || caps.Validate() != nil {
		return cwedp.Capabilities{}, ErrPeerHandshake
	}
	return caps, nil
}

func validatePeerHandshake(headers http.Header, required bool, expectedNodeID string) error {
	rawHello := headers.Get(HeaderPeerHello)
	rawCaps := headers.Get(HeaderPeerCaps)
	if rawHello == "" && rawCaps == "" {
		if required {
			return ErrPeerHandshake
		}
		return nil
	}
	if rawHello == "" || rawCaps == "" {
		return ErrPeerHandshake
	}
	handshake, err := ParsePeerHandshake(headers)
	if err != nil {
		return err
	}
	if handshake.Hello.Protocol != cwedp.ProtocolVersion {
		return ErrPeerHandshake
	}
	if expectedNodeID != "" && handshake.Hello.NodeID != expectedNodeID {
		return ErrPeerIdentity
	}
	return nil
}

type PullerConfig struct {
	Broker           *cwedp.Broker
	ResumeStore      cwedp.ResumeStore
	Registry         Registry
	ChunkSize        int64
	PollInterval     time.Duration
	QueueRetry       time.Duration
	RequestTimeout   time.Duration
	CRPReader        *CRPReader
	IntentVerifier   IntentSignatureVerifier
	CRPImportOptions *crp.ImportOptions
	AdapterProvider  AdapterProvider
	Production       bool
}

type Puller struct {
	broker           *cwedp.Broker
	store            cwedp.ResumeStore
	registry         Registry
	chunkSize        int64
	pollInterval     time.Duration
	queueRetry       time.Duration
	timeout          time.Duration
	reader           *CRPReader
	intentVerifier   IntentSignatureVerifier
	crpImportOptions *crp.ImportOptions
	adapterProvider  AdapterProvider
	production       bool
	ctx              context.Context
	cancel           context.CancelFunc
	startOnce        sync.Once
}

type Transport = Puller
type TransportConfig = PullerConfig

type PullResult struct {
	JobID    string
	Source   cwedp.Source
	Artifact []byte
	Data     []byte
	Complete bool
	Transfer cwedp.TransferResult
}

func NewPuller(cfg PullerConfig) (*Puller, error) {
	if cfg.Broker == nil || cfg.ResumeStore == nil || len(cfg.Registry.endpoints) == 0 {
		return nil, ErrPullConfig
	}
	if cfg.ChunkSize <= 0 {
		cfg.ChunkSize = cwedp.DefaultMaxChunkBytes
	}
	if cfg.ChunkSize > cwedp.DefaultMaxChunkBytes {
		cfg.ChunkSize = cwedp.DefaultMaxChunkBytes
	}
	if cfg.Production {
		if cfg.IntentVerifier == nil || cfg.CRPImportOptions == nil {
			return nil, ErrPullConfig
		}
		for _, endpoint := range cfg.Registry.endpoints {
			if err := validateOnlineTLSIdentity(endpoint); err != nil {
				return nil, ErrPullConfig
			}
			if endpoint.Source.Kind != cwedp.SourceOffline && endpoint.Adapter != nil {
				return nil, ErrPullConfig
			}
		}
		if hasOnlineEndpoint(cfg.Registry) && cfg.AdapterProvider == nil {
			return nil, ErrPullConfig
		}
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 2 * time.Millisecond
	}
	if cfg.QueueRetry <= 0 {
		cfg.QueueRetry = 2 * time.Millisecond
	}
	if cfg.RequestTimeout <= 0 {
		cfg.RequestTimeout = 30 * time.Second
	}
	ctx, cancel := context.WithCancel(context.Background())
	var importOptions *crp.ImportOptions
	if cfg.CRPImportOptions != nil {
		copied := *cfg.CRPImportOptions
		importOptions = &copied
	}
	return &Puller{broker: cfg.Broker, store: cfg.ResumeStore, registry: cfg.Registry, chunkSize: cfg.ChunkSize, pollInterval: cfg.PollInterval, queueRetry: cfg.QueueRetry, timeout: cfg.RequestTimeout, reader: cfg.CRPReader, intentVerifier: cfg.IntentVerifier, crpImportOptions: importOptions, adapterProvider: cfg.AdapterProvider, production: cfg.Production, ctx: ctx, cancel: cancel}, nil
}

func NewTransport(cfg PullerConfig) (*Puller, error) { return NewPuller(cfg) }

func (p *Puller) Close() {
	if p != nil && p.cancel != nil {
		p.cancel()
	}
}

// Pull negotiates the intent, starts the asynchronous broker worker, and
// streams only the selected registered source into Broker.Push.
func (p *Puller) Pull(ctx context.Context, req cwedp.TransferRequest) (PullResult, error) {
	if p == nil {
		return PullResult{}, ErrPullConfig
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return PullResult{}, err
	}
	if err := p.ctx.Err(); err != nil {
		return PullResult{}, err
	}
	if p.intentVerifier != nil {
		if err := verifyIntentSignature(req.Intent, p.intentVerifier); err != nil {
			return PullResult{}, err
		}
	}
	if err := p.registry.AuthorizeIntent(req.Intent); err != nil {
		return PullResult{}, err
	}
	if err := req.Hello.Validate(); err != nil {
		return PullResult{}, err
	}
	if err := req.Capabilities.Validate(); err != nil {
		return PullResult{}, err
	}
	p.startOnce.Do(func() { p.broker.Start(p.ctx) })
	job, err := p.broker.Submit(req)
	if err != nil {
		return PullResult{}, err
	}
	return p.pullJob(ctx, req, job.ID)
}

// ReportSourceFailure is the explicit policy/transport failure hook for a
// caller that owns an adapter outside Pull. The reason is closed by cwedp;
// arbitrary adapter error strings cannot silently trigger a source switch.
func (p *Puller) ReportSourceFailure(ctx context.Context, req cwedp.TransferRequest, jobID string, source cwedp.Source, reason cwedp.QuarantineReason) (cwedp.Job, error) {
	if p == nil || p.broker == nil {
		return cwedp.Job{}, ErrPullConfig
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := p.registry.AuthorizeIntent(req.Intent); err != nil {
		return cwedp.Job{}, err
	}
	if err := req.Hello.Validate(); err != nil {
		return cwedp.Job{}, err
	}
	if err := req.Capabilities.Validate(); err != nil {
		return cwedp.Job{}, err
	}
	p.startOnce.Do(func() { p.broker.Start(p.ctx) })
	return p.broker.QuarantineSource(jobID, req, source, reason)
}

func (p *Puller) pullJob(ctx context.Context, req cwedp.TransferRequest, id string) (PullResult, error) {
	for {
		state, err := p.store.Load(ctx, id)
		if err != nil {
			return PullResult{}, err
		}
		if state.Complete || state.Failed {
			return p.resultFromState(state)
		}
		endpoint, ok := p.registry.Endpoint(state.Source)
		if !ok {
			return PullResult{}, ErrUnauthorizedSource
		}
		adapter := endpoint.Adapter
		providerAdapter := false
		if p.production && endpoint.Source.Kind != cwedp.SourceOffline {
			if adapter != nil || p.adapterProvider == nil {
				return PullResult{}, ErrPullConfig
			}
			leaseAdapter, providerErr := p.adapterProvider(ctx, endpoint, req.Intent, req.Hello, req.Capabilities, state.NextOffset)
			if providerErr != nil {
				if leaseAdapter != nil {
					_ = leaseAdapter.Close()
				}
				return PullResult{}, providerErr
			}
			if err := ValidateLeaseBoundAdapter(leaseAdapter); err != nil {
				if leaseAdapter != nil {
					_ = leaseAdapter.Close()
				}
				return PullResult{}, err
			}
			adapter = leaseAdapter
		} else if adapter == nil {
			parsed, parseErr := url.Parse(endpoint.URL)
			if parseErr != nil {
				return PullResult{}, parseErr
			}
			if parsed.Scheme == "file" {
				adapter = FileAdapter{}
			} else if p.adapterProvider != nil {
				leaseAdapter, providerErr := p.adapterProvider(ctx, endpoint, req.Intent, req.Hello, req.Capabilities, state.NextOffset)
				if providerErr != nil {
					if leaseAdapter != nil {
						_ = leaseAdapter.Close()
					}
					return PullResult{}, providerErr
				}
				adapter = leaseAdapter
				providerAdapter = true
			} else {
				// An online source must be explicitly bound to a one-shot lease.
				// Do not manufacture a zero-value adapter: its eventual transport
				// error would otherwise look like a source failure and trigger
				// quarantine/source switching.
				return PullResult{}, ErrNetleaseRequired
			}
		}
		if adapter == nil {
			return PullResult{}, ErrNetleaseRequired
		}
		if endpoint.Source.Kind != cwedp.SourceOffline && !isBoundHTTPAdapter(adapter) {
			if providerAdapter {
				if leaseAdapter, ok := adapter.(LeaseBoundAdapter); ok {
					_ = leaseAdapter.Close()
				}
			}
			return PullResult{}, ErrNetleaseRequired
		}
		openCtx, cancel := context.WithTimeout(ctx, p.timeout)
		body, openErr := adapter.Open(openCtx, endpoint, req.Intent, req.Hello, req.Capabilities, state.NextOffset)
		if openErr != nil {
			cancel()
			if errors.Is(openErr, ErrNetleaseRequired) || errors.Is(openErr, ErrNetleaseBinding) || errors.Is(openErr, netlease.ErrBeforeDial) {
				return PullResult{}, openErr
			}
			if handled, qerr := p.quarantine(ctx, req, id, cwedp.QuarantineTransport); handled {
				if qerr != nil {
					return PullResult{}, qerr
				}
				continue
			} else {
				return PullResult{}, openErr
			}
		}
		if state.Intent.Size == 0 {
			var probe [1]byte
			n, readErr := body.Read(probe[:])
			_ = body.Close()
			cancel()
			if n != 0 || !errors.Is(readErr, io.EOF) {
				if handled, qerr := p.quarantine(ctx, req, id, cwedp.QuarantineTransport); handled {
					if qerr != nil {
						return PullResult{}, qerr
					}
					continue
				}
				return PullResult{}, io.ErrUnexpectedEOF
			}
			state.Complete = true
			state.UpdatedAt = time.Now().UTC()
			atomicStore, ok := p.store.(cwedp.AtomicResumeStore)
			if !ok {
				return PullResult{}, cwedp.ErrAtomicResumeRequired
			}
			if saveErr := atomicStore.SaveExpected(ctx, state.NextOffset, state); saveErr != nil {
				return PullResult{}, saveErr
			}
			continue
		}
		chunkSize := p.chunkSize
		if state.MaxChunk > 0 && state.MaxChunk < chunkSize {
			chunkSize = state.MaxChunk
		}
		readErr := p.streamBody(openCtx, req, id, body, state.NextOffset, state.Intent.Size, chunkSize, state.Source)
		_ = body.Close()
		cancel()
		if readErr == nil {
			continue
		}
		if (errors.Is(readErr, context.Canceled) || errors.Is(readErr, context.DeadlineExceeded)) && ctx.Err() != nil {
			return PullResult{}, readErr
		}
		// Broker may have completed an integrity transition while the
		// adapter was returning its final bytes. Treat the changed source
		// and reset offset as a retry signal, rather than quarantining the
		// fallback source a second time.
		if latest, loadErr := p.store.Load(ctx, id); loadErr == nil && !latest.Failed && latest.Source != state.Source {
			continue
		}
		if handled, qerr := p.quarantine(ctx, req, id, cwedp.QuarantineTransport); handled {
			if qerr != nil {
				return PullResult{}, qerr
			}
			continue
		}
		return PullResult{}, readErr
	}
}

func hasOnlineEndpoint(registry Registry) bool {
	for _, endpoint := range registry.endpoints {
		if endpoint.Source.Kind != cwedp.SourceOffline {
			return true
		}
	}
	return false
}

func (p *Puller) streamBody(ctx context.Context, req cwedp.TransferRequest, id string, body io.Reader, offset, size, chunkSize int64, source cwedp.Source) error {
	if offset < 0 || offset > size {
		return cwedp.ErrChunkOverlap
	}
	if chunkSize <= 0 || chunkSize > cwedp.DefaultMaxChunkBytes {
		return cwedp.ErrChunkSize
	}
	buf := make([]byte, chunkSize)
	current := offset
	for current < size {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, readErr := body.Read(buf)
		if n > 0 {
			if int64(n) > size-current {
				return cwedp.ErrChunkOverlap
			}
			chunk := append([]byte(nil), buf[:n]...)
			for {
				pushErr := p.broker.Push(id, current, chunk)
				if pushErr == nil {
					break
				}
				if !errors.Is(pushErr, cwedp.ErrBrokerQueue) {
					return pushErr
				}
				timer := time.NewTimer(p.queueRetry)
				select {
				case <-ctx.Done():
					timer.Stop()
					return ctx.Err()
				case <-timer.C:
				}
			}
			next, waitErr := p.waitProgress(ctx, req, id, current, source)
			if waitErr != nil {
				return waitErr
			}
			if next < current {
				return cwedp.ErrResumeOffsetConflict
			}
			if next == current {
				return cwedp.ErrChunkOverlap
			}
			current = next
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				if current == size {
					return nil
				}
				return io.ErrUnexpectedEOF
			}
			return readErr
		}
	}
	return nil
}

func (p *Puller) waitProgress(ctx context.Context, req cwedp.TransferRequest, id string, previous int64, source cwedp.Source) (int64, error) {
	ticker := time.NewTicker(p.pollInterval)
	defer ticker.Stop()
	for {
		state, err := p.store.Load(ctx, id)
		if err != nil {
			return 0, err
		}
		if state.Failed {
			if state.Failure != "" {
				return 0, errors.New(state.Failure)
			}
			return 0, cwedp.ErrInvalid
		}
		if state.Source != source {
			return state.NextOffset, errSourceChanged
		}
		if state.Complete || state.NextOffset != previous {
			return state.NextOffset, nil
		}
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-ticker.C:
		}
		_ = req // request is retained in the signature for future peer-state validation.
	}
}

func (p *Puller) quarantine(ctx context.Context, req cwedp.TransferRequest, id string, reason cwedp.QuarantineReason) (bool, error) {
	state, err := p.store.Load(ctx, id)
	if err != nil {
		return false, err
	}
	if state.Complete {
		return false, nil
	}
	if state.Failed && state.Failure != "" {
		return false, errors.New(state.Failure)
	}
	_, switchErr := p.broker.QuarantineSource(id, req, state.Source, reason)
	if switchErr != nil {
		return true, switchErr
	}
	return true, nil
}

func (p *Puller) resultFromState(state cwedp.ResumeState) (PullResult, error) {
	artifact := append([]byte(nil), state.Data...)
	result := PullResult{JobID: state.JobID, Source: state.Source, Artifact: artifact, Data: append([]byte(nil), artifact...), Complete: state.Complete, Transfer: cwedp.TransferResult{JobID: state.JobID, Source: state.Source, NextOffset: state.NextOffset, Complete: state.Complete, Failed: state.Failed}}
	if state.Failure != "" {
		result.Transfer.Failure = errors.New(state.Failure)
	}
	if state.Failed {
		if result.Transfer.Failure == nil {
			result.Transfer.Failure = cwedp.ErrInvalid
		}
		return result, result.Transfer.Failure
	}
	return result, nil
}

// PullCRP performs a pull and then runs the strict CRP archive reader over the
// verified artifact bytes. It never installs or activates the package.
func (p *Puller) PullCRP(ctx context.Context, req cwedp.TransferRequest) (crp.Package, PullResult, error) {
	if p == nil || p.intentVerifier == nil {
		return crp.Package{}, PullResult{}, ErrIntentSignature
	}
	result, err := p.Pull(ctx, req)
	if err != nil {
		return crp.Package{}, result, err
	}
	reader := p.reader
	if reader == nil {
		reader = &CRPReader{}
	}
	pkg, err := reader.ReadBytes(result.Artifact)
	if err != nil {
		return crp.Package{}, result, err
	}
	if p.crpImportOptions == nil {
		return crp.Package{}, result, ErrCRPAdmissionConfig
	}
	imported, err := crp.Import(pkg, *p.crpImportOptions)
	if err != nil {
		return crp.Package{}, result, err
	}
	if imported.Manifest.Source != result.Source.ID {
		return crp.Package{}, result, fmt.Errorf("%w: manifest=%q transport=%q", ErrCRPSourceBinding, imported.Manifest.Source, result.Source.ID)
	}
	endpoint, ok := p.registry.Endpoint(result.Source)
	if !ok || imported.Manifest.SourceRoot != endpoint.Root {
		return crp.Package{}, result, fmt.Errorf("%w: manifest root=%q transport root=%q", ErrCRPSourceBinding, imported.Manifest.SourceRoot, endpoint.Root)
	}
	return pkg, result, nil
}

func verifyIntentSignature(intent cwedp.DistributionIntent, verifier IntentSignatureVerifier) error {
	if intent.Signature == "" || verifier == nil {
		return ErrIntentSignature
	}
	if err := verifier.Verify(intent); err != nil {
		return fmt.Errorf("%w: %v", ErrIntentSignature, err)
	}
	return nil
}

// CRPReader materializes a strict CRP archive through crp.ParseArchive. The
// reader limit prevents a malformed compressed stream from becoming an
// unbounded allocation before the archive parser applies its own limits.
type CRPReader struct {
	Options  crp.ArchiveOptions
	MaxBytes int64
}

func (r CRPReader) Read(source io.Reader) (crp.Package, error) {
	if source == nil {
		return crp.Package{}, ErrReaderTooLarge
	}
	max := r.MaxBytes
	if max <= 0 {
		max = crp.DefaultArchiveMaxTotalBytes + (16 << 20)
	}
	data, err := io.ReadAll(io.LimitReader(source, max+1))
	if err != nil {
		return crp.Package{}, err
	}
	if int64(len(data)) > max {
		return crp.Package{}, ErrReaderTooLarge
	}
	return r.ReadBytes(data)
}

func (r CRPReader) ReadBytes(data []byte) (crp.Package, error) {
	return crp.ParseArchive(data, r.Options)
}

func ReadCRP(data []byte, opts crp.ArchiveOptions) (crp.Package, error) {
	return (CRPReader{Options: opts}).ReadBytes(data)
}

// ParseRangeOffset is exported for adapters that need to inspect a Range
// response while retaining strict integer parsing.
func ParseRangeOffset(value string) (int64, error) {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, "bytes=") || !strings.HasSuffix(value, "-") {
		return 0, ErrResumeUnsupported
	}
	raw := strings.TrimSuffix(strings.TrimPrefix(value, "bytes="), "-")
	offset, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || offset < 0 {
		return 0, ErrResumeUnsupported
	}
	return offset, nil
}

func parseContentRange(value string) (start, end, total int64, err error) {
	if !strings.HasPrefix(value, "bytes ") {
		return 0, 0, 0, ErrResumeUnsupported
	}
	parts := strings.Split(strings.TrimPrefix(value, "bytes "), "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return 0, 0, 0, ErrResumeUnsupported
	}
	bounds := strings.Split(parts[0], "-")
	if len(bounds) != 2 {
		return 0, 0, 0, ErrResumeUnsupported
	}
	start, err = strconv.ParseInt(bounds[0], 10, 64)
	if err != nil {
		return 0, 0, 0, ErrResumeUnsupported
	}
	end, err = strconv.ParseInt(bounds[1], 10, 64)
	if err != nil {
		return 0, 0, 0, ErrResumeUnsupported
	}
	total, err = strconv.ParseInt(parts[1], 10, 64)
	if err != nil || start < 0 || end < start || total <= 0 {
		return 0, 0, 0, ErrResumeUnsupported
	}
	return start, end, total, nil
}
