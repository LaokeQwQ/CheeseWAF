package netlease

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

const (
	defaultMaxHTTPBodyBytes     int64 = 1 << 20
	defaultMaxHTTPResponseBytes int64 = 8 << 20
	defaultOperationTimeout           = 30 * time.Second
	brokerWireOverheadBytes     int64 = 128 << 10
)

var (
	ErrBrokerDisabled       = errors.New("temporary network broker is disabled")
	ErrTransportUnavailable = errors.New("real network transport is required")
	ErrAddressPolicy        = errors.New("network address policy is required")
	ErrAddressDenied        = errors.New("resolved network address is denied")
	ErrProtocolUnsupported  = errors.New("egress protocol is not supported by the broker")
	ErrHTTPPath             = errors.New("HTTP request path is invalid")
	ErrHTTPHeaders          = errors.New("HTTP request headers are invalid")
	ErrHTTPBodyLimit        = errors.New("HTTP request body exceeds broker limit")
	ErrHTTPResponseLimit    = errors.New("HTTP response exceeds broker limit")
	ErrSocketPayloadLimit   = errors.New("socket payload exceeds broker limit")
	ErrTLSFingerprint       = errors.New("TLS certificate fingerprint mismatch")
	ErrTLSPolicy            = errors.New("TLS policy is invalid")
	ErrBeforeDial           = errors.New("network operation failed before dial")
)

var specialUseAddressPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/96"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001:2::/48"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
}

// HostResolver and NetworkTransport are small I/O seams. Production callers
// must pass a real transport such as NewStandardTransport. Tests may inject a
// controlled adapter, but NewBroker never manufactures a fake transport.
type HostResolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

type HostResolverFunc func(context.Context, string, string) ([]netip.Addr, error)

func (f HostResolverFunc) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return f(ctx, network, host)
}

type NetworkTransport interface {
	Resolve(context.Context, string) ([]netip.Addr, error)
	DialContext(context.Context, string, string) (net.Conn, error)
}

// StandardTransport is the explicit production network adapter. It has no
// goroutines or background dials; Resolve and DialContext run only for a
// caller-authorized broker operation.
type StandardTransport struct {
	Resolver HostResolver
	Dialer   *net.Dialer
}

func NewStandardTransport() *StandardTransport {
	return &StandardTransport{Resolver: net.DefaultResolver, Dialer: &net.Dialer{}}
}

func (t *StandardTransport) Resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	if t == nil {
		return nil, ErrTransportUnavailable
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{ip.Unmap()}, nil
	}
	if t.Resolver == nil {
		return nil, ErrTransportUnavailable
	}
	return t.Resolver.LookupNetIP(ctx, "ip", host)
}

func (t *StandardTransport) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if t == nil || t.Dialer == nil {
		return nil, ErrTransportUnavailable
	}
	return t.Dialer.DialContext(ctx, network, address)
}

// AddressPolicy is evaluated against the single resolved address selected for
// a lease. The broker dials that literal IP, never the hostname again, which
// prevents a second resolver lookup from changing the endpoint after policy
// evaluation.
type AddressPolicy interface {
	Allow(Target, netip.Addr) error
}

type AddressPolicyFunc func(Target, netip.Addr) error

func (f AddressPolicyFunc) Allow(target Target, address netip.Addr) error {
	return f(target, address)
}

// PublicAddressPolicy is the default explicit policy for temporary external
// operations. It denies loopback, unspecified, private, link-local,
// multicast, special-use, documentation, and non-global-unicast destinations.
type PublicAddressPolicy struct{}

func (PublicAddressPolicy) Allow(_ Target, address netip.Addr) error {
	address = address.Unmap()
	if !address.IsValid() || !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsMulticast() || address.IsUnspecified() {
		return ErrAddressDenied
	}
	for _, prefix := range specialUseAddressPrefixes {
		if prefix.Contains(address) {
			return ErrAddressDenied
		}
	}
	return nil
}

type BrokerConfig struct {
	// Enabled must be explicitly true. A zero-value config cannot make a
	// connection, preserving default-offline behavior.
	Enabled    bool
	Production bool

	Policy    OfflinePolicy
	Sessions  *TemporarySessionManager
	Transport NetworkTransport
	Addresses AddressPolicy
	Audit     AuditSink
	Now       func() time.Time

	MaxHTTPBodyBytes     int64
	MaxHTTPResponseBytes int64
	OperationTimeout     time.Duration
}

// Broker is the only runtime component in this package allowed to resolve or
// open a socket. It owns a secure lease manager so callers cannot inject a
// no-policy Manager and accidentally treat the contract as production I/O.
type Broker struct {
	leases            *Manager
	sessions          *TemporarySessionManager
	transport         NetworkTransport
	addresses         AddressPolicy
	audit             AuditSink
	now               func() time.Time
	maxBodyBytes      int64
	maxResponseBytes  int64
	timeout           time.Duration
	revokeMu          sync.Mutex
	revocationAudited map[string]struct{}
}

func NewBroker(cfg BrokerConfig) (*Broker, error) {
	if !cfg.Enabled {
		return nil, ErrBrokerDisabled
	}
	if cfg.Policy.Epoch() == 0 || cfg.Sessions == nil {
		return nil, ErrBrokerDisabled
	}
	if cfg.Transport == nil {
		return nil, ErrTransportUnavailable
	}
	if cfg.Addresses == nil {
		return nil, ErrAddressPolicy
	}
	if cfg.Audit == nil {
		return nil, ErrAuditUnavailable
	}
	if cfg.Production {
		transport, ok := cfg.Transport.(*StandardTransport)
		if !ok || transport == nil || transport.Resolver == nil || transport.Dialer == nil {
			return nil, ErrTransportUnavailable
		}
		durable, ok := cfg.Audit.(DurableAuditSink)
		if !ok || !durable.Durable() {
			return nil, ErrAuditUnavailable
		}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.MaxHTTPBodyBytes <= 0 {
		cfg.MaxHTTPBodyBytes = defaultMaxHTTPBodyBytes
	}
	if cfg.MaxHTTPResponseBytes <= 0 {
		cfg.MaxHTTPResponseBytes = defaultMaxHTTPResponseBytes
	}
	if cfg.OperationTimeout <= 0 {
		cfg.OperationTimeout = defaultOperationTimeout
	}
	return &Broker{
		leases:            NewSecureManager(cfg.Policy, cfg.Now, cfg.Sessions.ConfirmationVerifier()),
		sessions:          cfg.Sessions,
		transport:         cfg.Transport,
		addresses:         cfg.Addresses,
		audit:             cfg.Audit,
		now:               cfg.Now,
		maxBodyBytes:      cfg.MaxHTTPBodyBytes,
		maxResponseBytes:  cfg.MaxHTTPResponseBytes,
		timeout:           cfg.OperationTimeout,
		revocationAudited: make(map[string]struct{}),
	}, nil
}

func (b *Broker) BeginTemporarySession(ctx context.Context, req BeginTemporarySessionRequest) (TemporarySession, error) {
	if b == nil || b.sessions == nil {
		return TemporarySession{}, ErrBrokerDisabled
	}
	return b.sessions.Begin(ctx, req)
}

// IssueTemporary converts a fresh password confirmation into a one-time
// socket lease. A caller never supplies the operator or confirmation ID.
func (b *Broker) IssueTemporary(ctx context.Context, req ConfirmationInput) (Lease, error) {
	if b == nil || b.leases == nil || b.sessions == nil {
		return Lease{}, ErrBrokerDisabled
	}
	confirmation, err := b.sessions.Confirm(ctx, req)
	if err != nil {
		return Lease{}, err
	}
	lease, err := b.leases.IssueTemporary(IssueRequest{
		PluginID:              confirmation.PluginID,
		PluginVersion:         confirmation.PluginVersion,
		Target:                confirmation.Target,
		TLSFingerprint:        confirmation.TLSFingerprint,
		PolicyEpoch:           confirmation.PolicyEpoch,
		ConfirmationID:        confirmation.ID,
		OperatorID:            confirmation.AdministratorID,
		ConfirmationExpiresAt: confirmation.ExpiresAt,
		TTL:                   confirmation.TTL,
		TemporaryEgress:       true,
		MaxBytes:              confirmation.MaxBytes,
		MaxRequests:           1,
	})
	if err != nil {
		return Lease{}, err
	}
	if err := b.appendAudit(b.leaseAuditEvent(lease, "issued", "issued", 0, 0, 0)); err != nil {
		_ = b.Revoke(lease.ID)
		return Lease{}, fmt.Errorf("%w: %v", ErrAuditUnavailable, err)
	}
	return lease, nil
}

func (b *Broker) Revoke(id string) error {
	if b == nil || b.leases == nil {
		return ErrBrokerDisabled
	}
	b.revokeMu.Lock()
	defer b.revokeMu.Unlock()
	lease, ok := b.leases.Get(id)
	if !ok {
		return ErrInvalidLease
	}
	if b.revocationAudited == nil {
		b.revocationAudited = make(map[string]struct{})
	}
	if _, audited := b.revocationAudited[id]; audited {
		return nil
	}
	if !lease.Revoked {
		if err := b.leases.Revoke(id); err != nil {
			return err
		}
		lease, ok = b.leases.Get(id)
		if !ok {
			return ErrInvalidLease
		}
	}
	if err := b.appendAudit(b.leaseAuditEvent(lease, "revoked", "revoked", 0, 0, lease.Requests)); err != nil {
		return fmt.Errorf("%w: %v", ErrAuditUnavailable, err)
	}
	b.revocationAudited[id] = struct{}{}
	return nil
}

func (b *Broker) UpdatePolicy(policy OfflinePolicy) error {
	if b == nil || b.leases == nil {
		return ErrBrokerDisabled
	}
	return b.leases.UpdatePolicy(policy)
}

func (b *Broker) Lease(id string) (Lease, bool) {
	if b == nil || b.leases == nil {
		return Lease{}, false
	}
	return b.leases.Get(id)
}

func (b *Broker) Audit() []AuditEvent {
	if b == nil || b.leases == nil {
		return nil
	}
	return b.leases.Audit()
}

type HTTPRequest struct {
	LeaseID          string
	Scope            RequestScope
	TLSPolicy        *TLSPolicy
	Method, Path     string
	Header           http.Header
	Body             []byte
	MaxResponseBytes int64
}

// TLSPolicy supplies trusted endpoint TLS settings to the broker without
// weakening the lease's mandatory exact leaf pin. Config is defensively
// cloned before use. InsecureSkipVerify and a mismatched ServerName are
// rejected before DNS resolution or dialing.
type TLSPolicy struct {
	Config     *tls.Config
	VerifyLeaf func(*x509.Certificate) error
}

type HTTPResponse struct {
	StatusCode     int
	Header         http.Header
	Body           []byte
	TLSFingerprint string
	RemoteAddress  string
	BytesSent      int64
	BytesReceived  int64
}

// DoHTTP sends exactly one HTTPS request through a one-shot socket lease.
// Redirects, proxies, connection reuse, absolute URLs, and caller-supplied
// Host headers are absent by construction.
func (b *Broker) DoHTTP(ctx context.Context, req HTTPRequest) (response HTTPResponse, retErr error) {
	if b == nil {
		return HTTPResponse{}, ErrBrokerDisabled
	}
	if req.Scope.Target.Protocol != "https" {
		return HTTPResponse{}, beforeDialError(ErrProtocolUnsupported)
	}
	if err := b.validateHTTP(req); err != nil {
		return HTTPResponse{}, beforeDialError(err)
	}
	ctx, cancel := b.operationContext(ctx)
	defer cancel()
	conn, err := b.openTLS(ctx, req.LeaseID, req.Scope, b.httpWireLimit(req), req.TLSPolicy)
	if err != nil {
		return HTTPResponse{}, err
	}
	result := "success"
	defer func() {
		if finishErr := conn.finish(result); finishErr != nil && retErr == nil {
			retErr = finishErr
		}
	}()

	path := req.Path
	if path == "" {
		path = "/"
	}
	host := req.Scope.Target.Host
	if !isDefaultHTTPSPort(req.Scope.Target.Port) {
		host = net.JoinHostPort(host, strconv.Itoa(req.Scope.Target.Port))
	}
	requestURL, _ := url.ParseRequestURI(path)
	httpRequest := &http.Request{
		Method:        req.Method,
		URL:           requestURL,
		Host:          host,
		Header:        cloneHeader(req.Header),
		Body:          io.NopCloser(bytes.NewReader(req.Body)),
		ContentLength: int64(len(req.Body)),
		Close:         true,
	}
	if len(req.Body) == 0 {
		httpRequest.Body = nil
	}
	if err := httpRequest.Write(conn.tls); err != nil {
		result = "http_write_failed"
		return HTTPResponse{}, err
	}
	parsed, err := http.ReadResponse(bufio.NewReader(conn.tls), httpRequest)
	if err != nil {
		result = "http_read_failed"
		return HTTPResponse{}, err
	}
	defer parsed.Body.Close()
	limit := req.MaxResponseBytes
	if limit <= 0 {
		limit = b.maxResponseBytes
	}
	if parsed.ContentLength > limit {
		result = "response_limit"
		return HTTPResponse{}, ErrHTTPResponseLimit
	}
	body, err := io.ReadAll(io.LimitReader(parsed.Body, limit+1))
	if err != nil {
		result = classifyTransportResult(err, "http_body_failed")
		return HTTPResponse{}, err
	}
	if int64(len(body)) > limit {
		result = "response_limit"
		return HTTPResponse{}, ErrHTTPResponseLimit
	}
	result = "http_" + strconv.Itoa(parsed.StatusCode)
	return HTTPResponse{
		StatusCode:     parsed.StatusCode,
		Header:         cloneHeader(parsed.Header),
		Body:           body,
		TLSFingerprint: req.Scope.TLSFingerprint,
		RemoteAddress:  conn.remoteAddress,
		BytesSent:      conn.counter.BytesSent(),
		BytesReceived:  conn.counter.BytesReceived(),
	}, nil
}

type TLSExchangeRequest struct {
	LeaseID          string
	Scope            RequestScope
	TLSPolicy        *TLSPolicy
	Payload          []byte
	MaxResponseBytes int64
}

type TLSExchangeResponse struct {
	Data           []byte
	TLSFingerprint string
	RemoteAddress  string
	BytesSent      int64
	BytesReceived  int64
}

// ExchangeTLS is the socket-level broker surface. It keeps the net.Conn
// private, writes one bounded payload, reads one bounded response, and closes
// the connection before it records the final audit result.
func (b *Broker) ExchangeTLS(ctx context.Context, req TLSExchangeRequest) (response TLSExchangeResponse, retErr error) {
	if b == nil {
		return TLSExchangeResponse{}, ErrBrokerDisabled
	}
	if !supportsTLSProtocol(req.Scope.Target.Protocol) {
		return TLSExchangeResponse{}, beforeDialError(ErrProtocolUnsupported)
	}
	if !validOpaque(req.LeaseID, 256) || !validRequestScope(req.Scope) || int64(len(req.Payload)) > b.maxBodyBytes {
		return TLSExchangeResponse{}, beforeDialError(ErrSocketPayloadLimit)
	}
	limit := req.MaxResponseBytes
	if limit <= 0 {
		limit = b.maxResponseBytes
	}
	if limit > b.maxResponseBytes {
		return TLSExchangeResponse{}, beforeDialError(ErrHTTPResponseLimit)
	}
	ctx, cancel := b.operationContext(ctx)
	defer cancel()
	conn, err := b.openTLS(ctx, req.LeaseID, req.Scope, int64(len(req.Payload))+limit+brokerWireOverheadBytes, req.TLSPolicy)
	if err != nil {
		return TLSExchangeResponse{}, err
	}
	result := "success"
	defer func() {
		if finishErr := conn.finish(result); finishErr != nil && retErr == nil {
			retErr = finishErr
		}
	}()
	if _, err := conn.tls.Write(req.Payload); err != nil {
		result = classifyTransportResult(err, "socket_write_failed")
		return TLSExchangeResponse{}, err
	}
	data, err := io.ReadAll(io.LimitReader(conn.tls, limit+1))
	if err != nil {
		result = classifyTransportResult(err, "socket_read_failed")
		return TLSExchangeResponse{}, err
	}
	if int64(len(data)) > limit {
		result = "response_limit"
		return TLSExchangeResponse{}, ErrHTTPResponseLimit
	}
	return TLSExchangeResponse{
		Data:           data,
		TLSFingerprint: req.Scope.TLSFingerprint,
		RemoteAddress:  conn.remoteAddress,
		BytesSent:      conn.counter.BytesSent(),
		BytesReceived:  conn.counter.BytesReceived(),
	}, nil
}

type brokerConnection struct {
	broker        *Broker
	lease         Lease
	scope         RequestScope
	tls           *tls.Conn
	raw           net.Conn
	counter       *countingConn
	release       func()
	cancel        context.CancelFunc
	remoteAddress string
	finishOnce    sync.Once
	finishErr     error
}

func (b *Broker) openTLS(ctx context.Context, id string, scope RequestScope, maxWireBytes int64, policy *TLSPolicy) (*brokerConnection, error) {
	if !validOpaque(id, 256) || !validRequestScope(scope) || !supportsTLSProtocol(scope.Target.Protocol) {
		return nil, beforeDialError(ErrInvalidLease)
	}
	policy, err := snapshotTLSPolicy(scope, policy)
	if err != nil {
		return nil, beforeDialError(err)
	}
	lease, release, err := b.leases.AcquireUse(id, scope)
	if err != nil {
		return nil, beforeDialError(err)
	}
	connection := &brokerConnection{broker: b, lease: lease, scope: scope, release: release}
	ctx, connection.cancel = b.leaseBoundContext(ctx, lease)
	if err := b.appendAudit(b.leaseAuditEvent(lease, "connection_started", "started", 0, 0, 0)); err != nil {
		_ = connection.finish("audit_unavailable")
		return nil, beforeDialError(fmt.Errorf("%w: %v", ErrAuditUnavailable, err))
	}
	addresses, err := b.transport.Resolve(ctx, lease.Target.Host)
	if err != nil {
		_ = connection.finish("resolve_failed")
		return nil, beforeDialError(fmt.Errorf("resolve %s: %w", lease.Target.Host, err))
	}
	address, err := b.selectAddress(lease.Target, addresses)
	if err != nil {
		_ = connection.finish("address_denied")
		return nil, beforeDialError(err)
	}
	remote := net.JoinHostPort(address.String(), strconv.Itoa(lease.Target.Port))
	raw, err := b.transport.DialContext(ctx, "tcp", remote)
	if err != nil {
		_ = connection.finish("dial_failed")
		return nil, fmt.Errorf("dial %s: %w", remote, err)
	}
	if maxWireBytes <= 0 {
		maxWireBytes = brokerWireOverheadBytes
	}
	if lease.MaxBytes > 0 && lease.MaxBytes < maxWireBytes {
		maxWireBytes = lease.MaxBytes
	}
	connection.raw = raw
	connection.counter = &countingConn{Conn: raw, limit: maxWireBytes}
	if deadline, ok := ctx.Deadline(); ok {
		if err := raw.SetDeadline(deadline); err != nil {
			_ = connection.finish("deadline_failed")
			return nil, err
		}
	}
	tlsConfig, err := tlsConfigForLease(lease, policy)
	if err != nil {
		_ = connection.finish("tls_policy_invalid")
		return nil, beforeDialError(err)
	}
	connection.tls = tls.Client(connection.counter, tlsConfig)
	if err := connection.tls.HandshakeContext(ctx); err != nil {
		result := classifyTLSResult(err)
		_ = connection.finish(result)
		return nil, err
	}
	connection.remoteAddress = remote
	return connection, nil
}

func beforeDialError(err error) error {
	if err == nil || errors.Is(err, ErrBeforeDial) {
		return err
	}
	return fmt.Errorf("%w: %w", ErrBeforeDial, err)
}

func (b *Broker) selectAddress(target Target, addresses []netip.Addr) (netip.Addr, error) {
	for _, address := range addresses {
		address = address.Unmap()
		if !address.IsValid() {
			continue
		}
		if err := b.addresses.Allow(target, address); err != nil {
			continue
		}
		return address, nil
	}
	return netip.Addr{}, ErrAddressDenied
}

func (b *Broker) operationContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithTimeout(ctx, b.timeout)
}

func (b *Broker) leaseBoundContext(ctx context.Context, lease Lease) (context.Context, context.CancelFunc) {
	if lease.ExpiresAt.IsZero() {
		return ctx, func() {}
	}
	now := time.Now
	if b != nil && b.now != nil {
		now = b.now
	}
	return context.WithTimeout(ctx, lease.ExpiresAt.Sub(now()))
}

func (b *Broker) httpWireLimit(req HTTPRequest) int64 {
	limit := req.MaxResponseBytes
	if limit <= 0 {
		limit = b.maxResponseBytes
	}
	return int64(len(req.Body)) + limit + brokerWireOverheadBytes
}

func (b *Broker) validateHTTP(req HTTPRequest) error {
	if !validOpaque(req.LeaseID, 256) || !validRequestScope(req.Scope) || !validHTTPMethod(req.Method) || !validHTTPPath(req.Path) {
		return ErrHTTPPath
	}
	if int64(len(req.Body)) > b.maxBodyBytes {
		return ErrHTTPBodyLimit
	}
	if req.MaxResponseBytes > b.maxResponseBytes {
		return ErrHTTPResponseLimit
	}
	if !validHTTPHeader(req.Header) {
		return ErrHTTPHeaders
	}
	return nil
}

func validRequestScope(scope RequestScope) bool {
	return validOpaque(scope.PluginID, 256) &&
		validOpaque(scope.PluginVersion, 128) &&
		scope.Target.Validate() == nil &&
		ValidateTLSFingerprint(scope.TLSFingerprint) == nil &&
		scope.PolicyEpoch != 0 &&
		validOpaque(scope.OperatorID, 256) &&
		scope.TemporaryEgress &&
		scope.ResourceID == ""
}

func supportsTLSProtocol(protocol string) bool {
	switch protocol {
	case "https", "tls", "tcp+tls":
		return true
	default:
		return false
	}
}

func isDefaultHTTPSPort(port int) bool { return port == 443 }

func validHTTPMethod(method string) bool {
	if method == "" || len(method) > 32 {
		return false
	}
	for _, r := range method {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || strings.ContainsRune("!#$%&'*+-.^_`|~", r) {
			continue
		}
		return false
	}
	return true
}

func validHTTPPath(path string) bool {
	if path == "" {
		return true
	}
	if len(path) > 8192 || !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") || strings.Contains(path, "\\") || strings.Contains(strings.ToLower(path), "%0d") || strings.Contains(strings.ToLower(path), "%0a") {
		return false
	}
	for _, r := range path {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.IsSpace(r) {
			return false
		}
	}
	parsed, err := url.ParseRequestURI(path)
	return err == nil && !parsed.IsAbs() && parsed.Host == "" && parsed.User == nil
}

func validHTTPHeader(header http.Header) bool {
	for key, values := range header {
		if key == "" || strings.EqualFold(key, "host") || strings.EqualFold(key, "content-length") || strings.EqualFold(key, "transfer-encoding") || strings.EqualFold(key, "connection") || strings.HasPrefix(strings.ToLower(key), "proxy-") || !validHTTPHeaderToken(key) {
			return false
		}
		for _, value := range values {
			if len(value) > 8192 || value == "" {
				return false
			}
			for _, r := range value {
				if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
					return false
				}
			}
		}
	}
	return true
}

func validHTTPHeaderToken(value string) bool {
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || strings.ContainsRune("!#$%&'*+-.^_`|~", r) {
			continue
		}
		return false
	}
	return true
}

func cloneHeader(source http.Header) http.Header {
	if source == nil {
		return make(http.Header)
	}
	clone := make(http.Header, len(source))
	for key, values := range source {
		clone[key] = append([]string(nil), values...)
	}
	return clone
}

func validateTLSPolicy(scope RequestScope, policy *TLSPolicy) error {
	if policy == nil || policy.Config == nil {
		return nil
	}
	config := policy.Config
	if config.InsecureSkipVerify || (config.ServerName != "" && config.ServerName != scope.Target.Host) {
		return ErrTLSPolicy
	}
	if config.MinVersion != 0 && config.MinVersion < tls.VersionTLS12 {
		return ErrTLSPolicy
	}
	if config.MaxVersion != 0 && config.MaxVersion < tls.VersionTLS12 {
		return ErrTLSPolicy
	}
	return nil
}

func snapshotTLSPolicy(scope RequestScope, policy *TLSPolicy) (*TLSPolicy, error) {
	if err := validateTLSPolicy(scope, policy); err != nil {
		return nil, err
	}
	if policy == nil {
		return nil, nil
	}
	snapshot := &TLSPolicy{VerifyLeaf: policy.VerifyLeaf}
	if policy.Config != nil {
		snapshot.Config = cloneTLSConfig(policy.Config)
	}
	return snapshot, nil
}

func tlsConfigForLease(lease Lease, policy *TLSPolicy) (*tls.Config, error) {
	if err := validateTLSPolicy(RequestScope{Target: lease.Target}, policy); err != nil {
		return nil, err
	}
	// Keep the standard certificate-chain and hostname verification enabled.
	// The lease's exact leaf pin below is an additional constraint, not a
	// replacement for TLS verification.
	config := &tls.Config{MinVersion: tls.VersionTLS12}
	if policy != nil && policy.Config != nil {
		config = cloneTLSConfig(policy.Config)
		config.InsecureSkipVerify = false
		if config.MinVersion == 0 {
			config.MinVersion = tls.VersionTLS12
		}
	}
	config.ServerName = lease.Target.Host
	originalVerifyConnection := config.VerifyConnection
	config.VerifyConnection = func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) == 0 {
			return ErrTLSFingerprint
		}
		leaf := state.PeerCertificates[0]
		digest := sha256.Sum256(leaf.Raw)
		if "sha256:"+hex.EncodeToString(digest[:]) != lease.TLSFingerprint {
			return ErrTLSFingerprint
		}
		if originalVerifyConnection != nil {
			if err := originalVerifyConnection(state); err != nil {
				return err
			}
		}
		if policy != nil && policy.VerifyLeaf != nil {
			if err := policy.VerifyLeaf(leaf); err != nil {
				return err
			}
		}
		return nil
	}
	return config, nil
}

func cloneTLSConfig(source *tls.Config) *tls.Config {
	clone := source.Clone()
	if source.RootCAs != nil {
		clone.RootCAs = source.RootCAs.Clone()
	}
	if source.ClientCAs != nil {
		clone.ClientCAs = source.ClientCAs.Clone()
	}
	clone.Certificates = append([]tls.Certificate(nil), source.Certificates...)
	for i := range clone.Certificates {
		clone.Certificates[i].Certificate = cloneCertificateChain(source.Certificates[i].Certificate)
		clone.Certificates[i].OCSPStaple = append([]byte(nil), source.Certificates[i].OCSPStaple...)
		clone.Certificates[i].SignedCertificateTimestamps = cloneCertificateChain(source.Certificates[i].SignedCertificateTimestamps)
	}
	return clone
}

func cloneCertificateChain(source [][]byte) [][]byte {
	clone := make([][]byte, len(source))
	for i := range source {
		clone[i] = append([]byte(nil), source[i]...)
	}
	return clone
}

func (c *brokerConnection) finish(result string) error {
	if c == nil {
		return ErrAuditUnavailable
	}
	c.finishOnce.Do(func() {
		if c.tls != nil {
			_ = c.tls.Close()
		} else if c.raw != nil {
			_ = c.raw.Close()
		}
		if c.cancel != nil {
			c.cancel()
		}
		var usage Usage
		if c.counter != nil {
			usage.BytesSent = c.counter.BytesSent()
			usage.BytesReceived = c.counter.BytesReceived()
		}
		usage.Result = result
		managerErr := c.broker.leases.RecordTransferFinal(c.lease, c.scope, usage)
		event := c.broker.leaseAuditEvent(c.lease, "result", result, usage.BytesSent, usage.BytesReceived, 1)
		auditErr := c.broker.appendAudit(event)
		if c.release != nil {
			c.release()
		}
		if managerErr != nil {
			c.finishErr = managerErr
		}
		if auditErr != nil {
			if c.finishErr != nil {
				c.finishErr = fmt.Errorf("%w: %v", c.finishErr, auditErr)
			} else {
				c.finishErr = fmt.Errorf("%w: %v", ErrAuditUnavailable, auditErr)
			}
		}
	})
	return c.finishErr
}

func (b *Broker) appendAudit(event AuditEvent) error {
	if b == nil || b.audit == nil {
		return ErrAuditUnavailable
	}
	return b.audit.Append(context.Background(), event)
}

func (b *Broker) leaseAuditEvent(lease Lease, action, result string, sent, received, requests int64) AuditEvent {
	at := lease.IssuedAt
	if b != nil && b.now != nil {
		at = b.now().UTC()
	}
	return AuditEvent{
		LeaseID:         lease.ID,
		Action:          action,
		PluginID:        lease.PluginID,
		PluginVersion:   lease.PluginVersion,
		TargetHost:      lease.Target.Host,
		TargetPort:      lease.Target.Port,
		TargetProtocol:  lease.Target.Protocol,
		TLSFingerprint:  lease.TLSFingerprint,
		PolicyEpoch:     lease.PolicyEpoch,
		TemporaryEgress: lease.TemporaryEgress,
		ConfirmationID:  lease.ConfirmationID,
		ResourceID:      lease.ResourceID,
		OperatorID:      lease.OperatorID,
		Bytes:           sent + received,
		BytesSent:       sent,
		BytesReceived:   received,
		Requests:        requests,
		Result:          result,
		Reason:          result,
		At:              at,
	}
}

func classifyTLSResult(err error) string {
	if errors.Is(err, ErrTLSFingerprint) {
		return "tls_fingerprint_mismatch"
	}
	if errors.Is(err, ErrUsageLimit) {
		return "usage_limit"
	}
	return "tls_handshake_failed"
}

func classifyTransportResult(err error, fallback string) string {
	if errors.Is(err, ErrUsageLimit) {
		return "usage_limit"
	}
	return fallback
}

type countingConn struct {
	net.Conn
	mu       sync.Mutex
	limit    int64
	sent     int64
	received int64
}

func (c *countingConn) Read(buffer []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	limited, err := c.limitBuffer(buffer)
	if err != nil {
		return 0, err
	}
	n, readErr := c.Conn.Read(limited)
	c.received += int64(n)
	return n, readErr
}

func (c *countingConn) Write(buffer []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	limited, err := c.limitBuffer(buffer)
	if err != nil {
		return 0, err
	}
	n, writeErr := c.Conn.Write(limited)
	c.sent += int64(n)
	return n, writeErr
}

func (c *countingConn) limitBuffer(buffer []byte) ([]byte, error) {
	if c.limit <= 0 {
		return buffer, nil
	}
	remaining := c.limit - c.sent - c.received
	if remaining <= 0 {
		return nil, ErrUsageLimit
	}
	if int64(len(buffer)) > remaining {
		return buffer[:remaining], nil
	}
	return buffer, nil
}

func (c *countingConn) BytesSent() int64 {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sent
}

func (c *countingConn) BytesReceived() int64 {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.received
}
