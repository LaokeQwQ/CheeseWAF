package cli

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/cwedp"
	"github.com/LaokeQwQ/CheeseWAF/internal/cwedp/transport"
	"github.com/LaokeQwQ/CheeseWAF/internal/netlease"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
	"golang.org/x/crypto/bcrypt"
)

const productionTemporaryNetworkTestFingerprint = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestDefaultProductionFactoryOpensRequestScopedTemporaryNetworkProvider(t *testing.T) {
	factory := NewProductionDependencyFactory()
	if factory.OpenTemporaryNetwork == nil {
		t.Fatal("default production factory omitted the temporary network opener")
	}
}

type controlledTemporaryNetworkTransport struct {
	address string
	mu      sync.Mutex
	resolve int
	dial    int
}

func (t *controlledTemporaryNetworkTransport) Resolve(context.Context, string) ([]netip.Addr, error) {
	t.mu.Lock()
	t.resolve++
	t.mu.Unlock()
	return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
}

func (t *controlledTemporaryNetworkTransport) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	t.mu.Lock()
	t.dial++
	t.mu.Unlock()
	return (&net.Dialer{}).DialContext(ctx, network, address)
}

func (t *controlledTemporaryNetworkTransport) counts() (int, int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.resolve, t.dial
}

func TestProductionCWEDPAdapterFailsClosedBeforeDNSAfterManagementSessionRevocation(t *testing.T) {
	provider, store, user, session, _ := newProductionTemporaryNetworkProviderFixture(t)
	defer store.Close()
	defer provider.Close()
	endpoint, target, network, closeEndpoint := controlledCWEDPEndpoint(t, provider)
	defer closeEndpoint()
	request := productionCWEDPLeaseRequest(netlease.AdministratorIdentity{ID: user.ID, ManagementSessionID: session.ID})
	request.Target = target
	request.TLSFingerprint = endpoint.CertificateFingerprint
	adapter := requireProductionLeaseAdapter(t, provider, context.Background(), request)
	if err := store.RevokeSession(context.Background(), session.ID, user.ID); err != nil {
		t.Fatal(err)
	}
	_, err := adapter.Open(context.Background(), endpoint, cwedp.DistributionIntent{Size: 1}, cwedp.Hello{NodeID: "client", Protocol: cwedp.ProtocolVersion}, cwedp.Capabilities{NodeID: "client", ProtocolVersions: []string{cwedp.ProtocolVersion}, Sources: []cwedp.SourceKind{cwedp.SourcePeer}, MaxChunkSize: 1}, 0)
	if !errors.Is(err, netlease.ErrAdministratorSessionDenied) || !errors.Is(err, netlease.ErrBeforeDial) {
		t.Fatalf("Open() error=%v, want management-session pre-dial denial", err)
	}
	if resolves, dials := network.counts(); resolves != 0 || dials != 0 {
		t.Fatalf("revoked management session performed network I/O: resolves=%d dials=%d", resolves, dials)
	}
}

func TestProductionTemporaryHTTPExecutorPassesUseTimeSessionGate(t *testing.T) {
	provider, store, user, session, _ := newProductionTemporaryNetworkProviderFixture(t)
	defer store.Close()
	defer provider.Close()
	endpoint, target, network, closeEndpoint := controlledCWEDPEndpoint(t, provider)
	defer closeEndpoint()

	tlsConfig := endpoint.TLSConfig.Clone()
	tlsConfig.ServerName = endpoint.NodeID
	response, err := provider.ExecuteTemporaryHTTP(context.Background(), netlease.TemporaryHTTPExecution{
		Identity:         netlease.AdministratorIdentity{ID: user.ID, ManagementSessionID: session.ID},
		Password:         "correct horse battery staple",
		PluginID:         "temporary-http-plugin",
		PluginVersion:    "1.0.0",
		Target:           target,
		TLSFingerprint:   endpoint.CertificateFingerprint,
		PolicyEpoch:      provider.policyEpoch,
		TTL:              time.Minute,
		MaxBytes:         1 << 20,
		TLSPolicy:        &netlease.TLSPolicy{Config: tlsConfig},
		Method:           http.MethodGet,
		Path:             "/",
		MaxResponseBytes: 1024,
	})
	if err != nil {
		t.Fatalf("ExecuteTemporaryHTTP() error=%v", err)
	}
	if response.StatusCode != http.StatusOK || string(response.Body) != "x" {
		t.Fatalf("ExecuteTemporaryHTTP() response=%+v", response)
	}
	if resolves, dials := network.counts(); resolves != 1 || dials != 1 {
		t.Fatalf("ExecuteTemporaryHTTP() network counts resolves=%d dials=%d, want 1/1", resolves, dials)
	}
}

type blockingSessionLookupStore struct {
	storage.SessionLookupStore
	entered chan struct{}
	release chan struct{}
}

func (s *blockingSessionLookupStore) GetSession(ctx context.Context, id, userID string) (*storage.Session, error) {
	close(s.entered)
	<-s.release
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return s.SessionLookupStore.GetSession(ctx, id, userID)
}

func TestProductionTemporaryHTTPProviderCloseWaitsForInFlightRequest(t *testing.T) {
	provider, store, user, session, _ := newProductionTemporaryNetworkProviderFixture(t)
	defer store.Close()
	lookup := &blockingSessionLookupStore{
		SessionLookupStore: store,
		entered:            make(chan struct{}),
		release:            make(chan struct{}),
	}
	provider.management = lookup
	defer func() {
		select {
		case <-lookup.release:
		default:
			close(lookup.release)
		}
		_ = provider.Close()
	}()

	requestDone := make(chan error, 1)
	go func() {
		_, err := provider.ExecuteTemporaryHTTP(t.Context(), netlease.TemporaryHTTPExecution{
			Identity: netlease.AdministratorIdentity{ID: user.ID, ManagementSessionID: session.ID},
			TTL:      time.Minute,
		})
		requestDone <- err
	}()
	select {
	case <-lookup.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("temporary HTTP request did not reach the session lookup")
	}

	closeDone := make(chan error, 1)
	go func() { closeDone <- provider.Close() }()
	select {
	case <-provider.ctx.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("provider Close did not cancel the in-flight request")
	}
	select {
	case err := <-closeDone:
		t.Fatalf("provider Close returned before the in-flight request exited: %v", err)
	default:
	}
	close(lookup.release)
	if err := <-requestDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled temporary HTTP request error=%v, want context.Canceled", err)
	}
	if err := <-closeDone; err != nil {
		t.Fatalf("provider Close error=%v", err)
	}
	if _, err := provider.ExecuteTemporaryHTTP(t.Context(), netlease.TemporaryHTTPExecution{}); !errors.Is(err, ErrProductionTemporaryNetworkUnavailable) {
		t.Fatalf("request after Close error=%v, want production temporary network unavailable", err)
	}
}

func TestProductionCWEDPAdapterFailsClosedBeforeDNSAfterManagementSessionExpiry(t *testing.T) {
	provider, store, user, _, _ := newProductionTemporaryNetworkProviderFixture(t)
	defer store.Close()
	defer provider.Close()
	now := time.Now().UTC()
	short := storage.Session{ID: "short-management-session", UserID: user.ID, Username: user.Username, Role: user.Role, CredentialEpoch: user.CredentialEpoch, IssuedAt: now, ExpiresAt: now.Add(250 * time.Millisecond)}
	if err := store.CreateSession(context.Background(), &short); err != nil {
		t.Fatal(err)
	}
	endpoint, target, network, closeEndpoint := controlledCWEDPEndpoint(t, provider)
	defer closeEndpoint()
	request := productionCWEDPLeaseRequest(netlease.AdministratorIdentity{ID: user.ID, ManagementSessionID: short.ID})
	request.Target = target
	request.TLSFingerprint = endpoint.CertificateFingerprint
	request.TTL = time.Minute
	adapter := requireProductionLeaseAdapter(t, provider, context.Background(), request)
	lease, ok := provider.broker.Lease(adapter.LeaseID)
	if !ok || lease.ExpiresAt.After(short.ExpiresAt) {
		t.Fatalf("lease expiry=%s management expiry=%s", lease.ExpiresAt, short.ExpiresAt)
	}
	time.Sleep(time.Until(short.ExpiresAt) + 25*time.Millisecond)
	_, err := adapter.Open(context.Background(), endpoint, cwedp.DistributionIntent{Size: 1}, cwedp.Hello{NodeID: "client", Protocol: cwedp.ProtocolVersion}, cwedp.Capabilities{NodeID: "client", ProtocolVersions: []string{cwedp.ProtocolVersion}, Sources: []cwedp.SourceKind{cwedp.SourcePeer}, MaxChunkSize: 1}, 0)
	if (!errors.Is(err, netlease.ErrAdministratorSessionDenied) && !errors.Is(err, netlease.ErrConfirmationExpired) && !errors.Is(err, netlease.ErrLeaseExpired)) || !errors.Is(err, netlease.ErrBeforeDial) {
		t.Fatalf("Open() error=%v, want expired capability pre-dial denial", err)
	}
	if resolves, dials := network.counts(); resolves != 0 || dials != 0 {
		t.Fatalf("expired management session performed network I/O: resolves=%d dials=%d", resolves, dials)
	}
}

func TestProductionCWEDPAdapterProviderCloseRevokesCapabilitiesAndBlocksOpen(t *testing.T) {
	provider, store, user, session, _ := newProductionTemporaryNetworkProviderFixture(t)
	defer store.Close()
	endpoint, target, network, closeEndpoint := controlledCWEDPEndpoint(t, provider)
	defer closeEndpoint()
	request := productionCWEDPLeaseRequest(netlease.AdministratorIdentity{ID: user.ID, ManagementSessionID: session.ID})
	request.Target = target
	request.TLSFingerprint = endpoint.CertificateFingerprint
	adapter := requireProductionLeaseAdapter(t, provider, context.Background(), request)
	if err := provider.Close(); err != nil {
		t.Fatal(err)
	}
	lease, ok := provider.broker.Lease(adapter.LeaseID)
	if !ok || !lease.Revoked {
		t.Fatalf("Close() did not revoke lease: %+v", lease)
	}
	_, err := adapter.Open(context.Background(), endpoint, cwedp.DistributionIntent{Size: 1}, cwedp.Hello{NodeID: "client", Protocol: cwedp.ProtocolVersion}, cwedp.Capabilities{NodeID: "client", ProtocolVersions: []string{cwedp.ProtocolVersion}, Sources: []cwedp.SourceKind{cwedp.SourcePeer}, MaxChunkSize: 1}, 0)
	if !errors.Is(err, netlease.ErrLeaseRevoked) || !errors.Is(err, netlease.ErrBeforeDial) {
		t.Fatalf("Open() after Close error=%v, want revoked pre-dial denial", err)
	}
	if resolves, dials := network.counts(); resolves != 0 || dials != 0 {
		t.Fatalf("provider Close allowed network I/O: resolves=%d dials=%d", resolves, dials)
	}
}

func TestProductionCWEDPAdapterIssueCloseRaceLeavesNoActiveCapability(t *testing.T) {
	provider, store, user, session, _ := newProductionTemporaryNetworkProviderFixture(t)
	defer store.Close()
	request := productionCWEDPLeaseRequest(netlease.AdministratorIdentity{ID: user.ID, ManagementSessionID: session.ID})
	start := make(chan struct{})
	adapters := make(chan transport.LeaseBoundAdapter, 16)
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			adapter, err := provider.CWEDPAdapter(context.Background(), request)
			if err == nil {
				adapters <- adapter
			}
		}()
	}
	close(start)
	if err := provider.Close(); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	close(adapters)
	for adapter := range adapters {
		bound := adapter.(transport.HTTPAdapter)
		lease, ok := provider.broker.Lease(bound.LeaseID)
		if !ok || !lease.Revoked {
			t.Fatalf("Issue/Close race leaked lease: %+v", lease)
		}
		if err := adapter.Close(); err != nil {
			t.Fatal(err)
		}
	}
	provider.mu.Lock()
	active := len(provider.active)
	provider.mu.Unlock()
	if active != 0 {
		t.Fatalf("Issue/Close race left %d active capabilities", active)
	}
}

func controlledCWEDPEndpoint(t *testing.T, provider *productionTemporaryNetworkProvider) (transport.Endpoint, netlease.Target, *controlledTemporaryNetworkTransport, func()) {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "x") }))
	_, portText, err := net.SplitHostPort(strings.TrimPrefix(server.URL, "https://"))
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	certificate := server.Certificate()
	if certificate == nil || len(certificate.DNSNames) == 0 {
		server.Close()
		t.Fatal("test TLS server lacks DNS identity")
	}
	pool := x509.NewCertPool()
	pool.AddCert(certificate)
	config := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, Certificates: server.TLS.Certificates}
	network := &controlledTemporaryNetworkTransport{address: net.JoinHostPort("127.0.0.1", portText)}
	broker, err := netlease.NewBroker(netlease.BrokerConfig{Enabled: true, Policy: netlease.NewOfflinePolicyWithEpoch(nil, provider.policyEpoch), Sessions: provider.sessions, Transport: network, Addresses: netlease.AddressPolicyFunc(func(netlease.Target, netip.Addr) error { return nil }), Audit: netlease.NewMemoryAuditSinkForTesting(), PreDialGate: provider.preDialGate})
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	provider.broker = broker
	return transport.Endpoint{Source: cwedp.Source{Kind: cwedp.SourcePeer, ID: "peer-a"}, URL: "https://" + certificate.DNSNames[0] + ":" + portText + "/asset.crp", NodeID: certificate.DNSNames[0], CertificateFingerprint: transport.CertificateFingerprint(certificate), TLSConfig: config}, netlease.Target{Host: certificate.DNSNames[0], Port: port, Protocol: "https"}, network, server.Close
}

func TestProductionTemporaryNetworkProviderRejectsInvalidRequestSessionPasswordAndFence(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name    string
		prepare func(*storage.SQLiteStore, storage.User, storage.Session) netlease.AdministratorIdentity
		mutate  func(*ProductionCWEDPLeaseRequest)
		want    error
	}{
		{
			name: "absent management session",
			prepare: func(_ *storage.SQLiteStore, user storage.User, _ storage.Session) netlease.AdministratorIdentity {
				return netlease.AdministratorIdentity{ID: user.ID}
			},
			want: netlease.ErrAdministratorSessionDenied,
		},
		{
			name: "bad password",
			prepare: func(_ *storage.SQLiteStore, user storage.User, session storage.Session) netlease.AdministratorIdentity {
				return netlease.AdministratorIdentity{ID: user.ID, ManagementSessionID: session.ID}
			},
			mutate: func(req *ProductionCWEDPLeaseRequest) { req.Password = "incorrect" },
			want:   netlease.ErrAdministratorPasswordDenied,
		},
		{
			name: "expired management session",
			prepare: func(store *storage.SQLiteStore, user storage.User, session storage.Session) netlease.AdministratorIdentity {
				expired := session
				expired.ID = "expired-session"
				expired.ExpiresAt = time.Now().UTC().Add(-time.Minute)
				if err := store.CreateSession(ctx, &expired); err != nil {
					t.Fatal(err)
				}
				return netlease.AdministratorIdentity{ID: user.ID, ManagementSessionID: expired.ID}
			},
			want: netlease.ErrAdministratorSessionDenied,
		},
		{
			name: "revoked management session",
			prepare: func(store *storage.SQLiteStore, user storage.User, session storage.Session) netlease.AdministratorIdentity {
				if err := store.RevokeSession(ctx, session.ID, user.ID); err != nil {
					t.Fatal(err)
				}
				return netlease.AdministratorIdentity{ID: user.ID, ManagementSessionID: session.ID}
			},
			want: netlease.ErrAdministratorSessionDenied,
		},
		{
			name: "wrong policy fence",
			prepare: func(_ *storage.SQLiteStore, user storage.User, session storage.Session) netlease.AdministratorIdentity {
				return netlease.AdministratorIdentity{ID: user.ID, ManagementSessionID: session.ID}
			},
			mutate: func(req *ProductionCWEDPLeaseRequest) { req.PolicyEpoch++ },
			want:   netlease.ErrPolicyEpoch,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			provider, store, user, session, _ := newProductionTemporaryNetworkProviderFixture(t)
			defer store.Close()
			defer provider.Close()

			req := productionCWEDPLeaseRequest(tc.prepare(store, user, session))
			if tc.mutate != nil {
				tc.mutate(&req)
			}
			if _, err := provider.CWEDPAdapter(ctx, req); !errors.Is(err, tc.want) {
				t.Fatalf("CWEDPAdapter() error=%v, want %v", err, tc.want)
			}
		})
	}
}

func TestProductionTemporaryNetworkProviderMintsAndReleasesDistinctCWEDPLeases(t *testing.T) {
	ctx := context.Background()
	provider, store, user, session, dataDir := newProductionTemporaryNetworkProviderFixture(t)
	defer store.Close()
	defer provider.Close()

	request := productionCWEDPLeaseRequest(netlease.AdministratorIdentity{ID: user.ID, ManagementSessionID: session.ID})
	first := requireProductionLeaseAdapter(t, provider, ctx, request)
	firstLease, ok := provider.broker.Lease(first.LeaseID)
	if !ok || firstLease.Revoked {
		t.Fatalf("first lease was not active after adapter issuance: %+v", firstLease)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	firstLease, ok = provider.broker.Lease(first.LeaseID)
	if !ok || !firstLease.Revoked {
		t.Fatalf("first lease was not revoked by adapter Close: %+v", firstLease)
	}

	second := requireProductionLeaseAdapter(t, provider, ctx, request)
	if second.LeaseID == first.LeaseID {
		t.Fatalf("CWEDP adapters reused lease %q", second.LeaseID)
	}
	endpoint, closeEndpoint := productionLoopbackCWEDPEndpoint(t)
	defer closeEndpoint()
	if _, err := second.Open(ctx, endpoint, cwedp.DistributionIntent{Size: 1}, cwedp.Hello{}, cwedp.Capabilities{}, 0); !errors.Is(err, netlease.ErrAddressDenied) {
		t.Fatalf("CWEDP adapter Open() error=%v, want loopback address denial", err)
	}
	secondLease, ok := provider.broker.Lease(second.LeaseID)
	if !ok || !secondLease.Revoked {
		t.Fatalf("second lease was not revoked after adapter Open: %+v", secondLease)
	}

	auditPath := filepath.Join(dataDir, "audit", temporaryOnlineAuditFile)
	audit, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("read runtime temporary-network audit: %v", err)
	}
	for _, action := range []string{"\"Action\":\"issued\"", "\"Action\":\"revoked\""} {
		if !strings.Contains(string(audit), action) {
			t.Fatalf("runtime audit does not record %s: %s", action, audit)
		}
	}
}

func productionLoopbackCWEDPEndpoint(t *testing.T) (transport.Endpoint, func()) {
	t.Helper()
	server := httptest.NewTLSServer(nil)
	certificate, err := x509.ParseCertificate(server.TLS.Certificates[0].Certificate[0])
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(certificate)
	config := &tls.Config{
		Certificates: server.TLS.Certificates,
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS12,
	}
	return transport.Endpoint{
		Source:                 cwedp.Source{Kind: cwedp.SourcePeer, ID: "peer-a"},
		URL:                    "https://127.0.0.1/asset.crp",
		CertificateFingerprint: productionTemporaryNetworkTestFingerprint,
		NodeID:                 "node-a",
		TLSConfig:              config,
	}, server.Close
}

func newProductionTemporaryNetworkProviderFixture(t *testing.T) (*productionTemporaryNetworkProvider, *storage.SQLiteStore, storage.User, storage.Session, string) {
	t.Helper()
	ctx := context.Background()
	dataDir := t.TempDir()
	store, err := storage.OpenSQLite(filepath.Join(dataDir, "management.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(ctx); err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("correct horse battery staple"), bcrypt.MinCost)
	if err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	user := storage.User{ID: "admin-id", Username: "admin", PasswordHash: string(hash), Role: "admin"}
	if err := store.CreateUser(ctx, &user); err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	now := time.Now().UTC()
	session := storage.Session{ID: "management-session", UserID: user.ID, Username: user.Username, Role: user.Role, CredentialEpoch: user.CredentialEpoch, IssuedAt: now, ExpiresAt: now.Add(time.Hour)}
	if err := store.CreateSession(ctx, &session); err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	provider, err := newProductionTemporaryNetworkProvider(ctx, ProductionTemporaryNetworkOptions{ManagementStore: store, PolicyEpoch: 7, DataDir: dataDir})
	if err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	return provider, store, user, session, dataDir
}

func productionCWEDPLeaseRequest(identity netlease.AdministratorIdentity) ProductionCWEDPLeaseRequest {
	return ProductionCWEDPLeaseRequest{
		Identity:       identity,
		Password:       "correct horse battery staple",
		PluginID:       "cwedp-plugin",
		PluginVersion:  "1.0.0",
		Target:         netlease.Target{Host: "127.0.0.1", Port: 443, Protocol: "https"},
		TLSFingerprint: productionTemporaryNetworkTestFingerprint,
		PolicyEpoch:    7,
		TTL:            time.Minute,
		MaxBytes:       1024,
	}
}

func requireProductionLeaseAdapter(t *testing.T, provider *productionTemporaryNetworkProvider, ctx context.Context, req ProductionCWEDPLeaseRequest) transport.HTTPAdapter {
	t.Helper()
	adapter, err := provider.CWEDPAdapter(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	bound, ok := adapter.(transport.HTTPAdapter)
	if !ok {
		t.Fatalf("adapter type=%T, want transport.HTTPAdapter", adapter)
	}
	return bound
}
