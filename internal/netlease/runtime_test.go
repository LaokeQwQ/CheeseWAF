package netlease

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
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
)

type testAdministratorAuthenticator struct {
	mu              sync.Mutex
	sessionAllowed  bool
	passwordAllowed bool
	sessionCalls    int
	passwordCalls   int
}

func (a *testAdministratorAuthenticator) VerifySession(_ context.Context, identity AdministratorIdentity, _ time.Time) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.sessionCalls++
	if !a.sessionAllowed || identity.ID != "admin" {
		return errors.New("session denied")
	}
	return nil
}

func (a *testAdministratorAuthenticator) VerifyPassword(_ context.Context, identity AdministratorIdentity, password string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.passwordCalls++
	if !a.passwordAllowed || identity.ID != "admin" || password != "correct horse battery staple" {
		return errors.New("password denied")
	}
	return nil
}

type loopbackTransport struct {
	address  string
	mu       sync.Mutex
	dials    []string
	resolves int
}

func (t *loopbackTransport) Resolve(_ context.Context, _ string) ([]netip.Addr, error) {
	t.mu.Lock()
	t.resolves++
	t.mu.Unlock()
	return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
}

func (t *loopbackTransport) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	t.mu.Lock()
	t.dials = append(t.dials, address)
	t.mu.Unlock()
	if address != t.address {
		return nil, fmt.Errorf("unexpected direct address %q", address)
	}
	return (&net.Dialer{}).DialContext(ctx, network, address)
}

func (t *loopbackTransport) dialCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.dials)
}

func (t *loopbackTransport) resolveCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.resolves
}

func testCertificateFingerprint(t *testing.T, server *httptest.Server) string {
	t.Helper()
	if server == nil || server.TLS == nil || len(server.TLS.Certificates) != 1 || len(server.TLS.Certificates[0].Certificate) == 0 {
		t.Fatal("test TLS server has no leaf certificate")
	}
	cert, err := x509.ParseCertificate(server.TLS.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(cert.Raw)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func newTestBroker(t *testing.T, server *httptest.Server, fingerprint string, auth *testAdministratorAuthenticator) (*Broker, *MemoryAuditSink, *loopbackTransport, time.Time) {
	t.Helper()
	if auth == nil {
		auth = &testAdministratorAuthenticator{sessionAllowed: true, passwordAllowed: true}
	}
	now := time.Unix(1_700_000_000, 0).UTC()
	sessions, err := NewTemporarySessionManager(TemporarySessionManagerOptions{Now: func() time.Time { return now }, Authenticator: auth})
	if err != nil {
		t.Fatal(err)
	}
	_, portText, err := net.SplitHostPort(strings.TrimPrefix(server.URL, "https://"))
	if err != nil {
		t.Fatal(err)
	}
	transport := &loopbackTransport{address: net.JoinHostPort("127.0.0.1", portText)}
	sink := NewMemoryAuditSinkForTesting()
	broker, err := NewBroker(BrokerConfig{
		Enabled:              true,
		Policy:               NewOfflinePolicyWithEpoch(nil, 7),
		Sessions:             sessions,
		Transport:            transport,
		Addresses:            AddressPolicyFunc(func(Target, netip.Addr) error { return nil }),
		Audit:                sink,
		Now:                  func() time.Time { return now },
		MaxHTTPBodyBytes:     64 << 10,
		MaxHTTPResponseBytes: 64 << 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	return broker, sink, transport, now
}

func issueTestLease(t *testing.T, broker *Broker, port int, fingerprint string) (Lease, RequestScope) {
	t.Helper()
	session, err := broker.BeginTemporarySession(context.Background(), BeginTemporarySessionRequest{Identity: AdministratorIdentity{ID: "admin", ManagementSessionID: "management-session"}, TTL: time.Minute})
	if err != nil {
		t.Fatalf("begin temporary session: %v", err)
	}
	target := Target{Host: "updates.example.test", Port: port, Protocol: "https"}
	lease, err := broker.IssueTemporary(context.Background(), ConfirmationInput{
		SessionID:      session.ID,
		Password:       "correct horse battery staple",
		PluginID:       "plugin-a",
		PluginVersion:  "1.2.3",
		Target:         target,
		TLSFingerprint: fingerprint,
		PolicyEpoch:    7,
		TTL:            time.Minute,
		MaxBytes:       64 << 10,
	})
	if err != nil {
		t.Fatalf("issue temporary lease: %v", err)
	}
	return lease, RequestScope{PluginID: "plugin-a", PluginVersion: "1.2.3", Target: target, TLSFingerprint: fingerprint, PolicyEpoch: 7, OperatorID: "admin", TemporaryEgress: true}
}

func TestBrokerPerformsPinnedHTTPSOverDirectResolvedAddressAndAudits(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host == "" || r.URL.Path != "/release" || r.URL.RawQuery != "channel=stable" {
			t.Errorf("unexpected request host=%q path=%q query=%q", r.Host, r.URL.Path, r.URL.RawQuery)
		}
		if got := r.Header.Get("X-CWEDP-Test"); got != "yes" {
			t.Errorf("missing broker header: %q", got)
		}
		_, _ = w.Write([]byte("signed-artifact"))
	}))
	server.StartTLS()
	defer server.Close()

	fingerprint := testCertificateFingerprint(t, server)
	broker, sink, transport, now := newTestBroker(t, server, fingerprint, nil)
	_, portText, _ := net.SplitHostPort(strings.TrimPrefix(server.URL, "https://"))
	port, _ := strconv.Atoi(portText)
	lease, scope := issueTestLease(t, broker, port, fingerprint)

	response, err := broker.DoHTTP(context.Background(), HTTPRequest{LeaseID: lease.ID, Scope: scope, Method: http.MethodGet, Path: "/release?channel=stable", Header: http.Header{"X-CWEDP-Test": []string{"yes"}}})
	if err != nil {
		t.Fatalf("DoHTTP: %v", err)
	}
	if response.StatusCode != http.StatusOK || string(response.Body) != "signed-artifact" || response.RemoteAddress != transport.address {
		t.Fatalf("unexpected response: %+v", response)
	}
	if response.BytesSent <= 0 || response.BytesReceived <= 0 {
		t.Fatalf("response did not report wire bytes: %+v", response)
	}
	if transport.dialCount() != 1 {
		t.Fatalf("dials=%d, want exactly one direct socket", transport.dialCount())
	}
	if _, err := broker.DoHTTP(context.Background(), HTTPRequest{LeaseID: lease.ID, Scope: scope, Method: http.MethodGet, Path: "/release"}); !errors.Is(err, ErrLeaseConsumed) {
		t.Fatalf("consumed lease was reused: %v", err)
	}
	if transport.dialCount() != 1 {
		t.Fatalf("reused lease opened another socket: %d", transport.dialCount())
	}
	var result AuditEvent
	for _, event := range sink.Events() {
		if event.Action == "result" {
			result = event
		}
	}
	if result.Action != "result" || result.TargetHost != scope.Target.Host || result.TargetPort != scope.Target.Port || result.TLSFingerprint != fingerprint || result.PolicyEpoch != scope.PolicyEpoch || result.OperatorID != scope.OperatorID || result.ConfirmationID != lease.ConfirmationID || result.Requests != 1 || result.Bytes <= 0 || result.Bytes != result.BytesSent+result.BytesReceived || result.Result != "http_200" || !result.At.Equal(now) {
		t.Fatalf("missing connection audit fields: %+v", result)
	}
}

func TestExecuteTemporaryHTTPOwnsConfirmationNetworkAndCleanupLifecycle(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host == "" || r.URL.Path != "/probe" {
			t.Errorf("unexpected request host=%q path=%q", r.Host, r.URL.Path)
		}
		_, _ = w.Write([]byte("ok"))
	}))
	server.StartTLS()
	defer server.Close()

	fingerprint := testCertificateFingerprint(t, server)
	broker, sink, transport, _ := newTestBroker(t, server, fingerprint, nil)
	_, portText, err := net.SplitHostPort(strings.TrimPrefix(server.URL, "https://"))
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	target := Target{Host: "updates.example.test", Port: port, Protocol: "https"}

	response, err := broker.ExecuteTemporaryHTTP(context.Background(), TemporaryHTTPExecution{
		Identity:         AdministratorIdentity{ID: "admin", ManagementSessionID: "management-session"},
		Password:         "correct horse battery staple",
		PluginID:         "plugin-a",
		PluginVersion:    "1.2.3",
		Target:           target,
		TLSFingerprint:   fingerprint,
		PolicyEpoch:      7,
		TTL:              time.Minute,
		MaxBytes:         64 << 10,
		Method:           http.MethodGet,
		Path:             "/probe",
		MaxResponseBytes: 1024,
	})
	if err != nil {
		t.Fatalf("ExecuteTemporaryHTTP: %v", err)
	}
	if response.StatusCode != http.StatusOK || string(response.Body) != "ok" || transport.dialCount() != 1 {
		t.Fatalf("unexpected response=%+v dials=%d", response, transport.dialCount())
	}

	var leaseID string
	var actions []string
	for _, event := range sink.Events() {
		actions = append(actions, event.Action)
		if event.Action == "issued" {
			leaseID = event.LeaseID
		}
	}
	if got, want := strings.Join(actions, ","), "issued,connection_started,result,revoked"; got != want {
		t.Fatalf("audit actions=%q, want %q", got, want)
	}
	if leaseID == "" {
		t.Fatal("missing issued lease ID")
	}
	lease, ok := broker.Lease(leaseID)
	if !ok || !lease.Revoked || !lease.Completed || lease.Requests != 1 {
		t.Fatalf("lease cleanup/accounting=%+v found=%v", lease, ok)
	}
	broker.sessions.mu.Lock()
	var sessions []TemporarySession
	for _, session := range broker.sessions.sessions {
		sessions = append(sessions, session)
	}
	broker.sessions.mu.Unlock()
	if len(sessions) != 1 || !sessions[0].Revoked {
		t.Fatalf("temporary session cleanup=%+v", sessions)
	}
}

func TestBrokerRevokePersistsOnceAndRetriesDurableAuditAfterFailure(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }))
	defer server.Close()
	fingerprint := testCertificateFingerprint(t, server)
	broker, sink, _, now := newTestBroker(t, server, fingerprint, nil)
	_, portText, err := net.SplitHostPort(strings.TrimPrefix(server.URL, "https://"))
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	lease, _ := issueTestLease(t, broker, port, fingerprint)
	sink.SetErrorForTesting(errors.New("audit unavailable"))
	if err := broker.Revoke(lease.ID); !errors.Is(err, ErrAuditUnavailable) {
		t.Fatalf("first revoke error=%v, want durable audit failure", err)
	}
	stored, ok := broker.Lease(lease.ID)
	if !ok || !stored.Revoked {
		t.Fatalf("lease was not revoked before audit retry: %+v found=%v", stored, ok)
	}
	sink.SetErrorForTesting(nil)
	if err := broker.Revoke(lease.ID); err != nil {
		t.Fatalf("revoke audit retry: %v", err)
	}
	if err := broker.Revoke(lease.ID); err != nil {
		t.Fatalf("idempotent revoke: %v", err)
	}
	var revoked []AuditEvent
	for _, event := range sink.Events() {
		if event.Action == "revoked" {
			revoked = append(revoked, event)
		}
	}
	if len(revoked) != 1 || !revoked[0].At.Equal(now) || revoked[0].LeaseID != lease.ID {
		t.Fatalf("revocation audit events=%+v, want one durable event at %v", revoked, now)
	}
}

func TestPublicAddressPolicyRejectsSpecialUseRanges(t *testing.T) {
	policy := PublicAddressPolicy{}
	target := Target{Host: "updates.example.test", Port: 443, Protocol: "https"}
	for _, raw := range []string{
		"0.1.2.3",
		"10.0.0.1",
		"100.64.0.1",
		"127.0.0.1",
		"192.0.2.1",
		"198.18.0.1",
		"203.0.113.1",
		"240.0.0.1",
		"::1",
		"2001:db8::1",
		"fc00::1",
	} {
		if err := policy.Allow(target, netip.MustParseAddr(raw)); !errors.Is(err, ErrAddressDenied) {
			t.Fatalf("special-use address %s was accepted: %v", raw, err)
		}
	}
	for _, raw := range []string{"8.8.8.8", "2606:4700:4700::1111"} {
		if err := policy.Allow(target, netip.MustParseAddr(raw)); err != nil {
			t.Fatalf("public address %s was rejected: %v", raw, err)
		}
	}
}

func TestNewBrokerProductionRequiresStandardTransport(t *testing.T) {
	authenticator := &testAdministratorAuthenticator{sessionAllowed: true, passwordAllowed: true}
	sessions, err := NewTemporarySessionManager(TemporarySessionManagerOptions{Authenticator: authenticator})
	if err != nil {
		t.Fatal(err)
	}
	audit, err := NewFileAuditSink(filepath.Join(t.TempDir(), "audit", "netlease.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	config := BrokerConfig{
		Enabled:    true,
		Production: true,
		Policy:     NewOfflinePolicyWithEpoch(nil, 1),
		Sessions:   sessions,
		Addresses:  PublicAddressPolicy{},
		Audit:      audit,
	}
	config.Transport = &loopbackTransport{}
	if _, err := NewBroker(config); !errors.Is(err, ErrTransportUnavailable) {
		t.Fatalf("production broker accepted injected transport: %v", err)
	}
	config.Transport = NewStandardTransport()
	if _, err := NewBroker(config); err != nil {
		t.Fatalf("production broker rejected standard transport: %v", err)
	}
}

func TestBrokerOperationContextHonorsBrokerTimeoutBeforeCallerDeadline(t *testing.T) {
	broker := &Broker{timeout: time.Minute}
	start := time.Now()
	caller, callerCancel := context.WithDeadline(context.Background(), start.Add(time.Hour))
	defer callerCancel()
	operation, operationCancel := broker.operationContext(caller)
	defer operationCancel()
	deadline, ok := operation.Deadline()
	if !ok || deadline.After(start.Add(2*time.Minute)) {
		t.Fatalf("operation deadline=%v, want broker timeout before caller deadline", deadline)
	}
}

func TestLeaseBoundContextHonorsLeaseExpiryBeforeCallerDeadline(t *testing.T) {
	start := time.Now()
	caller, callerCancel := context.WithDeadline(context.Background(), start.Add(time.Hour))
	defer callerCancel()
	broker := &Broker{now: func() time.Time { return start }}
	operation, operationCancel := broker.leaseBoundContext(caller, Lease{ExpiresAt: start.Add(time.Minute)})
	defer operationCancel()
	deadline, ok := operation.Deadline()
	if !ok || deadline.After(start.Add(2*time.Minute)) {
		t.Fatalf("operation deadline=%v, want lease expiry before caller deadline", deadline)
	}
}

func TestBrokerFailsClosedForPasswordPinScopeAndAuditFailures(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }))
	defer server.Close()
	fingerprint := testCertificateFingerprint(t, server)
	_, portText, _ := net.SplitHostPort(strings.TrimPrefix(server.URL, "https://"))
	port, _ := strconv.Atoi(portText)

	t.Run("password", func(t *testing.T) {
		auth := &testAdministratorAuthenticator{sessionAllowed: true, passwordAllowed: false}
		broker, _, transport, _ := newTestBroker(t, server, fingerprint, auth)
		session, err := broker.BeginTemporarySession(context.Background(), BeginTemporarySessionRequest{Identity: AdministratorIdentity{ID: "admin"}, TTL: time.Minute})
		if err != nil {
			t.Fatal(err)
		}
		_, err = broker.IssueTemporary(context.Background(), ConfirmationInput{SessionID: session.ID, Password: "correct horse battery staple", PluginID: "plugin-a", PluginVersion: "1", Target: Target{Host: "updates.example.test", Port: port, Protocol: "https"}, TLSFingerprint: fingerprint, PolicyEpoch: 7, TTL: time.Minute})
		if !errors.Is(err, ErrAdministratorPasswordDenied) || transport.dialCount() != 0 {
			t.Fatalf("password confirmation bypass: err=%v dials=%d", err, transport.dialCount())
		}
	})

	t.Run("pin", func(t *testing.T) {
		broker, sink, transport, _ := newTestBroker(t, server, fingerprint, nil)
		wrong := "sha256:" + strings.Repeat("b", 64)
		lease, scope := issueTestLease(t, broker, port, wrong)
		_, err := broker.DoHTTP(context.Background(), HTTPRequest{LeaseID: lease.ID, Scope: scope, Method: http.MethodGet, Path: "/"})
		if !errors.Is(err, ErrTLSFingerprint) || transport.dialCount() != 1 {
			t.Fatalf("pin mismatch was not enforced: err=%v dials=%d", err, transport.dialCount())
		}
		found := false
		for _, event := range sink.Events() {
			found = found || (event.Action == "result" && event.Result == "tls_fingerprint_mismatch")
		}
		if !found {
			t.Fatalf("pin failure was not audited: %+v", sink.Events())
		}
	})

	t.Run("scope", func(t *testing.T) {
		broker, _, transport, _ := newTestBroker(t, server, fingerprint, nil)
		lease, scope := issueTestLease(t, broker, port, fingerprint)
		scope.Target.Host = "substituted.example.test"
		_, err := broker.DoHTTP(context.Background(), HTTPRequest{LeaseID: lease.ID, Scope: scope, Method: http.MethodGet, Path: "/"})
		if !errors.Is(err, ErrLeaseScope) || !errors.Is(err, ErrBeforeDial) || transport.dialCount() != 0 {
			t.Fatalf("scope substitution reached transport: err=%v dials=%d", err, transport.dialCount())
		}
	})

	t.Run("address policy", func(t *testing.T) {
		broker, _, transport, _ := newTestBroker(t, server, fingerprint, nil)
		broker.addresses = AddressPolicyFunc(func(Target, netip.Addr) error { return ErrAddressDenied })
		lease, scope := issueTestLease(t, broker, port, fingerprint)
		_, err := broker.DoHTTP(context.Background(), HTTPRequest{LeaseID: lease.ID, Scope: scope, Method: http.MethodGet, Path: "/"})
		if !errors.Is(err, ErrAddressDenied) || !errors.Is(err, ErrBeforeDial) || transport.dialCount() != 0 {
			t.Fatalf("address policy rejection reached dial: err=%v dials=%d", err, transport.dialCount())
		}
	})

	t.Run("audit", func(t *testing.T) {
		broker, sink, transport, _ := newTestBroker(t, server, fingerprint, nil)
		sink.SetErrorForTesting(errors.New("disk unavailable"))
		session, err := broker.BeginTemporarySession(context.Background(), BeginTemporarySessionRequest{Identity: AdministratorIdentity{ID: "admin"}, TTL: time.Minute})
		if err != nil {
			t.Fatal(err)
		}
		_, err = broker.IssueTemporary(context.Background(), ConfirmationInput{SessionID: session.ID, Password: "correct horse battery staple", PluginID: "plugin-a", PluginVersion: "1", Target: Target{Host: "updates.example.test", Port: port, Protocol: "https"}, TLSFingerprint: fingerprint, PolicyEpoch: 7, TTL: time.Minute})
		if !errors.Is(err, ErrAuditUnavailable) || transport.dialCount() != 0 {
			t.Fatalf("unavailable audit did not fail closed: err=%v dials=%d", err, transport.dialCount())
		}
	})
}

func TestBrokerClassifiesAuthorizationAndTLSPolicyRejectionsBeforeDial(t *testing.T) {
	tests := []struct {
		name     string
		expected error
		mutate   func(*Broker, Lease, *RequestScope, *TLSPolicy, *time.Time)
	}{
		{
			name:     "expired lease",
			expected: ErrLeaseExpired,
			mutate: func(broker *Broker, lease Lease, _ *RequestScope, _ *TLSPolicy, now *time.Time) {
				broker.leases.mu.Lock()
				stored := broker.leases.leases[lease.ID]
				stored.ConfirmationExpiresAt = time.Time{}
				broker.leases.leases[lease.ID] = stored
				broker.leases.mu.Unlock()
				*now = now.Add(2 * time.Minute)
			},
		},
		{
			name:     "revoked lease",
			expected: ErrLeaseRevoked,
			mutate: func(broker *Broker, lease Lease, _ *RequestScope, _ *TLSPolicy, _ *time.Time) {
				if err := broker.Revoke(lease.ID); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name:     "scope mismatch",
			expected: ErrLeaseScope,
			mutate: func(_ *Broker, _ Lease, scope *RequestScope, _ *TLSPolicy, _ *time.Time) {
				scope.PluginVersion = "substituted"
			},
		},
		{
			name:     "policy epoch mismatch",
			expected: ErrPolicyEpoch,
			mutate: func(broker *Broker, _ Lease, _ *RequestScope, _ *TLSPolicy, _ *time.Time) {
				if err := broker.UpdatePolicy(NewOfflinePolicyWithEpoch(nil, 8)); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name:     "confirmation expired",
			expected: ErrConfirmationExpired,
			mutate: func(_ *Broker, _ Lease, _ *RequestScope, _ *TLSPolicy, now *time.Time) {
				*now = now.Add(2 * time.Minute)
			},
		},
		{
			name:     "lease consumed",
			expected: ErrLeaseConsumed,
			mutate: func(broker *Broker, lease Lease, scope *RequestScope, _ *TLSPolicy, _ *time.Time) {
				if err := broker.leases.Consume(lease, *scope); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name:     "weak TLS policy",
			expected: ErrTLSPolicy,
			mutate: func(_ *Broker, _ Lease, _ *RequestScope, policy *TLSPolicy, _ *time.Time) {
				policy.Config = &tls.Config{InsecureSkipVerify: true} // #nosec G402 -- rejection fixture.
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			now := time.Unix(1_700_001_000, 0).UTC()
			auth := &testAdministratorAuthenticator{sessionAllowed: true, passwordAllowed: true}
			sessions, err := NewTemporarySessionManager(TemporarySessionManagerOptions{Now: func() time.Time { return now }, Authenticator: auth})
			if err != nil {
				t.Fatal(err)
			}
			transport := &loopbackTransport{}
			broker, err := NewBroker(BrokerConfig{
				Enabled:              true,
				Policy:               NewOfflinePolicyWithEpoch(nil, 7),
				Sessions:             sessions,
				Transport:            transport,
				Addresses:            AddressPolicyFunc(func(Target, netip.Addr) error { return nil }),
				Audit:                NewMemoryAuditSinkForTesting(),
				Now:                  func() time.Time { return now },
				MaxHTTPResponseBytes: 1024,
			})
			if err != nil {
				t.Fatal(err)
			}
			session, err := broker.BeginTemporarySession(context.Background(), BeginTemporarySessionRequest{Identity: AdministratorIdentity{ID: "admin"}, TTL: time.Minute})
			if err != nil {
				t.Fatal(err)
			}
			target := Target{Host: "updates.example.test", Port: 443, Protocol: "https"}
			lease, err := broker.IssueTemporary(context.Background(), ConfirmationInput{SessionID: session.ID, Password: "correct horse battery staple", PluginID: "plugin", PluginVersion: "1", Target: target, TLSFingerprint: testTLSFingerprint, PolicyEpoch: 7, TTL: time.Minute})
			if err != nil {
				t.Fatal(err)
			}
			scope := RequestScope{PluginID: "plugin", PluginVersion: "1", Target: target, TLSFingerprint: testTLSFingerprint, PolicyEpoch: 7, OperatorID: "admin", TemporaryEgress: true}
			policy := TLSPolicy{}
			test.mutate(broker, lease, &scope, &policy, &now)
			_, err = broker.DoHTTP(context.Background(), HTTPRequest{LeaseID: lease.ID, Scope: scope, TLSPolicy: &policy, Method: http.MethodGet, Path: "/"})
			if !errors.Is(err, test.expected) || !errors.Is(err, ErrBeforeDial) {
				t.Fatalf("err=%v, want %v and %v", err, test.expected, ErrBeforeDial)
			}
			if transport.resolveCount() != 0 || transport.dialCount() != 0 {
				t.Fatalf("pre-dial rejection performed I/O: resolves=%d dials=%d", transport.resolveCount(), transport.dialCount())
			}
		})
	}
}

func TestTLSPolicySnapshotIsIndependentFromCallerMutation(t *testing.T) {
	certificateBytes := []byte{1, 2, 3}
	policy := &TLSPolicy{Config: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{certificateBytes}}}}}
	scope := RequestScope{Target: Target{Host: "updates.example.test", Port: 443, Protocol: "https"}}
	snapshot, err := snapshotTLSPolicy(scope, policy)
	if err != nil {
		t.Fatal(err)
	}
	policy.Config.InsecureSkipVerify = true
	policy.Config.Certificates[0].Certificate[0][0] = 9
	if snapshot == nil || snapshot.Config == nil || snapshot.Config.InsecureSkipVerify || snapshot.Config.Certificates[0].Certificate[0][0] != 1 {
		t.Fatalf("TLS policy snapshot followed caller mutation: %+v", snapshot)
	}
}

func TestTemporaryConfirmationIsBoundOneTimeAndSessionRevocationWins(t *testing.T) {
	now := time.Unix(1_700_000_100, 0).UTC()
	auth := &testAdministratorAuthenticator{sessionAllowed: true, passwordAllowed: true}
	manager, err := NewTemporarySessionManager(TemporarySessionManagerOptions{Now: func() time.Time { return now }, Authenticator: auth})
	if err != nil {
		t.Fatal(err)
	}
	session, err := manager.Begin(context.Background(), BeginTemporarySessionRequest{Identity: AdministratorIdentity{ID: "admin", ManagementSessionID: "session"}, TTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	target := Target{Host: "updates.example.test", Port: 443, Protocol: "https"}
	confirmation, err := manager.Confirm(context.Background(), ConfirmationInput{SessionID: session.ID, Password: "correct horse battery staple", PluginID: "plugin-a", PluginVersion: "1", Target: target, TLSFingerprint: testTLSFingerprint, PolicyEpoch: 7, TTL: time.Minute, MaxBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	req := ConfirmationRequest{ID: confirmation.ID, OperatorID: "admin", PluginID: "plugin-a", PluginVersion: "1", Target: target, TLSFingerprint: testTLSFingerprint, PolicyEpoch: 7, TTL: time.Minute, ConfirmationExpiresAt: confirmation.ExpiresAt, TemporaryEgress: true, MaxBytes: 1024}
	if err := manager.ConsumeConfirmation(context.Background(), req); err != nil {
		t.Fatalf("consume confirmation: %v", err)
	}
	if err := manager.ConsumeConfirmation(context.Background(), req); !errors.Is(err, ErrConfirmationReplay) {
		t.Fatalf("confirmation replay accepted: %v", err)
	}

	confirmation, err = manager.Confirm(context.Background(), ConfirmationInput{SessionID: session.ID, Password: "correct horse battery staple", PluginID: "plugin-a", PluginVersion: "1", Target: target, TLSFingerprint: testTLSFingerprint, PolicyEpoch: 7, TTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	req.ID = confirmation.ID
	req.MaxBytes = 0
	req.Target.Port = 8443
	if err := manager.ConsumeConfirmation(context.Background(), req); !errors.Is(err, ErrConfirmationScope) {
		t.Fatalf("scope substitution was accepted: %v", err)
	}
	if err := manager.Revoke(session.ID); err != nil {
		t.Fatal(err)
	}
	req.Target = target
	if err := manager.ConsumeConfirmation(context.Background(), req); !errors.Is(err, ErrTemporarySessionRevoked) {
		t.Fatalf("revoked temporary session issued capability: %v", err)
	}
}

func TestRecordTransferFinalSurvivesExpiryAfterConsumeAndPolicyUpdateWaits(t *testing.T) {
	now := time.Unix(1_700_000_200, 0).UTC()
	target := Target{Host: "control.internal", Port: 8443, Protocol: "https"}
	manager := NewSecureManager(NewOfflinePolicyWithEpoch([]Resource{target}, 1), func() time.Time { return now }, func(ConfirmationRequest) error { return nil })
	lease, err := manager.Issue(IssueRequest{PluginID: "plugin", PluginVersion: "1", Target: target, TLSFingerprint: testTLSFingerprint, PolicyEpoch: 1, ConfirmationID: "confirm", OperatorID: "admin", TTL: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	scope := RequestScope{PluginID: "plugin", PluginVersion: "1", Target: target, TLSFingerprint: testTLSFingerprint, PolicyEpoch: 1, OperatorID: "admin"}
	consumed, release, err := manager.AcquireUse(lease.ID, scope)
	if err != nil {
		t.Fatal(err)
	}
	updateDone := make(chan error, 1)
	go func() { updateDone <- manager.UpdatePolicy(NewOfflinePolicyWithEpoch([]Resource{target}, 2)) }()
	select {
	case err := <-updateDone:
		t.Fatalf("policy update crossed an active use: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	now = now.Add(2 * time.Second)
	if err := manager.RecordTransferFinal(consumed, scope, Usage{BytesSent: 10, BytesReceived: 20, Result: "timeout"}); err != nil {
		t.Fatalf("final audit after expiry: %v", err)
	}
	release()
	if err := <-updateDone; err != nil {
		t.Fatalf("policy update after release: %v", err)
	}
}

func TestFileAuditSinkPersistsMetadataOnlyWithOwnerOnlyMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit", "netlease.jsonl")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	sink, err := NewFileAuditSink(path)
	if err != nil {
		t.Fatal(err)
	}
	event := AuditEvent{LeaseID: "lease-a", Action: "result", PluginID: "plugin-a", PluginVersion: "1", TargetHost: "updates.example.test", TargetPort: 443, TargetProtocol: "https", TLSFingerprint: testTLSFingerprint, PolicyEpoch: 7, TemporaryEgress: true, ConfirmationID: "confirmation-a", OperatorID: "admin", Bytes: 42, BytesSent: 12, BytesReceived: 30, Requests: 1, Result: "success", Reason: "success", At: time.Now().UTC()}
	if err := sink.Append(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "payload") || !strings.Contains(string(data), "updates.example.test") || !strings.Contains(string(data), "BytesSent") {
		t.Fatalf("unexpected audit content: %s", data)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("audit permissions=%#o, want 0600", info.Mode().Perm())
	}
	dirInfo, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if dirInfo.Mode().Perm() != 0o700 {
		t.Fatalf("audit directory permissions=%#o, want 0700", dirInfo.Mode().Perm())
	}
}
