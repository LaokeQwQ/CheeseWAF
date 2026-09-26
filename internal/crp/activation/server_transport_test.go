package activation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/cluster/identity"
	"github.com/LaokeQwQ/CheeseWAF/internal/crp"
)

func TestControlPlaneServerTLSConfigRequiresVerifiedClientCertificate(t *testing.T) {
	pki := newMTLSPKIFixture(t)
	serverBundle, err := pki.service.IssueNodeCertificateBundle(identity.NodeIdentity{NodeID: "control-plane", Role: "monitor", ClusterID: "cluster-a", AdvertiseAddr: "127.0.0.1:443"})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.pem")
	certFile := filepath.Join(dir, "server.pem")
	keyFile := filepath.Join(dir, "server-key.pem")
	for path, file := range map[string]struct {
		data []byte
		mode os.FileMode
	}{
		caFile:   {data: serverBundle.CAPEM, mode: 0o600},
		certFile: {data: serverBundle.CertPEM, mode: 0o600},
		keyFile:  {data: serverBundle.KeyPEM, mode: 0o600},
	} {
		if err := os.WriteFile(path, file.data, file.mode); err != nil {
			t.Fatal(err)
		}
	}
	config, err := NewControlPlaneServerTLSConfig(ServerTLSOptions{CAFile: caFile, CertFile: certFile, KeyFile: keyFile})
	if err != nil {
		t.Fatal(err)
	}
	if config.MinVersion != tls.VersionTLS13 || config.ClientAuth != tls.RequireAndVerifyClientCert || config.InsecureSkipVerify {
		t.Fatalf("server TLS config=%+v, want TLS13 and required verified client certificate", config)
	}
	if config.ClientCAs == nil || len(config.Certificates) != 1 {
		t.Fatalf("server TLS config omitted CA or certificate: %+v", config)
	}

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &httptest.Server{Listener: listener, Config: &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) != 1 {
			t.Errorf("handler did not receive exactly one verified peer certificate: %+v", r.TLS)
		}
		w.WriteHeader(http.StatusNoContent)
	})}}
	server.TLS = config
	server.StartTLS()
	t.Cleanup(server.Close)

	clientCA, clientCert, clientKey := writeMTLSBundleFiles(t, pki.clientBundle, 0o600)
	client, err := NewMTLSClient(MTLSOptions{CAFile: clientCA, CertFile: clientCert, KeyFile: clientKey, ClusterID: "cluster-a", NodeID: "node-a", Role: "waf", ServerName: "control-plane", Timeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("mTLS server status=%d, want %d", response.StatusCode, http.StatusNoContent)
	}
}

func TestControlPlaneHandlerRequiresStrictMTLSJSONAndConsumesOnce(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	pki := newMTLSPKIFixture(t)
	leaf := pki.clientBundle.Certificate
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pki.clientBundle.CAPEM) {
		t.Fatal("failed to parse CA")
	}
	identity := certificateTransportIdentity(leaf, "cluster-a", "node-a", "waf")
	descriptor := SidecarDescriptor{PluginID: "rate-limit", Runtime: "sidecar", Version: "1.0.0", Namespace: "official/security", Source: "ota", SourceRoot: "root", ManifestIdentity: strings.Repeat("a", 64), ArtifactIdentity: strings.Repeat("b", 64)}
	digest, err := descriptorIdentity(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	request := AuthorizationRequest{SchemaVersion: TransportSchemaVersion, RequestID: "request-1", Identity: identity, Action: crp.RuntimeActionPromote, Permission: PermissionActivate, Target: RuntimeTarget{Key: "rate-limit", PluginID: "rate-limit", Namespace: descriptor.Namespace, Version: descriptor.Version, ReleaseSequence: 1, ManifestIdentity: descriptor.ManifestIdentity, ArtifactIdentity: descriptor.ArtifactIdentity, Revision: 1}, ExpectedRevision: 1, Descriptor: descriptor, DescriptorIdentity: digest, Canary: CanaryPolicy{ObserveProbes: 1, CanaryProbes: 1}, RequestedAt: now}
	request.ApprovalClaim = testApprovalClaim(request)
	expires := now.Add(time.Minute)
	authorizer := func(_ context.Context, got AuthorizationRequest, _ TransportIdentity) (Authorization, error) {
		return Authorization{SchemaVersion: TransportSchemaVersion, ID: "auth-1", Request: got, ApprovalClaim: got.ApprovalClaim, Fence: Fence{ClusterID: "cluster-a", Token: "fence-1", Epoch: 1, Revision: 1, ExpiresAt: expires}, Confirmation: &WireConfirmation{ID: got.ApprovalClaim.ConfirmationID, Actor: got.ApprovalClaim.Actor, Action: got.Action, PluginKey: got.Target.Key, ManifestIdentity: got.Target.ManifestIdentity, ExpectedRevision: got.ExpectedRevision, AuthorizedAt: now, ExpiresAt: expires}, IssuedAt: now, ExpiresAt: expires}, nil
	}
	consumed := 0
	h, err := NewControlPlaneHandler(ControlPlaneHandlerOptions{ClusterID: "cluster-a", Role: "waf", ClientCA: roots, Clock: func() time.Time { return now }, Authorize: authorizer, Validate: func(context.Context, TransportIdentity, Authorization) error { return nil }, Consume: func(context.Context, TransportIdentity, Authorization) error { consumed++; return nil }})
	if err != nil {
		t.Fatal(err)
	}

	call := func(path string, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CheeseWAF-Transport-Schema", TransportSchemaVersion)
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}, VerifiedChains: [][]*x509.Certificate{{leaf}}}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	unknown := call(controlAuthorizePath, `{"schema_version":"bad"}`)
	if unknown.Code != http.StatusBadRequest && unknown.Code != http.StatusUnauthorized && unknown.Code != http.StatusForbidden {
		t.Fatalf("unknown/invalid authorization status=%d body=%s", unknown.Code, unknown.Body.String())
	}

	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	authorized := call(controlAuthorizePath, string(raw))
	if authorized.Code != http.StatusOK {
		t.Fatalf("authorize status=%d body=%s", authorized.Code, authorized.Body.String())
	}
	var auth Authorization
	if err := json.Unmarshal(authorized.Body.Bytes(), &auth); err != nil {
		t.Fatal(err)
	}
	envelope, _ := json.Marshal(authorizationEnvelope{SchemaVersion: TransportSchemaVersion, Authorization: auth})
	valid := call(controlValidatePath, string(envelope))
	if valid.Code != http.StatusOK {
		t.Fatalf("validate status=%d body=%s", valid.Code, valid.Body.String())
	}
	consumedOnce := call(controlConsumePath, string(envelope))
	if consumedOnce.Code != http.StatusOK || consumed != 1 {
		t.Fatalf("first consume status=%d consumed=%d body=%s", consumedOnce.Code, consumed, consumedOnce.Body.String())
	}
	consumedTwice := call(controlConsumePath, string(envelope))
	if consumedTwice.Code == http.StatusOK || consumed != 1 {
		t.Fatalf("replayed consume status=%d consumed=%d body=%s", consumedTwice.Code, consumed, consumedTwice.Body.String())
	}

	tooLarge := call(controlAuthorizePath, `{"schema_version":"`+strings.Repeat("x", int(maxTransportBodyBytes))+`"}`)
	if tooLarge.Code == http.StatusOK {
		t.Fatal("oversized authorization body unexpectedly accepted")
	}
	_ = bytes.NewBuffer(nil)
}

func certificateTransportIdentity(cert *x509.Certificate, cluster, node, role string) TransportIdentity {
	digest := sha256.Sum256(cert.Raw)
	return TransportIdentity{ClusterID: cluster, NodeID: node, Role: role, CertificateSHA256: hex.EncodeToString(digest[:])}
}

func TestControlPlaneHandlerCoalescesSharedAuthorizationStateConsumption(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	pki := newMTLSPKIFixture(t)
	leaf := pki.clientBundle.Certificate
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pki.clientBundle.CAPEM) {
		t.Fatal("failed to parse CA")
	}
	identity := certificateTransportIdentity(leaf, "cluster-a", "node-a", "waf")
	descriptor := SidecarDescriptor{PluginID: "shared-state", Runtime: "sidecar", Version: "1.0.0", Namespace: "official/security", Source: "ota", SourceRoot: "root", ManifestIdentity: strings.Repeat("c", 64), ArtifactIdentity: strings.Repeat("d", 64)}
	descriptorDigest, err := descriptorIdentity(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	request := AuthorizationRequest{
		SchemaVersion: TransportSchemaVersion,
		RequestID:     "request-shared-state",
		Identity:      identity,
		Action:        crp.RuntimeActionPromote,
		Permission:    PermissionActivate,
		Target: RuntimeTarget{
			Key: "shared-state", PluginID: "shared-state", Namespace: "official/security", Version: "1.0.0",
			ReleaseSequence: 1, ManifestIdentity: strings.Repeat("c", 64), ArtifactIdentity: strings.Repeat("d", 64), Revision: 1,
		},
		ExpectedRevision:   1,
		Descriptor:         descriptor,
		DescriptorIdentity: descriptorDigest,
		Canary:             CanaryPolicy{ObserveProbes: 1, CanaryProbes: 1},
		RequestedAt:        now,
	}
	request.ApprovalClaim = testApprovalClaim(request)
	authorization := Authorization{
		SchemaVersion: TransportSchemaVersion,
		ID:            "auth-shared-state",
		Request:       request,
		ApprovalClaim: request.ApprovalClaim,
		Fence:         Fence{ClusterID: "cluster-a", Token: "fence-shared-state", Epoch: 1, Revision: 1, ExpiresAt: now.Add(time.Minute)},
		Confirmation: &WireConfirmation{
			ID: request.ApprovalClaim.ConfirmationID, Actor: request.ApprovalClaim.Actor, Action: request.Action,
			PluginKey: request.Target.Key, ManifestIdentity: request.Target.ManifestIdentity,
			ExpectedRevision: request.ExpectedRevision, AuthorizedAt: now, ExpiresAt: now.Add(time.Minute),
		},
		IssuedAt: now, ExpiresAt: now.Add(time.Minute),
	}
	memory, err := NewMemoryAuthorizationState(1, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	state := &countingAuthorizationState{delegate: memory}
	if err := state.Put(context.Background(), authorization); err != nil {
		t.Fatal(err)
	}
	provider := &sharedAuthorizationStateProvider{state: state, authorization: authorization}
	h, err := NewControlPlaneHandler(ControlPlaneHandlerOptions{
		ClusterID: "cluster-a", Role: "waf", ClientCA: roots, Clock: func() time.Time { return now },
		State: state, Provider: provider,
	})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(authorizationEnvelope{SchemaVersion: TransportSchemaVersion, Authorization: authorization})
	if err != nil {
		t.Fatal(err)
	}
	consume := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, controlConsumePath, bytes.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CheeseWAF-Transport-Schema", TransportSchemaVersion)
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}, VerifiedChains: [][]*x509.Certificate{{leaf}}}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	rec := consume()

	if rec.Code != http.StatusOK {
		t.Fatalf("shared-state consume status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	consumeCalls := state.consumeCallCount()
	providerCalls, afterCalls := provider.callCounts()
	if consumeCalls != 1 || providerCalls != 0 || afterCalls != 1 {
		t.Fatalf("shared-state calls: state=%d provider=%d after=%d, want 1/0/1", consumeCalls, providerCalls, afterCalls)
	}
	replayed := consume()
	if replayed.Code != http.StatusConflict {
		t.Fatalf("shared-state replay status=%d body=%s, want 409", replayed.Code, replayed.Body.String())
	}
	consumeCalls = state.consumeCallCount()
	providerCalls, afterCalls = provider.callCounts()
	if consumeCalls != 1 || providerCalls != 0 || afterCalls != 1 {
		t.Fatalf("shared-state replay changed calls: state=%d provider=%d after=%d, want 1/0/1", consumeCalls, providerCalls, afterCalls)
	}
}

func TestControlPlaneHandlerKeepsSeparateProviderConsumption(t *testing.T) {
	now := time.Now().UTC()
	authorization := Authorization{ID: "auth-separate-state", ExpiresAt: now.Add(time.Minute)}
	newState := func() *countingAuthorizationState {
		memory, err := NewMemoryAuthorizationState(1, func() time.Time { return now })
		if err != nil {
			t.Fatal(err)
		}
		state := &countingAuthorizationState{delegate: memory}
		if err := state.Put(context.Background(), authorization); err != nil {
			t.Fatal(err)
		}
		return state
	}
	handlerState := newState()
	providerState := newState()
	provider := &sharedAuthorizationStateProvider{state: providerState, authorization: authorization}
	h := &ControlPlaneHandler{state: handlerState, provider: provider, consume: provider.Consume}

	if err := handlerState.Consume(context.Background(), authorization); err != nil {
		t.Fatal(err)
	}
	if err := h.consumeAfterState(context.Background(), TransportIdentity{}, authorization); err != nil {
		t.Fatal(err)
	}

	providerCalls, afterCalls := provider.callCounts()
	if handlerState.consumeCallCount() != 1 || providerState.consumeCallCount() != 1 || providerCalls != 1 || afterCalls != 0 {
		t.Fatalf("separate-state calls: handler=%d provider-state=%d provider=%d after=%d, want 1/1/1/0", handlerState.consumeCallCount(), providerState.consumeCallCount(), providerCalls, afterCalls)
	}
}

func TestControlPlaneHandlerCoalescedConsumptionIsConcurrentOneShot(t *testing.T) {
	now := time.Now().UTC()
	authorization := Authorization{ID: "auth-concurrent-shared-state", ExpiresAt: now.Add(time.Minute)}
	memory, err := NewMemoryAuthorizationState(1, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	state := &countingAuthorizationState{delegate: memory}
	if err := state.Put(context.Background(), authorization); err != nil {
		t.Fatal(err)
	}
	provider := &sharedAuthorizationStateProvider{state: state, authorization: authorization}
	h := &ControlPlaneHandler{state: state, provider: provider, consume: provider.Consume}

	const callers = 16
	results := make(chan error, callers)
	var wg sync.WaitGroup
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := state.Consume(context.Background(), authorization); err != nil {
				results <- err
				return
			}
			results <- h.consumeAfterState(context.Background(), TransportIdentity{}, authorization)
		}()
	}
	wg.Wait()
	close(results)

	successes := 0
	replays := 0
	for err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrAuthorizationReplay):
			replays++
		default:
			t.Fatalf("concurrent consume error=%v, want success or replay", err)
		}
	}
	providerCalls, afterCalls := provider.callCounts()
	if successes != 1 || replays != callers-1 || providerCalls != 0 || afterCalls != 1 {
		t.Fatalf("concurrent results success=%d replay=%d provider=%d after=%d, want 1/%d/0/1", successes, replays, providerCalls, afterCalls, callers-1)
	}
}

type countingAuthorizationState struct {
	delegate *MemoryAuthorizationState
	mu       sync.Mutex
	consumes int
}

func (s *countingAuthorizationState) Put(ctx context.Context, authorization Authorization) error {
	return s.delegate.Put(ctx, authorization)
}

func (s *countingAuthorizationState) Get(ctx context.Context, id string) (Authorization, error) {
	return s.delegate.Get(ctx, id)
}

func (s *countingAuthorizationState) Consume(ctx context.Context, authorization Authorization) error {
	s.mu.Lock()
	s.consumes++
	s.mu.Unlock()
	return s.delegate.Consume(ctx, authorization)
}

func (s *countingAuthorizationState) consumeCallCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.consumes
}

type sharedAuthorizationStateProvider struct {
	state         *countingAuthorizationState
	authorization Authorization
	mu            sync.Mutex
	consumeCalls  int
	afterCalls    int
	afterErr      error
}

func (p *sharedAuthorizationStateProvider) Authorize(context.Context, TransportIdentity, AuthorizationRequest) (Authorization, error) {
	return p.authorization, nil
}

func (*sharedAuthorizationStateProvider) Validate(context.Context, TransportIdentity, Authorization) error {
	return nil
}

func (p *sharedAuthorizationStateProvider) Consume(ctx context.Context, _ TransportIdentity, authorization Authorization) error {
	p.mu.Lock()
	p.consumeCalls++
	p.mu.Unlock()
	return p.state.Consume(ctx, authorization)
}

func (p *sharedAuthorizationStateProvider) UsesAuthorizationState(state AuthorizationState) bool {
	return state == p.state
}

func (p *sharedAuthorizationStateProvider) ConsumeAfterState(context.Context, TransportIdentity, Authorization) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.afterCalls++
	return p.afterErr
}

func (p *sharedAuthorizationStateProvider) callCounts() (int, int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.consumeCalls, p.afterCalls
}
