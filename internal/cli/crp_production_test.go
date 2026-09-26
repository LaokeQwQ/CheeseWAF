package cli

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
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/cluster/identity"
	"github.com/LaokeQwQ/CheeseWAF/internal/crp"
	"github.com/LaokeQwQ/CheeseWAF/internal/crp/activation"
)

type productionCRPTestState struct {
	mu      sync.Mutex
	pending map[string]activation.Authorization
	used    map[string]struct{}
}

func newProductionCRPTestState() *productionCRPTestState {
	return &productionCRPTestState{pending: make(map[string]activation.Authorization), used: make(map[string]struct{})}
}

func (s *productionCRPTestState) Durable() bool { return s != nil }

func (s *productionCRPTestState) Put(_ context.Context, authorization activation.Authorization) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, used := s.used[authorization.ID]; used {
		return activation.ErrAuthorizationReplay
	}
	s.pending[authorization.ID] = authorization
	return nil
}

func (s *productionCRPTestState) Get(_ context.Context, id string) (activation.Authorization, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, used := s.used[id]; used {
		return activation.Authorization{}, activation.ErrAuthorizationReplay
	}
	authorization, ok := s.pending[id]
	if !ok {
		return activation.Authorization{}, activation.ErrAuthorizationNotFound
	}
	return authorization, nil
}

func (s *productionCRPTestState) Consume(_ context.Context, authorization activation.Authorization) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, used := s.used[authorization.ID]; used {
		return activation.ErrAuthorizationReplay
	}
	if _, ok := s.pending[authorization.ID]; !ok {
		return activation.ErrAuthorizationNotFound
	}
	delete(s.pending, authorization.ID)
	s.used[authorization.ID] = struct{}{}
	return nil
}

type productionCRPTestProvider struct {
	now      time.Time
	mu       sync.Mutex
	consumed int
}

func (p *productionCRPTestProvider) Durable() bool        { return p != nil }
func (p *productionCRPTestProvider) LiveFenceBound() bool { return p != nil }

func (p *productionCRPTestProvider) Authorize(_ context.Context, _ activation.TransportIdentity, request activation.AuthorizationRequest) (activation.Authorization, error) {
	expires := p.now.Add(time.Minute)
	return activation.Authorization{
		SchemaVersion: activation.TransportSchemaVersion,
		ID:            "authorization-1",
		Request:       request,
		ApprovalClaim: request.ApprovalClaim,
		Fence: activation.Fence{
			ClusterID: request.Identity.ClusterID, Token: "fence-token-1", Epoch: 1,
			Revision: request.ExpectedRevision, ExpiresAt: expires,
		},
		Confirmation: &activation.WireConfirmation{
			ID: request.ApprovalClaim.ConfirmationID, Actor: request.ApprovalClaim.Actor,
			Action: request.Action, PluginKey: request.Target.Key,
			ManifestIdentity: request.Target.ManifestIdentity, ExpectedRevision: request.ExpectedRevision,
			AuthorizedAt: p.now, ExpiresAt: expires,
		},
		IssuedAt: p.now, ExpiresAt: expires,
	}, nil
}

func (*productionCRPTestProvider) Validate(context.Context, activation.TransportIdentity, activation.Authorization) error {
	return nil
}

func (p *productionCRPTestProvider) Consume(context.Context, activation.TransportIdentity, activation.Authorization) error {
	p.mu.Lock()
	p.consumed++
	p.mu.Unlock()
	return nil
}

type productionCRPTestAudit struct {
	mu     sync.Mutex
	events map[string]activation.AuthorizationAuditEvent
}

func (a *productionCRPTestAudit) Durable() bool    { return a != nil }
func (a *productionCRPTestAudit) Idempotent() bool { return a != nil }

func (a *productionCRPTestAudit) Append(_ context.Context, event activation.AuthorizationAuditEvent) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if prior, ok := a.events[event.EventID]; ok {
		priorJSON, _ := json.Marshal(prior)
		eventJSON, _ := json.Marshal(event)
		if string(priorJSON) != string(eventJSON) {
			return errors.New("conflicting audit event")
		}
		return nil
	}
	a.events[event.EventID] = event
	return nil
}

type productionCRPTestFenceSource struct{}

func (productionCRPTestFenceSource) CurrentFence(context.Context, activation.AuthorizationRequest) (activation.Fence, error) {
	return activation.Fence{}, nil
}

func (productionCRPTestFenceSource) ValidateFence(context.Context, activation.Authorization, activation.Fence) error {
	return nil
}

type productionCRPTestSidecarBackend struct {
	mu     sync.Mutex
	starts int
	probes int
	modes  []activation.SidecarMode
	stops  int
}

func (b *productionCRPTestSidecarBackend) Start(context.Context, activation.SidecarLaunchSpec) (activation.SidecarLauncherProcess, error) {
	b.mu.Lock()
	b.starts++
	b.mu.Unlock()
	return &productionCRPTestSidecarProcess{backend: b}, nil
}

func (b *productionCRPTestSidecarBackend) counts() (int, int, []activation.SidecarMode, int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.starts, b.probes, append([]activation.SidecarMode(nil), b.modes...), b.stops
}

type productionCRPTestSidecarProcess struct {
	backend *productionCRPTestSidecarBackend
}

func (p *productionCRPTestSidecarProcess) SetMode(_ context.Context, mode activation.SidecarMode) error {
	p.backend.mu.Lock()
	p.backend.modes = append(p.backend.modes, mode)
	p.backend.mu.Unlock()
	return nil
}

func (p *productionCRPTestSidecarProcess) Probe(context.Context) error {
	p.backend.mu.Lock()
	p.backend.probes++
	p.backend.mu.Unlock()
	return nil
}

func (p *productionCRPTestSidecarProcess) Stop(context.Context) error {
	p.backend.mu.Lock()
	p.backend.stops++
	p.backend.mu.Unlock()
	return nil
}

type productionCRPPKI struct {
	caFile         string
	serverCertFile string
	serverKeyFile  string
	clientCertFile string
	clientKeyFile  string
}

func TestProductionCRPOptionsFromEnvironmentUsesExplicitPrecedence(t *testing.T) {
	values := map[string]string{
		EnvProductionCRPListenEndpoint:        "127.0.0.1:9443",
		EnvProductionCRPSidecarListenEndpoint: "127.0.0.1:9444",
		EnvProductionCRPControlEndpoint:       "https://control.example",
		EnvProductionCRPSidecarServerName:     "sidecar.example",
	}
	opts := productionCRPOptionsFromLookup(ProductionCRPOptions{ControlEndpoint: "https://explicit.example"}, func(name string) (string, bool) {
		value, ok := values[name]
		return value, ok
	})
	if opts.ListenEndpoint != values[EnvProductionCRPListenEndpoint] || opts.SidecarListenEndpoint != values[EnvProductionCRPSidecarListenEndpoint] || opts.SidecarServerName != values[EnvProductionCRPSidecarServerName] {
		t.Fatalf("environment options not loaded: %+v", opts)
	}
	if opts.ControlEndpoint != "https://explicit.example" {
		t.Fatalf("explicit control endpoint was overwritten: %q", opts.ControlEndpoint)
	}
}

func TestOpenProductionCRPFailsClosedOnMissingAuthorityOrTransport(t *testing.T) {
	opts, _ := productionCRPTestOptions(t)
	tests := []struct {
		name   string
		mutate func(*ProductionCRPOptions)
	}{
		{name: "listen endpoint", mutate: func(opts *ProductionCRPOptions) { opts.ListenEndpoint = "" }},
		{name: "sidecar listen endpoint", mutate: func(opts *ProductionCRPOptions) { opts.SidecarListenEndpoint = "" }},
		{name: "control endpoint", mutate: func(opts *ProductionCRPOptions) { opts.ControlEndpoint = "" }},
		{name: "sidecar endpoint", mutate: func(opts *ProductionCRPOptions) { opts.SidecarEndpoint = "" }},
		{name: "CA", mutate: func(opts *ProductionCRPOptions) { opts.CAFile = "" }},
		{name: "server certificate", mutate: func(opts *ProductionCRPOptions) { opts.ServerCertFile = "" }},
		{name: "client certificate", mutate: func(opts *ProductionCRPOptions) { opts.ClientCertFile = "" }},
		{name: "control server name", mutate: func(opts *ProductionCRPOptions) { opts.ControlServerName = "" }},
		{name: "sidecar server name", mutate: func(opts *ProductionCRPOptions) { opts.SidecarServerName = "" }},
		{name: "provider", mutate: func(opts *ProductionCRPOptions) { opts.Provider = nil }},
		{name: "fence source", mutate: func(opts *ProductionCRPOptions) { opts.FenceSource = nil }},
		{name: "sidecar backend", mutate: func(opts *ProductionCRPOptions) { opts.SidecarBackend = nil }},
		{name: "runtime", mutate: func(opts *ProductionCRPOptions) { opts.Runtime = nil }},
		{name: "approval resolver", mutate: func(opts *ProductionCRPOptions) { opts.ApprovalClaimResolver = nil }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := opts
			test.mutate(&candidate)
			bundle, err := OpenProductionCRP(context.Background(), candidate)
			if bundle != nil {
				_ = bundle.Close()
			}
			if err == nil {
				t.Fatal("unsafe production CRP options were accepted")
			}
		})
	}
}

func TestProductionCRPMTLSAuthorizeValidateConsumeAndClose(t *testing.T) {
	opts, provider := productionCRPTestOptions(t)
	bundle, err := OpenProductionCRP(context.Background(), opts)
	if err != nil {
		t.Fatalf("OpenProductionCRP() error=%v", err)
	}
	if bundle.Handler() == nil || bundle.SidecarHandler() == nil || bundle.ControlPlane() == nil || bundle.Sidecars() == nil || bundle.Service() == nil {
		t.Fatal("production bundle omitted a control/sidecar handler, client, sidecar manager, or activation service")
	}
	if bundle.Runtime() != opts.Runtime {
		t.Fatal("production bundle replaced the caller-owned shared runtime")
	}
	if err := bundle.Start(); err != nil {
		t.Fatalf("Start() error=%v", err)
	}

	plainClient := &http.Client{Timeout: time.Second}
	if response, plainErr := plainClient.Get("http://" + bundle.listener.Addr().String()); plainErr == nil {
		_ = response.Body.Close()
		if response.StatusCode >= 200 && response.StatusCode < 300 {
			t.Fatalf("plaintext request reached control-plane handler with status=%d", response.StatusCode)
		}
	}

	untrusted := newProductionCRPUntrustedClient(t, opts.CAFile, opts.ControlServerName)
	request, claim := productionCRPAuthorizationRequest(t, bundle.ControlPlane().TransportIdentity(), provider.now)
	request.ApprovalClaim = claim
	requestBody, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	httpRequest, err := http.NewRequest(http.MethodPost, bundle.Endpoint()+"/v1/crp/activation/authorize", bytes.NewReader(requestBody))
	if err != nil {
		t.Fatal(err)
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("X-CheeseWAF-Transport-Schema", activation.TransportSchemaVersion)
	if response, untrustedErr := untrusted.Do(httpRequest); untrustedErr == nil {
		_ = response.Body.Close()
		t.Fatalf("untrusted client certificate was accepted with status=%d", response.StatusCode)
	}

	authorization, err := bundle.ControlPlane().Authorize(context.Background(), request)
	if err != nil {
		t.Fatalf("Authorize() error=%v", err)
	}
	if err := bundle.ControlPlane().Validate(context.Background(), authorization); err != nil {
		t.Fatalf("Validate() error=%v", err)
	}
	if authorization.Confirmation == nil {
		t.Fatal("authorization omitted confirmation")
	}
	if err := bundle.ControlPlane().Consume(context.Background(), authorization.Confirmation.RuntimeConfirmation()); err != nil {
		t.Fatalf("Consume() error=%v", err)
	}
	provider.mu.Lock()
	consumed := provider.consumed
	provider.mu.Unlock()
	if consumed != 1 {
		t.Fatalf("provider consume count=%d, want 1", consumed)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := bundle.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("Shutdown() error=%v", err)
	}
	if err := bundle.Wait(shutdownCtx); err != nil {
		t.Fatalf("Wait() after shutdown error=%v", err)
	}
	if err := bundle.Close(); err != nil {
		t.Fatalf("idempotent Close() error=%v", err)
	}
	if _, err := plainClient.Get(bundle.Endpoint()); err == nil {
		t.Fatal("closed production CRP server still accepted connections")
	}
	if _, err := plainClient.Get(bundle.SidecarEndpoint()); err == nil {
		t.Fatal("closed production CRP sidecar server still accepted connections")
	}
}

func TestProductionCRPActivationUsesOwnedSidecarListener(t *testing.T) {
	for _, test := range []struct {
		name string
		stop func(*ProductionCRP) error
	}{
		{name: "close", stop: func(bundle *ProductionCRP) error { return bundle.Close() }},
		{name: "shutdown", stop: func(bundle *ProductionCRP) error {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			return bundle.Shutdown(ctx)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			opts, _ := productionCRPTestOptions(t)
			backend := opts.SidecarBackend.(*productionCRPTestSidecarBackend)
			now := opts.Clock()
			pkg, imported := newCRPActivationAdapterPackage(t, now)
			staged, err := opts.Runtime.Stage(pkg, imported)
			if err != nil {
				t.Fatal(err)
			}
			descriptor := activation.SidecarDescriptor{
				PluginID: staged.PluginID, Runtime: "sidecar", Version: staged.Version,
				ManifestIdentity: staged.ManifestIdentity, ArtifactIdentity: staged.ArtifactIdentity,
				Namespace: staged.Namespace, Source: "ota", SourceRoot: "root",
				Capabilities: []string{"observe"},
			}
			bundle, err := OpenProductionCRP(context.Background(), opts)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = bundle.Close() })
			if err := bundle.Start(); err != nil {
				t.Fatal(err)
			}
			executor, err := NewProductionCRPActivationExecutor(bundle.Service())
			if err != nil {
				t.Fatal(err)
			}
			result, err := executor.ExecuteCRPActivation(context.Background(), activation.AsyncRequest{
				Action: crp.RuntimeActionPromote, Key: staged.Key, ExpectedRevision: staged.Revision,
				Descriptor: descriptor,
				Policy:     activation.CanaryPolicy{ObserveProbes: 1, CanaryProbes: 1, ProbeTimeout: time.Second},
			})
			if err != nil {
				t.Fatalf("activation through owned sidecar listener failed: %v", err)
			}
			if result.Phase != activation.PhaseActive || result.Record.Key != staged.Key {
				t.Fatalf("activation result=%+v, want active %q", result, staged.Key)
			}
			starts, probes, modes, stops := backend.counts()
			if starts != 1 || probes != 2 || len(modes) != 2 || modes[0] != activation.SidecarModeCanary || modes[1] != activation.SidecarModeActive || stops != 0 {
				t.Fatalf("sidecar lifecycle starts=%d probes=%d modes=%v stops=%d, want 1/2/[canary active]/0", starts, probes, modes, stops)
			}
			if err := test.stop(bundle); err != nil {
				t.Fatalf("%s active bundle: %v", test.name, err)
			}
			_, _, _, stops = backend.counts()
			if stops != 1 {
				t.Fatalf("%s stopped processes=%d, want 1", test.name, stops)
			}
		})
	}
}

func TestProductionCRPUnexpectedSidecarListenerExitStopsBothListeners(t *testing.T) {
	opts, _ := productionCRPTestOptions(t)
	bundle, err := OpenProductionCRP(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = bundle.Close() })
	if err := bundle.Start(); err != nil {
		t.Fatal(err)
	}
	if err := bundle.sidecarServer.Close(); err != nil {
		t.Fatal(err)
	}
	waitCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := bundle.Wait(waitCtx); !errors.Is(err, ErrProductionCRPLifecycle) {
		t.Fatalf("Wait() error=%v, want ErrProductionCRPLifecycle", err)
	}
	for name, address := range map[string]string{"control": bundle.listener.Addr().String(), "sidecar": bundle.sidecarListener.Addr().String()} {
		connection, dialErr := net.DialTimeout("tcp", address, 250*time.Millisecond)
		if dialErr == nil {
			_ = connection.Close()
			t.Fatalf("%s listener remained open after peer listener failed", name)
		}
	}
}

func TestProductionCRPCloseBeforeStart(t *testing.T) {
	opts, _ := productionCRPTestOptions(t)
	bundle, err := OpenProductionCRP(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	address := bundle.listener.Addr().String()
	if err := bundle.Close(); err != nil {
		t.Fatalf("Close() error=%v", err)
	}
	if err := bundle.Close(); err != nil {
		t.Fatalf("second Close() error=%v", err)
	}
	if err := bundle.Start(); !errors.Is(err, ErrProductionCRPLifecycle) {
		t.Fatalf("Start() after Close error=%v, want ErrProductionCRPLifecycle", err)
	}
	connection, err := net.DialTimeout("tcp", address, 250*time.Millisecond)
	if err == nil {
		_ = connection.Close()
		t.Fatal("Close() left the unstarted listener open")
	}
}

func TestOpenProductionCRPRejectsPreboundRuntimeAuthorizer(t *testing.T) {
	opts, _ := productionCRPTestOptions(t)
	if err := opts.Runtime.BindAuthorizer(crp.RuntimeAuthorizerFunc(func(crp.Confirmation) error { return nil })); err != nil {
		t.Fatal(err)
	}
	bundle, err := OpenProductionCRP(context.Background(), opts)
	if bundle != nil || !errors.Is(err, ErrProductionCRPUnavailable) {
		if bundle != nil {
			_ = bundle.Close()
		}
		t.Fatalf("OpenProductionCRP() bundle=%v error=%v, want fail-closed prebound runtime rejection", bundle, err)
	}
}

func TestOpenProductionCRPConstructionFailureDoesNotPoisonSharedRuntime(t *testing.T) {
	opts, _ := productionCRPTestOptions(t)
	validSidecarEndpoint := opts.SidecarEndpoint
	opts.SidecarEndpoint = "://invalid-sidecar-endpoint"

	bundle, err := OpenProductionCRP(context.Background(), opts)
	if bundle != nil || err == nil {
		if bundle != nil {
			_ = bundle.Close()
		}
		t.Fatalf("OpenProductionCRP() bundle=%v error=%v, want construction failure", bundle, err)
	}

	opts.SidecarEndpoint = validSidecarEndpoint
	bundle, err = OpenProductionCRP(context.Background(), opts)
	if err != nil {
		t.Fatalf("retry with corrected transport error=%v; failed construction poisoned shared runtime", err)
	}
	if err := bundle.Close(); err != nil {
		t.Fatalf("Close() error=%v", err)
	}
}

func TestOpenProductionCRPListenFailureDoesNotPoisonSharedRuntime(t *testing.T) {
	opts, _ := productionCRPTestOptions(t)
	occupied, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	opts.ListenEndpoint = occupied.Addr().String()

	bundle, err := OpenProductionCRP(context.Background(), opts)
	if bundle != nil || err == nil {
		if bundle != nil {
			_ = bundle.Close()
		}
		_ = occupied.Close()
		t.Fatalf("OpenProductionCRP() bundle=%v error=%v, want occupied-listener failure", bundle, err)
	}
	if err := occupied.Close(); err != nil {
		t.Fatal(err)
	}

	bundle, err = OpenProductionCRP(context.Background(), opts)
	if err != nil {
		t.Fatalf("retry after releasing listener error=%v; failed listen poisoned shared runtime", err)
	}
	if err := bundle.Close(); err != nil {
		t.Fatalf("Close() error=%v", err)
	}
}

func productionCRPTestOptions(t *testing.T) (ProductionCRPOptions, *productionCRPTestProvider) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	pki := newProductionCRPPKI(t)
	listenEndpoint := reserveProductionCRPAddress(t)
	sidecarListenEndpoint := reserveProductionCRPAddress(t)
	controlEndpoint := "https://" + listenEndpoint
	sidecarEndpoint := "https://" + sidecarListenEndpoint
	runtime, err := crp.NewRuntimeStore(filepath.Join(t.TempDir(), "runtime"), crp.RuntimeStoreOptions{
		Clock:       func() time.Time { return now },
		HealthCheck: crp.HealthCheckFunc(func(crp.RuntimeRecord) error { return nil }),
		Revalidate:  crp.RuntimeRevalidateFunc(func(crp.RuntimeRecord) error { return nil }),
	})
	if err != nil {
		t.Fatal(err)
	}
	provider := &productionCRPTestProvider{now: now}
	resolver := func(_ context.Context, request activation.AuthorizationRequest) (activation.ApprovalClaim, error) {
		claim := activation.ApprovalClaim{
			ApprovalID: "approval-1", ConfirmationID: "confirmation-1", Actor: "operator",
			PolicyEpoch: 1, TTL: time.Minute, IssuedAt: now, ExpiresAt: now.Add(time.Minute),
			Nonce: "nonce-1", SessionID: "session-1",
		}
		claim.Scope = activation.ApprovalScope(request)
		claim.IntentDigest = activation.ApprovalIntentDigest(request)
		return claim, nil
	}
	return ProductionCRPOptions{
		ListenEndpoint: listenEndpoint, SidecarListenEndpoint: sidecarListenEndpoint,
		ControlEndpoint: controlEndpoint, SidecarEndpoint: sidecarEndpoint,
		CAFile: pki.caFile, ServerCertFile: pki.serverCertFile, ServerKeyFile: pki.serverKeyFile,
		ClientCertFile: pki.clientCertFile, ClientKeyFile: pki.clientKeyFile,
		ControlServerName: "control-plane", SidecarServerName: "control-plane",
		ClusterID: "cluster-a", NodeID: "node-a", TransportTimeout: 3 * time.Second,
		Runtime: runtime, State: newProductionCRPTestState(), Provider: provider,
		Audit:          &productionCRPTestAudit{events: make(map[string]activation.AuthorizationAuditEvent)},
		FenceSource:    productionCRPTestFenceSource{},
		SidecarBackend: &productionCRPTestSidecarBackend{}, ApprovalClaimResolver: resolver,
		Policy: activation.Policy{
			AllowedCapabilities: map[string]struct{}{"observe": {}, "canary": {}},
			VerifyRecord:        func(context.Context, crp.RuntimeRecord) error { return nil },
		},
		Clock: func() time.Time { return now },
	}, provider
}

func productionCRPAuthorizationRequest(t *testing.T, transportIdentity activation.TransportIdentity, now time.Time) (activation.AuthorizationRequest, activation.ApprovalClaim) {
	t.Helper()
	descriptor := activation.SidecarDescriptor{
		PluginID: "rate-limit", Runtime: "sidecar", Version: "1.0.0", Namespace: "official/security",
		Source: "cwedp", SourceRoot: "official", ManifestIdentity: digestProductionCRPValue("manifest"),
		ArtifactIdentity: digestProductionCRPValue("artifact"), Capabilities: []string{"observe"},
	}
	descriptorJSON, err := json.Marshal(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	descriptorDigest := sha256.Sum256(descriptorJSON)
	request := activation.AuthorizationRequest{
		SchemaVersion: activation.TransportSchemaVersion, RequestID: "request-1", Identity: transportIdentity,
		Action: crp.RuntimeActionPromote, Permission: activation.PermissionActivate,
		Target: activation.RuntimeTarget{
			Key: "rate-limit", PluginID: descriptor.PluginID, Namespace: descriptor.Namespace, Version: descriptor.Version,
			ReleaseSequence: 1, ManifestIdentity: descriptor.ManifestIdentity,
			ArtifactIdentity: descriptor.ArtifactIdentity, Revision: 1,
		},
		ExpectedRevision: 1, Descriptor: descriptor, DescriptorIdentity: hex.EncodeToString(descriptorDigest[:]),
		Canary: activation.CanaryPolicy{ObserveProbes: 1, CanaryProbes: 1}, RequestedAt: now,
	}
	claim := activation.ApprovalClaim{
		ApprovalID: "approval-1", ConfirmationID: "confirmation-1", Actor: "operator",
		PolicyEpoch: 1, TTL: time.Minute, IssuedAt: now, ExpiresAt: now.Add(time.Minute),
		Nonce: "nonce-1", SessionID: "session-1",
	}
	claim.Scope = activation.ApprovalScope(request)
	claim.IntentDigest = activation.ApprovalIntentDigest(request)
	return request, claim
}

func newProductionCRPPKI(t *testing.T) productionCRPPKI {
	t.Helper()
	service, err := identity.NewMemoryIdentityService(identity.ServiceOptions{ClusterID: "cluster-a"})
	if err != nil {
		t.Fatal(err)
	}
	server, err := service.IssueNodeCertificateBundle(identity.NodeIdentity{
		NodeID: "control-plane", Role: "monitor", ClusterID: "cluster-a", AdvertiseAddr: "127.0.0.1:443",
	})
	if err != nil {
		t.Fatal(err)
	}
	client, err := service.IssueNodeCertificateBundle(identity.NodeIdentity{
		NodeID: "node-a", Role: "waf", ClusterID: "cluster-a", AdvertiseAddr: "127.0.0.1:443",
	})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	pki := productionCRPPKI{
		caFile: filepath.Join(dir, "ca.pem"), serverCertFile: filepath.Join(dir, "server.pem"),
		serverKeyFile: filepath.Join(dir, "server-key.pem"), clientCertFile: filepath.Join(dir, "client.pem"),
		clientKeyFile: filepath.Join(dir, "client-key.pem"),
	}
	files := map[string][]byte{
		pki.caFile: server.CAPEM, pki.serverCertFile: server.CertPEM, pki.serverKeyFile: server.KeyPEM,
		pki.clientCertFile: client.CertPEM, pki.clientKeyFile: client.KeyPEM,
	}
	for name, data := range files {
		if err := os.WriteFile(name, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return pki
}

func newProductionCRPUntrustedClient(t *testing.T, serverCAFile, serverName string) *http.Client {
	t.Helper()
	service, err := identity.NewMemoryIdentityService(identity.ServiceOptions{ClusterID: "cluster-a"})
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := service.IssueNodeCertificateBundle(identity.NodeIdentity{
		NodeID: "node-a", Role: "waf", ClusterID: "cluster-a", AdvertiseAddr: "127.0.0.1:443",
	})
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.X509KeyPair(bundle.CertPEM, bundle.KeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	serverCA, err := os.ReadFile(serverCAFile)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(serverCA) {
		t.Fatal("server CA contains no certificates")
	}
	return &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{certificate}, ServerName: serverName,
		}},
		Timeout: 2 * time.Second,
	}
}

func reserveProductionCRPAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}

func digestProductionCRPValue(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}
