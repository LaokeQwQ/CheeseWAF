package activation

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/cluster/identity"
	"github.com/LaokeQwQ/CheeseWAF/internal/crp"
)

type transportHarness struct {
	mu sync.Mutex

	identity  TransportIdentity
	now       time.Time
	requests  []AuthorizationRequest
	validates []Authorization
	consumes  []crp.Confirmation
	peers     []peerCertificateObservation

	tamperAuthorization bool
	denyValidateAt      int
	validateCalls       int

	sidecarRequests []string
	sidecarModes    []SidecarMode
	sidecarStops    int
}

type peerCertificateObservation struct {
	CommonName string
	DNSNames   []string
}

func (h *transportHarness) controlHandler(w http.ResponseWriter, r *http.Request) {
	h.observePeer(r)
	switch r.URL.Path {
	case controlAuthorizePath:
		var request AuthorizationRequest
		if !decodeTransportJSON(w, r, &request) {
			return
		}
		h.mu.Lock()
		h.requests = append(h.requests, request)
		n := len(h.requests)
		h.mu.Unlock()
		now := h.now
		if now.IsZero() {
			now = time.Now().UTC()
		}
		expires := now.Add(2 * time.Minute)
		confirmation := WireConfirmation{
			ID:               fmt.Sprintf("wire-confirmation-%d", n),
			Actor:            "operator-wire",
			Action:           request.Action,
			PluginKey:        request.Target.Key,
			ManifestIdentity: request.Target.ManifestIdentity,
			ExpectedRevision: request.ExpectedRevision,
			AuthorizedAt:     now,
			ExpiresAt:        expires,
		}
		authorization := Authorization{
			SchemaVersion: TransportSchemaVersion,
			ID:            fmt.Sprintf("wire-authorization-%d", n),
			Request:       request,
			Fence: Fence{
				ClusterID: request.Identity.ClusterID,
				Token:     fmt.Sprintf("wire-fence-%d", n),
				Epoch:     1,
				Revision:  uint64(n),
				ExpiresAt: expires,
			},
			Confirmation: &confirmation,
			IssuedAt:     now,
			ExpiresAt:    expires,
		}
		h.mu.Lock()
		tamper := h.tamperAuthorization
		h.mu.Unlock()
		if tamper {
			authorization.Request.Target.Key = authorization.Request.Target.Key + "-tampered"
		}
		writeTransportJSON(w, authorization)
	case controlValidatePath:
		var envelope authorizationEnvelope
		if !decodeTransportJSON(w, r, &envelope) {
			return
		}
		h.mu.Lock()
		h.validateCalls++
		call := h.validateCalls
		deny := h.denyValidateAt > 0 && call >= h.denyValidateAt
		h.validates = append(h.validates, envelope.Authorization)
		h.mu.Unlock()
		if deny {
			writeTransportStatus(w, http.StatusForbidden)
			return
		}
		writeTransportJSON(w, transportAcknowledgement{
			SchemaVersion:   TransportSchemaVersion,
			AuthorizationID: envelope.Authorization.ID,
			RequestID:       envelope.Authorization.Request.RequestID,
			NodeID:          envelope.Authorization.Request.Identity.NodeID,
			Status:          "valid",
		})
	case controlConsumePath:
		var envelope authorizationEnvelope
		if !decodeTransportJSON(w, r, &envelope) {
			return
		}
		if envelope.Authorization.Confirmation != nil {
			h.mu.Lock()
			h.consumes = append(h.consumes, envelope.Authorization.Confirmation.RuntimeConfirmation())
			h.mu.Unlock()
		}
		writeTransportJSON(w, transportAcknowledgement{
			SchemaVersion:   TransportSchemaVersion,
			AuthorizationID: envelope.Authorization.ID,
			RequestID:       envelope.Authorization.Request.RequestID,
			NodeID:          envelope.Authorization.Request.Identity.NodeID,
			Status:          "consumed",
		})
	default:
		writeTransportStatus(w, http.StatusNotFound)
	}
}

func (h *transportHarness) sidecarHandler(w http.ResponseWriter, r *http.Request) {
	h.observePeer(r)
	if r.URL.Path == sidecarStartPath {
		var request SidecarStartRequest
		if !decodeTransportJSON(w, r, &request) {
			return
		}
		h.mu.Lock()
		h.sidecarRequests = append(h.sidecarRequests, "start")
		h.mu.Unlock()
		writeTransportJSON(w, SidecarAcknowledgement{
			SchemaVersion: TransportSchemaVersion, AuthorizationID: request.Authorization.ID,
			RequestID: request.Authorization.Request.RequestID, NodeID: request.Authorization.Request.Identity.NodeID,
			HandleID: "wire-handle-1", PluginKey: request.Target.Key, ManifestIdentity: request.Target.ManifestIdentity,
			Mode: request.Mode, Status: "started",
		})
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/crp/sidecars/"), "/")
	if len(parts) != 2 || parts[0] != "wire-handle-1" {
		writeTransportStatus(w, http.StatusNotFound)
		return
	}
	var request SidecarOperationRequest
	if !decodeTransportJSON(w, r, &request) {
		return
	}
	h.mu.Lock()
	h.sidecarRequests = append(h.sidecarRequests, parts[1])
	if parts[1] == "mode" {
		h.sidecarModes = append(h.sidecarModes, request.Mode)
	}
	if parts[1] == "stop" {
		h.sidecarStops++
	}
	h.mu.Unlock()
	status := "healthy"
	if parts[1] == "mode" {
		status = "mode_set"
	}
	if parts[1] == "stop" {
		status = "stopped"
	}
	writeTransportJSON(w, SidecarAcknowledgement{
		SchemaVersion: TransportSchemaVersion, AuthorizationID: request.Authorization.ID,
		RequestID: request.Authorization.Request.RequestID, NodeID: request.Authorization.Request.Identity.NodeID,
		HandleID: request.HandleID, PluginKey: request.Authorization.Request.Target.Key,
		ManifestIdentity: request.Authorization.Request.Target.ManifestIdentity,
		Mode:             request.Mode, Status: status,
	})
}

func (h *transportHarness) observePeer(r *http.Request) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return
	}
	certificate := r.TLS.PeerCertificates[0]
	h.mu.Lock()
	h.peers = append(h.peers, peerCertificateObservation{CommonName: certificate.Subject.CommonName, DNSNames: append([]string(nil), certificate.DNSNames...)})
	h.mu.Unlock()
}

func decodeTransportJSON(w http.ResponseWriter, r *http.Request, target any) bool {
	defer r.Body.Close()
	decoder := json.NewDecoder(io.LimitReader(r.Body, maxTransportBodyBytes+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		writeTransportStatus(w, http.StatusBadRequest)
		return false
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		writeTransportStatus(w, http.StatusBadRequest)
		return false
	}
	return true
}

type mTLSServerFixture struct {
	server *httptest.Server
}

type mTLSPKIFixture struct {
	service      *identity.MemoryIdentityService
	clientBundle identity.NodeCertificateBundle
}

func newMTLSPKIFixture(t *testing.T) *mTLSPKIFixture {
	t.Helper()
	identityService, err := identity.NewMemoryIdentityService(identity.ServiceOptions{ClusterID: "cluster-a"})
	if err != nil {
		t.Fatal(err)
	}
	clientBundle, err := identityService.IssueNodeCertificateBundle(identity.NodeIdentity{NodeID: "node-a", Role: "waf", ClusterID: "cluster-a", AdvertiseAddr: "127.0.0.1:443"})
	if err != nil {
		t.Fatal(err)
	}
	return &mTLSPKIFixture{service: identityService, clientBundle: clientBundle}
}

func (p *mTLSPKIFixture) newServer(t *testing.T, nodeID string, handler http.Handler) mTLSServerFixture {
	t.Helper()
	bundle, err := p.service.IssueNodeCertificateBundle(identity.NodeIdentity{NodeID: nodeID, Role: "monitor", ClusterID: "cluster-a", AdvertiseAddr: "127.0.0.1:443"})
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.X509KeyPair(bundle.CertPEM, bundle.KeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(bundle.CAPEM) {
		t.Fatal("failed to parse fixture CA")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &httptest.Server{Listener: listener, Config: &http.Server{Handler: handler}}
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{certificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    roots,
		MinVersion:   tls.VersionTLS13,
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	return mTLSServerFixture{server: server}
}

func writeMTLSBundleFiles(t *testing.T, bundle identity.NodeCertificateBundle, keyMode os.FileMode) (caPath, certPath, keyPath string) {
	t.Helper()
	dir := t.TempDir()
	caPath, certPath, keyPath = filepath.Join(dir, "ca.pem"), filepath.Join(dir, "node.pem"), filepath.Join(dir, "node-key.pem")
	for path, file := range map[string]struct {
		data []byte
		mode os.FileMode
	}{
		caPath:   {data: bundle.CAPEM, mode: 0o600},
		certPath: {data: bundle.CertPEM, mode: 0o600},
		keyPath:  {data: bundle.KeyPEM, mode: keyMode},
	} {
		if err := os.WriteFile(path, file.data, file.mode); err != nil {
			t.Fatal(err)
		}
	}
	return caPath, certPath, keyPath
}

func newWireClients(t *testing.T, controlEndpoint, controlServerName, sidecarEndpoint, sidecarServerName string, bundle identity.NodeCertificateBundle) (*HTTPControlPlaneClient, *HTTPSidecarManager) {
	t.Helper()
	caPath, certPath, keyPath := writeMTLSBundleFiles(t, bundle, 0o600)
	options := MTLSOptions{CAFile: caPath, CertFile: certPath, KeyFile: keyPath, ClusterID: "cluster-a", NodeID: "node-a", Role: "waf", ServerName: controlServerName, Timeout: 3 * time.Second}
	controlTransport, err := NewMTLSClient(options)
	if err != nil {
		t.Fatal(err)
	}
	controlPlane, err := NewHTTPControlPlaneClient(controlEndpoint, controlTransport, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	options.ServerName = sidecarServerName
	sidecarTransport, err := NewMTLSClient(options)
	if err != nil {
		t.Fatal(err)
	}
	sidecars, err := NewHTTPSidecarManager(sidecarEndpoint, sidecarTransport, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	return controlPlane, sidecars
}

func TestMTLSActivationTransportEndToEnd(t *testing.T) {
	now := time.Now().UTC()
	controlHarness := &transportHarness{now: now}
	sidecarHarness := &transportHarness{}
	pki := newMTLSPKIFixture(t)
	controlServer := pki.newServer(t, "control-plane", http.HandlerFunc(controlHarness.controlHandler))
	sidecarServer := pki.newServer(t, "sidecar-launcher", http.HandlerFunc(sidecarHarness.sidecarHandler))
	controlPlane, sidecars := newWireClients(t, controlServer.server.URL, "control-plane", sidecarServer.server.URL, "sidecar-launcher", pki.clientBundle)
	store := newActivationStore(t, now, controlPlane)
	pkg, imported := activationPackage(t, now, "1.0.0", 1, []byte("wire-artifact-v1"))
	staged := stageActivationRecord(t, store, pkg, imported)
	service := newActivationService(t, store, controlPlane, sidecars, now, Policy{})

	result, err := service.ActivateAuthorized(context.Background(), staged.Key, staged.Revision, activationDescriptor(staged), CanaryPolicy{ObserveProbes: 1, CanaryProbes: 1})
	if err != nil {
		t.Fatal(err)
	}
	if result.Phase != PhaseActive {
		t.Fatalf("phase=%s, want active", result.Phase)
	}
	if _, err := store.Current(staged.Key); err != nil {
		t.Fatalf("current runtime missing: %v", err)
	}
	if _, err := store.Staged(staged.Key); !errors.Is(err, crp.ErrRuntimeNotFound) {
		t.Fatalf("staged runtime remains after promotion: %v", err)
	}

	controlHarness.mu.Lock()
	requests := append([]AuthorizationRequest(nil), controlHarness.requests...)
	validations := len(controlHarness.validates)
	consumes := len(controlHarness.consumes)
	peers := append([]peerCertificateObservation(nil), controlHarness.peers...)
	controlHarness.mu.Unlock()
	if len(requests) != 1 {
		t.Fatalf("authorization requests=%d, want 1", len(requests))
	}
	request := requests[0]
	if request.Identity.NodeID != "node-a" || request.Identity.Role != "waf" || request.Permission != PermissionActivate || request.Action != crp.RuntimeActionPromote {
		t.Fatalf("authorization identity/action=%+v", request)
	}
	if request.Descriptor.Source != "ota" || request.Descriptor.SourceRoot != "root" || request.Target.ManifestIdentity != staged.ManifestIdentity || request.Target.ArtifactIdentity != staged.ArtifactIdentity {
		t.Fatalf("authorization source/content binding=%+v", request)
	}
	if validations != 6 || consumes != 1 {
		t.Fatalf("validations=%d consumes=%d, want 6 and 1", validations, consumes)
	}
	if len(peers) == 0 {
		t.Fatal("control plane did not observe a client certificate")
	}
	for _, peer := range peers {
		if peer.CommonName != "cluster-a/waf/node-a" || !containsString(peer.DNSNames, "node-a") {
			t.Fatalf("unexpected peer certificate=%+v", peer)
		}
	}

	sidecarHarness.mu.Lock()
	defer sidecarHarness.mu.Unlock()
	if fmt.Sprint(sidecarHarness.sidecarRequests) != "[start probe mode probe mode]" {
		t.Fatalf("sidecar request order=%v", sidecarHarness.sidecarRequests)
	}
	if fmt.Sprint(sidecarHarness.sidecarModes) != "[canary active]" || sidecarHarness.sidecarStops != 0 {
		t.Fatalf("sidecar modes=%v stops=%d", sidecarHarness.sidecarModes, sidecarHarness.sidecarStops)
	}
}

func TestMTLSRollbackTransportEndToEnd(t *testing.T) {
	now := time.Now().UTC()
	controlHarness := &transportHarness{now: now}
	sidecarHarness := &transportHarness{}
	pki := newMTLSPKIFixture(t)
	controlServer := pki.newServer(t, "control-plane", http.HandlerFunc(controlHarness.controlHandler))
	sidecarServer := pki.newServer(t, "sidecar-launcher", http.HandlerFunc(sidecarHarness.sidecarHandler))
	controlPlane, sidecars := newWireClients(t, controlServer.server.URL, "control-plane", sidecarServer.server.URL, "sidecar-launcher", pki.clientBundle)
	store := newActivationStore(t, now, controlPlane)
	service := newActivationService(t, store, controlPlane, sidecars, now, Policy{})

	pkg1, imported1 := activationPackage(t, now, "1.0.0", 1, []byte("wire-artifact-v1"))
	v1 := stageActivationRecord(t, store, pkg1, imported1)
	if _, err := service.ActivateAuthorized(context.Background(), v1.Key, v1.Revision, activationDescriptor(v1), CanaryPolicy{}); err != nil {
		t.Fatal(err)
	}
	pkg2, imported2 := activationPackage(t, now, "2.0.0", 2, []byte("wire-artifact-v2"))
	v2 := stageActivationRecord(t, store, pkg2, imported2)
	current, err := service.ActivateAuthorized(context.Background(), v2.Key, v2.Revision, activationDescriptor(v2), CanaryPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	previous, err := store.Previous(v2.Key)
	if err != nil {
		t.Fatal(err)
	}
	rolled, err := service.RollbackAuthorized(context.Background(), v2.Key, current.Record.Revision, activationDescriptor(previous), CanaryPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	if rolled.Phase != PhaseRolled || rolled.Record.Version != "1.0.0" || rolled.Record.ManifestIdentity != previous.ManifestIdentity {
		t.Fatalf("rollback result=%+v, want exact previous v1", rolled)
	}

	controlHarness.mu.Lock()
	defer controlHarness.mu.Unlock()
	if len(controlHarness.requests) != 3 || len(controlHarness.consumes) != 3 {
		t.Fatalf("authorization requests=%d consumes=%d, want 3 and 3", len(controlHarness.requests), len(controlHarness.consumes))
	}
	request := controlHarness.requests[2]
	if request.Action != crp.RuntimeActionRollback || request.Permission != PermissionRollback || request.ExpectedRevision != current.Record.Revision || request.Target.ManifestIdentity != previous.ManifestIdentity || request.Target.Revision >= request.ExpectedRevision {
		t.Fatalf("rollback wire binding=%+v", request)
	}
}

func TestMTLSActivationRejectsTamperedAuthorization(t *testing.T) {
	now := time.Now().UTC()
	controlHarness := &transportHarness{now: now, tamperAuthorization: true}
	sidecarHarness := &transportHarness{}
	pki := newMTLSPKIFixture(t)
	controlServer := pki.newServer(t, "control-plane", http.HandlerFunc(controlHarness.controlHandler))
	sidecarServer := pki.newServer(t, "sidecar-launcher", http.HandlerFunc(sidecarHarness.sidecarHandler))
	controlPlane, sidecars := newWireClients(t, controlServer.server.URL, "control-plane", sidecarServer.server.URL, "sidecar-launcher", pki.clientBundle)
	store := newActivationStore(t, now, controlPlane)
	pkg, imported := activationPackage(t, now, "1.0.0", 1, []byte("wire-artifact-v1"))
	staged := stageActivationRecord(t, store, pkg, imported)
	service := newActivationService(t, store, controlPlane, sidecars, now, Policy{})

	_, err := service.ActivateAuthorized(context.Background(), staged.Key, staged.Revision, activationDescriptor(staged), CanaryPolicy{})
	if !errors.Is(err, ErrAuthorizationBinding) {
		t.Fatalf("tampered authorization error=%v, want ErrAuthorizationBinding", err)
	}
	assertStagedOnly(t, store, staged.Key)
	sidecarHarness.mu.Lock()
	defer sidecarHarness.mu.Unlock()
	if len(sidecarHarness.sidecarRequests) != 0 {
		t.Fatalf("tampered authorization reached sidecar: %v", sidecarHarness.sidecarRequests)
	}
}

func TestMTLSActivationStopsSidecarWhenFenceValidationIsDenied(t *testing.T) {
	now := time.Now().UTC()
	controlHarness := &transportHarness{now: now, denyValidateAt: 2}
	sidecarHarness := &transportHarness{}
	pki := newMTLSPKIFixture(t)
	controlServer := pki.newServer(t, "control-plane", http.HandlerFunc(controlHarness.controlHandler))
	sidecarServer := pki.newServer(t, "sidecar-launcher", http.HandlerFunc(sidecarHarness.sidecarHandler))
	controlPlane, sidecars := newWireClients(t, controlServer.server.URL, "control-plane", sidecarServer.server.URL, "sidecar-launcher", pki.clientBundle)
	store := newActivationStore(t, now, controlPlane)
	pkg, imported := activationPackage(t, now, "1.0.0", 1, []byte("wire-artifact-v1"))
	staged := stageActivationRecord(t, store, pkg, imported)
	service := newActivationService(t, store, controlPlane, sidecars, now, Policy{})

	_, err := service.ActivateAuthorized(context.Background(), staged.Key, staged.Revision, activationDescriptor(staged), CanaryPolicy{})
	if !errors.Is(err, ErrAuthorizationDenied) {
		t.Fatalf("denied fence error=%v, want ErrAuthorizationDenied", err)
	}
	assertStagedOnly(t, store, staged.Key)
	sidecarHarness.mu.Lock()
	defer sidecarHarness.mu.Unlock()
	if sidecarHarness.sidecarStops != 1 {
		t.Fatalf("sidecar stops=%d, want 1", sidecarHarness.sidecarStops)
	}
}

func TestMTLSClientRejectsNodeAndPrivateKeyBindingBeforeNetwork(t *testing.T) {
	pki := newMTLSPKIFixture(t)
	var requests atomic.Int32
	_ = pki.newServer(t, "control-plane", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		writeTransportStatus(w, http.StatusInternalServerError)
	}))
	caPath, certPath, keyPath := writeMTLSBundleFiles(t, pki.clientBundle, 0o600)
	badNode, err := NewMTLSClient(MTLSOptions{CAFile: caPath, CertFile: certPath, KeyFile: keyPath, ClusterID: "cluster-a", NodeID: "node-b", Role: "waf", ServerName: "node-a", Timeout: 2 * time.Second})
	if badNode != nil || !errors.Is(err, ErrTransportTLS) {
		t.Fatalf("mismatched node client=%v err=%v, want ErrTransportTLS", badNode, err)
	}
	if err := os.Chmod(keyPath, 0o644); err != nil {
		t.Fatal(err)
	}
	badMode, err := NewMTLSClient(MTLSOptions{CAFile: caPath, CertFile: certPath, KeyFile: keyPath, ClusterID: "cluster-a", NodeID: "node-a", Role: "waf", ServerName: "node-a", Timeout: 2 * time.Second})
	if badMode != nil || !errors.Is(err, ErrTransportTLS) {
		t.Fatalf("insecure key client=%v err=%v, want ErrTransportTLS", badMode, err)
	}
	if requests.Load() != 0 {
		t.Fatalf("invalid local TLS inputs reached the network: requests=%d", requests.Load())
	}
}

func TestMTLSClientRejectsNonHTTPSOrigin(t *testing.T) {
	pki := newMTLSPKIFixture(t)
	caPath, certPath, keyPath := writeMTLSBundleFiles(t, pki.clientBundle, 0o600)
	client, err := NewMTLSClient(MTLSOptions{CAFile: caPath, CertFile: certPath, KeyFile: keyPath, ClusterID: "cluster-a", NodeID: "node-a", Role: "waf", Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewHTTPControlPlaneClient("http://127.0.0.1:1234", client, time.Now); !errors.Is(err, ErrTransportConfig) {
		t.Fatalf("HTTP control-plane client error=%v, want ErrTransportConfig", err)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
