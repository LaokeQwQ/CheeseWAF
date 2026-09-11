package activation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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
	expires := now.Add(time.Minute)
	authorizer := func(_ context.Context, got AuthorizationRequest, _ TransportIdentity) (Authorization, error) {
		return Authorization{SchemaVersion: TransportSchemaVersion, ID: "auth-1", Request: got, Fence: Fence{ClusterID: "cluster-a", Token: "fence-1", Epoch: 1, Revision: 1, ExpiresAt: expires}, Confirmation: &WireConfirmation{ID: "confirm-1", Actor: "operator-1", Action: got.Action, PluginKey: got.Target.Key, ManifestIdentity: got.Target.ManifestIdentity, ExpectedRevision: got.ExpectedRevision, AuthorizedAt: now, ExpiresAt: expires}, IssuedAt: now, ExpiresAt: expires}, nil
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
