package extensions

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/audit"
)

func TestOutputHTTPHandlerAuthenticatesAndSubmitsBoundOutput(t *testing.T) {
	fixture := newOutputTransportFixture(t)
	now := fixture.now
	private := fixture.private
	ingress, err := NewIngress(IngressOptions{
		Keys:     map[string]TrustKey{"host-v1": {ID: "host-v1", PublicKey: private.Public().(ed25519.PublicKey)}},
		PluginID: "jev", PluginVersion: "1.2.3", TenantRef: "tenant:demo", SiteRef: "site:demo", PolicyEpoch: 7,
		StreamID: "extensions", Now: func() time.Time { return now }, Sink: OutputSinkFunc(func(_ context.Context, _ audit.Event) (audit.Record, error) { return audit.Record{}, nil }),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ingress.Close()
	handler, err := NewOutputHTTPHandler(OutputHTTPHandlerOptions{
		Ingress: ingress, Peer: fixture.authenticator(), PluginID: "jev", TenantRef: "tenant:demo", SiteRef: "site:demo",
	})
	if err != nil {
		t.Fatal(err)
	}
	body := signedIngressOutput(t, private, now, "evt-http", 1, `{"risk":"medium"}`)
	req := httptest.NewRequest(http.MethodPost, OutputTransportPath, strings.NewReader(string(body)))
	setOutputTransportHeaders(req)
	fixture.attachPeer(req)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status=%d body=%q", rec.Code, rec.Body.String())
	}
	var receipt outputTransportReceipt
	if err := json.Unmarshal(rec.Body.Bytes(), &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.EventID != "evt-http" || receipt.Sequence != 1 || receipt.PluginID != "jev" {
		t.Fatalf("receipt=%+v", receipt)
	}
}

func TestOutputHTTPHandlerRejectsTransportAndScopeFailures(t *testing.T) {
	fixture := newOutputTransportFixture(t)
	ingress := newOutputTransportIngress(t, fixture, "jev", "tenant:demo", "site:demo")
	defer ingress.Close()
	handler, err := NewOutputHTTPHandler(OutputHTTPHandlerOptions{Ingress: ingress, Peer: fixture.authenticator(), PluginID: "jev", TenantRef: "tenant:demo", SiteRef: "site:demo"})
	if err != nil {
		t.Fatal(err)
	}
	body := signedIngressOutput(t, fixture.private, fixture.now, "evt-http", 1, `{}`)
	call := func(method, path string, wire []byte, peer bool) int {
		req := httptest.NewRequest(method, path, strings.NewReader(string(wire)))
		setOutputTransportHeaders(req)
		if peer {
			fixture.attachPeer(req)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Code
	}
	if got := call(http.MethodPost, OutputTransportPath, body, false); got != http.StatusUnauthorized {
		t.Fatalf("missing peer status=%d", got)
	}
	if got := call(http.MethodGet, OutputTransportPath, body, true); got != http.StatusMethodNotAllowed {
		t.Fatalf("method status=%d", got)
	}
	if got := call(http.MethodPost, OutputTransportPath+"?x=1", body, true); got != http.StatusNotFound {
		t.Fatalf("query status=%d", got)
	}
	wrongContent := httptest.NewRequest(http.MethodPost, OutputTransportPath, strings.NewReader(string(body)))
	wrongContent.Header.Set("Content-Type", "text/plain")
	wrongContent.Header.Set("X-CheeseWAF-Extension-Schema", OutputTransportSchemaVersion)
	fixture.attachPeer(wrongContent)
	wrongContentRec := httptest.NewRecorder()
	handler.ServeHTTP(wrongContentRec, wrongContent)
	if wrongContentRec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("content type status=%d", wrongContentRec.Code)
	}
	wrongScope := signedIngressOutputWith(t, fixture.private, fixture.now, OutputClaims{APIVersion: RiskHintAPIVersion, PluginID: "jev", PluginVersion: "1.2.3", EventID: "evt-wrong", Sequence: 1, TenantRef: "tenant:other", SiteRef: "site:demo", PolicyEpoch: 7, ObservedAt: fixture.now, ExpiresAt: fixture.now.Add(time.Minute)}, `{}`)
	if got := call(http.MethodPost, OutputTransportPath, wrongScope, true); got != http.StatusForbidden {
		t.Fatalf("scope status=%d", got)
	}
}

func TestOutputHTTPHandlerBoundsBodyAndMapsIngressErrors(t *testing.T) {
	fixture := newOutputTransportFixture(t)
	ingress := newOutputTransportIngress(t, fixture, "jev", "tenant:demo", "site:demo")
	defer ingress.Close()
	handler, err := NewOutputHTTPHandler(OutputHTTPHandlerOptions{Ingress: ingress, Peer: fixture.authenticator(), PluginID: "jev", TenantRef: "tenant:demo", SiteRef: "site:demo", MaxBodyBytes: 256})
	if err != nil {
		t.Fatal(err)
	}
	large := bytes.Repeat([]byte("x"), 257)
	req := httptest.NewRequest(http.MethodPost, OutputTransportPath, strings.NewReader(string(large)))
	setOutputTransportHeaders(req)
	fixture.attachPeer(req)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("large status=%d", rec.Code)
	}
	closed, err := NewIngress(IngressOptions{Keys: map[string]TrustKey{"host-v1": {ID: "host-v1", PublicKey: fixture.private.Public().(ed25519.PublicKey)}}, PluginID: "jev", PluginVersion: "1.2.3", TenantRef: "tenant:demo", SiteRef: "site:demo", PolicyEpoch: 7, StreamID: "extensions", Now: func() time.Time { return fixture.now }, Sink: OutputSinkFunc(func(context.Context, audit.Event) (audit.Record, error) { return audit.Record{}, nil })})
	if err != nil {
		t.Fatal(err)
	}
	closedHandler, err := NewOutputHTTPHandler(OutputHTTPHandlerOptions{Ingress: closed, Peer: fixture.authenticator(), PluginID: "jev", TenantRef: "tenant:demo", SiteRef: "site:demo"})
	if err != nil {
		t.Fatal(err)
	}
	_ = closed.Close()
	wire := signedIngressOutput(t, fixture.private, fixture.now, "evt-closed", 1, `{}`)
	req = httptest.NewRequest(http.MethodPost, OutputTransportPath, strings.NewReader(string(wire)))
	setOutputTransportHeaders(req)
	fixture.attachPeer(req)
	rec = httptest.NewRecorder()
	closedHandler.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("closed status=%d", rec.Code)
	}
}

type outputTransportFixture struct {
	now     time.Time
	ca      *x509.CertPool
	leaf    *x509.Certificate
	private ed25519.PrivateKey
	certDER []byte
}

func newOutputTransportFixture(t *testing.T) outputTransportFixture {
	t.Helper()
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-ca"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, public, private)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "jev"}, DNSNames: []string{"jev"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caTemplate, public, private)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return outputTransportFixture{now: now, ca: roots, leaf: leaf, private: private, certDER: leafDER}
}

func (f outputTransportFixture) authenticator() MTLSPeerAuthenticator {
	return MTLSPeerAuthenticator{ClientCA: f.ca, Clock: func() time.Time { return f.now }, Resolve: func(cert *x509.Certificate) (PeerIdentity, error) {
		if cert.Subject.CommonName != "jev" {
			return PeerIdentity{}, errors.New("wrong plugin")
		}
		return PeerIdentity{PluginID: "jev", TenantRef: "tenant:demo", SiteRef: "site:demo"}, nil
	}}
}

func (f outputTransportFixture) attachPeer(r *http.Request) {
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{f.leaf}, VerifiedChains: [][]*x509.Certificate{{f.leaf}}}
}

func setOutputTransportHeaders(r *http.Request) {
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CheeseWAF-Extension-Schema", OutputTransportSchemaVersion)
}

func newOutputTransportIngress(t *testing.T, f outputTransportFixture, plugin, tenant, site string) *Ingress {
	t.Helper()
	ingress, err := NewIngress(IngressOptions{Keys: map[string]TrustKey{"host-v1": {ID: "host-v1", PublicKey: f.private.Public().(ed25519.PublicKey)}}, PluginID: plugin, PluginVersion: "1.2.3", TenantRef: tenant, SiteRef: site, PolicyEpoch: 7, StreamID: "extensions", Now: func() time.Time { return f.now }, Sink: OutputSinkFunc(func(context.Context, audit.Event) (audit.Record, error) { return audit.Record{}, nil })})
	if err != nil {
		t.Fatal(err)
	}
	return ingress
}
