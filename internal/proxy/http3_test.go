package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/setup"
	"github.com/quic-go/quic-go"
)

func TestHTTP3ListenAddrFallbacks(t *testing.T) {
	if got := HTTP3ListenAddr(config.ServerConfig{ListenHTTP3: "127.0.0.1:8443", ListenTLS: "127.0.0.1:9443"}); got != "127.0.0.1:8443" {
		t.Fatalf("expected explicit HTTP/3 addr, got %q", got)
	}
	if got := HTTP3ListenAddr(config.ServerConfig{ListenTLS: "127.0.0.1:9443"}); got != "127.0.0.1:9443" {
		t.Fatalf("expected TLS addr fallback, got %q", got)
	}
	if got := HTTP3ListenAddr(config.ServerConfig{}); got != ":443" {
		t.Fatalf("expected default HTTPS addr, got %q", got)
	}
}

func TestHTTP3AltSvcValue(t *testing.T) {
	got, err := HTTP3AltSvcValue("127.0.0.1:9443")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != `h3=":9443"; ma=2592000` {
		t.Fatalf("unexpected Alt-Svc value %q", got)
	}
	if _, err := HTTP3AltSvcValue("127.0.0.1"); err == nil {
		t.Fatal("expected invalid address error")
	}
}

func TestHTTP3ServerRequiresCertificate(t *testing.T) {
	cfg := config.Default()
	cfg.Server.HTTP3.Enabled = true
	cfg.TLS.CertFile = ""
	cfg.TLS.KeyFile = ""
	srv := &Server{config: &cfg}

	if _, _, err := srv.HTTP3Server(); err == nil {
		t.Fatal("expected missing certificate error")
	}
}

func TestHTTP3ServerBuildsQUICConfig(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "server.crt")
	keyFile := filepath.Join(dir, "server.key")
	if err := setup.GenerateSelfSignedCertificate(certFile, keyFile, []string{"localhost", "127.0.0.1"}, time.Hour); err != nil {
		t.Fatalf("generate cert: %v", err)
	}

	cfg := config.Default()
	cfg.Server.ListenHTTP3 = "127.0.0.1:9443"
	cfg.Server.HTTP3.Enabled = true
	cfg.Server.HTTP3.ZeroRTT = true
	cfg.Server.IdleTimeout = 17 * time.Second
	cfg.TLS.CertFile = certFile
	cfg.TLS.KeyFile = keyFile
	cfg.Sites[0].WAF.Performance.MaxHeaderBytes = 2048
	t.Logf("h3 cfg enabled=%v max=%d", cfg.Sites[0].Enabled, cfg.Sites[0].WAF.Performance.MaxHeaderBytes)
	certs, err := NewSiteCertificateStore(&cfg)
	if err != nil {
		t.Fatalf("build certificate store: %v", err)
	}
	srv := &Server{config: &cfg, certs: certs}

	h3, altSvc, err := srv.HTTP3Server()
	if err != nil {
		t.Fatalf("build HTTP/3 server: %v", err)
	}
	if h3.Addr != "127.0.0.1:9443" {
		t.Fatalf("unexpected addr %q", h3.Addr)
	}
	if altSvc != `h3=":9443"; ma=2592000` {
		t.Fatalf("unexpected Alt-Svc %q", altSvc)
	}
	if h3.QUICConfig == nil || !h3.QUICConfig.Allow0RTT {
		t.Fatal("expected 0-RTT to be enabled")
	}
	if h3.MaxHeaderBytes != 2048 {
		t.Fatalf("unexpected max header bytes %d", h3.MaxHeaderBytes)
	}
	if h3.ConnContext == nil {
		t.Fatal("expected HTTP/3 connection context when 0-RTT is enabled")
	}
}

func TestMaxHeaderBytesUsesSmallestEnabledSiteLimit(t *testing.T) {
	cfg := config.Default()
	t.Logf("default enabled=%v max=%d sites=%d", cfg.Sites[0].Enabled, cfg.Sites[0].WAF.Performance.MaxHeaderBytes, len(cfg.Sites))
	cfg.Sites[0].WAF.Performance.MaxHeaderBytes = 8192
	cfg.Sites = append(cfg.Sites, config.SiteConfig{
		Enabled: true,
		WAF:     config.WAFConfig{Performance: config.PerformanceTuningConfig{MaxHeaderBytes: 2048}},
	})
	if got := maxHeaderBytes(&cfg); got != 2048 {
		t.Fatalf("maxHeaderBytes=%d, want 2048", got)
	}
	cfg.Sites[1].Enabled = false
	if got := maxHeaderBytes(&cfg); got != 8192 {
		t.Fatalf("disabled site limit affected maxHeaderBytes=%d, want 8192", got)
	}
}

type replayTestConnection struct {
	state     quic.ConnectionState
	handshake <-chan struct{}
}

func (c replayTestConnection) ConnectionState() quic.ConnectionState { return c.state }
func (c replayTestConnection) HandshakeComplete() <-chan struct{}    { return c.handshake }

func TestWithQUICReplayGuardRejectsUnsafe0RTTMethods(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	})
	handler := withQUICReplayGuard(next)
	openHandshake := make(chan struct{})
	ctx := context.WithValue(context.Background(), quicReplayConnectionKey{}, replayTestConnection{
		state: quic.ConnectionState{Used0RTT: true}, handshake: openHandshake,
	})
	request := httptest.NewRequest(http.MethodPost, "/write", nil).WithContext(ctx)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusTooEarly || called {
		t.Fatalf("unsafe 0-RTT request code=%d called=%v", recorder.Code, called)
	}

	called = false
	request = httptest.NewRequest(http.MethodGet, "/read", nil).WithContext(ctx)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNoContent || !called {
		t.Fatalf("safe 0-RTT request code=%d called=%v", recorder.Code, called)
	}

	// Once the handshake completes, a normal unsafe method on the same resumed
	// connection is ordinary 1-RTT traffic and must not be rejected forever.
	close(openHandshake)
	called = false
	request = httptest.NewRequest(http.MethodPost, "/write-after-handshake", nil).WithContext(ctx)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNoContent || !called {
		t.Fatalf("post-handshake request code=%d called=%v", recorder.Code, called)
	}
}

func TestWithAltSvc(t *testing.T) {
	handler := withAltSvc(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), `h3=":9443"; ma=2592000`)
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))

	if got := recorder.Header().Get("Alt-Svc"); got != `h3=":9443"; ma=2592000` {
		t.Fatalf("unexpected Alt-Svc header %q", got)
	}
}
