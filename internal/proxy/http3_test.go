package proxy

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/setup"
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
