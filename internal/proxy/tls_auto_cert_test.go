package proxy

import (
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

// tls.auto_cert starts the listener before ACME has issued anything, so the
// static certificate requirement must not block startup when the operator
// opted in and a site can fill the store later.
func TestTLSServerStartsWithoutStaticCertificateInAutoCertMode(t *testing.T) {
	cfg := config.Default()
	cfg.Server.ListenTLS = "127.0.0.1:0"
	cfg.TLS.CertFile = ""
	cfg.TLS.KeyFile = ""
	cfg.TLS.AutoCert = false
	server, err := NewServer(&cfg, engine.NewPipeline(), noopSink{})
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	if _, err := server.TLSServer(""); err == nil {
		t.Fatal("expected the static certificate requirement to reject startup")
	}

	cfg.TLS.AutoCert = true
	server, err = NewServer(&cfg, engine.NewPipeline(), noopSink{})
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	httpServer, err := server.TLSServer("")
	if err != nil {
		t.Fatalf("auto-cert mode rejected startup: %v", err)
	}
	if httpServer == nil || httpServer.TLSConfig == nil || httpServer.TLSConfig.GetCertificate == nil {
		t.Fatalf("auto-cert server is not SNI-driven: %+v", httpServer)
	}
}
