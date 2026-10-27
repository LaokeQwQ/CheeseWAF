package config

import (
	"strings"
	"testing"
)

func autoCertTestConfig() Config {
	cfg := Default()
	cfg.Server.ListenTLS = "127.0.0.1:8443"
	cfg.TLS.CertFile = ""
	cfg.TLS.KeyFile = ""
	cfg.Sites = []SiteConfig{{
		ID: "site-1", Name: "site", Domains: []string{"site.example"}, Enabled: true, EnableSSL: true,
		Upstreams:   []UpstreamConfig{{Address: "http://127.0.0.1:9000"}},
		Certificate: SiteCertificateConfig{Mode: "acme"},
	}}
	return cfg
}

// tls.auto_cert is the only way to start the TLS listener before ACME has
// issued a certificate; without it the static requirement still applies.
func TestListenTLSRequiresCertificateUnlessAutoCertHasAnACMESite(t *testing.T) {
	cfg := autoCertTestConfig()
	cfg.TLS.AutoCert = false
	if err := Validate(&cfg); err == nil || !strings.Contains(err.Error(), "auto_cert") {
		t.Fatalf("expected the static certificate requirement, got %v", err)
	}

	cfg.TLS.AutoCert = true
	if err := Validate(&cfg); err != nil {
		t.Fatalf("auto_cert configuration rejected: %v", err)
	}

	// Auto-cert without an ACME site could never fill the store.
	cfg.Sites[0].Certificate.Mode = "file"
	if err := Validate(&cfg); err == nil {
		t.Fatal("auto_cert without an ACME site must be rejected")
	}
}
