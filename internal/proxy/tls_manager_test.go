package proxy

import (
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

func TestSiteCertificateStoreDoesNotLoadUnusedDefaultCertificate(t *testing.T) {
	cfg := &config.Config{
		TLS: config.TLSConfig{
			CertFile: "missing-default.crt",
			KeyFile:  "missing-default.key",
		},
	}

	store, err := NewSiteCertificateStore(cfg)
	if err != nil {
		t.Fatalf("NewSiteCertificateStore() error = %v", err)
	}
	if store.HasCertificate() {
		t.Fatal("unused default certificate should not be loaded")
	}
}

func TestSiteCertificateStoreRequiresDefaultCertificateForTLSListener(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{ListenTLS: ":443"},
		TLS: config.TLSConfig{
			CertFile: "missing-default.crt",
			KeyFile:  "missing-default.key",
		},
	}

	_, err := NewSiteCertificateStore(cfg)
	if err == nil || !strings.Contains(err.Error(), "load default tls certificate") {
		t.Fatalf("NewSiteCertificateStore() error = %v, want missing default certificate error", err)
	}
}

func TestSiteCertificateStoreRequiresConfiguredSiteCertificate(t *testing.T) {
	cfg := &config.Config{
		Sites: []config.SiteConfig{{
			Name:      "secure-site",
			Domains:   []string{"example.test"},
			Enabled:   true,
			EnableSSL: true,
			CertFile:  "missing-site.crt",
			KeyFile:   "missing-site.key",
		}},
	}

	_, err := NewSiteCertificateStore(cfg)
	if err == nil || !strings.Contains(err.Error(), `load site "secure-site" tls certificate`) {
		t.Fatalf("NewSiteCertificateStore() error = %v, want missing site certificate error", err)
	}
}

func TestDefaultCertificateRequirementForHTTP3(t *testing.T) {
	tests := []struct {
		name string
		cfg  *config.Config
		want bool
	}{
		{name: "disabled", cfg: &config.Config{Server: config.ServerConfig{ListenHTTP3: ":443"}}},
		{name: "missing address", cfg: &config.Config{Server: config.ServerConfig{HTTP3: config.HTTP3Config{Enabled: true}}}},
		{name: "enabled with address", cfg: &config.Config{Server: config.ServerConfig{ListenHTTP3: ":443", HTTP3: config.HTTP3Config{Enabled: true}}}, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := requiresDefaultTLSCertificate(tt.cfg); got != tt.want {
				t.Fatalf("requiresDefaultTLSCertificate() = %v, want %v", got, tt.want)
			}
		})
	}
}
