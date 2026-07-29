package proxy

import (
	"crypto/tls"
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

func TestParseMinTLSVersion(t *testing.T) {
	if got := parseMinTLSVersion("1.3", tls.VersionTLS12); got != tls.VersionTLS13 {
		t.Fatalf("1.3 => %#x", got)
	}
	if got := parseMinTLSVersion("1.2", tls.VersionTLS13); got != tls.VersionTLS12 {
		t.Fatalf("1.2 => %#x", got)
	}
	if got := parseMinTLSVersion("", tls.VersionTLS13); got != tls.VersionTLS13 {
		t.Fatalf("fallback => %#x", got)
	}
}

func TestSiteCertificateStoreAppliesSiteMinTLS(t *testing.T) {
	store := &SiteCertificateStore{
		minTLSByDomain: map[string]uint16{
			"strict.example.test": tls.VersionTLS13,
			"legacy.example.test": tls.VersionTLS12,
		},
		defaultMinTLS: tls.VersionTLS12,
	}
	if got := store.minTLSForSNI("strict.example.test"); got != tls.VersionTLS13 {
		t.Fatalf("strict min = %#x", got)
	}
	if got := store.minTLSForSNI("legacy.example.test"); got != tls.VersionTLS12 {
		t.Fatalf("legacy min = %#x", got)
	}
	if got := store.minTLSForSNI("other.example.test"); got != tls.VersionTLS12 {
		t.Fatalf("fallback min = %#x", got)
	}
	cfg := store.TLSConfig(config.TLSConfig{MinVersion: "1.2"})
	if cfg.GetConfigForClient == nil {
		t.Fatal("expected GetConfigForClient")
	}
	clientCfg, err := cfg.GetConfigForClient(&tls.ClientHelloInfo{ServerName: "strict.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	if clientCfg.MinVersion != tls.VersionTLS13 {
		t.Fatalf("client min = %#x, want TLS1.3", clientCfg.MinVersion)
	}
}

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
