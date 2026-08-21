package cli

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/setup"
)

func TestCheckAdminReadinessUsesLoopbackForUnspecifiedListener(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health/ready" {
			t.Fatalf("healthcheck path = %q", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := config.Default()
	cfg.Server.AdminListen = "0.0.0.0" + strings.TrimPrefix(server.URL, "http://127.0.0.1")
	cfg.Server.AdminTLS.Enabled = false
	if err := checkAdminReadiness(context.Background(), &cfg); err != nil {
		t.Fatal(err)
	}
}

func TestCheckAdminReadinessRejectsNonSuccessStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	cfg := config.Default()
	cfg.Server.AdminListen = strings.TrimPrefix(server.URL, "http://")
	cfg.Server.AdminTLS.Enabled = false
	if err := checkAdminReadiness(context.Background(), &cfg); err == nil {
		t.Fatal("unready admin endpoint was accepted")
	}
}

func TestResolveHealthcheckConfigPathPrefersExistingRuntimeFile(t *testing.T) {
	dir := t.TempDir()
	runtimeCfg := filepath.Join(dir, "config", setup.DefaultConfigFile)
	if err := os.MkdirAll(filepath.Dir(runtimeCfg), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(runtimeCfg, []byte("server: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	origConfig, origData := configPath, dataDir
	t.Cleanup(func() {
		configPath, dataDir = origConfig, origData
	})
	t.Setenv("CHEESEWAF_CONFIG", "")
	configPath = filepath.Join(dir, "missing.yaml")
	dataDir = dir
	if got := resolveHealthcheckConfigPath(); got != runtimeCfg {
		t.Fatalf("got %q want %q", got, runtimeCfg)
	}
}

func TestResolveHealthcheckConfigPathUsesEnvWhenFlagMissing(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, "from-env.yaml")
	if err := os.WriteFile(envPath, []byte("server: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	origConfig, origData := configPath, dataDir
	t.Cleanup(func() {
		configPath, dataDir = origConfig, origData
	})
	configPath = filepath.Join(dir, "missing.yaml")
	dataDir = dir
	t.Setenv("CHEESEWAF_CONFIG", envPath)
	if got := resolveHealthcheckConfigPath(); got != envPath {
		t.Fatalf("got %q want %q", got, envPath)
	}
}

func TestProbeOutboundTLSRejectsHTTP(t *testing.T) {
	if err := probeOutboundTLS(context.Background(), "http://127.0.0.1/"); err == nil {
		t.Fatal("http URL was accepted")
	}
}

func TestProbeOutboundTLSFailsWhenPoolEmpty(t *testing.T) {
	orig := loadSystemCertPool
	t.Cleanup(func() { loadSystemCertPool = orig })
	loadSystemCertPool = func() (*x509.CertPool, error) { return nil, nil }
	if err := probeOutboundTLS(context.Background(), "https://example.com/"); err == nil {
		t.Fatal("empty CA pool was accepted")
	}
}

func TestProbeOutboundTLSAcceptsHTTPSWithInjectedPool(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	orig := loadSystemCertPool
	t.Cleanup(func() { loadSystemCertPool = orig })
	loadSystemCertPool = func() (*x509.CertPool, error) {
		pool := x509.NewCertPool()
		pool.AddCert(server.Certificate())
		return pool, nil
	}
	if err := probeOutboundTLS(context.Background(), server.URL); err != nil {
		t.Fatal(err)
	}
}
