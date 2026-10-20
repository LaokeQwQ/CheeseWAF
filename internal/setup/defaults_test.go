package setup

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

func TestEnsureDefaultsCreatesConfigAndCertificate(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	bundle, err := EnsureDefaults(DefaultOptions{
		DataDir:   dataDir,
		Hostnames: []string{"127.0.0.1", "localhost", "admin.cheesewaf.test"},
		ValidFor:  time.Hour,
	})
	if err != nil {
		t.Fatalf("EnsureDefaults() error = %v", err)
	}

	for _, path := range []string{bundle.Paths.ConfigFile, bundle.Paths.CertFile, bundle.Paths.KeyFile} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected %s to exist: %v", path, err)
		}
	}

	if _, err := tls.LoadX509KeyPair(bundle.Paths.CertFile, bundle.Paths.KeyFile); err != nil {
		t.Fatalf("generated TLS pair is invalid: %v", err)
	}

	config, err := os.ReadFile(bundle.Paths.ConfigFile)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if !bytes.Contains(config, []byte("three_end_unified: true")) {
		t.Fatalf("default config should keep the three-end unified flag")
	}
	if bytes.Contains(config, []byte("change-me-in-production")) {
		t.Fatalf("default config must not write the placeholder bot secret")
	}
	if bytes.Contains(config, []byte("admin_public: true")) || !bytes.Contains(config, []byte("enabled: true")) {
		t.Fatalf("default config should keep the admin listener private while enabling TLS")
	}
}

func TestEnsureDefaultsDoesNotOverwriteExistingConfig(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	configPath := DefaultConfigPath(dataDir)
	if err := os.MkdirAll(filepath.Dir(configPath), 0o750); err != nil {
		t.Fatalf("mkdir config dir: %v", err)
	}
	if err := os.WriteFile(configPath, []byte("custom: true\n"), 0o640); err != nil {
		t.Fatalf("write custom config: %v", err)
	}

	if _, err := EnsureDefaults(DefaultOptions{DataDir: dataDir}); err != nil {
		t.Fatalf("EnsureDefaults() error = %v", err)
	}

	config, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if string(config) != "custom: true\n" {
		t.Fatalf("config was overwritten: %q", string(config))
	}
}

func TestBootstrapTemplateMatchesGeneratedAdminProfile(t *testing.T) {
	t.Parallel()

	generatedPath := filepath.Join(t.TempDir(), DefaultConfigFile)
	generatedDir := t.TempDir()
	generated := filepath.Join(generatedDir, DefaultConfigFile)
	paths := ResolveDefaultPaths(DefaultOptions{DataDir: generatedDir, ConfigPath: generated})
	if err := os.WriteFile(generatedPath, DefaultConfigYAML(paths), 0o640); err != nil {
		t.Fatalf("write generated bootstrap config: %v", err)
	}
	sample, err := config.Load("../../configs/cheesewaf.yaml")
	if err != nil {
		t.Fatalf("load repository bootstrap config: %v", err)
	}
	generatedConfig, err := config.Load(generatedPath)
	if err != nil {
		t.Fatalf("load generated bootstrap config: %v", err)
	}
	if sample.Server.AdminListen != generatedConfig.Server.AdminListen ||
		sample.Server.AdminPublic != generatedConfig.Server.AdminPublic ||
		sample.Server.AdminTLS.Enabled != generatedConfig.Server.AdminTLS.Enabled ||
		sample.Console.Login.CAPTCHA.MaxNumber != generatedConfig.Console.Login.CAPTCHA.MaxNumber ||
		sample.Protection.Bot.CAPTCHABlockDuration != generatedConfig.Protection.Bot.CAPTCHABlockDuration ||
		sample.Protection.Bot.AltchaMaxNumber != generatedConfig.Protection.Bot.AltchaMaxNumber {
		t.Fatalf("repository and generated bootstrap profiles diverged: sample server=%+v generated server=%+v", sample.Server, generatedConfig.Server)
	}
}

func TestGenerateSelfSignedCertificateIncludesSANsAndPrivateCA(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	certFile := filepath.Join(dir, "admin.crt")
	keyFile := filepath.Join(dir, "admin.key")
	if err := GenerateSelfSignedCertificate(certFile, keyFile, []string{"127.0.0.1", "admin.local"}, time.Hour); err != nil {
		t.Fatalf("GenerateSelfSignedCertificate() error = %v", err)
	}
	for _, path := range []string{filepath.Join(dir, DefaultAdminCAFile), filepath.Join(dir, DefaultAdminCAKeyFile)} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected %s to exist: %v", path, err)
		}
	}

	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	certs := parsePEMCerts(t, certPEM)
	if len(certs) != 2 {
		t.Fatalf("expected leaf + ca chain, got %d certs", len(certs))
	}
	cert := certs[0]
	ca := certs[1]

	if err := cert.VerifyHostname("127.0.0.1"); err != nil {
		t.Fatalf("certificate should verify IP SAN: %v", err)
	}
	if err := cert.VerifyHostname("admin.local"); err != nil {
		t.Fatalf("certificate should verify DNS SAN: %v", err)
	}
	if !ca.IsCA {
		t.Fatal("second certificate should be a CA")
	}
	if ca.Subject.CommonName != defaultCACommonName {
		t.Fatalf("unexpected CA CN: %q", ca.Subject.CommonName)
	}
	if len(ca.Subject.Organization) != 1 || ca.Subject.Organization[0] != defaultOrganization {
		t.Fatalf("unexpected CA organization: %+v", ca.Subject.Organization)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	if _, err := cert.Verify(x509.VerifyOptions{DNSName: "admin.local", Roots: roots}); err != nil {
		t.Fatalf("leaf certificate should verify against generated CA: %v", err)
	}
}

func TestWizardSetupLock(t *testing.T) {
	t.Parallel()

	wizard := NewWizard(t.TempDir())
	if !wizard.NeedsSetup() {
		t.Fatal("new data dir should need setup")
	}
	if err := wizard.MarkComplete(); err != nil {
		t.Fatalf("MarkComplete() error = %v", err)
	}
	if wizard.NeedsSetup() {
		t.Fatal("completed data dir should not need setup")
	}
}

func TestWizardSetupHandlerCreatesAdminAndMarksComplete(t *testing.T) {
	dataDir := t.TempDir()
	wizard := NewWizard(dataDir)
	wizard.AdminAPI = "127.0.0.1:9443"
	bundle, err := wizard.PrepareDefaults()
	if err != nil {
		t.Fatalf("PrepareDefaults() error = %v", err)
	}
	done := make(chan struct{})
	handler := wizard.setupHTTPHandler(bundle, done)
	body := `{"username":"admin","password":"Correct-Horse-9x!","admin_listen":"127.0.0.1:9444"}`
	req := httptest.NewRequest(http.MethodPost, "/api/setup", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("setup returned %d: %s", rr.Code, rr.Body.String())
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("setup handler did not signal completion")
	}
	if wizard.NeedsSetup() {
		t.Fatal("setup lock was not written")
	}
	store, err := storage.OpenSQLite(bundle.Paths.SQLiteFile)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer store.Close()
	users, err := store.ListUsers(context.Background())
	if err != nil {
		t.Fatalf("list users: %v", err)
	}
	if len(users) != 1 || users[0].Username != "admin" {
		t.Fatalf("unexpected users %+v", users)
	}
	cfg, err := config.Load(bundle.Paths.ConfigFile)
	if err != nil {
		t.Fatalf("reload config: %v", err)
	}
	if cfg.Server.AdminListen != "127.0.0.1:9444" {
		t.Fatalf("admin listener was not persisted: %q", cfg.Server.AdminListen)
	}
	if !cfg.Console.Login.SecurityEntry.Enabled || !regexp.MustCompile(`^/[A-Za-z0-9]{8,64}$`).MatchString(cfg.Console.Login.SecurityEntry.Path) {
		t.Fatalf("security entry was not generated for web setup: %+v", cfg.Console.Login.SecurityEntry)
	}
}

func TestWizardSetupHandlerAppliesSecurityHeadersAndMinimizesStatus(t *testing.T) {
	dataDir := t.TempDir()
	wizard := NewWizard(dataDir)
	bundle, err := wizard.PrepareDefaults()
	if err != nil {
		t.Fatalf("PrepareDefaults() error = %v", err)
	}
	handler := wizard.setupHTTPHandler(bundle, make(chan struct{}))

	request := httptest.NewRequest(http.MethodGet, "/api/setup/status", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status endpoint returned %d: %s", response.Code, response.Body.String())
	}
	for name, want := range map[string]string{
		"Cache-Control":                "no-store",
		"X-Frame-Options":              "DENY",
		"X-Content-Type-Options":       "nosniff",
		"Referrer-Policy":              "no-referrer",
		"Cross-Origin-Opener-Policy":   "same-origin",
		"Cross-Origin-Resource-Policy": "same-origin",
	} {
		if got := response.Header().Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	for _, want := range []string{"default-src 'self'", "frame-ancestors 'none'", "script-src 'none'"} {
		if !strings.Contains(response.Header().Get("Content-Security-Policy"), want) {
			t.Errorf("CSP %q does not contain %q", response.Header().Get("Content-Security-Policy"), want)
		}
	}
	if got := response.Header().Get("Strict-Transport-Security"); got != "" {
		t.Errorf("HTTP setup response must not advertise HSTS, got %q", got)
	}
	for _, secret := range []string{bundle.Paths.ConfigFile, bundle.Paths.CertFile, bundle.Paths.SQLiteFile} {
		if strings.Contains(response.Body.String(), secret) {
			t.Errorf("anonymous setup status exposed server path %q: %s", secret, response.Body.String())
		}
	}

	tlsRequest := httptest.NewRequest(http.MethodGet, "/api/setup/status", nil)
	tlsRequest.TLS = &tls.ConnectionState{}
	tlsResponse := httptest.NewRecorder()
	handler.ServeHTTP(tlsResponse, tlsRequest)
	if got := tlsResponse.Header().Get("Strict-Transport-Security"); got == "" {
		t.Fatal("TLS setup response must include HSTS")
	}
}

func TestWizardSetupHandlerRejectsTrailingJSON(t *testing.T) {
	wizard := NewWizard(t.TempDir())
	bundle, err := wizard.PrepareDefaults()
	if err != nil {
		t.Fatalf("PrepareDefaults() error = %v", err)
	}
	handler := wizard.setupHTTPHandler(bundle, make(chan struct{}))
	request := httptest.NewRequest(http.MethodPost, "/api/setup", strings.NewReader(`{"username":"admin","password":"Correct-Horse-9x!"} {}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("trailing JSON returned %d, want 400: %s", response.Code, response.Body.String())
	}
	if !wizard.NeedsSetup() {
		t.Fatal("rejected setup request marked setup complete")
	}
}

func TestWizardSetupCanEnablePublicAdminTLS(t *testing.T) {
	dataDir := t.TempDir()
	wizard := NewWizard(dataDir)
	bundle, err := wizard.PrepareDefaults()
	if err != nil {
		t.Fatalf("PrepareDefaults() error = %v", err)
	}
	payload := SetupPayload{
		Username:          "admin",
		Password:          "Correct-Horse-9x!",
		AdminListen:       "0.0.0.0:9443",
		AdminStrategy:     "public_tls",
		SecurityEntryPath: "InstallerEntry123",
	}
	if err := wizard.completeSetup(context.Background(), bundle, payload); err != nil {
		t.Fatalf("completeSetup() error = %v", err)
	}
	cfg, err := config.Load(bundle.Paths.ConfigFile)
	if err != nil {
		t.Fatalf("reload config: %v", err)
	}
	if !cfg.Server.AdminPublic || !cfg.Server.AdminTLS.Enabled {
		t.Fatalf("public admin TLS was not persisted: %+v", cfg.Server)
	}
	if !cfg.Console.Login.SecurityEntry.Enabled || cfg.Console.Login.SecurityEntry.Path != "/InstallerEntry123" {
		t.Fatalf("security entry was not preserved and enabled: %+v", cfg.Console.Login.SecurityEntry)
	}
}

func TestCompleteSetupRejectsPublicAdminWithoutPublicTLS(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	wizard := NewWizard(dataDir)
	bundle, err := wizard.PrepareDefaults()
	if err != nil {
		t.Fatalf("PrepareDefaults() error = %v", err)
	}
	payload := SetupPayload{
		Username:    "admin",
		Password:    "Correct-Horse-9x!",
		AdminListen: "0.0.0.0:9443",
	}
	if err := wizard.completeSetup(context.Background(), bundle, payload); err == nil {
		t.Fatal("expected setup to reject public admin listener without public TLS strategy")
	}
	store, err := storage.OpenSQLite(bundle.Paths.SQLiteFile)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer store.Close()
	users, err := store.ListUsers(context.Background())
	if err != nil {
		t.Fatalf("list users: %v", err)
	}
	if len(users) != 0 {
		t.Fatalf("setup should not create admin user on validation failure: %+v", users)
	}
	if !wizard.NeedsSetup() {
		t.Fatal("setup lock should not be written on validation failure")
	}
}

func parsePEMCerts(t *testing.T, raw []byte) []*x509.Certificate {
	t.Helper()
	var certs []*x509.Certificate
	for len(raw) > 0 {
		var block *pem.Block
		block, raw = pem.Decode(raw)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("parse cert: %v", err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		t.Fatal("certificate PEM was empty")
	}
	return certs
}
