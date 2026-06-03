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
}

func TestEnsureDefaultsDoesNotOverwriteExistingConfig(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	configPath := filepath.Join(dataDir, DefaultConfigFile)
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

func TestGenerateSelfSignedCertificateIncludesSANs(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	certFile := filepath.Join(dir, "admin.crt")
	keyFile := filepath.Join(dir, "admin.key")
	if err := GenerateSelfSignedCertificate(certFile, keyFile, []string{"127.0.0.1", "admin.local"}, time.Hour); err != nil {
		t.Fatalf("GenerateSelfSignedCertificate() error = %v", err)
	}

	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("certificate PEM was empty")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}

	if err := cert.VerifyHostname("127.0.0.1"); err != nil {
		t.Fatalf("certificate should verify IP SAN: %v", err)
	}
	if err := cert.VerifyHostname("admin.local"); err != nil {
		t.Fatalf("certificate should verify DNS SAN: %v", err)
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
	body := `{"username":"admin","password":"correct-horse-battery","admin_listen":"127.0.0.1:9444"}`
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
}
