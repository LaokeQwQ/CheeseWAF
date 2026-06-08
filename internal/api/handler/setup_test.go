package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/setup"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

func TestSetupAPIUsesSharedCompletionPath(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	bundle, err := setup.EnsureDefaults(setup.DefaultOptions{DataDir: dataDir})
	if err != nil {
		t.Fatalf("EnsureDefaults() error = %v", err)
	}
	cfg, err := config.Load(bundle.Paths.ConfigFile)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	store, err := storage.OpenSQLite(bundle.Paths.SQLiteFile)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer store.Close()
	if err := store.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate sqlite: %v", err)
	}
	for _, path := range []string{bundle.Paths.CertFile, bundle.Paths.KeyFile, bundle.Paths.CAFile, bundle.Paths.CAKeyFile} {
		if err := os.Remove(path); err != nil {
			t.Fatalf("remove generated cert fixture %s: %v", path, err)
		}
	}
	handler := New(Options{
		Config:     cfg,
		ConfigPath: bundle.Paths.ConfigFile,
		Store:      store,
	})

	body := `{"username":"admin","password":"correct-horse-battery","admin_listen":"0.0.0.0:9443","admin_strategy":"public_tls"}`
	req := httptest.NewRequest(http.MethodPost, "/api/setup", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler.Setup(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("setup returned %d: %s", rr.Code, rr.Body.String())
	}
	var envelope struct {
		Data map[string]any `json:"data"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&envelope); err != nil {
		t.Fatalf("decode setup response: %v", err)
	}
	if envelope.Data["setup_complete"] != true {
		t.Fatalf("setup response should report completion: %+v", envelope.Data)
	}
	if setup.NeedsSetup(dataDir) {
		t.Fatal("setup API should write setup lock")
	}
	users, err := store.ListUsers(context.Background())
	if err != nil {
		t.Fatalf("list users: %v", err)
	}
	if len(users) != 1 || users[0].Username != "admin" || users[0].Role != "admin" {
		t.Fatalf("unexpected setup users: %+v", users)
	}
	reloaded, err := config.Load(bundle.Paths.ConfigFile)
	if err != nil {
		t.Fatalf("reload config: %v", err)
	}
	if !reloaded.Server.AdminPublic || !reloaded.Server.AdminTLS.Enabled {
		t.Fatalf("setup API should persist public TLS admin settings: %+v", reloaded.Server)
	}
	if reloaded.Server.AdminTLS.CertFile == "" || reloaded.Server.AdminTLS.KeyFile == "" {
		t.Fatalf("setup API should persist admin cert paths: %+v", reloaded.Server.AdminTLS)
	}
	for _, path := range []string{bundle.Paths.CertFile, bundle.Paths.KeyFile, bundle.Paths.CAFile, bundle.Paths.CAKeyFile} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("setup API should regenerate admin certificate bundle %s: %v", path, err)
		}
	}
}

func TestSetupAPIValidationFailureDoesNotCreateAdmin(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	bundle, err := setup.EnsureDefaults(setup.DefaultOptions{
		DataDir:    dataDir,
		ConfigPath: filepath.Join(dataDir, "cheesewaf.yaml"),
	})
	if err != nil {
		t.Fatalf("EnsureDefaults() error = %v", err)
	}
	cfg, err := config.Load(bundle.Paths.ConfigFile)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	store, err := storage.OpenSQLite(bundle.Paths.SQLiteFile)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer store.Close()
	if err := store.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate sqlite: %v", err)
	}
	handler := New(Options{
		Config:     cfg,
		ConfigPath: bundle.Paths.ConfigFile,
		Store:      store,
	})

	body := `{"username":"admin","password":"short","admin_listen":"127.0.0.1:9443"}`
	req := httptest.NewRequest(http.MethodPost, "/api/setup", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler.Setup(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("setup returned %d, want 400: %s", rr.Code, rr.Body.String())
	}
	users, err := store.ListUsers(context.Background())
	if err != nil {
		t.Fatalf("list users: %v", err)
	}
	if len(users) != 0 {
		t.Fatalf("setup should not create users on validation failure: %+v", users)
	}
	if !setup.NeedsSetup(dataDir) {
		t.Fatal("setup lock should not be written on validation failure")
	}
}
