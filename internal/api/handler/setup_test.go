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
	"time"

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
	drafts := setup.NewDraftStore(time.Minute)
	draft, err := drafts.Create()
	if err != nil {
		t.Fatal(err)
	}
	if !drafts.SetPassword(draft.ID, "Correct-Horse-9x!") {
		t.Fatal("set draft password")
	}
	handler := New(Options{
		Config:      cfg,
		ConfigPath:  bundle.Paths.ConfigFile,
		Store:       store,
		SetupToken:  "local-setup-secret",
		SetupDrafts: drafts,
	})

	body := `{"username":"admin","password":"Correct-Horse-9x!","admin_listen":"0.0.0.0:9443","admin_strategy":"public_tls"}`
	req := httptest.NewRequest(http.MethodPost, "/api/setup", strings.NewReader(body))
	req.RemoteAddr = "127.0.0.1:1234"
	req.AddCookie(&http.Cookie{Name: setup.SetupSessionCookie, Value: draft.ID})
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CheeseWAF-Setup-Token", "local-setup-secret")
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
	if _, ok := drafts.Password(draft.ID); ok {
		t.Fatal("successful setup retained the draft password")
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
		SetupToken: "local-setup-secret",
	})

	body := `{"username":"admin","password":"short","admin_listen":"127.0.0.1:9443"}`
	req := httptest.NewRequest(http.MethodPost, "/api/setup", strings.NewReader(body))
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CheeseWAF-Setup-Token", "local-setup-secret")
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

func TestSetupMutationRequiresTokenForEveryPeer(t *testing.T) {
	cfg := config.Default()
	cfg.Setup.DataDir = t.TempDir()
	h := New(Options{Config: &cfg, SetupToken: "remote-setup-secret"})

	for _, remoteAddr := range []string{"127.0.0.1:1234", "198.51.100.20:1234"} {
		withoutToken := httptest.NewRequest(http.MethodPost, "/api/setup", nil)
		withoutToken.RemoteAddr = remoteAddr
		withoutRecorder := httptest.NewRecorder()
		if h.allowSetupMutation(withoutRecorder, withoutToken) {
			t.Fatalf("setup without token from %s must be rejected", remoteAddr)
		}
		if withoutRecorder.Code != http.StatusUnauthorized {
			t.Fatalf("setup without token from %s returned %d", remoteAddr, withoutRecorder.Code)
		}
		wrongToken := httptest.NewRequest(http.MethodPost, "/api/setup", nil)
		wrongToken.RemoteAddr = remoteAddr
		wrongToken.Header.Set("X-CheeseWAF-Setup-Token", "wrong-token")
		wrongRecorder := httptest.NewRecorder()
		if h.allowSetupMutation(wrongRecorder, wrongToken) || wrongRecorder.Code != http.StatusUnauthorized {
			t.Fatalf("setup with wrong token from %s was accepted: code=%d body=%s", remoteAddr, wrongRecorder.Code, wrongRecorder.Body.String())
		}
	}
	noConfiguredToken := New(Options{Config: &cfg})
	noConfigured := httptest.NewRequest(http.MethodPost, "/api/setup", nil)
	noConfigured.RemoteAddr = "127.0.0.1:1234"
	noConfigured.Header.Set("X-CheeseWAF-Setup-Token", "anything")
	noConfiguredRecorder := httptest.NewRecorder()
	if noConfiguredToken.allowSetupMutation(noConfiguredRecorder, noConfigured) || noConfiguredRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("setup without a server token must fail closed: code=%d body=%s", noConfiguredRecorder.Code, noConfiguredRecorder.Body.String())
	}
	queryToken := httptest.NewRequest(http.MethodPost, "/api/setup?setup_token=remote-setup-secret", nil)
	queryToken.RemoteAddr = "198.51.100.20:1234"
	queryRecorder := httptest.NewRecorder()
	if h.allowSetupMutation(queryRecorder, queryToken) || queryRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("setup token in URL must be rejected: code=%d body=%s", queryRecorder.Code, queryRecorder.Body.String())
	}

	withToken := httptest.NewRequest(http.MethodPost, "/api/setup", nil)
	withToken.RemoteAddr = "198.51.100.20:1234"
	withToken.Header.Set("X-CheeseWAF-Setup-Token", "remote-setup-secret")
	withRecorder := httptest.NewRecorder()
	if !h.allowSetupMutation(withRecorder, withToken) {
		t.Fatalf("remote setup with valid token was rejected: %d %s", withRecorder.Code, withRecorder.Body.String())
	}
}

func TestSetupProbeChecksDraftCapacityBeforeRunningProbe(t *testing.T) {
	cfg := config.Default()
	cfg.Setup.DataDir = t.TempDir()
	drafts := setup.NewDraftStoreWithLimit(time.Minute, 1)
	if _, err := drafts.Create(); err != nil {
		t.Fatal(err)
	}
	probeCalls := 0
	h := New(Options{
		Config:      &cfg,
		SetupToken:  "local-setup-secret",
		SetupDrafts: drafts,
		RunSetupProbe: func(context.Context, string) setup.ProbeResult {
			probeCalls++
			return setup.ProbeResult{}
		},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/setup/probe", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("X-CheeseWAF-Setup-Token", "local-setup-secret")
	recorder := httptest.NewRecorder()
	h.SetupProbe(recorder, req)
	if recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("capacity response = %d, want 429: %s", recorder.Code, recorder.Body.String())
	}
	if probeCalls != 0 {
		t.Fatalf("probe ran %d times after capacity was exhausted", probeCalls)
	}
}

func TestSetupStatusReportsNeedsSetupWithoutToken(t *testing.T) {
	dataDir := t.TempDir()
	cfg := config.Default()
	cfg.Setup.DataDir = dataDir
	h := New(Options{Config: &cfg})
	rec := httptest.NewRecorder()
	h.SetupStatus(rec, httptest.NewRequest(http.MethodGet, "/api/setup/status", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"needs_setup":true`) {
		t.Fatalf("fresh install should need setup: %s", rec.Body.String())
	}
	if err := setup.MarkComplete(dataDir); err != nil {
		t.Fatal(err)
	}
	done := httptest.NewRecorder()
	h.SetupStatus(done, httptest.NewRequest(http.MethodGet, "/api/setup/status", nil))
	if !strings.Contains(done.Body.String(), `"needs_setup":false`) {
		t.Fatalf("completed install should not need setup: %s", done.Body.String())
	}
}

func TestSetupStatusNeverExposesSetupTokenInResponse(t *testing.T) {
	dataDir := t.TempDir()
	cfg := config.Default()
	cfg.Setup.DataDir = dataDir
	cfg.Server.AdminListen = "127.0.0.1:9443"
	h := New(Options{Config: &cfg, SetupToken: "loop-token"})
	loop := httptest.NewRequest(http.MethodGet, "/api/setup/status", nil)
	loop.RemoteAddr = "127.0.0.1:54321"
	rec := httptest.NewRecorder()
	h.SetupStatus(rec, loop)
	body := rec.Body.String()
	if strings.Contains(body, `"setup_url"`) || strings.Contains(body, "loop-token") {
		t.Fatalf("loopback setup status leaked setup token: %s", body)
	}
	remote := httptest.NewRequest(http.MethodGet, "/api/setup/status", nil)
	remote.RemoteAddr = "203.0.113.9:54321"
	out := httptest.NewRecorder()
	h.SetupStatus(out, remote)
	if strings.Contains(out.Body.String(), "setup_url") {
		t.Fatalf("non-loopback must not include setup_url: %s", out.Body.String())
	}
}
