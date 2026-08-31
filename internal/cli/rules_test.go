package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

func TestImportSiteCustomRulesKeepsOldOnInvalidFile(t *testing.T) {
	store, cfgPath, siteID := rulesTestStore(t)
	old := []storage.SiteCustomRule{{
		ID: "old", Name: "old", Pattern: "old-token", Location: "uri", Action: "block", Severity: "low", Enabled: true, Priority: 9,
	}}
	site, err := store.GetSite(context.Background(), siteID)
	if err != nil {
		t.Fatal(err)
	}
	site.Advanced.CustomRules = old
	if err := store.UpdateSite(context.Background(), site); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(bad, []byte("custom_rules:\n  - id: x\n    pattern: \"(\"\n    location: uri\n    action: block\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := importSiteCustomRules(context.Background(), siteID, bad); err == nil {
		t.Fatal("expected invalid import error")
	}
	updated, err := store.GetSite(context.Background(), siteID)
	if err != nil {
		t.Fatal(err)
	}
	if len(updated.Advanced.CustomRules) != 1 || updated.Advanced.CustomRules[0].ID != "old" {
		t.Fatalf("old rules must remain: %+v", updated.Advanced.CustomRules)
	}
	loaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Sites[0].WAF.CustomRules) != 0 {
		t.Fatalf("invalid import must not rewrite config: %+v", loaded.Sites[0].WAF.CustomRules)
	}
}

func TestImportSiteCustomRulesRejectsDuplicateRules(t *testing.T) {
	store, cfgPath, siteID := rulesTestStore(t)
	file := filepath.Join(t.TempDir(), "ok.yaml")
	body := `custom_rules:
  - id: keep
    name: first
    pattern: admin
    location: uri
    action: block
    severity: medium
    enabled: true
    priority: 10
  - id: keep
    name: second
    pattern: other
    location: uri
    action: block
    severity: medium
    enabled: true
    priority: 11
`
	if err := os.WriteFile(file, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := importSiteCustomRules(context.Background(), siteID, file); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate import must fail, got %v", err)
	}
	updated, err := store.GetSite(context.Background(), siteID)
	if err != nil {
		t.Fatal(err)
	}
	if len(updated.Advanced.CustomRules) != 0 {
		t.Fatalf("duplicate import must not modify site rules: %+v", updated.Advanced.CustomRules)
	}
	loaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Sites[0].WAF.CustomRules) != 0 {
		t.Fatalf("duplicate import must not modify config: %+v", loaded.Sites[0].WAF.CustomRules)
	}
}

func TestExportSiteCustomRulesRoundTripJSON(t *testing.T) {
	store, _, siteID := rulesTestStore(t)
	site, err := store.GetSite(context.Background(), siteID)
	if err != nil {
		t.Fatal(err)
	}
	site.Advanced.CustomRules = []storage.SiteCustomRule{{
		ID: "exp", Name: "exp", Pattern: "exp-token", Location: "header", Action: "log", Severity: "high", Enabled: true, Priority: 4,
	}}
	if err := store.UpdateSite(context.Background(), site); err != nil {
		t.Fatal(err)
	}
	body, err := exportSiteCustomRules(context.Background(), siteID, "json")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "exp-token") {
		t.Fatalf("export missing pattern: %s", body)
	}
	parsed, err := config.ParseCustomRules(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed) != 1 || parsed[0].Location != "header" {
		t.Fatalf("parse export: %+v", parsed)
	}
}

func rulesTestStore(t *testing.T) (*storage.SQLiteStore, string, string) {
	t.Helper()
	originalConfigPath := configPath
	originalDataDir := dataDir
	t.Cleanup(func() {
		configPath = originalConfigPath
		dataDir = originalDataDir
	})
	root := t.TempDir()
	dataDir = root
	cfgPath := filepath.Join(root, "cheesewaf.yaml")
	sqlitePath := filepath.Join(root, "cheesewaf.db")
	configPath = cfgPath
	cfg := config.Default()
	cfg.Setup.DataDir = root
	cfg.Storage.SQLite.Path = sqlitePath
	cfg.Sites = []config.SiteConfig{{
		ID:         "site-a",
		Name:       "site-a",
		Domains:    []string{"example.test"},
		Upstreams:  []config.UpstreamConfig{{Address: "127.0.0.1:9000", Weight: 1}},
		ListenPort: 80,
		Enabled:    true,
		WAF:        config.WAFConfig{Enabled: true, Mode: "block"},
	}}
	if err := config.Save(cfgPath, &cfg); err != nil {
		t.Fatal(err)
	}
	store, err := storage.OpenSQLite(sqlitePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	site := storage.SiteFromConfig(cfg.Sites[0])
	if err := store.CreateSite(context.Background(), &site); err != nil {
		t.Fatal(err)
	}
	return store, cfgPath, site.ID
}
