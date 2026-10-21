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

func TestImportSiteCustomRulesMergesExistingRules(t *testing.T) {
	store, cfgPath, siteID := rulesTestStore(t)
	site, err := store.GetSite(context.Background(), siteID)
	if err != nil {
		t.Fatal(err)
	}
	site.Advanced.CustomRules = []storage.SiteCustomRule{{
		ID: "keep", Name: "keep", Pattern: "keep-token", Location: "uri", Action: "block", Severity: "low", Enabled: true, Priority: 9,
	}}
	if err := store.UpdateSite(context.Background(), site); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "merge.yaml")
	body := `custom_rules:
  - id: append
    name: append
    pattern: append-token
    location: header
    action: log
    severity: medium
    enabled: true
    priority: 10
`
	if err := os.WriteFile(file, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := importSiteCustomRules(context.Background(), siteID, file); err != nil {
		t.Fatal(err)
	}
	updated, err := store.GetSite(context.Background(), siteID)
	if err != nil {
		t.Fatal(err)
	}
	if len(updated.Advanced.CustomRules) != 2 || updated.Advanced.CustomRules[0].ID != "keep" || updated.Advanced.CustomRules[1].ID != "append" {
		t.Fatalf("import must retain and append rules: %+v", updated.Advanced.CustomRules)
	}
	loaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Sites[0].WAF.CustomRules) != 2 {
		t.Fatalf("merged rules were not persisted to config: %+v", loaded.Sites[0].WAF.CustomRules)
	}
}

func TestImportSiteCustomRulesPreservesMissingIDMergeSemantics(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{"json", `{"custom_rules":[{"name":"renamed","pattern":"probe","location":"request_uri","action":"log","enabled":true},{"name":"keep","pattern":"new-token","location":"request_uri","action":"block","enabled":true}]}`},
		{"yaml", "custom_rules:\n  - name: renamed\n    pattern: probe\n    location: request_uri\n    action: log\n    enabled: true\n  - name: keep\n    pattern: new-token\n    location: request_uri\n    action: block\n    enabled: true\n"},
		{"modsecurity", "SecRule REQUEST_URI \"@contains probe\" \"msg:'renamed',log\"\nSecRule REQUEST_URI \"@contains new-token\" \"msg:'keep',deny\""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, cfgPath, siteID := rulesTestStore(t)
			site, err := store.GetSite(t.Context(), siteID)
			if err != nil {
				t.Fatal(err)
			}
			site.Advanced.CustomRules = []storage.SiteCustomRule{
				{ID: "keep", Name: "keep", Pattern: "keep-token", Location: "request_uri", Action: "block", Severity: "low", Enabled: true},
				{ID: "stable", Name: "old", Pattern: "probe", Location: "request_uri", Action: "block", Severity: "low", Enabled: true},
			}
			if err := store.UpdateSite(t.Context(), site); err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(t.TempDir(), "import.rules")
			if err := os.WriteFile(file, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			for attempt := 0; attempt < 2; attempt++ {
				count, err := importSiteCustomRules(t.Context(), siteID, file)
				if err != nil {
					t.Fatalf("attempt %d: %v", attempt, err)
				}
				if count != 2 {
					t.Fatalf("import count = %d, want input count 2", count)
				}
				updated, err := store.GetSite(t.Context(), siteID)
				if err != nil {
					t.Fatal(err)
				}
				loaded, err := config.Load(cfgPath)
				if err != nil {
					t.Fatal(err)
				}
				for _, rules := range [][]config.CustomRuleConfig{loaded.Sites[0].WAF.CustomRules, storage.SiteCustomRulesToConfig(updated.Advanced.CustomRules)} {
					if len(rules) != 3 || rules[0].ID != "keep" || rules[0].Pattern != "keep-token" || rules[1].ID != "stable" || rules[1].Name != "renamed" || rules[1].Action != "log" || rules[2].ID != "keep-2" || rules[2].Pattern != "new-token" {
						t.Fatalf("missing IDs must preserve matched identities and append unrelated rules: %+v", rules)
					}
				}
			}
		})
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
