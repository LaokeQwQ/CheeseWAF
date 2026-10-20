package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

func TestImportModSecurityPreservesDetectionOnlyAction(t *testing.T) {
	store, cfgPath, siteID := rulesTestStore(t)
	file := filepath.Join(t.TempDir(), "rules.conf")
	body := `SecRule REQUEST_URI "@contains observe" "id:observe,phase:2"
SecRule REQUEST_URI "@contains prevent" "id:prevent,deny,log"`
	if err := os.WriteFile(file, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if count, err := importSiteCustomRules(t.Context(), siteID, file); err != nil || count != 2 {
		t.Fatalf("import = %d, %v", count, err)
	}
	updated, err := store.GetSite(t.Context(), siteID)
	if err != nil {
		t.Fatal(err)
	}
	if len(updated.Advanced.CustomRules) != 2 || updated.Advanced.CustomRules[0].Action != "log" || updated.Advanced.CustomRules[1].Action != "block" {
		t.Fatalf("stored import lost action semantics: %+v", updated.Advanced.CustomRules)
	}
	loaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	rules := loaded.Sites[0].WAF.CustomRules
	if len(rules) != 2 || rules[0].Action != "log" || rules[1].Action != "block" {
		t.Fatalf("persisted config lost action semantics: %+v", rules)
	}
}

func TestImportModSecurityRejectsWholeHeaderAndCookieCollectionsAtomically(t *testing.T) {
	for _, tc := range []struct {
		variable string
		operator string
	}{
		{variable: "REQUEST_HEADERS", operator: "rx"},
		{variable: "REQUEST_HEADERS", operator: "streq"},
		{variable: "REQUEST_HEADERS", operator: "contains"},
		{variable: "REQUEST_COOKIES", operator: "rx"},
		{variable: "REQUEST_COOKIES", operator: "streq"},
		{variable: "REQUEST_COOKIES", operator: "contains"},
	} {
		t.Run(tc.variable+"_"+tc.operator, func(t *testing.T) {
			store, cfgPath, siteID := rulesTestStore(t)
			oldRules := []config.CustomRuleConfig{{
				ID: "old", Name: "old", Pattern: "old-token", Location: "header", Action: "block", Severity: "low", Enabled: true,
			}}
			site, err := store.GetSite(t.Context(), siteID)
			if err != nil {
				t.Fatal(err)
			}
			site.Advanced.CustomRules = storage.SiteCustomRulesFromConfig(oldRules)
			if err := store.UpdateSite(t.Context(), site); err != nil {
				t.Fatal(err)
			}
			disk, err := config.Load(cfgPath)
			if err != nil {
				t.Fatal(err)
			}
			disk.Sites[0].WAF.CustomRules = oldRules
			if err := config.Save(cfgPath, disk); err != nil {
				t.Fatal(err)
			}
			beforeBytes, err := os.ReadFile(cfgPath)
			if err != nil {
				t.Fatal(err)
			}

			file := filepath.Join(t.TempDir(), "rules.conf")
			body := "SecRule REQUEST_URI \"@contains accepted\" \"id:accepted,deny\"\n" +
				"SecRule " + tc.variable + " \"@" + tc.operator + " rejected\" \"id:rejected,deny\"\n"
			if err := os.WriteFile(file, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			if count, err := importSiteCustomRules(t.Context(), siteID, file); err == nil {
				t.Errorf("whole %s collection with @%s unexpectedly imported %d rules", tc.variable, tc.operator, count)
			} else if !strings.Contains(err.Error(), "unsupported variable") || !strings.Contains(err.Error(), tc.variable) {
				t.Errorf("whole %s collection with @%s returned wrong error: %v", tc.variable, tc.operator, err)
			}
			updated, err := store.GetSite(t.Context(), siteID)
			if err != nil {
				t.Fatal(err)
			}
			if got := storage.SiteCustomRulesToConfig(updated.Advanced.CustomRules); !reflect.DeepEqual(got, oldRules) {
				t.Errorf("failed import changed stored site rules: got=%+v want=%+v", got, oldRules)
			}
			afterBytes, err := os.ReadFile(cfgPath)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(afterBytes, beforeBytes) {
				t.Error("failed import changed persisted config bytes")
			}
		})
	}
}

func TestImportNativeJSONAndYAMLHeaderCookieRules(t *testing.T) {
	for _, tc := range []struct {
		name     string
		body     string
		location string
	}{
		{name: "json header", location: "header", body: `{"custom_rules":[{"id":"json-header","name":"json-header","pattern":"x-test","location":"header","action":"block","severity":"medium","enabled":true}]}`},
		{name: "json cookie", location: "cookie", body: `{"custom_rules":[{"id":"json-cookie","name":"json-cookie","pattern":"session","location":"cookie","action":"log","severity":"low","enabled":true}]}`},
		{name: "yaml header", location: "header", body: "custom_rules:\n  - id: yaml-header\n    name: yaml-header\n    pattern: x-test\n    location: header\n    action: block\n    severity: medium\n    enabled: true\n"},
		{name: "yaml cookie", location: "cookie", body: "custom_rules:\n  - id: yaml-cookie\n    name: yaml-cookie\n    pattern: session\n    location: cookie\n    action: log\n    severity: low\n    enabled: true\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, cfgPath, siteID := rulesTestStore(t)
			file := filepath.Join(t.TempDir(), "rules."+tc.name)
			if err := os.WriteFile(file, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			if count, err := importSiteCustomRules(t.Context(), siteID, file); err != nil || count != 1 {
				t.Fatalf("native %s import = %d, %v", tc.name, count, err)
			}
			updated, err := store.GetSite(t.Context(), siteID)
			if err != nil {
				t.Fatal(err)
			}
			if len(updated.Advanced.CustomRules) != 1 || updated.Advanced.CustomRules[0].Location != tc.location {
				t.Fatalf("native %s import lost location: %+v", tc.name, updated.Advanced.CustomRules)
			}
			loaded, err := config.Load(cfgPath)
			if err != nil {
				t.Fatal(err)
			}
			if len(loaded.Sites) != 1 || len(loaded.Sites[0].WAF.CustomRules) != 1 || loaded.Sites[0].WAF.CustomRules[0].Location != tc.location {
				t.Fatalf("native %s persisted location changed: %+v", tc.name, loaded.Sites)
			}
		})
	}
}
