package handler

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
	"github.com/go-chi/chi/v5"
)

func TestImportModSecurityPreservesDetectionOnlyAction(t *testing.T) {
	h, store, site := newSiteTestHandler(t)
	var applied []config.CustomRuleConfig
	h.OnSitesChanged = func(sites []config.SiteConfig) error {
		for _, updated := range sites {
			if updated.ID == site.ID {
				applied = updated.WAF.CustomRules
			}
		}
		return nil
	}
	router := chi.NewRouter()
	router.Post("/rules/import", h.ImportCustomRules)
	body := `SecRule REQUEST_URI "@contains observe" "id:observe,phase:2"
SecRule REQUEST_URI "@contains prevent" "id:prevent,deny,log"`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/rules/import?site_id="+site.ID, strings.NewReader(body))
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	updated, err := store.GetSite(t.Context(), site.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(updated.Advanced.CustomRules) != 2 || updated.Advanced.CustomRules[0].Action != "log" || updated.Advanced.CustomRules[1].Action != "block" {
		t.Fatalf("stored import lost action semantics: %+v", updated.Advanced.CustomRules)
	}
	if len(applied) != 2 || applied[0].Action != "log" || applied[1].Action != "block" {
		t.Fatalf("hot reload lost action semantics: %+v", applied)
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
			h, store, site := newSiteTestHandler(t)
			applied := 0
			h.OnSitesChanged = func([]config.SiteConfig) error {
				applied++
				return nil
			}
			oldRules := []config.CustomRuleConfig{{
				ID: "old", Name: "old", Pattern: "old-token", Location: "header", Action: "block", Severity: "low", Enabled: true,
			}}
			site.Advanced.CustomRules = storage.SiteCustomRulesFromConfig(oldRules)
			if err := store.UpdateSite(t.Context(), &site); err != nil {
				t.Fatal(err)
			}
			disk, err := config.Load(h.ConfigPath)
			if err != nil {
				t.Fatal(err)
			}
			for index := range disk.Sites {
				if disk.Sites[index].ID == site.ID {
					disk.Sites[index].WAF.CustomRules = oldRules
				}
			}
			if err := config.Save(h.ConfigPath, disk); err != nil {
				t.Fatal(err)
			}
			beforeBytes, err := os.ReadFile(h.ConfigPath)
			if err != nil {
				t.Fatal(err)
			}

			body := "SecRule REQUEST_URI \"@contains accepted\" \"id:accepted,deny\"\n" +
				"SecRule " + tc.variable + " \"@" + tc.operator + " rejected\" \"id:rejected,deny\"\n"
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/rules/import?site_id="+site.ID, strings.NewReader(body))
			h.ImportCustomRules(rec, req)
			if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "RULES_IMPORT_INVALID") {
				t.Errorf("whole %s collection with @%s must fail atomically: status=%d body=%s", tc.variable, tc.operator, rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), "unsupported variable") || !strings.Contains(rec.Body.String(), tc.variable) {
				t.Errorf("unsupported collection must report its variable: %s", rec.Body.String())
			}
			if applied != 0 {
				t.Errorf("failed import hot reloaded %d times", applied)
			}
			updated, err := store.GetSite(t.Context(), site.ID)
			if err != nil {
				t.Fatal(err)
			}
			if got := storage.SiteCustomRulesToConfig(updated.Advanced.CustomRules); !reflect.DeepEqual(got, oldRules) {
				t.Errorf("failed import changed stored site rules: got=%+v want=%+v", got, oldRules)
			}
			afterBytes, err := os.ReadFile(h.ConfigPath)
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
			h, store, site := newSiteTestHandler(t)
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/rules/import?site_id="+site.ID, strings.NewReader(tc.body))
			h.ImportCustomRules(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("native %s import status = %d: %s", tc.name, rec.Code, rec.Body.String())
			}
			updated, err := store.GetSite(t.Context(), site.ID)
			if err != nil {
				t.Fatal(err)
			}
			if len(updated.Advanced.CustomRules) != 1 || updated.Advanced.CustomRules[0].Location != tc.location {
				t.Fatalf("native %s import lost location: %+v", tc.name, updated.Advanced.CustomRules)
			}
			loaded, err := config.Load(h.ConfigPath)
			if err != nil {
				t.Fatal(err)
			}
			if len(loaded.Sites) != 1 || len(loaded.Sites[0].WAF.CustomRules) != 1 || loaded.Sites[0].WAF.CustomRules[0].Location != tc.location {
				t.Fatalf("native %s persisted location changed: %+v", tc.name, loaded.Sites)
			}
		})
	}
}
