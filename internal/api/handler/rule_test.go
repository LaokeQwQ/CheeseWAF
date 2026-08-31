package handler

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
	"github.com/go-chi/chi/v5"
)

var errReloadFailed = errors.New("reload failed")

func TestCreateRuleUsesUnifiedCustomRuleValidation(t *testing.T) {
	h, store, site := newSiteTestHandler(t)
	router := chi.NewRouter()
	router.Post("/rules", h.CreateRule)

	for _, tc := range []struct {
		name string
		body string
	}{
		{name: "invalid regexp", body: `{"site_id":"` + site.ID + `","name":"bad","pattern":"(","location":"body","action":"block","severity":"high","enabled":true,"priority":10}`},
		{name: "invalid action", body: `{"site_id":"` + site.ID + `","name":"bad","pattern":"attack","location":"body","action":"allow-all","severity":"high","enabled":true,"priority":10}`},
		{name: "invalid location", body: `{"site_id":"` + site.ID + `","name":"bad","pattern":"attack","location":"database","action":"block","severity":"high","enabled":true,"priority":10}`},
		{name: "invalid priority", body: `{"site_id":"` + site.ID + `","name":"bad","pattern":"attack","location":"body","action":"block","severity":"high","enabled":true,"priority":1000001}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/rules", bytes.NewBufferString(tc.body)))
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: %s", rec.Code, rec.Body.String())
			}
			updated, err := store.GetSite(t.Context(), site.ID)
			if err != nil {
				t.Fatal(err)
			}
			if len(updated.Advanced.CustomRules) != 0 {
				t.Fatalf("invalid rule reached custom_rules: %+v", updated.Advanced.CustomRules)
			}
		})
	}
}

func TestApplyGeneratedCustomRuleUsesSiteRuleFlow(t *testing.T) {
	h, store, site := newSiteTestHandler(t)
	applied := 0
	h.OnSitesChanged = func([]config.SiteConfig) error {
		applied++
		return nil
	}
	rule := &storage.Rule{
		ID: "generated", SiteID: site.ID, Name: "generated", Description: "created by automation",
		Pattern: "probe", Location: "query", Action: "block", Severity: "high", Enabled: true, Priority: 30,
	}
	if err := h.ApplyGeneratedCustomRule(t.Context(), rule); err != nil {
		t.Fatal(err)
	}
	stored, err := store.GetSite(t.Context(), site.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(stored.Advanced.CustomRules) != 1 || stored.Advanced.CustomRules[0].Description != rule.Description {
		t.Fatalf("generated rule did not reach site custom rules: %+v", stored.Advanced.CustomRules)
	}
	if applied != 1 {
		t.Fatalf("generated rule must hot reload once, got %d", applied)
	}
}

func TestCreateRulePreservesRestartOnlyValuesAlreadySavedOnDisk(t *testing.T) {
	h, store, site := newSiteTestHandler(t)
	disk, err := config.Load(h.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	disk.Server.Listen = ":65501"
	if err := config.Save(h.ConfigPath, disk); err != nil {
		t.Fatal(err)
	}
	h.OnSitesChanged = func([]config.SiteConfig) error { return nil }

	router := chi.NewRouter()
	router.Post("/rules", h.CreateRule)
	body := fmt.Sprintf(`{"site_id":%q,"name":"preserve","pattern":"probe","location":"uri","action":"block","severity":"low","enabled":true,"priority":10}`, site.ID)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("create rule status = %d: %s", rec.Code, rec.Body.String())
	}
	stored, err := config.Load(h.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Server.Listen != ":65501" {
		t.Fatalf("rule save overwrote restart-only listen value: %q", stored.Server.Listen)
	}
	if len(stored.Sites[0].WAF.CustomRules) != 1 {
		t.Fatalf("rule was not persisted with disk value: %+v", stored.Sites[0].WAF.CustomRules)
	}
	_ = store
}

func TestImportCustomRulesRejectsDuplicatesAndKeepsOldRules(t *testing.T) {
	h, store, site := newSiteTestHandler(t)
	applied := 0
	h.OnSitesChanged = func(sites []config.SiteConfig) error {
		applied++
		return nil
	}
	site.Advanced.CustomRules = []storage.SiteCustomRule{{
		ID: "old", Name: "old", Pattern: "old-token", Location: "uri", Action: "block", Severity: "low", Enabled: true, Priority: 10,
	}}
	if err := store.UpdateSite(t.Context(), &site); err != nil {
		t.Fatal(err)
	}
	router := chi.NewRouter()
	router.Post("/rules/import", h.ImportCustomRules)
	body := `custom_rules:
  - id: dup
    name: first
    pattern: admin
    location: uri
    action: block
    severity: medium
    enabled: true
    priority: 20
  - id: dup
    name: second
    pattern: other
    location: uri
    action: block
    severity: medium
    enabled: true
    priority: 21
`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/rules/import?site_id="+site.ID, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/yaml")
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	updated, err := store.GetSite(t.Context(), site.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(updated.Advanced.CustomRules) != 1 || updated.Advanced.CustomRules[0].ID != "old" {
		t.Fatalf("duplicate import must keep the old rules, got %+v", updated.Advanced.CustomRules)
	}
	if applied != 0 {
		t.Fatalf("duplicate import must not hot reload, got %d", applied)
	}
}

func TestImportCustomRulesKeepsOldOnInvalid(t *testing.T) {
	h, store, site := newSiteTestHandler(t)
	h.OnSitesChanged = func(sites []config.SiteConfig) error {
		t.Fatal("hot reload must not run on invalid import")
		return nil
	}
	site.Advanced.CustomRules = []storage.SiteCustomRule{{
		ID: "old", Name: "old", Pattern: "old-token", Location: "uri", Action: "block", Severity: "low", Enabled: true, Priority: 10,
	}}
	if err := store.UpdateSite(t.Context(), &site); err != nil {
		t.Fatal(err)
	}
	router := chi.NewRouter()
	router.Post("/rules/import", h.ImportCustomRules)
	body := `custom_rules:
  - id: bad
    name: bad
    pattern: "("
    location: uri
    action: block
    severity: medium
    enabled: true
`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/rules/import?site_id="+site.ID, strings.NewReader(body))
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "RULES_IMPORT_INVALID") {
		t.Fatalf("expected import error payload, got %s", rec.Body.String())
	}
	updated, err := store.GetSite(t.Context(), site.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(updated.Advanced.CustomRules) != 1 || updated.Advanced.CustomRules[0].ID != "old" {
		t.Fatalf("old rules must remain: %+v", updated.Advanced.CustomRules)
	}
}

func TestExampleCustomRulesDownload(t *testing.T) {
	h, _, _ := newSiteTestHandler(t)
	router := chi.NewRouter()
	router.Get("/rules/example", h.ExampleCustomRules)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/rules/example?format=json", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Header().Get("Content-Disposition"), "custom_rules.example.json") {
		t.Fatalf("disposition = %q", rec.Header().Get("Content-Disposition"))
	}
	parsed, err := config.ParseCustomRules(rec.Body.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed) == 0 || parsed[0].ID != "block-admin-probe" {
		t.Fatalf("example rules: %+v", parsed)
	}
}

func TestReloadLiveConfigKeepsPreviousOnApplyFailure(t *testing.T) {
	h, _, _ := newSiteTestHandler(t)
	original := h.currentConfig()
	if original == nil || len(original.Sites) == 0 {
		t.Fatal("expected seeded site config")
	}
	next, err := config.Clone(original)
	if err != nil {
		t.Fatal(err)
	}
	next.Sites[0].WAF.CustomRules = []config.CustomRuleConfig{{
		ID: "live", Name: "live", Pattern: "token", Location: "uri", Action: "block", Severity: "low", Enabled: true, Priority: 5,
	}}
	applied := 0
	h.OnSitesChanged = func(sites []config.SiteConfig) error {
		applied++
		if len(sites) > 0 && len(sites[0].WAF.CustomRules) > 0 {
			return errReloadFailed
		}
		return nil
	}
	if err := h.ReloadLiveConfig(next); err == nil {
		t.Fatal("expected apply failure")
	}
	current := h.currentConfig()
	if len(current.Sites[0].WAF.CustomRules) != 0 {
		t.Fatalf("published config should keep old rules: %+v", current.Sites[0].WAF.CustomRules)
	}
	if applied < 1 {
		t.Fatal("expected apply attempt")
	}
}

func TestReloadLiveConfigPublishesOnlyHotAppliedSettings(t *testing.T) {
	h, store, site := newSiteTestHandler(t)
	h.OnSitesChanged = func([]config.SiteConfig) error { return nil }
	original := h.currentConfig()
	if original == nil {
		t.Fatal("expected live config")
	}
	originalListen := original.Server.Listen
	next, err := config.Clone(original)
	if err != nil {
		t.Fatal(err)
	}
	next.Server.Listen = ":65501"
	next.Sites[0].WAF.CustomRules = []config.CustomRuleConfig{{
		ID: "hot", Name: "hot", Pattern: "hot-token", Location: "uri", Action: "block", Severity: "low", Enabled: true, Priority: 4,
	}}
	if err := h.ReloadLiveConfig(next); err != nil {
		t.Fatal(err)
	}
	current := h.currentConfig()
	if current.Server.Listen != originalListen {
		t.Fatalf("listen %q published as live, want running %q", current.Server.Listen, originalListen)
	}
	if len(current.Sites[0].WAF.CustomRules) != 1 || current.Sites[0].WAF.CustomRules[0].ID != "hot" {
		t.Fatalf("hot custom rules missing: %+v", current.Sites[0].WAF.CustomRules)
	}
	stored, err := store.GetSite(t.Context(), site.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(stored.Advanced.CustomRules) != 1 || stored.Advanced.CustomRules[0].ID != "hot" {
		t.Fatalf("store custom rules: %+v", stored.Advanced.CustomRules)
	}
}

func TestReplaceStoreSitesRestoresSnapshotOnFailure(t *testing.T) {
	h, store, first := newSiteTestHandler(t)
	h.OnSitesChanged = func([]config.SiteConfig) error { return nil }
	second := storage.Site{
		ID:         "site-two",
		Name:       "site-two",
		Domains:    []string{"two.example.test"},
		Upstreams:  []string{"127.0.0.1:9001"},
		ListenPort: 80,
		WAFEnabled: true,
		WAFMode:    "block",
		Enabled:    true,
	}
	if err := store.CreateSite(t.Context(), &second); err != nil {
		t.Fatal(err)
	}
	original := h.currentConfig()
	next, err := config.Clone(original)
	if err != nil {
		t.Fatal(err)
	}
	if len(next.Sites) < 1 {
		t.Fatal("expected a site in config")
	}
	next.Sites = append(next.Sites, storage.SiteToConfig(second))
	next.Sites[0].WAF.CustomRules = []config.CustomRuleConfig{{
		ID: "a", Name: "a", Pattern: "token-a", Location: "uri", Action: "block", Severity: "low", Enabled: true, Priority: 1,
	}}
	next.Sites[1].WAF.CustomRules = []config.CustomRuleConfig{{
		ID: "b", Name: "b", Pattern: "token-b", Location: "uri", Action: "block", Severity: "low", Enabled: true, Priority: 1,
	}}
	h.Store = &failAfterUpdatesStore{Store: store, failOn: 2}
	if err := h.ReloadLiveConfig(next); err == nil {
		t.Fatal("expected store sync failure")
	}
	gotFirst, err := store.GetSite(t.Context(), first.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(gotFirst.Advanced.CustomRules) != 0 {
		t.Fatalf("first site left half-updated: %+v", gotFirst.Advanced.CustomRules)
	}
	gotSecond, err := store.GetSite(t.Context(), second.ID)
	if err != nil {
		t.Fatal(err)
	}
	if gotSecond == nil || len(gotSecond.Advanced.CustomRules) != 0 {
		t.Fatalf("second site left half-updated: %+v", gotSecond)
	}
}

func TestConcurrentCreateRulesKeepAllWrites(t *testing.T) {
	h, store, site := newSiteTestHandler(t)
	h.OnSitesChanged = func([]config.SiteConfig) error { return nil }
	router := chi.NewRouter()
	router.Post("/rules", h.CreateRule)
	const n = 20
	var wg sync.WaitGroup
	errs := make(chan error, n)
	wg.Add(n)
	for i := 0; i < n; i++ {
		i := i
		go func() {
			defer wg.Done()
			body := fmt.Sprintf(`{"site_id":%q,"id":"r-%d","name":"r-%d","pattern":"p%d","location":"uri","action":"block","severity":"low","enabled":true,"priority":%d}`, site.ID, i, i, i, i+1)
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(body)))
			if rec.Code != http.StatusOK {
				errs <- fmt.Errorf("create r-%d status %d: %s", i, rec.Code, rec.Body.String())
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	updated, err := store.GetSite(t.Context(), site.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(updated.Advanced.CustomRules) != n {
		t.Fatalf("concurrent creates dropped rules: got %d want %d (%+v)", len(updated.Advanced.CustomRules), n, updated.Advanced.CustomRules)
	}
}

type failAfterUpdatesStore struct {
	storage.Store
	failOn int
	n      int
}

func (s *failAfterUpdatesStore) UpdateSite(ctx context.Context, site *storage.Site) error {
	s.n++
	if s.failOn > 0 && s.n == s.failOn {
		return errors.New("forced update failure")
	}
	return s.Store.UpdateSite(ctx, site)
}
