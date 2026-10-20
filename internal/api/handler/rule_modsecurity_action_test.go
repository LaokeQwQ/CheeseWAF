package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
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
