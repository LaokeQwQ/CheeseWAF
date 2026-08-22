package handler

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
)

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
			rules, err := store.ListRules(t.Context(), site.ID)
			if err != nil {
				t.Fatal(err)
			}
			if len(rules) != 0 {
				t.Fatalf("invalid rule reached storage: %+v", rules)
			}
		})
	}
}
