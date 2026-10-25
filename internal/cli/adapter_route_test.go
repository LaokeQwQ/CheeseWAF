package cli

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWithAdapterAPIServesAdapterRoutesBeforeFallback(t *testing.T) {
	adapter := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	fallback := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := withAdapterAPI(adapter, fallback)
	for _, path := range []string{
		"/api/v1/adapter/inspect",
		"/api/v1/adapter/telemetry",
		"/healthz",
	} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, path, nil))
		if recorder.Code != http.StatusNoContent {
			t.Errorf("%s status = %d, want adapter handler", path, recorder.Code)
		}
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/version", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("fallback status = %d", recorder.Code)
	}
}
