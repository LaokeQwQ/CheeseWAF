package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

// TestServerRejectsMatrixSegmentTraversal pins the end-to-end closure: a path
// whose normalization fails is rejected by the existing invalid_path guard
// before any policy, ACL, or upstream call runs.
func TestServerRejectsMatrixSegmentTraversal(t *testing.T) {
	server, _ := newRewriteWAFServer(t, "/target", engine.NewPipeline(), nil)
	for _, target := range []string{
		"/api/v1/x/..;/..;/admin",
		"/..%3b/admin",
		"/admin/..;/..;/manager/html",
		"/foo/..;/admin",
	} {
		rec := httptest.NewRecorder()
		server.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://localhost"+target, nil))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s: status=%d want 400", target, rec.Code)
		}
		if got := rec.Header().Get("X-Upstream-URI"); got != "" {
			t.Fatalf("%s reached the upstream: %q", target, got)
		}
	}
}

// TestServerStripsMatrixParamsBeforeForwarding is the false-positive guard: a
// legacy URL-session path must still be served, not rejected.
func TestServerStripsMatrixParamsBeforeForwarding(t *testing.T) {
	server, _ := newRewriteWAFServer(t, "/target", engine.NewPipeline(), nil)
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://localhost/;jsessionid=ABC123/original", nil))
	if rec.Code == http.StatusBadRequest {
		t.Fatalf("legacy URL-session path was rejected: status=%d", rec.Code)
	}
}
