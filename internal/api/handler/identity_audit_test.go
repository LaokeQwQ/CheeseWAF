package handler

import (
	"net/http"
	"net/url"
	"path/filepath"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/api/middleware"
)

func TestAuditLoginFailurePreservesExactUsername(t *testing.T) {
	auditor := middleware.NewAuditor(filepath.Join(t.TempDir(), "audit.jsonl"))
	h := &Handler{Auditor: auditor}
	r := &http.Request{Method: http.MethodPost, RemoteAddr: "127.0.0.1:9443", URL: &url.URL{Path: "/api/login"}}
	h.auditLoginFailure(r, " admin ", "invalid_username")

	entries, err := auditor.Query(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].User != " admin " {
		t.Fatalf("audit entry lost exact username: %+v", entries)
	}
}
