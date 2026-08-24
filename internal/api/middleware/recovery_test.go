package middleware

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestRecoveryReturnsTraceAndWritesPanicAudit(t *testing.T) {
	auditor := NewAuditor(filepath.Join(t.TempDir(), "audit.jsonl"))
	h := Recovery(auditor)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("secret panic detail")
	}))
	req := httptest.NewRequest(http.MethodPost, "/api/panic", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	var body struct {
		Error struct {
			Code    string `json:"code"`
			TraceID string `json:"trace_id"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Error.Code != "INTERNAL_ERROR" || body.Error.TraceID == "" {
		t.Fatalf("unexpected recovery body: %+v", body)
	}
	if body.Error.Message == "secret panic detail" {
		t.Fatal("panic detail leaked to client")
	}
	entries, err := auditor.Query(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Status != http.StatusInternalServerError || entries[0].Target != "panic" {
		t.Fatalf("panic audit missing: %+v", entries)
	}
	if entries[0].Message != "trace_id="+body.Error.TraceID {
		t.Fatalf("panic audit trace mismatch: %+v", entries[0])
	}
}

func TestRecoveryQuotesControlCharactersAndOmitsStack(t *testing.T) {
	var logs bytes.Buffer
	previousWriter := log.Writer()
	previousFlags := log.Flags()
	previousPrefix := log.Prefix()
	log.SetOutput(&logs)
	log.SetFlags(0)
	log.SetPrefix("")
	t.Cleanup(func() {
		log.SetOutput(previousWriter)
		log.SetFlags(previousFlags)
		log.SetPrefix(previousPrefix)
	})

	h := Recovery(nil)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("boom\r\nforged_entry=true")
	}))
	req := httptest.NewRequest(http.MethodPost, "http://example.test/api/%0d%0aforged_path=true", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	logged := logs.String()
	if strings.Count(logged, "\n") != 1 || strings.Contains(logged, "\r") {
		t.Fatalf("recovery log contains injected line breaks: %q", logged)
	}
	for _, want := range []string{`trace_id=`, `method="POST"`, `path="/api/\r\nforged_path=true"`, `panic="boom\r\nforged_entry=true"`} {
		if !strings.Contains(logged, want) {
			t.Errorf("recovery log %q does not contain %q", logged, want)
		}
	}
	if strings.Contains(logged, "goroutine ") {
		t.Fatalf("recovery log exposed a debug stack: %q", logged)
	}
}
