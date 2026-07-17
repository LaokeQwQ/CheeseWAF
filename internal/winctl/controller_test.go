package winctl

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewRejectsNonLoopbackListen(t *testing.T) {
	_, err := New(Options{Listen: "0.0.0.0:17943"})
	if err == nil {
		t.Fatal("expected non-loopback listen to fail")
	}
}

func TestNewDefaultsLoopback(t *testing.T) {
	c, err := New(Options{Binary: "cheesewaf", ConfigPath: "c.yaml", DataDir: "d"})
	if err != nil {
		t.Fatal(err)
	}
	if c.opts.Listen != "127.0.0.1:17943" {
		t.Fatalf("listen = %q", c.opts.Listen)
	}
	paths := c.Paths()
	if paths["binary"] == "" || paths["config"] == "" {
		t.Fatalf("paths incomplete: %+v", paths)
	}
}

func TestLocalOnlyHandlerRejectsNonLoopback(t *testing.T) {
	h := withLocalOnly(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "8.8.8.8:1234"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

func TestLocalOnlyHandlerAllowsLoopback(t *testing.T) {
	h := withLocalOnly(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:9999"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
}

func TestLocalOnlyRejectsNonLoopbackOriginOnPOST(t *testing.T) {
	h := withLocalOnly(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodPost, "/api/start", nil)
	req.RemoteAddr = "127.0.0.1:9999"
	req.Header.Set("Origin", "https://evil.example")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

func TestLocalOnlyAllowsLoopbackOriginOnPOST(t *testing.T) {
	h := withLocalOnly(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodPost, "/api/start", nil)
	req.RemoteAddr = "127.0.0.1:9999"
	req.Header.Set("Origin", "http://127.0.0.1:17943")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
}

func TestPathsIncludeVersion(t *testing.T) {
	c, err := New(Options{Binary: "cheesewaf", ConfigPath: "c.yaml", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	paths := c.Paths()
	if paths["version"] == "" {
		t.Fatalf("missing version in paths: %+v", paths)
	}
}

func TestStatusHandlerJSON(t *testing.T) {
	c, err := New(Options{Binary: "cheesewaf", ConfigPath: "c.yaml", DataDir: t.TempDir(), Listen: "127.0.0.1:17944"})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	req.RemoteAddr = "127.0.0.1:1"
	rec := httptest.NewRecorder()
	withLocalOnly(http.HandlerFunc(c.handleStatus)).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["ok"] != true {
		t.Fatalf("body=%v", body)
	}
}
