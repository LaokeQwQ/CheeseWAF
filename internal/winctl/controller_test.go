package winctl

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func testController(t *testing.T) *Controller {
	t.Helper()
	c, err := New(Options{Binary: "cheesewaf", ConfigPath: "c.yaml", DataDir: t.TempDir(), Listen: "127.0.0.1:17943"})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestDefaultCheeseWAFBinaryPrefersAppResources(t *testing.T) {
	root := t.TempDir()
	macos := filepath.Join(root, "CheeseWAF.app", "Contents", "MacOS")
	binDir := filepath.Join(root, "CheeseWAF.app", "Contents", "Resources", "bin")
	if err := os.MkdirAll(macos, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	gui := filepath.Join(macos, "CheeseWAF")
	engineName := "cheesewaf"
	if runtime.GOOS == "windows" {
		engineName = "cheesewaf.exe"
	}
	engine := filepath.Join(binDir, engineName)
	if err := os.WriteFile(gui, []byte("gui"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(engine, []byte("engine"), 0o755); err != nil {
		t.Fatal(err)
	}
	got := defaultCheeseWAFBinary(gui)
	if got != engine {
		t.Fatalf("binary = %q, want %q", got, engine)
	}
}

func TestServeCommandUsesDataDirWorkingDirectory(t *testing.T) {
	root := t.TempDir()
	c, err := New(Options{Binary: "cheesewaf", ConfigPath: filepath.Join(root, "c.yaml"), DataDir: root})
	if err != nil {
		t.Fatal(err)
	}
	cmd, logFile, err := c.serveCommand()
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close()
	if cmd.Dir != root {
		t.Fatalf("cmd.Dir = %q, want data dir %q", cmd.Dir, root)
	}
	if cmd.Stdout == nil || cmd.Stderr == nil {
		t.Fatal("serve stdout/stderr must be captured")
	}
}

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
	if c.ControlToken() == "" {
		t.Fatal("expected control token")
	}
	paths := c.Paths()
	if paths["binary"] == "" || paths["config"] == "" {
		t.Fatalf("paths incomplete: %+v", paths)
	}
}

func TestLocalOnlyHandlerRejectsNonLoopback(t *testing.T) {
	c := testController(t)
	h := withLocalOnly(c, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	c := testController(t)
	h := withLocalOnly(c, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	c := testController(t)
	h := withLocalOnly(c, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodPost, "/api/start", nil)
	req.RemoteAddr = "127.0.0.1:9999"
	req.Header.Set("Origin", "https://evil.example")
	req.Header.Set("X-CheeseWAF-Control-Token", c.ControlToken())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

func TestLocalOnlyRejectsMissingControlTokenOnPOST(t *testing.T) {
	c := testController(t)
	h := withLocalOnly(c, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodPost, "/api/start", nil)
	req.RemoteAddr = "127.0.0.1:9999"
	req.Header.Set("Origin", "http://127.0.0.1:17943")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestLocalOnlyAllowsLoopbackOriginOnPOST(t *testing.T) {
	c := testController(t)
	h := withLocalOnly(c, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodPost, "/api/start", nil)
	req.RemoteAddr = "127.0.0.1:9999"
	req.Header.Set("Origin", "http://127.0.0.1:17943")
	req.Header.Set("X-CheeseWAF-Control-Token", c.ControlToken())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
}

func TestLocalOnlyRejectsControlTokenInQuery(t *testing.T) {
	c := testController(t)
	h := withLocalOnly(c, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodPost, "/api/start?token="+c.ControlToken(), nil)
	req.RemoteAddr = "127.0.0.1:9999"
	req.Header.Set("Origin", "http://127.0.0.1:17943")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestAutostartRejectsOversizedJSONBody(t *testing.T) {
	c := testController(t)
	payload := `{"enabled":true,"padding":"` + strings.Repeat("x", 8<<10) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/autostart", strings.NewReader(payload))
	req.RemoteAddr = "127.0.0.1:9999"
	req.Header.Set("Origin", "http://127.0.0.1:17943")
	req.Header.Set("X-CheeseWAF-Control-Token", c.ControlToken())
	rec := httptest.NewRecorder()
	withLocalOnly(c, http.HandlerFunc(c.handleAutostart)).ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
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
	withLocalOnly(c, http.HandlerFunc(c.handleStatus)).ServeHTTP(rec, req)
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
