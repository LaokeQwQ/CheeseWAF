package cli

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/diagnostics/integration"
)

func writeUploadToken(t *testing.T, token string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "upload.token")
	if err := os.WriteFile(path, []byte(token), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestHTTPUploadAdapterPostsBearerTokenAndRejectsRedirects(t *testing.T) {
	tokenPath := writeUploadToken(t, "upload-secret")
	var seenAuth, seenBody string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenAuth = r.Header.Get("Authorization")
		raw, _ := io.ReadAll(r.Body)
		seenBody = string(raw)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	adapter := newHTTPUploadAdapter(server.URL+"/v1/diagnostics", tokenPath, 5*time.Second)
	adapter.client = server.Client()
	adapter.client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	request := integration.UploadRequest{UploadID: "upload-1", TenantID: "tenant-a", PluginID: "plugin-a", PluginVersion: "1.0.0", Target: "edge-1", LeaseID: "lease-1", Digest: strings.Repeat("a", 64), PolicyEpoch: 3, Attempt: 1, Envelope: []byte("ciphertext-envelope")}
	if err := adapter.Upload(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if seenAuth != "Bearer upload-secret" {
		t.Fatalf("authorization=%q", seenAuth)
	}
	encodedEnvelope := base64.StdEncoding.EncodeToString([]byte("ciphertext-envelope"))
	if !strings.Contains(seenBody, encodedEnvelope) || strings.Contains(seenBody, "ciphertext-envelope") {
		t.Fatalf("upload body missing envelope: %q", seenBody)
	}

	redirect := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/elsewhere", http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	redirectAdapter := newHTTPUploadAdapter(redirect.URL, tokenPath, 5*time.Second)
	redirectAdapter.client = redirect.Client()
	redirectAdapter.client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if err := redirectAdapter.Upload(context.Background(), request); err == nil {
		t.Fatal("redirect must not be followed")
	}

	failing := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer failing.Close()
	failingAdapter := newHTTPUploadAdapter(failing.URL, tokenPath, 5*time.Second)
	failingAdapter.client = failing.Client()
	if err := failingAdapter.Upload(context.Background(), request); err == nil {
		t.Fatal("non-2xx must fail")
	}
}

func TestHTTPUploadAdapterRejectsMissingTokenFile(t *testing.T) {
	adapter := newHTTPUploadAdapter("https://upload.example/v1", filepath.Join(t.TempDir(), "missing.token"), time.Second)
	request := integration.UploadRequest{UploadID: "upload-1"}
	if err := adapter.Upload(context.Background(), request); err == nil {
		t.Fatal("missing token file must fail closed")
	}
}
