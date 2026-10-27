package cli

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/diagnostics"
	"github.com/LaokeQwQ/CheeseWAF/internal/diagnostics/integration"
)

func TestDiagnosticsRuntimeUploadsCiphertextEndToEnd(t *testing.T) {
	dir := t.TempDir()
	kmsRuntime, kmsCloser, err := openKMSRuntime(embeddedKMSConfig(t, dir), 9, "v1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if kmsCloser != nil {
		defer kmsCloser.Close()
	}

	bodies := make(chan string, 4)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		bodies <- string(raw)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	uploader := &httpUploadAdapter{
		endpoint: server.URL,
		token:    func(context.Context) (string, error) { return "upload-token", nil },
		client:   server.Client(),
	}
	runtime, err := integration.NewRuntime(integration.Config{
		QueueRoot:    filepath.Join(dir, "queue"),
		BrokerConfig: diagnostics.Config{VerifyRaw: func(context.Context, diagnostics.Request) error { return nil }},
		Provider:     kmsEnvelopeProvider{runtime: kmsRuntime},
		KeyVersion:   "v1",
		TenantID:     "tenant-a",
		Actor:        "diagnostics",
		Uploader:     uploader,
		AutoStart:    true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	receipt, err := runtime.Submit(ctx, diagnostics.Request{
		Package: diagnostics.Package{
			Kind:     diagnostics.KindMetadata,
			Metadata: map[string]string{"component": "proxy", "marker": "sentinel-plaintext-42"},
		},
		Target:         "edge-1",
		PluginID:       "plugin-a",
		PluginVersion:  "1.0.0",
		PolicyEpoch:    9,
		LeaseID:        "lease-1",
		IdempotencyKey: "idempotency-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if receipt.UploadID == "" {
		t.Fatal("receipt has no upload id")
	}

	select {
	case body := <-bodies:
		if strings.Contains(body, "sentinel-plaintext-42") {
			t.Fatalf("upload leaked plaintext diagnostics: %s", body)
		}
		if !strings.Contains(body, "Envelope") || len(body) < 128 {
			t.Fatalf("upload body is not a sealed envelope: %s", body)
		}
	case <-ctx.Done():
		t.Fatal("diagnostic upload did not reach the uploader")
	}
}
