package cli

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

func TestCheckAdminReadinessUsesLoopbackForUnspecifiedListener(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health/ready" {
			t.Fatalf("healthcheck path = %q", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := config.Default()
	cfg.Server.AdminListen = "0.0.0.0" + strings.TrimPrefix(server.URL, "http://127.0.0.1")
	cfg.Server.AdminTLS.Enabled = false
	if err := checkAdminReadiness(context.Background(), &cfg); err != nil {
		t.Fatal(err)
	}
}

func TestCheckAdminReadinessRejectsNonSuccessStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	cfg := config.Default()
	cfg.Server.AdminListen = strings.TrimPrefix(server.URL, "http://")
	cfg.Server.AdminTLS.Enabled = false
	if err := checkAdminReadiness(context.Background(), &cfg); err == nil {
		t.Fatal("unready admin endpoint was accepted")
	}
}
