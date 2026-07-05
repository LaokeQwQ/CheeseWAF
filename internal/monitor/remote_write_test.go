package monitor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

func TestRemoteWriteRejectsPrivateEndpointByDefault(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("remote_write should not dial a private endpoint by default")
	}))
	defer server.Close()

	writer := NewRemoteWriter(config.RemoteWriteConfig{
		Enabled:  true,
		Endpoint: server.URL,
	}, nil)

	err := writer.Push(context.Background(), Snapshot{})
	if err == nil || !strings.Contains(err.Error(), "remote_write endpoint host IP must be public") {
		t.Fatalf("expected private endpoint guard error, got %v", err)
	}
}

func TestRemoteWriteAllowsPrivateEndpointWhenExplicit(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if got := r.Header.Get("Content-Type"); !strings.Contains(got, "text/plain") {
			t.Fatalf("unexpected content type %q", got)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	writer := NewRemoteWriter(config.RemoteWriteConfig{
		Enabled:              true,
		Endpoint:             server.URL,
		AllowPrivateEndpoint: true,
	}, nil)

	if err := writer.Push(context.Background(), Snapshot{Requests: 1}); err != nil {
		t.Fatalf("expected remote_write to allow explicitly trusted private endpoint: %v", err)
	}
	if requests != 1 {
		t.Fatalf("expected one remote_write request, got %d", requests)
	}
}
