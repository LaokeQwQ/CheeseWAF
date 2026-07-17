package api

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/ai"
	"github.com/LaokeQwQ/CheeseWAF/internal/api/middleware"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/timekeeper"
)

type routerTimeSyncStub struct {
	status        timekeeper.Status
	statusCalls   int
	reselectCalls int
	syncCalls     int
}

func (s *routerTimeSyncStub) Status() timekeeper.Status {
	s.statusCalls++
	return s.status
}

func (s *routerTimeSyncStub) ReselectNow(context.Context) error {
	s.reselectCalls++
	return nil
}

func (s *routerTimeSyncStub) SyncNow(context.Context) error {
	s.syncCalls++
	return nil
}

func TestRouterTimeSyncOptionsAndManagementAPITokenScopes(t *testing.T) {
	const (
		readToken  = "cwapi_router_time_sync_read"
		writeToken = "cwapi_router_time_sync_write"
	)
	service := &routerTimeSyncStub{status: timekeeper.Status{
		Primary:      "time.google.com",
		ActiveSource: "time.google.com",
		Synchronized: true,
		Offset:       125 * time.Millisecond,
	}}
	router := newTimeSyncTokenRouter(t, service,
		timeSyncAPIToken("time-sync-reader", readToken, "read:system"),
		timeSyncAPIToken("time-sync-writer", writeToken, "write:system"),
	)

	t.Run("read system token gets injected service status", func(t *testing.T) {
		response := perform(router, http.MethodGet, "/api/system/time-sync", readToken, nil)
		if response.Code != http.StatusOK {
			t.Fatalf("read:system token status = %d, want 200: %s", response.Code, response.Body.String())
		}
		var envelope struct {
			Data struct {
				State        string `json:"state"`
				ActiveSource string `json:"active_source"`
				OffsetMillis int64  `json:"offset_ms"`
			} `json:"data"`
		}
		if err := json.NewDecoder(response.Body).Decode(&envelope); err != nil {
			t.Fatalf("decode time synchronization status: %v", err)
		}
		if envelope.Data.State != "synchronized" || envelope.Data.ActiveSource != "time.google.com" || envelope.Data.OffsetMillis != 125 {
			t.Fatalf("router did not expose injected time synchronization service: %+v", envelope.Data)
		}
		if service.statusCalls != 1 {
			t.Fatalf("injected service status calls = %d, want 1", service.statusCalls)
		}
	})

	t.Run("read system token cannot run write operations", func(t *testing.T) {
		for _, path := range []string{"/api/system/time-sync/sync", "/api/system/time-sync/reselect"} {
			response := perform(router, http.MethodPost, path, readToken, nil)
			if response.Code != http.StatusForbidden {
				t.Fatalf("read:system token POST %s = %d, want 403: %s", path, response.Code, response.Body.String())
			}
		}
		if service.syncCalls != 0 || service.reselectCalls != 0 {
			t.Fatalf("forbidden requests reached injected service: sync=%d reselect=%d", service.syncCalls, service.reselectCalls)
		}
	})

	t.Run("write system token runs sync and reselect", func(t *testing.T) {
		read := perform(router, http.MethodGet, "/api/system/time-sync", writeToken, nil)
		if read.Code != http.StatusForbidden {
			t.Fatalf("write:system-only token GET status = %d, want 403: %s", read.Code, read.Body.String())
		}

		for _, path := range []string{"/api/system/time-sync/sync", "/api/system/time-sync/reselect"} {
			response := perform(router, http.MethodPost, path, writeToken, nil)
			if response.Code != http.StatusOK {
				t.Fatalf("write:system token POST %s = %d, want 200: %s", path, response.Code, response.Body.String())
			}
		}
		if service.syncCalls != 1 || service.reselectCalls != 1 {
			t.Fatalf("injected service operation calls = sync:%d reselect:%d, want 1 each", service.syncCalls, service.reselectCalls)
		}
	})
}

func newTimeSyncTokenRouter(t *testing.T, service *routerTimeSyncStub, tokens ...config.ManagementAPITokenConfig) http.Handler {
	t.Helper()
	cfg := config.Default()
	cfg.APISec.Audit.Enabled = false
	cfg.APISec.ManagementAPI.Enabled = true
	cfg.APISec.ManagementAPI.Tokens = tokens
	cfg.CAPTCHAAssets.Local.Path = filepath.Join(t.TempDir(), "captcha-assets")
	return NewRouter(Options{
		Config:             &cfg,
		Secret:             "router-time-sync-test-secret",
		AssistantApprovals: ai.NewApprovalStore(),
		TimeSync:           service,
	})
}

func timeSyncAPIToken(id, raw string, scopes ...string) config.ManagementAPITokenConfig {
	return config.ManagementAPITokenConfig{
		ID:        id,
		Name:      id,
		Prefix:    "cwapi_router",
		Hash:      middleware.HashManagementAPIToken(raw),
		Scopes:    scopes,
		Enabled:   true,
		CreatedAt: time.Now().UTC(),
	}
}
