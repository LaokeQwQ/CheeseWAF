package handler

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	_ "github.com/jackc/pgx/v5/stdlib"
)

func (h *Handler) System(w http.ResponseWriter, _ *http.Request) {
	writeData(w, map[string]any{
		"server":        h.Config.Server,
		"tls":           h.Config.TLS,
		"storage":       h.Config.Storage,
		"logging":       h.Config.Logging,
		"protection":    h.Config.Protection,
		"setup":         h.Config.Setup,
		"scheduler":     h.Config.Scheduler,
		"edge":          h.Config.Edge,
		"ai":            aiConfigView(h.Config.AI),
		"update":        h.Config.Update,
		"vulnerability": h.Config.Vulnerability,
		"monitor":       h.Config.Monitor,
		"apisec":        h.Config.APISec,
	})
}

type systemPayload struct {
	Server        *config.ServerConfig        `json:"server"`
	TLS           *config.TLSConfig           `json:"tls"`
	Setup         *config.SetupConfig         `json:"setup"`
	Storage       *config.StorageConfig       `json:"storage"`
	Logging       *config.LoggingConfig       `json:"logging"`
	Protection    *config.ProtectionConfig    `json:"protection"`
	Scheduler     *config.SchedulerConfig     `json:"scheduler"`
	Edge          *config.EdgeConfig          `json:"edge"`
	AI            *config.AIConfig            `json:"ai"`
	Update        *config.UpdateConfig        `json:"update"`
	Vulnerability *config.VulnerabilityConfig `json:"vulnerability"`
	Monitor       *config.MonitorConfig       `json:"monitor"`
	APISec        *config.APISecConfig        `json:"apisec"`
}

func (h *Handler) UpdateSystem(w http.ResponseWriter, r *http.Request) {
	var req systemPayload
	if !decode(w, r, &req) {
		return
	}
	next := *h.Config
	if req.Server != nil {
		next.Server = *req.Server
	}
	if req.TLS != nil {
		next.TLS = *req.TLS
	}
	if req.Setup != nil {
		next.Setup = *req.Setup
	}
	if req.Storage != nil {
		next.Storage = *req.Storage
	}
	if req.Logging != nil {
		next.Logging = *req.Logging
	}
	if req.Protection != nil {
		next.Protection = *req.Protection
	}
	if req.Scheduler != nil {
		next.Scheduler = *req.Scheduler
	}
	if req.Edge != nil {
		next.Edge = *req.Edge
	}
	if req.AI != nil {
		next.AI = *req.AI
		if next.AI.APIKey == "" {
			next.AI.APIKey = h.Config.AI.APIKey
		}
	}
	if req.Update != nil {
		next.Update = *req.Update
	}
	if req.Vulnerability != nil {
		next.Vulnerability = *req.Vulnerability
	}
	if req.Monitor != nil {
		next.Monitor = *req.Monitor
	}
	if req.APISec != nil {
		next.APISec = *req.APISec
	}
	next.Protection.Policy = next.Protection.Policy.WithDefaults(config.DefaultProtectionPolicy())
	if _, err := config.EnsureRuntimeSecrets(&next); err != nil {
		writeError(w, http.StatusInternalServerError, "CONFIG_REPAIR_ERROR", err.Error())
		return
	}
	if err := config.Validate(&next); err != nil {
		writeError(w, http.StatusBadRequest, "CONFIG_INVALID", err.Error())
		return
	}
	*h.Config = next
	if err := h.persistConfig(); err != nil {
		writeError(w, http.StatusInternalServerError, "CONFIG_SAVE_ERROR", err.Error())
		return
	}
	if h.OnSitesChanged != nil {
		h.OnSitesChanged(h.Config.Sites)
	}
	if req.Protection != nil {
		if err := h.notifyProtectionChanged(); err != nil {
			writeError(w, http.StatusInternalServerError, "PROTECTION_RELOAD_ERROR", err.Error())
			return
		}
	}
	if req.APISec != nil {
		if err := h.notifyAPISecChanged(); err != nil {
			writeError(w, http.StatusInternalServerError, "APISEC_RELOAD_ERROR", err.Error())
			return
		}
	}
	h.System(w, r)
}

type storageTestPayload struct {
	Backend string               `json:"backend"`
	Storage config.StorageConfig `json:"storage"`
}

func (h *Handler) TestStorageBackend(w http.ResponseWriter, r *http.Request) {
	var req storageTestPayload
	if !decode(w, r, &req) {
		return
	}
	if req.Backend == "" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "backend is required")
		return
	}
	if err := testStorage(r.Context(), strings.ToLower(req.Backend), req.Storage); err != nil {
		writeError(w, http.StatusBadRequest, "STORAGE_TEST_FAILED", err.Error())
		return
	}
	writeData(w, map[string]any{"ok": true, "backend": req.Backend})
}

func testStorage(ctx context.Context, backend string, storage config.StorageConfig) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	switch backend {
	case "sqlite":
		path := storage.SQLite.Path
		if path == "" {
			return fmt.Errorf("sqlite path is required")
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			return err
		}
		file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o640)
		if err != nil {
			return err
		}
		return file.Close()
	case "redis":
		if !storage.Redis.Enabled {
			return fmt.Errorf("redis is disabled")
		}
		if storage.Redis.Address == "" {
			return fmt.Errorf("redis address is required")
		}
		dialer := &net.Dialer{Timeout: 5 * time.Second}
		conn, err := dialer.DialContext(ctx, "tcp", storage.Redis.Address)
		if err != nil {
			return err
		}
		return conn.Close()
	case "postgresql", "postgres", "pg":
		if !storage.PostgreSQL.Enabled {
			return fmt.Errorf("postgresql is disabled")
		}
		db, err := sql.Open("pgx", storage.PostgreSQL.DSN)
		if err != nil {
			return err
		}
		defer db.Close()
		return db.PingContext(ctx)
	case "clickhouse":
		if !storage.ClickHouse.Enabled {
			return fmt.Errorf("clickhouse is disabled")
		}
		return testHTTP(ctx, storage.ClickHouse.Endpoint, storage.ClickHouse.Username, storage.ClickHouse.Password, "")
	case "victorialogs":
		if !storage.VictoriaLogs.Enabled {
			return fmt.Errorf("victorialogs is disabled")
		}
		return testHTTP(ctx, storage.VictoriaLogs.Endpoint, "", "", "")
	case "elasticsearch", "elastic":
		if !storage.Elasticsearch.Enabled {
			return fmt.Errorf("elasticsearch is disabled")
		}
		return testHTTP(ctx, storage.Elasticsearch.Endpoint, storage.Elasticsearch.Username, storage.Elasticsearch.Password, storage.Elasticsearch.APIKey)
	default:
		return fmt.Errorf("unsupported backend %q", backend)
	}
}

func testHTTP(ctx context.Context, endpoint, username, password, apiKey string) error {
	if endpoint == "" {
		return fmt.Errorf("endpoint is required")
	}
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return err
	}
	if apiKey != "" {
		req.Header.Set("Authorization", "ApiKey "+apiKey)
	} else if username != "" {
		req.SetBasicAuth(username, password)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 500 {
		return fmt.Errorf("endpoint returned %s", resp.Status)
	}
	return nil
}
