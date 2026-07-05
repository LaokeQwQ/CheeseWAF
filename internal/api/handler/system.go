package handler

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/blockpage"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/version"
	"github.com/go-chi/chi/v5"
	_ "github.com/jackc/pgx/v5/stdlib"
)

const maxMapBoundaryBytes = 5 << 20

var chinaMapAdcodePattern = regexp.MustCompile(`^\d{6}$`)

var systemHTTPClient = &http.Client{Timeout: 8 * time.Second}

func (h *Handler) System(w http.ResponseWriter, _ *http.Request) {
	view := systemConfigView(h.Config)
	view["version"] = version.Current()
	writeData(w, view)
}

func (h *Handler) Version(w http.ResponseWriter, _ *http.Request) {
	writeData(w, version.Current())
}

type systemPayload struct {
	Server        *config.ServerConfig        `json:"server"`
	TLS           *config.TLSConfig           `json:"tls"`
	Setup         *config.SetupConfig         `json:"setup"`
	Storage       *config.StorageConfig       `json:"storage"`
	Logging       *config.LoggingConfig       `json:"logging"`
	Console       *config.ConsoleConfig       `json:"console"`
	ACME          *config.ACMEConfig          `json:"acme"`
	Protection    *config.ProtectionConfig    `json:"protection"`
	Scheduler     *config.SchedulerConfig     `json:"scheduler"`
	Edge          *config.EdgeConfig          `json:"edge"`
	AI            *config.AIConfig            `json:"ai"`
	Update        *config.UpdateConfig        `json:"update"`
	Vulnerability *config.VulnerabilityConfig `json:"vulnerability"`
	Monitor       *config.MonitorConfig       `json:"monitor"`
	APISec        *config.APISecConfig        `json:"apisec"`
	BlockPage     *config.BlockPageConfig     `json:"block_page"`
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
	if req.Console != nil {
		next.Console = *req.Console
	}
	if req.ACME != nil {
		next.ACME = *req.ACME
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
	if req.BlockPage != nil {
		next.BlockPage = *req.BlockPage
		if next.BlockPage.TemplateID == "" {
			next.BlockPage.TemplateID = config.Default().BlockPage.TemplateID
		}
		if _, ok := blockpage.TemplateByID(next.BlockPage.TemplateID); !ok {
			writeError(w, http.StatusBadRequest, "BLOCK_PAGE_TEMPLATE_UNKNOWN", "unknown block page template")
			return
		}
		if _, err := blockpage.NewRendererFromConfig(next.BlockPage); err != nil {
			writeError(w, http.StatusBadRequest, "BLOCK_PAGE_TEMPLATE_INVALID", err.Error())
			return
		}
	}
	preserveSystemSecrets(*h.Config, &next)
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
	if req.BlockPage != nil {
		if err := h.notifyBlockPageChanged(); err != nil {
			writeError(w, http.StatusInternalServerError, "BLOCK_PAGE_RELOAD_ERROR", err.Error())
			return
		}
	}
	h.System(w, r)
}

func (h *Handler) ChinaMapBoundary(w http.ResponseWriter, r *http.Request) {
	boundary := h.Config.Console.Map.ChinaBoundary
	if !boundary.Enabled {
		writeData(w, map[string]any{
			"enabled": false,
			"reason":  "china boundary rendering is disabled",
		})
		return
	}
	body, err := h.readMapBoundary(r.Context(), boundary)
	if err != nil {
		writeError(w, http.StatusBadRequest, "MAP_BOUNDARY_UNAVAILABLE", err.Error())
		return
	}
	var geojson any
	if err := json.Unmarshal(body, &geojson); err != nil {
		writeError(w, http.StatusBadRequest, "MAP_BOUNDARY_INVALID", "boundary source is not valid GeoJSON/JSON")
		return
	}
	if err := validateGeoJSONFeatureCollection(geojson); err != nil {
		writeError(w, http.StatusBadRequest, "MAP_BOUNDARY_INVALID", err.Error())
		return
	}
	writeData(w, map[string]any{
		"enabled":     true,
		"source_type": sourceTypeOrDefault(boundary.SourceType),
		"source":      boundary.Source,
		"license":     boundary.License,
		"review_id":   boundary.ReviewID,
		"attribution": boundary.Attribution,
		"geojson":     geojson,
	})
}

func (h *Handler) ChinaMapBoundaryByCode(w http.ResponseWriter, r *http.Request) {
	adcode := chi.URLParam(r, "adcode")
	if !chinaMapAdcodePattern.MatchString(adcode) {
		writeError(w, http.StatusBadRequest, "MAP_BOUNDARY_BAD_ADCODE", "adcode must be a 6 digit administrative code")
		return
	}
	boundary := h.Config.Console.Map.ChinaBoundary
	if !boundary.Enabled {
		writeData(w, map[string]any{
			"enabled": false,
			"adcode":  adcode,
			"reason":  "china boundary rendering is disabled",
		})
		return
	}
	body, resolved, err := h.readMapBoundaryByCode(r.Context(), boundary, adcode)
	if err != nil {
		writeData(w, map[string]any{
			"enabled":     false,
			"adcode":      adcode,
			"source_type": sourceTypeOrDefault(boundary.SourceType),
			"source":      boundary.Source,
			"license":     boundary.License,
			"review_id":   boundary.ReviewID,
			"attribution": boundary.Attribution,
			"reason":      err.Error(),
		})
		return
	}
	var geojson any
	if err := json.Unmarshal(body, &geojson); err != nil {
		writeError(w, http.StatusBadRequest, "MAP_BOUNDARY_INVALID", "boundary source is not valid GeoJSON/JSON")
		return
	}
	if err := validateGeoJSONFeatureCollection(geojson); err != nil {
		writeError(w, http.StatusBadRequest, "MAP_BOUNDARY_INVALID", err.Error())
		return
	}
	writeData(w, map[string]any{
		"enabled":         true,
		"adcode":          adcode,
		"source_type":     sourceTypeOrDefault(boundary.SourceType),
		"source":          boundary.Source,
		"resolved_source": resolved,
		"license":         boundary.License,
		"review_id":       boundary.ReviewID,
		"attribution":     boundary.Attribution,
		"geojson":         geojson,
	})
}

func (h *Handler) readMapBoundary(ctx context.Context, boundary config.MapBoundaryConfig) ([]byte, error) {
	sourceType := sourceTypeOrDefault(boundary.SourceType)
	source := strings.TrimSpace(boundary.Source)
	if source == "" {
		return nil, fmt.Errorf("boundary source is empty")
	}
	if sourceType == "url" {
		return h.readRemoteMapBoundary(ctx, source)
	}
	body, err := os.ReadFile(source)
	if err != nil {
		return nil, err
	}
	if len(body) > maxMapBoundaryBytes {
		return nil, fmt.Errorf("boundary source exceeds %d bytes", maxMapBoundaryBytes)
	}
	return body, nil
}

func (h *Handler) readMapBoundaryByCode(ctx context.Context, boundary config.MapBoundaryConfig, adcode string) ([]byte, string, error) {
	sourceType := sourceTypeOrDefault(boundary.SourceType)
	source := strings.TrimSpace(boundary.Source)
	if source == "" {
		return nil, "", fmt.Errorf("boundary source is empty")
	}
	if sourceType == "url" {
		urlSource := boundarySourceForAdcode(source, adcode)
		body, err := h.readRemoteMapBoundary(ctx, urlSource)
		return body, urlSource, err
	}
	for _, candidate := range boundaryFileCandidates(source, adcode) {
		body, err := os.ReadFile(candidate)
		if err == nil {
			if len(body) > maxMapBoundaryBytes {
				return nil, candidate, fmt.Errorf("boundary source exceeds %d bytes", maxMapBoundaryBytes)
			}
			return body, candidate, nil
		}
		if err != nil && !os.IsNotExist(err) {
			return nil, candidate, err
		}
	}
	return nil, "", fmt.Errorf("boundary file for adcode %s is not configured", adcode)
}

func (h *Handler) readRemoteMapBoundary(ctx context.Context, source string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/geo+json, application/json;q=0.9, */*;q=0.1")
	resp, err := systemHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("boundary source returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxMapBoundaryBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxMapBoundaryBytes {
		return nil, fmt.Errorf("boundary source exceeds %d bytes", maxMapBoundaryBytes)
	}
	return body, nil
}

func boundarySourceForAdcode(source, adcode string) string {
	if strings.Contains(source, "{adcode}") {
		return strings.ReplaceAll(source, "{adcode}", adcode)
	}
	if strings.Contains(source, "%s") {
		return fmt.Sprintf(source, adcode)
	}
	base := strings.TrimRight(source, "/")
	return base + "/" + adcode + ".json"
}

func boundaryFileCandidates(source, adcode string) []string {
	if strings.Contains(source, "{adcode}") {
		return []string{strings.ReplaceAll(source, "{adcode}", adcode)}
	}
	if strings.Contains(source, "%s") {
		return []string{fmt.Sprintf(source, adcode)}
	}
	info, err := os.Stat(source)
	if err == nil && !info.IsDir() {
		return []string{source}
	}
	return []string{
		filepath.Join(source, adcode+".json"),
		filepath.Join(source, adcode+"_full.json"),
		filepath.Join(source, adcode, adcode+".json"),
		filepath.Join(source, adcode, adcode+"_full.json"),
	}
}

func validateGeoJSONFeatureCollection(value any) error {
	root, ok := value.(map[string]any)
	if !ok {
		return fmt.Errorf("boundary source must be a GeoJSON FeatureCollection object")
	}
	if typeName, _ := root["type"].(string); typeName != "FeatureCollection" {
		return fmt.Errorf("boundary source must be a GeoJSON FeatureCollection")
	}
	features, ok := root["features"].([]any)
	if !ok {
		return fmt.Errorf("boundary source features must be an array")
	}
	if len(features) == 0 {
		return fmt.Errorf("boundary source must contain at least one feature")
	}
	return nil
}

func sourceTypeOrDefault(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "file"
	}
	return value
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
	resp, err := systemHTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 500 {
		return fmt.Errorf("endpoint returned %s", resp.Status)
	}
	return nil
}
