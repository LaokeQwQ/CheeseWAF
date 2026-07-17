package handler

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/blockpage"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/netguard"
	"github.com/LaokeQwQ/CheeseWAF/internal/setup"
	"github.com/LaokeQwQ/CheeseWAF/internal/version"
	"github.com/go-chi/chi/v5"
	_ "github.com/jackc/pgx/v5/stdlib"
)

const maxMapBoundaryBytes = 5 << 20

var chinaMapAdcodePattern = regexp.MustCompile(`^\d{6}$`)

var systemHTTPClient = func(policy netguard.URLPolicy) *http.Client {
	return netguard.NewHTTPClient(netguard.HTTPClientOptions{
		Timeout: 8 * time.Second,
		Policy:  policy,
	})
}

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
	TimeSync      *timeSyncPayload            `json:"time_sync"`
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

// timeSyncPayload is a field-presence-aware patch so partial JSON updates cannot
// silently zero enabled/sources/intervals.
type timeSyncPayload struct {
	Enabled            *bool          `json:"enabled"`
	Sources            *[]string      `json:"sources"`
	SelectionInterval  *time.Duration `json:"selection_interval"`
	SyncInterval       *time.Duration `json:"sync_interval"`
	Timeout            *time.Duration `json:"timeout"`
	SamplesPerSource   *int           `json:"samples_per_source"`
	MaxAcceptedOffset  *time.Duration `json:"max_accepted_offset"`
	MaxRootDispersion  *time.Duration `json:"max_root_dispersion"`
	ConsensusTolerance *time.Duration `json:"consensus_tolerance"`
}

func (p *timeSyncPayload) apply(base config.TimeSyncConfig) config.TimeSyncConfig {
	if p == nil {
		return base
	}
	if p.Enabled != nil {
		base.Enabled = *p.Enabled
	}
	if p.Sources != nil {
		base.Sources = append([]string(nil), (*p.Sources)...)
	}
	if p.SelectionInterval != nil {
		base.SelectionInterval = *p.SelectionInterval
	}
	if p.SyncInterval != nil {
		base.SyncInterval = *p.SyncInterval
	}
	if p.Timeout != nil {
		base.Timeout = *p.Timeout
	}
	if p.SamplesPerSource != nil {
		base.SamplesPerSource = *p.SamplesPerSource
	}
	if p.MaxAcceptedOffset != nil {
		base.MaxAcceptedOffset = *p.MaxAcceptedOffset
	}
	if p.MaxRootDispersion != nil {
		base.MaxRootDispersion = *p.MaxRootDispersion
	}
	if p.ConsensusTolerance != nil {
		base.ConsensusTolerance = *p.ConsensusTolerance
	}
	return base
}

func (h *Handler) UpdateSystem(w http.ResponseWriter, r *http.Request) {
	if h.rejectClusterConfigWriteIfFrozen(w, r) {
		return
	}
	var req systemPayload
	if !decode(w, r, &req) {
		return
	}
	committed, err := h.commitConfigMutation(func(candidate *config.Config) error {
		return applySystemPayload(candidate, req)
	}, func(candidate *config.Config) error {
		return h.applySystemRuntime(req, candidate)
	})
	if err != nil {
		code := "CONFIG_SAVE_ERROR"
		status := http.StatusInternalServerError
		if strings.Contains(err.Error(), "runtime") {
			code = "CONFIG_RELOAD_ERROR"
		}
		if strings.Contains(err.Error(), "frozen") || h.configWriteFrozen {
			code = "CONFIG_WRITES_FROZEN"
		} else if strings.Contains(err.Error(), "unknown block page template") {
			code = "BLOCK_PAGE_TEMPLATE_UNKNOWN"
			status = http.StatusBadRequest
		} else if strings.Contains(err.Error(), "block page") || strings.Contains(err.Error(), "template") {
			code = "BLOCK_PAGE_TEMPLATE_INVALID"
			status = http.StatusBadRequest
		} else if strings.Contains(err.Error(), "required") || strings.Contains(err.Error(), "invalid") || strings.Contains(err.Error(), "must ") {
			code = "CONFIG_INVALID"
			status = http.StatusBadRequest
		}
		writeError(w, status, code, err.Error())
		return
	}
	_ = committed
	h.System(w, r)
}

func clonePermissionMap(in map[string][]string) map[string][]string {
	if in == nil {
		return nil
	}
	out := make(map[string][]string, len(in))
	for role, perms := range in {
		out[role] = append([]string(nil), perms...)
	}
	return out
}

func applySystemPayload(next *config.Config, req systemPayload) error {
	previous := *next
	if req.Server != nil {
		next.Server = *req.Server
	}
	if req.TimeSync != nil {
		next.TimeSync = req.TimeSync.apply(previous.TimeSync)
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
			next.AI.APIKey = previous.AI.APIKey
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
		// Privileged control-plane fields must not be minted via generic system update.
		// RBAC maps and management API tokens have dedicated endpoints with stricter checks.
		next.APISec.Permissions = clonePermissionMap(previous.APISec.Permissions)
		managementEnabled := next.APISec.ManagementAPI.Enabled
		next.APISec.ManagementAPI = previous.APISec.ManagementAPI
		next.APISec.ManagementAPI.Enabled = managementEnabled
		next.APISec.ManagementAPI.Tokens = append([]config.ManagementAPITokenConfig(nil), previous.APISec.ManagementAPI.Tokens...)
	}
	if req.BlockPage != nil {
		next.BlockPage = *req.BlockPage
		if next.BlockPage.TemplateID == "" {
			next.BlockPage.TemplateID = config.Default().BlockPage.TemplateID
		}
		if _, ok := blockpage.TemplateByID(next.BlockPage.TemplateID); !ok {
			return fmt.Errorf("unknown block page template")
		}
		if _, err := blockpage.NewRendererFromConfig(next.BlockPage); err != nil {
			return err
		}
	}
	preserveSystemSecrets(previous, next)
	next.Protection.Policy = next.Protection.Policy.WithDefaults(config.DefaultProtectionPolicy())
	return nil
}

func (h *Handler) applySystemRuntime(req systemPayload, candidate *config.Config) error {
	if req.TimeSync != nil && h.OnTimeSyncChanged != nil {
		if err := h.OnTimeSyncChanged(candidate.TimeSync); err != nil {
			return err
		}
	}
	if (req.Server != nil || req.TLS != nil) && h.OnSitesChanged != nil {
		if err := h.OnSitesChanged(candidate.Sites); err != nil {
			return err
		}
	}
	if req.Protection != nil {
		if err := h.notifyProtectionConfigChanged(candidate.Protection); err != nil {
			return err
		}
	}
	if req.APISec != nil {
		if err := h.notifyAPISecConfigChanged(candidate.APISec); err != nil {
			return err
		}
	}
	if req.BlockPage != nil {
		if err := h.notifyBlockPageConfigChanged(candidate.BlockPage); err != nil {
			return err
		}
	}
	return nil
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
		return h.readRemoteMapBoundary(ctx, source, boundary)
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
		body, err := h.readRemoteMapBoundary(ctx, urlSource, boundary)
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

func (h *Handler) readRemoteMapBoundary(ctx context.Context, source string, boundary config.MapBoundaryConfig) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	policy := mapBoundaryURLPolicy(boundary)
	req, err := netguard.NewRequest(ctx, http.MethodGet, source, nil, policy)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/geo+json, application/json;q=0.9, */*;q=0.1")
	client := netguard.NewHTTPClient(netguard.HTTPClientOptions{
		Timeout: 8 * time.Second,
		Policy:  policy,
	})
	resp, err := client.Do(req)
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

func mapBoundaryURLPolicy(boundary config.MapBoundaryConfig) netguard.URLPolicy {
	schemes := []string{"https"}
	if boundary.AllowInsecure {
		schemes = []string{"http", "https"}
	}
	return netguard.URLPolicy{
		Purpose:        "map boundary",
		HostPurpose:    "map boundary",
		AllowedSchemes: schemes,
		AllowPrivate:   boundary.AllowPrivate,
	}
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
	dataDir := ""
	if h.Config != nil {
		dataDir = h.Config.Setup.DataDir
	}
	if err := testStorageWithDataDir(r.Context(), strings.ToLower(req.Backend), req.Storage, dataDir); err != nil {
		writeError(w, http.StatusBadRequest, "STORAGE_TEST_FAILED", err.Error())
		return
	}
	writeData(w, map[string]any{"ok": true, "backend": req.Backend})
}

func testStorage(ctx context.Context, backend string, storage config.StorageConfig) error {
	return testStorageWithDataDir(ctx, backend, storage, setup.DefaultDataDir)
}

func testStorageWithDataDir(ctx context.Context, backend string, storage config.StorageConfig, dataDir string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	switch backend {
	case "sqlite":
		path, err := safeSQLiteTestPath(storage.SQLite.Path, dataDir)
		if err != nil {
			return err
		}
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
		if err := dialStorageEndpoint(ctx, storage.Redis.Address, "redis address", false); err != nil {
			return err
		}
		return nil
	case "postgresql", "postgres", "pg":
		if !storage.PostgreSQL.Enabled {
			return fmt.Errorf("postgresql is disabled")
		}
		hostPort, err := postgresDialTarget(storage.PostgreSQL.DSN)
		if err != nil {
			return err
		}
		if err := dialStorageEndpoint(ctx, hostPort, "postgresql endpoint", false); err != nil {
			return err
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
		return testHTTP(ctx, storage.ClickHouse.Endpoint, storage.ClickHouse.Username, storage.ClickHouse.Password, "", storage.ClickHouse.AllowPrivateEndpoint, "clickhouse endpoint")
	case "victorialogs":
		if !storage.VictoriaLogs.Enabled {
			return fmt.Errorf("victorialogs is disabled")
		}
		return testHTTP(ctx, storage.VictoriaLogs.Endpoint, "", "", "", storage.VictoriaLogs.AllowPrivateEndpoint, "victorialogs endpoint")
	case "elasticsearch", "elastic":
		if !storage.Elasticsearch.Enabled {
			return fmt.Errorf("elasticsearch is disabled")
		}
		return testHTTP(ctx, storage.Elasticsearch.Endpoint, storage.Elasticsearch.Username, storage.Elasticsearch.Password, storage.Elasticsearch.APIKey, storage.Elasticsearch.AllowPrivateEndpoint, "elasticsearch endpoint")
	default:
		return fmt.Errorf("unsupported backend %q", backend)
	}
}

func dialStorageEndpoint(ctx context.Context, address, purpose string, allowPrivate bool) error {
	address = strings.TrimSpace(address)
	if address == "" {
		return fmt.Errorf("%s is required", purpose)
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		// Host-only Redis addresses (no port) are rejected; require host:port.
		return fmt.Errorf("%s must be host:port: %w", purpose, err)
	}
	host = strings.Trim(host, "[]")
	if host == "" {
		return fmt.Errorf("%s host is required", purpose)
	}
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", purpose, err)
	}
	if len(ips) == 0 {
		return fmt.Errorf("%s resolved to no addresses", purpose)
	}
	if !allowPrivate {
		for _, ip := range ips {
			if !netguard.IsPublicIP(ip) {
				return fmt.Errorf("%s resolved to non-public IP %s", purpose, ip)
			}
		}
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ips[0].String(), port))
	if err != nil {
		return err
	}
	return conn.Close()
}

func postgresDialTarget(dsn string) (string, error) {
	dsn = strings.TrimSpace(dsn)
	if dsn == "" {
		return "", fmt.Errorf("postgresql dsn is required")
	}
	// Support URL form postgres://user:pass@host:port/db and keyword form host= port=
	if strings.Contains(dsn, "://") {
		u, err := netguard.ValidateURL(dsn, netguard.URLPolicy{
			Purpose:        "postgresql endpoint",
			HostPurpose:    "postgresql endpoint",
			AllowedSchemes: []string{"postgres", "postgresql"},
			AllowPrivate:   false,
			AllowUserInfo:  true,
		})
		if err != nil {
			return "", err
		}
		host := u.Hostname()
		port := u.Port()
		if port == "" {
			port = "5432"
		}
		return net.JoinHostPort(host, port), nil
	}
	var host, port string
	for _, part := range strings.Fields(dsn) {
		key, value, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "host", "hostname":
			host = strings.TrimSpace(value)
		case "port":
			port = strings.TrimSpace(value)
		}
	}
	if host == "" {
		return "", fmt.Errorf("postgresql dsn host is required")
	}
	if port == "" {
		port = "5432"
	}
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil && !netguard.IsPublicIP(ip) {
		return "", fmt.Errorf("postgresql endpoint host IP must be public")
	}
	return net.JoinHostPort(host, port), nil
}

func safeSQLiteTestPath(rawPath, dataDir string) (string, error) {
	path := strings.TrimSpace(rawPath)
	if path == "" {
		return "", nil
	}
	if dataDir == "" {
		dataDir = setup.DefaultDataDir
	}
	allowedRoot, err := filepath.Abs(filepath.Clean(dataDir))
	if err != nil {
		return "", err
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(allowedRoot, path)
	}
	cleaned, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return "", err
	}
	if cleaned == allowedRoot || !isPathWithin(cleaned, allowedRoot) {
		return "", fmt.Errorf("sqlite path must stay under data directory %s", allowedRoot)
	}
	return cleaned, nil
}

func isPathWithin(path, root string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return rel != "." && rel != "" && !strings.HasPrefix(rel, "..") && !filepath.IsAbs(rel)
}

func testHTTP(ctx context.Context, endpoint, username, password, apiKey string, allowPrivate bool, purpose string) error {
	if endpoint == "" {
		return fmt.Errorf("endpoint is required")
	}
	policy := netguard.URLPolicy{
		Purpose:        purpose,
		HostPurpose:    purpose,
		AllowedSchemes: []string{"http", "https"},
		AllowPrivate:   allowPrivate,
	}
	req, err := netguard.NewRequest(ctx, http.MethodGet, endpoint, nil, policy)
	if err != nil {
		return err
	}
	if apiKey != "" {
		req.Header.Set("Authorization", "ApiKey "+apiKey)
	} else if username != "" {
		req.SetBasicAuth(username, password)
	}
	client := systemHTTPClient(policy)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 500 {
		return fmt.Errorf("endpoint returned %s", resp.Status)
	}
	return nil
}
