package handler

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/LaokeQwQ/CheeseWAF/internal/api/middleware"
	"github.com/LaokeQwQ/CheeseWAF/internal/identity"
	"github.com/LaokeQwQ/CheeseWAF/internal/netguard"
	"github.com/LaokeQwQ/CheeseWAF/internal/setup"
)

var (
	setupDraftOnce sync.Once
	setupDrafts    *setup.DraftStore
)

func draftStore() *setup.DraftStore {
	setupDraftOnce.Do(func() {
		setupDrafts = setup.NewDraftStore(setup.DefaultDraftTTL)
	})
	return setupDrafts
}

func (h *Handler) setupDraftStore() *setup.DraftStore {
	if h != nil && h.SetupDrafts != nil {
		return h.SetupDrafts
	}
	return draftStore()
}

// allowSetupMutation gates first-install endpoints: setup must still be needed,
// the setup token must match, and browser mutations need a local or same Origin.
func (h *Handler) allowSetupMutation(w http.ResponseWriter, r *http.Request) bool {
	if h == nil {
		writeError(w, http.StatusServiceUnavailable, "SETUP_UNAVAILABLE", "setup is unavailable")
		return false
	}
	if !setup.NeedsSetup(h.setupDataDir()) {
		writeError(w, http.StatusConflict, "SETUP_ALREADY_COMPLETE", "setup is already complete")
		return false
	}
	// Authoritative safety: if any admin user already exists, refuse re-init even if lock is missing.
	if h.Store != nil {
		users, err := h.Store.ListUsers(r.Context())
		if err == nil && len(users) > 0 {
			writeError(w, http.StatusConflict, "SETUP_ALREADY_COMPLETE", "administrator already exists")
			return false
		}
	}
	expected := ""
	if h.SetupTokenSource != nil {
		expected = h.SetupTokenSource.Current()
	}
	if expected == "" {
		expected = h.SetupToken
	}
	if expected == "" {
		expected = os.Getenv("CHEESEWAF_SETUP_TOKEN")
	}
	if expected == "" {
		expected = setup.GetSetupToken()
	}
	got := r.Header.Get("X-CheeseWAF-Setup-Token")
	if !validSetupTokenValue(expected) || !validSetupTokenValue(got) {
		writeError(w, http.StatusUnauthorized, "SETUP_TOKEN_REQUIRED", "setup token is required")
		return false
	}
	if !setupTokensEqual(got, expected) {
		writeError(w, http.StatusUnauthorized, "SETUP_TOKEN_REQUIRED", "setup token is invalid")
		return false
	}
	if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch || r.Method == http.MethodDelete {
		if origin := strings.TrimSpace(r.Header.Get("Origin")); origin != "" {
			if !isLocalOrSameOrigin(origin, r) {
				writeError(w, http.StatusForbidden, "SETUP_ORIGIN_DENIED", "setup origin is not allowed")
				return false
			}
		}
	}
	return true
}

func validSetupTokenValue(value string) bool {
	if value == "" || value != strings.TrimSpace(value) {
		return false
	}
	for _, r := range value {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func setupTokensEqual(got, expected string) bool {
	gotHash := sha256.Sum256([]byte(got))
	expectedHash := sha256.Sum256([]byte(expected))
	return subtle.ConstantTimeCompare(gotHash[:], expectedHash[:]) == 1
}

func isLocalOrSameOrigin(origin string, r *http.Request) bool {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	host := u.Hostname()
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return true
	}
	if r != nil && r.Host != "" {
		reqHost := r.Host
		if h, _, err := net.SplitHostPort(reqHost); err == nil {
			reqHost = h
		}
		return strings.EqualFold(host, reqHost)
	}
	return false
}

// SetupStatus reports whether first-install is still required. Setup credentials
// are delivered only through the serve process's stdout/runtime URL file.
func (h *Handler) SetupStatus(w http.ResponseWriter, r *http.Request) {
	needs := true
	if h != nil {
		needs = setup.NeedsSetup(h.setupDataDir())
		if !needs {
			writeData(w, map[string]any{"needs_setup": false})
			return
		}
		if h.Store != nil {
			users, err := h.Store.ListUsers(context.Background())
			if err == nil && len(users) > 0 {
				writeData(w, map[string]any{"needs_setup": false})
				return
			}
		}
	}
	payload := map[string]any{"needs_setup": needs}
	writeData(w, payload)
}

// SetupProbe runs the first-install performance probe (R0). Only meaningful when NeedsSetup.
func (h *Handler) SetupProbe(w http.ResponseWriter, r *http.Request) {
	if !h.allowSetupMutation(w, r) {
		return
	}
	if h.currentConfig() == nil {
		writeError(w, http.StatusServiceUnavailable, "SETUP_UNAVAILABLE", "setup is unavailable")
		return
	}
	store := h.setupDraftStore()
	draft, cached, err := store.ReserveProbe(setupSessionID(r))
	if cached {
		h.writeSetupProbeResponse(w, r, draft, *draft.Probe)
		return
	}
	if errors.Is(err, setup.ErrDraftStoreFull) {
		writeError(w, http.StatusTooManyRequests, "SETUP_CAPACITY_REACHED", "too many active setup sessions")
		return
	}
	if errors.Is(err, setup.ErrDraftProbeInProgress) {
		writeError(w, http.StatusTooManyRequests, "SETUP_PROBE_IN_PROGRESS", "setup probe is already running")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "SETUP_DRAFT_ERROR", err.Error())
		return
	}
	result := h.runSetupProbe(r.Context(), h.setupDataDir())
	draft, ok := store.CompleteProbe(draft.ID, result)
	if !ok {
		writeError(w, http.StatusConflict, "SETUP_DRAFT_EXPIRED", "setup session expired while probe was running")
		return
	}
	h.writeSetupProbeResponse(w, r, draft, result)
}

func (h *Handler) writeSetupProbeResponse(w http.ResponseWriter, r *http.Request, draft *setup.SetupDraft, result setup.ProbeResult) {
	middleware.WriteCookie(w, r, &http.Cookie{
		Name:     setup.SetupSessionCookie,
		Value:    draft.ID,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(setup.DefaultDraftTTL.Seconds()),
	})
	writeData(w, map[string]any{
		"probe":    result,
		"draft_id": draft.ID,
		"profiles": map[string]setup.ProfileConfig{
			"low":    setup.ProfileDefaults(setup.ProfileLow),
			"medium": setup.ProfileDefaults(setup.ProfileMedium),
			"high":   setup.ProfileDefaults(setup.ProfileHigh),
		},
	})
}

// SetupDraftGet returns the current setup draft for the session cookie.
func (h *Handler) SetupDraftGet(w http.ResponseWriter, r *http.Request) {
	id := setupSessionID(r)
	if id == "" {
		writeError(w, http.StatusUnauthorized, "SETUP_SESSION_REQUIRED", "setup session required")
		return
	}
	d, ok := h.setupDraftStore().Get(id)
	if !ok {
		writeError(w, http.StatusNotFound, "SETUP_DRAFT_NOT_FOUND", "setup draft not found or expired")
		return
	}
	writeData(w, d)
}

type setupDraftPatch struct {
	Profile       string                    `json:"profile"`
	Custom        *setup.ProfileConfig      `json:"custom"`
	Username      string                    `json:"username"`
	Password      string                    `json:"password"`
	AdminListen   string                    `json:"admin_listen"`
	AdminStrategy string                    `json:"admin_strategy"`
	Integrations  *setup.IntegrationsConfig `json:"integrations"`
	Confirmed     *bool                     `json:"confirmed"`
}

// SetupDraftPatch updates multi-step wizard fields. CompleteSetup remains a separate final call.
func (h *Handler) SetupDraftPatch(w http.ResponseWriter, r *http.Request) {
	if !h.allowSetupMutation(w, r) {
		return
	}
	id := setupSessionID(r)
	if id == "" {
		writeError(w, http.StatusUnauthorized, "SETUP_SESSION_REQUIRED", "setup session required")
		return
	}
	var req setupDraftPatch
	if !decode(w, r, &req) {
		return
	}
	if req.Username != "" {
		if err := identity.ValidateUsername(req.Username); err != nil {
			writeError(w, http.StatusBadRequest, "USERNAME_INVALID", err.Error())
			return
		}
	}
	if req.Password != "" {
		if !h.setupDraftStore().SetPassword(id, req.Password) {
			writeError(w, http.StatusNotFound, "SETUP_DRAFT_NOT_FOUND", "setup draft not found or expired")
			return
		}
	}
	d, ok := h.setupDraftStore().Update(id, func(d *setup.SetupDraft) {
		if req.Profile != "" {
			d.Profile = setup.HardwareProfile(req.Profile)
		}
		if req.Custom != nil {
			d.Custom = req.Custom
			d.Profile = setup.ProfileCustom
		}
		if req.Username != "" {
			d.Username = req.Username
		}
		if req.AdminListen != "" {
			d.AdminListen = req.AdminListen
		}
		if req.AdminStrategy != "" {
			d.AdminStrategy = req.AdminStrategy
		}
		if req.Integrations != nil {
			d.Integrations = sanitizeSetupIntegrations(req.Integrations)
		}
		if req.Confirmed != nil {
			d.Confirmed = *req.Confirmed
		}
	})
	if !ok {
		writeError(w, http.StatusNotFound, "SETUP_DRAFT_NOT_FOUND", "setup draft not found or expired")
		return
	}
	writeData(w, d)
}

// sanitizeSetupIntegrations keeps the first-install draft useful for the
// review page without turning its JSON response into a secret store. The live
// runtime configuration is not written by this endpoint; connection secrets
// must be supplied again under System Settings after setup.
func sanitizeSetupIntegrations(in *setup.IntegrationsConfig) *setup.IntegrationsConfig {
	if in == nil {
		return nil
	}
	out := *in
	out.PostgresDSN = ""
	if parsed, err := url.Parse(strings.TrimSpace(out.VictoriaEndpoint)); err == nil && parsed.User != nil {
		parsed.User = nil
		out.VictoriaEndpoint = parsed.String()
	}
	return &out
}

// setupPostgreSQLTestRequest contains only the connection details needed for a
// one-shot first-install connectivity check. It is deliberately not a config
// patch: the password is used in memory for PingContext and is never echoed.
type setupPostgreSQLTestRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Host     string `json:"host"`
	Port     string `json:"port"`
	Database string `json:"database"`
	SSL      bool   `json:"ssl"`
}

// SetupPostgreSQLTest validates and pings the operator-supplied PostgreSQL
// endpoint while the setup lock is still open. Setup is a capability-gated,
// local-first flow, so private hosts are allowed here; this endpoint never
// persists the submitted values.
func (h *Handler) SetupPostgreSQLTest(w http.ResponseWriter, r *http.Request) {
	if !h.allowSetupMutation(w, r) {
		return
	}
	var req setupPostgreSQLTestRequest
	if !decode(w, r, &req) {
		return
	}
	dsn, err := buildSetupPostgreSQLDSN(req)
	if err != nil {
		writeError(w, http.StatusBadRequest, "SETUP_POSTGRES_INVALID", err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		writeError(w, http.StatusBadGateway, "SETUP_POSTGRES_UNREACHABLE", "无法连接 PostgreSQL，请检查地址、端口、账号、密码和 SSL 设置")
		return
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if err := db.PingContext(ctx); err != nil {
		writeError(w, http.StatusBadGateway, "SETUP_POSTGRES_UNREACHABLE", "无法连接 PostgreSQL，请检查地址、端口、账号、密码和 SSL 设置")
		return
	}
	writeData(w, map[string]any{
		"connected": true,
		"message":   "PostgreSQL 连接成功",
	})
}

type setupVictoriaLogsTestRequest struct {
	Endpoint string `json:"endpoint"`
}

// SetupVictoriaLogsTest performs a read-only HTTP probe against the configured
// write endpoint. A 4xx response still proves the service is reachable (the
// endpoint may only accept POST); 5xx and transport failures are reported as
// connectivity errors. No log payload is written during the probe.
func (h *Handler) SetupVictoriaLogsTest(w http.ResponseWriter, r *http.Request) {
	if !h.allowSetupMutation(w, r) {
		return
	}
	var req setupVictoriaLogsTestRequest
	if !decode(w, r, &req) {
		return
	}
	endpoint := strings.TrimSpace(req.Endpoint)
	policy := netguard.URLPolicy{
		Purpose:        "victorialogs endpoint",
		HostPurpose:    "victorialogs endpoint",
		AllowedSchemes: []string{"http", "https"},
		AllowPrivate:   true,
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	request, err := netguard.NewRequest(ctx, http.MethodGet, endpoint, nil, policy)
	if err != nil {
		writeError(w, http.StatusBadRequest, "SETUP_VICTORIALOGS_INVALID", "VictoriaLogs 地址无效，请填写 http:// 或 https:// 地址")
		return
	}
	resp, err := netguard.NewHTTPClient(netguard.HTTPClientOptions{Timeout: 8 * time.Second, Policy: policy}).Do(request)
	if err != nil {
		writeError(w, http.StatusBadGateway, "SETUP_VICTORIALOGS_UNREACHABLE", "无法连接 VictoriaLogs，请检查地址和网络")
		return
	}
	defer netguard.DrainAndClose(resp.Body)
	if resp.StatusCode >= http.StatusInternalServerError {
		writeError(w, http.StatusBadGateway, "SETUP_VICTORIALOGS_UNREACHABLE", "VictoriaLogs 返回了服务端错误，请检查地址和服务状态")
		return
	}
	writeData(w, map[string]any{
		"connected":   true,
		"status_code": resp.StatusCode,
		"message":     "VictoriaLogs 服务已响应",
	})
}

func buildSetupPostgreSQLDSN(req setupPostgreSQLTestRequest) (string, error) {
	username := strings.TrimSpace(req.Username)
	host := strings.TrimSpace(req.Host)
	port := strings.TrimSpace(req.Port)
	database := strings.TrimSpace(req.Database)
	if username == "" || host == "" || port == "" || database == "" {
		return "", errors.New("PostgreSQL 用户名、地址、端口和数据库不能为空")
	}
	if strings.ContainsAny(username, "\r\n\t") || strings.ContainsAny(host, "\r\n\t") || strings.ContainsAny(database, "\r\n\t") {
		return "", errors.New("PostgreSQL 连接字段不能包含控制字符")
	}
	if strings.ContainsAny(host, "/?#") || strings.ContainsAny(database, "/?#") {
		return "", errors.New("PostgreSQL 地址或数据库名格式无效")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return "", errors.New("PostgreSQL 端口必须是 1 到 65535 之间的数字")
	}
	host = strings.Trim(host, "[]")
	if host == "" {
		return "", errors.New("PostgreSQL 地址不能为空")
	}
	query := url.Values{}
	if req.SSL {
		query.Set("sslmode", "require")
	} else {
		query.Set("sslmode", "disable")
	}
	dsn := url.URL{
		Scheme:   "postgresql",
		User:     url.UserPassword(username, req.Password),
		Host:     net.JoinHostPort(host, strconv.Itoa(portNumber)),
		Path:     "/" + database,
		RawQuery: query.Encode(),
	}
	return dsn.String(), nil
}

func setupSessionID(r *http.Request) string {
	if r == nil {
		return ""
	}
	c, err := r.Cookie(setup.SetupSessionCookie)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(c.Value)
}

func (h *Handler) setupDataDir() string {
	if h != nil && h.currentConfig() != nil && h.currentConfig().Setup.DataDir != "" {
		return h.currentConfig().Setup.DataDir
	}
	return setup.DefaultDataDir
}
