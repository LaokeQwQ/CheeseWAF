package adapterapi

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

const (
	// Base64 inflates a body by 4/3, and the surrounding JSON (path, query,
	// headers, metadata) adds a bounded amount on top. Sizing this as
	// maxInspectBodyBytes+1MiB rejected any base64 body above ~24.75 MiB before
	// Request.Validate could enforce the real 32 MiB contract limit.
	maxInspectJSONBytes   = (maxInspectBodyBytes+2)/3*4 + 4<<20
	maxTelemetryJSONBytes = 1 << 20
)

type Inspector interface {
	InspectAdapter(context.Context, Request) (Decision, error)
}

type Handler struct {
	inspector Inspector
	tokenMu   sync.RWMutex
	token     string
	sink      storage.LogSink
	now       func() time.Time
}

func NewHandler(inspector Inspector, token string, sink storage.LogSink) (*Handler, error) {
	if inspector == nil {
		return nil, errors.New("adapter inspector is required")
	}
	return &Handler{
		inspector: inspector,
		token:     strings.TrimSpace(token),
		sink:      sink,
		now:       time.Now,
	}, nil
}

// SetToken replaces the shared adapter credential. The serving process calls it
// when server.adapter_token changes so a rotation takes effect without a
// restart; an empty token restores the loopback-only mode.
func (h *Handler) SetToken(token string) {
	if h == nil {
		return
	}
	h.tokenMu.Lock()
	h.token = strings.TrimSpace(token)
	h.tokenMu.Unlock()
}

func (h *Handler) currentToken() string {
	if h == nil {
		return ""
	}
	h.tokenMu.RLock()
	token := h.token
	h.tokenMu.RUnlock()
	return token
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/api/v1/adapter/inspect":
		h.inspect(w, r)
	case "/api/v1/adapter/telemetry":
		h.telemetry(w, r)
	case "/healthz":
		h.health(w, r)
	default:
		writeError(w, http.StatusNotFound, "not found")
	}
}

func (h *Handler) inspect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !h.authorized(w, r) {
		return
	}
	var request Request
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxInspectJSONBytes))
	if err := decoder.Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid inspection payload")
		return
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		writeError(w, http.StatusBadRequest, "inspection payload must contain one JSON object")
		return
	}
	if request.ContractVersion == "" {
		request.ContractVersion = Version
	}
	if request.Source == "" {
		request.Source = SourceGeneric
	}
	if err := request.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid inspection payload")
		return
	}
	decision, err := h.inspector.InspectAdapter(r.Context(), request)
	if err != nil {
		writeError(w, http.StatusBadGateway, "inspection unavailable")
		return
	}
	decision = decision.Normalized()
	if err := decision.Validate(); err != nil {
		writeError(w, http.StatusInternalServerError, "invalid inspection decision")
		return
	}
	writeJSON(w, http.StatusOK, decision)
}

func (h *Handler) telemetry(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !h.authorized(w, r) {
		return
	}
	if h.sink == nil {
		writeError(w, http.StatusServiceUnavailable, "telemetry sink is unavailable")
		return
	}
	var event TelemetryEvent
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxTelemetryJSONBytes))
	if err := decoder.Decode(&event); err != nil {
		writeError(w, http.StatusBadRequest, "invalid telemetry payload")
		return
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		writeError(w, http.StatusBadRequest, "telemetry payload must contain one JSON object")
		return
	}
	if event.ContractVersion == "" {
		event.ContractVersion = Version
	}
	if event.Source == "" {
		event.Source = SourceGeneric
	}
	if err := event.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid telemetry payload")
		return
	}
	entry := &storage.LogEntry{
		ID:         event.RequestID,
		Timestamp:  h.now().UTC(),
		TraceID:    event.RequestID,
		URI:        event.Path,
		StatusCode: event.StatusCode,
		Action:     string(event.Action),
		DetectorID: "adapter_telemetry",
		Category:   "adapter_telemetry",
		Severity:   "info",
		Message:    "adapter telemetry",
		Latency:    time.Duration(event.LatencyNanos),
		Metadata: map[string]any{
			"source":         string(event.Source),
			"policy_version": event.PolicyVersion,
		},
	}
	if entry.ID == "" {
		entry.ID = fmt.Sprintf("adapter-%d", h.now().UnixNano())
	}
	if err := h.sink.Write(r.Context(), entry); err != nil {
		writeError(w, http.StatusBadGateway, "telemetry unavailable")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "accepted"})
}

func (h *Handler) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *Handler) authorized(w http.ResponseWriter, r *http.Request) bool {
	token := h.currentToken()
	if token == "" {
		if loopbackPeer(r.RemoteAddr) {
			return true
		}
		writeError(w, http.StatusUnauthorized, "adapter authentication required")
		return false
	}
	provided := ""
	if values := r.Header.Values("X-CheeseWAF-Adapter-Token"); len(values) == 1 {
		provided = strings.TrimSpace(values[0])
	}
	if provided == "" {
		auth := strings.TrimSpace(r.Header.Get("Authorization"))
		if strings.HasPrefix(auth, "Bearer ") {
			provided = strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
		}
	}
	if provided == "" || subtle.ConstantTimeCompare([]byte(provided), []byte(token)) != 1 {
		w.Header().Set("WWW-Authenticate", "Bearer")
		writeError(w, http.StatusUnauthorized, "adapter authentication required")
		return false
	}
	return true
}

func loopbackPeer(remote string) bool {
	host, _, err := net.SplitHostPort(strings.TrimSpace(remote))
	if err != nil {
		return false
	}
	addr, err := netip.ParseAddr(strings.Trim(host, "[]"))
	return err == nil && addr.IsLoopback()
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
