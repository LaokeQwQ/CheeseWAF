package handler

import (
	"net/http"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/api/middleware"
	"github.com/LaokeQwQ/CheeseWAF/internal/netlease"
)

const (
	maxTemporaryHTTPBody     = 1 << 20
	maxTemporaryHTTPResponse = 4 << 20
)

// temporaryHTTPRequest deliberately excludes operator/session fields. Those
// values come from the already authenticated management session and cannot be
// spoofed by a browser or plugin caller.
type temporaryHTTPRequest struct {
	Password         string              `json:"password"`
	PluginID         string              `json:"plugin_id"`
	PluginVersion    string              `json:"plugin_version"`
	Target           netlease.Target     `json:"target"`
	TLSFingerprint   string              `json:"tls_fingerprint"`
	PolicyEpoch      uint64              `json:"policy_epoch"`
	TTL              time.Duration       `json:"ttl"`
	MaxBytes         int64               `json:"max_bytes"`
	Method           string              `json:"method"`
	Path             string              `json:"path"`
	Header           map[string][]string `json:"header,omitempty"`
	Body             []byte              `json:"body,omitempty"`
	MaxResponseBytes int64               `json:"max_response_bytes"`
}

// TemporaryHTTP executes exactly one administrator-approved HTTPS operation.
// It is intentionally mounted only inside the authenticated management API;
// the executor owns fresh session/confirmation/lease creation and cleanup.
func (h *Handler) TemporaryHTTP(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.TemporaryHTTPExecutor == nil {
		writeError(w, http.StatusServiceUnavailable, "TEMPORARY_NETWORK_UNAVAILABLE", "temporary network is not wired")
		return
	}
	claims, _ := r.Context().Value(middleware.UserContextKey).(*middleware.Claims)
	if claims == nil || claims.Subject == "" || claims.ID == "" {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "authenticated management session is required")
		return
	}
	var req temporaryHTTPRequest
	if !decode(w, r, &req) {
		return
	}
	if req.Password == "" || req.MaxBytes <= 0 || req.MaxBytes > maxTemporaryHTTPBody || req.MaxResponseBytes <= 0 || req.MaxResponseBytes > maxTemporaryHTTPResponse {
		writeError(w, http.StatusBadRequest, "TEMPORARY_NETWORK_INVALID", "temporary network limits or password are invalid")
		return
	}
	if int64(len(req.Body)) > req.MaxBytes {
		writeError(w, http.StatusBadRequest, "TEMPORARY_NETWORK_INVALID", "request body exceeds the approved byte limit")
		return
	}
	response, err := h.TemporaryHTTPExecutor.ExecuteTemporaryHTTP(r.Context(), netlease.TemporaryHTTPExecution{
		Identity:         netlease.AdministratorIdentity{ID: claims.Subject, ManagementSessionID: claims.ID},
		Password:         req.Password,
		PluginID:         req.PluginID,
		PluginVersion:    req.PluginVersion,
		Target:           req.Target,
		TLSFingerprint:   req.TLSFingerprint,
		PolicyEpoch:      req.PolicyEpoch,
		TTL:              req.TTL,
		MaxBytes:         req.MaxBytes,
		Method:           req.Method,
		Path:             req.Path,
		Header:           req.Header,
		Body:             req.Body,
		MaxResponseBytes: req.MaxResponseBytes,
	})
	if err != nil {
		writeError(w, http.StatusBadGateway, "TEMPORARY_NETWORK_FAILED", "temporary network operation was rejected or failed")
		return
	}
	writeData(w, map[string]any{
		"status_code":     response.StatusCode,
		"header":          response.Header,
		"body":            response.Body,
		"tls_fingerprint": response.TLSFingerprint,
		"remote_address":  response.RemoteAddress,
		"bytes_sent":      response.BytesSent,
		"bytes_received":  response.BytesReceived,
	})
}
