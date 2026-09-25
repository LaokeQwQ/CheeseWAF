package handler

import (
	"errors"
	"net/http"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/api/middleware"
	"github.com/LaokeQwQ/CheeseWAF/internal/cwedp"
	"github.com/LaokeQwQ/CheeseWAF/internal/cwedp/consumer"
	"github.com/LaokeQwQ/CheeseWAF/internal/netlease"
)

const maxCWEDPDownloadBytes int64 = cwedp.DefaultMaxArtifactBytes

// cwedpDownloadRequest has no operator, management-session, endpoint, TLS,
// registry, or trust-root fields. The authenticated session and the injected
// production consumer provide those authorities; a browser may only submit a
// signed intent and fresh credential proof for one request.
type cwedpDownloadRequest struct {
	Password     string                   `json:"password"`
	Intent       cwedp.DistributionIntent `json:"intent"`
	Hello        cwedp.Hello              `json:"hello"`
	Capabilities cwedp.Capabilities       `json:"capabilities"`
	PolicyEpoch  uint64                   `json:"policy_epoch"`
	TTLSeconds   int64                    `json:"ttl_seconds"`
	MaxBytes     int64                    `json:"max_bytes"`
}

// DownloadCWEDP executes one authenticated, durable transfer and stages the
// admitted CRP. It never promotes, activates, or starts the staged package.
func (h *Handler) DownloadCWEDP(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.CWEDPDownload == nil {
		writeError(w, http.StatusServiceUnavailable, "CWEDP_UNAVAILABLE", "CWEDP download is not wired")
		return
	}
	claims, _ := r.Context().Value(middleware.UserContextKey).(*middleware.Claims)
	if claims == nil || claims.Subject == "" || claims.ID == "" || claims.Username == "" {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "authenticated management session is required")
		return
	}
	var request cwedpDownloadRequest
	if !decode(w, r, &request) {
		return
	}
	if request.Password == "" || request.TTLSeconds <= 0 || request.TTLSeconds > int64(netlease.MaxLeaseTTL/time.Second) || request.MaxBytes <= 0 || request.MaxBytes > maxCWEDPDownloadBytes {
		writeError(w, http.StatusBadRequest, "CWEDP_INVALID", "CWEDP limits or password are invalid")
		return
	}
	// Confirm against the current server-side account after session middleware
	// has validated the management session. This cannot be satisfied by a
	// management API token or by identity fields supplied in JSON.
	if !h.verifyCurrentCallerPassword(r, request.Password) {
		writeError(w, http.StatusBadRequest, "CWEDP_CONFIRMATION_FAILED", "CWEDP confirmation was rejected")
		return
	}
	result, err := h.CWEDPDownload.DownloadCWEDP(r.Context(), consumer.Request{
		Identity:     netlease.AdministratorIdentity{ID: claims.Subject, ManagementSessionID: claims.ID},
		Password:     request.Password,
		Intent:       request.Intent,
		Hello:        request.Hello,
		Capabilities: request.Capabilities,
		PolicyEpoch:  request.PolicyEpoch,
		TTL:          time.Duration(request.TTLSeconds) * time.Second,
		MaxBytes:     request.MaxBytes,
	})
	if err != nil {
		switch {
		case errors.Is(err, consumer.ErrUnavailable):
			writeError(w, http.StatusServiceUnavailable, "CWEDP_UNAVAILABLE", "CWEDP download is not available")
		case errors.Is(err, consumer.ErrRequest), errors.Is(err, cwedp.ErrInvalid), errors.Is(err, cwedp.ErrIntentSignature):
			writeError(w, http.StatusBadRequest, "CWEDP_REJECTED", "CWEDP request was rejected")
		default:
			// Do not expose source, certificate, lease, or CRP admission detail to
			// the browser. The durable audit/transfer records remain authoritative.
			writeError(w, http.StatusBadGateway, "CWEDP_FAILED", "CWEDP transfer or staging failed")
		}
		return
	}
	writeData(w, map[string]any{
		"job_id":                result.JobID,
		"source":                result.Source.ID,
		"stage_status":          string(result.Staged.Slot),
		"plugin_key":            result.Staged.Key,
		"version":               result.Staged.Version,
		"revision":              result.Staged.Revision,
		"manifest_identity":     result.Staged.ManifestIdentity,
		"artifact_identity":     result.Staged.ArtifactIdentity,
		"requires_confirmation": result.Staged.RequiresConfirm,
		"activation_performed":  false,
	})
}
