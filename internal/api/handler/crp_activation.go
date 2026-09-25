package handler

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/api/middleware"
	"github.com/LaokeQwQ/CheeseWAF/internal/crp"
	"github.com/LaokeQwQ/CheeseWAF/internal/crp/activation"
)

const maxCRPActivationProbeCount = 64

// CRPActivationExecutor is the management-plane seam backed by the production
// activation service. The HTTP layer cannot inject a fence, confirmation or
// approval claim; it can only request an operation that the service must bind
// to an already-approved durable record.
type CRPActivationExecutor interface {
	ExecuteCRPActivation(context.Context, activation.AsyncRequest) (activation.ActivationResult, error)
}

type crpActivationRequest struct {
	PluginKey           string                       `json:"plugin_key"`
	ExpectedRevision    uint64                       `json:"expected_revision"`
	Descriptor          activation.SidecarDescriptor `json:"descriptor"`
	ObserveProbes       int                          `json:"observe_probes"`
	CanaryProbes        int                          `json:"canary_probes"`
	ProbeTimeoutSeconds int64                        `json:"probe_timeout_seconds"`
}

func (h *Handler) ActivateCRP(w http.ResponseWriter, r *http.Request) {
	h.executeCRPActivation(w, r, crp.RuntimeActionPromote)
}

func (h *Handler) RollbackCRP(w http.ResponseWriter, r *http.Request) {
	h.executeCRPActivation(w, r, crp.RuntimeActionRollback)
}

func (h *Handler) executeCRPActivation(w http.ResponseWriter, r *http.Request, action crp.RuntimeAction) {
	if h == nil || h.CRPActivation == nil {
		writeError(w, http.StatusServiceUnavailable, "CRP_ACTIVATION_UNAVAILABLE", "CRP activation is not wired")
		return
	}
	claims, _ := r.Context().Value(middleware.UserContextKey).(*middleware.Claims)
	if claims == nil || claims.Subject == "" || claims.ID == "" || claims.Username == "" {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "authenticated management session is required")
		return
	}
	var request crpActivationRequest
	if !decode(w, r, &request) {
		return
	}
	if request.PluginKey == "" || request.PluginKey != strings.TrimSpace(request.PluginKey) || request.ExpectedRevision == 0 ||
		request.ObserveProbes < 1 || request.ObserveProbes > maxCRPActivationProbeCount ||
		request.CanaryProbes < 1 || request.CanaryProbes > maxCRPActivationProbeCount ||
		request.ProbeTimeoutSeconds < 1 || request.ProbeTimeoutSeconds > int64(time.Minute/time.Second) {
		writeError(w, http.StatusBadRequest, "CRP_ACTIVATION_INVALID", "CRP activation request is invalid")
		return
	}
	result, err := h.CRPActivation.ExecuteCRPActivation(r.Context(), activation.AsyncRequest{
		Action:           action,
		Key:              request.PluginKey,
		ExpectedRevision: request.ExpectedRevision,
		Descriptor:       request.Descriptor,
		Policy: activation.CanaryPolicy{
			ObserveProbes: request.ObserveProbes,
			CanaryProbes:  request.CanaryProbes,
			ProbeTimeout:  time.Duration(request.ProbeTimeoutSeconds) * time.Second,
		},
	})
	if err != nil {
		writeCRPActivationError(w, err)
		return
	}
	writeData(w, map[string]any{
		"phase":             result.Phase,
		"plugin_key":        result.Record.Key,
		"version":           result.Record.Version,
		"revision":          result.Record.Revision,
		"manifest_identity": result.Record.ManifestIdentity,
		"fence_epoch":       result.Fence.Epoch,
		"fence_revision":    result.Fence.Revision,
	})
}

func writeCRPActivationError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, activation.ErrAsyncQueueFull):
		writeError(w, http.StatusTooManyRequests, "CRP_ACTIVATION_BUSY", "CRP activation queue is full")
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		writeError(w, http.StatusRequestTimeout, "CRP_ACTIVATION_TIMEOUT", "CRP activation did not complete")
	case errors.Is(err, activation.ErrApprovalClaimUnavailable), errors.Is(err, activation.ErrAuthorizationDenied),
		errors.Is(err, activation.ErrAuthorizationBinding), errors.Is(err, crp.ErrRuntimeConflict),
		errors.Is(err, crp.ErrRuntimeNotFound):
		writeError(w, http.StatusConflict, "CRP_ACTIVATION_REJECTED", "CRP activation was rejected")
	case errors.Is(err, activation.ErrControlPlaneUnavailable), errors.Is(err, activation.ErrSidecarUnavailable):
		writeError(w, http.StatusServiceUnavailable, "CRP_ACTIVATION_UNAVAILABLE", "CRP activation dependency is unavailable")
	case errors.Is(err, activation.ErrInvalidDescriptor), errors.Is(err, activation.ErrCapabilityDenied),
		errors.Is(err, activation.ErrResourceLimit), errors.Is(err, activation.ErrAsyncAction):
		writeError(w, http.StatusBadRequest, "CRP_ACTIVATION_INVALID", "CRP activation request is invalid")
	default:
		writeError(w, http.StatusBadGateway, "CRP_ACTIVATION_FAILED", "CRP activation failed")
	}
}
