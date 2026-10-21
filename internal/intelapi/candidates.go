package intelapi

import (
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode"

	"github.com/go-chi/chi/v5"

	"github.com/LaokeQwQ/CheeseWAF/internal/api/middleware"
	"github.com/LaokeQwQ/CheeseWAF/internal/intel"
	"github.com/LaokeQwQ/CheeseWAF/internal/intel/impact"
	"github.com/LaokeQwQ/CheeseWAF/internal/intel/pipeline"
	"github.com/LaokeQwQ/CheeseWAF/internal/intelstore"
)

const (
	maxApproverBytesValue = 128
	maxRejectReasonBytes  = 512
)

type approveRequest struct {
	ApprovedBy string     `json:"approved_by"`
	Action     string     `json:"action,omitempty"`
	Confirm    bool       `json:"confirm"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
}

type rejectRequest struct {
	RejectedBy string `json:"rejected_by,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

type candidateResponse struct {
	Candidate intel.Candidate    `json:"candidate"`
	Plan      *impact.Plan       `json:"plan,omitempty"`
	Impact    *impact.Assessment `json:"impact,omitempty"`
}

type itemsResponse struct {
	Items []intel.Item `json:"items"`
	Count int          `json:"count"`
}

type candidatesResponse struct {
	Candidates []intel.Candidate `json:"candidates"`
	Count      int               `json:"count"`
}

type impactResponse struct {
	SiteID      string              `json:"site_id"`
	Profiles    int                 `json:"profiles"`
	Assessments []impact.Assessment `json:"assessments"`
}

func (h *handler) handleListItems(w http.ResponseWriter, r *http.Request) {
	limit, err := parseLimit(r)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "invalid_limit", "limit must be a positive integer")
		return
	}
	state, err := parseState(r)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "invalid_state", "state is not a known candidate state")
		return
	}
	items, err := h.store.ListItems(r.Context(), intelstore.ItemFilter{Limit: limit, State: state})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "storage_error", "could not list intelligence items")
		return
	}
	writeJSON(w, http.StatusOK, itemsResponse{Items: items, Count: len(items)})
}

func (h *handler) handleListCandidates(w http.ResponseWriter, r *http.Request) {
	limit, err := parseLimit(r)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "invalid_limit", "limit must be a positive integer")
		return
	}
	state, err := parseState(r)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "invalid_state", "state is not a known candidate state")
		return
	}
	siteID := strings.TrimSpace(r.URL.Query().Get("site_id"))
	if siteID != "" {
		if err := (intel.Scope{SiteID: siteID}).Validate(); err != nil {
			writeError(w, http.StatusUnprocessableEntity, "invalid_site", "site_id is not valid")
			return
		}
	}
	candidates, err := h.store.ListCandidates(r.Context(), intelstore.CandidateFilter{Limit: limit, SiteID: siteID, State: state})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "storage_error", "could not list rule candidates")
		return
	}
	writeJSON(w, http.StatusOK, candidatesResponse{Candidates: candidates, Count: len(candidates)})
}

func (h *handler) handleGetCandidate(w http.ResponseWriter, r *http.Request) {
	candidate, err := h.store.GetCandidate(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		writeCandidateStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, candidateResponse{Candidate: candidate})
}

func (h *handler) handleApproveCandidate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var request approveRequest
	if err := decodeBody(w, r, maxApproveBodyBytes, &request); err != nil {
		writeDecodeError(w, err)
		return
	}
	approver, err := h.authenticatedActor(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "unauthenticated", "an authenticated reviewer is required")
		return
	}
	if !request.Confirm {
		writeError(w, http.StatusUnprocessableEntity, "confirmation_required", "confirm must be true to approve a candidate")
		return
	}

	candidate, err := h.store.GetCandidate(ctx, chi.URLParam(r, "id"))
	if err != nil {
		writeCandidateStoreError(w, err)
		return
	}
	switch candidate.State {
	case intel.CandidateRejected:
		writeError(w, http.StatusConflict, "already_rejected", "rejected candidates cannot be approved")
		return
	case intel.CandidateExpired:
		writeError(w, http.StatusConflict, "expired", "expired candidates cannot be approved")
		return
	}

	targetAction := candidate.Action
	if raw := strings.TrimSpace(request.Action); raw != "" {
		targetAction = strings.ToLower(raw)
	}
	switch targetAction {
	case intel.ActionLog, intel.ActionChallenge, intel.ActionBlock:
	default:
		writeError(w, http.StatusUnprocessableEntity, "invalid_action", "action must be log, challenge, or block")
		return
	}

	preview := candidate
	if targetAction != candidate.Action {
		rewritten, err := intelstore.RewriteRuleAction(candidate.RuleJSON, targetAction)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "invalid_candidate", "stored candidate rule is not valid")
			return
		}
		preview.RuleJSON = rewritten
		preview.Action = targetAction
	}
	preview.Provenance.Approved = true
	preview.Provenance.ApprovedBy = approver
	structural := preview
	if targetAction == intel.ActionBlock {
		// Block candidates are only valid in canary or active rollout, which the
		// promotion gate below decides. Validate the rest of the record against
		// the target state so a corrupt rule cannot slip through.
		structural.State = intel.CandidateCanary
	}
	if err := intel.ValidateCandidate(structural); err != nil {
		writeError(w, http.StatusConflict, "candidate_state", "candidate cannot be approved in its current state")
		return
	}

	policy := impact.DefaultPolicy()
	view, err := impactView(preview)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "invalid_candidate", "stored candidate rule is not valid")
		return
	}
	var profiles []impact.Profile
	if h.profiles != nil {
		profiles, err = h.profiles(ctx, view)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "profile_error", "impact profiles are unavailable")
			return
		}
	}
	assessment := policy.Estimate(view, profiles)
	if assessment.Verdict == impact.VerdictReject {
		writeErrorReasons(w, http.StatusConflict, "impact_rejected", "impact assessment rejected this candidate", assessment.Reasons)
		return
	}

	now := h.now().UTC()
	planTTL := candidate.TTL
	if planTTL <= 0 || planTTL > policy.MaxTTL {
		planTTL = policy.MaxTTL
	}
	plan, err := impact.NewPlan(impact.PlanConfig{CandidateID: candidate.ID, Action: targetAction, TTL: planTTL}, now, policy)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "plan_error", "could not build a rollout plan")
		return
	}

	promotedState := candidate.State
	var nextPlan *impact.Plan
	promote := false

	if targetAction == intel.ActionBlock {
		if assessment.Verdict != impact.VerdictAllowShadow {
			reasons := assessment.Reasons
			if len(reasons) == 0 {
				reasons = []string{"no profile evidence is available"}
			}
			writeErrorReasons(w, http.StatusConflict, "impact_insufficient",
				"block promotion requires impact evidence that the candidate is safe to enforce", reasons)
			return
		}
		switch candidate.State {
		case intel.CandidateCanary, intel.CandidateActive:
			// Already enforcing: record the approval without changing rollout.
		case intel.CandidateShadow:
			shadowStarted := candidate.UpdatedAt
			if shadowStarted.IsZero() {
				shadowStarted = candidate.CreatedAt
			}
			if now.Sub(shadowStarted) < policy.MinShadowDuration {
				writeError(w, http.StatusConflict, "shadow_too_short",
					"block promotion requires at least one shadow observation window")
				return
			}
			plan, err = plan.StartShadow(shadowStarted, policy)
			if err != nil {
				writeErrorReasons(w, http.StatusConflict, "promotion_rejected", "rollout gates rejected the candidate", []string{err.Error()})
				return
			}
			promote = true
		default:
			writeError(w, http.StatusConflict, "shadow_required",
				"block promotion requires the candidate to complete a shadow stage first")
			return
		}
	} else if candidate.State == intel.CandidateDraft {
		promote = true
	}

	if promote {
		evidence := impact.Evidence{Observations: assessment.Observations, FalsePositives: assessment.BenignBlocks}
		promotedPlan, promoted, err := h.promotePipeline.Promote(pipeline.Candidate{Candidate: preview, Impact: assessment}, plan, evidence)
		if err != nil {
			status, code, message, reasons := mapPromoteError(err)
			writeErrorReasons(w, status, code, message, reasons)
			return
		}
		nextPlan = &promotedPlan
		promotedState = promoted.State
	}

	state := promotedState
	updated, err := h.store.UpdateCandidate(ctx, candidate.ID, intelstore.CandidateUpdate{
		State:         &state,
		Action:        &targetAction,
		ApprovedBy:    approver,
		ExpiresAt:     request.ExpiresAt,
		ExpectedState: &candidate.State,
	})
	if err != nil {
		if errors.Is(err, intelstore.ErrConflict) {
			writeError(w, http.StatusConflict, "stale_candidate", "candidate changed while it was being approved; reload and retry")
			return
		}
		if errors.Is(err, intelstore.ErrNotFound) {
			writeCandidateStoreError(w, err)
			return
		}
		if errors.Is(err, intelstore.ErrInvalid) {
			writeError(w, http.StatusUnprocessableEntity, "invalid_update", "candidate approval update is not valid")
			return
		}
		writeError(w, http.StatusInternalServerError, "storage_error", "could not persist the candidate approval")
		return
	}

	assessment.CandidateID = updated.ID
	writeJSON(w, http.StatusOK, candidateResponse{Candidate: updated, Plan: nextPlan, Impact: &assessment})
}

func (h *handler) handleRejectCandidate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var request rejectRequest
	if err := decodeOptionalBody(w, r, maxApproveBodyBytes, &request); err != nil {
		writeDecodeError(w, err)
		return
	}
	actor, err := h.authenticatedActor(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "unauthenticated", "an authenticated reviewer is required")
		return
	}
	if request.Reason != "" {
		if len(request.Reason) > maxRejectReasonBytes || hasControl(request.Reason) {
			writeError(w, http.StatusUnprocessableEntity, "invalid_reason", "reason exceeds the length limit or contains control characters")
			return
		}
	}

	candidate, err := h.store.GetCandidate(ctx, chi.URLParam(r, "id"))
	if err != nil {
		writeCandidateStoreError(w, err)
		return
	}
	if candidate.State == intel.CandidateRejected {
		writeError(w, http.StatusConflict, "already_rejected", "candidate is already rejected")
		return
	}
	if candidate.State == intel.CandidateExpired {
		writeError(w, http.StatusConflict, "expired", "expired candidates cannot be rejected")
		return
	}
	state := intel.CandidateRejected
	action := intel.ActionLog
	updated, err := h.store.UpdateCandidate(ctx, candidate.ID, intelstore.CandidateUpdate{State: &state, Action: &action, ApprovedBy: actor, ExpectedState: &candidate.State})
	if err != nil {
		if errors.Is(err, intelstore.ErrConflict) {
			writeError(w, http.StatusConflict, "stale_candidate", "candidate changed while it was being rejected; reload and retry")
			return
		}
		if errors.Is(err, intelstore.ErrNotFound) {
			writeCandidateStoreError(w, err)
			return
		}
		writeError(w, http.StatusInternalServerError, "storage_error", "could not persist the rejection")
		return
	}
	writeJSON(w, http.StatusOK, candidateResponse{Candidate: updated})
}

func (h *handler) authenticatedActor(r *http.Request) (string, error) {
	if h != nil && h.actor != nil {
		return validateApproverActor(h.actor(r))
	}
	claims, _ := r.Context().Value(middleware.UserContextKey).(*middleware.Claims)
	if claims == nil {
		return "", ErrUnauthorized
	}
	return validateApproverActor(claims.Subject, nil)
}

func validateApproverActor(actor string, err error) (string, error) {
	if err != nil {
		return "", err
	}
	return validateApprover(actor)
}

func (h *handler) handleImpact(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	siteID := strings.TrimSpace(r.URL.Query().Get("site_id"))
	if siteID == "" {
		writeError(w, http.StatusUnprocessableEntity, "invalid_site", "site_id is required")
		return
	}
	if err := (intel.Scope{SiteID: siteID}).Validate(); err != nil {
		writeError(w, http.StatusUnprocessableEntity, "invalid_site", "site_id is not valid")
		return
	}
	candidates, err := h.store.ListCandidates(ctx, intelstore.CandidateFilter{SiteID: siteID, Limit: intelstore.MaxListLimit})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "storage_error", "could not list rule candidates")
		return
	}
	policy := impact.DefaultPolicy()
	assessments := make([]impact.Assessment, 0, len(candidates))
	profileCount := 0
	for _, candidate := range candidates {
		view, err := impactView(candidate)
		if err != nil {
			continue
		}
		var profiles []impact.Profile
		if h.profiles != nil {
			profiles, err = h.profiles(ctx, view)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "profile_error", "impact profiles are unavailable")
				return
			}
		}
		profileCount += len(profiles)
		assessments = append(assessments, policy.Estimate(view, profiles))
	}
	writeJSON(w, http.StatusOK, impactResponse{SiteID: siteID, Profiles: profileCount, Assessments: assessments})
}

func impactView(candidate intel.Candidate) (impact.Candidate, error) {
	compiled, err := intel.DecodeCompiledRule([]byte(candidate.RuleJSON))
	if err != nil {
		return impact.Candidate{}, err
	}
	return impact.Candidate{
		ID:         candidate.ID,
		SiteID:     candidate.SiteID,
		PathPrefix: compiled.Scope.PathPrefix,
		Methods:    compiled.Scope.Methods,
		Action:     candidate.Action,
		Approved:   candidate.Provenance.Approved,
	}, nil
}

func mapPromoteError(err error) (int, string, string, []string) {
	switch {
	case errors.Is(err, pipeline.ErrImpactRejected):
		return http.StatusConflict, "impact_rejected", "impact assessment rejected this candidate", nil
	case errors.Is(err, pipeline.ErrApprovalRequired):
		return http.StatusConflict, "approval_required", "promotion requires a named human approval", nil
	case errors.Is(err, pipeline.ErrExpired), errors.Is(err, impact.ErrPlanExpired):
		return http.StatusConflict, "expired", "candidate or rollout plan has expired", nil
	case errors.Is(err, impact.ErrInsufficientSamples),
		errors.Is(err, impact.ErrShadowTooShort),
		errors.Is(err, impact.ErrHealthThreshold),
		errors.Is(err, impact.ErrInvalidTransition):
		return http.StatusConflict, "promotion_rejected", "rollout gates rejected the promotion", []string{err.Error()}
	default:
		return http.StatusConflict, "promotion_rejected", "candidate cannot be promoted", nil
	}
}

func validateApprover(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > maxApproverBytesValue || hasControl(value) {
		return "", errors.New("invalid approver")
	}
	return value, nil
}

func hasControl(value string) bool {
	for _, r := range value {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}

func writeCandidateStoreError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, intelstore.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "candidate not found")
	case errors.Is(err, intelstore.ErrInvalid):
		writeError(w, http.StatusUnprocessableEntity, "invalid_id", "candidate id is not valid")
	default:
		writeError(w, http.StatusInternalServerError, "storage_error", "candidate storage failed")
	}
}
