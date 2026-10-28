package impact

import (
	"fmt"
	"math"
	"strings"
	"time"
)

// PlanState is the rollout state of one candidate plan.
type PlanState string

const (
	PlanDraft      PlanState = "draft"
	PlanShadow     PlanState = "shadow"
	PlanCanary     PlanState = "canary"
	PlanActive     PlanState = "active"
	PlanRolledBack PlanState = "rolled_back"
	PlanExpired    PlanState = "expired"
)

// Valid reports whether the state is one of the supported values.
func (s PlanState) Valid() bool {
	switch s {
	case PlanDraft, PlanShadow, PlanCanary, PlanActive, PlanRolledBack, PlanExpired:
		return true
	default:
		return false
	}
}

func (s PlanState) terminal() bool {
	return s == PlanRolledBack || s == PlanExpired
}

// PlanConfig is the immutable input for a new rollout plan.
type PlanConfig struct {
	CandidateID string
	Action      string
	TTL         time.Duration
}

// Plan tracks one candidate's rollout. All transition methods have value
// receivers and return a new Plan; callers persist the returned value.
type Plan struct {
	CandidateID     string    `json:"candidate_id"`
	Action          string    `json:"action"`
	State           PlanState `json:"state"`
	Revision        int64     `json:"revision"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
	ExpiresAt       time.Time `json:"expires_at"`
	ShadowStartedAt time.Time `json:"shadow_started_at,omitempty"`
	CanaryStartedAt time.Time `json:"canary_started_at,omitempty"`
	ActivatedAt     time.Time `json:"activated_at,omitempty"`
	RolledBackAt    time.Time `json:"rolled_back_at,omitempty"`
	CanaryPercent   float64   `json:"canary_percent,omitempty"`
	Approved        bool      `json:"approved,omitempty"`
	ApprovedBy      string    `json:"approved_by,omitempty"`
	StableState     PlanState `json:"stable_state"`
	StableRevision  int64     `json:"stable_revision"`
	RollbackReason  string    `json:"rollback_reason,omitempty"`
}

// Evidence is the observation set used by promotion gates.
type Evidence struct {
	Observations   int64 `json:"observations"`
	Errors         int64 `json:"errors"`
	FalsePositives int64 `json:"false_positives"`
}

// Health is the live canary/active observation set used for automatic rollback.
type Health struct {
	Requests       int64 `json:"requests"`
	Errors         int64 `json:"errors"`
	FalsePositives int64 `json:"false_positives"`
}

// ErrorRate returns the error share, or zero when there are no requests.
func (h Health) ErrorRate() float64 {
	return ratioInt(h.Errors, h.Requests)
}

// FalsePositiveRate returns the false-positive share, or zero without requests.
func (h Health) FalsePositiveRate() float64 {
	return ratioInt(h.FalsePositives, h.Requests)
}

func (h Health) validate() error {
	if h.Requests < 0 || h.Errors < 0 || h.FalsePositives < 0 {
		return fmt.Errorf("%w: health counters must not be negative", ErrInvalidPlan)
	}
	if h.Errors > h.Requests || h.FalsePositives > h.Requests {
		return fmt.Errorf("%w: health counters exceed requests", ErrInvalidPlan)
	}
	return nil
}

func (e Evidence) validate() error {
	if e.Observations < 0 || e.Errors < 0 || e.FalsePositives < 0 {
		return fmt.Errorf("%w: evidence counters must not be negative", ErrInvalidPlan)
	}
	if e.Errors > e.Observations || e.FalsePositives > e.Observations {
		return fmt.Errorf("%w: evidence counters exceed observations", ErrInvalidPlan)
	}
	return nil
}

func (e Evidence) errorRate() float64 {
	return ratioInt(e.Errors, e.Observations)
}

func (e Evidence) falsePositiveRate() float64 {
	return ratioInt(e.FalsePositives, e.Observations)
}

// Rollback reports the stable revision a plan returns to. Applied is false when
// the plan was already terminal or had not started, making repeated rollback
// calls idempotent.
type Rollback struct {
	PriorState    PlanState `json:"prior_state"`
	PriorRevision int64     `json:"prior_revision"`
	FromState     PlanState `json:"from_state"`
	FromRevision  int64     `json:"from_revision"`
	Reason        string    `json:"reason"`
	Applied       bool      `json:"applied"`
}

// NewPlan creates a draft plan with a bounded TTL.
func NewPlan(config PlanConfig, now time.Time, policy Policy) (Plan, error) {
	effective := policy.effective()
	if err := effective.Validate(); err != nil {
		return Plan{}, err
	}

	candidateID := strings.TrimSpace(config.CandidateID)
	if candidateID == "" || len(candidateID) > maxIDBytes {
		return Plan{}, fmt.Errorf("%w: candidate id must be 1-%d bytes", ErrInvalidPlan, maxIDBytes)
	}
	action := strings.ToLower(strings.TrimSpace(config.Action))
	switch action {
	case "log", "challenge", "block":
	default:
		return Plan{}, fmt.Errorf("%w: action must be log, challenge, or block", ErrInvalidPlan)
	}
	if config.TTL <= 0 {
		return Plan{}, fmt.Errorf("%w: TTL must be positive", ErrInvalidPlan)
	}
	if config.TTL > effective.MaxTTL {
		return Plan{}, fmt.Errorf("%w: TTL exceeds maximum %s", ErrInvalidPlan, effective.MaxTTL)
	}

	return Plan{
		CandidateID:    candidateID,
		Action:         action,
		State:          PlanDraft,
		Revision:       1,
		CreatedAt:      now,
		UpdatedAt:      now,
		ExpiresAt:      now.Add(config.TTL),
		StableState:    PlanDraft,
		StableRevision: 1,
	}, nil
}

// CheckExpiry expires a live plan whose TTL has elapsed. Terminal plans are
// never changed.
func (p Plan) CheckExpiry(now time.Time) (Plan, bool) {
	if p.State.terminal() || p.ExpiresAt.IsZero() || now.Before(p.ExpiresAt) {
		return p, false
	}
	p.State = PlanExpired
	p.Revision++
	p.UpdatedAt = now
	return p, true
}

// Expired reports whether the plan's TTL has elapsed at now.
func (p Plan) Expired(now time.Time) bool {
	return !p.State.terminal() && !p.ExpiresAt.IsZero() && !now.Before(p.ExpiresAt)
}

// Approve records human approval. It is idempotent once approved.
func (p Plan) Approve(by string, now time.Time, policy Policy) (Plan, error) {
	if err := checkPlan(p, policy); err != nil {
		return p, err
	}
	p, expired := p.CheckExpiry(now)
	if expired || p.State == PlanExpired {
		return p, ErrPlanExpired
	}
	if p.State.terminal() {
		return p, fmt.Errorf("%w: cannot approve a %s plan", ErrInvalidTransition, p.State)
	}
	if p.Approved {
		return p, nil
	}
	by = strings.TrimSpace(by)
	if by == "" || len(by) > maxIDBytes {
		return p, fmt.Errorf("%w: approver must be 1-%d bytes", ErrInvalidPlan, maxIDBytes)
	}
	p.Approved = true
	p.ApprovedBy = by
	p.Revision++
	p.UpdatedAt = now
	return p, nil
}

// StartShadow moves a draft plan into non-blocking observation.
func (p Plan) StartShadow(now time.Time, policy Policy) (Plan, error) {
	if err := checkPlan(p, policy); err != nil {
		return p, err
	}
	p, expired := p.CheckExpiry(now)
	if expired || p.State == PlanExpired {
		return p, ErrPlanExpired
	}
	if p.State == PlanShadow {
		return p, nil
	}
	if p.State != PlanDraft {
		return p, fmt.Errorf("%w: shadow requires draft, got %s", ErrInvalidTransition, p.State)
	}
	p.State = PlanShadow
	p.Revision++
	p.ShadowStartedAt = now
	p.UpdatedAt = now
	p.StableState = PlanShadow
	p.StableRevision = p.Revision
	return p, nil
}

// StartCanary promotes a shadow plan after the minimum shadow duration and
// minimum observation count. Block actions additionally require approval.
func (p Plan) StartCanary(percent float64, evidence Evidence, now time.Time, policy Policy) (Plan, error) {
	if err := checkPlan(p, policy); err != nil {
		return p, err
	}
	effective := policy.effective()
	p, expired := p.CheckExpiry(now)
	if expired || p.State == PlanExpired {
		return p, ErrPlanExpired
	}
	if p.State != PlanShadow {
		return p, fmt.Errorf("%w: canary requires shadow, got %s", ErrInvalidTransition, p.State)
	}
	if err := evidence.validate(); err != nil {
		return p, err
	}
	if evidence.Observations < effective.MinObservations {
		return p, fmt.Errorf("%w: %d < %d", ErrInsufficientSamples, evidence.Observations, effective.MinObservations)
	}
	if p.ShadowStartedAt.IsZero() || now.Before(p.ShadowStartedAt) {
		return p, fmt.Errorf("%w: shadow start time is invalid", ErrInvalidTransition)
	}
	if elapsed := now.Sub(p.ShadowStartedAt); elapsed < effective.MinShadowDuration {
		return p, fmt.Errorf("%w: %s < %s", ErrShadowTooShort, elapsed, effective.MinShadowDuration)
	}
	if math.IsNaN(percent) || math.IsInf(percent, 0) || percent < effective.CanaryMinPercent || percent > effective.CanaryMaxPercent {
		return p, fmt.Errorf("%w: %v not within [%v, %v]", ErrInvalidCanaryPercent, percent, effective.CanaryMinPercent, effective.CanaryMaxPercent)
	}
	if !p.Approved && p.Action == "block" && !effective.AllowUnapprovedBlock {
		return p, fmt.Errorf("%w: block action %q has no approver", ErrApprovalRequired, p.CandidateID)
	}
	if evidence.errorRate() > effective.MaxErrorRate {
		return p, fmt.Errorf("%w: shadow error rate %s", ErrHealthThreshold, formatPercent(evidence.errorRate()))
	}
	if evidence.falsePositiveRate() > effective.MaxFalsePositiveRate {
		return p, fmt.Errorf("%w: shadow false-positive rate %s", ErrHealthThreshold, formatPercent(evidence.falsePositiveRate()))
	}

	p.State = PlanCanary
	p.Revision++
	p.CanaryPercent = percent
	p.CanaryStartedAt = now
	p.UpdatedAt = now
	return p, nil
}

// Activate promotes a canary plan to full blocking after health gates pass.
func (p Plan) Activate(evidence Evidence, now time.Time, policy Policy) (Plan, error) {
	if err := checkPlan(p, policy); err != nil {
		return p, err
	}
	effective := policy.effective()
	p, expired := p.CheckExpiry(now)
	if expired || p.State == PlanExpired {
		return p, ErrPlanExpired
	}
	if p.State != PlanCanary {
		return p, fmt.Errorf("%w: activation requires canary, got %s", ErrInvalidTransition, p.State)
	}
	if err := evidence.validate(); err != nil {
		return p, err
	}
	if evidence.Observations < effective.MinObservations {
		return p, fmt.Errorf("%w: %d < %d", ErrInsufficientSamples, evidence.Observations, effective.MinObservations)
	}
	if !p.Approved && p.Action == "block" && !effective.AllowUnapprovedBlock {
		return p, fmt.Errorf("%w: block action %q has no approver", ErrApprovalRequired, p.CandidateID)
	}
	if evidence.errorRate() > effective.MaxErrorRate {
		return p, fmt.Errorf("%w: canary error rate %s", ErrHealthThreshold, formatPercent(evidence.errorRate()))
	}
	if evidence.falsePositiveRate() > effective.MaxFalsePositiveRate {
		return p, fmt.Errorf("%w: canary false-positive rate %s", ErrHealthThreshold, formatPercent(evidence.falsePositiveRate()))
	}

	p.State = PlanActive
	p.Revision++
	p.CanaryPercent = 100
	p.ActivatedAt = now
	p.UpdatedAt = now
	return p, nil
}

// EvaluateHealth applies automatic rollback when a canary or active plan
// exceeds the configured error or false-positive thresholds.
func (p Plan) EvaluateHealth(health Health, now time.Time, policy Policy) (Plan, *Rollback) {
	effective := policy.effective()
	if err := effective.Validate(); err != nil {
		return p, nil
	}
	p, expired := p.CheckExpiry(now)
	if expired {
		return p, nil
	}
	if p.State != PlanCanary && p.State != PlanActive {
		return p, nil
	}
	if err := health.validate(); err != nil || health.Requests == 0 {
		return p, nil
	}

	reasons := make([]string, 0, 2)
	if rate := health.ErrorRate(); rate > effective.MaxErrorRate {
		reasons = append(reasons, fmt.Sprintf("error rate %s exceeds %s", formatPercent(rate), formatPercent(effective.MaxErrorRate)))
	}
	if rate := health.FalsePositiveRate(); rate > effective.MaxFalsePositiveRate {
		reasons = append(reasons, fmt.Sprintf("false-positive rate %s exceeds %s", formatPercent(rate), formatPercent(effective.MaxFalsePositiveRate)))
	}
	if len(reasons) == 0 {
		return p, nil
	}

	reason := "automatic rollback: " + strings.Join(reasons, "; ")
	next, result := p.Rollback(reason, now)
	return next, &result
}

// Rollback disables a live plan and reports the prior stable state/revision.
// It has no external side effects. Calls on an already rolled-back plan are
// idempotent and return the original reason without changing the revision.
func (p Plan) Rollback(reason string, now time.Time) (Plan, Rollback) {
	if p.State == PlanRolledBack {
		return p, Rollback{
			PriorState:    p.StableState,
			PriorRevision: p.StableRevision,
			FromState:     p.State,
			FromRevision:  p.Revision,
			Reason:        p.RollbackReason,
			Applied:       false,
		}
	}
	if p.State == PlanExpired {
		return p, Rollback{
			PriorState:    p.StableState,
			PriorRevision: p.StableRevision,
			FromState:     p.State,
			FromRevision:  p.Revision,
			Reason:        "plan expired",
			Applied:       false,
		}
	}
	if p.State == PlanDraft {
		return p, Rollback{
			PriorState:    p.StableState,
			PriorRevision: p.StableRevision,
			FromState:     p.State,
			FromRevision:  p.Revision,
			Reason:        "plan has not started",
			Applied:       false,
		}
	}

	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = "rollback requested"
	}
	result := Rollback{
		PriorState:    p.StableState,
		PriorRevision: p.StableRevision,
		FromState:     p.State,
		FromRevision:  p.Revision,
		Reason:        reason,
		Applied:       true,
	}
	p.State = PlanRolledBack
	p.Revision++
	p.RollbackReason = reason
	p.RolledBackAt = now
	p.UpdatedAt = now
	return p, result
}

func checkPlan(p Plan, policy Policy) error {
	effective := policy.effective()
	if err := effective.Validate(); err != nil {
		return err
	}
	if !p.State.Valid() {
		return fmt.Errorf("%w: unknown state %q", ErrInvalidPlan, p.State)
	}
	if p.Revision <= 0 {
		return fmt.Errorf("%w: revision must be positive", ErrInvalidPlan)
	}
	if !p.StableState.Valid() || p.StableRevision <= 0 || p.StableRevision > p.Revision {
		return fmt.Errorf("%w: stable state/revision is invalid", ErrInvalidPlan)
	}
	if strings.TrimSpace(p.CandidateID) == "" {
		return fmt.Errorf("%w: candidate id is empty", ErrInvalidPlan)
	}
	if p.Approved && strings.TrimSpace(p.ApprovedBy) == "" {
		return fmt.Errorf("%w: approved plan has no approver", ErrInvalidPlan)
	}
	switch p.Action {
	case "log", "challenge", "block":
	default:
		return fmt.Errorf("%w: unknown action %q", ErrInvalidPlan, p.Action)
	}
	if p.ExpiresAt.IsZero() || !p.ExpiresAt.After(p.CreatedAt) {
		return fmt.Errorf("%w: plan expiry is invalid", ErrInvalidPlan)
	}
	if p.ExpiresAt.Sub(p.CreatedAt) > effective.MaxTTL {
		return fmt.Errorf("%w: plan TTL exceeds maximum %s", ErrInvalidPlan, effective.MaxTTL)
	}
	return nil
}
