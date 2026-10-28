package pipeline

import (
	"fmt"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/intel"
	"github.com/LaokeQwQ/CheeseWAF/internal/intel/impact"
)

// Promote advances one candidate plan by one rollout step. It enforces the
// impact verdict, candidate TTL, and a named human approval before canary or
// active rollout (and before any rollout when impact requested review). Block
// actions additionally require approval through the impact policy gate.
//
// The candidate's Provenance.Approved/ApprovedBy fields are the approval
// record; callers set them before promotion. Promote returns updated values
// and never persists them.
func (p *Pipeline) Promote(candidate Candidate, plan impact.Plan, evidence impact.Evidence) (impact.Plan, Candidate, error) {
	if strings.TrimSpace(candidate.ID) == "" {
		return plan, candidate, fmt.Errorf("%w: candidate id is required", ErrInvalid)
	}
	if plan.CandidateID != candidate.ID {
		return plan, candidate, fmt.Errorf("%w: plan candidate %q does not match candidate %q", ErrInvalid, plan.CandidateID, candidate.ID)
	}
	if plan.Action != candidate.Action {
		return plan, candidate, fmt.Errorf("%w: plan action %q does not match candidate action %q", ErrInvalid, plan.Action, candidate.Action)
	}
	if !candidate.Impact.Verdict.Valid() {
		return plan, candidate, fmt.Errorf("%w: impact verdict is missing or unknown", ErrInvalid)
	}
	if candidate.Impact.CandidateID != "" && candidate.Impact.CandidateID != candidate.ID {
		return plan, candidate, fmt.Errorf("%w: impact assessment belongs to %q", ErrInvalid, candidate.Impact.CandidateID)
	}
	if candidate.Impact.Verdict == impact.VerdictReject {
		reason := strings.Join(candidate.Impact.Reasons, "; ")
		if reason == "" {
			reason = "impact assessment rejected the candidate"
		}
		return plan, candidate, fmt.Errorf("%w: %s", ErrImpactRejected, reason)
	}

	now := p.now().UTC()
	if expiresAt := candidate.ExpiresAt(); !expiresAt.IsZero() && !now.Before(expiresAt) {
		return plan, candidate, fmt.Errorf("%w: candidate %q expired at %s", ErrExpired, candidate.ID, expiresAt.Format(time.RFC3339))
	}

	approved := candidate.Provenance.Approved
	approver := strings.TrimSpace(candidate.Provenance.ApprovedBy)
	if approved && approver == "" {
		return plan, candidate, fmt.Errorf("%w: approval must name an approver", ErrApprovalRequired)
	}
	if !approved {
		approver = ""
	}

	switch plan.State {
	case impact.PlanRolledBack, impact.PlanExpired:
		return plan, candidate, fmt.Errorf("%w: cannot promote a %s plan", ErrInvalid, plan.State)
	case impact.PlanDraft, impact.PlanShadow, impact.PlanCanary, impact.PlanActive:
	default:
		return plan, candidate, fmt.Errorf("%w: unknown plan state %q", ErrInvalid, plan.State)
	}

	requireApproval := candidate.Impact.Verdict == impact.VerdictNeedsReview ||
		plan.State == impact.PlanShadow ||
		plan.State == impact.PlanCanary ||
		plan.State == impact.PlanActive
	if requireApproval && !approved {
		return plan, candidate, fmt.Errorf("%w: candidate %q requires a named human approval before %s", ErrApprovalRequired, candidate.ID, plan.State)
	}

	if approved && !plan.Approved {
		next, err := plan.Approve(approver, now, p.impactPolicy)
		if err != nil {
			return plan, candidate, err
		}
		plan = next
	}

	var err error
	switch plan.State {
	case impact.PlanDraft:
		plan, err = plan.StartShadow(now, p.impactPolicy)
	case impact.PlanShadow:
		plan, err = plan.StartCanary(p.canaryPercent, evidence, now, p.impactPolicy)
	case impact.PlanCanary:
		plan, err = plan.Activate(evidence, now, p.impactPolicy)
	case impact.PlanActive:
		// Already fully promoted; report the current state unchanged.
	}
	if err != nil {
		return plan, candidate, err
	}

	candidate.State = promotedState(plan.State)
	if approved {
		candidate.Provenance.Approved = true
		candidate.Provenance.ApprovedBy = approver
	}
	if err := intel.ValidateCandidate(candidate.Candidate); err != nil {
		return plan, candidate, fmt.Errorf("%w: promoted candidate is invalid: %w", ErrInvalid, err)
	}
	return plan, candidate, nil
}

func promotedState(state impact.PlanState) intel.CandidateState {
	switch state {
	case impact.PlanShadow:
		return intel.CandidateShadow
	case impact.PlanCanary:
		return intel.CandidateCanary
	case impact.PlanActive:
		return intel.CandidateActive
	default:
		return intel.CandidateDraft
	}
}
