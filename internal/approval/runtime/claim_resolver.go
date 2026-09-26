package runtime

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/approval"
	"github.com/LaokeQwQ/CheeseWAF/internal/crp/activation"
)

var (
	ErrApprovalClaimNotFound  = errors.New("approved CRP claim was not found")
	ErrApprovalClaimAmbiguous = errors.New("multiple approved CRP claims matched")
	ErrApprovalClaimInvalid   = errors.New("approved CRP claim metadata is invalid")
	ErrApprovalClaimExpired   = errors.New("approved CRP claim has expired")
)

const maxCRPApprovalClaimTTL = 5 * time.Minute

// ApprovalClaimResolver exposes the metadata-only bridge from the restored
// approval gate to CRP activation. The returned resolver never confirms an
// approval and never receives or forwards password/TOTP material.
func (s *Service) ApprovalClaimResolver() activation.ApprovalClaimResolver {
	if s == nil || s.gate == nil || s.clock == nil || s.policyEpoch == 0 {
		return nil
	}
	return func(ctx context.Context, request activation.AuthorizationRequest) (activation.ApprovalClaim, error) {
		if ctx == nil {
			return activation.ApprovalClaim{}, ErrApprovalClaimInvalid
		}
		if err := ctx.Err(); err != nil {
			return activation.ApprovalClaim{}, err
		}
		epoch := s.gate.PolicyEpoch()
		if epoch == 0 || epoch != s.policyEpoch {
			return activation.ApprovalClaim{}, fmt.Errorf("%w: gate epoch does not match runtime epoch", ErrApprovalClaimInvalid)
		}
		claim, err := resolveApprovalClaim(s.gate.ApprovedRecords(), epoch, s.clock().UTC(), request)
		if err != nil {
			return activation.ApprovalClaim{}, err
		}
		if s.gate.PolicyEpoch() != epoch {
			return activation.ApprovalClaim{}, fmt.Errorf("%w: gate epoch changed during resolution", ErrApprovalClaimInvalid)
		}
		return claim, nil
	}
}

func resolveApprovalClaim(records []approval.Record, policyEpoch uint64, now time.Time, request activation.AuthorizationRequest) (activation.ApprovalClaim, error) {
	intentDigest := activation.ApprovalIntentDigest(request)
	scope := activation.ApprovalScope(request)
	if policyEpoch == 0 || now.IsZero() || request.RequestedAt.IsZero() || intentDigest == "" || scope == "" {
		return activation.ApprovalClaim{}, ErrApprovalClaimInvalid
	}

	var matched activation.ApprovalClaim
	matches := 0
	expired := false
	for _, record := range records {
		if record.Status != approval.StatusApproved || record.Request.IntentDigest != intentDigest || record.Request.Scope != scope || record.Request.PolicyEpoch != policyEpoch {
			continue
		}
		claim, err := claimFromApprovedRecord(record, now, request.RequestedAt)
		if errors.Is(err, ErrApprovalClaimExpired) {
			expired = true
			continue
		}
		if err != nil {
			return activation.ApprovalClaim{}, err
		}
		matches++
		if matches > 1 {
			return activation.ApprovalClaim{}, ErrApprovalClaimAmbiguous
		}
		matched = claim
	}
	if matches == 0 {
		if expired {
			return activation.ApprovalClaim{}, ErrApprovalClaimExpired
		}
		return activation.ApprovalClaim{}, ErrApprovalClaimNotFound
	}
	return matched, nil
}

func claimFromApprovedRecord(record approval.Record, now, requestedAt time.Time) (activation.ApprovalClaim, error) {
	if err := approval.ValidateRecordForAdapter(record); err != nil {
		return activation.ApprovalClaim{}, fmt.Errorf("%w: %v", ErrApprovalClaimInvalid, err)
	}
	commit := record.Commit
	confirmation := record.Confirmation
	if commit == nil || commit.Risk != record.Request.Risk || commit.TTL != record.Request.TTL || commit.ConfirmationLanguage != record.Request.ConfirmationLanguage ||
		confirmation.ConfirmationID != commit.ConfirmationID || confirmation.Actor != commit.Actor || confirmation.Scope != commit.Scope || confirmation.PolicyEpoch != commit.PolicyEpoch ||
		confirmation.TTL != commit.TTL || confirmation.SessionID != commit.SessionID || confirmation.IntentDigest != commit.IntentDigest || confirmation.WorkflowDigest != commit.WorkflowDigest || confirmation.Nonce != commit.Nonce {
		return activation.ApprovalClaim{}, ErrApprovalClaimInvalid
	}
	if !now.Before(commit.ExpiresAt) || !requestedAt.Before(commit.ExpiresAt) {
		return activation.ApprovalClaim{}, ErrApprovalClaimExpired
	}
	if now.Before(commit.IssuedAt) || requestedAt.Before(commit.IssuedAt) {
		return activation.ApprovalClaim{}, ErrApprovalClaimInvalid
	}
	effectiveTTL := commit.ExpiresAt.Sub(commit.IssuedAt)
	if effectiveTTL <= 0 || effectiveTTL > maxCRPApprovalClaimTTL {
		return activation.ApprovalClaim{}, ErrApprovalClaimInvalid
	}
	return activation.ApprovalClaim{
		ApprovalID:     record.ID,
		ConfirmationID: commit.ConfirmationID,
		Actor:          commit.Actor,
		Scope:          commit.Scope,
		PolicyEpoch:    commit.PolicyEpoch,
		TTL:            effectiveTTL,
		IssuedAt:       commit.IssuedAt,
		ExpiresAt:      commit.ExpiresAt,
		WorkflowDigest: commit.WorkflowDigest,
		IntentDigest:   commit.IntentDigest,
		Nonce:          commit.Nonce,
		SessionID:      commit.SessionID,
	}, nil
}
