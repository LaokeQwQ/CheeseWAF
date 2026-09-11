package approval

import (
	"errors"
	"sync"
	"time"
)

// WorkflowRoute describes the decision made by the core security kernel. A
// workflow sidecar may provide a visual DAG and notifications, but it cannot
// turn a route into an AuthorizationCommit.
type WorkflowRoute string

const (
	WorkflowAutoApproved   WorkflowRoute = "auto_approved"
	WorkflowLocalManual    WorkflowRoute = "local_manual"
	WorkflowSidecarPending WorkflowRoute = "workflow_pending"
	WorkflowBreakGlass     WorkflowRoute = "break_glass_pending"
)

type WorkflowPlan struct {
	Route               WorkflowRoute `json:"route"`
	WorkflowAvailable   bool          `json:"workflow_available"`
	RequiresInteractive bool          `json:"requires_interactive"`
	RequiresWorkflow    bool          `json:"requires_workflow"`
	RequiresBreakGlass  bool          `json:"requires_break_glass"`
	Reason              string        `json:"reason"`
}

// PlanWorkflow applies the 39/50 fallback matrix. It is deliberately pure:
// no sidecar, timer, network or persistence call is made here.
func PlanWorkflow(req Request, workflowAvailable bool) (WorkflowPlan, error) {
	normalized := req
	if err := normalizeRequest(&normalized); err != nil {
		return WorkflowPlan{}, ErrInvalidRequest
	}
	if normalized.Risk == RiskEmergency {
		return WorkflowPlan{Route: WorkflowBreakGlass, WorkflowAvailable: workflowAvailable, RequiresInteractive: true, RequiresWorkflow: workflowAvailable, RequiresBreakGlass: true, Reason: "emergency operations require restricted break-glass confirmation"}, nil
	}
	if normalized.Risk == RiskLow && normalized.PreApproved && !normalized.sensitive() && !normalized.BreakGlass {
		return WorkflowPlan{Route: WorkflowAutoApproved, WorkflowAvailable: workflowAvailable, Reason: "explicit low-risk pre-approval"}, nil
	}
	if normalized.sensitive() || normalized.Risk == RiskHigh {
		return WorkflowPlan{Route: WorkflowSidecarPending, WorkflowAvailable: workflowAvailable, RequiresInteractive: true, RequiresWorkflow: true, Reason: "sensitive or high-risk operation cannot be auto-approved"}, nil
	}
	return WorkflowPlan{Route: WorkflowLocalManual, WorkflowAvailable: workflowAvailable, RequiresInteractive: true, Reason: "ordinary operation requires local human confirmation"}, nil
}

// WorkflowBinding is the sidecar's read-only snapshot of the core request.
// Every field is compared exactly before a sidecar event can be merged.
type WorkflowBinding struct {
	ApprovalID     string        `json:"approval_id"`
	ConfirmationID string        `json:"confirmation_id,omitempty"`
	IntentDigest   string        `json:"intent_digest"`
	WorkflowDigest string        `json:"workflow_digest,omitempty"`
	Scope          string        `json:"scope"`
	SessionID      string        `json:"session_id"`
	Nonce          string        `json:"nonce"`
	PolicyEpoch    uint64        `json:"policy_epoch"`
	EventSequence  uint64        `json:"event_sequence"`
	TTL            time.Duration `json:"ttl"`
}

var (
	ErrWorkflowBinding    = errors.New("workflow binding does not match approval state")
	ErrWorkflowEventStale = errors.New("workflow event sequence is stale")
	ErrBatchInvalid       = errors.New("logical super batch is invalid")
	ErrDelegationInvalid  = errors.New("approval delegation is invalid")
	ErrDelegationReplay   = errors.New("approval delegation has already been consumed")
	ErrDelegationChain    = errors.New("approval delegation cannot be chained")
	ErrDelegationSelf     = errors.New("approval delegation cannot target its issuer")
)

// WorkflowBindingFor returns the current binding and latest core audit event
// sequence. It is a snapshot only; callers must validate it again immediately
// before merging or executing an operation.
func (g *Gate) WorkflowBindingFor(now time.Time, requestID string) (WorkflowBinding, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	record, ok := g.requests[requestID]
	if !ok {
		return WorkflowBinding{}, ErrNotFound
	}
	if !now.Before(record.ExpiresAt) {
		return WorkflowBinding{}, ErrExpired
	}
	if record.Status == StatusRevoked {
		return WorkflowBinding{}, ErrRevoked
	}
	sequence := uint64(0)
	for _, event := range g.audit {
		if event.RequestID == record.ID && event.Sequence > sequence {
			sequence = event.Sequence
		}
	}
	if sequence == 0 {
		return WorkflowBinding{}, ErrWorkflowBinding
	}
	confirmationID := record.Confirmation.ConfirmationID
	if record.Commit != nil {
		confirmationID = record.Commit.ConfirmationID
	}
	return WorkflowBinding{ApprovalID: record.ID, ConfirmationID: confirmationID, IntentDigest: record.Request.IntentDigest, WorkflowDigest: record.Request.WorkflowDigest, Scope: record.Request.Scope, SessionID: record.Request.SessionID, Nonce: record.Request.Nonce, PolicyEpoch: record.Request.PolicyEpoch, EventSequence: sequence, TTL: record.Request.TTL}, nil
}

// ValidateWorkflowBinding checks the sidecar snapshot against the core gate.
// It never grants authorization and is safe to call from a persistence adapter
// or a preflight path.
func (g *Gate) ValidateWorkflowBinding(now time.Time, requestID string, binding WorkflowBinding) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	record, ok := g.requests[requestID]
	if !ok {
		return ErrNotFound
	}
	if record.Status == StatusRevoked {
		return ErrRevoked
	}
	if !now.Before(record.ExpiresAt) {
		return ErrExpired
	}
	if binding.ApprovalID != requestID || binding.IntentDigest != record.Request.IntentDigest || binding.WorkflowDigest != record.Request.WorkflowDigest || binding.Scope != record.Request.Scope || binding.SessionID != record.Request.SessionID || binding.Nonce != record.Request.Nonce || binding.PolicyEpoch != record.Request.PolicyEpoch || binding.TTL != record.Request.TTL || binding.EventSequence == 0 {
		return ErrWorkflowBinding
	}
	if record.Commit != nil && binding.ConfirmationID != record.Commit.ConfirmationID {
		return ErrWorkflowBinding
	}
	if record.Commit == nil && binding.ConfirmationID != "" && binding.ConfirmationID != record.Confirmation.ConfirmationID {
		return ErrWorkflowBinding
	}
	latest := uint64(0)
	for _, event := range g.audit {
		if event.RequestID == requestID && event.Sequence > latest {
			latest = event.Sequence
		}
	}
	if binding.EventSequence != latest {
		return ErrWorkflowEventStale
	}
	return nil
}

// ValidateSuperBatch verifies the prepare barrier for a logical all-or-none
// batch. It does not mutate any request or make a child operation visible.
func ValidateSuperBatch(bindings []WorkflowBinding) error {
	if len(bindings) == 0 {
		return ErrBatchInvalid
	}
	seen := make(map[string]struct{}, len(bindings))
	baseEpoch := bindings[0].PolicyEpoch
	baseWorkflow := bindings[0].WorkflowDigest
	for _, binding := range bindings {
		if ValidateIdentifier(binding.ApprovalID) != nil || !validDigest(binding.IntentDigest) || (binding.WorkflowDigest != "" && ValidateIdentifier(binding.WorkflowDigest) != nil) || ValidateIdentifier(binding.Scope) != nil || ValidateIdentifier(binding.SessionID) != nil || ValidateIdentifier(binding.Nonce) != nil || (binding.ConfirmationID != "" && ValidateIdentifier(binding.ConfirmationID) != nil) || binding.PolicyEpoch == 0 || binding.EventSequence == 0 || binding.TTL <= 0 {
			return ErrBatchInvalid
		}
		if binding.PolicyEpoch != baseEpoch || binding.WorkflowDigest != baseWorkflow {
			return ErrBatchInvalid
		}
		if _, exists := seen[binding.ApprovalID]; exists {
			return ErrBatchInvalid
		}
		seen[binding.ApprovalID] = struct{}{}
	}
	return nil
}

// ApprovalDelegation is a one-hop, one-time handoff for a preconfigured
// workflow. The core still requires the delegate to submit a fresh
// Confirmation; delegation is not an authorization commit.
type ApprovalDelegation struct {
	ID                string    `json:"id"`
	ApprovalID        string    `json:"approval_id"`
	Issuer            string    `json:"issuer"`
	IssuerSessionID   string    `json:"issuer_session_id"`
	Delegate          string    `json:"delegate"`
	DelegateSessionID string    `json:"delegate_session_id"`
	Scope             string    `json:"scope"`
	IntentDigest      string    `json:"intent_digest"`
	WorkflowDigest    string    `json:"workflow_digest,omitempty"`
	PolicyEpoch       uint64    `json:"policy_epoch"`
	IssuedAt          time.Time `json:"issued_at"`
	ExpiresAt         time.Time `json:"expires_at"`
	OneTime           bool      `json:"one_time"`
	ParentID          string    `json:"parent_id,omitempty"`
}

func ValidateApprovalDelegation(record Record, delegation ApprovalDelegation, now time.Time) error {
	if record.Status == StatusRevoked || record.Status == StatusExpired || !now.Before(record.ExpiresAt) {
		return ErrDelegationInvalid
	}
	if ValidateIdentifier(delegation.ID) != nil || delegation.ApprovalID != record.ID || ValidateIdentifier(delegation.Issuer) != nil || ValidateIdentifier(delegation.IssuerSessionID) != nil || ValidateIdentifier(delegation.Delegate) != nil || ValidateIdentifier(delegation.DelegateSessionID) != nil || ValidateIdentifier(delegation.Scope) != nil || !validDigest(delegation.IntentDigest) || (delegation.WorkflowDigest != "" && ValidateIdentifier(delegation.WorkflowDigest) != nil) || delegation.PolicyEpoch != record.Request.PolicyEpoch || delegation.Issuer != record.Request.Actor || delegation.IssuerSessionID != record.Request.SessionID || delegation.Scope != record.Request.Scope || delegation.IntentDigest != record.Request.IntentDigest || delegation.WorkflowDigest != record.Request.WorkflowDigest || !delegation.OneTime || delegation.ParentID != "" || delegation.Issuer == delegation.Delegate || !delegation.IssuedAt.Before(delegation.ExpiresAt) || !now.Before(delegation.ExpiresAt) || delegation.ExpiresAt.After(record.ExpiresAt) {
		if delegation.ParentID != "" {
			return ErrDelegationChain
		}
		if delegation.Issuer == delegation.Delegate {
			return ErrDelegationSelf
		}
		return ErrDelegationInvalid
	}
	return nil
}

type DelegationLedger struct {
	mu   sync.Mutex
	used map[string]struct{}
}

func NewDelegationLedger() *DelegationLedger {
	return &DelegationLedger{used: make(map[string]struct{})}
}

func (l *DelegationLedger) Consume(now time.Time, record Record, delegation ApprovalDelegation) error {
	if l == nil {
		return ErrDelegationInvalid
	}
	if err := ValidateApprovalDelegation(record, delegation, now); err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, exists := l.used[delegation.ID]; exists {
		return ErrDelegationReplay
	}
	l.used[delegation.ID] = struct{}{}
	return nil
}
