package ai

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/approval"
	"github.com/google/uuid"
)

var (
	// ErrHighRiskApprovalUnavailable is returned when a destructive AI tool
	// has no usable core approval gate. The safe result is to refuse the
	// operation, never to fall back to ApprovalStore.ApproveFor.
	ErrHighRiskApprovalUnavailable = errors.New("high-risk AI approval gate is unavailable")

	// ErrHighRiskApproverRequired prevents the requester from approving their
	// own destructive AI request through the gate adapter.
	ErrHighRiskApproverRequired = errors.New("a different approver is required for high-risk AI approval")

	ErrHighRiskConfirmationNotStarted        = errors.New("high-risk AI confirmation has not been started")
	ErrHighRiskCommitUnavailable             = errors.New("high-risk AI authorization commit is unavailable")
	ErrUnsupportedGateApprovalTool           = errors.New("gate approval adapter only handles destructive AI tools")
	ErrHighRiskCredentialVerifierUnavailable = errors.New("high-risk AI credential verifier is unavailable")
	ErrHighRiskCredentialRejected            = errors.New("high-risk AI credential was rejected")
	ErrHighRiskCredentialProofInvalid        = errors.New("high-risk AI credential proof is invalid")
)

// GateApprovalChallenge is the server-created challenge returned before a
// destructive AI request can be confirmed. WarningStartedAt is authoritative;
// callers cannot supply an earlier timestamp to bypass the ten-second delay.
type GateApprovalChallenge struct {
	ApprovalID                string    `json:"approval_id"`
	ConfirmationID            string    `json:"confirmation_id"`
	WarningStartedAt          time.Time `json:"warning_started_at"`
	ExpiresAt                 time.Time `json:"expires_at"`
	Language                  string    `json:"language"`
	Phrase                    string    `json:"phrase"`
	ConfirmationStep          uint8     `json:"confirmation_step"`
	RequiresThirdConfirmation bool      `json:"requires_third_confirmation"`
}

// GateApprovalCredentialProof is an opaque result produced by the injected
// credential verifier. Callers cannot construct a valid proof by setting the
// confirmation booleans on GateApprovalConfirmation; the adapter ignores those
// legacy fields and only forwards verifier-produced proof state to the core
// gate.
type GateApprovalCredentialProof struct {
	token             string
	passwordConfirmed bool
	totpConfirmed     bool
}

// NewGateApprovalCredentialProof creates a proof for a trusted credential
// verifier. The token must be non-empty and the proof must attest at least one
// credential type.
func NewGateApprovalCredentialProof(token string, passwordConfirmed, totpConfirmed bool) GateApprovalCredentialProof {
	return GateApprovalCredentialProof{token: token, passwordConfirmed: passwordConfirmed, totpConfirmed: totpConfirmed}
}

// Token returns the verifier-issued token for audit or downstream binding.
func (p GateApprovalCredentialProof) Token() string { return p.token }

func (p GateApprovalCredentialProof) valid() bool {
	return p.token != "" && approval.ValidateIdentifier(p.token) == nil && (p.passwordConfirmed || p.totpConfirmed)
}

// GateApprovalCredentialVerifier verifies operator credentials and returns a
// verifier-issued proof. Returning an empty proof is treated as failure.
type GateApprovalCredentialVerifier func(context.Context, ApprovalActor, GateApprovalConfirmation) (GateApprovalCredentialProof, error)

// GateApprovalConfirmation contains operator-entered confirmation data.
// Actor, session, locality, scope, nonce, warning timestamp and confirmation
// ID are all supplied by the adapter from the authenticated challenge state.
type GateApprovalConfirmation struct {
	// PasswordConfirmed and TOTPConfirmed are retained for source compatibility
	// with older in-process callers. They are deliberately ignored by Confirm.
	PasswordConfirmed  bool   `json:"-"`
	TOTPConfirmed      bool   `json:"-"`
	Password           string `json:"password,omitempty"`
	TOTPCode           string `json:"totp_code,omitempty"`
	SecondConfirmation bool   `json:"second_confirmation"`
	ThirdConfirmation  bool   `json:"third_confirmation"`
	ConfirmationPhrase string `json:"confirmation_phrase"`
}

// GateApprovalResult carries the compatibility ApprovalRequest plus the core
// commit when the three-step flow completes. On the first high-risk click,
// Confirm returns this result together with approval.ErrThirdConfirmation.
type GateApprovalResult struct {
	Approval  ApprovalRequest               `json:"approval"`
	Commit    *approval.AuthorizationCommit `json:"commit,omitempty"`
	Challenge GateApprovalChallenge         `json:"challenge"`
}

type gateApprovalBinding struct {
	toolName     string
	scope        string
	intentDigest string
	requester    ApprovalActor
}

type gateApprovalChallengeState struct {
	challenge    GateApprovalChallenge
	approver     ApprovalActor
	scope        string
	intentDigest string
}

// GateApprovalAdapter is the narrow bridge between the historical AI
// ApprovalStore API and internal/approval's strict core gate. It intentionally
// handles only Destructive tools. Modify tools continue using the legacy API
// until their HTTP/UI flow can provide the same explicit confirmation fields.
//
// The adapter keeps the core gate and the compatibility store separate. The
// store remains the public AI request snapshot and argument binding; the gate
// is the authority for high-risk confirmation. If either side disagrees,
// execution is refused. A process restart loses the in-memory gate challenge
// and therefore fails closed for any old pending destructive request.
type GateApprovalAdapter struct {
	store       *ApprovalStore
	gate        *approval.Gate
	policyEpoch uint64
	now         func() time.Time

	mu                 sync.Mutex
	bindings           map[string]gateApprovalBinding
	challenges         map[string]gateApprovalChallengeState
	credentialVerifier GateApprovalCredentialVerifier
}

// NewGateApprovalAdapter creates an adapter over an existing AI store. The
// caller must pass the same store to NewAssistantWithApprovalGate so API
// snapshots and execution use one compatibility record.
func NewGateApprovalAdapter(store *ApprovalStore, gate *approval.Gate, policyEpoch uint64) (*GateApprovalAdapter, error) {
	if store == nil || gate == nil || policyEpoch == 0 {
		return nil, ErrHighRiskApprovalUnavailable
	}
	return &GateApprovalAdapter{
		store:       store,
		gate:        gate,
		policyEpoch: policyEpoch,
		now:         time.Now,
		bindings:    make(map[string]gateApprovalBinding),
		challenges:  make(map[string]gateApprovalChallengeState),
	}, nil
}

// NewGateApprovalAdapterWithCredentialVerifier is the fail-closed constructor
// for callers that can inject a server-side credential verifier.
func NewGateApprovalAdapterWithCredentialVerifier(store *ApprovalStore, gate *approval.Gate, policyEpoch uint64, verifier GateApprovalCredentialVerifier) (*GateApprovalAdapter, error) {
	adapter, err := NewGateApprovalAdapter(store, gate, policyEpoch)
	if err != nil {
		return nil, err
	}
	adapter.SetCredentialVerifier(verifier)
	return adapter, nil
}

// SetCredentialVerifier injects the server-side verifier used by future
// confirmations. A nil verifier intentionally leaves the adapter fail-closed.
func (a *GateApprovalAdapter) SetCredentialVerifier(verifier GateApprovalCredentialVerifier) {
	if a == nil {
		return
	}
	a.mu.Lock()
	a.credentialVerifier = verifier
	a.mu.Unlock()
}

// Store returns the compatibility store used by the adapter. It is intended
// for wiring checks and does not grant access to the gate.
func (a *GateApprovalAdapter) Store() *ApprovalStore {
	if a == nil {
		return nil
	}
	return a.store
}

func (a *GateApprovalAdapter) ensure() error {
	if a == nil || a.store == nil || a.gate == nil || a.policyEpoch == 0 {
		return ErrHighRiskApprovalUnavailable
	}
	return nil
}

func (a *GateApprovalAdapter) nowUTC() time.Time {
	now := time.Now
	if a != nil && a.now != nil {
		now = a.now
	}
	return now().UTC()
}

// CreateFor creates a pending destructive AI request whose requester identity
// is required before the gate challenge can be opened.
func (a *GateApprovalAdapter) CreateFor(tool Tool, args map[string]any, diff string, actor ApprovalActor) (ApprovalRequest, error) {
	return a.CreateForWithPreview(tool, args, diff, "", actor)
}

// CreateForWithPreview preserves the existing AI argument/preview digest while
// recording a parallel immutable intent digest for internal/approval.
func (a *GateApprovalAdapter) CreateForWithPreview(tool Tool, args map[string]any, diff, preview string, actor ApprovalActor) (ApprovalRequest, error) {
	if err := a.ensure(); err != nil {
		return ApprovalRequest{}, err
	}
	if tool == nil || tool.Sensitivity() != Destructive {
		return ApprovalRequest{}, ErrUnsupportedGateApprovalTool
	}
	if err := validateGateActor(actor); err != nil {
		return ApprovalRequest{}, err
	}
	if !a.store.CanPersistModifications() {
		return ApprovalRequest{}, ErrHighRiskApprovalUnavailable
	}
	request, err := a.store.CreateForWithPreview(tool, args, diff, preview, actor)
	if err != nil {
		return ApprovalRequest{}, err
	}
	binding := gateApprovalBinding{
		toolName:     request.ToolName,
		scope:        "ai:tool:" + request.ToolName,
		intentDigest: gateIntentDigest(request),
		requester:    actor,
	}
	a.mu.Lock()
	a.bindings[request.ID] = binding
	a.mu.Unlock()
	return request, nil
}

// BeginConfirmation starts the server-held warning window for a second
// approver and reserves a fresh confirmation ID. It does not authorize the
// request; the caller must wait at least approval.WarningDelay before calling
// Confirm.
func (a *GateApprovalAdapter) BeginConfirmation(id string, actor ApprovalActor, language string) (GateApprovalChallenge, error) {
	if err := a.ensure(); err != nil {
		return GateApprovalChallenge{}, err
	}
	request, ok := a.store.Get(id)
	if !ok {
		return GateApprovalChallenge{}, fmt.Errorf("approval request %q not found", id)
	}
	if request.Sensitivity != Destructive {
		return GateApprovalChallenge{}, ErrUnsupportedGateApprovalTool
	}
	if request.RequesterSubject == "" || request.RequesterSessionID == "" {
		return GateApprovalChallenge{}, ErrHighRiskApprovalUnavailable
	}
	if request.Status != ApprovalPending {
		return GateApprovalChallenge{}, fmt.Errorf("approval request %q is %s, not pending", id, request.Status)
	}
	if err := validateGateActor(actor); err != nil {
		return GateApprovalChallenge{}, err
	}
	if request.RequesterSubject == actor.Subject {
		return GateApprovalChallenge{}, ErrHighRiskApproverRequired
	}
	canonicalLanguage, err := approval.NormalizeConfirmationLanguage(language)
	if err != nil {
		return GateApprovalChallenge{}, err
	}
	phrase, err := approval.ExpectedConfirmationPhrase(canonicalLanguage)
	if err != nil {
		return GateApprovalChallenge{}, err
	}
	now := a.nowUTC()
	if !request.ExpiresAt.After(now) {
		return GateApprovalChallenge{}, approval.ErrExpired
	}
	ttl := request.ExpiresAt.Sub(now)
	if ttl > approval.MaxApprovalTTL {
		return GateApprovalChallenge{}, approval.ErrTTLExceeded
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	binding, ok := a.bindings[id]
	if !ok {
		// A pending compatibility request may be re-challenged after a
		// restart. The new Gate request starts a fresh warning window and no
		// old confirmation ID or commit is reused.
		binding = gateApprovalBinding{toolName: request.ToolName, scope: "ai:tool:" + request.ToolName, intentDigest: gateIntentDigest(request), requester: ApprovalActor{Subject: request.RequesterSubject, SessionID: request.RequesterSessionID, Username: request.RequesterUsername}}
		a.bindings[id] = binding
	}
	if binding.toolName != request.ToolName || binding.intentDigest != gateIntentDigest(request) || binding.requester.Subject != request.RequesterSubject || binding.requester.SessionID != request.RequesterSessionID {
		return GateApprovalChallenge{}, ErrHighRiskCommitUnavailable
	}
	if existing, exists := a.challenges[id]; exists {
		if existing.approver.Subject != actor.Subject {
			return GateApprovalChallenge{}, ErrHighRiskApproverRequired
		}
		if existing.approver.SessionID != actor.SessionID {
			return GateApprovalChallenge{}, approval.ErrSessionChanged
		}
		if existing.challenge.Language != canonicalLanguage {
			return GateApprovalChallenge{}, approval.ErrConfirmationLanguage
		}
		if !existing.challenge.ExpiresAt.After(now) {
			return GateApprovalChallenge{}, approval.ErrExpired
		}
		return existing.challenge, nil
	}

	gateRequest := approval.Request{
		ID:                   id,
		Risk:                 approval.RiskHigh,
		Scope:                binding.scope,
		PolicyEpoch:          a.policyEpoch,
		TTL:                  ttl,
		Actor:                actor.Subject,
		SessionID:            actor.SessionID,
		ConfirmationLanguage: canonicalLanguage,
		IntentDigest:         binding.intentDigest,
	}
	record, err := a.gate.Submit(now, gateRequest)
	if err != nil {
		return GateApprovalChallenge{}, err
	}
	challenge := GateApprovalChallenge{
		ApprovalID:                id,
		ConfirmationID:            uuid.NewString(),
		WarningStartedAt:          now,
		ExpiresAt:                 record.ExpiresAt,
		Language:                  canonicalLanguage,
		Phrase:                    phrase,
		ConfirmationStep:          1,
		RequiresThirdConfirmation: true,
	}
	a.challenges[id] = gateApprovalChallengeState{challenge: challenge, approver: actor, scope: binding.scope, intentDigest: binding.intentDigest}
	return challenge, nil
}

// StartConfirmation is an explicit alias for callers that use start/confirm
// terminology in their transport layer.
func (a *GateApprovalAdapter) StartConfirmation(id string, actor ApprovalActor, language string) (GateApprovalChallenge, error) {
	return a.BeginConfirmation(id, actor, language)
}

// Confirm feeds the immutable challenge fields into internal/approval. The
// first successful checkpoint returns approval.ErrThirdConfirmation; only a
// second unchanged call with ThirdConfirmation=true can produce a commit.
func (a *GateApprovalAdapter) Confirm(id string, actor ApprovalActor, input GateApprovalConfirmation) (GateApprovalResult, error) {
	return a.ConfirmContext(context.Background(), id, actor, input)
}

// ConfirmContext verifies the submitted credentials before forwarding any
// confirmation state to the core Gate. A missing verifier or empty proof is
// always rejected.
func (a *GateApprovalAdapter) ConfirmContext(ctx context.Context, id string, actor ApprovalActor, input GateApprovalConfirmation) (GateApprovalResult, error) {
	if err := a.ensure(); err != nil {
		return GateApprovalResult{}, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	a.mu.Lock()
	state, ok := a.challenges[id]
	if !ok {
		a.mu.Unlock()
		return GateApprovalResult{}, ErrHighRiskConfirmationNotStarted
	}
	if actor.Subject != state.approver.Subject {
		a.mu.Unlock()
		return GateApprovalResult{}, approval.ErrInvalidActor
	}
	if actor.SessionID != state.approver.SessionID {
		a.mu.Unlock()
		return GateApprovalResult{}, approval.ErrSessionChanged
	}
	request, ok := a.store.Get(id)
	if !ok {
		a.mu.Unlock()
		return GateApprovalResult{}, fmt.Errorf("approval request %q not found", id)
	}
	record, ok := a.gate.Get(id)
	if !ok {
		a.mu.Unlock()
		return GateApprovalResult{}, ErrHighRiskCommitUnavailable
	}
	now := a.nowUTC()
	if record.Status == approval.StatusApproved && record.Commit != nil {
		if request.Status == ApprovalApproved {
			a.mu.Unlock()
			return GateApprovalResult{Approval: request, Commit: cloneAuthorizationCommit(record.Commit), Challenge: state.challenge}, approval.ErrConfirmationReplay
		}
		if err := validateGateCommit(record, state); err != nil {
			a.mu.Unlock()
			return GateApprovalResult{}, err
		}
		if !record.Commit.ExpiresAt.After(now) {
			a.mu.Unlock()
			return GateApprovalResult{}, approval.ErrExpired
		}
		approved, err := a.store.approveFor(id, state.approver, true)
		if err != nil {
			a.mu.Unlock()
			return GateApprovalResult{Approval: request, Commit: cloneAuthorizationCommit(record.Commit), Challenge: state.challenge}, err
		}
		state.challenge.ConfirmationStep = 3
		state.challenge.RequiresThirdConfirmation = false
		a.challenges[id] = state
		a.mu.Unlock()
		return GateApprovalResult{Approval: approved, Commit: cloneAuthorizationCommit(record.Commit), Challenge: state.challenge}, nil
	}
	if record.Status != approval.StatusPending {
		a.mu.Unlock()
		return GateApprovalResult{Approval: request, Challenge: state.challenge}, fmt.Errorf("approval request %q is %s, not pending", id, record.Status)
	}
	if !record.ExpiresAt.After(now) {
		a.mu.Unlock()
		return GateApprovalResult{Approval: request, Challenge: state.challenge}, approval.ErrExpired
	}
	if input.ConfirmationPhrase != state.challenge.Phrase {
		a.mu.Unlock()
		return GateApprovalResult{Approval: request, Challenge: state.challenge}, approval.ErrConfirmationPhrase
	}
	if now.Before(state.challenge.WarningStartedAt.Add(approval.WarningDelay)) {
		a.mu.Unlock()
		return GateApprovalResult{Approval: request, Challenge: state.challenge}, approval.ErrWarningDelay
	}
	verifier := a.credentialVerifier
	a.mu.Unlock()
	if verifier == nil {
		return GateApprovalResult{Approval: request, Challenge: state.challenge}, ErrHighRiskCredentialVerifierUnavailable
	}
	proof, err := verifier(ctx, actor, input)
	if err != nil {
		return GateApprovalResult{Approval: request, Challenge: state.challenge}, fmt.Errorf("%w: %v", ErrHighRiskCredentialRejected, err)
	}
	if !proof.valid() {
		return GateApprovalResult{Approval: request, Challenge: state.challenge}, ErrHighRiskCredentialProofInvalid
	}
	return a.confirmWithProof(id, actor, input, proof)
}

func (a *GateApprovalAdapter) confirmWithProof(id string, actor ApprovalActor, input GateApprovalConfirmation, proof GateApprovalCredentialProof) (GateApprovalResult, error) {
	if err := a.ensure(); err != nil {
		return GateApprovalResult{}, err
	}
	now := a.nowUTC()
	a.mu.Lock()
	defer a.mu.Unlock()
	state, ok := a.challenges[id]
	if !ok {
		return GateApprovalResult{}, ErrHighRiskConfirmationNotStarted
	}
	if actor.Subject != state.approver.Subject {
		return GateApprovalResult{}, approval.ErrInvalidActor
	}
	if actor.SessionID != state.approver.SessionID {
		return GateApprovalResult{}, approval.ErrSessionChanged
	}
	request, ok := a.store.Get(id)
	if !ok {
		return GateApprovalResult{}, fmt.Errorf("approval request %q not found", id)
	}
	record, ok := a.gate.Get(id)
	if !ok {
		return GateApprovalResult{}, ErrHighRiskCommitUnavailable
	}
	if record.Status == approval.StatusApproved && record.Commit != nil {
		if request.Status == ApprovalApproved {
			return GateApprovalResult{Approval: request, Commit: cloneAuthorizationCommit(record.Commit), Challenge: state.challenge}, approval.ErrConfirmationReplay
		}
		if err := validateGateCommit(record, state); err != nil {
			return GateApprovalResult{}, err
		}
		if !record.Commit.ExpiresAt.After(now) {
			return GateApprovalResult{}, approval.ErrExpired
		}
		approved, err := a.store.approveFor(id, state.approver, true)
		if err != nil {
			return GateApprovalResult{Approval: request, Commit: cloneAuthorizationCommit(record.Commit), Challenge: state.challenge}, err
		}
		state.challenge.ConfirmationStep = 3
		state.challenge.RequiresThirdConfirmation = false
		a.challenges[id] = state
		return GateApprovalResult{Approval: approved, Commit: cloneAuthorizationCommit(record.Commit), Challenge: state.challenge}, nil
	}
	if record.Status != approval.StatusPending {
		return GateApprovalResult{Approval: request, Challenge: state.challenge}, fmt.Errorf("approval request %q is %s, not pending", id, record.Status)
	}
	confirmation := approval.Confirmation{
		WarningReadAt:      state.challenge.WarningStartedAt,
		PasswordConfirmed:  proof.passwordConfirmed,
		TOTPConfirmed:      proof.totpConfirmed,
		SecondConfirmation: input.SecondConfirmation,
		ThirdConfirmation:  input.ThirdConfirmation,
		ConfirmationID:     state.challenge.ConfirmationID,
		Actor:              actor.Subject,
		ActorRole:          gateActorRole(actor.Role),
		Scope:              state.scope,
		PolicyEpoch:        a.policyEpoch,
		// This method is intentionally an in-process local-control-plane API;
		// a network handler must establish loopback/local provenance before
		// calling it. No client-controlled field can turn a remote request
		// into a local confirmation.
		Local:                true,
		SessionID:            actor.SessionID,
		ConfirmationLanguage: state.challenge.Language,
		ConfirmationPhrase:   input.ConfirmationPhrase,
		IntentDigest:         state.intentDigest,
		Nonce:                record.Request.Nonce,
	}
	commit, err := a.gate.Confirm(now, id, confirmation)
	if errors.Is(err, approval.ErrThirdConfirmation) {
		state.challenge.ConfirmationStep = 2
		state.challenge.RequiresThirdConfirmation = true
		a.challenges[id] = state
		return GateApprovalResult{Approval: request, Challenge: state.challenge}, err
	}
	if err != nil {
		return GateApprovalResult{Approval: request, Challenge: state.challenge}, err
	}
	state.challenge.ConfirmationStep = 3
	state.challenge.RequiresThirdConfirmation = false
	a.challenges[id] = state
	approved, err := a.store.approveFor(id, state.approver, true)
	if err != nil {
		return GateApprovalResult{Approval: request, Commit: cloneAuthorizationCommit(&commit), Challenge: state.challenge}, err
	}
	return GateApprovalResult{Approval: approved, Commit: cloneAuthorizationCommit(&commit), Challenge: state.challenge}, nil
}

// BeginExecutionForWithPreview requires both the compatibility approval and a
// live, exactly-bound AuthorizationCommit before allowing the requester to run
// the tool. The requester session is intentionally distinct from the approver
// session stored in the gate challenge.
func (a *GateApprovalAdapter) BeginExecutionForWithPreview(id, toolName string, args map[string]any, preview string, actor ApprovalActor) (ApprovalRequest, error) {
	if err := a.ensure(); err != nil {
		return ApprovalRequest{}, err
	}
	now := a.nowUTC()
	a.mu.Lock()
	defer a.mu.Unlock()
	state, ok := a.challenges[id]
	if !ok {
		return ApprovalRequest{}, ErrHighRiskConfirmationNotStarted
	}
	record, ok := a.gate.Get(id)
	if !ok || record.Status != approval.StatusApproved || record.Commit == nil {
		return ApprovalRequest{}, ErrHighRiskCommitUnavailable
	}
	if err := validateGateCommit(record, state); err != nil {
		return ApprovalRequest{}, err
	}
	if !record.Commit.ExpiresAt.After(now) {
		return ApprovalRequest{}, approval.ErrExpired
	}
	if _, err := a.store.approveFor(id, state.approver, true); err != nil {
		return ApprovalRequest{}, err
	}
	return a.store.beginExecutionForWithPreview(id, toolName, args, preview, actor, true)
}

func (a *GateApprovalAdapter) BeginExecutionFor(id, toolName string, args map[string]any, actor ApprovalActor) (ApprovalRequest, error) {
	return a.BeginExecutionForWithPreview(id, toolName, args, "", actor)
}

func (a *GateApprovalAdapter) MarkExecuted(id string, actor ApprovalActor) (ApprovalRequest, error) {
	return a.finishExecution(id, actor, true)
}

func (a *GateApprovalAdapter) MarkExecutionFailed(id string, actor ApprovalActor) (ApprovalRequest, error) {
	return a.finishExecution(id, actor, false)
}

// finishExecution only requires that the Gate commit was valid when execution
// began. A long-running tool must still be allowed to record its real outcome
// after that commit expires; BeginExecutionForWithPreview performs the live
// expiry check before any side effect starts.
func (a *GateApprovalAdapter) finishExecution(id string, actor ApprovalActor, succeeded bool) (ApprovalRequest, error) {
	if err := a.ensure(); err != nil {
		return ApprovalRequest{}, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	state, ok := a.challenges[id]
	if !ok {
		return ApprovalRequest{}, ErrHighRiskConfirmationNotStarted
	}
	record, ok := a.gate.Get(id)
	if !ok || record.Status != approval.StatusApproved || record.Commit == nil {
		return ApprovalRequest{}, ErrHighRiskCommitUnavailable
	}
	if err := validateGateCommit(record, state); err != nil {
		return ApprovalRequest{}, err
	}
	if succeeded {
		return a.store.finishExecution(id, ApprovalExecuted, actor, true)
	}
	return a.store.finishExecution(id, ApprovalFailed, actor, true)
}

// RejectFor revokes a gate record before marking the compatibility request
// rejected. Revocation is best-effort only when no gate challenge exists; a
// failed store persistence still leaves the gate revoked, which is fail-closed.
func (a *GateApprovalAdapter) RejectFor(id string, actor ApprovalActor, reason string) (ApprovalRequest, error) {
	if err := a.ensure(); err != nil {
		return ApprovalRequest{}, err
	}
	if reason == "" {
		reason = "AI high-risk approval rejected"
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.challenges[id]; ok {
		if err := a.gate.Revoke(a.nowUTC(), id, actor.Subject, reason); err != nil && !errors.Is(err, approval.ErrRevoked) && !errors.Is(err, approval.ErrExpired) {
			return ApprovalRequest{}, err
		}
		delete(a.challenges, id)
	}
	delete(a.bindings, id)
	return a.store.RejectFor(id, actor)
}

func validateGateCommit(record approval.Record, state gateApprovalChallengeState) error {
	if record.Commit == nil || record.Commit.RequestID != record.ID || record.Commit.ConfirmationID != state.challenge.ConfirmationID || record.Commit.Actor != state.approver.Subject || record.Commit.SessionID != state.approver.SessionID || record.Commit.Scope != state.scope || record.Commit.PolicyEpoch != record.Request.PolicyEpoch || record.Commit.IntentDigest != state.intentDigest || record.Commit.Nonce != record.Request.Nonce || !record.Commit.ExpiresAt.Equal(record.ExpiresAt) {
		return ErrHighRiskCommitUnavailable
	}
	return nil
}

func validateGateActor(actor ApprovalActor) error {
	if actor.Subject == "" {
		return approval.ErrActorRequired
	}
	if approval.ValidateIdentifier(actor.Subject) != nil {
		return approval.ErrInvalidActor
	}
	if actor.SessionID == "" {
		return approval.ErrSessionRequired
	}
	if approval.ValidateIdentifier(actor.SessionID) != nil {
		return approval.ErrSessionRequired
	}
	return nil
}

func gateActorRole(value string) approval.ActorRole {
	actorRole, ok := approval.CanonicalActorRole(value)
	if !ok {
		return approval.RoleOperator
	}
	return actorRole
}

func gateIntentDigest(request ApprovalRequest) string {
	type intent struct {
		ToolName      string          `json:"tool_name"`
		Sensitivity   ToolSensitivity `json:"sensitivity"`
		ArgsDigest    string          `json:"args_digest"`
		PreviewDigest string          `json:"preview_digest,omitempty"`
		DiffDigest    string          `json:"diff_digest,omitempty"`
	}
	diffDigest := ""
	if request.Diff != "" {
		sum := sha256.Sum256([]byte(request.Diff))
		diffDigest = hex.EncodeToString(sum[:])
	}
	b, _ := json.Marshal(intent{ToolName: request.ToolName, Sensitivity: request.Sensitivity, ArgsDigest: request.ArgsDigest, PreviewDigest: request.PreviewDigest, DiffDigest: diffDigest})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func cloneAuthorizationCommit(commit *approval.AuthorizationCommit) *approval.AuthorizationCommit {
	if commit == nil {
		return nil
	}
	cloned := *commit
	return &cloned
}
