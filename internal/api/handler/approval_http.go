package handler

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/api/middleware"
	"github.com/LaokeQwQ/CheeseWAF/internal/approval"
	"github.com/LaokeQwQ/CheeseWAF/internal/timekeeper"
	"github.com/go-chi/chi/v5"
)

var (
	ErrApprovalCredentialRejected            = errors.New("approval credential was rejected")
	ErrApprovalVerifierUnavailable           = errors.New("approval credential verifier is unavailable")
	ErrApprovalCredentialVerifierUnavailable = ErrApprovalVerifierUnavailable
)

// approvalHTTPMaxBodyBytes bounds every approval JSON document independently
// of any server-wide request limit. Approval payloads are intentionally small:
// they carry immutable binding fields and credentials, never arbitrary data.
const approvalHTTPMaxBodyBytes int64 = 64 << 10

const (
	approvalCredentialMaxFailures = 5
	approvalCredentialLockWindow  = 5 * time.Minute
	approvalCredentialProofTTL    = time.Minute
	// Full tables reject new sessions without evicting live failure budgets.
	approvalCredentialBudgetMaxEntries = 1024
)

type localApprovalTransportKey struct{}

// WithLocalApprovalTransport is only for the ConnContext of the dedicated
// local Unix-domain control listener. Never apply it to the public TCP listener.
func WithLocalApprovalTransport(ctx context.Context) context.Context {
	return context.WithValue(ctx, localApprovalTransportKey{}, true)
}

// IsLocalApprovalTransport reports whether the trusted server listener marked
// the connection as local control transport.
func IsLocalApprovalTransport(ctx context.Context) bool {
	return ctx != nil && ctx.Value(localApprovalTransportKey{}) == true
}

// ApprovalCredentialProof is an opaque result produced by a trusted
// credential verifier. Confirmation booleans are derived only from this proof
// and are never accepted from an HTTP payload.
type ApprovalCredentialProof struct {
	token             string
	passwordConfirmed bool
	totpConfirmed     bool
	requiresTOTP      bool
}

// NewApprovalCredentialProof creates a verifier-issued proof. The token must
// be non-empty; callers should use a short-lived, single-use value bound to the
// authenticated session and approval challenge.
func NewApprovalCredentialProof(token string, passwordConfirmed, totpConfirmed bool) ApprovalCredentialProof {
	return ApprovalCredentialProof{token: token, passwordConfirmed: passwordConfirmed, totpConfirmed: totpConfirmed}
}

// NewMFAApprovalCredentialProof marks a verified password as requiring the
// account's enrolled second factor before authorization may be committed.
func NewMFAApprovalCredentialProof(token string, passwordConfirmed, totpConfirmed, requiresTOTP bool) ApprovalCredentialProof {
	return ApprovalCredentialProof{token: token, passwordConfirmed: passwordConfirmed, totpConfirmed: totpConfirmed, requiresTOTP: requiresTOTP}
}

func (p ApprovalCredentialProof) valid() bool {
	return p.token != "" && approval.ValidateIdentifier(p.token) == nil && (p.passwordConfirmed || p.totpConfirmed)
}

// Accessors and CombineApprovalCredentialProof are used by production
// composition adapters without exposing mutable credential state.
func (p ApprovalCredentialProof) Token() string           { return p.token }
func (p ApprovalCredentialProof) PasswordConfirmed() bool { return p.passwordConfirmed }
func (p ApprovalCredentialProof) TOTPConfirmed() bool     { return p.totpConfirmed }
func (p ApprovalCredentialProof) RequiresTOTP() bool      { return p.requiresTOTP }
func CombineApprovalCredentialProof(password, totp ApprovalCredentialProof) ApprovalCredentialProof {
	if !password.valid() || !totp.valid() || !totp.totpConfirmed {
		return ApprovalCredentialProof{}
	}
	return ApprovalCredentialProof{token: password.token, passwordConfirmed: password.passwordConfirmed, totpConfirmed: true, requiresTOTP: password.requiresTOTP}
}

// ApprovalCredentialVerifier verifies one operator credential against the
// authenticated server-side session and returns a proof. Implementations must
// not persist the supplied credential.
type ApprovalCredentialVerifier func(ctx context.Context, session ApprovalSession, credential string) (ApprovalCredentialProof, error)

// ApprovalSession is derived from middleware.Claims. Fields supplied by an
// HTTP client are never used to construct this value.
type ApprovalSession struct {
	Subject    string `json:"subject"`
	SessionID  string `json:"session_id"`
	ID         string `json:"id,omitempty"`
	Username   string `json:"username,omitempty"`
	Role       string `json:"role,omitempty"`
	RemoteAddr string `json:"-"`
	Local      bool   `json:"-"`
}

// ApprovalChallenge is the server-created state needed to complete one
// approval. WarningStartedAt, scope, intent, epoch, TTL and nonce are all
// authoritative server values.
type ApprovalChallenge struct {
	ApprovalID                string        `json:"approval_id"`
	ConfirmationID            string        `json:"confirmation_id"`
	WarningStartedAt          time.Time     `json:"warning_started_at"`
	ExpiresAt                 time.Time     `json:"expires_at"`
	Language                  string        `json:"language"`
	Phrase                    string        `json:"phrase"`
	ConfirmationStep          uint8         `json:"confirmation_step"`
	RequiresThirdConfirmation bool          `json:"requires_third_confirmation"`
	Scope                     string        `json:"scope"`
	IntentDigest              string        `json:"intent_digest"`
	WorkflowDigest            string        `json:"workflow_digest,omitempty"`
	PolicyEpoch               uint64        `json:"policy_epoch"`
	TTL                       time.Duration `json:"ttl"`
	Nonce                     string        `json:"nonce"`
	SessionID                 string        `json:"session_id"`
}

type ApprovalHTTPOptions struct {
	Gate               *approval.Gate
	Clock              func() time.Time
	PasswordVerifier   ApprovalCredentialVerifier
	TOTPVerifier       ApprovalCredentialVerifier
	CredentialVerifier ApprovalCredentialVerifier
	SessionValidator   middleware.SessionValidator
	AuthorityResolver  approval.AuthorityResolver
}

type ApprovalHTTPHandler struct {
	gate                 *approval.Gate
	clock                func() time.Time
	passwordVerifier     ApprovalCredentialVerifier
	totpVerifier         ApprovalCredentialVerifier
	credentialVerifierFn ApprovalCredentialVerifier
	sessionValidator     middleware.SessionValidator
	authorityResolver    approval.AuthorityResolver

	mu                sync.Mutex
	challenges        map[string]approvalChallengeState
	credentialBudgets map[string]approvalCredentialBudget
}

// SessionValidator returns the validator bound to this approval transport.
// Production composition uses this to keep approval sessions on the same
// management-store lifetime as the rest of the authenticated API.
func (h *ApprovalHTTPHandler) SessionValidator() middleware.SessionValidator {
	if h == nil {
		return nil
	}
	return h.sessionValidator
}

// PolicyEpoch returns the epoch enforced by the underlying approval Gate.
// It deliberately reads the Gate rather than a duplicated provider field.
func (h *ApprovalHTTPHandler) PolicyEpoch() uint64 {
	if h == nil || h.gate == nil {
		return 0
	}
	return h.gate.PolicyEpoch()
}

// SessionValidator returns the validator bound to this approval transport.
// The production composition root uses this to prove that the interactive
// approval endpoints and the management API share the same session lifetime.
func (h *ApprovalHTTPHandler) SessionValidator() middleware.SessionValidator {
	if h == nil {
		return nil
	}
	return h.sessionValidator
}

// PolicyEpoch returns the epoch enforced by the underlying approval Gate.
// It deliberately reads the Gate rather than a duplicated provider field.
func (h *ApprovalHTTPHandler) PolicyEpoch() uint64 {
	if h == nil || h.gate == nil {
		return 0
	}
	return h.gate.PolicyEpoch()
}

type approvalChallengeState struct {
	challenge      ApprovalChallenge
	session        ApprovalSession
	failures       int
	verifying      bool
	proof          ApprovalCredentialProof
	proofExpiresAt time.Time
}

type approvalCredentialBudget struct {
	failures  int
	verifying bool
	expiresAt time.Time
}

// pruneCredentialBudgetsLocked removes expired, inactive session budgets.
// In-flight verifications and unexpired failure budgets must remain so session
// churn cannot make room by resetting another session's credential limit.
func (h *ApprovalHTTPHandler) pruneCredentialBudgetsLocked(now time.Time) {
	for key, budget := range h.credentialBudgets {
		if !budget.verifying && !budget.expiresAt.After(now) {
			delete(h.credentialBudgets, key)
		}
	}
}

func NewApprovalHTTPHandler(opts ApprovalHTTPOptions) *ApprovalHTTPHandler {
	clock := opts.Clock
	if clock == nil {
		clock = time.Now
	}
	authority := opts.AuthorityResolver
	if authority == nil {
		authority = approval.DefaultAuthorityResolver{}
	}
	return &ApprovalHTTPHandler{
		gate:                 opts.Gate,
		clock:                clock,
		passwordVerifier:     opts.PasswordVerifier,
		totpVerifier:         opts.TOTPVerifier,
		credentialVerifierFn: opts.CredentialVerifier,
		sessionValidator:     opts.SessionValidator,
		authorityResolver:    authority,
		challenges:           make(map[string]approvalChallengeState),
		credentialBudgets:    make(map[string]approvalCredentialBudget),
	}
}

// Mount registers the transport endpoints below the supplied router. If a
// session validator is configured, the current middleware session check is
// applied at the route boundary as well as by direct handler calls.
func (h *ApprovalHTTPHandler) Mount(r chi.Router) {
	if h == nil || r == nil {
		return
	}
	register := func(r chi.Router) {
		r.Post("/approvals", h.SubmitApproval)
		r.Post("/approvals/{id}/confirmation/start", h.StartApprovalConfirmation)
		r.Post("/approvals/{id}/confirmation", h.ConfirmApproval)
	}
	if h.sessionValidator == nil {
		register(r)
		return
	}
	r.With(middleware.SessionMiddlewareWithClock(h.sessionValidator, approvalHTTPClock{h})).Group(func(r chi.Router) {
		register(r)
	})
}

// SubmitApproval creates an immutable request bound to the current session.
func (h *ApprovalHTTPHandler) SubmitApproval(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.gate == nil {
		writeError(w, http.StatusServiceUnavailable, "APPROVAL_GATE_UNAVAILABLE", "approval gate is unavailable")
		return
	}
	session, ok := approvalSessionFromRequest(w, r)
	if !ok {
		return
	}
	var payload approvalSubmitPayload
	if !decodeApprovalJSON(w, r, &payload) {
		return
	}
	if payload.Actor != "" && payload.Actor != session.Subject {
		writeError(w, http.StatusForbidden, "APPROVAL_ACTOR_CHANGED", "approval actor must come from the current session")
		return
	}
	if payload.SessionID != "" && payload.SessionID != session.SessionID {
		writeError(w, http.StatusForbidden, "APPROVAL_SESSION_CHANGED", "approval session must come from the current session")
		return
	}
	if payload.PreApproved {
		writeError(w, http.StatusForbidden, "APPROVAL_PREAPPROVAL_FORBIDDEN", "HTTP approval requires interactive authorization")
		return
	}
	language := payload.Language
	if language == "" {
		language = payload.ConfirmationLanguage
	}
	if language == "" {
		language = approval.DefaultConfirmationLanguage
	}
	ttl, err := payload.TTL.duration()
	if err != nil {
		writeError(w, http.StatusBadRequest, "APPROVAL_INVALID", "ttl must be a duration such as 1m")
		return
	}
	record, err := h.gate.Submit(h.now(), approval.Request{
		ID:                   payload.ID,
		Risk:                 approval.RiskHigh,
		Scope:                payload.Scope,
		PolicyEpoch:          payload.PolicyEpoch,
		TTL:                  ttl,
		PreApproved:          false,
		Untrusted:            true,
		Test:                 payload.Test,
		TokenOperation:       payload.TokenOperation,
		KMSOperation:         payload.KMSOperation,
		ClusterOperation:     payload.ClusterOperation || strings.HasPrefix(payload.Scope, "crp:") || strings.HasPrefix(payload.Scope, "cluster:"),
		BreakGlass:           payload.BreakGlass,
		Actor:                session.Subject,
		SessionID:            session.SessionID,
		ConfirmationLanguage: language,
		IntentDigest:         payload.IntentDigest,
		WorkflowDigest:       payload.WorkflowDigest,
		Nonce:                payload.Nonce,
	})
	if err != nil {
		writeApprovalError(w, err)
		return
	}
	writeData(w, struct {
		Record approval.Record `json:"record"`
	}{Record: record})
}

// StartApprovalConfirmation starts the server-side warning window and
// creates a one-time confirmation ID.
func (h *ApprovalHTTPHandler) StartApprovalConfirmation(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.gate == nil {
		writeError(w, http.StatusServiceUnavailable, "APPROVAL_GATE_UNAVAILABLE", "approval gate is unavailable")
		return
	}
	session, ok := approvalSessionFromRequest(w, r)
	if !ok {
		return
	}
	id := approvalIDFromRequest(r)
	if id == "" {
		writeError(w, http.StatusBadRequest, "APPROVAL_ID_REQUIRED", "approval id is required")
		return
	}
	var payload approvalStartPayload
	if !decodeApprovalJSON(w, r, &payload) {
		return
	}
	record, exists := h.gate.Get(id)
	if !exists {
		writeError(w, http.StatusNotFound, "APPROVAL_NOT_FOUND", "approval request not found")
		return
	}
	if record.Status != approval.StatusPending {
		writeApprovalError(w, approval.ErrNotPending)
		return
	}
	if record.Request.Actor == session.Subject || record.Request.SessionID == session.SessionID {
		writeError(w, http.StatusForbidden, "APPROVAL_SESSION_CHANGED", approval.ErrSessionChanged.Error())
		return
	}
	language := payload.Language
	if language == "" {
		language = record.Request.ConfirmationLanguage
	}
	canonical, err := approval.NormalizeConfirmationLanguage(language)
	if err != nil || canonical != record.Request.ConfirmationLanguage {
		writeError(w, http.StatusBadRequest, "APPROVAL_LANGUAGE_INVALID", approval.ErrConfirmationLanguage.Error())
		return
	}
	if payload.Scope != "" && payload.Scope != record.Request.Scope || payload.IntentDigest != "" && payload.IntentDigest != record.Request.IntentDigest || payload.Nonce != "" && payload.Nonce != record.Request.Nonce || payload.PolicyEpoch != 0 && payload.PolicyEpoch != record.Request.PolicyEpoch {
		writeError(w, http.StatusConflict, "APPROVAL_BINDING_CHANGED", "approval binding changed")
		return
	}
	now := h.now()
	if !record.ExpiresAt.After(now) {
		writeError(w, http.StatusGone, "APPROVAL_EXPIRED", approval.ErrExpired.Error())
		return
	}
	phrase, err := approval.ExpectedConfirmationPhrase(canonical)
	if err != nil {
		writeError(w, http.StatusBadRequest, "APPROVAL_LANGUAGE_INVALID", err.Error())
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	if existing, exists := h.challenges[id]; exists {
		if existing.session.Subject != session.Subject || existing.session.SessionID != session.SessionID {
			writeError(w, http.StatusConflict, "APPROVAL_SESSION_CHANGED", approval.ErrSessionChanged.Error())
			return
		}
		if existing.challenge.Language != canonical {
			writeError(w, http.StatusConflict, "APPROVAL_LANGUAGE_INVALID", approval.ErrConfirmationLanguage.Error())
			return
		}
		if !existing.challenge.ExpiresAt.After(now) {
			writeError(w, http.StatusGone, "APPROVAL_EXPIRED", approval.ErrExpired.Error())
			return
		}
		writeData(w, struct {
			Challenge ApprovalChallenge `json:"challenge"`
		}{Challenge: existing.challenge})
		return
	}
	confirmationID, err := newApprovalConfirmationID()
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "APPROVAL_CONFIRMATION_UNAVAILABLE", "unable to allocate confirmation id")
		return
	}
	challenge := ApprovalChallenge{
		ApprovalID:                id,
		ConfirmationID:            confirmationID,
		WarningStartedAt:          now,
		ExpiresAt:                 record.ExpiresAt,
		Language:                  canonical,
		Phrase:                    phrase,
		ConfirmationStep:          1,
		RequiresThirdConfirmation: true,
		Scope:                     record.Request.Scope,
		IntentDigest:              record.Request.IntentDigest,
		WorkflowDigest:            record.Request.WorkflowDigest,
		PolicyEpoch:               record.Request.PolicyEpoch,
		TTL:                       record.Request.TTL,
		Nonce:                     record.Request.Nonce,
		SessionID:                 session.SessionID,
	}
	h.challenges[id] = approvalChallengeState{challenge: challenge, session: session}
	writeData(w, struct {
		Challenge ApprovalChallenge `json:"challenge"`
	}{Challenge: challenge})
}

// ConfirmApproval validates credentials and feeds only server-bound fields to
// approval.Gate. The Gate mutex makes the final commit atomic under retries.
func (h *ApprovalHTTPHandler) ConfirmApproval(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.gate == nil {
		writeError(w, http.StatusServiceUnavailable, "APPROVAL_GATE_UNAVAILABLE", "approval gate is unavailable")
		return
	}
	session, ok := approvalSessionFromRequest(w, r)
	if !ok {
		return
	}
	id := approvalIDFromRequest(r)
	if id == "" {
		writeError(w, http.StatusBadRequest, "APPROVAL_ID_REQUIRED", "approval id is required")
		return
	}
	var payload approvalConfirmPayload
	if !decodeApprovalJSON(w, r, &payload) {
		return
	}
	local := approvalHTTPRequestIsLocal(r)

	h.mu.Lock()
	h.pruneCredentialBudgetsLocked(h.now())
	state, exists := h.challenges[id]
	if !exists {
		h.mu.Unlock()
		writeError(w, http.StatusConflict, "APPROVAL_CONFIRMATION_NOT_STARTED", "approval confirmation has not been started")
		return
	}
	if state.session.Subject != session.Subject || state.session.SessionID != session.SessionID {
		h.mu.Unlock()
		writeError(w, http.StatusForbidden, "APPROVAL_SESSION_CHANGED", approval.ErrSessionChanged.Error())
		return
	}
	if state.failures >= approvalCredentialMaxFailures {
		h.mu.Unlock()
		writeError(w, http.StatusTooManyRequests, "APPROVAL_CREDENTIAL_LOCKED", "approval challenge is locked after repeated credential failures")
		return
	}
	if state.verifying {
		h.mu.Unlock()
		writeError(w, http.StatusTooManyRequests, "APPROVAL_CREDENTIAL_BUSY", "approval credential verification is already in progress")
		return
	}
	payloadLanguage := payload.Language
	if payloadLanguage == "" {
		payloadLanguage = payload.ConfirmationLanguage
	}
	if payload.Scope != "" && payload.Scope != state.challenge.Scope ||
		payload.IntentDigest != "" && payload.IntentDigest != state.challenge.IntentDigest ||
		payload.WorkflowDigest != "" && payload.WorkflowDigest != state.challenge.WorkflowDigest ||
		payload.Nonce != "" && payload.Nonce != state.challenge.Nonce ||
		payload.PolicyEpoch != 0 && payload.PolicyEpoch != state.challenge.PolicyEpoch ||
		payload.SessionID != "" && payload.SessionID != state.session.SessionID ||
		payloadLanguage != "" && payloadLanguage != state.challenge.Language ||
		payload.TTL.value != 0 && payload.TTL.value != state.challenge.TTL {
		h.mu.Unlock()
		writeError(w, http.StatusConflict, "APPROVAL_BINDING_CHANGED", "approval binding changed")
		return
	}
	if payload.ConfirmationID != "" && payload.ConfirmationID != state.challenge.ConfirmationID {
		h.mu.Unlock()
		writeError(w, http.StatusConflict, "APPROVAL_CONFIRMATION_REPLAY", approval.ErrConfirmationReplay.Error())
		return
	}
	h.mu.Unlock()

	record, exists := h.gate.Get(id)
	if !exists {
		writeError(w, http.StatusNotFound, "APPROVAL_NOT_FOUND", approval.ErrNotFound.Error())
		return
	}
	if record.Status != approval.StatusPending {
		writeApprovalError(w, approval.ErrNotPending)
		return
	}
	actorRole, validRole := approval.CanonicalActorRole(session.Role)
	if !validRole || h.authorityResolver == nil || !h.authorityResolver.CanApprove(session.Role, state.challenge.Scope) {
		writeError(w, http.StatusForbidden, "APPROVAL_ROLE_INVALID", "approval role is not authorized")
		return
	}
	if record.Request.Risk == approval.RiskEmergency &&
		(actorRole != approval.RoleSecurityAdmin && actorRole != approval.RoleTenantOwner || !h.authorityResolver.CanBreakGlass(session.Role, state.challenge.Scope)) {
		writeError(w, http.StatusForbidden, "APPROVAL_BREAK_GLASS_UNAUTHORIZED", approval.ErrBreakGlassActor.Error())
		return
	}
	if !local {
		writeError(w, http.StatusForbidden, "APPROVAL_LOCAL_REQUIRED", approval.ErrLocalConfirmation.Error())
		return
	}
	now := h.now()
	if !record.ExpiresAt.After(now) {
		writeError(w, http.StatusGone, "APPROVAL_EXPIRED", approval.ErrExpired.Error())
		return
	}
	if now.Before(state.challenge.WarningStartedAt.Add(approval.WarningDelay)) {
		writeError(w, http.StatusConflict, "APPROVAL_WARNING_DELAY", approval.ErrWarningDelay.Error())
		return
	}
	h.mu.Lock()
	current := h.challenges[id]
	budgetKey := session.Subject + ":" + session.SessionID
	budget, exists := h.credentialBudgets[budgetKey]
	if !exists {
		if len(h.credentialBudgets) >= approvalCredentialBudgetMaxEntries {
			h.mu.Unlock()
			writeError(w, http.StatusTooManyRequests, "APPROVAL_CREDENTIAL_BUDGET_CAPACITY", "approval credential verification is temporarily unavailable")
			return
		}
		budget = approvalCredentialBudget{expiresAt: now.Add(approvalCredentialLockWindow)}
	} else if !budget.verifying && !budget.expiresAt.After(now) {
		budget = approvalCredentialBudget{expiresAt: now.Add(approvalCredentialLockWindow)}
	}
	if current.verifying || current.failures >= approvalCredentialMaxFailures || budget.verifying || budget.failures >= approvalCredentialMaxFailures {
		h.mu.Unlock()
		writeError(w, http.StatusTooManyRequests, "APPROVAL_CREDENTIAL_LOCKED", "approval challenge is unavailable")
		return
	}
	current.verifying = true
	h.challenges[id] = current
	budget.verifying = true
	h.credentialBudgets[budgetKey] = budget
	h.mu.Unlock()
	proof := current.proof
	var err error
	if !payload.ThirdConfirmation || current.challenge.ConfirmationStep < 2 || !current.proofExpiresAt.After(now) || !proof.valid() {
		proof, err = h.verifyApprovalCredentials(r, session, payload)
	}
	h.mu.Lock()
	current = h.challenges[id]
	current.verifying = false
	budget = h.credentialBudgets[budgetKey]
	budget.verifying = false
	if err != nil && !errors.Is(err, ErrApprovalVerifierUnavailable) {
		current.failures++
		budget.failures++
	}
	h.challenges[id] = current
	h.credentialBudgets[budgetKey] = budget
	h.mu.Unlock()
	if err != nil {
		if errors.Is(err, ErrApprovalVerifierUnavailable) {
			writeError(w, http.StatusServiceUnavailable, "APPROVAL_CREDENTIAL_VERIFIER_UNAVAILABLE", "approval credential verifier is unavailable")
		} else {
			writeError(w, http.StatusForbidden, "APPROVAL_CREDENTIAL_REJECTED", ErrApprovalCredentialRejected.Error())
		}
		return
	}
	confirmation := approval.Confirmation{
		WarningReadAt:        state.challenge.WarningStartedAt,
		PasswordConfirmed:    proof.passwordConfirmed,
		TOTPConfirmed:        proof.totpConfirmed,
		SecondConfirmation:   payload.SecondConfirmation,
		ThirdConfirmation:    payload.ThirdConfirmation,
		ConfirmationID:       state.challenge.ConfirmationID,
		Actor:                session.Subject,
		ActorRole:            actorRole,
		Scope:                state.challenge.Scope,
		PolicyEpoch:          state.challenge.PolicyEpoch,
		Local:                local,
		BreakGlass:           payload.BreakGlass,
		BreakGlassReason:     payload.BreakGlassReason,
		SessionID:            session.SessionID,
		ConfirmationLanguage: state.challenge.Language,
		ConfirmationPhrase:   payload.ConfirmationPhrase,
		IntentDigest:         state.challenge.IntentDigest,
		WorkflowDigest:       state.challenge.WorkflowDigest,
		Nonce:                state.challenge.Nonce,
	}
	// Re-read challenge state after external credential verification. A
	// concurrent request may have consumed this challenge in the meantime;
	// only the request that wins the Gate transition may commit.
	h.mu.Lock()
	latest, latestExists := h.challenges[id]
	if !latestExists || latest.challenge.ConfirmationID != state.challenge.ConfirmationID || latest.session.Subject != session.Subject || latest.session.SessionID != session.SessionID {
		h.mu.Unlock()
		writeError(w, http.StatusConflict, "APPROVAL_CONFIRMATION_REPLAY", approval.ErrConfirmationReplay.Error())
		return
	}
	state = latest
	confirmation.WarningReadAt = state.challenge.WarningStartedAt
	confirmation.ConfirmationID = state.challenge.ConfirmationID
	confirmation.Scope = state.challenge.Scope
	confirmation.PolicyEpoch = state.challenge.PolicyEpoch
	confirmation.ConfirmationLanguage = state.challenge.Language
	confirmation.IntentDigest = state.challenge.IntentDigest
	confirmation.WorkflowDigest = state.challenge.WorkflowDigest
	confirmation.Nonce = state.challenge.Nonce
	confirmation.SessionID = state.session.SessionID
	commit, err := h.gate.Confirm(h.now(), id, confirmation)
	if errors.Is(err, approval.ErrThirdConfirmation) {
		state.challenge.ConfirmationStep = 2
		state.challenge.RequiresThirdConfirmation = true
		state.proof = proof
		state.proofExpiresAt = h.now().Add(approvalCredentialProofTTL)
		h.challenges[id] = state
		h.mu.Unlock()
		writeError(w, http.StatusConflict, "APPROVAL_THIRD_CONFIRMATION_REQUIRED", err.Error())
		return
	}
	if err != nil {
		h.mu.Unlock()
		writeApprovalError(w, err)
		return
	}
	state.challenge.ConfirmationStep = 3
	state.challenge.RequiresThirdConfirmation = false
	state.proof = ApprovalCredentialProof{}
	state.proofExpiresAt = time.Time{}
	h.challenges[id] = state
	h.mu.Unlock()
	approved, _ := h.gate.Get(id)
	writeData(w, struct {
		Record    approval.Record              `json:"record"`
		Commit    approval.AuthorizationCommit `json:"commit"`
		Challenge ApprovalChallenge            `json:"challenge"`
	}{Record: approved, Commit: commit, Challenge: state.challenge})
}

func (h *ApprovalHTTPHandler) verifyApprovalCredentials(r *http.Request, session ApprovalSession, payload approvalConfirmPayload) (ApprovalCredentialProof, error) {
	var proof ApprovalCredentialProof
	provided := false
	if payload.TOTPCode == "" {
		payload.TOTPCode = payload.TOTP
	}
	if payload.TOTPCode == "" {
		payload.TOTPCode = payload.Code
	}
	if payload.Password != "" {
		provided = true
		verifier := h.passwordVerifier
		if verifier == nil {
			verifier = h.credentialVerifier()
		}
		if verifier == nil {
			return ApprovalCredentialProof{}, ErrApprovalVerifierUnavailable
		}
		passwordProof, err := verifier(r.Context(), session, payload.Password)
		if err != nil {
			if errors.Is(err, ErrApprovalVerifierUnavailable) {
				return ApprovalCredentialProof{}, err
			}
			return ApprovalCredentialProof{}, ErrApprovalCredentialRejected
		}
		if !passwordProof.valid() || !passwordProof.passwordConfirmed {
			return ApprovalCredentialProof{}, ErrApprovalCredentialRejected
		}
		proof = passwordProof
	}
	if payload.TOTPCode != "" {
		provided = true
		verifier := h.totpVerifier
		if verifier == nil {
			verifier = h.credentialVerifier()
		}
		if verifier == nil {
			return ApprovalCredentialProof{}, ErrApprovalVerifierUnavailable
		}
		totpProof, err := verifier(r.Context(), session, payload.TOTPCode)
		if err != nil {
			if errors.Is(err, ErrApprovalVerifierUnavailable) {
				return ApprovalCredentialProof{}, err
			}
			return ApprovalCredentialProof{}, ErrApprovalCredentialRejected
		}
		if !totpProof.valid() || !totpProof.totpConfirmed {
			return ApprovalCredentialProof{}, ErrApprovalCredentialRejected
		}
		if proof.valid() {
			proof.totpConfirmed = true
		} else {
			proof = totpProof
		}
	}
	if !provided || (!proof.passwordConfirmed && !proof.totpConfirmed) || (proof.requiresTOTP && !proof.totpConfirmed) {
		return ApprovalCredentialProof{}, ErrApprovalCredentialRejected
	}
	if !proof.valid() {
		return ApprovalCredentialProof{}, ErrApprovalCredentialRejected
	}
	return proof, nil
}

func (h *ApprovalHTTPHandler) credentialVerifier() ApprovalCredentialVerifier {
	if h == nil {
		return nil
	}
	return h.credentialVerifierFn
}

func (h *ApprovalHTTPHandler) now() time.Time {
	if h == nil || h.clock == nil {
		return time.Now().UTC()
	}
	return h.clock().UTC()
}

type approvalHTTPClock struct{ h *ApprovalHTTPHandler }

var _ timekeeper.Clock = approvalHTTPClock{}

func (c approvalHTTPClock) Now() time.Time {
	if c.h == nil {
		return time.Now().UTC()
	}
	return c.h.now()
}

type approvalSubmitPayload struct {
	ID                   string               `json:"id"`
	Risk                 string               `json:"risk"`
	Scope                string               `json:"scope"`
	PolicyEpoch          uint64               `json:"policy_epoch"`
	TTL                  approvalJSONDuration `json:"ttl"`
	PreApproved          bool                 `json:"pre_approved"`
	Untrusted            bool                 `json:"untrusted"`
	Test                 bool                 `json:"test"`
	TokenOperation       bool                 `json:"token_operation"`
	KMSOperation         bool                 `json:"kms_operation"`
	ClusterOperation     bool                 `json:"cluster_operation"`
	BreakGlass           bool                 `json:"break_glass"`
	Actor                string               `json:"actor"`
	SessionID            string               `json:"session_id"`
	Language             string               `json:"language"`
	ConfirmationLanguage string               `json:"confirmation_language"`
	IntentDigest         string               `json:"intent_digest"`
	WorkflowDigest       string               `json:"workflow_digest"`
	Nonce                string               `json:"nonce"`
}

type approvalStartPayload struct {
	Language     string `json:"language"`
	Scope        string `json:"scope"`
	IntentDigest string `json:"intent_digest"`
	Nonce        string `json:"nonce"`
	PolicyEpoch  uint64 `json:"policy_epoch"`
}

type approvalConfirmPayload struct {
	ConfirmationID       string               `json:"confirmation_id"`
	WarningReadAt        time.Time            `json:"warning_read_at"`
	Password             string               `json:"password"`
	TOTPCode             string               `json:"totp_code"`
	SecondConfirmation   bool                 `json:"second_confirmation"`
	ThirdConfirmation    bool                 `json:"third_confirmation"`
	ConfirmationPhrase   string               `json:"confirmation_phrase"`
	Scope                string               `json:"scope"`
	IntentDigest         string               `json:"intent_digest"`
	WorkflowDigest       string               `json:"workflow_digest"`
	Nonce                string               `json:"nonce"`
	PolicyEpoch          uint64               `json:"policy_epoch"`
	TTL                  approvalJSONDuration `json:"ttl"`
	SessionID            string               `json:"session_id"`
	Language             string               `json:"language"`
	ConfirmationLanguage string               `json:"confirmation_language"`
	TOTP                 string               `json:"totp"`
	Code                 string               `json:"code"`
	BreakGlass           bool                 `json:"break_glass"`
	BreakGlassReason     string               `json:"break_glass_reason"`
}

type approvalJSONDuration struct{ value time.Duration }

func (d *approvalJSONDuration) UnmarshalJSON(b []byte) error {
	if string(b) == "null" || len(b) == 0 {
		d.value = 0
		return nil
	}
	var text string
	if len(b) > 0 && b[0] == '"' {
		if err := json.Unmarshal(b, &text); err != nil {
			return err
		}
		v, err := time.ParseDuration(text)
		if err != nil {
			return err
		}
		d.value = v
		return nil
	}
	var number int64
	if err := json.Unmarshal(b, &number); err != nil {
		return err
	}
	d.value = time.Duration(number)
	return nil
}

func (d approvalJSONDuration) duration() (time.Duration, error) {
	return d.value, nil
}

func decodeApprovalJSON(w http.ResponseWriter, r *http.Request, target any) bool {
	if r == nil || r.Body == nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "request body is required")
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, approvalHTTPMaxBodyBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			writeError(w, http.StatusRequestEntityTooLarge, "REQUEST_BODY_TOO_LARGE", "request body exceeds approval limit")
			return false
		}
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "request body must be valid JSON")
		return false
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			writeError(w, http.StatusRequestEntityTooLarge, "REQUEST_BODY_TOO_LARGE", "request body exceeds approval limit")
			return false
		}
		if err == nil {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "request body must contain exactly one JSON document")
		} else {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "request body must contain exactly one valid JSON document")
		}
		return false
	}
	return true
}

func approvalSessionFromRequest(w http.ResponseWriter, r *http.Request) (ApprovalSession, bool) {
	if r == nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "unauthorized")
		return ApprovalSession{}, false
	}
	claims, _ := r.Context().Value(middleware.UserContextKey).(*middleware.Claims)
	// Interactive approvals are bound to a real browser/session identity.
	// Management API tokens may authenticate ordinary management calls, but
	// they cannot satisfy a password/TOTP confirmation or locality check.
	if claims == nil || claims.Subject == "" || claims.ID == "" || claims.Role == "api_token" || strings.HasPrefix(claims.Subject, "api-token:") || approval.ValidateIdentifier(claims.Subject) != nil || approval.ValidateIdentifier(claims.ID) != nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "unauthorized")
		return ApprovalSession{}, false
	}
	return ApprovalSession{Subject: claims.Subject, SessionID: claims.ID, ID: claims.ID, Username: claims.Username, Role: claims.Role, RemoteAddr: r.RemoteAddr, Local: approvalHTTPRequestIsLocal(r)}, true
}

func approvalIDFromRequest(r *http.Request) string {
	if r == nil {
		return ""
	}
	if id := chi.URLParam(r, "id"); id != "" {
		return id
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	for i, part := range parts {
		if part == "approvals" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

func approvalHTTPRemoteIsLoopback(remote string) bool {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	host = strings.Trim(host, "[]")
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func approvalHTTPActorRole(role string) approval.ActorRole {
	actorRole, ok := approval.CanonicalActorRole(role)
	if !ok {
		return approval.RoleOperator
	}
	return actorRole
}

func newApprovalConfirmationID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err == nil {
		return "http-" + hex.EncodeToString(b), nil
	}
	return "", errors.New("confirmation id entropy unavailable")
}

func writeApprovalError(w http.ResponseWriter, err error) {
	status, code, message := http.StatusServiceUnavailable, "APPROVAL_BACKEND_UNAVAILABLE", "approval backend is unavailable"
	switch {
	case errors.Is(err, approval.ErrNotFound):
		status, code = http.StatusNotFound, "APPROVAL_NOT_FOUND"
	case errors.Is(err, approval.ErrNotPending), errors.Is(err, approval.ErrThirdConfirmation), errors.Is(err, approval.ErrWarningDelay), errors.Is(err, approval.ErrConfirmationReplay), errors.Is(err, approval.ErrSessionChanged), errors.Is(err, approval.ErrScopeChanged), errors.Is(err, approval.ErrIntentChanged), errors.Is(err, approval.ErrWorkflowChanged), errors.Is(err, approval.ErrTTLChanged), errors.Is(err, approval.ErrEpochChanged), errors.Is(err, approval.ErrConfirmationSequence):
		status, code = http.StatusConflict, "APPROVAL_CONFLICT"
	case errors.Is(err, approval.ErrExpired):
		status, code = http.StatusGone, "APPROVAL_EXPIRED"
	case errors.Is(err, approval.ErrRevoked):
		status, code = http.StatusConflict, "APPROVAL_REVOKED"
	case errors.Is(err, approval.ErrLocalConfirmation):
		status, code = http.StatusForbidden, "APPROVAL_LOCAL_REQUIRED"
	case errors.Is(err, approval.ErrPasswordConfirmation):
		status, code = http.StatusForbidden, "APPROVAL_CREDENTIAL_REQUIRED"
	case errors.Is(err, approval.ErrInvalidActor), errors.Is(err, approval.ErrActorRequired), errors.Is(err, approval.ErrSessionRequired):
		status, code = http.StatusForbidden, "APPROVAL_SESSION_INVALID"
	case errors.Is(err, approval.ErrDuplicateRequest):
		status, code = http.StatusConflict, "APPROVAL_DUPLICATE"
	case errors.Is(err, approval.ErrTTLExceeded):
		status, code = http.StatusBadRequest, "APPROVAL_TTL_INVALID"
	case isApprovalInvalidInput(err):
		status, code = http.StatusBadRequest, "APPROVAL_INVALID"
	}
	if status != http.StatusServiceUnavailable {
		message = err.Error()
	}
	if errors.Is(err, approval.ErrWarningDelay) {
		message = "warning must be read for at least 10 seconds"
	}
	writeError(w, status, code, message)
}

func isApprovalInvalidInput(err error) bool {
	return errors.Is(err, approval.ErrInvalidRequest) ||
		errors.Is(err, approval.ErrSecondConfirmation) ||
		errors.Is(err, approval.ErrConfirmationRequired) ||
		errors.Is(err, approval.ErrInvalidConfirmationID) ||
		errors.Is(err, approval.ErrConfirmationLanguage) ||
		errors.Is(err, approval.ErrConfirmationPhrase) ||
		errors.Is(err, approval.ErrReasonRequired) ||
		errors.Is(err, approval.ErrInvalidReason) ||
		errors.Is(err, approval.ErrBreakGlassRequired) ||
		errors.Is(err, approval.ErrBreakGlassReason) ||
		errors.Is(err, approval.ErrBreakGlassActor) ||
		errors.Is(err, approval.ErrEpochRegression)
}

// Only the dedicated local listener can establish transport locality. A TCP
// loopback peer may be an unmarked reverse proxy and does not prove locality.
func approvalHTTPRequestIsLocal(r *http.Request) bool {
	if r == nil || !IsLocalApprovalTransport(r.Context()) {
		return false
	}
	for _, name := range []string{"Forwarded", "X-Forwarded-For", "X-Real-IP", "X-Forwarded-Host", "X-Forwarded-Proto"} {
		if r.Header.Get(name) != "" {
			return false
		}
	}
	return true
}
