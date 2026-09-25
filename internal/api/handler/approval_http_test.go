package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/api/middleware"
	"github.com/LaokeQwQ/CheeseWAF/internal/approval"
	"github.com/go-chi/chi/v5"
)

type approvalHTTPFixture struct {
	handler *ApprovalHTTPHandler
	gate    *approval.Gate
	now     time.Time
	clock   *time.Time
}

type approvalHTTPFailingPersistence struct {
	*approval.MemoryPersistence
	err error
}

func (p approvalHTTPFailingPersistence) Apply(context.Context, approval.ApprovalMutation) error {
	return p.err
}

func newApprovalHTTPFixture(t *testing.T, withVerifier bool) approvalHTTPFixture {
	t.Helper()
	now := time.Date(2026, 9, 8, 15, 0, 0, 0, time.UTC)
	clock := &now
	gate := approval.NewGate(7)
	opts := ApprovalHTTPOptions{Gate: gate, Clock: func() time.Time { return *clock }}
	if withVerifier {
		opts.PasswordVerifier = func(_ context.Context, session ApprovalSession, password string) (ApprovalCredentialProof, error) {
			if session.Subject != "operator" || password != "secret" {
				return ApprovalCredentialProof{}, ErrApprovalCredentialRejected
			}
			return NewApprovalCredentialProof("http-test-proof", true, false), nil
		}
	}
	h := NewApprovalHTTPHandler(opts)
	if h == nil {
		t.Fatal("NewApprovalHTTPHandler returned nil")
	}
	return approvalHTTPFixture{handler: h, gate: gate, now: now, clock: clock}
}

func TestApprovalHTTPHandlerPolicyEpochComesFromGate(t *testing.T) {
	gate := approval.NewGate(17)
	h := NewApprovalHTTPHandler(ApprovalHTTPOptions{Gate: gate})
	if got := h.PolicyEpoch(); got != 17 {
		t.Fatalf("handler policy epoch = %d, want 17", got)
	}
	if err := gate.AdvanceEpoch(18); err != nil {
		t.Fatal(err)
	}
	if got := h.PolicyEpoch(); got != 18 {
		t.Fatalf("handler policy epoch after gate advance = %d, want 18", got)
	}
}

func (f *approvalHTTPFixture) advance(d time.Duration) {
	f.now = f.now.Add(d)
	*f.clock = f.now
}

func approvalHTTPRequest(method, target, body, subject, session, role, remote string) *http.Request {
	request := httptest.NewRequest(method, target, bytes.NewBufferString(body))
	request.Header.Set("Content-Type", "application/json")
	request.RemoteAddr = remote
	claims := &middleware.Claims{Subject: subject, ID: session, Username: subject, Role: role}
	return request.WithContext(context.WithValue(request.Context(), middleware.UserContextKey, claims))
}

func withApprovalRouteID(request *http.Request, id string) *http.Request {
	routeContext := chi.NewRouteContext()
	routeContext.URLParams.Add("id", id)
	return request.WithContext(context.WithValue(request.Context(), chi.RouteCtxKey, routeContext))
}

func submitApprovalHTTP(t *testing.T, f approvalHTTPFixture, id string) approval.Record {
	t.Helper()
	body := "{\"id\":\"" + id + "\",\"risk\":\"high\",\"scope\":\"site:primary\",\"policy_epoch\":7,\"ttl\":\"1m\",\"confirmation_language\":\"en-US\"}"
	recorder := httptest.NewRecorder()
	req := approvalHTTPRequest(http.MethodPost, "/api/approvals", body, "operator", "session-operator", "admin", "127.0.0.1:1234")
	f.handler.SubmitApproval(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("submit code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var envelope struct {
		Data struct{ Record approval.Record }
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode submit response: %v", err)
	}
	if envelope.Data.Record.ID == "" {
		t.Fatalf("missing submitted record: %s", recorder.Body.String())
	}
	return envelope.Data.Record
}

func startApprovalHTTP(t *testing.T, f approvalHTTPFixture, record approval.Record) ApprovalChallenge {
	t.Helper()
	recorder := httptest.NewRecorder()
	req := approvalHTTPRequest(http.MethodPost, "/api/approvals/"+record.ID+"/confirmation/start", "{\"language\":\"en-US\"}", "operator", "session-operator", "admin", "127.0.0.1:1234")
	req = withApprovalRouteID(req, record.ID)
	f.handler.StartApprovalConfirmation(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("start code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var envelope struct {
		Data struct{ Challenge ApprovalChallenge }
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode start response: %v", err)
	}
	if envelope.Data.Challenge.ConfirmationID == "" || envelope.Data.Challenge.WarningStartedAt.IsZero() {
		t.Fatalf("missing challenge fields: %s", recorder.Body.String())
	}
	return envelope.Data.Challenge
}

func confirmApprovalHTTP(t *testing.T, f approvalHTTPFixture, record approval.Record, body, subject, session, remote string) *httptest.ResponseRecorder {
	return confirmApprovalHTTPWithRole(t, f, record, body, subject, session, "admin", remote)
}

func confirmApprovalHTTPWithRole(t *testing.T, f approvalHTTPFixture, record approval.Record, body, subject, session, role, remote string) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	req := approvalHTTPRequest(http.MethodPost, "/api/approvals/"+record.ID+"/confirmation", body, subject, session, role, remote)
	req = withApprovalRouteID(req, record.ID)
	f.handler.ConfirmApproval(recorder, req)
	return recorder
}

func TestApprovalHTTPConfirmationUsesServerWarningStartAndRequiresTenSeconds(t *testing.T) {
	f := newApprovalHTTPFixture(t, true)
	record := submitApprovalHTTP(t, f, "http-warning")
	challenge := startApprovalHTTP(t, f, record)
	body := "{\"confirmation_id\":\"" + challenge.ConfirmationID + "\",\"confirmation_phrase\":\"" + challenge.Phrase + "\",\"password\":\"secret\",\"second_confirmation\":true}"
	early := confirmApprovalHTTP(t, f, record, body, "operator", "session-operator", "127.0.0.1:1234")
	if early.Code != http.StatusConflict || !strings.Contains(early.Body.String(), "warning") {
		t.Fatalf("early confirmation code=%d body=%s", early.Code, early.Body.String())
	}
	f.advance(9 * time.Second)
	nine := confirmApprovalHTTP(t, f, record, body, "operator", "session-operator", "127.0.0.1:1234")
	if nine.Code != http.StatusConflict {
		t.Fatalf("9-second confirmation code=%d body=%s", nine.Code, nine.Body.String())
	}
	f.advance(time.Second)
	checkpoint := confirmApprovalHTTP(t, f, record, body, "operator", "session-operator", "127.0.0.1:1234")
	if checkpoint.Code != http.StatusConflict {
		t.Fatalf("checkpoint code=%d body=%s", checkpoint.Code, checkpoint.Body.String())
	}
	if got, ok := f.gate.Get(record.ID); !ok || got.Confirmation.ConfirmationStep != 2 || got.Status != approval.StatusPending {
		t.Fatalf("checkpoint did not remain pending: %+v", got)
	}
}

func TestApprovalHTTPActorRoleUsesCanonicalManagementRoles(t *testing.T) {
	tests := []struct {
		role string
		want approval.ActorRole
	}{
		{role: "admin", want: approval.RoleOperator},
		{role: "security_admin", want: approval.RoleSecurityAdmin},
		{role: "tenant_owner", want: approval.RoleTenantOwner},
		{role: "readonly", want: approval.RoleOperator},
		{role: "custom", want: approval.RoleOperator},
	}
	for _, test := range tests {
		if got := approvalHTTPActorRole(test.role); got != test.want {
			t.Errorf("approvalHTTPActorRole(%q)=%q, want %q", test.role, got, test.want)
		}
	}
}

func TestApprovalHTTPDefaultAuthorityRejectsRestrictedClaimBeforeCredentialVerification(t *testing.T) {
	f := newApprovalHTTPFixture(t, true)
	verifierCalls := 0
	f.handler.passwordVerifier = func(ctx context.Context, session ApprovalSession, password string) (ApprovalCredentialProof, error) {
		verifierCalls++
		return NewApprovalCredentialProof("http-test-proof", true, false), nil
	}
	record := submitApprovalHTTP(t, f, "http-role-default")
	challenge := startApprovalHTTP(t, f, record)
	f.advance(approval.WarningDelay)
	body := "{\"confirmation_id\":\"" + challenge.ConfirmationID + "\",\"confirmation_phrase\":\"" + challenge.Phrase + "\",\"password\":\"secret\",\"second_confirmation\":true}"
	recorder := confirmApprovalHTTPWithRole(t, f, record, body, "operator", "session-operator", "security_admin", "127.0.0.1:1234")
	if recorder.Code != http.StatusForbidden || !strings.Contains(recorder.Body.String(), "role") {
		t.Fatalf("restricted role code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if verifierCalls != 0 {
		t.Fatalf("restricted role reached credential verifier %d times", verifierCalls)
	}
}

func TestApprovalHTTPRejectsClientWarningTimeSessionAndLocalSpoofing(t *testing.T) {
	f := newApprovalHTTPFixture(t, true)
	record := submitApprovalHTTP(t, f, "http-spoof")
	challenge := startApprovalHTTP(t, f, record)
	body := "{\"confirmation_id\":\"" + challenge.ConfirmationID + "\",\"warning_read_at\":\"" + f.now.Add(-approval.WarningDelay).Format(time.RFC3339Nano) + "\",\"confirmation_phrase\":\"" + challenge.Phrase + "\",\"password\":\"secret\",\"second_confirmation\":true,\"local\":true,\"session_id\":\"session-operator\"}"
	recorder := confirmApprovalHTTP(t, f, record, body, "operator", "session-operator", "198.51.100.9:1234")
	if recorder.Code != http.StatusBadRequest && recorder.Code != http.StatusForbidden && recorder.Code != http.StatusConflict {
		t.Fatalf("spoofed confirmation code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if got, _ := f.gate.Get(record.ID); got.Confirmation.ConfirmationID != "" {
		t.Fatalf("spoofed confirmation mutated gate: %+v", got)
	}
}

func TestApprovalHTTPRejectsChangedScopeAndConfirmationReplay(t *testing.T) {
	f := newApprovalHTTPFixture(t, true)
	record := submitApprovalHTTP(t, f, "http-replay")
	challenge := startApprovalHTTP(t, f, record)
	f.advance(approval.WarningDelay)
	changedScope := "{\"confirmation_id\":\"" + challenge.ConfirmationID + "\",\"scope\":\"site:changed\",\"confirmation_phrase\":\"" + challenge.Phrase + "\",\"password\":\"secret\",\"second_confirmation\":true}"
	changed := confirmApprovalHTTP(t, f, record, changedScope, "operator", "session-operator", "127.0.0.1:1234")
	if changed.Code != http.StatusConflict {
		t.Fatalf("changed scope code=%d body=%s", changed.Code, changed.Body.String())
	}
	valid := "{\"confirmation_id\":\"" + challenge.ConfirmationID + "\",\"confirmation_phrase\":\"" + challenge.Phrase + "\",\"password\":\"secret\",\"second_confirmation\":true}"
	checkpoint := confirmApprovalHTTP(t, f, record, valid, "operator", "session-operator", "127.0.0.1:1234")
	if checkpoint.Code != http.StatusConflict {
		t.Fatalf("checkpoint code=%d body=%s", checkpoint.Code, checkpoint.Body.String())
	}
	f.advance(time.Second)
	finalBody := "{\"confirmation_id\":\"" + challenge.ConfirmationID + "\",\"confirmation_phrase\":\"" + challenge.Phrase + "\",\"password\":\"secret\",\"second_confirmation\":true,\"third_confirmation\":true}"
	final := confirmApprovalHTTP(t, f, record, finalBody, "operator", "session-operator", "127.0.0.1:1234")
	if final.Code != http.StatusOK {
		t.Fatalf("final code=%d body=%s", final.Code, final.Body.String())
	}
	replay := confirmApprovalHTTP(t, f, record, finalBody, "operator", "session-operator", "127.0.0.1:1234")
	if replay.Code != http.StatusConflict {
		t.Fatalf("replay code=%d body=%s", replay.Code, replay.Body.String())
	}
}

func TestApprovalHTTPConfirmationFailsClosedWithoutCredentialVerifier(t *testing.T) {
	f := newApprovalHTTPFixture(t, false)
	record := submitApprovalHTTP(t, f, "http-no-verifier")
	challenge := startApprovalHTTP(t, f, record)
	f.advance(approval.WarningDelay)
	body := "{\"confirmation_id\":\"" + challenge.ConfirmationID + "\",\"confirmation_phrase\":\"" + challenge.Phrase + "\",\"password\":\"secret\",\"second_confirmation\":true}"
	recorder := confirmApprovalHTTP(t, f, record, body, "operator", "session-operator", "127.0.0.1:1234")
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing verifier code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if got, _ := f.gate.Get(record.ID); got.Status != approval.StatusPending {
		t.Fatalf("missing verifier authorized request: %+v", got)
	}
}

func TestApprovalHTTPVerifierUnavailablePreservesSentinelAndRedactsCause(t *testing.T) {
	f := newApprovalHTTPFixture(t, false)
	backendErr := errors.Join(ErrApprovalVerifierUnavailable, errors.New("postgres password=do-not-expose"))
	f.handler.passwordVerifier = func(context.Context, ApprovalSession, string) (ApprovalCredentialProof, error) {
		return ApprovalCredentialProof{}, backendErr
	}
	record := submitApprovalHTTP(t, f, "http-verifier-unavailable")
	challenge := startApprovalHTTP(t, f, record)
	f.advance(approval.WarningDelay)
	body := "{\"confirmation_id\":\"" + challenge.ConfirmationID + "\",\"confirmation_phrase\":\"" + challenge.Phrase + "\",\"password\":\"secret\",\"second_confirmation\":true}"

	request := approvalHTTPRequest(http.MethodPost, "/api/approvals/"+record.ID+"/confirmation", body, "operator", "session-operator", "admin", "127.0.0.1:1234")
	proof, err := f.handler.verifyApprovalCredentials(request, ApprovalSession{Subject: "operator", SessionID: "session-operator"}, approvalConfirmPayload{Password: "secret"})
	if proof.valid() || !errors.Is(err, ErrApprovalVerifierUnavailable) {
		t.Fatalf("verifier error=%v proof=%+v, want unavailable sentinel and no proof", err, proof)
	}

	recorder := confirmApprovalHTTP(t, f, record, body, "operator", "session-operator", "127.0.0.1:1234")
	if recorder.Code != http.StatusServiceUnavailable || !strings.Contains(recorder.Body.String(), "APPROVAL_CREDENTIAL_VERIFIER_UNAVAILABLE") {
		t.Fatalf("unavailable verifier code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "do-not-expose") || strings.Contains(recorder.Body.String(), "postgres") {
		t.Fatalf("unavailable verifier leaked backend details: %s", recorder.Body.String())
	}
	if got, _ := f.gate.Get(record.ID); got.Status != approval.StatusPending {
		t.Fatalf("unavailable verifier authorized request: %+v", got)
	}
}

func TestApprovalHTTPDurableSubmitFailureIsServiceUnavailableAndRedacted(t *testing.T) {
	backendErr := errors.New("dial postgres with password=do-not-expose")
	persistence := approvalHTTPFailingPersistence{MemoryPersistence: approval.NewMemoryPersistence(), err: backendErr}
	gate, err := approval.NewGateWithPersistence(7, persistence)
	if err != nil {
		t.Fatal(err)
	}
	h := NewApprovalHTTPHandler(ApprovalHTTPOptions{Gate: gate})
	recorder := httptest.NewRecorder()
	request := approvalHTTPRequest(http.MethodPost, "/api/approvals", `{"id":"http-durable-failure","risk":"high","scope":"site:primary","policy_epoch":7,"ttl":"1m","confirmation_language":"en-US"}`, "operator", "session-operator", "admin", "127.0.0.1:1234")
	h.SubmitApproval(recorder, request)
	if recorder.Code != http.StatusServiceUnavailable || !strings.Contains(recorder.Body.String(), "APPROVAL_BACKEND_UNAVAILABLE") {
		t.Fatalf("durable failure code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "do-not-expose") || strings.Contains(recorder.Body.String(), "postgres") {
		t.Fatalf("durable failure leaked backend details: %s", recorder.Body.String())
	}
	if _, ok := gate.Get("http-durable-failure"); ok {
		t.Fatal("failed durable submit became visible")
	}
}

func TestApprovalHTTPConcurrentConfirmationHasSingleCommit(t *testing.T) {
	f := newApprovalHTTPFixture(t, true)
	record := submitApprovalHTTP(t, f, "http-concurrent")
	challenge := startApprovalHTTP(t, f, record)
	f.advance(approval.WarningDelay)
	body := "{\"confirmation_id\":\"" + challenge.ConfirmationID + "\",\"confirmation_phrase\":\"" + challenge.Phrase + "\",\"password\":\"secret\",\"second_confirmation\":true}"
	checkpoint := confirmApprovalHTTP(t, f, record, body, "operator", "session-operator", "127.0.0.1:1234")
	if checkpoint.Code != http.StatusConflict {
		t.Fatalf("checkpoint code=%d body=%s", checkpoint.Code, checkpoint.Body.String())
	}
	f.advance(time.Second)
	finalBody := "{\"confirmation_id\":\"" + challenge.ConfirmationID + "\",\"confirmation_phrase\":\"" + challenge.Phrase + "\",\"password\":\"secret\",\"second_confirmation\":true,\"third_confirmation\":true}"
	const callers = 12
	results := make(chan int, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- confirmApprovalHTTP(t, f, record, finalBody, "operator", "session-operator", "127.0.0.1:1234").Code
		}()
	}
	wg.Wait()
	close(results)
	successes := 0
	for code := range results {
		if code == http.StatusOK {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent final confirmations yielded %d successful commits", successes)
	}
	if got, _ := f.gate.Get(record.ID); got.Status != approval.StatusApproved || got.Commit == nil {
		t.Fatalf("concurrent confirmation did not approve exactly once: %+v", got)
	}
}

func TestApprovalHTTPRoutesExposeMountableEndpoints(t *testing.T) {
	f := newApprovalHTTPFixture(t, true)
	router := chi.NewRouter()
	f.handler.Mount(router)
	request := approvalHTTPRequest(http.MethodPost, "/approvals", "{}", "", "", "", "127.0.0.1:1234")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("unauthed mounted route code=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestApprovalHTTPRejectsMalformedTrailingJSON(t *testing.T) {
	f := newApprovalHTTPFixture(t, true)
	recorder := httptest.NewRecorder()
	req := approvalHTTPRequest(http.MethodPost, "/api/approvals",
		"{\"id\":\"http-trailing\",\"risk\":\"high\",\"scope\":\"site:primary\",\"policy_epoch\":7,\"ttl\":\"1m\",\"confirmation_language\":\"en-US\"}{",
		"operator", "session-operator", "admin", "127.0.0.1:1234")
	f.handler.SubmitApproval(recorder, req)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("trailing JSON code=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestApprovalHTTPRejectsOversizedJSONBody(t *testing.T) {
	f := newApprovalHTTPFixture(t, true)
	body := "{\"id\":\"oversized\",\"risk\":\"high\",\"scope\":\"site:primary\",\"policy_epoch\":7,\"ttl\":\"1m\",\"confirmation_language\":\"en-US\",\"nonce\":\"" + strings.Repeat("n", int(approvalHTTPMaxBodyBytes)) + "\"}"
	recorder := httptest.NewRecorder()
	req := approvalHTTPRequest(http.MethodPost, "/api/approvals", body, "operator", "session-operator", "admin", "127.0.0.1:1234")
	f.handler.SubmitApproval(recorder, req)
	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if _, ok := f.gate.Get("oversized"); ok {
		t.Fatal("oversized request created an approval record")
	}
}

func TestApprovalHTTPRejectsSpoofedCredentialConfirmationBooleans(t *testing.T) {
	f := newApprovalHTTPFixture(t, true)
	record := submitApprovalHTTP(t, f, "http-spoofed-bool")
	_ = startApprovalHTTP(t, f, record)
	f.advance(approval.WarningDelay)
	recorder := confirmApprovalHTTP(t, f, record, `{"password_confirmed":true,"second_confirmation":true}`, "operator", "session-operator", "127.0.0.1:1234")
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("spoofed credential boolean code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if got, _ := f.gate.Get(record.ID); got.Status != approval.StatusPending || got.Confirmation.ConfirmationID != "" {
		t.Fatalf("spoofed credential boolean mutated gate: %+v", got)
	}
}

func TestApprovalHTTPVerifierDoesNotBlockIndependentStart(t *testing.T) {
	f := newApprovalHTTPFixture(t, true)
	entered := make(chan struct{})
	release := make(chan struct{})
	f.handler.passwordVerifier = func(_ context.Context, session ApprovalSession, password string) (ApprovalCredentialProof, error) {
		if session.Subject != "operator" || password != "secret" {
			return ApprovalCredentialProof{}, ErrApprovalCredentialRejected
		}
		select {
		case <-entered:
		default:
			close(entered)
		}
		<-release
		return NewApprovalCredentialProof("http-blocked-proof", true, false), nil
	}
	first := submitApprovalHTTP(t, f, "http-blocked-first")
	second := submitApprovalHTTP(t, f, "http-blocked-second")
	firstChallenge := startApprovalHTTP(t, f, first)
	f.advance(approval.WarningDelay)
	body := "{\"confirmation_id\":\"" + firstChallenge.ConfirmationID + "\",\"confirmation_phrase\":\"" + firstChallenge.Phrase + "\",\"password\":\"secret\",\"second_confirmation\":true}"
	result := make(chan int, 1)
	go func() {
		recorder := confirmApprovalHTTP(t, f, first, body, "operator", "session-operator", "127.0.0.1:1234")
		result <- recorder.Code
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("password verifier was not reached")
	}
	started := make(chan int, 1)
	go func() {
		recorder := httptest.NewRecorder()
		req := approvalHTTPRequest(http.MethodPost, "/api/approvals/"+second.ID+"/confirmation/start", "{\"language\":\"en-US\"}", "operator", "session-operator", "admin", "127.0.0.1:1234")
		req = withApprovalRouteID(req, second.ID)
		f.handler.StartApprovalConfirmation(recorder, req)
		started <- recorder.Code
	}()
	select {
	case code := <-started:
		if code != http.StatusOK {
			t.Fatalf("independent start code=%d", code)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("independent start blocked behind credential verifier")
	}
	close(release)
	if code := <-result; code != http.StatusConflict {
		t.Fatalf("checkpoint code=%d", code)
	}
}
