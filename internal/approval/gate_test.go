package approval

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func approvalTestBinding(record Record, now time.Time, id, actor string) Confirmation {
	phrase, err := ExpectedConfirmationPhrase(record.Request.ConfirmationLanguage)
	if err != nil {
		panic(err)
	}
	return Confirmation{
		WarningReadAt: now.Add(-WarningDelay), PasswordConfirmed: true, SecondConfirmation: true,
		ConfirmationID: id, Actor: actor, Scope: record.Request.Scope, PolicyEpoch: record.Request.PolicyEpoch,
		Local: true, SessionID: record.Request.SessionID, ConfirmationLanguage: record.Request.ConfirmationLanguage,
		ConfirmationPhrase: phrase, IntentDigest: record.Request.IntentDigest, WorkflowDigest: record.Request.WorkflowDigest, Nonce: record.Request.Nonce,
	}
}

func TestLowRiskPreapprovalProducesCommitWithoutInteractiveConfirmation(t *testing.T) {
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	gate := NewGate(7)
	record, err := gate.Submit(now, Request{ID: "r-low", Risk: RiskLow, Scope: "site:a", PolicyEpoch: 7, TTL: time.Minute, PreApproved: true, Actor: "scheduler", SessionID: "session-low", ConfirmationLanguage: "zh-CN"})
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if record.Status != StatusApproved || record.Commit == nil {
		t.Fatalf("expected pre-approved commit, got %+v", record)
	}
	if record.Commit.Scope != "site:a" || record.Commit.PolicyEpoch != 7 {
		t.Fatalf("commit binding lost: %+v", record.Commit)
	}
}

func TestSensitiveRequestsCannotBePreApprovedAndNeedThreeConfirmations(t *testing.T) {
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	gate := NewGate(2)
	record, err := gate.Submit(now, Request{ID: "r-token", Risk: RiskLow, Scope: "token:write", PolicyEpoch: 2, TTL: time.Minute, PreApproved: true, TokenOperation: true, Actor: "operator", SessionID: "session-token", ConfirmationLanguage: "zh-CN"})
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if record.Status != StatusPending || record.Commit != nil {
		t.Fatalf("sensitive request was auto-approved: %+v", record)
	}
	confirmation := approvalTestBinding(record, now, "c-1", "operator")
	if _, err := gate.Confirm(now, record.ID, confirmation); !errors.Is(err, ErrThirdConfirmationRequired) {
		t.Fatalf("expected third confirmation requirement, got %v", err)
	}
	confirmation.ThirdConfirmation = true
	commit, err := gate.Confirm(now, record.ID, confirmation)
	if err != nil {
		t.Fatalf("confirm: %v", err)
	}
	if commit.ConfirmationID != "c-1" {
		t.Fatalf("unexpected commit: %+v", commit)
	}
}

func TestConfirmationRequiresTenSecondWarningAndBinding(t *testing.T) {
	now := time.Date(2026, 9, 5, 12, 0, 20, 0, time.UTC)
	gate := NewGate(3)
	record, err := gate.Submit(now, Request{ID: "r-medium", Risk: RiskMedium, Scope: "site:a", PolicyEpoch: 3, TTL: time.Minute, Actor: "operator", SessionID: "session-medium", ConfirmationLanguage: "zh-CN"})
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	base := approvalTestBinding(record, now, "c-2", "operator")
	base.WarningReadAt = now.Add(-9 * time.Second)
	if _, err := gate.Confirm(now, record.ID, base); !errors.Is(err, ErrWarningDelay) {
		t.Fatalf("expected warning delay, got %v", err)
	}
	base.WarningReadAt = now.Add(-10 * time.Second)
	base.Scope = "site:b"
	if _, err := gate.Confirm(now, record.ID, base); !errors.Is(err, ErrScopeChanged) {
		t.Fatalf("expected scope rejection, got %v", err)
	}
}

func TestExpiredRevokedAndEpochChangedRequestsFailClosed(t *testing.T) {
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	gate := NewGate(4)
	expired, err := gate.Submit(now, Request{ID: "r-expired", Risk: RiskMedium, Scope: "site:a", PolicyEpoch: 4, TTL: time.Second, Actor: "operator", SessionID: "session-expired", ConfirmationLanguage: "zh-CN"})
	if err != nil {
		t.Fatalf("submit expired: %v", err)
	}
	c := approvalTestBinding(expired, now, "c-expired", "operator")
	if _, err := gate.Confirm(now.Add(2*time.Second), expired.ID, c); !errors.Is(err, ErrExpired) {
		t.Fatalf("expected expiry, got %v", err)
	}

	revoked, err := gate.Submit(now, Request{ID: "r-revoked", Risk: RiskMedium, Scope: "site:a", PolicyEpoch: 4, TTL: time.Minute, Actor: "operator", SessionID: "session-revoked", ConfirmationLanguage: "zh-CN"})
	if err != nil {
		t.Fatalf("submit revoked: %v", err)
	}
	if err := gate.Revoke(now, revoked.ID, "security", "incident"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := gate.Confirm(now, revoked.ID, c); !errors.Is(err, ErrRevoked) {
		t.Fatalf("expected revoke, got %v", err)
	}

	changed, err := gate.Submit(now, Request{ID: "r-epoch", Risk: RiskMedium, Scope: "site:a", PolicyEpoch: 4, TTL: time.Minute, Actor: "operator", SessionID: "session-epoch", ConfirmationLanguage: "zh-CN"})
	if err != nil {
		t.Fatalf("submit epoch: %v", err)
	}
	if err := gate.AdvanceEpoch(5); err != nil {
		t.Fatalf("advance epoch: %v", err)
	}
	if _, err := gate.Confirm(now, changed.ID, c); !errors.Is(err, ErrEpochChanged) {
		t.Fatalf("expected epoch rejection, got %v", err)
	}
}

func TestEmergencyRequiresRestrictedBreakGlassAndAuditIsAppendOnly(t *testing.T) {
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	gate := NewGate(9)
	record, err := gate.Submit(now, Request{ID: "r-emergency", Risk: RiskEmergency, Scope: "cluster:prod", PolicyEpoch: 9, TTL: 5 * time.Minute, BreakGlass: true, Actor: "sec-admin", SessionID: "session-emergency", ConfirmationLanguage: "zh-CN"})
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	c := approvalTestBinding(record, now, "c-bg", "sec-admin")
	c.ActorRole, c.BreakGlass, c.BreakGlassReason = RoleSecurityAdmin, true, "active incident"
	if _, err := gate.Confirm(now, record.ID, c); !errors.Is(err, ErrThirdConfirmationRequired) {
		t.Fatalf("expected third confirmation checkpoint, got %v", err)
	}
	c.ThirdConfirmation = true
	commit, err := gate.Confirm(now, record.ID, c)
	if err != nil {
		t.Fatalf("confirm break-glass: %v", err)
	}
	if commit.Risk != RiskEmergency {
		t.Fatalf("unexpected commit: %+v", commit)
	}
	events := gate.AuditEvents()
	if len(events) < 2 || events[len(events)-1].Type != AuditAuthorized {
		t.Fatalf("missing authorization audit: %+v", events)
	}
	events[0].Actor = "tampered"
	if gate.AuditEvents()[0].Actor == "tampered" {
		t.Fatal("audit snapshot was mutable")
	}
}

func TestConfirmationIDCannotBeReplayed(t *testing.T) {
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	gate := NewGate(1)
	r1, _ := gate.Submit(now, Request{ID: "r1", Risk: RiskMedium, Scope: "site:a", PolicyEpoch: 1, TTL: time.Minute, Actor: "operator", SessionID: "session-r1", ConfirmationLanguage: "zh-CN"})
	c := approvalTestBinding(r1, now, "same", "operator")
	if _, err := gate.Confirm(now, r1.ID, c); err != nil {
		t.Fatalf("first confirm: %v", err)
	}
	r2, _ := gate.Submit(now, Request{ID: "r2", Risk: RiskMedium, Scope: "site:a", PolicyEpoch: 1, TTL: time.Minute, Actor: "operator", SessionID: "session-r2", ConfirmationLanguage: "zh-CN"})
	if _, err := gate.Confirm(now, r2.ID, c); !errors.Is(err, ErrConfirmationReplay) {
		t.Fatalf("expected replay rejection, got %v", err)
	}
}

func TestPreapprovedConfirmationIDIsReservedAgainstReplay(t *testing.T) {
	now := time.Date(2026, 9, 5, 13, 30, 0, 0, time.UTC)
	gate := NewGate(1)
	first, err := gate.Submit(now, Request{ID: "pre-one", Risk: RiskLow, Scope: "site:a", PolicyEpoch: 1, TTL: time.Minute, PreApproved: true, Actor: "scheduler", SessionID: "session-pre-one", ConfirmationLanguage: "zh-CN"})
	if err != nil {
		t.Fatalf("submit first: %v", err)
	}
	second, err := gate.Submit(now, Request{ID: "pre-two", Risk: RiskMedium, Scope: "site:a", PolicyEpoch: 1, TTL: time.Minute, Actor: "requester", SessionID: "session-pre-two", ConfirmationLanguage: "zh-CN"})
	if err != nil {
		t.Fatalf("submit second: %v", err)
	}
	c := approvalTestBinding(second, now, first.Commit.ConfirmationID, "operator")
	if _, err := gate.Confirm(now, second.ID, c); !errors.Is(err, ErrConfirmationReplay) {
		t.Fatalf("expected preapproval replay rejection, got %v", err)
	}
}

func TestApprovedRecordsReturnsDeepCopies(t *testing.T) {
	now := time.Date(2026, 9, 24, 8, 0, 0, 0, time.UTC)
	gate := NewGate(1)
	record, err := gate.Submit(now, Request{ID: "approved-snapshot", Risk: RiskLow, Scope: "site:a", PolicyEpoch: 1, TTL: time.Minute, PreApproved: true, Actor: "scheduler", SessionID: "session-snapshot", ConfirmationLanguage: "zh-CN"})
	if err != nil {
		t.Fatal(err)
	}
	records := gate.ApprovedRecords()
	if len(records) != 1 || records[0].Commit == nil {
		t.Fatalf("ApprovedRecords()=%+v, want one approved record", records)
	}
	records[0].Request.Scope = "site:tampered"
	records[0].Commit.Scope = "site:tampered"
	stored, ok := gate.Get(record.ID)
	if !ok || stored.Request.Scope != "site:a" || stored.Commit == nil || stored.Commit.Scope != "site:a" {
		t.Fatalf("ApprovedRecords snapshot mutated gate state: %+v", stored)
	}
}

func TestEveryRestrictedClassIgnoresPreapproval(t *testing.T) {
	now := time.Date(2026, 9, 5, 13, 0, 0, 0, time.UTC)
	tests := []struct {
		name string
		req  Request
	}{
		{name: "high risk", req: Request{Risk: RiskHigh}},
		{name: "untrusted", req: Request{Risk: RiskLow, Untrusted: true}},
		{name: "test signed", req: Request{Risk: RiskLow, Test: true}},
		{name: "token", req: Request{Risk: RiskLow, TokenOperation: true}},
		{name: "kms", req: Request{Risk: RiskLow, KMSOperation: true}},
		{name: "cluster", req: Request{Risk: RiskLow, ClusterOperation: true}},
	}
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gate := NewGate(1)
			tt.req.ID = "restricted-" + string(rune('a'+i))
			tt.req.Scope, tt.req.PolicyEpoch, tt.req.TTL, tt.req.PreApproved, tt.req.Actor = "resource:one", 1, time.Minute, true, "operator"
			tt.req.SessionID, tt.req.ConfirmationLanguage = "session-restricted", "zh-CN"
			record, err := gate.Submit(now, tt.req)
			if err != nil {
				t.Fatalf("submit: %v", err)
			}
			if record.Status != StatusPending || record.Commit != nil {
				t.Fatalf("restricted class was auto-approved: %+v", record)
			}
		})
	}
}

func TestConfirmationStateCarriesTTLAndRejectedAttemptsAreAudited(t *testing.T) {
	now := time.Date(2026, 9, 5, 13, 0, 0, 0, time.UTC)
	gate := NewGate(11)
	record, err := gate.Submit(now, Request{ID: "ttl", Risk: RiskMedium, Scope: "site:a", PolicyEpoch: 11, TTL: 2 * time.Minute, Actor: "requester", SessionID: "session-ttl", ConfirmationLanguage: "zh-CN"})
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	bad := approvalTestBinding(record, now, "bad", "approver")
	bad.PasswordConfirmed = false
	if _, err := gate.Confirm(now, record.ID, bad); !errors.Is(err, ErrPasswordConfirmation) {
		t.Fatalf("expected password rejection, got %v", err)
	}
	events := gate.AuditEvents()
	if events[len(events)-1].Type != AuditRejected {
		t.Fatalf("rejection was not audited: %+v", events)
	}
	good := bad
	good.PasswordConfirmed = true
	good.ConfirmationID = "good"
	commit, err := gate.Confirm(now, record.ID, good)
	if err != nil {
		t.Fatalf("confirm: %v", err)
	}
	stored, ok := gate.Get(record.ID)
	if !ok || stored.Confirmation.TTL != 2*time.Minute || commit.TTL != 2*time.Minute {
		t.Fatalf("TTL missing from confirmation/commit: record=%+v commit=%+v", stored, commit)
	}
}

func TestEmergencyCannotBeSubmittedOutsideBreakGlass(t *testing.T) {
	gate := NewGate(1)
	_, err := gate.Submit(time.Now(), Request{ID: "emergency", Risk: RiskEmergency, Scope: "cluster:a", PolicyEpoch: 1, TTL: time.Minute, Actor: "admin", SessionID: "session-emergency", ConfirmationLanguage: "zh-CN"})
	if !errors.Is(err, ErrBreakGlassRequired) {
		t.Fatalf("expected restricted break-glass requirement, got %v", err)
	}
}

func TestInteractiveApprovalMustBeLocalAndBreakGlassRoleIsRestricted(t *testing.T) {
	now := time.Date(2026, 9, 5, 14, 0, 0, 0, time.UTC)
	gate := NewGate(1)
	medium, _ := gate.Submit(now, Request{ID: "local", Risk: RiskMedium, Scope: "site:a", PolicyEpoch: 1, TTL: time.Minute, Actor: "requester", SessionID: "session-local", ConfirmationLanguage: "zh-CN"})
	c := approvalTestBinding(medium, now, "remote", "operator")
	c.Local = false
	if _, err := gate.Confirm(now, medium.ID, c); !errors.Is(err, ErrLocalConfirmation) {
		t.Fatalf("expected local confirmation rejection, got %v", err)
	}

	emergency, err := gate.Submit(now, Request{ID: "role", Risk: RiskEmergency, Scope: "cluster:a", PolicyEpoch: 1, TTL: time.Minute, Actor: "requester", SessionID: "session-role", ConfirmationLanguage: "zh-CN", BreakGlass: true})
	if err != nil {
		t.Fatalf("submit emergency: %v", err)
	}
	c = approvalTestBinding(emergency, now, "role-confirm", "operator")
	c.ThirdConfirmation, c.BreakGlass, c.BreakGlassReason = true, true, "incident"
	c.ActorRole = RoleOperator
	if _, err := gate.Confirm(now, emergency.ID, c); !errors.Is(err, ErrBreakGlassActor) {
		t.Fatalf("expected break-glass actor rejection, got %v", err)
	}
}

func TestApprovalRejectsTTLAbovePlatformLimit(t *testing.T) {
	gate := NewGate(1)
	_, err := gate.Submit(time.Date(2026, 9, 5, 15, 0, 0, 0, time.UTC), Request{ID: "long", Risk: RiskMedium, Scope: "site:a", PolicyEpoch: 1, TTL: MaxApprovalTTL + time.Second, Actor: "operator", SessionID: "session-long", ConfirmationLanguage: "zh-CN"})
	if !errors.Is(err, ErrTTLExceeded) {
		t.Fatalf("overlong approval accepted: %v", err)
	}
}

func TestApprovalRejectsWhitespaceAndInvisibleIdentityFieldsWithoutNormalization(t *testing.T) {
	now := time.Date(2026, 9, 8, 9, 0, 0, 0, time.UTC)
	base := Request{ID: "request-identity", Risk: RiskMedium, Scope: "site:primary", PolicyEpoch: 1, TTL: time.Minute, Actor: "admin", SessionID: "session-admin", ConfirmationLanguage: "zh-CN"}
	for name, mutate := range map[string]func(*Request){
		"space actor":      func(r *Request) { r.Actor = " admin " },
		"space request ID": func(r *Request) { r.ID = " request-identity " },
		"zero width scope": func(r *Request) { r.Scope = "site:\u200bprimary" },
		"space session":    func(r *Request) { r.SessionID = " session-admin" },
		"missing language": func(r *Request) { r.ConfirmationLanguage = "" },
	} {
		t.Run(name, func(t *testing.T) {
			g := NewGate(1)
			req := base
			mutate(&req)
			if _, err := g.Submit(now, req); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("Submit() error = %v, want ErrInvalidRequest", err)
			}
		})
	}

	gate := NewGate(1)
	record, err := gate.Submit(now, base)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]struct {
		apply func(*Confirmation)
		want  error
	}{
		"space actor":        {func(c *Confirmation) { c.Actor = " admin " }, ErrInvalidActor},
		"invisible actor":    {func(c *Confirmation) { c.Actor = "admin\u200b" }, ErrInvalidActor},
		"space confirmation": {func(c *Confirmation) { c.ConfirmationID = " confirm-1 " }, ErrInvalidConfirmationID},
		"missing language":   {func(c *Confirmation) { c.ConfirmationLanguage = "" }, ErrConfirmationLanguage},
	} {
		t.Run(name, func(t *testing.T) {
			c := approvalTestBinding(record, now, "confirm-identity-"+strings.ReplaceAll(name, " ", "-"), "admin")
			mutate.apply(&c)
			if _, err := gate.Confirm(now, record.ID, c); !errors.Is(err, mutate.want) {
				t.Fatalf("Confirm() error = %v, want %v", err, mutate.want)
			}
		})
	}
}

func TestApprovalConfirmationBindsSessionPhraseIntentWorkflowAndTTL(t *testing.T) {
	now := time.Date(2026, 9, 8, 9, 10, 0, 0, time.UTC)
	gate := NewGate(2)
	record, err := gate.Submit(now, Request{
		ID: "binding-request", Risk: RiskMedium, Scope: "site:primary", PolicyEpoch: 2, TTL: 2 * time.Minute,
		Actor: "admin", SessionID: "session-admin", ConfirmationLanguage: "en-US", WorkflowDigest: "workflow-v1",
	})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*Confirmation)
		want   error
	}{
		{name: "wrong phrase", mutate: func(c *Confirmation) { c.ConfirmationPhrase = "确认" }, want: ErrConfirmationPhrase},
		{name: "changed session", mutate: func(c *Confirmation) { c.SessionID = "session-other" }, want: ErrSessionChanged},
		{name: "changed intent", mutate: func(c *Confirmation) { c.IntentDigest = strings.Repeat("a", 64) }, want: ErrIntentChanged},
		{name: "changed workflow", mutate: func(c *Confirmation) { c.WorkflowDigest = "workflow-v2" }, want: ErrWorkflowChanged},
		{name: "changed ttl", mutate: func(c *Confirmation) { c.TTL = time.Minute }, want: ErrTTLChanged},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := approvalTestBinding(record, now, "binding-"+strings.ReplaceAll(tt.name, " ", "-"), "admin")
			tt.mutate(&c)
			if _, err := gate.Confirm(now, record.ID, c); !errors.Is(err, tt.want) {
				t.Fatalf("Confirm() error = %v, want %v", err, tt.want)
			}
		})
	}

	valid := approvalTestBinding(record, now, "binding-valid", "admin")
	if _, err := gate.Confirm(now, record.ID, valid); err != nil {
		t.Fatalf("valid confirmation failed: %v", err)
	}
}

func TestHighRiskCheckpointReservesConfirmationAndRequiresUnchangedFinalClick(t *testing.T) {
	now := time.Date(2026, 9, 8, 9, 20, 0, 0, time.UTC)
	gate := NewGate(3)
	high, err := gate.Submit(now, Request{ID: "high-request", Risk: RiskHigh, Scope: "plugin:example", PolicyEpoch: 3, TTL: time.Minute, Actor: "admin", SessionID: "session-high", ConfirmationLanguage: "zh-CN"})
	if err != nil {
		t.Fatal(err)
	}
	checkpoint := approvalTestBinding(high, now, "checkpoint-1", "admin")
	if _, err := gate.Confirm(now, high.ID, checkpoint); !errors.Is(err, ErrThirdConfirmation) {
		t.Fatalf("checkpoint error = %v, want third confirmation", err)
	}
	stored, ok := gate.Get(high.ID)
	if !ok || stored.Status != StatusPending || stored.Confirmation.ConfirmationStep != 2 {
		t.Fatalf("checkpoint was not retained: %+v", stored)
	}

	other, err := gate.Submit(now, Request{ID: "other-request", Risk: RiskMedium, Scope: "plugin:other", PolicyEpoch: 3, TTL: time.Minute, Actor: "admin", SessionID: "session-other", ConfirmationLanguage: "zh-CN"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gate.Confirm(now, other.ID, approvalTestBinding(other, now, checkpoint.ConfirmationID, "admin")); !errors.Is(err, ErrConfirmationReplay) {
		t.Fatalf("reserved ID reuse error = %v, want replay", err)
	}

	changed := checkpoint
	changed.ThirdConfirmation = true
	changed.IntentDigest = strings.Repeat("b", 64)
	if _, err := gate.Confirm(now, high.ID, changed); !errors.Is(err, ErrIntentChanged) {
		t.Fatalf("changed final confirmation error = %v, want intent change", err)
	}
	final := checkpoint
	final.ThirdConfirmation = true
	if _, err := gate.Confirm(now, high.ID, final); err != nil {
		t.Fatalf("final confirmation failed: %v", err)
	}
}

func TestCheckpointExpiresAndRevocationAuditRejectsUnsafeInput(t *testing.T) {
	now := time.Date(2026, 9, 8, 9, 30, 0, 0, time.UTC)
	gate := NewGate(4)
	record, err := gate.Submit(now, Request{ID: "expires-checkpoint", Risk: RiskHigh, Scope: "plugin:example", PolicyEpoch: 4, TTL: 20 * time.Second, Actor: "admin", SessionID: "session-expire", ConfirmationLanguage: "zh-CN"})
	if err != nil {
		t.Fatal(err)
	}
	checkpoint := approvalTestBinding(record, now, "expires-checkpoint-id", "admin")
	if _, err := gate.Confirm(now, record.ID, checkpoint); !errors.Is(err, ErrThirdConfirmation) {
		t.Fatal(err)
	}
	checkpoint.ThirdConfirmation = true
	if _, err := gate.Confirm(now.Add(20*time.Second), record.ID, checkpoint); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired checkpoint error = %v, want expiry", err)
	}
	if err := gate.Revoke(now, record.ID, " admin ", "incident"); !errors.Is(err, ErrInvalidActor) {
		t.Fatalf("whitespace revoke actor error = %v", err)
	}
	if err := gate.Revoke(now, record.ID, "admin", " "); !errors.Is(err, ErrReasonRequired) {
		t.Fatalf("blank revoke reason error = %v", err)
	}
}

func TestTOTPCanSatisfyStrongAuthenticationWithoutPassword(t *testing.T) {
	now := time.Date(2026, 9, 8, 9, 40, 0, 0, time.UTC)
	gate := NewGate(5)
	record, err := gate.Submit(now, Request{ID: "totp-request", Risk: RiskMedium, Scope: "site:totp", PolicyEpoch: 5, TTL: time.Minute, Actor: "admin", SessionID: "session-totp", ConfirmationLanguage: "en-US"})
	if err != nil {
		t.Fatal(err)
	}
	c := approvalTestBinding(record, now, "totp-confirm", "admin")
	c.PasswordConfirmed = false
	c.TOTPConfirmed = true
	if _, err := gate.Confirm(now, record.ID, c); err != nil {
		t.Fatalf("TOTP confirmation failed: %v", err)
	}
}

func TestConcurrentConfirmationIDReplayHasExactlyOneWinner(t *testing.T) {
	now := time.Date(2026, 9, 8, 9, 50, 0, 0, time.UTC)
	gate := NewGate(6)
	first, err := gate.Submit(now, Request{ID: "concurrent-one", Risk: RiskMedium, Scope: "site:one", PolicyEpoch: 6, TTL: time.Minute, Actor: "admin", SessionID: "session-one", ConfirmationLanguage: "zh-CN"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := gate.Submit(now, Request{ID: "concurrent-two", Risk: RiskMedium, Scope: "site:two", PolicyEpoch: 6, TTL: time.Minute, Actor: "admin", SessionID: "session-two", ConfirmationLanguage: "zh-CN"})
	if err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 2)
	go func() {
		_, err := gate.Confirm(now, first.ID, approvalTestBinding(first, now, "shared-confirmation", "admin"))
		results <- err
	}()
	go func() {
		_, err := gate.Confirm(now, second.ID, approvalTestBinding(second, now, "shared-confirmation", "admin"))
		results <- err
	}()
	var succeeded, replayed int
	for range 2 {
		err := <-results
		if err == nil {
			succeeded++
		} else if errors.Is(err, ErrConfirmationReplay) {
			replayed++
		} else {
			t.Fatalf("unexpected concurrent confirmation error: %v", err)
		}
	}
	if succeeded != 1 || replayed != 1 {
		t.Fatalf("winners=%d replays=%d, want 1/1", succeeded, replayed)
	}
}
