package approval

import (
	"sync"
	"testing"
	"time"
)

func revisionApprovedRecord(t *testing.T) Record {
	t.Helper()
	now := time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)
	g := NewGate(7)
	r, err := g.Submit(now, Request{ID: "revision-approval", Risk: RiskHigh, Scope: "cluster:join:node", PolicyEpoch: 7, TTL: time.Minute, Actor: "requester", SessionID: "requester-session", ConfirmationLanguage: "en-US"})
	if err != nil {
		t.Fatal(err)
	}
	phrase, _ := ExpectedConfirmationPhrase(r.Request.ConfirmationLanguage)
	c := Confirmation{WarningReadAt: now, PasswordConfirmed: true, SecondConfirmation: true, ConfirmationID: "revision-confirmation", Actor: "approver", SessionID: "approver-session", Scope: r.Request.Scope, PolicyEpoch: 7, Local: true, ConfirmationLanguage: r.Request.ConfirmationLanguage, ConfirmationPhrase: phrase, IntentDigest: r.Request.IntentDigest, Nonce: r.Request.Nonce}
	if _, err := g.Confirm(now.Add(WarningDelay), r.ID, c); err != ErrThirdConfirmation {
		t.Fatalf("checkpoint: %v", err)
	}
	c.ThirdConfirmation = true
	if _, err := g.Confirm(now.Add(WarningDelay), r.ID, c); err != nil {
		t.Fatal(err)
	}
	r, _ = g.Get(r.ID)
	return r
}

func TestGateConsumeAuthorizationOnlyOnce(t *testing.T) {
	type authorizationConsumer interface {
		ConsumeAuthorization(time.Time, string, string, string) error
	}
	var candidate any = NewGate(7)
	if _, ok := candidate.(authorizationConsumer); !ok {
		t.Fatal("Gate has no atomic single-use authorization consumer")
	}
	now := time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)
	g := NewGate(7)
	r, err := g.Submit(now, Request{ID: "consume", Risk: RiskLow, Scope: "site:one", PolicyEpoch: 7, TTL: time.Minute, PreApproved: true, Actor: "system", SessionID: "system-session", ConfirmationLanguage: "en-US"})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 10)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- any(g).(authorizationConsumer).ConsumeAuthorization(now, r.ID, r.Request.Scope, r.Request.IntentDigest)
		}()
	}
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("authorization consumed %d times", successes)
	}
}

func TestAdapterRejectsMissingOrAlteredInteractiveEvidence(t *testing.T) {
	for name, mutate := range map[string]func(*Record){
		"missing evidence":    func(r *Record) { r.Confirmation = Confirmation{} },
		"different actor":     func(r *Record) { r.Confirmation.Actor = "other-approver" },
		"different session":   func(r *Record) { r.Confirmation.SessionID = "other-session" },
		"third click omitted": func(r *Record) { r.Confirmation.ThirdConfirmation = false; r.Confirmation.ConfirmationStep = 2 },
		"nonlocal":            func(r *Record) { r.Confirmation.Local = false },
	} {
		t.Run(name, func(t *testing.T) {
			r := revisionApprovedRecord(t)
			mutate(&r)
			if err := ValidateRecordForAdapter(r); err == nil {
				t.Fatal("tampered interactive approval accepted")
			}
		})
	}
}
