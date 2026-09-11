package approval

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func approvalMutationFixture() ApprovalMutation {
	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	req := Request{ID: "req-1", Risk: RiskMedium, Scope: "site:a", PolicyEpoch: 7, TTL: time.Minute, Actor: "op", SessionID: "session-op", ConfirmationLanguage: "zh-CN", WorkflowDigest: "wf-1"}
	req.Nonce = nonceForRequest(req)
	req.IntentDigest = IntentDigestForRequest(req)
	rec := Record{ID: "req-1", Request: req, Status: StatusApproved, SubmittedAt: now, ExpiresAt: now.Add(time.Minute), Commit: &AuthorizationCommit{RequestID: "req-1", ConfirmationID: "confirm-1", Actor: "op", Scope: "site:a", PolicyEpoch: 7, Risk: RiskMedium, TTL: time.Minute, IssuedAt: now, ExpiresAt: now.Add(time.Minute), WorkflowDigest: "wf-1", SessionID: "session-op", ConfirmationLanguage: "zh-CN", IntentDigest: req.IntentDigest, Nonce: req.Nonce}}
	return ApprovalMutation{IdempotencyKey: "idem-1", WorkflowDigest: "wf-1", Record: rec, Event: AuditEvent{Sequence: 1, Type: AuditSubmitted, At: now, RequestID: "req-1", Actor: "op", Scope: "site:a", PolicyEpoch: 7}}
}

func TestMemoryApprovalPersistenceIsAtomicAndRejectsIdempotencyConflict(t *testing.T) {
	p := NewMemoryPersistence()
	m := approvalMutationFixture()
	if err := p.Apply(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	if err := p.Apply(context.Background(), m); err != nil {
		t.Fatalf("retry: %v", err)
	}
	conflict := m
	conflict.Record.Status = StatusRevoked
	if err := p.Apply(context.Background(), conflict); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("conflict=%v", err)
	}
	events, err := p.Events(context.Background(), "req-1")
	if err != nil || len(events) != 1 || events[0].Hash == "" {
		t.Fatalf("events=%+v err=%v", events, err)
	}
}

func TestApprovalPersistenceEnforcesHashSequenceAndBindings(t *testing.T) {
	p := NewMemoryPersistence()
	m := approvalMutationFixture()
	if err := p.Apply(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	next := m
	next.IdempotencyKey = "idem-2"
	next.Event.Sequence = 3
	next.Event.Type = AuditAuthorized
	if err := p.Apply(context.Background(), next); !errors.Is(err, ErrEventSequence) {
		t.Fatalf("sequence gap=%v", err)
	}
	next.Event.Sequence = 2
	next.Event.Scope = "site:b"
	if err := p.Apply(context.Background(), next); !errors.Is(err, ErrBindingConflict) {
		t.Fatalf("scope mismatch=%v", err)
	}
}

func TestValidateRecordForAdapterRejectsTamperedStrictBindings(t *testing.T) {
	m := approvalMutationFixture()
	if err := ValidateRecordForAdapter(m.Record); err != nil {
		t.Fatalf("fixture rejected: %v", err)
	}
	checks := []struct {
		name   string
		mutate func(*Record)
	}{
		{name: "status without commit", mutate: func(r *Record) { r.Commit = nil }},
		{name: "scope changed", mutate: func(r *Record) { r.Commit.Scope = "site:other" }},
		{name: "nonce changed", mutate: func(r *Record) { r.Request.Nonce = "nonce-other" }},
		{name: "invalid actor", mutate: func(r *Record) { r.Commit.Actor = " admin " }},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			record := m.Record
			if record.Commit != nil {
				commit := *record.Commit
				record.Commit = &commit
			}
			check.mutate(&record)
			if err := ValidateRecordForAdapter(record); err == nil {
				t.Fatal("tampered record was accepted")
			}
		})
	}
}

func TestMemoryPersistenceRejectsTamperedEventBindingsAndHash(t *testing.T) {
	mutations := []struct {
		name   string
		mutate func(*AuditEvent)
	}{
		{"request id", func(e *AuditEvent) { e.RequestID = "req-other" }},
		{"scope", func(e *AuditEvent) { e.Scope = "site:other" }},
		{"policy epoch", func(e *AuditEvent) { e.PolicyEpoch++ }},
		{"intent digest", func(e *AuditEvent) { e.IntentDigest = strings.Repeat("a", 64) }},
		{"workflow digest", func(e *AuditEvent) { e.WorkflowDigest = "wf-other" }},
		{"session", func(e *AuditEvent) { e.SessionID = "session-other" }},
		{"nonce", func(e *AuditEvent) { e.Nonce = "nonce-other" }},
	}
	for _, tt := range mutations {
		t.Run(tt.name, func(t *testing.T) {
			p := NewMemoryPersistence()
			m := approvalMutationFixture()
			if err := p.Apply(context.Background(), m); err != nil {
				t.Fatal(err)
			}
			stored := p.records[m.Record.ID]
			tt.mutate(&stored.events[0])
			stored.events[0].Hash = hashEvent(stored.events[0])
			p.records[m.Record.ID] = stored
			if _, err := p.Events(context.Background(), m.Record.ID); !errors.Is(err, ErrInvalidPersistence) {
				t.Fatalf("Events() error = %v", err)
			}
		})
	}
	t.Run("event hash", func(t *testing.T) {
		p := NewMemoryPersistence()
		m := approvalMutationFixture()
		if err := p.Apply(context.Background(), m); err != nil {
			t.Fatal(err)
		}
		stored := p.records[m.Record.ID]
		stored.events[0].Hash = strings.Repeat("f", 64)
		p.records[m.Record.ID] = stored
		if _, err := p.Events(context.Background(), m.Record.ID); !errors.Is(err, ErrInvalidPersistence) {
			t.Fatalf("Events() error = %v", err)
		}
	})
}
