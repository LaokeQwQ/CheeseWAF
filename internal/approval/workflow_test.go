package approval

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func workflowRequest(id string, risk RiskLevel) Request {
	return Request{ID: id, Risk: risk, Scope: "site:" + id, PolicyEpoch: 7, TTL: time.Minute, Actor: "admin", SessionID: "session-" + id, ConfirmationLanguage: "zh-CN"}
}

func TestPlanWorkflowUsesCoreFallbackMatrix(t *testing.T) {
	tests := []struct {
		name  string
		req   Request
		avail bool
		want  WorkflowRoute
	}{
		{name: "preapproved low", req: func() Request { r := workflowRequest("low", RiskLow); r.PreApproved = true; return r }(), want: WorkflowAutoApproved},
		{name: "ordinary medium", req: workflowRequest("medium", RiskMedium), want: WorkflowLocalManual},
		{name: "high with sidecar", req: workflowRequest("high", RiskHigh), avail: true, want: WorkflowSidecarPending},
		{name: "high without sidecar", req: workflowRequest("high-offline", RiskHigh), avail: false, want: WorkflowSidecarPending},
		{name: "token low", req: func() Request {
			r := workflowRequest("token", RiskLow)
			r.TokenOperation = true
			r.PreApproved = true
			return r
		}(), want: WorkflowSidecarPending},
		{name: "emergency", req: func() Request { r := workflowRequest("emergency", RiskEmergency); r.BreakGlass = true; return r }(), want: WorkflowBreakGlass},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plan, err := PlanWorkflow(tt.req, tt.avail)
			if err != nil {
				t.Fatalf("PlanWorkflow() error = %v", err)
			}
			if plan.Route != tt.want {
				t.Fatalf("route = %q, want %q", plan.Route, tt.want)
			}
		})
	}
}

func TestWorkflowBindingIsExactAndRefreshesAfterCoreEvent(t *testing.T) {
	now := time.Date(2026, 9, 8, 10, 0, 0, 0, time.UTC)
	gate := NewGate(7)
	record, err := gate.Submit(now, workflowRequest("binding", RiskMedium))
	if err != nil {
		t.Fatal(err)
	}
	binding, err := gate.WorkflowBindingFor(now, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := gate.ValidateWorkflowBinding(now, record.ID, binding); err != nil {
		t.Fatalf("initial binding rejected: %v", err)
	}
	changed := binding
	changed.Scope = "site:other"
	if err := gate.ValidateWorkflowBinding(now, record.ID, changed); !errors.Is(err, ErrWorkflowBinding) {
		t.Fatalf("changed scope error = %v, want workflow binding", err)
	}
	c := approvalTestBinding(record, now, "binding-confirm", "admin")
	c.ConfirmationPhrase = "错误"
	if _, err := gate.Confirm(now, record.ID, c); !errors.Is(err, ErrConfirmationPhrase) {
		t.Fatalf("invalid phrase error = %v", err)
	}
	if err := gate.ValidateWorkflowBinding(now, record.ID, binding); !errors.Is(err, ErrWorkflowEventStale) {
		t.Fatalf("stale binding error = %v, want stale event", err)
	}
	refreshed, err := gate.WorkflowBindingFor(now, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if refreshed.EventSequence <= binding.EventSequence {
		t.Fatalf("event sequence did not advance: old=%d new=%d", binding.EventSequence, refreshed.EventSequence)
	}
	if err := gate.ValidateWorkflowBinding(now, record.ID, refreshed); err != nil {
		t.Fatalf("refreshed binding rejected: %v", err)
	}
}

func TestSuperBatchAndDelegationAreBounded(t *testing.T) {
	now := time.Date(2026, 9, 8, 10, 10, 0, 0, time.UTC)
	gate := NewGate(7)
	first, err := gate.Submit(now, workflowRequest("batch-one", RiskMedium))
	if err != nil {
		t.Fatal(err)
	}
	second, err := gate.Submit(now, workflowRequest("batch-two", RiskMedium))
	if err != nil {
		t.Fatal(err)
	}
	one, err := gate.WorkflowBindingFor(now, first.ID)
	if err != nil {
		t.Fatal(err)
	}
	two, err := gate.WorkflowBindingFor(now, second.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateSuperBatch([]WorkflowBinding{one, two}); err != nil {
		t.Fatalf("valid super batch rejected: %v", err)
	}
	if err := ValidateSuperBatch([]WorkflowBinding{one, one}); !errors.Is(err, ErrBatchInvalid) {
		t.Fatalf("duplicate super batch error = %v", err)
	}

	delegation := ApprovalDelegation{ID: "delegation-1", ApprovalID: first.ID, Issuer: first.Request.Actor, IssuerSessionID: first.Request.SessionID, Delegate: "security-admin", DelegateSessionID: "delegate-session", Scope: first.Request.Scope, IntentDigest: first.Request.IntentDigest, WorkflowDigest: first.Request.WorkflowDigest, PolicyEpoch: first.Request.PolicyEpoch, IssuedAt: now, ExpiresAt: now.Add(30 * time.Second), OneTime: true}
	if err := ValidateApprovalDelegation(first, delegation, now); err != nil {
		t.Fatalf("valid delegation rejected: %v", err)
	}
	ledger := NewDelegationLedger()
	if err := ledger.Consume(now, first, delegation); err != nil {
		t.Fatalf("consume delegation: %v", err)
	}
	if err := ledger.Consume(now, first, delegation); !errors.Is(err, ErrDelegationReplay) {
		t.Fatalf("delegation replay error = %v", err)
	}
	self := delegation
	self.ID = "delegation-self"
	self.Delegate = self.Issuer
	if err := ValidateApprovalDelegation(first, self, now); !errors.Is(err, ErrDelegationSelf) {
		t.Fatalf("self delegation error = %v", err)
	}
	chain := delegation
	chain.ID = "delegation-chain"
	chain.ParentID = "parent"
	if err := ValidateApprovalDelegation(first, chain, now); !errors.Is(err, ErrDelegationChain) {
		t.Fatalf("chained delegation error = %v", err)
	}
	invalid := one
	invalid.IntentDigest = strings.Repeat("z", 64)
	if err := ValidateSuperBatch([]WorkflowBinding{invalid}); !errors.Is(err, ErrBatchInvalid) {
		t.Fatalf("invalid digest batch error = %v", err)
	}
}
