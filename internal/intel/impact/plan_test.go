package impact

import (
	"errors"
	"strings"
	"testing"
	"time"
)

var testNow = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)

func newTestPlan(t *testing.T, action string, ttl time.Duration) Plan {
	t.Helper()
	plan, err := NewPlan(PlanConfig{
		CandidateID: "cand-1",
		Action:      action,
		TTL:         ttl,
	}, testNow, DefaultPolicy())
	if err != nil {
		t.Fatalf("NewPlan: %v", err)
	}
	return plan
}

func TestNewPlanValidation(t *testing.T) {
	plan := newTestPlan(t, "log", 24*time.Hour)
	if plan.State != PlanDraft || plan.Revision != 1 {
		t.Fatalf("plan = %+v, want draft revision 1", plan)
	}
	if !plan.ExpiresAt.Equal(testNow.Add(24 * time.Hour)) {
		t.Fatalf("expires at = %v", plan.ExpiresAt)
	}
	if plan.StableState != PlanDraft || plan.StableRevision != 1 {
		t.Fatalf("stable = %s/%d", plan.StableState, plan.StableRevision)
	}

	cases := []struct {
		name   string
		config PlanConfig
	}{
		{"empty candidate", PlanConfig{CandidateID: "", Action: "log", TTL: time.Hour}},
		{"unknown action", PlanConfig{CandidateID: "cand", Action: "drop", TTL: time.Hour}},
		{"zero ttl", PlanConfig{CandidateID: "cand", Action: "log", TTL: 0}},
		{"excessive ttl", PlanConfig{CandidateID: "cand", Action: "log", TTL: 91 * 24 * time.Hour}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewPlan(tc.config, testNow, DefaultPolicy()); !errors.Is(err, ErrInvalidPlan) {
				t.Fatalf("err = %v, want ErrInvalidPlan", err)
			}
		})
	}
}

func TestShadowAndCanaryPromotionGates(t *testing.T) {
	plan := newTestPlan(t, "block", 24*time.Hour)
	shadowAt := testNow.Add(time.Minute)

	next, err := plan.StartShadow(shadowAt, DefaultPolicy())
	if err != nil {
		t.Fatalf("StartShadow: %v", err)
	}
	if next.State != PlanShadow || next.ShadowStartedAt != shadowAt {
		t.Fatalf("shadow plan = %+v", next)
	}
	if next.StableState != PlanShadow || next.StableRevision != next.Revision {
		t.Fatalf("stable after shadow = %s/%d", next.StableState, next.StableRevision)
	}

	goodEvidence := Evidence{Observations: 2000}

	if _, err := next.StartCanary(5, goodEvidence, shadowAt.Add(10*time.Minute), DefaultPolicy()); !errors.Is(err, ErrShadowTooShort) {
		t.Fatalf("early canary err = %v, want ErrShadowTooShort", err)
	}
	if _, err := next.StartCanary(5, Evidence{Observations: 10}, shadowAt.Add(2*time.Hour), DefaultPolicy()); !errors.Is(err, ErrInsufficientSamples) {
		t.Fatalf("low-sample canary err = %v, want ErrInsufficientSamples", err)
	}
	if _, err := next.StartCanary(0, goodEvidence, shadowAt.Add(2*time.Hour), DefaultPolicy()); !errors.Is(err, ErrInvalidCanaryPercent) {
		t.Fatalf("zero percent err = %v, want ErrInvalidCanaryPercent", err)
	}
	if _, err := next.StartCanary(50, goodEvidence, shadowAt.Add(2*time.Hour), DefaultPolicy()); !errors.Is(err, ErrInvalidCanaryPercent) {
		t.Fatalf("high percent err = %v, want ErrInvalidCanaryPercent", err)
	}
	if _, err := next.StartCanary(5, goodEvidence, shadowAt.Add(2*time.Hour), DefaultPolicy()); !errors.Is(err, ErrApprovalRequired) {
		t.Fatalf("unapproved block err = %v, want ErrApprovalRequired", err)
	}

	approved, err := next.Approve("alice", shadowAt.Add(30*time.Minute), DefaultPolicy())
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if approved, err = approved.Approve("alice", shadowAt.Add(31*time.Minute), DefaultPolicy()); err != nil {
		t.Fatalf("idempotent Approve: %v", err)
	}
	if approved.ApprovedBy != "alice" || !approved.Approved {
		t.Fatalf("approval not recorded: %+v", approved)
	}

	canary, err := approved.StartCanary(5, goodEvidence, shadowAt.Add(2*time.Hour), DefaultPolicy())
	if err != nil {
		t.Fatalf("StartCanary: %v", err)
	}
	if canary.State != PlanCanary || canary.CanaryPercent != 5 {
		t.Fatalf("canary = %+v", canary)
	}
	if canary.StableState != PlanShadow {
		t.Fatalf("stable state = %s, want shadow", canary.StableState)
	}

	// Non-block actions do not need approval.
	logPlan, err := newTestPlan(t, "log", 24*time.Hour).StartShadow(shadowAt, DefaultPolicy())
	if err != nil {
		t.Fatalf("log StartShadow: %v", err)
	}
	if _, err := logPlan.StartCanary(1, goodEvidence, shadowAt.Add(2*time.Hour), DefaultPolicy()); err != nil {
		t.Fatalf("log StartCanary: %v", err)
	}
	if _, err := logPlan.StartCanary(25, goodEvidence, shadowAt.Add(2*time.Hour), DefaultPolicy()); err != nil {
		t.Fatalf("upper bound canary rejected: %v", err)
	}
}

func TestActivationGates(t *testing.T) {
	shadowAt := testNow.Add(time.Minute)
	plan, err := newTestPlan(t, "log", 24*time.Hour).StartShadow(shadowAt, DefaultPolicy())
	if err != nil {
		t.Fatalf("StartShadow: %v", err)
	}
	canaryAt := shadowAt.Add(2 * time.Hour)
	canary, err := plan.StartCanary(5, Evidence{Observations: 2000}, canaryAt, DefaultPolicy())
	if err != nil {
		t.Fatalf("StartCanary: %v", err)
	}

	if _, err := canary.Activate(Evidence{Observations: 10}, canaryAt.Add(time.Hour), DefaultPolicy()); !errors.Is(err, ErrInsufficientSamples) {
		t.Fatalf("low-sample activate err = %v, want ErrInsufficientSamples", err)
	}
	if _, err := canary.Activate(Evidence{Observations: 2000, Errors: 100}, canaryAt.Add(time.Hour), DefaultPolicy()); !errors.Is(err, ErrHealthThreshold) {
		t.Fatalf("unhealthy activate err = %v, want ErrHealthThreshold", err)
	}

	active, err := canary.Activate(Evidence{Observations: 2000, Errors: 20, FalsePositives: 1}, canaryAt.Add(time.Hour), DefaultPolicy())
	if err != nil {
		t.Fatalf("Activate: %v", err)
	}
	if active.State != PlanActive || active.CanaryPercent != 100 {
		t.Fatalf("active = %+v", active)
	}
	if active.StableState != PlanShadow {
		t.Fatalf("stable state = %s, want shadow", active.StableState)
	}
}

func TestTTLExpiry(t *testing.T) {
	plan := newTestPlan(t, "log", time.Hour)
	expired, changed := plan.CheckExpiry(testNow.Add(2 * time.Hour))
	if !changed || expired.State != PlanExpired {
		t.Fatalf("expiry = %v changed=%v", expired.State, changed)
	}
	if _, changed := expired.CheckExpiry(testNow.Add(3 * time.Hour)); changed {
		t.Fatal("expiry must be idempotent")
	}
	if _, err := expired.StartShadow(testNow.Add(2*time.Hour), DefaultPolicy()); !errors.Is(err, ErrPlanExpired) {
		t.Fatalf("StartShadow on expired plan err = %v, want ErrPlanExpired", err)
	}
	if _, err := plan.StartShadow(testNow.Add(2*time.Hour), DefaultPolicy()); !errors.Is(err, ErrPlanExpired) {
		t.Fatalf("StartShadow after TTL err = %v, want ErrPlanExpired", err)
	}
	if !plan.Expired(testNow.Add(2 * time.Hour)) {
		t.Fatal("plan should report expired")
	}

	shadow, err := plan.StartShadow(testNow.Add(time.Minute), DefaultPolicy())
	if err != nil {
		t.Fatalf("StartShadow: %v", err)
	}
	rolledBack, _ := shadow.Rollback("manual", testNow.Add(30*time.Minute))
	if rolledBack.State != PlanRolledBack {
		t.Fatalf("state = %s, want rolled_back", rolledBack.State)
	}
	if _, changed := rolledBack.CheckExpiry(testNow.Add(2 * time.Hour)); changed {
		t.Fatal("rolled-back plan must not expire")
	}
}

func TestAutomaticRollback(t *testing.T) {
	shadowAt := testNow.Add(time.Minute)
	plan, err := newTestPlan(t, "log", 24*time.Hour).StartShadow(shadowAt, DefaultPolicy())
	if err != nil {
		t.Fatalf("StartShadow: %v", err)
	}
	canaryAt := shadowAt.Add(2 * time.Hour)
	canary, err := plan.StartCanary(5, Evidence{Observations: 2000}, canaryAt, DefaultPolicy())
	if err != nil {
		t.Fatalf("StartCanary: %v", err)
	}

	healthy, rollback := canary.EvaluateHealth(Health{Requests: 1000, Errors: 10, FalsePositives: 0}, canaryAt.Add(time.Hour), DefaultPolicy())
	if rollback != nil {
		t.Fatalf("unexpected rollback: %+v", rollback)
	}
	if healthy.State != PlanCanary {
		t.Fatalf("healthy state = %s", healthy.State)
	}

	rolled, rollback := canary.EvaluateHealth(Health{Requests: 1000, Errors: 30}, canaryAt.Add(time.Hour), DefaultPolicy())
	if rollback == nil || !rollback.Applied {
		t.Fatalf("rollback = %+v, want applied", rollback)
	}
	if rolled.State != PlanRolledBack {
		t.Fatalf("state = %s, want rolled_back", rolled.State)
	}
	if rollback.PriorState != PlanShadow {
		t.Fatalf("prior state = %s, want shadow", rollback.PriorState)
	}
	if !strings.Contains(rollback.Reason, "automatic rollback") || !strings.Contains(rollback.Reason, "error rate") {
		t.Fatalf("reason = %q", rollback.Reason)
	}
	if rolled.RollbackReason != rollback.Reason {
		t.Fatalf("stored reason = %q, want %q", rolled.RollbackReason, rollback.Reason)
	}

	// False positives above the limit also trigger rollback.
	fpRolled, fpRollback := canary.EvaluateHealth(Health{Requests: 1000, FalsePositives: 5}, canaryAt.Add(time.Hour), DefaultPolicy())
	if fpRollback == nil || fpRolled.State != PlanRolledBack {
		t.Fatalf("fp rollback = %+v state=%s", fpRollback, fpRolled.State)
	}
	if !strings.Contains(fpRollback.Reason, "false-positive rate") {
		t.Fatalf("reason = %q", fpRollback.Reason)
	}

	// Invalid or empty health data is ignored rather than triggering.
	if next, rb := canary.EvaluateHealth(Health{}, canaryAt.Add(time.Hour), DefaultPolicy()); rb != nil || next.State != PlanCanary {
		t.Fatalf("empty health triggered rollback: %+v", rb)
	}
	if _, rb := canary.EvaluateHealth(Health{Requests: 10, Errors: 11}, canaryAt.Add(time.Hour), DefaultPolicy()); rb != nil {
		t.Fatal("invalid health triggered rollback")
	}
}

func TestRollbackIdempotence(t *testing.T) {
	shadowAt := testNow.Add(time.Minute)
	plan, err := newTestPlan(t, "log", 24*time.Hour).StartShadow(shadowAt, DefaultPolicy())
	if err != nil {
		t.Fatalf("StartShadow: %v", err)
	}
	canaryAt := shadowAt.Add(2 * time.Hour)
	active, err := plan.StartCanary(5, Evidence{Observations: 2000}, canaryAt, DefaultPolicy())
	if err != nil {
		t.Fatalf("StartCanary: %v", err)
	}
	active, err = active.Activate(Evidence{Observations: 2000}, canaryAt.Add(time.Hour), DefaultPolicy())
	if err != nil {
		t.Fatalf("Activate: %v", err)
	}

	original := active
	rolled, first := active.Rollback("manual rollback", canaryAt.Add(2*time.Hour))
	if !first.Applied {
		t.Fatalf("first rollback not applied: %+v", first)
	}
	if first.PriorState != PlanShadow || first.PriorRevision != plan.Revision {
		t.Fatalf("prior = %s/%d, want shadow/%d", first.PriorState, first.PriorRevision, plan.Revision)
	}
	if rolled.State != PlanRolledBack || rolled.Revision != active.Revision+1 {
		t.Fatalf("rolled = %+v", rolled)
	}
	if rolled.RollbackReason != "manual rollback" {
		t.Fatalf("reason = %q", rolled.RollbackReason)
	}
	if active.State != PlanActive || active.Revision != original.Revision {
		t.Fatal("rollback must not mutate the receiver")
	}

	second, again := rolled.Rollback("different reason", canaryAt.Add(3*time.Hour))
	if again.Applied {
		t.Fatal("second rollback must be idempotent")
	}
	if again.PriorState != first.PriorState || again.PriorRevision != first.PriorRevision {
		t.Fatalf("prior changed: %+v vs %+v", again, first)
	}
	if again.Reason != "manual rollback" {
		t.Fatalf("idempotent reason = %q, want manual rollback", again.Reason)
	}
	if second.Revision != rolled.Revision || second.State != PlanRolledBack {
		t.Fatal("idempotent rollback changed the plan")
	}

	draft := newTestPlan(t, "log", 24*time.Hour)
	if _, result := draft.Rollback("", testNow); result.Applied {
		t.Fatal("draft rollback must not apply")
	}
}

func TestPlanTransitionsRequireValidState(t *testing.T) {
	plan := newTestPlan(t, "log", 24*time.Hour)
	if _, err := plan.StartCanary(5, Evidence{Observations: 2000}, testNow.Add(2*time.Hour), DefaultPolicy()); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("err = %v, want ErrInvalidTransition", err)
	}
	shadow, err := plan.StartShadow(testNow.Add(time.Minute), DefaultPolicy())
	if err != nil {
		t.Fatalf("StartShadow: %v", err)
	}
	if _, err := shadow.StartShadow(testNow.Add(2*time.Minute), DefaultPolicy()); err != nil {
		t.Fatalf("idempotent StartShadow: %v", err)
	}
	if _, err := shadow.Activate(Evidence{Observations: 2000}, testNow.Add(2*time.Hour), DefaultPolicy()); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("activate from shadow err = %v, want ErrInvalidTransition", err)
	}
}
