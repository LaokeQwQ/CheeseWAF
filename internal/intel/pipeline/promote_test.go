package pipeline

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/intel"
	"github.com/LaokeQwQ/CheeseWAF/internal/intel/impact"
)

func ingestOne(t *testing.T, p *Pipeline) Candidate {
	t.Helper()
	candidates, err := p.Ingest(context.Background(), "vendor-feed", rssBody("adv-1", "CVE-2025-1234", "summary"), 1, intel.Scope{SiteID: "site-1"})
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if len(candidates) != 1 {
		t.Fatalf("candidates = %d, want 1", len(candidates))
	}
	return candidates[0]
}

func newPlan(t *testing.T, candidate Candidate, now time.Time) impact.Plan {
	t.Helper()
	plan, err := impact.NewPlan(impact.PlanConfig{
		CandidateID: candidate.ID,
		Action:      candidate.Action,
		TTL:         24 * time.Hour,
	}, now, impact.DefaultPolicy())
	if err != nil {
		t.Fatalf("NewPlan: %v", err)
	}
	return plan
}

func TestPromoteAllowsShadowWithoutApproval(t *testing.T) {
	registry := testRegistry(t, sourceConfig("vendor-feed", "vendor"))
	now := testClock
	p := testPipeline(t, registry, FixedExtractor(nestedExtraction()), &now, 6*time.Hour)
	candidate := ingestOne(t, p)
	candidate.Impact.Verdict = impact.VerdictAllowShadow
	plan := newPlan(t, candidate, now)

	plan, promoted, err := p.Promote(candidate, plan, impact.Evidence{})
	if err != nil {
		t.Fatalf("Promote: %v", err)
	}
	if plan.State != impact.PlanShadow {
		t.Errorf("plan state = %q, want shadow", plan.State)
	}
	if promoted.State != intel.CandidateShadow {
		t.Errorf("candidate state = %q, want shadow", promoted.State)
	}
	if plan.Approved || promoted.Provenance.Approved {
		t.Error("shadow promotion must not record approval")
	}
}

func TestPromoteImpactRejectBlocksPromotion(t *testing.T) {
	registry := testRegistry(t, sourceConfig("vendor-feed", "vendor"))
	now := testClock
	p := testPipeline(t, registry, FixedExtractor(nestedExtraction()), &now, 6*time.Hour)
	candidate := ingestOne(t, p)
	candidate.Impact.Verdict = impact.VerdictReject
	candidate.Impact.Reasons = []string{"broadness 12% exceeds 5%"}
	plan := newPlan(t, candidate, now)

	if _, _, err := p.Promote(candidate, plan, impact.Evidence{}); !errors.Is(err, ErrImpactRejected) {
		t.Fatalf("err = %v, want ErrImpactRejected", err)
	}
}

func TestPromoteNeedsReviewRequiresApprovalBeforeShadow(t *testing.T) {
	registry := testRegistry(t, sourceConfig("vendor-feed", "vendor"))
	now := testClock
	p := testPipeline(t, registry, FixedExtractor(nestedExtraction()), &now, 6*time.Hour)
	candidate := ingestOne(t, p)
	candidate.Impact.Verdict = impact.VerdictNeedsReview
	plan := newPlan(t, candidate, now)

	if _, _, err := p.Promote(candidate, plan, impact.Evidence{}); !errors.Is(err, ErrApprovalRequired) {
		t.Fatalf("err = %v, want ErrApprovalRequired", err)
	}

	candidate.Provenance.Approved = true
	candidate.Provenance.ApprovedBy = "alice"
	plan, promoted, err := p.Promote(candidate, plan, impact.Evidence{})
	if err != nil {
		t.Fatalf("approved Promote: %v", err)
	}
	if plan.State != impact.PlanShadow || promoted.State != intel.CandidateShadow {
		t.Errorf("plan=%q candidate=%q, want shadow", plan.State, promoted.State)
	}
}

func TestPromoteRequiresApprovalBeforeCanary(t *testing.T) {
	registry := testRegistry(t, sourceConfig("vendor-feed", "vendor"))
	now := testClock
	p := testPipeline(t, registry, FixedExtractor(nestedExtraction()), &now, 6*time.Hour)
	candidate := ingestOne(t, p)
	candidate.Impact.Verdict = impact.VerdictAllowShadow

	plan, err := newPlan(t, candidate, now).StartShadow(now, impact.DefaultPolicy())
	if err != nil {
		t.Fatalf("StartShadow: %v", err)
	}
	if _, _, err := p.Promote(candidate, plan, impact.Evidence{Observations: 1000}); !errors.Is(err, ErrApprovalRequired) {
		t.Fatalf("err = %v, want ErrApprovalRequired", err)
	}

	candidate.Provenance.Approved = true
	candidate.Provenance.ApprovedBy = "alice"
	now = now.Add(2 * time.Hour)
	plan, promoted, err := p.Promote(candidate, plan, impact.Evidence{Observations: 1000})
	if err != nil {
		t.Fatalf("Promote: %v", err)
	}
	if plan.State != impact.PlanCanary {
		t.Errorf("plan state = %q, want canary", plan.State)
	}
	if promoted.State != intel.CandidateCanary {
		t.Errorf("candidate state = %q, want canary", promoted.State)
	}
	if !plan.Approved || plan.ApprovedBy != "alice" {
		t.Errorf("plan approval = %v/%q", plan.Approved, plan.ApprovedBy)
	}
	if !promoted.Provenance.Approved || promoted.Provenance.ApprovedBy != "alice" {
		t.Errorf("candidate approval = %v/%q", promoted.Provenance.Approved, promoted.Provenance.ApprovedBy)
	}
}

func TestPromoteExpiredCandidateRejected(t *testing.T) {
	registry := testRegistry(t, sourceConfig("vendor-feed", "vendor"))
	now := testClock
	p := testPipeline(t, registry, FixedExtractor(nestedExtraction()), &now, time.Hour)
	candidate := ingestOne(t, p)
	candidate.Impact.Verdict = impact.VerdictAllowShadow
	plan := newPlan(t, candidate, now)

	now = now.Add(2 * time.Hour)
	if _, _, err := p.Promote(candidate, plan, impact.Evidence{}); !errors.Is(err, ErrExpired) {
		t.Fatalf("err = %v, want ErrExpired", err)
	}
}

func TestPromoteRejectsPlanCandidateMismatch(t *testing.T) {
	registry := testRegistry(t, sourceConfig("vendor-feed", "vendor"))
	now := testClock
	p := testPipeline(t, registry, FixedExtractor(nestedExtraction()), &now, 6*time.Hour)
	candidate := ingestOne(t, p)
	candidate.Impact.Verdict = impact.VerdictAllowShadow
	plan := newPlan(t, candidate, now)
	plan.CandidateID = "cand-other"

	if _, _, err := p.Promote(candidate, plan, impact.Evidence{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("err = %v, want ErrInvalid", err)
	}
}

func TestIngestImpactProfilesDriveVerdict(t *testing.T) {
	build := func(matches int64) (*Pipeline, time.Time) {
		now := testClock
		registry := testRegistry(t, sourceConfig("vendor-feed", "vendor"))
		p, err := New(Config{
			Registry:  registry,
			Extractor: FixedExtractor(nestedExtraction()),
			TTL:       6 * time.Hour,
			Now:       func() time.Time { return now },
			Profiles: ProfileProviderFunc(func(_ context.Context, candidate impact.Candidate) []impact.Profile {
				return []impact.Profile{{
					SiteID:   candidate.SiteID,
					Path:     "/api/upload/form",
					Method:   "POST",
					Requests: 2000,
					Matches: impact.MatchCounts{
						candidate.ID: impact.MatchObservation{Count: matches},
					},
				}}
			}),
		})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		return p, now
	}

	allowed, _ := build(10)
	candidates, err := allowed.Ingest(context.Background(), "vendor-feed", rssBody("adv-1", "CVE-2025-1234", "summary"), 1, intel.Scope{SiteID: "site-1"})
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if candidates[0].Impact.Verdict != impact.VerdictAllowShadow {
		t.Errorf("verdict = %q, want allow-shadow", candidates[0].Impact.Verdict)
	}

	rejected, now := build(400)
	candidates, err = rejected.Ingest(context.Background(), "vendor-feed", rssBody("adv-1", "CVE-2025-1234", "summary"), 1, intel.Scope{SiteID: "site-1"})
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if candidates[0].Impact.Verdict != impact.VerdictReject {
		t.Fatalf("verdict = %q, want reject", candidates[0].Impact.Verdict)
	}
	plan := newPlan(t, candidates[0], now)
	if _, _, err := rejected.Promote(candidates[0], plan, impact.Evidence{Observations: 2000}); !errors.Is(err, ErrImpactRejected) {
		t.Fatalf("err = %v, want ErrImpactRejected", err)
	}
}
