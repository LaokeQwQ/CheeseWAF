package impact

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func baseCandidate(action string) Candidate {
	return Candidate{
		ID:         "cand-1",
		SiteID:     "site-a",
		PathPrefix: "/login",
		Methods:    []string{"POST"},
		Action:     action,
	}
}

func matchProfile(path string, requests, matches, benign int64) Profile {
	return Profile{
		SiteID:   "site-a",
		Path:     path,
		Method:   "POST",
		Requests: requests,
		Statuses: StatusCounts{200: requests - requests/10, 403: requests / 10},
		MultipartShapes: ShapeCounts{
			"fields=2": requests / 2,
		},
		Matches: MatchCounts{
			"cand-1": {Count: matches, Benign: benign},
		},
	}
}

func TestEstimateLowFalsePositiveAllowsShadow(t *testing.T) {
	profiles := []Profile{
		matchProfile("/login", 10000, 100, 5),
		{
			SiteID:   "site-a",
			Path:     "/login/other",
			Method:   "POST",
			Requests: 5000,
		},
		{
			SiteID:   "site-b",
			Path:     "/login",
			Method:   "POST",
			Requests: 999999,
			Matches:  MatchCounts{"cand-1": {Count: 900000, Benign: 900000}},
		},
	}

	report := Estimate(baseCandidate("block"), profiles)
	if report.Verdict != VerdictAllowShadow {
		t.Fatalf("verdict = %s, want %s (%v)", report.Verdict, VerdictAllowShadow, report.Reasons)
	}
	if report.Observations != 15000 {
		t.Fatalf("observations = %d, want 15000", report.Observations)
	}
	if report.WouldBlock != 100 {
		t.Fatalf("would block = %d, want 100", report.WouldBlock)
	}
	if report.BenignBlocks != 5 {
		t.Fatalf("benign blocks = %d, want 5", report.BenignBlocks)
	}
	wantRate := 5.0 / 15000.0
	if report.BenignBlockRate != wantRate {
		t.Fatalf("benign block rate = %v, want %v", report.BenignBlockRate, wantRate)
	}
	if !reflect.DeepEqual(report.UniquePaths, []string{"/login"}) {
		t.Fatalf("unique paths = %v, want [/login]", report.UniquePaths)
	}
	if report.PathCoverage != 0.5 {
		t.Fatalf("path coverage = %v, want 0.5", report.PathCoverage)
	}
	if report.MultipartShapes != 1 {
		t.Fatalf("multipart shapes = %d, want 1", report.MultipartShapes)
	}
	if report.StatusDistribution[200] != 9000 {
		t.Fatalf("status 200 = %d, want 9000", report.StatusDistribution[200])
	}
	if report.StatusDistribution[403] != 1000 {
		t.Fatalf("status 403 = %d, want 1000", report.StatusDistribution[403])
	}
	if !report.RequiresApprovalForBlock {
		t.Fatal("unapproved block action must require approval")
	}
	if report.CandidateID != "cand-1" {
		t.Fatalf("candidate id = %q", report.CandidateID)
	}
}

func TestEstimateHighFalsePositiveRejects(t *testing.T) {
	report := Estimate(baseCandidate("block"), []Profile{
		matchProfile("/login", 10000, 100, 50),
	})
	if report.Verdict != VerdictReject {
		t.Fatalf("verdict = %s, want reject", report.Verdict)
	}
	if !strings.Contains(strings.Join(report.Reasons, " "), "benign block rate") {
		t.Fatalf("reasons = %v, want benign block rate", report.Reasons)
	}
}

func TestEstimateInsufficientSamplesNeedsReview(t *testing.T) {
	report := Estimate(baseCandidate("log"), []Profile{
		matchProfile("/login", 500, 10, 0),
	})
	if report.Verdict != VerdictNeedsReview {
		t.Fatalf("verdict = %s, want needs-review", report.Verdict)
	}
	if !strings.Contains(strings.Join(report.Reasons, " "), "insufficient observations") {
		t.Fatalf("reasons = %v", report.Reasons)
	}
}

func TestEstimateBroadMatchRejects(t *testing.T) {
	report := Estimate(baseCandidate("log"), []Profile{
		matchProfile("/login", 2000, 400, 1),
	})
	if report.Verdict != VerdictReject {
		t.Fatalf("verdict = %s, want reject", report.Verdict)
	}
	if !strings.Contains(strings.Join(report.Reasons, " "), "broadness limit") {
		t.Fatalf("reasons = %v", report.Reasons)
	}
}

func TestEstimateNoMatchesNeedsReview(t *testing.T) {
	report := Estimate(baseCandidate("log"), []Profile{
		matchProfile("/login", 2000, 0, 0),
	})
	if report.Verdict != VerdictNeedsReview {
		t.Fatalf("verdict = %s, want needs-review", report.Verdict)
	}
	if !strings.Contains(strings.Join(report.Reasons, " "), "matched no observed requests") {
		t.Fatalf("reasons = %v", report.Reasons)
	}
}

func TestEstimateScopeAndValidation(t *testing.T) {
	t.Run("global site", func(t *testing.T) {
		candidate := baseCandidate("log")
		candidate.SiteID = "*"
		if report := Estimate(candidate, nil); report.Verdict != VerdictReject {
			t.Fatalf("verdict = %s, want reject", report.Verdict)
		}
	})

	t.Run("unknown action", func(t *testing.T) {
		candidate := baseCandidate("drop")
		if report := Estimate(candidate, nil); report.Verdict != VerdictReject {
			t.Fatalf("verdict = %s, want reject", report.Verdict)
		}
	})

	t.Run("other site excluded", func(t *testing.T) {
		report := Estimate(baseCandidate("log"), []Profile{
			{
				SiteID:   "site-b",
				Path:     "/login",
				Method:   "POST",
				Requests: 5000,
				Matches:  MatchCounts{"cand-1": {Count: 100}},
			},
		})
		if report.Verdict != VerdictNeedsReview {
			t.Fatalf("verdict = %s, want needs-review", report.Verdict)
		}
		if !strings.Contains(strings.Join(report.Reasons, " "), "no profiles match") {
			t.Fatalf("reasons = %v", report.Reasons)
		}
	})

	t.Run("invalid profile", func(t *testing.T) {
		profile := matchProfile("/login", 10000, 100, 101)
		report := Estimate(baseCandidate("log"), []Profile{profile})
		if report.Verdict != VerdictReject {
			t.Fatalf("verdict = %s, want reject", report.Verdict)
		}
		if !strings.Contains(strings.Join(report.Reasons, " "), "invalid match observation") {
			t.Fatalf("reasons = %v", report.Reasons)
		}
	})

	t.Run("invalid policy", func(t *testing.T) {
		policy := DefaultPolicy()
		policy.MaxBroadness = 2
		report := policy.Estimate(baseCandidate("log"), []Profile{matchProfile("/login", 10000, 100, 1)})
		if report.Verdict != VerdictReject {
			t.Fatalf("verdict = %s, want reject", report.Verdict)
		}
		if !errors.Is(policy.Validate(), ErrInvalidPolicy) {
			t.Fatal("policy validation should fail")
		}
	})
}

func TestEstimateCustomPolicyAndApproval(t *testing.T) {
	policy := Policy{
		MaxBenignBlockRate:   0.5,
		MinObservations:      10,
		MaxBroadness:         0.5,
		AllowUnapprovedBlock: true,
	}
	report := policy.Estimate(baseCandidate("block"), []Profile{
		matchProfile("/login", 20, 5, 1),
	})
	if report.Verdict != VerdictAllowShadow {
		t.Fatalf("verdict = %s, want allow-shadow (%v)", report.Verdict, report.Reasons)
	}
	if report.RequiresApprovalForBlock {
		t.Fatal("explicitly configured policy must not require approval")
	}

	approved := baseCandidate("block")
	approved.Approved = true
	if report := Estimate(approved, []Profile{matchProfile("/login", 10000, 100, 1)}); report.RequiresApprovalForBlock {
		t.Fatal("approved block candidate must not require approval")
	}
}

func TestEstimateDeterministicAcrossInputOrder(t *testing.T) {
	first := matchProfile("/login", 10000, 100, 1)
	second := Profile{
		SiteID:   "site-a",
		Path:     "/login/oauth",
		Method:   "POST",
		Requests: 4000,
		Matches:  MatchCounts{"cand-1": {Count: 20, Benign: 0}},
	}
	a := Estimate(baseCandidate("log"), []Profile{first, second})
	b := Estimate(baseCandidate("log"), []Profile{second, first})
	if a.Verdict != b.Verdict || a.WouldBlock != b.WouldBlock || a.Observations != b.Observations {
		t.Fatalf("reports differ: %+v vs %+v", a, b)
	}
	if !reflect.DeepEqual(a.UniquePaths, b.UniquePaths) {
		t.Fatalf("paths differ: %v vs %v", a.UniquePaths, b.UniquePaths)
	}
}

func TestPolicyValidate(t *testing.T) {
	if err := DefaultPolicy().Validate(); err != nil {
		t.Fatalf("default policy invalid: %v", err)
	}
	bad := []Policy{
		{MaxBenignBlockRate: -1},
		{MinObservations: -1},
		{MaxBroadness: -1},
		{MinShadowDuration: -1},
		{CanaryMinPercent: 30, CanaryMaxPercent: 10},
		{MaxErrorRate: -1},
		{MaxFalsePositiveRate: -1},
		{MaxTTL: -1},
	}
	for i, policy := range bad {
		if err := policy.Validate(); !errors.Is(err, ErrInvalidPolicy) {
			t.Fatalf("policy %d: err = %v, want ErrInvalidPolicy", i, err)
		}
	}
}
