package intel

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"
)

func php2shellExtraction() Extraction {
	return Extraction{
		CVEIDs:           []string{"CVE-2026-12345"},
		Products:         []string{"php"},
		AffectedVersions: []string{"8.1.x", "8.2.x"},
		Request: RequestShape{
			Method:           "POST",
			Path:             "/upload.php",
			ContentType:      "multipart/form-data; boundary=x",
			ParameterNames:   []string{"files"},
			Markers:          []string{"<?php"},
			NestedArrays:     true,
			SessionParameter: MultipartProgressMarker,
			UploadProgress:   true,
		},
		Response: ResponseEvidence{
			StatusCodes:            []int{200},
			OversizedSessionCookie: true,
		},
		Confidence: 0.92,
		References: []string{"https://vendor.example.test/advisories/CVE-2026-12345"},
	}
}

func TestCompileMultipartSessionProgress(t *testing.T) {
	compiled, err := NewRuleCompiler().Compile(php2shellExtraction(), Scope{SiteID: "site-a"})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if compiled.Rule.Location != "body" {
		t.Fatalf("expected body location, got %q", compiled.Rule.Location)
	}
	if !strings.Contains(compiled.Rule.Pattern, MultipartProgressMarker) {
		t.Fatalf("expected session progress marker in pattern: %q", compiled.Rule.Pattern)
	}
	if strings.Contains(compiled.Rule.Pattern, ".*") {
		t.Fatalf("pattern must not contain an unbounded wildcard: %q", compiled.Rule.Pattern)
	}
	if compiled.Rule.Action != ActionLog || compiled.Rule.Enabled {
		t.Fatalf("generated rule must be disabled and log-only: %+v", compiled.Rule)
	}
	if compiled.Scope.PathPrefix != "/upload.php" {
		t.Fatalf("expected path scope from extraction, got %q", compiled.Scope.PathPrefix)
	}
	if len(compiled.Scope.Methods) != 1 || compiled.Scope.Methods[0] != "POST" {
		t.Fatalf("expected POST scope from extraction, got %v", compiled.Scope.Methods)
	}
	if err := ValidateCompiledRule(compiled); err != nil {
		t.Fatalf("compiled rule failed validation: %v", err)
	}
}

func TestCompileNestedArrays(t *testing.T) {
	extraction := Extraction{
		CVEIDs:     []string{"CVE-2026-20001"},
		Confidence: 0.8,
		Request: RequestShape{
			Method:         "POST",
			Path:           "/api/import",
			NestedArrays:   true,
			ParameterNames: []string{"files"},
		},
	}
	compiled, err := NewRuleCompiler().Compile(extraction, Scope{SiteID: "site-b"})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if compiled.Rule.Location != "body" {
		t.Fatalf("expected body location, got %q", compiled.Rule.Location)
	}
	if !strings.Contains(compiled.Rule.Pattern, "files") || !strings.Contains(compiled.Rule.Pattern, `\]`) {
		t.Fatalf("expected nested array shape: %q", compiled.Rule.Pattern)
	}
	if strings.Contains(compiled.Rule.Pattern, ".*") {
		t.Fatalf("pattern must not contain an unbounded wildcard: %q", compiled.Rule.Pattern)
	}
}

func TestCompilePHPMarkers(t *testing.T) {
	extraction := Extraction{
		CVEIDs:     []string{"CVE-2026-20002"},
		Confidence: 0.75,
		Request: RequestShape{
			Method:  "POST",
			Path:    "/upload.php",
			Markers: []string{"<?php", "serialized"},
		},
	}
	compiled, err := NewRuleCompiler().Compile(extraction, Scope{SiteID: "site-c"})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if !strings.Contains(compiled.Rule.Pattern, `<\?php`) {
		t.Fatalf("missing PHP tag marker: %q", compiled.Rule.Pattern)
	}
	if !strings.Contains(compiled.Rule.Pattern, `O:[0-9]{1,4}`) {
		t.Fatalf("missing serialized marker: %q", compiled.Rule.Pattern)
	}
}

func TestCompileOversizedSessionCookie(t *testing.T) {
	extraction := Extraction{
		CVEIDs:     []string{"CVE-2026-20003"},
		Confidence: 0.7,
		Request: RequestShape{
			Method:           "POST",
			Path:             "/login",
			SessionParameter: "PHPSESSID",
		},
		Response: ResponseEvidence{OversizedSessionCookie: true},
	}
	compiled, err := NewRuleCompiler().Compile(extraction, Scope{SiteID: "site-d"})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if compiled.Rule.Location != "cookie" {
		t.Fatalf("expected cookie location, got %q", compiled.Rule.Location)
	}
	if !strings.Contains(compiled.Rule.Pattern, "PHPSESSID") {
		t.Fatalf("expected session parameter in pattern: %q", compiled.Rule.Pattern)
	}
}

func TestCompiledMultipartRuleMatchesOnlyTheTargetShape(t *testing.T) {
	compiled, err := NewRuleCompiler().Compile(php2shellExtraction(), Scope{SiteID: "site-a"})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	re := regexp.MustCompile(compiled.Rule.Pattern)
	malicious := "------boundary\r\nContent-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\n1\r\n"
	if !re.MatchString(malicious) {
		t.Fatalf("rule does not match the PHP2Shell upload progress shape: %q", compiled.Rule.Pattern)
	}
	benign := "------boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"photo.jpg\"\r\n\r\njpeg\r\n"
	if re.MatchString(benign) {
		t.Fatalf("rule matches a benign multipart upload: %q", compiled.Rule.Pattern)
	}
}

func TestCompiledCookieRuleMatchesOnlyOversizedValues(t *testing.T) {
	extraction := Extraction{
		CVEIDs:     []string{"CVE-2026-20003"},
		Confidence: 0.7,
		Request:    RequestShape{Path: "/login", SessionParameter: "PHPSESSID"},
		Response:   ResponseEvidence{OversizedSessionCookie: true},
	}
	compiled, err := NewRuleCompiler().Compile(extraction, Scope{SiteID: "site-d"})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	re := regexp.MustCompile(compiled.Rule.Pattern)
	if !re.MatchString("PHPSESSID=" + strings.Repeat("a", 300)) {
		t.Fatalf("rule does not match an oversized session cookie: %q", compiled.Rule.Pattern)
	}
	if re.MatchString("PHPSESSID=" + strings.Repeat("a", 26)) {
		t.Fatalf("rule matches a normal session cookie: %q", compiled.Rule.Pattern)
	}
}

func TestCompileVagueAdvisoryHasNoSafeRule(t *testing.T) {
	extraction := Extraction{
		CVEIDs:           []string{"CVE-2026-30000"},
		Products:         []string{"php"},
		AffectedVersions: []string{"8.3.x"},
		Confidence:       0.4,
	}
	_, err := NewRuleCompiler().Compile(extraction, Scope{SiteID: "site-a"})
	if !errors.Is(err, ErrNoSafeRule) {
		t.Fatalf("expected ErrNoSafeRule, got %v", err)
	}
}

func TestCompileRequiresSiteScope(t *testing.T) {
	_, err := NewRuleCompiler().Compile(php2shellExtraction(), Scope{})
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("expected ErrInvalid for global scope, got %v", err)
	}
	if _, err := NewRuleCompiler().Compile(php2shellExtraction(), Scope{SiteID: "global"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("expected ErrInvalid for literal global scope, got %v", err)
	}
}

func TestCompileIsDeterministic(t *testing.T) {
	first, err := NewRuleCompiler().Compile(php2shellExtraction(), Scope{SiteID: "site-a"})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	second, err := NewRuleCompiler().Compile(php2shellExtraction(), Scope{SiteID: "site-a"})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if first.Rule.ID != second.Rule.ID || first.Rule.Pattern != second.Rule.Pattern {
		t.Fatalf("compiler is not deterministic: %+v vs %+v", first.Rule, second.Rule)
	}
	other, err := NewRuleCompiler().Compile(php2shellExtraction(), Scope{SiteID: "site-b"})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if other.Rule.ID == first.Rule.ID {
		t.Fatal("rule id must depend on the scope")
	}
}

func TestNewCandidate(t *testing.T) {
	extraction := php2shellExtraction()
	compiled, err := NewRuleCompiler().Compile(extraction, Scope{SiteID: "site-a"})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	item := Item{
		ID:         "item-1",
		SourceID:   "feed-vendor",
		References: []string{"https://vendor.example.test/advisories/CVE-2026-12345"},
	}
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	candidate, err := NewCandidate(CandidateOptions{
		Item:       item,
		Extraction: extraction,
		Decision:   TrustDecision{Allowed: true, Trust: TrustVendor},
		Rule:       compiled,
		Now:        now,
	})
	if err != nil {
		t.Fatalf("new candidate: %v", err)
	}
	if candidate.State != CandidateDraft || candidate.Action != ActionLog {
		t.Fatalf("unexpected candidate rollout defaults: %+v", candidate)
	}
	if candidate.TTL != DefaultCandidateTTL {
		t.Fatalf("expected default TTL, got %s", candidate.TTL)
	}
	if !candidate.ExpiresAt().Equal(now.Add(DefaultCandidateTTL)) {
		t.Fatalf("unexpected expiry %s", candidate.ExpiresAt())
	}
	if candidate.Provenance.SourceTrust != TrustVendor || candidate.Provenance.ItemID != "item-1" {
		t.Fatalf("unexpected provenance: %+v", candidate.Provenance)
	}
	if _, err := DecodeCompiledRule([]byte(candidate.RuleJSON)); err != nil {
		t.Fatalf("candidate rule json is invalid: %v", err)
	}
	if err := ValidateCandidate(candidate); err != nil {
		t.Fatalf("candidate failed validation: %v", err)
	}
}

func TestNewCandidateRejectsQuarantinedDecision(t *testing.T) {
	_, err := NewCandidate(CandidateOptions{
		Item:     Item{ID: "item-1", SourceID: "feed-unknown"},
		Decision: TrustDecision{Quarantined: true, Reason: "unknown source"},
	})
	if !errors.Is(err, ErrQuarantined) {
		t.Fatalf("expected ErrQuarantined, got %v", err)
	}
}

func TestNewCandidateHasNoBlockByDefault(t *testing.T) {
	extraction := php2shellExtraction()
	compiled, err := NewRuleCompiler().Compile(extraction, Scope{SiteID: "site-a"})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	candidate, err := NewCandidate(CandidateOptions{
		Item:       Item{ID: "item-1", SourceID: "feed-vendor"},
		Extraction: extraction,
		Decision:   TrustDecision{Allowed: true, Trust: TrustVendor},
		Rule:       compiled,
	})
	if err != nil {
		t.Fatalf("new candidate: %v", err)
	}
	blocked := candidate
	blocked.Action = ActionBlock
	if err := ValidateCandidate(blocked); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "approval") {
		t.Fatalf("expected block-on-draft rejection, got %v", err)
	}
	approved := blocked
	approved.Provenance.Approved = true
	if err := ValidateCandidate(approved); !errors.Is(err, ErrInvalid) {
		t.Fatalf("expected block-on-draft state rejection, got %v", approved)
	}
}

func TestValidateCandidateRequiresTTLAndSpecificScope(t *testing.T) {
	extraction := php2shellExtraction()
	compiled, err := NewRuleCompiler().Compile(extraction, Scope{SiteID: "site-a"})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	candidate, err := NewCandidate(CandidateOptions{
		Item:       Item{ID: "item-1", SourceID: "feed-vendor"},
		Extraction: extraction,
		Decision:   TrustDecision{Allowed: true, Trust: TrustVendor},
		Rule:       compiled,
	})
	if err != nil {
		t.Fatalf("new candidate: %v", err)
	}
	withoutTTL := candidate
	withoutTTL.TTL = 0
	if err := ValidateCandidate(withoutTTL); !errors.Is(err, ErrInvalid) {
		t.Fatalf("expected missing TTL rejection, got %v", err)
	}
	global := compiled
	global.Scope = Scope{}
	if err := ValidateCompiledRule(global); !errors.Is(err, ErrInvalid) {
		t.Fatalf("expected global scope rejection, got %v", err)
	}
}

func TestValidateCandidateRejectsBroadRuleJSON(t *testing.T) {
	candidate := Candidate{
		ID:         "cand-1",
		ItemID:     "item-1",
		SiteID:     "site-a",
		Action:     ActionLog,
		State:      CandidateDraft,
		Confidence: 0.9,
		Provenance: Provenance{
			SourceID:    "feed-vendor",
			SourceTrust: TrustVendor,
			ItemID:      "item-1",
			Extractor:   "test",
		},
		TTL:       time.Hour,
		CreatedAt: time.Now().UTC(),
		RuleJSON:  `{"rule":{"id":"bad","name":"bad","pattern":".*","location":"body","action":"log","severity":"medium","enabled":false,"priority":200},"scope":{"site_id":"site-a"}}`,
	}
	err := ValidateCandidate(candidate)
	if !errors.Is(err, ErrBroadRule) {
		t.Fatalf("expected ErrBroadRule, got %v", err)
	}
}

func TestRuleJSONRoundTrip(t *testing.T) {
	extraction := php2shellExtraction()
	compiled, err := NewRuleCompiler().Compile(extraction, Scope{SiteID: "site-a"})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	payload, err := json.Marshal(compiled)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	decoded, err := DecodeCompiledRule(payload)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded.Rule.Pattern != compiled.Rule.Pattern || decoded.Scope.SiteID != "site-a" {
		t.Fatalf("round trip mismatch: %+v vs %+v", decoded, compiled)
	}
}

func TestExtractorFunc(t *testing.T) {
	called := false
	extractor := ExtractorFunc(func(context.Context, Item, Document) (Extraction, error) {
		called = true
		return Extraction{CVEIDs: []string{"CVE-2026-12345"}, Confidence: 0.5}, nil
	})
	if _, err := extractor.Extract(context.Background(), Item{}, Document{}); err != nil {
		t.Fatalf("extract: %v", err)
	}
	if !called {
		t.Fatal("extractor function was not called")
	}
}
