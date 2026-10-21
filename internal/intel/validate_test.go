package intel

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestValidatePatternBroadnessRejectsBroadPatterns(t *testing.T) {
	tests := []string{
		"",
		"   ",
		".*",
		"(?s).*",
		".+",
		"(?:.*)",
		"^.*$",
		`\S*`,
		`[^x]*`,
		".{100,}",
		"(?s).{50,}",
		"()",
		"(a|)",
	}
	for _, pattern := range tests {
		t.Run(pattern, func(t *testing.T) {
			if err := ValidatePatternBroadness(pattern); !errors.Is(err, ErrBroadRule) {
				t.Fatalf("expected ErrBroadRule for %q, got %v", pattern, err)
			}
		})
	}
}

func TestValidatePatternBroadnessAcceptsMinimalPatterns(t *testing.T) {
	tests := []string{
		`(?i)content-disposition:[^\r\n]{0,256}\bname="PHP_SESSION_UPLOAD_PROGRESS"`,
		`(?i)(?:^|&)PHP_SESSION_UPLOAD_PROGRESS=`,
		`(?i)(?:<\?php|O:[0-9]{1,4}:"[A-Za-z_\\][A-Za-z0-9_\\]{0,64}")`,
		`(?i)(?:^|;\s*)PHPSESSID=[^;\s]{200,}`,
		`(?i)(?:^|[&;]|name=")files(?:\[[^\]\r\n]{0,32}\]){3,}`,
		`(?i)\.php$`,
	}
	for _, pattern := range tests {
		t.Run(pattern, func(t *testing.T) {
			if err := ValidatePatternBroadness(pattern); err != nil {
				t.Fatalf("expected %q to pass, got %v", pattern, err)
			}
		})
	}
}

func TestValidateExtraction(t *testing.T) {
	valid := php2shellExtraction()
	if err := ValidateExtraction(valid); err != nil {
		t.Fatalf("expected valid extraction, got %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*Extraction)
	}{
		{name: "zero confidence", mutate: func(e *Extraction) { e.Confidence = 0 }},
		{name: "confidence above one", mutate: func(e *Extraction) { e.Confidence = 1.01 }},
		{name: "bad cve", mutate: func(e *Extraction) { e.CVEIDs = []string{"CVE-26-1"} }},
		{name: "duplicate cve", mutate: func(e *Extraction) { e.CVEIDs = []string{"CVE-2026-1234", "cve-2026-1234"} }},
		{name: "empty product", mutate: func(e *Extraction) { e.Products = []string{" "} }},
		{name: "bad method", mutate: func(e *Extraction) { e.Request.Method = "TRACE" }},
		{name: "relative path", mutate: func(e *Extraction) { e.Request.Path = "upload.php" }},
		{name: "path with query", mutate: func(e *Extraction) { e.Request.Path = "/upload.php?x=1" }},
		{name: "bad parameter", mutate: func(e *Extraction) { e.Request.ParameterNames = []string{"bad name"} }},
		{name: "control marker", mutate: func(e *Extraction) { e.Request.Markers = []string{"a\nb"} }},
		{name: "bad session parameter", mutate: func(e *Extraction) { e.Request.SessionParameter = "PHP SESSID" }},
		{name: "bad status", mutate: func(e *Extraction) { e.Response.StatusCodes = []int{99} }},
		{name: "bad header", mutate: func(e *Extraction) { e.Response.HeaderNames = []string{"bad header"} }},
		{name: "bad reference scheme", mutate: func(e *Extraction) { e.References = []string{"javascript:alert(1)"} }},
		{name: "private reference", mutate: func(e *Extraction) { e.References = []string{"http://127.0.0.1/advisory"} }},
		{name: "too many references", mutate: func(e *Extraction) {
			e.References = make([]string, MaxExtractionReferences+1)
			for i := range e.References {
				e.References[i] = fmt.Sprintf("https://example.test/advisory/%d", i)
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			extraction := valid
			extraction.CVEIDs = append([]string(nil), valid.CVEIDs...)
			extraction.Request.ParameterNames = append([]string(nil), valid.Request.ParameterNames...)
			extraction.Request.Markers = append([]string(nil), valid.Request.Markers...)
			extraction.Response.StatusCodes = append([]int(nil), valid.Response.StatusCodes...)
			extraction.Response.HeaderNames = append([]string(nil), valid.Response.HeaderNames...)
			extraction.References = append([]string(nil), valid.References...)
			test.mutate(&extraction)
			if err := ValidateExtraction(extraction); !errors.Is(err, ErrInvalid) {
				t.Fatalf("expected ErrInvalid, got %v", err)
			}
		})
	}
}

func TestValidateExtractionAllowsEmptyOptionalFields(t *testing.T) {
	extraction := Extraction{Confidence: 0.5}
	if err := ValidateExtraction(extraction); err != nil {
		t.Fatalf("expected minimal extraction to validate, got %v", err)
	}
}

func TestDecodeExtraction(t *testing.T) {
	extraction, err := DecodeExtraction([]byte(`{"confidence":0.5,"extra_metadata":{"model":"test"}}`))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if extraction.Confidence != 0.5 {
		t.Fatalf("unexpected confidence %v", extraction.Confidence)
	}
	if _, err := DecodeExtraction([]byte(`{"confidence":0.5}{"confidence":0.6}`)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("expected trailing json rejection, got %v", err)
	}
	if _, err := DecodeExtraction([]byte(`not json`)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("expected malformed json rejection, got %v", err)
	}
}

func TestScopeValidate(t *testing.T) {
	valid := []Scope{
		{SiteID: "site-a"},
		{SiteID: "site-a", PathPrefix: "/upload"},
		{SiteID: "site-a", Methods: []string{"post", "PUT"}},
	}
	for _, scope := range valid {
		if err := scope.Validate(); err != nil {
			t.Fatalf("expected %+v to validate, got %v", scope, err)
		}
	}
	invalid := []Scope{
		{},
		{SiteID: "*"},
		{SiteID: "global"},
		{SiteID: "all"},
		{SiteID: "site-a", PathPrefix: "/"},
		{SiteID: "site-a", PathPrefix: "upload"},
		{SiteID: "site-a", Methods: []string{"TRACE"}},
		{SiteID: "site-a", Methods: []string{"POST", "post"}},
	}
	for _, scope := range invalid {
		if err := scope.Validate(); !errors.Is(err, ErrInvalid) {
			t.Fatalf("expected %+v to fail, got %v", scope, err)
		}
	}
}

func TestValidateSource(t *testing.T) {
	if err := ValidateSource(Source{ID: "feed-a", Type: "rss", URL: "https://example.test/feed", Trust: TrustVendor, Enabled: true}); err != nil {
		t.Fatalf("expected valid source, got %v", err)
	}
	if err := ValidateSource(Source{ID: "manual-a", Type: "manual", Trust: TrustOfficial, Enabled: true}); err != nil {
		t.Fatalf("expected manual source without url, got %v", err)
	}
	invalid := []Source{
		{ID: "", Type: "rss", URL: "https://example.test/feed"},
		{ID: "feed-a", Type: "unknown", URL: "https://example.test/feed"},
		{ID: "feed-a", Type: "rss", URL: "file:///etc/passwd"},
		{ID: "feed-a", Type: "rss", URL: "http://127.0.0.1/feed"},
		{ID: "feed-a", Type: "rss", URL: ""},
		{ID: "feed-a", Type: "rss", URL: "https://example.test/feed", Trust: TrustLevel("trusted")},
	}
	for _, source := range invalid {
		if err := ValidateSource(source); !errors.Is(err, ErrInvalid) {
			t.Fatalf("expected %+v to fail, got %v", source, err)
		}
	}
}

func TestValidateCompiledRuleRejectsEnabledRule(t *testing.T) {
	compiled, err := NewRuleCompiler().Compile(php2shellExtraction(), Scope{SiteID: "site-a"})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	compiled.Rule.Enabled = true
	if err := ValidateCompiledRule(compiled); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("expected disabled-rule rejection, got %v", err)
	}
}

func TestDecodeCandidate(t *testing.T) {
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
	payload, err := json.Marshal(candidate)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	decoded, err := DecodeCandidate(payload)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded.ID != candidate.ID || decoded.RuleJSON != candidate.RuleJSON {
		t.Fatalf("decode mismatch: %+v vs %+v", decoded, candidate)
	}
	candidate.TTL = 0
	payload, err = json.Marshal(candidate)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := DecodeCandidate(payload); !errors.Is(err, ErrInvalid) {
		t.Fatalf("expected missing TTL rejection, got %v", err)
	}
}
