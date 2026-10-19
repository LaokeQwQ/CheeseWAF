package rules

import (
	"bytes"
	"context"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

func TestEngineMatchesCustomRule(t *testing.T) {
	compiled, err := FromConfig([]config.CustomRuleConfig{{
		ID: "admin", Name: "Admin Probe", Pattern: `(?i)/admin`, Location: "uri", Action: "block", Severity: "high", Enabled: true,
	}})
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodGet, "/admin", nil)
	reqCtx, err := engine.NewRequestContext(req, "default")
	if err != nil {
		t.Fatal(err)
	}
	result, err := New(compiled).Detect(context.Background(), reqCtx)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || !result.Detected || result.Action != engine.ActionBlock {
		t.Fatalf("expected custom rule block, got %+v", result)
	}
}

func TestFromConfigExtractsSafeLiteralPrefix(t *testing.T) {
	compiled, err := FromConfig([]config.CustomRuleConfig{{
		ID: "prefix", Name: "prefix", Pattern: `^/admin`, Location: "uri", Action: "block", Severity: "high", Enabled: true,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(compiled) != 1 || compiled[0].literalPrefix != "/admin" {
		t.Fatalf("literal prefix = %q, want /admin", compiled[0].literalPrefix)
	}
}

func TestEngineSeparatesURIAndQueryLocations(t *testing.T) {
	compiled, err := FromConfig([]config.CustomRuleConfig{
		{ID: "uri", Name: "URI", Pattern: `debug=true`, Location: "uri", Action: "block", Severity: "high", Enabled: true},
		{ID: "query", Name: "Query", Pattern: `debug=true`, Location: "query", Action: "challenge", Severity: "medium", Enabled: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodGet, "/search?debug=true", nil)
	if err != nil {
		t.Fatal(err)
	}
	reqCtx, err := engine.NewRequestContext(req, "default")
	if err != nil {
		t.Fatal(err)
	}
	result, err := New(compiled).Detect(context.Background(), reqCtx)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || result.DetectorID != "rules.custom.query" || result.Action != engine.ActionChallenge {
		t.Fatalf("query-only input must match the query rule: %+v", result)
	}
}

func TestEngineARGSRuleMatchesQueryAndURLEncodedFormValues(t *testing.T) {
	compiled, err := FromConfig([]config.CustomRuleConfig{{
		ID: "args", Name: "ARGS", Pattern: `(?i)union\s+select`, Location: "args", Action: "block", Severity: "high", Enabled: true,
	}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		url  string
		body string
	}{
		{name: "query", url: "/search?q=union+select"},
		{name: "form", url: "/search", body: "q=union+select"},
		{name: "query and form", url: "/search?q=safe", body: "q=union+select"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodPost, tc.url, strings.NewReader(tc.body))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			reqCtx, err := engine.NewRequestContext(req, "default")
			if err != nil {
				t.Fatal(err)
			}
			result, err := New(compiled).Detect(context.Background(), reqCtx)
			if err != nil || result == nil || result.Action != engine.ActionBlock {
				t.Fatalf("ARGS should match argument value: result=%+v err=%v", result, err)
			}
		})
	}
}

func TestEngineARGSRuleMatchesMultipartFieldsButNotFileNamesOrContent(t *testing.T) {
	compiled, err := FromConfig([]config.CustomRuleConfig{{
		ID: "args", Name: "ARGS", Pattern: `(?i)union\s+select`, Location: "args", Action: "block", Severity: "high", Enabled: true,
	}})
	if err != nil {
		t.Fatal(err)
	}
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	if err := writer.WriteField("comment", "union select"); err != nil {
		t.Fatal(err)
	}
	file, err := writer.CreateFormFile("upload", "union select.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(file, "safe file content"); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, "/upload?q=safe", bytes.NewReader(body.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	reqCtx, err := engine.NewRequestContext(req, "default")
	if err != nil {
		t.Fatal(err)
	}
	result, err := New(compiled).Detect(context.Background(), reqCtx)
	if err != nil || result == nil || result.Action != engine.ActionBlock {
		t.Fatalf("ARGS should match multipart field values: result=%+v err=%v", result, err)
	}

	// A filename or opaque file body is not an ARGS value by ModSecurity semantics.
	for _, value := range []string{"union select.txt", "safe file content"} {
		var fileBody bytes.Buffer
		fileWriter := multipart.NewWriter(&fileBody)
		file, err := fileWriter.CreateFormFile("upload", "safe.txt")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(file, value); err != nil {
			t.Fatal(err)
		}
		if err := fileWriter.Close(); err != nil {
			t.Fatal(err)
		}
		fileReq, err := http.NewRequest(http.MethodPost, "/upload", bytes.NewReader(fileBody.Bytes()))
		if err != nil {
			t.Fatal(err)
		}
		fileReq.Header.Set("Content-Type", fileWriter.FormDataContentType())
		fileCtx, err := engine.NewRequestContext(fileReq, "default")
		if err != nil {
			t.Fatal(err)
		}
		got, err := New(compiled).Detect(context.Background(), fileCtx)
		if err != nil || got != nil {
			t.Fatalf("ARGS must not match uploaded file data %q: result=%+v err=%v", value, got, err)
		}
	}
}

func TestARGSMultipartFieldLimitReportsIncomplete(t *testing.T) {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	for i := 0; i <= maxArgumentFields; i++ {
		if err := writer.WriteField("field", "value"); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, "/upload", bytes.NewReader(body.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	reqCtx, err := engine.NewRequestContext(req, "default")
	if err != nil {
		t.Fatal(err)
	}
	views := new(requestViews)
	_ = views.argumentValues(reqCtx)
	var incomplete interface {
		AnalysisIncomplete() bool
		IncompleteReason() string
	}
	if !errors.As(views.err, &incomplete) || !incomplete.AnalysisIncomplete() || incomplete.IncompleteReason() != "custom_rule_multipart_limit" {
		t.Fatalf("multipart argument cap should be reported as incomplete, got %v", views.err)
	}
}

func TestEngineURIRulesUseCanonicalRequestPath(t *testing.T) {
	compiled, err := FromConfig([]config.CustomRuleConfig{{
		ID: "admin", Name: "Admin", Pattern: `^/admin`, Location: "uri", Action: "block", Severity: "high", Enabled: true,
	}})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodGet, "http://example.test/public/../admin", nil)
	if err != nil {
		t.Fatal(err)
	}
	reqCtx, err := engine.NewRequestContext(req, "default")
	if err != nil {
		t.Fatal(err)
	}
	result, err := New(compiled).Detect(context.Background(), reqCtx)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || !result.Detected || result.Action != engine.ActionBlock {
		t.Fatalf("canonical URI rule did not match path traversal form: %+v (normalized=%q)", result, reqCtx.NormalizedPath)
	}
}

func TestEngineRequestURIRulesIncludeQuery(t *testing.T) {
	compiled, err := FromConfig([]config.CustomRuleConfig{{
		ID: "target", Name: "target", Pattern: `\A/search\?debug=true\z`, Location: "request_uri", Action: "block", Severity: "high", Enabled: true,
	}})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodGet, "/search?debug=true", nil)
	if err != nil {
		t.Fatal(err)
	}
	reqCtx, err := engine.NewRequestContext(req, "default")
	if err != nil {
		t.Fatal(err)
	}
	result, err := New(compiled).Detect(context.Background(), reqCtx)
	if err != nil || result == nil || result.Action != engine.ActionBlock {
		t.Fatalf("request URI rule did not match full request target: result=%+v err=%v", result, err)
	}
}

func TestEngineMatchesEncodedApplicationViews(t *testing.T) {
	cases := []struct {
		name     string
		location string
		setup    func(*http.Request)
	}{
		{name: "query", location: "query", setup: func(r *http.Request) { r.URL.RawQuery = "q=%2575nion%2520select" }},
		{name: "body form", location: "body", setup: func(r *http.Request) {
			r.Method = http.MethodPost
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}},
		{name: "cookie", location: "cookie", setup: func(r *http.Request) { r.Header.Set("Cookie", "q=%75nion%20select") }},
		{name: "header", location: "header", setup: func(r *http.Request) { r.Header.Set("X-Probe", "%75nion%20select") }},
		{name: "header HTML entity", location: "header", setup: func(r *http.Request) { r.Header.Set("X-Probe", "&#x75;nion&#32;select") }},
		{name: "cookie double encoding", location: "cookie", setup: func(r *http.Request) { r.Header.Set("Cookie", "q=%2575nion%2520select") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			compiled, err := FromConfig([]config.CustomRuleConfig{{
				ID: tc.name, Name: tc.name, Pattern: `(?i)union\s+select`, Location: tc.location, Action: "block", Severity: "high", Enabled: true,
			}})
			if err != nil {
				t.Fatal(err)
			}
			var body io.Reader
			if tc.location == "body" {
				body = strings.NewReader("q=%2575nion%2520select")
			}
			req, err := http.NewRequest(http.MethodGet, "http://example.test/search", body)
			if err != nil {
				t.Fatal(err)
			}
			tc.setup(req)
			reqCtx, err := engine.NewRequestContext(req, "default")
			if err != nil {
				t.Fatal(err)
			}
			result, err := New(compiled).Detect(context.Background(), reqCtx)
			if err != nil {
				t.Fatal(err)
			}
			if result == nil || !result.Detected {
				t.Fatalf("encoded application value was not matched: %+v", result)
			}
		})
	}
}

func TestEngineMatchesCustomRuleAfterLegacyBodyCutoff(t *testing.T) {
	const needle = "LATE_BODY_RULE_MATCH"
	body := strings.Repeat("x", engine.MaxDecodedBytes+128) + needle
	compiled, err := FromConfig([]config.CustomRuleConfig{{
		ID: "late", Name: "Late body match", Pattern: needle, Location: "body", Action: "block", Severity: "high", Enabled: true,
	}})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, "http://example.test/upload", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	reqCtx, err := engine.NewRequestContextWithLimits(req, "default", nil, int64(len(body)))
	if err != nil {
		t.Fatal(err)
	}
	result, err := New(compiled).Detect(context.Background(), reqCtx)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || !result.Detected || result.Action != engine.ActionBlock {
		t.Fatalf("custom body rule missed value after old 2MiB cutoff: %+v", result)
	}
}

func TestEngineMarksMalformedJSONRuleViewIncomplete(t *testing.T) {
	compiled, err := FromConfig([]config.CustomRuleConfig{{
		ID: "miss", Name: "never matches", Pattern: `NEVER_MATCH`, Location: "body", Action: "block", Severity: "high", Enabled: true,
	}})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, "http://example.test/json", strings.NewReader(`{"value":`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	reqCtx, err := engine.NewRequestContext(req, "default")
	if err != nil {
		t.Fatal(err)
	}
	_, err = New(compiled).Detect(context.Background(), reqCtx)
	var incomplete interface{ AnalysisIncomplete() bool }
	if !errors.As(err, &incomplete) || !incomplete.AnalysisIncomplete() {
		t.Fatalf("error=%v, want typed incomplete inspection", err)
	}
}

func TestEngineBlockBeatsEarlierLogMatch(t *testing.T) {
	compiled, err := FromConfig([]config.CustomRuleConfig{
		{ID: "log", Name: "Log", Pattern: `probe`, Location: "uri", Action: "log", Severity: "low", Enabled: true, Priority: 10},
		{ID: "block", Name: "Block", Pattern: `probe`, Location: "uri", Action: "block", Severity: "high", Enabled: true, Priority: 20},
	})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodGet, "/probe", nil)
	if err != nil {
		t.Fatal(err)
	}
	reqCtx, err := engine.NewRequestContext(req, "default")
	if err != nil {
		t.Fatal(err)
	}
	result, err := New(compiled).Detect(context.Background(), reqCtx)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || result.DetectorID != "rules.custom.block" || result.Action != engine.ActionBlock {
		t.Fatalf("block rule must beat an earlier log rule: %+v", result)
	}
}

func TestEngineRedactsHeaderAndCookieMatchPayloads(t *testing.T) {
	for _, tc := range []struct {
		name     string
		location string
		setup    func(*http.Request)
	}{
		{
			name:     "header",
			location: "header",
			setup: func(req *http.Request) {
				req.Header.Set("Authorization", "Bearer secret-token")
			},
		},
		{
			name:     "cookie",
			location: "cookie",
			setup: func(req *http.Request) {
				req.AddCookie(&http.Cookie{Name: "session", Value: "secret-token"})
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			compiled, err := FromConfig([]config.CustomRuleConfig{{
				ID: tc.name, Name: tc.name, Pattern: `secret-token`, Location: tc.location, Action: "block", Severity: "high", Enabled: true,
			}})
			if err != nil {
				t.Fatal(err)
			}
			req, err := http.NewRequest(http.MethodGet, "/", nil)
			if err != nil {
				t.Fatal(err)
			}
			tc.setup(req)
			reqCtx, err := engine.NewRequestContext(req, "default")
			if err != nil {
				t.Fatal(err)
			}
			result, err := New(compiled).Detect(context.Background(), reqCtx)
			if err != nil {
				t.Fatal(err)
			}
			if result == nil || !result.Detected {
				t.Fatalf("expected a %s match, got %+v", tc.location, result)
			}
			if strings.Contains(result.Payload, "secret-token") || strings.Contains(result.Payload, "Authorization") {
				t.Fatalf("sensitive %s value leaked into payload: %q", tc.location, result.Payload)
			}
		})
	}
}

func TestEngineClipsLongBodyPayload(t *testing.T) {
	needle := "EVIL_NEEDLE_TOKEN"
	// 4KB body with needle near the middle so a window around the match is required.
	prefix := strings.Repeat("A", 2000)
	suffix := strings.Repeat("B", 2000)
	body := prefix + needle + suffix

	compiled, err := FromConfig([]config.CustomRuleConfig{{
		ID: "long-body", Name: "Long Body Needle", Pattern: needle, Location: "body", Action: "block", Severity: "high", Enabled: true,
	}})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, "/submit", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "text/plain")
	reqCtx, err := engine.NewRequestContext(req, "default")
	if err != nil {
		t.Fatal(err)
	}
	result, err := New(compiled).Detect(context.Background(), reqCtx)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || !result.Detected {
		t.Fatalf("expected detection, got %+v", result)
	}
	if len(result.Payload) > 512 {
		t.Fatalf("Payload length %d exceeds 512-byte clip limit", len(result.Payload))
	}
	if !strings.Contains(result.Payload, needle) {
		t.Fatalf("clipped Payload lost match needle: %q", result.Payload)
	}
}

func TestFromStorageCompilesSiteCustomRules(t *testing.T) {
	compiled, err := FromStorage([]storage.Rule{{
		ID: "admin", SiteID: "default", Name: "Admin Probe", Pattern: `(?i)/admin`, Location: "uri", Action: "block", Severity: "high", Enabled: true,
	}})
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodGet, "/admin", nil)
	reqCtx, err := engine.NewRequestContext(req, "default")
	if err != nil {
		t.Fatal(err)
	}
	result, err := New(compiled).Detect(context.Background(), reqCtx)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || !result.Detected || result.Action != engine.ActionBlock {
		t.Fatalf("expected custom rule block from storage, got %+v", result)
	}
}
