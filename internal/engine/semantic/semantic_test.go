package semantic

import (
	"bytes"
	"context"
	"net/http"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

func TestSQLDetectorBlocksClassicPayload(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "/items?id=1%27%20OR%20%271%27%3D%271", nil)
	reqCtx, err := engine.NewRequestContext(req, "default")
	if err != nil {
		t.Fatal(err)
	}
	result, err := NewSQLDetector("block").Detect(context.Background(), reqCtx)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || !result.Detected || result.Action != engine.ActionBlock {
		t.Fatalf("expected SQLi block, got %+v", result)
	}
}

func TestSQLDetectorBlocksFunctionBasedPayloads(t *testing.T) {
	cases := []string{
		"/search?q=1%20and%20extractvalue(1,concat(0x7e,(select%20database()),0x7e))",
		"/login?u=admin'%3Bselect%20pg_sleep(5)--",
		"/search?q=1%20or%20char(49)%3Dchar(49)",
	}
	for _, target := range cases {
		t.Run(target, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodGet, target, nil)
			reqCtx, err := engine.NewRequestContext(req, "default")
			if err != nil {
				t.Fatal(err)
			}
			result, err := NewSQLDetector("block").Detect(context.Background(), reqCtx)
			if err != nil {
				t.Fatal(err)
			}
			if result == nil || !result.Detected || result.Action != engine.ActionBlock {
				t.Fatalf("expected SQLi block, got %+v", result)
			}
		})
	}
}

func TestSQLDetectorKeepsBenignDocumentationClean(t *testing.T) {
	req, _ := http.NewRequest(http.MethodPost, "/docs", bytes.NewBufferString(`{"text":"The char() and concat() SQL functions are documented here."}`))
	req.Header.Set("Content-Type", "application/json")
	reqCtx, err := engine.NewRequestContext(req, "default")
	if err != nil {
		t.Fatal(err)
	}
	result, err := NewSQLDetector("block").Detect(context.Background(), reqCtx)
	if err != nil {
		t.Fatal(err)
	}
	if result != nil {
		t.Fatalf("expected benign SQL documentation to pass, got %+v", result)
	}
}

func TestAnalyzerFollowsStagedSemanticFlow(t *testing.T) {
	req, _ := http.NewRequest(http.MethodPost, "/api/search", bytes.NewBufferString(`{"filter":"JTI3JTIwb3IlMjAxJTNEMQ=="}`))
	req.Header.Set("Content-Type", "application/json")
	reqCtx, err := engine.NewRequestContext(req, "default")
	if err != nil {
		t.Fatal(err)
	}
	result, err := NewAnalyzer("block", "sqli").Detect(context.Background(), reqCtx)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || !result.Detected || result.Category != "sqli" {
		t.Fatalf("expected staged SQLi detection, got %+v", result)
	}
	report, ok := reqCtx.Metadata["semantic_analysis"].(AnalysisReport)
	if !ok || len(report.Inputs) == 0 || len(report.Hits) == 0 {
		t.Fatalf("expected semantic analysis report, got %+v", reqCtx.Metadata["semantic_analysis"])
	}
	if report.Hits[0].Syntax == "" || report.Hits[0].Semantics == "" {
		t.Fatalf("expected syntax and semantic evidence, got %+v", report.Hits[0])
	}
}

func TestAnalyzerUsesHeaderAndBodyInputs(t *testing.T) {
	req, _ := http.NewRequest(http.MethodPost, "/submit", bytes.NewBufferString("name=alice&comment=%3Csvg%20onload%3Dalert(1)%3E"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Forwarded-Host", "http://169.254.169.254/latest/meta-data")
	reqCtx, err := engine.NewRequestContext(req, "default")
	if err != nil {
		t.Fatal(err)
	}
	result, err := NewAnalyzer("block", "xss", "ssrf").Detect(context.Background(), reqCtx)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || !result.Detected {
		t.Fatalf("expected semantic detection, got %+v", result)
	}
	report := reqCtx.Metadata["semantic_analysis"].(AnalysisReport)
	var sawHeader, sawBody bool
	for _, input := range report.Inputs {
		if input.Source == "header" {
			sawHeader = true
		}
		if input.Source == "body.form" {
			sawBody = true
		}
	}
	if !sawHeader || !sawBody {
		t.Fatalf("expected header and form inputs in report: %+v", report.Inputs)
	}
}

func TestAnalyzerDoesNotFlagBenignText(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "/docs?q=selecting%20a%20theme%20from%20the%20menu", nil)
	reqCtx, err := engine.NewRequestContext(req, "default")
	if err != nil {
		t.Fatal(err)
	}
	result, err := NewAnalyzer("block", "sqli", "xss").Detect(context.Background(), reqCtx)
	if err != nil {
		t.Fatal(err)
	}
	if result != nil {
		t.Fatalf("expected benign text to pass, got %+v", result)
	}
}

func TestAnalyzerAgainstOpenWAFRegressionPayloads(t *testing.T) {
	// Payload shapes are derived from public OWASP CRS regression cases and LFI data files.
	cases := []struct {
		name        string
		method      string
		target      string
		contentType string
		body        string
		header      map[string]string
		category    string
	}{
		{name: "crs-sqli-tautology", method: http.MethodPost, target: "/post", contentType: "application/x-www-form-urlencoded", body: "var=1234 OR 1=1", category: "sqli"},
		{name: "crs-sqli-waitfor", method: http.MethodPost, target: "/post", contentType: "application/x-www-form-urlencoded", body: "var=foo')waitfor%20delay'0%3a0%3a5'--", category: "sqli"},
		{name: "crs-xss-namespace-script", method: http.MethodGet, target: `/get?body=%3Cx:script%20xmlns:x=%22http://www.w3.org/1999/xhtml%22%20src=%22data:,alert(1)%22%20/%3E`, category: "xss"},
		{name: "crs-xss-event-handler", method: http.MethodPost, target: "/post", contentType: "application/x-www-form-urlencoded", body: "foo=<xss onbeforehellfreezes%3Dalert(1)>", category: "xss"},
		{name: "crs-rce-qualified-perl", method: http.MethodPost, target: "/post", contentType: "application/x-www-form-urlencoded", body: "cmd=/usr/bin/perl -e 'print readline' /tmp/a", category: "rce"},
		{name: "crs-rce-shell-env", method: http.MethodGet, target: `/get?code=%24SHELL%20-c%20%22echo%20hi%22`, category: "rce"},
		{name: "crs-rce-bin-gunzip", method: http.MethodPost, target: "/post", contentType: "application/x-www-form-urlencoded", body: "cmd=/bin/gunzip -c /var/log/app.gz", category: "rce"},
		{name: "crs-lfi-cloud-secret", method: http.MethodGet, target: "/download?file=.aws/credentials", category: "lfi"},
		{name: "crs-lfi-wordpress-config", method: http.MethodGet, target: "/download?file=wp-config.php", category: "lfi"},
		{name: "crs-xss-user-agent", method: http.MethodGet, target: "/get", header: map[string]string{"User-Agent": `%3Cx:script%20xmlns:x=%22http://www.w3.org/1999/xhtml%22%20src=%22data:,alert(1)%22%20/%3E`}, category: "xss"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest(tc.method, tc.target, bytes.NewBufferString(tc.body))
			if tc.contentType != "" {
				req.Header.Set("Content-Type", tc.contentType)
			}
			for key, value := range tc.header {
				req.Header.Set(key, value)
			}
			reqCtx, err := engine.NewRequestContext(req, "default")
			if err != nil {
				t.Fatal(err)
			}
			result, err := NewAnalyzer("block").Detect(context.Background(), reqCtx)
			if err != nil {
				t.Fatal(err)
			}
			if result == nil || !result.Detected || result.Category != tc.category {
				t.Fatalf("expected %s detection, got %+v", tc.category, result)
			}
		})
	}
}

func TestAnalyzerKeepsOpenWAFNegativeCasesClean(t *testing.T) {
	cases := []struct {
		name   string
		body   string
		target string
	}{
		{name: "zip-word", target: "/post", body: "sentence=The zip on my coat is stuck"},
		{name: "bare-command-words", target: "/post", body: "note=dont match commands that are not fully qualified like bash python and perl"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodPost, tc.target, bytes.NewBufferString(tc.body))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			reqCtx, err := engine.NewRequestContext(req, "default")
			if err != nil {
				t.Fatal(err)
			}
			result, err := NewAnalyzer("block").Detect(context.Background(), reqCtx)
			if err != nil {
				t.Fatal(err)
			}
			if result != nil {
				t.Fatalf("expected benign open-WAF negative case to pass, got %+v", result)
			}
		})
	}
}

func TestXSSDetectorBlocksScriptPayload(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "/search?q=%3Cscript%3Ealert(1)%3C/script%3E", nil)
	reqCtx, err := engine.NewRequestContext(req, "default")
	if err != nil {
		t.Fatal(err)
	}
	result, err := NewXSSDetector("block").Detect(context.Background(), reqCtx)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || !result.Detected || result.Category != "xss" {
		t.Fatalf("expected XSS detection, got %+v", result)
	}
}

func TestXSSDetectorBlocksObfuscatedBrowserContexts(t *testing.T) {
	cases := []string{
		"/?next=%3Ca%20href%3Djava%00script%3Aalert(1)%3Ego%3C%2Fa%3E",
		"/?q=%26lt%3Bimg%20src%3Dx%20onerror%3Dalert(1)%26gt%3B",
	}
	for _, target := range cases {
		t.Run(target, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodGet, target, nil)
			reqCtx, err := engine.NewRequestContext(req, "default")
			if err != nil {
				t.Fatal(err)
			}
			result, err := NewXSSDetector("block").Detect(context.Background(), reqCtx)
			if err != nil {
				t.Fatal(err)
			}
			if result == nil || !result.Detected || result.Category != "xss" {
				t.Fatalf("expected XSS detection, got %+v", result)
			}
		})
	}
}

func TestXSSDetectorKeepsBenignDocumentationClean(t *testing.T) {
	req, _ := http.NewRequest(http.MethodPost, "/docs", bytes.NewBufferString(`{"text":"This page explains why javascript: URLs are dangerous, but includes no tag attribute."}`))
	req.Header.Set("Content-Type", "application/json")
	reqCtx, err := engine.NewRequestContext(req, "default")
	if err != nil {
		t.Fatal(err)
	}
	result, err := NewXSSDetector("block").Detect(context.Background(), reqCtx)
	if err != nil {
		t.Fatal(err)
	}
	if result != nil {
		t.Fatalf("expected benign XSS documentation to pass, got %+v", result)
	}
}

func TestPhase2SemanticDetectors(t *testing.T) {
	cases := []struct {
		name     string
		target   string
		detector engine.Detector
		category string
	}{
		{name: "rce", target: "/run?cmd=1%3Bcat%20/etc/passwd", detector: NewRCEDetector("block"), category: "rce"},
		{name: "lfi", target: "/download?file=..%2F..%2F..%2Fetc%2Fpasswd", detector: NewLFIDetector("block"), category: "lfi"},
		{name: "xxe", target: "/xml?body=%3C!DOCTYPE%20foo%20%5B%3C!ENTITY%20xxe%20SYSTEM%20%22file%3A///etc/passwd%22%3E%5D%3E", detector: NewXXEDetector("block"), category: "xxe"},
		{name: "ssrf", target: "/fetch?url=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data", detector: NewSSRFDetector("block"), category: "ssrf"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodGet, tc.target, nil)
			reqCtx, err := engine.NewRequestContext(req, "default")
			if err != nil {
				t.Fatal(err)
			}
			result, err := tc.detector.Detect(context.Background(), reqCtx)
			if err != nil {
				t.Fatal(err)
			}
			if result == nil || !result.Detected || result.Category != tc.category {
				t.Fatalf("expected %s detection, got %+v", tc.category, result)
			}
		})
	}
}
