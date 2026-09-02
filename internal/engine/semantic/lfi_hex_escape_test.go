package semantic

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

func TestLFITextualHexNullByteEscape(t *testing.T) {
	// The request uses textual hex bytes for dots and a slash, with NUL
	// separators. Query parsing decodes %00 before semantic candidates are built.
	payload := `0x2e.%000x2f0x2e.%00/WINDOWS/win.ini`
	target := "/get?foo=" + url.QueryEscape(payload)

	a := NewAnalyzer("block", 2)
	got := detectOnTarget(t, a, "GET", target, "", "")
	if got == nil || !got.Detected || got.Category != "lfi" {
		t.Fatalf("expected analyzer LFI detection, got %+v", got)
	}
	if !strings.Contains(got.Payload, payload) {
		t.Fatalf("hit payload=%q does not retain original payload %q", got.Payload, payload)
	}

	req := readinessRequest(t, "GET", target, "", "")
	reqCtx, err := engine.NewRequestContext(req, "default")
	if err != nil {
		t.Fatal(err)
	}
	standalone, err := NewLFIDetector("block").Detect(context.Background(), reqCtx)
	if err != nil {
		t.Fatal(err)
	}
	if standalone == nil || !standalone.Detected || standalone.Category != "lfi" {
		t.Fatalf("expected standalone LFI detection, got %+v", standalone)
	}
	if !strings.Contains(standalone.Payload, "0x2e.") || !strings.Contains(standalone.Payload, "win.ini") {
		t.Fatalf("standalone payload=%q does not retain the original path markers", standalone.Payload)
	}
}

func TestUTF16ProbeFastGatePreservesDetectionShapes(t *testing.T) {
	plain := "ordinary printable request text"
	if looksLikeUTF16String(plain) {
		t.Fatal("plain ASCII was incorrectly classified as UTF-16-like")
	}
	utf16Text := string(utf16LEXML(`<?xml version="1.0"?><!DOCTYPE foo><foo/>`))
	if !looksLikeUTF16String(utf16Text) {
		t.Fatal("UTF-16 XML without a BOM was not classified as UTF-16-like")
	}
	decoded, ok := decodeUTF16Payload(utf16Text)
	if !ok || !strings.Contains(strings.ToLower(decoded), "<!doctype") {
		t.Fatalf("UTF-16 XML was not decoded: ok=%t value=%q", ok, decoded)
	}
	if decoded, ok := decodeUTF16Payload(plain); ok || decoded != "" {
		t.Fatalf("plain text unexpectedly decoded as UTF-16: ok=%t value=%q", ok, decoded)
	}
}

func TestLFITextualHexEscapeGate(t *testing.T) {
	positive := []struct {
		name, raw, source, field string
	}{
		{"generic-nul-sensitive", `0x2e.%000x2f0x2e.%00/WINDOWS/win.ini`, "query", "foo"},
		{"generic-nul-encoded-target", `0x2e0x2e0x2f%00%2fetc%2fpasswd`, "query", "foo"},
		{"explicit-file-field", `0x2e0x2e0x2fconfig.txt`, "query", "file"},
		{"explicit-filepath-field", `0x2e0x2e0x2fconfig.txt`, "body.json", "filePath"},
		{"uri-path", `0x2e0x2e0x2fnotes.txt`, "uri", "path"},
	}
	for _, tc := range positive {
		t.Run(tc.name, func(t *testing.T) {
			folded, ok := foldLFIHexPathEscapes(tc.raw, tc.source, tc.field)
			if !ok || folded == tc.raw {
				t.Fatalf("foldLFIHexPathEscapes(%q, %q, %q) did not fold: %q, %v", tc.raw, tc.source, tc.field, folded, ok)
			}
			if !strings.Contains(folded, "..") || !strings.ContainsAny(folded, "/\\") {
				t.Fatalf("folded path=%q lacks traversal shape", folded)
			}
		})
	}

	negative := []struct {
		name, raw, source, field string
	}{
		{"single-dot-sql-hex", `select 0x2e, 0x2f`, "query", "q"},
		{"two-dot-sql-hex", `select 0x2e, 0x2e, 0x2f`, "query", "q"},
		{"generic-document-field", `0x2e0x2e0x2fnotes.txt`, "body.json", "document"},
		{"generic-config-field", `0x2e0x2e0x2fnotes.txt`, "body.json", "config"},
		{"prose-sensitive-without-boundary", `Documentation mentions 0x2e/0x2f and win.ini as an example.`, "query", "text"},
	}
	for _, tc := range negative {
		t.Run(tc.name, func(t *testing.T) {
			if folded, ok := foldLFIHexPathEscapes(tc.raw, tc.source, tc.field); ok || folded != tc.raw {
				t.Fatalf("ordinary value was folded: %q, %v", folded, ok)
			}
		})
	}
}

func TestLongCandidateSQLSignalsSurvivePrefilter(t *testing.T) {
	cases := []struct {
		name, payload string
	}{
		{"spaced-boolean", `1' OR 1 = 1--`},
		{"union-all-without-from", `1 UNION ALL SELECT password`},
		{"drop-table", `1; DROP TABLE users`},
		{"drop-table-tabbed", "1 DROP\tTABLE users"},
		{"drop-table-comment-bridged", "1/**/DROP TABLE users"},
		{"order-by", `1 ORDER BY 9`},
		{"order-by-newline", "1 ORDER\nBY 9"},
		{"order-by-comment-bridged", "1/**/ORDER BY 9"},
		{"case-when", `1 CASE WHEN 1=1 THEN 1 ELSE 0 END`},
		{"case-when-tabbed", "1 CASE\tWHEN 1=1\nTHEN 1 ELSE 0 END"},
		{"server-version", `1 SELECT @@version`},
		{"server-version-newline", "1 SELECT\n@@version"},
		{"union-all-at-start", "UNION\nALL SELECT password"},
	}
	a := NewAnalyzer("block", 2, "sqli")
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload := strings.Repeat("x", 320) + "1 " + tc.payload
			target := "/search?q=" + url.QueryEscape(payload)
			got := detectOnTarget(t, a, "GET", target, "", "")
			if got == nil || !got.Detected || got.Category != "sqli" {
				t.Fatalf("long SQL payload was dropped by prefilter: %+v", got)
			}
		})
	}
}

func TestLFITextualHexDocumentationDoesNotTripStandalone(t *testing.T) {
	body := `{"text":"Documentation mentions 0x2e0x2e0x2f%00 and win.ini as a Windows path example, without requesting a file. ` +
		strings.Repeat("This guide discusses encoded path examples for defenders and does not execute them. ", 8) + `"}`
	req := readinessRequest(t, "POST", "/docs", "application/json", body)
	reqCtx, err := engine.NewRequestContext(req, "default")
	if err != nil {
		t.Fatal(err)
	}
	reqCtx.DecodedBody = []byte(body)
	result, err := NewLFIDetector("block").Detect(context.Background(), reqCtx)
	if err != nil {
		t.Fatal(err)
	}
	if result != nil && result.Detected {
		t.Fatalf("standalone LFI detector flagged documented textual hex example: %+v", result)
	}
}

func TestLFITextualHexDocumentationPrefixDoesNotHideLaterAttack(t *testing.T) {
	body := `{"text":"Documentation example: 0x2e0x2e0x2f%00 and win.ini are discussed as text. ` +
		strings.Repeat("This guide discusses encoded path examples for defenders. ", 5) +
		`Later request value: 0x2e0x2e0x2f%00/etc/passwd"}`
	req := readinessRequest(t, "POST", "/docs", "application/json", body)
	reqCtx, err := engine.NewRequestContext(req, "default")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(reqCtx.DecodedBody), "Later request value") {
		t.Fatalf("request body was not available to standalone detector: %q", string(reqCtx.DecodedBody))
	}
	result, err := NewLFIDetector("block").Detect(context.Background(), reqCtx)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || !result.Detected || result.Category != "lfi" {
		t.Fatalf("later textual-hex LFI payload was hidden by earlier documentation example: %+v", result)
	}
}

func TestLFITextualHexDocumentationDoesNotTripExplicitField(t *testing.T) {
	body := `{"file":"Documentation example: 0x2e, 0x2e, 0x2f%00 and win.ini are discussed as text."}`
	got := detectOnTarget(t, NewAnalyzer("block", 2, "lfi"), "POST", "/docs", "application/json", body)
	if got != nil && got.Detected {
		t.Fatalf("analyzer flagged documented explicit-field example: %+v", got)
	}
}

func TestLongCandidateSQLDocsStayBlocked(t *testing.T) {
	payload := strings.Repeat("x", 320) + "The article explains UNION ALL SELECT, DROP TABLE, ORDER BY 9, CASE WHEN branches, and SELECT @@version as examples."
	target := "/search?q=" + url.QueryEscape(payload)

	got := detectOnTarget(t, NewAnalyzer("block", 2, "sqli"), "GET", target, "", "")
	if got != nil && got.Detected {
		t.Fatalf("ordinary SQL documentation was reopened by long prefilter: %+v", got)
	}
}

func TestLongCandidateSQLLeadingDocumentationStayBlocked(t *testing.T) {
	payload := "UNION ALL SELECT, DROP TABLE, ORDER BY 9, CASE WHEN, and SELECT @@version are SQL examples for defenders. " + strings.Repeat("This reference explains syntax without executing user input. ", 8)
	target := "/docs?q=" + url.QueryEscape(payload)
	req := readinessRequest(t, "GET", target, "", "")
	reqCtx, err := engine.NewRequestContext(req, "default")
	if err != nil {
		t.Fatal(err)
	}
	got, err := NewAnalyzer("block", 2, "sqli").Detect(context.Background(), reqCtx)
	if err != nil {
		t.Fatal(err)
	}
	if got != nil && got.Detected {
		t.Fatalf("leading SQL documentation was reopened by long prefilter: %+v", got)
	}
}

func TestAnalyzerOversizedMiddleMarkersRemainCovered(t *testing.T) {
	cases := []struct {
		name, category, payload string
	}{
		{"sql-tabbed-drop", "sqli", "1 DROP\tTABLE users"},
		{"sql-newline-order", "sqli", "1 ORDER\nBY 9"},
		{"lfi-textual-hex", "lfi", `0x2e.%000x2f0x2e.%00/etc/passwd`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := strings.Repeat("a", maxInputRawBytes*2) + tc.payload + strings.Repeat("b", maxInputRawBytes*2)
			if !rawCoverageSignal.MatchString(tc.payload) {
				t.Fatalf("raw coverage signal missed %q", tc.payload)
			}
			sample := clipRawBytes([]byte(body))
			if !strings.Contains(sample, tc.payload) {
				t.Fatalf("bounded sample dropped middle marker %q", tc.payload)
			}
			assertAnalyzerCategory(t, httptestRequestWithBody(t, "application/octet-stream", []byte(body)), tc.category)
		})
	}
}

func TestOversizedHexDocumentationPrefixDoesNotHideLaterLFI(t *testing.T) {
	prefix := `{"text":"Documentation example 0x2e0x2e0x2f and win.ini is discussed for defenders."}` + strings.Repeat("x", maxInputRawBytes)
	payload := `0x2e0x2e0x2f%00/etc/passwd`
	body := prefix + payload + strings.Repeat("y", maxInputRawBytes)
	sample := clipRawBytes([]byte(body))
	if !strings.Contains(sample, payload) {
		t.Fatalf("bounded sample dropped later textual-hex payload")
	}
	assertAnalyzerCategory(t, httptestRequestWithBody(t, "application/octet-stream", []byte(body)), "lfi")
}

func TestOversizedCoverageAnchorHandlesUnicodeContext(t *testing.T) {
	body := strings.Repeat("文档说明 ", 2048) + `1; DROP TABLE users` + strings.Repeat("尾部 ", 2048)
	sample := clipRawBytes([]byte(body))
	if !strings.Contains(sample, "DROP TABLE") {
		t.Fatal("unicode context caused the SQL coverage anchor to be lost")
	}
}

func TestOversizedCoverageAnchorScansPastMarkerFlood(t *testing.T) {
	prefix := strings.Repeat("0x2e0x2e0x2f "+strings.Repeat("z", 96), 300)
	payload := `0x2e0x2e0x2f%00/etc/passwd`
	body := prefix + strings.Repeat("q", maxInputRawBytes) + payload
	sample := clipRawBytes([]byte(body))
	if !strings.Contains(sample, payload) {
		t.Fatal("marker flood hid the later high-confidence LFI anchor")
	}
}
