package engine

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDetectProtocolViolationsHTTP2ForbiddenHopByHopHeaders(t *testing.T) {
	cases := []struct {
		name      string
		header    string
		value     string
		wantType  string
		wantLevel Severity
	}{
		{name: "connection", header: "Connection", value: "keep-alive", wantType: "smuggling", wantLevel: SeverityHigh},
		{name: "upgrade", header: "Upgrade", value: "websocket", wantType: "smuggling", wantLevel: SeverityHigh},
		{name: "transfer-encoding", header: "Transfer-Encoding", value: "chunked", wantType: "smuggling", wantLevel: SeverityCritical},
		{name: "te-not-trailers", header: "TE", value: "chunked", wantType: "smuggling", wantLevel: SeverityHigh},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "https://example.test/", nil)
			req.Proto = "HTTP/2.0"
			req.ProtoMajor = 2
			req.ProtoMinor = 0
			req.Header.Set(tc.header, tc.value)

			got := DetectProtocolViolations(req)
			if got == nil || !got.Detected {
				t.Fatalf("expected protocol violation for %s", tc.header)
			}
			if got.Type != tc.wantType || got.Severity != tc.wantLevel {
				t.Fatalf("unexpected violation: %+v", got)
			}
		})
	}
}

func TestDetectProtocolViolationsAllowsHTTP2TrailersHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://example.test/", nil)
	req.Proto = "HTTP/2.0"
	req.ProtoMajor = 2
	req.ProtoMinor = 0
	req.Header.Set("TE", "trailers")

	if got := DetectProtocolViolations(req); got != nil {
		t.Fatalf("expected TE: trailers to pass for HTTP/2, got %+v", got)
	}
}

func TestDetectProtocolViolationsWebSocketUpgradeShape(t *testing.T) {
	t.Run("valid upgrade passes", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://example.test/ws", nil)
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Upgrade", "websocket")
		req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
		req.Header.Set("Sec-WebSocket-Version", "13")

		if got := DetectProtocolViolations(req); got != nil {
			t.Fatalf("expected valid websocket upgrade to pass, got %+v", got)
		}
	})

	t.Run("malformed upgrade is blocked", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "http://example.test/ws", strings.NewReader("payload"))
		req.Header.Set("Connection", "keep-alive")
		req.Header.Set("Upgrade", "websocket")

		got := DetectProtocolViolations(req)
		if got == nil || got.Type != "upgrade_abuse" || got.Severity != SeverityMedium {
			t.Fatalf("expected malformed upgrade violation, got %+v", got)
		}
	})
}

func TestDetectProtocolViolationsRequiresWebSocketVersion13(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.test/socket", nil)
	req.ProtoMajor = 1
	req.ProtoMinor = 1
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	req.Header.Set("Sec-WebSocket-Version", "12")
	violation := DetectProtocolViolations(req)
	if violation == nil || violation.Type != "upgrade_abuse" {
		t.Fatalf("violation=%+v, want malformed websocket upgrade", violation)
	}
}

func TestDetectProtocolViolationsRejectsAmbiguousContentHeaders(t *testing.T) {
	for _, name := range []string{"Content-Type", "Content-Encoding", "Transfer-Encoding"} {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "http://example.test/upload", strings.NewReader("body"))
			req.Header.Add(name, "first")
			req.Header.Add(name, "second")
			violation := DetectProtocolViolations(req)
			if violation == nil || violation.Type != "ambiguous_header" {
				t.Fatalf("violation=%+v, want ambiguous_header", violation)
			}
		})
	}
}

func TestDetectProtocolViolationsRejectsEmptyOrMergedContentMetadata(t *testing.T) {
	for _, tc := range []struct {
		name   string
		header string
		value  string
	}{
		{name: "empty content type", header: "Content-Type", value: ""},
		{name: "merged content type", header: "Content-Type", value: "text/plain, application/json"},
		{name: "empty content encoding", header: "Content-Encoding", value: ""},
		{name: "merged content encoding", header: "Content-Encoding", value: "identity, gzip"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "http://example.test/upload", strings.NewReader("body"))
			req.Header[tc.header] = []string{tc.value}
			violation := DetectProtocolViolations(req)
			if violation == nil || violation.Type != "ambiguous_header" {
				t.Fatalf("violation=%+v, want ambiguous_header", violation)
			}
		})
	}
}

func TestDetectProtocolViolationsAllowsQuotedCommaInContentTypeParameter(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "http://example.test/upload", strings.NewReader("body"))
	req.Header.Set("Content-Type", `multipart/form-data; boundary="a,b"`)

	if violation := DetectProtocolViolations(req); violation != nil {
		t.Fatalf("expected quoted comma in Content-Type parameter to pass, got %+v", violation)
	}
}

func TestDetectProtocolViolationsRejectsMalformedContentType(t *testing.T) {
	for _, value := range []string{
		"text/plain, application/json",
		`multipart/form-data; boundary="unterminated`,
	} {
		t.Run(value, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "http://example.test/upload", strings.NewReader("body"))
			req.Header.Set("Content-Type", value)
			if violation := DetectProtocolViolations(req); violation == nil || violation.Type != "ambiguous_header" {
				t.Fatalf("violation=%+v, want ambiguous_header", violation)
			}
		})
	}
}

func TestDetectCLTESmugglingFromTransferEncodingField(t *testing.T) {
	// net/http moves TE into r.TransferEncoding and may clear Header["Transfer-Encoding"].
	req := httptest.NewRequest(http.MethodPost, "http://example.test/", strings.NewReader("0123456789"))
	req.Header.Set("Content-Length", "10")
	req.ContentLength = 10
	req.TransferEncoding = []string{"chunked"}
	req.Header.Del("Transfer-Encoding")

	got := DetectProtocolViolations(req)
	if got == nil || !got.Detected || got.Type != "smuggling" {
		t.Fatalf("expected CL.TE smuggling when TE lives only on TransferEncoding field, got %+v", got)
	}
}

func TestDetectTECLSmugglingFromTransferEncodingExtraValue(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "http://example.test/", nil)
	req.TransferEncoding = []string{"chunked", "identity"}
	req.Header.Del("Transfer-Encoding")

	got := DetectProtocolViolations(req)
	if got == nil || !got.Detected || got.Type != "smuggling" || got.Severity != SeverityCritical {
		t.Fatalf("expected TE.CL multi-value smuggling via TransferEncoding field, got %+v", got)
	}
}
