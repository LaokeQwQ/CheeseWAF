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
