package engine

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestNewRequestContextPreservesLargeBodyForUpstream(t *testing.T) {
	body := strings.Repeat("a", requestContextBodyPreviewLimit) + "tail"
	req, _ := http.NewRequest(http.MethodPost, "http://example.test/upload", io.NopCloser(bytes.NewBufferString(body)))

	ctx, err := NewRequestContext(req, "site-a")
	if err != nil {
		t.Fatalf("new request context: %v", err)
	}
	if len(ctx.DecodedBody) != requestContextBodyPreviewLimit {
		t.Fatalf("expected decoded preview to be capped at %d bytes, got %d", requestContextBodyPreviewLimit, len(ctx.DecodedBody))
	}
	if got, ok := ctx.Metadata["body_preview_truncated"].(bool); !ok || !got {
		t.Fatalf("expected body_preview_truncated metadata, got %+v", ctx.Metadata)
	}
	replayed, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("read replayed body: %v", err)
	}
	if string(replayed) != body {
		t.Fatalf("request body was not preserved for upstream, got len=%d want=%d", len(replayed), len(body))
	}
}

func TestClientIPWithTrustedProxiesRequiresTrustedRemote(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "http://example.test/", nil)
	req.RemoteAddr = "198.51.100.20:1234"
	req.Header.Set("X-Real-IP", "203.0.113.10")

	if got := ClientIPWithTrustedProxies(req, []string{"10.0.0.0/8"}); got != "198.51.100.20" {
		t.Fatalf("expected remote address when proxy is untrusted, got %q", got)
	}
}

func TestClientIPWithTrustedProxiesUsesCDNHeaders(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "http://example.test/", nil)
	req.RemoteAddr = "198.51.100.20:1234"
	req.Header.Set("CF-Connecting-IP", "203.0.113.10")

	if got := ClientIPWithTrustedProxies(req, []string{"198.51.100.0/24"}); got != "203.0.113.10" {
		t.Fatalf("expected CF-Connecting-IP, got %q", got)
	}
}

func TestClientIPWithTrustedProxiesUsesAdditionalCDNHeaders(t *testing.T) {
	tests := []struct {
		name   string
		header string
		value  string
		want   string
	}{
		{name: "aliyun", header: "Ali-CDN-Real-IP", value: "203.0.113.21", want: "203.0.113.21"},
		{name: "vercel list", header: "X-Vercel-Forwarded-For", value: "203.0.113.22, 198.51.100.20", want: "203.0.113.22"},
		{name: "digitalocean", header: "DO-Connecting-IP", value: "203.0.113.23", want: "203.0.113.23"},
		{name: "azure", header: "X-Azure-ClientIP", value: "203.0.113.24", want: "203.0.113.24"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodGet, "http://example.test/", nil)
			req.RemoteAddr = "198.51.100.20:1234"
			req.Header.Set(tc.header, tc.value)

			if got := ClientIPWithTrustedProxies(req, []string{"198.51.100.0/24"}); got != tc.want {
				t.Fatalf("expected %s, got %q", tc.want, got)
			}
		})
	}
}

func TestClientIPWithTrustedProxiesUsesForwardedForChain(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "http://example.test/", nil)
	req.RemoteAddr = "198.51.100.20:1234"
	req.Header.Set("X-Forwarded-For", "203.0.113.10, 10.0.0.5, 198.51.100.20")

	if got := ClientIPWithTrustedProxies(req, []string{"198.51.100.0/24", "10.0.0.0/8"}); got != "203.0.113.10" {
		t.Fatalf("expected first untrusted forwarded IP, got %q", got)
	}
}

func TestClientIPWithTrustedProxiesParsesForwardedHeader(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "http://example.test/", nil)
	req.RemoteAddr = "198.51.100.20:1234"
	req.Header.Set("Forwarded", `for="[2001:db8::10]:443";proto=https`)

	if got := ClientIPWithTrustedProxies(req, []string{"198.51.100.20"}); got != "2001:db8::10" {
		t.Fatalf("expected forwarded IPv6 address, got %q", got)
	}
}
