package engine

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestNewRequestContextRejectsBodyOverHardLimit(t *testing.T) {
	body := strings.Repeat("a", defaultRequestBodyLimit) + "tail"
	req, _ := http.NewRequest(http.MethodPost, "http://example.test/upload", io.NopCloser(bytes.NewBufferString(body)))

	if _, err := NewRequestContext(req, "site-a"); !errors.Is(err, ErrRequestBodyTooLarge) {
		t.Fatalf("expected ErrRequestBodyTooLarge, got %v", err)
	}
}

func TestNewRequestContextWithLimitsRejectsChunkedBodyOverHardLimit(t *testing.T) {
	req, _ := http.NewRequest(http.MethodPost, "http://example.test/upload", io.NopCloser(strings.NewReader("123456789")))
	req.ContentLength = -1
	if _, err := NewRequestContextWithLimits(req, "site-a", nil, 8); !errors.Is(err, ErrRequestBodyTooLarge) {
		t.Fatalf("expected chunked body to exceed hard limit, got %v", err)
	}
}

func TestNewRequestContextWithLimitsReplaysFullyInspectedBody(t *testing.T) {
	req, _ := http.NewRequest(http.MethodPost, "http://example.test/upload", strings.NewReader("12345678"))
	ctx, err := NewRequestContextWithLimits(req, "site-a", nil, 8)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(ctx.DecodedBody); got != "12345678" {
		t.Fatalf("decoded body = %q", got)
	}
	replayed, err := io.ReadAll(req.Body)
	if err != nil || string(replayed) != "12345678" {
		t.Fatalf("replayed body = %q, err=%v", replayed, err)
	}
}

func TestClientIPIgnoresForwardedHeadersByDefault(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "http://example.test/", nil)
	req.RemoteAddr = "198.51.100.20:1234"
	req.Header.Set("CF-Connecting-IP", "203.0.113.10")
	req.Header.Set("X-Real-IP", "203.0.113.11")
	req.Header.Set("X-Forwarded-For", "203.0.113.12")

	if got := ClientIP(req); got != "198.51.100.20" {
		t.Fatalf("expected default client IP to use socket peer only, got %q", got)
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

func TestClientIPWithTrustedProxiesPrefersValidatedChainOverSpoofableVendorHeader(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "http://example.test/", nil)
	req.RemoteAddr = "198.51.100.20:1234"
	req.Header.Set("CF-Connecting-IP", "192.0.2.99")
	req.Header.Set("X-Forwarded-For", "203.0.113.10, 198.51.100.20")

	if got := ClientIPWithTrustedProxies(req, []string{"198.51.100.0/24"}); got != "203.0.113.10" {
		t.Fatalf("expected validated forwarding chain, got %q", got)
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
