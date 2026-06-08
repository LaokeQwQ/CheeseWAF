package engine

import (
	"net/http"
	"testing"
)

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
