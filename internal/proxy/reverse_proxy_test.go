package proxy

import (
	"net/http"
	"net/url"
	"testing"
	"time"
)

func TestNewReverseProxyReusesTransportForSamePolicy(t *testing.T) {
	target, err := url.Parse("http://127.0.0.1:8080")
	if err != nil {
		t.Fatal(err)
	}
	first := NewReverseProxy(target, 17*time.Second)
	second := NewReverseProxy(target, 17*time.Second)
	if first.Transport != second.Transport {
		t.Fatal("reverse proxies with the same timeout must share a connection pool")
	}
	third := NewReverseProxy(target, 19*time.Second)
	if first.Transport == third.Transport {
		t.Fatal("different response-header timeout policies must not share a transport")
	}
	transport, ok := first.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("unexpected transport type %T", first.Transport)
	}
	if transport.MaxConnsPerHost <= 0 {
		t.Fatal("transport must cap active connections per upstream")
	}
}

func TestNewReverseProxyPreservesOriginalForwardedHost(t *testing.T) {
	target, err := url.Parse("http://origin.internal:8080")
	if err != nil {
		t.Fatal(err)
	}
	proxy := NewReverseProxy(target, time.Second)
	req, err := http.NewRequest(http.MethodGet, "https://app.example.test/path", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "app.example.test"
	proxy.Director(req)
	if got := req.Host; got != "origin.internal:8080" {
		t.Fatalf("expected upstream host, got %q", got)
	}
	if got := req.Header.Get("X-Forwarded-Host"); got != "app.example.test" {
		t.Fatalf("expected original forwarded host, got %q", got)
	}
}

func TestPeerIPOnlyReturnsParsedAddresses(t *testing.T) {
	cases := map[string]string{
		"203.0.113.9:443":    "203.0.113.9",
		"[2001:db8::1]:8443": "2001:db8::1",
		"not-an-ip:80":       "",
		"evil.example":       "",
		"":                   "",
		"203.0.113.10":       "203.0.113.10",
	}
	for in, want := range cases {
		if got := peerIP(in); got != want {
			t.Fatalf("peerIP(%q)=%q, want %q", in, got, want)
		}
	}
}

func TestNewReverseProxyStripsAllProviderIdentityHeaders(t *testing.T) {
	target, err := url.Parse("http://origin.internal:8080")
	if err != nil {
		t.Fatal(err)
	}
	proxy := NewReverseProxy(target, time.Second)
	req, err := http.NewRequest(http.MethodGet, "http://app.example.test/path", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.RemoteAddr = "192.0.2.10:1234"
	for _, header := range stripClientForwardHeaders {
		req.Header.Set(header, "203.0.113.99")
	}

	proxy.Director(req)
	for _, header := range stripClientForwardHeaders {
		got := req.Header.Get(header)
		switch http.CanonicalHeaderKey(header) {
		case http.CanonicalHeaderKey("X-Forwarded-For"), http.CanonicalHeaderKey("X-Real-IP"):
			if got != "192.0.2.10" {
				t.Fatalf("%s was not rebuilt from the socket peer: %q", header, got)
			}
		case http.CanonicalHeaderKey("X-Forwarded-Host"):
			if got != "app.example.test" {
				t.Fatalf("forwarded host was not rebuilt from the request host: %q", got)
			}
		case http.CanonicalHeaderKey("X-Forwarded-Proto"):
			if got != "http" {
				t.Fatalf("forwarded proto was not rebuilt from the request transport: %q", got)
			}
		default:
			if got != "" {
				t.Fatalf("provider identity header %s leaked upstream as %q", header, got)
			}
		}
	}
}

func TestNewReverseProxyForClientForwardsValidatedClientIdentity(t *testing.T) {
	target, err := url.Parse("http://origin.internal:8080")
	if err != nil {
		t.Fatal(err)
	}
	proxy := NewReverseProxyForClient(target, time.Second, "203.0.113.42")
	req, err := http.NewRequest(http.MethodGet, "http://app.example.test/path", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.RemoteAddr = "192.0.2.10:1234"
	req.Header.Set("X-Forwarded-For", "198.51.100.99")
	req.Header.Set("CF-Connecting-IP", "198.51.100.100")

	proxy.Director(req)
	if got := req.Header.Get("X-Forwarded-For"); got != "203.0.113.42" {
		t.Fatalf("X-Forwarded-For = %q, want validated client IP", got)
	}
	if got := req.Header.Get("X-Real-IP"); got != "203.0.113.42" {
		t.Fatalf("X-Real-IP = %q, want validated client IP", got)
	}
	if got := req.Header.Get("CF-Connecting-IP"); got != "" {
		t.Fatalf("provider identity header leaked upstream as %q", got)
	}
}

func TestNewReverseProxyForClientRejectsInvalidValidatedIdentity(t *testing.T) {
	target, err := url.Parse("http://origin.internal:8080")
	if err != nil {
		t.Fatal(err)
	}
	proxy := NewReverseProxyForClient(target, time.Second, "not-an-ip")
	req, err := http.NewRequest(http.MethodGet, "http://app.example.test/path", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.RemoteAddr = "192.0.2.10:1234"

	proxy.Director(req)
	if got := req.Header.Get("X-Forwarded-For"); got != "192.0.2.10" {
		t.Fatalf("X-Forwarded-For = %q, want socket peer fallback", got)
	}
}
