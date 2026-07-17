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
