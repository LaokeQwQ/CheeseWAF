package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

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
	var gotHost, gotForwardedHost string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost, gotForwardedHost = r.Host, r.Header.Get("X-Forwarded-Host")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	target, _ := url.Parse(upstream.URL)
	proxy := NewReverseProxy(target, time.Second)
	req := httptest.NewRequest(http.MethodGet, "https://app.example.test/path", nil)
	req.Host = "app.example.test"
	proxy.ServeHTTP(httptest.NewRecorder(), req)
	if gotHost != target.Host {
		t.Fatalf("expected upstream host %q, got %q", target.Host, gotHost)
	}
	if got := gotForwardedHost; got != "app.example.test" {
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
	var received http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { received = r.Header.Clone(); w.WriteHeader(204) }))
	defer upstream.Close()
	target, _ := url.Parse(upstream.URL)
	proxy := NewReverseProxy(target, time.Second)
	req := httptest.NewRequest(http.MethodGet, "http://app.example.test/path", nil)
	req.RemoteAddr = "192.0.2.10:1234"
	for _, header := range stripClientForwardHeaders {
		req.Header.Set(header, "203.0.113.99")
	}

	proxy.ServeHTTP(httptest.NewRecorder(), req)
	for _, header := range stripClientForwardHeaders {
		got := received.Get(header)
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
		case http.CanonicalHeaderKey("X-Forwarded-Port"):
			if got != "80" {
				t.Fatalf("forwarded port was not rebuilt from the request transport: %q", got)
			}
		default:
			if got != "" {
				t.Fatalf("provider identity header %s leaked upstream as %q", header, got)
			}
		}
	}
}

func TestNewReverseProxyForClientForwardsValidatedClientIdentity(t *testing.T) {
	var received http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { received = r.Header.Clone(); w.WriteHeader(204) }))
	defer upstream.Close()
	target, _ := url.Parse(upstream.URL)
	proxy := NewReverseProxyForClient(target, time.Second, "203.0.113.42")
	req := httptest.NewRequest(http.MethodGet, "http://app.example.test/path", nil)
	req.RemoteAddr = "192.0.2.10:1234"
	req.Header.Set("X-Forwarded-For", "198.51.100.99")
	req.Header.Set("CF-Connecting-IP", "198.51.100.100")

	proxy.ServeHTTP(httptest.NewRecorder(), req)
	if got := received.Get("X-Forwarded-For"); got != "203.0.113.42" {
		t.Fatalf("X-Forwarded-For = %q, want validated client IP", got)
	}
	if got := received.Get("X-Real-IP"); got != "203.0.113.42" {
		t.Fatalf("X-Real-IP = %q, want validated client IP", got)
	}
	if got := received.Get("CF-Connecting-IP"); got != "" {
		t.Fatalf("provider identity header leaked upstream as %q", got)
	}
}

func TestNewReverseProxyForClientRejectsInvalidValidatedIdentity(t *testing.T) {
	var received http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { received = r.Header.Clone(); w.WriteHeader(204) }))
	defer upstream.Close()
	target, _ := url.Parse(upstream.URL)
	proxy := NewReverseProxyForClient(target, time.Second, "not-an-ip")
	req := httptest.NewRequest(http.MethodGet, "http://app.example.test/path", nil)
	req.RemoteAddr = "192.0.2.10:1234"

	proxy.ServeHTTP(httptest.NewRecorder(), req)
	if got := received.Get("X-Forwarded-For"); got != "192.0.2.10" {
		t.Fatalf("X-Forwarded-For = %q, want socket peer fallback", got)
	}
}

func TestNewReverseProxyForSiteAppliesOriginSchemeAndHostPolicy(t *testing.T) {
	target, _ := url.Parse("http://origin.internal:8080/base")
	var gotScheme, gotHost string
	proxy := NewReverseProxyForSite(target, time.Second, "203.0.113.42", "https", true, "origin.example.test")
	proxy.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		gotScheme, gotHost = r.URL.Scheme, r.Host
		return &http.Response{StatusCode: http.StatusNoContent, Header: make(http.Header), Body: io.NopCloser(http.NoBody), Request: r}, nil
	})
	req := httptest.NewRequest(http.MethodGet, "http://public.example.test/path", nil)
	req.Host = "public.example.test"
	proxy.ServeHTTP(httptest.NewRecorder(), req)
	if gotScheme != "https" {
		t.Fatalf("origin scheme = %q, want https", gotScheme)
	}
	if gotHost != "origin.example.test" {
		t.Fatalf("origin Host = %q, want configured host header", gotHost)
	}

	proxy = NewReverseProxyForSite(target, time.Second, "203.0.113.42", "http", true, "")
	proxy.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		gotScheme, gotHost = r.URL.Scheme, r.Host
		return &http.Response{StatusCode: http.StatusNoContent, Header: make(http.Header), Body: io.NopCloser(http.NoBody), Request: r}, nil
	})
	proxy.ServeHTTP(httptest.NewRecorder(), req)
	if gotScheme != "http" || gotHost != "public.example.test" {
		t.Fatalf("pass_host policy = scheme %q host %q", gotScheme, gotHost)
	}
}

func TestNewReverseProxyForSitePreservesSecureOriginWithoutOverride(t *testing.T) {
	target, _ := url.Parse("https://origin.internal:8443/base")
	proxy := NewReverseProxyForSite(target, time.Second, "203.0.113.42", "", false, "")
	var gotScheme string
	proxy.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		gotScheme = r.URL.Scheme
		return &http.Response{StatusCode: http.StatusNoContent, Header: make(http.Header), Body: io.NopCloser(http.NoBody), Request: r}, nil
	})
	proxy.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "http://public.example.test/path", nil))
	if gotScheme != "https" {
		t.Fatalf("secure origin scheme = %q, want https", gotScheme)
	}
}
