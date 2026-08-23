package proxytrust

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSplitHeaderListPreservesQuotedSeparators(t *testing.T) {
	parts := splitHeaderList(`for="198.51.100.1,still-quoted";proto=https, for=203.0.113.2`, ',')
	if len(parts) != 2 {
		t.Fatalf("quoted comma split into %d parts: %#v", len(parts), parts)
	}
	params := splitHeaderList(parts[0], ';')
	if len(params) != 2 {
		t.Fatalf("unquoted semicolon was not split: %#v", params)
	}
}

func TestCompileRejectsUnknownProviderAndInvalidCIDR(t *testing.T) {
	if _, err := Compile(nil, map[string][]string{"unknown": {"198.51.100.0/24"}}); err == nil {
		t.Fatal("expected unknown provider to fail closed")
	}
	if _, err := Compile(nil, map[string][]string{"cloudflare": {"not-an-ip"}}); err == nil {
		t.Fatal("expected invalid provider CIDR to fail closed")
	}
}

func TestClientIPPrefersProviderIdentityOverForwardedChain(t *testing.T) {
	policy, err := Compile([]string{"10.0.0.0/8"}, map[string][]string{
		"cloudflare": {"10.0.0.0/8"},
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	req.RemoteAddr = "10.0.0.2:443"
	req.Header.Set("CF-Connecting-IP", "203.0.113.7")
	req.Header.Set("X-Forwarded-For", "198.51.100.99")
	if got := policy.ClientIP(req); got != "203.0.113.7" {
		t.Fatalf("provider-bound identity must win over XFF, got %q", got)
	}
}

func TestClientIPMalformedProviderIdentityFailsClosed(t *testing.T) {
	policy, err := Compile([]string{"10.0.0.0/8"}, map[string][]string{
		"cloudflare": {"10.0.0.0/8"},
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	req.RemoteAddr = "10.0.0.2:443"
	req.Header.Set("CF-Connecting-IP", "not-an-ip")
	req.Header.Set("X-Forwarded-For", "198.51.100.99")
	if got := policy.ClientIP(req); got != "10.0.0.2" {
		t.Fatalf("malformed provider identity must fall back to peer, got %q", got)
	}
}

func TestClientIPMissingProviderIdentityFallsBackToXFF(t *testing.T) {
	policy, err := Compile([]string{"10.0.0.0/8"}, map[string][]string{
		"cloudflare": {"10.0.0.0/8"},
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	req.RemoteAddr = "10.0.0.2:443"
	req.Header.Set("X-Forwarded-For", "198.51.100.99")
	if got := policy.ClientIP(req); got != "198.51.100.99" {
		t.Fatalf("missing provider identity should allow XFF fallback, got %q", got)
	}
}

func TestClientIPStopsAtMalformedForwardingElement(t *testing.T) {
	policy, err := Compile([]string{"10.0.0.0/8"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		header string
		value  string
		want   string
	}{
		{name: "xff nearest trusted hop", header: "X-Forwarded-For", value: "198.51.100.5, malformed, 10.0.0.3", want: "10.0.0.3"},
		{name: "xff malformed nearest peer", header: "X-Forwarded-For", value: "198.51.100.5, malformed", want: "10.0.0.2"},
		{name: "forwarded nearest trusted hop", header: "Forwarded", value: "for=198.51.100.5, for=_hidden, for=10.0.0.3", want: "10.0.0.3"},
		{name: "forwarded for with proto", header: "Forwarded", value: "for=198.51.100.5;proto=https", want: "198.51.100.5"},
		{name: "forwarded quoted for", header: "Forwarded", value: `for="198.51.100.5";proto=https`, want: "198.51.100.5"},
		{name: "forwarded missing for", header: "Forwarded", value: "for=198.51.100.5, proto=https", want: "10.0.0.2"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
			req.RemoteAddr = "10.0.0.2:443"
			req.Header.Set(tc.header, tc.value)
			if got := policy.ClientIP(req); got != tc.want {
				t.Fatalf("ClientIP()=%q, want %q", got, tc.want)
			}
		})
	}
}
