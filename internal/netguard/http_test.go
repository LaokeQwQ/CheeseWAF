package netguard

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

func TestValidateURLRejectsUnsafeEndpoints(t *testing.T) {
	policy := URLPolicy{Purpose: "provider", AllowedSchemes: []string{"http", "https"}}
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{name: "loopback", raw: "http://127.0.0.1/feed.json", want: "provider host IP must be public"},
		{name: "metadata", raw: "http://100.100.100.200/latest/meta-data", want: "provider host IP must be public"},
		{name: "credentials", raw: "https://user:pass@example.test/feed", want: "credentials in provider URL are not allowed"},
		{name: "fragment", raw: "https://example.test/feed#token", want: "fragments in provider URL are not allowed"},
		{name: "scheme", raw: "file:///etc/passwd", want: "only http and https provider URLs are allowed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ValidateURL(tt.raw, policy)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("expected error containing %q, got %v", tt.want, err)
			}
		})
	}
}

func TestHTTPClientRejectsPrivateResolvedAddress(t *testing.T) {
	client := NewHTTPClient(HTTPClientOptions{
		Timeout: 100 * time.Millisecond,
		Resolver: func(context.Context, string, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("10.0.0.8")}, nil
		},
		Policy: URLPolicy{Purpose: "provider", AllowedSchemes: []string{"http", "https"}},
	})
	_, err := client.Get("http://intel.example.test/feed.json")
	if err == nil || !strings.Contains(err.Error(), "provider host resolved to non-public IP") {
		t.Fatalf("expected DNS rebinding guard error, got %v", err)
	}
}

func TestHTTPClientAllowsPrivateWhenExplicit(t *testing.T) {
	client := NewHTTPClient(HTTPClientOptions{
		Timeout: 100 * time.Millisecond,
		Resolver: func(context.Context, string, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("10.0.0.8")}, nil
		},
		Policy: URLPolicy{Purpose: "provider", AllowedSchemes: []string{"http", "https"}, AllowPrivate: true},
	})
	_, err := client.Get("http://intel.example.test:1/feed.json")
	if err == nil || strings.Contains(err.Error(), "non-public IP") {
		t.Fatalf("expected connection error after private IP was allowed, got %v", err)
	}
}
