package netguard

import (
	"context"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestIsPublicIPRejectsSpecialUseAndPrivateTransitionTargets(t *testing.T) {
	for _, raw := range []string{
		"0.1.2.3", "192.0.0.1", "192.0.0.8", "192.0.0.170", "192.0.0.171",
		"192.0.2.1", "192.88.99.1", "198.18.0.1", "198.19.255.254",
		"198.51.100.1", "203.0.113.1", "240.0.0.1",
		"::127.0.0.1", "::10.0.0.1", "::8.8.8.8",
		"64:ff9b::7f00:1", "64:ff9b::a00:1", "64:ff9b::c000:201",
		"64:ff9b:1::808:808", "100::1", "100:0:0:1::1",
		"2001::1", "2001:2::1", "2001:10::1", "2001:db8::1",
		"2002:7f00:1::1", "2002:a00:1::1", "2002:c000:201::1",
		"3fff::1", "5f00::1",
	} {
		t.Run(raw, func(t *testing.T) {
			ip := net.ParseIP(raw)
			if ip == nil {
				t.Fatalf("invalid test address %q", raw)
			}
			if IsPublicIP(ip) {
				t.Fatalf("special-use or private transition target %s classified public", raw)
			}
		})
	}
}

func TestIsPublicIPPreservesGlobalAddressesAndPublicTransitionTargets(t *testing.T) {
	for _, raw := range []string{
		"8.8.8.8", "1.1.1.1", "192.0.0.9", "192.0.0.10",
		"192.31.196.1", "192.52.193.1", "192.175.48.1",
		"::ffff:8.8.8.8", "2606:4700:4700::1111", "2001:4860:4860::8888",
		"2001:1::1", "2001:1::2", "2001:1::3", "2001:3::1", "2001:4:112::1",
		"2001:20::1", "2001:30::1", "2620:4f:8000::1",
		"64:ff9b::808:808", "2002:808:808::1",
	} {
		t.Run(raw, func(t *testing.T) {
			if !IsPublicIP(net.ParseIP(raw)) {
				t.Fatalf("public address %s was rejected", raw)
			}
		})
	}
}

func TestTransitionURLPolicyRetainsExplicitPrivateOptIn(t *testing.T) {
	for _, raw := range []string{
		"https://[::127.0.0.1]/feed", "https://[64:ff9b::7f00:1]/feed",
		"https://[2002:7f00:1::1]/feed", "https://[2001::1]/feed",
		"https://192.0.2.1/feed", "https://198.18.0.1/feed",
	} {
		t.Run(raw, func(t *testing.T) {
			if _, err := ValidateURL(raw, URLPolicy{}); err == nil {
				t.Fatal("default public-only policy accepted special target")
			}
			if _, err := ValidateURL(raw, URLPolicy{AllowPrivate: true}); err != nil {
				t.Fatalf("explicit private opt-in rejected: %v", err)
			}
		})
	}
}

func TestHTTPClientRejectsSpecialResolvedAddressesBeforeDial(t *testing.T) {
	for _, raw := range []string{"::127.0.0.1", "64:ff9b::7f00:1", "2002:7f00:1::1", "198.18.0.1"} {
		t.Run(raw, func(t *testing.T) {
			client := NewHTTPClient(HTTPClientOptions{
				Timeout: time.Second,
				Resolver: func(context.Context, string, string) ([]net.IP, error) {
					// A public answer must not hide another non-public answer.
					return []net.IP{net.ParseIP("8.8.8.8"), net.ParseIP(raw)}, nil
				},
			})
			// Invoke the actual guard with an already-canceled dial context so
			// even the unfixed implementation cannot open a network connection.
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			transport := client.Transport.(validatingTransport).next.(*http.Transport)
			_, err := transport.DialContext(ctx, "tcp", "policy.example.test:80")
			if err == nil || !strings.Contains(err.Error(), "resolved to non-public IP") {
				t.Fatalf("expected pre-dial policy rejection, got %v", err)
			}
		})
	}
}

func TestHTTPClientRejectsSpecialRedirectTargets(t *testing.T) {
	client := NewHTTPClient(HTTPClientOptions{})
	for _, raw := range []string{"http://[64:ff9b::7f00:1]/feed", "http://[2002:7f00:1::1]/feed", "http://198.18.0.1/feed"} {
		req, err := http.NewRequest(http.MethodGet, raw, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := client.CheckRedirect(req, nil); err == nil {
			t.Fatalf("special redirect %s was accepted", raw)
		}
	}
}
