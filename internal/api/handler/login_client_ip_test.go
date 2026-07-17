package handler

import (
	"net/http"
	"testing"
)

func TestTrustedLoginClientIPOnlyHonorsXFFFromLoopback(t *testing.T) {
	t.Parallel()

	req := func(remote, xff string) *http.Request {
		r := &http.Request{Header: make(http.Header), RemoteAddr: remote}
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		return r
	}

	cases := []struct {
		name string
		peer string
		xff  string
		want string
	}{
		{name: "loopback honors xff", peer: "127.0.0.1", xff: "198.51.100.50", want: "198.51.100.50"},
		{name: "ipv6 loopback honors xff", peer: "::1", xff: "203.0.113.9", want: "203.0.113.9"},
		{name: "private non-loopback ignores xff", peer: "10.0.0.5", xff: "198.51.100.50", want: ""},
		{name: "rfc1918 192.168 ignores xff", peer: "192.168.1.1", xff: "198.51.100.50", want: ""},
		{name: "public peer ignores xff", peer: "203.0.113.40", xff: "198.51.100.50", want: ""},
		{name: "loopback without xff", peer: "127.0.0.1", xff: "", want: ""},
		{name: "loopback takes first xff hop", peer: "127.0.0.1", xff: "198.51.100.1, 10.0.0.2", want: "198.51.100.1"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := trustedLoginClientIP(req(tc.peer+":12345", tc.xff), tc.peer)
			if got != tc.want {
				t.Fatalf("trustedLoginClientIP peer=%q xff=%q = %q, want %q", tc.peer, tc.xff, got, tc.want)
			}
		})
	}
}

func TestLoginRateLimitKeysIgnorePrivatePeerXFF(t *testing.T) {
	t.Parallel()
	r := &http.Request{
		Header:     make(http.Header),
		RemoteAddr: "10.1.2.3:4444",
	}
	r.Header.Set("X-Forwarded-For", "198.51.100.77")
	keys := loginRateLimitKeys(r, "admin")
	for _, key := range keys {
		if key == "client:198.51.100.77" {
			t.Fatalf("rate limit keys must not include spoofable XFF client, got %v", keys)
		}
	}
	foundPeer := false
	for _, key := range keys {
		if key == "peer:10.1.2.3" {
			foundPeer = true
		}
	}
	if !foundPeer {
		t.Fatalf("expected peer key, got %v", keys)
	}
}
