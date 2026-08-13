package ip

import (
	"net/netip"
	"testing"
)

func TestCanonicalPrefixConvertsIPv4MappedIPv6Range(t *testing.T) {
	prefix, err := canonicalPrefix(netip.MustParsePrefix("::ffff:192.0.2.0/120"))
	if err != nil {
		t.Fatalf("canonicalPrefix returned error: %v", err)
	}
	if want := netip.MustParsePrefix("192.0.2.0/24"); prefix != want {
		t.Fatalf("canonicalPrefix = %v, want %v", prefix, want)
	}

	matcher, err := NewMatcher([]string{"::ffff:192.0.2.0/120"})
	if err != nil {
		t.Fatalf("NewMatcher returned error: %v", err)
	}
	if !matcher.Contains("192.0.2.15") {
		t.Fatal("mapped IPv6 prefix did not match its IPv4 address range")
	}
	if matcher.Contains("192.0.3.1") {
		t.Fatal("mapped IPv6 prefix matched an IPv4 address outside its range")
	}
}

func TestCanonicalPrefixRejectsMappedPrefixBroaderThanMappedRange(t *testing.T) {
	if _, err := canonicalPrefix(netip.MustParsePrefix("::ffff:192.0.2.0/95")); err == nil {
		t.Fatal("canonicalPrefix accepted a mapped prefix broader than ::ffff:0:0/96")
	}
	if _, err := NewMatcher([]string{"::ffff:192.0.2.0/95"}); err == nil {
		t.Fatal("NewMatcher accepted a mapped prefix broader than ::ffff:0:0/96")
	}
}
