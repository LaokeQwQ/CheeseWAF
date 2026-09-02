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
	for _, raw := range []string{"::ffff:0:0/96", "::ffff:192.0.2.0/95"} {
		if _, err := canonicalPrefix(netip.MustParsePrefix(raw)); err == nil {
			t.Fatalf("canonicalPrefix accepted unsafe mapped prefix %s", raw)
		}
		if _, err := NewMatcher([]string{raw}); err == nil {
			t.Fatalf("NewMatcher accepted unsafe mapped prefix %s", raw)
		}
	}
}

func TestNewMatcherRejectsInvalidExactAddress(t *testing.T) {
	if _, err := NewMatcher([]string{"203.0.113.10", "203.0.113.999"}); err == nil {
		t.Fatal("NewMatcher accepted an invalid exact address")
	}
}

func TestNewMatcherRejectsEmptyEntry(t *testing.T) {
	if _, err := NewMatcher([]string{"203.0.113.10", " "}); err == nil {
		t.Fatal("NewMatcher accepted an empty entry")
	}
}
