package proxytrust

import "testing"

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
