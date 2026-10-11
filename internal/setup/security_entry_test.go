package setup

import (
	"regexp"
	"testing"
)

func TestNewSecurityEntrySegmentIsAlphanumeric(t *testing.T) {
	value, err := NewSecurityEntrySegment()
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateSecurityEntrySegment(value); err != nil {
		t.Fatalf("generated entry %q rejected: %v", value, err)
	}
	if !regexp.MustCompile(`^[A-Za-z0-9]+$`).MatchString(value) {
		t.Fatalf("generated entry contains symbols: %q", value)
	}
}

func TestValidateSecurityEntrySegmentRejectsSymbols(t *testing.T) {
	for _, value := range []string{"", "short", "with-dash", "with space", "../../admin", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"} {
		if err := ValidateSecurityEntrySegment(value); err == nil {
			t.Fatalf("ValidateSecurityEntrySegment(%q) unexpectedly succeeded", value)
		}
	}
}
