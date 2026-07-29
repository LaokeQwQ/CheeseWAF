package passpolicy

import (
	"errors"
	"testing"
)

func TestValidateRejectsAdmin123456(t *testing.T) {
	err := Validate("Admin123456", "admin")
	if err == nil {
		t.Fatal("expected Admin123456 to be rejected")
	}
	// Username related or weak or classes — any rejection is fine; must not accept.
	if Validate("Admin123456", "") == nil {
		t.Fatal("expected Admin123456 rejected without username too")
	}
}

func TestValidateAcceptsStrongPassword(t *testing.T) {
	// upper + lower + non-repeating digits + special = 4 classes
	if err := Validate("Tr0ubad0r&X", ""); err != nil {
		t.Fatalf("expected strong password accepted, got %v (%s)", err, Explain("Tr0ubad0r&X"))
	}
	// 3 classes without digits: upper+lower+special
	if err := Validate("Correct-Horse!", ""); err != nil {
		t.Fatalf("expected 3-class password accepted, got %v", err)
	}
	// 3 classes without special: upper+lower+non-repeating digits
	if err := Validate("CorrectHorse9a", ""); err != nil {
		t.Fatalf("expected no-special 3-class accepted, got %v (%s)", err, Explain("CorrectHorse9a"))
	}
}

func TestValidateMinLength(t *testing.T) {
	if !errors.Is(Validate("Ab1!xYz", ""), ErrTooShort) {
		t.Fatal("expected too short")
	}
}

func TestValidateNeedThreeClasses(t *testing.T) {
	// only lower
	if !errors.Is(Validate("onlylowercase", ""), ErrNeedClasses) && Validate("onlylowercase", "") == nil {
		t.Fatal("expected reject only-lowercase")
	}
	// lower + sequential digits only (digit class fails sequence) → 1 class
	err := Validate("password12345", "")
	if err == nil {
		t.Fatal("expected password12345 rejected")
	}
}

func TestNonRepeatingDigits(t *testing.T) {
	// digit 1 repeated
	c := Classify("Abcdefg11!")
	if c.NonRepeatingDigit {
		t.Fatal("repeated digits should not satisfy non-repeating digit class")
	}
	// unique non-sequential digits
	c = Classify("Abcdefg19!")
	if !c.NonRepeatingDigit {
		t.Fatalf("expected non-repeating digit class, got %+v", c)
	}
	// sequential unique digits
	c = Classify("Abcde1234!")
	if c.NonRepeatingDigit {
		t.Fatal("sequential digits should not satisfy non-repeating digit class")
	}
}

func TestUsernameRelated(t *testing.T) {
	if !errors.Is(Validate("MyAdminSecret!", "admin"), ErrUsernameRelated) {
		// contains "admin"
		if Validate("MyAdminSecret!", "admin") == nil {
			t.Fatal("expected username-related reject")
		}
	}
	if err := Validate("Zx9!qLmN2p", "admin"); err != nil {
		t.Fatalf("unrelated strong password rejected: %v", err)
	}
}

func TestClassifyCount(t *testing.T) {
	c := Classify("Aa1!")
	if c.Count() != 4 {
		t.Fatalf("count=%d want 4 (%+v)", c.Count(), c)
	}
}
