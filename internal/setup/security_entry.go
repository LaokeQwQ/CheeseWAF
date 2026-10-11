package setup

import (
	"crypto/rand"
	"fmt"
	"regexp"
)

const (
	securityEntryLength = 32
	securityEntryMin    = 8
	securityEntryMax    = 64
)

var securityEntryPattern = regexp.MustCompile(`^[A-Za-z0-9]+$`)

// NewSecurityEntrySegment returns a URL-safe, symbol-free management entry.
// It is intentionally independent from the setup token so the entry can be
// rotated without invalidating the one-time first-install credential.
func NewSecurityEntrySegment() (string, error) {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	buf := make([]byte, securityEntryLength)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate admin security entry: %w", err)
	}
	for i, value := range buf {
		buf[i] = alphabet[int(value)%len(alphabet)]
	}
	return string(buf), nil
}

// ValidateSecurityEntrySegment accepts only a path segment made of ASCII
// letters and digits. The bounds keep accidental empty or unbounded entries
// out of the admin router while leaving custom values easy to type.
func ValidateSecurityEntrySegment(value string) error {
	if len(value) < securityEntryMin || len(value) > securityEntryMax {
		return fmt.Errorf("admin security entry must contain %d-%d ASCII letters or digits", securityEntryMin, securityEntryMax)
	}
	if !securityEntryPattern.MatchString(value) {
		return fmt.Errorf("admin security entry must contain ASCII letters or digits only")
	}
	return nil
}
