// Package identity defines canonical identity-field rules shared by setup,
// API, CLI, and authentication boundaries.
package identity

import (
	"errors"
	"fmt"
	"unicode"
)

const (
	MinUsernameLength = 3
	MaxUsernameLength = 32
)

var ErrInvalidUsername = errors.New("invalid username")

// ValidateUsername accepts the canonical account form used by all user
// management paths. It deliberately rejects, rather than trims, surrounding
// or embedded whitespace so an identity cannot change between interfaces.
func ValidateUsername(value string) error {
	if value == "" {
		return fmt.Errorf("%w: username is required", ErrInvalidUsername)
	}
	if len([]rune(value)) < MinUsernameLength {
		return fmt.Errorf("%w: username must contain at least %d characters", ErrInvalidUsername, MinUsernameLength)
	}
	if len([]rune(value)) > MaxUsernameLength {
		return fmt.Errorf("%w: username must contain at most %d characters", ErrInvalidUsername, MaxUsernameLength)
	}
	runes := []rune(value)
	if !isASCIIAlpha(runes[0]) {
		return fmt.Errorf("%w: username must start with an ASCII letter", ErrInvalidUsername)
	}
	if !isASCIIAlnum(runes[len(runes)-1]) {
		return fmt.Errorf("%w: username must end with an ASCII letter or digit", ErrInvalidUsername)
	}
	for _, r := range runes {
		if unicode.IsSpace(r) || unicode.IsControl(r) || !isASCIIUsernameChar(r) {
			return fmt.Errorf("%w: username may contain only ASCII letters, digits, '.', '_' and '-'", ErrInvalidUsername)
		}
	}
	return nil
}

func isASCIIUsernameChar(r rune) bool {
	return isASCIIAlnum(r) || r == '.' || r == '_' || r == '-'
}

func isASCIIAlpha(r rune) bool {
	return r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z'
}

func isASCIIAlnum(r rune) bool {
	return isASCIIAlpha(r) || r >= '0' && r <= '9'
}
