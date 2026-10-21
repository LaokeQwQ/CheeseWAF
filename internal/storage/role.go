package storage

import (
	"errors"
	"strings"
	"unicode"
)

// ValidateRoleName accepts identities only, never RBAC permission expressions.
func ValidateRoleName(role string) error {
	if role == "" || len(role) > 128 || strings.ContainsAny(role, "*:") || strings.IndexFunc(role, func(r rune) bool { return r < '!' || r > '~' || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) }) >= 0 {
		return errors.New("role must be a nonempty role name, not a permission expression")
	}
	return nil
}
