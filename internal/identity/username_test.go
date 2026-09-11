package identity

import (
	"errors"
	"testing"
)

func TestValidateUsernameRejectsWhitespaceInsteadOfNormalizing(t *testing.T) {
	for _, value := range []string{" admin", "admin ", "ad min", "admin\t", "admin\u200b"} {
		t.Run(value, func(t *testing.T) {
			if err := ValidateUsername(value); !errors.Is(err, ErrInvalidUsername) {
				t.Fatalf("ValidateUsername(%q) error = %v, want ErrInvalidUsername", value, err)
			}
		})
	}
}

func TestValidateUsernameAcceptsCanonicalNames(t *testing.T) {
	for _, value := range []string{"admin", "root-admin", "ops_01", "A.b"} {
		if err := ValidateUsername(value); err != nil {
			t.Fatalf("ValidateUsername(%q) error = %v", value, err)
		}
	}
}

func TestValidateUsernameRejectsMalformedNames(t *testing.T) {
	for _, value := range []string{"", "ab", "1admin", "admin-", "admin/name", "管理员"} {
		if err := ValidateUsername(value); !errors.Is(err, ErrInvalidUsername) {
			t.Fatalf("ValidateUsername(%q) error = %v, want ErrInvalidUsername", value, err)
		}
	}
}
