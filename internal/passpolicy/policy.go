// Package passpolicy enforces CheeseWAF admin password rules for setup, API, and CLI.
//
// Policy (new passwords only):
//   - minimum length 10
//   - four character classes: uppercase, lowercase, non-repeating digits, special
//   - at least any 3 of the 4 classes must be present
//   - reject common / sequential weak passwords (e.g. Admin123456)
//   - reject passwords equal to or containing the username (when username is set)
package passpolicy

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
)

const MinLength = 10

// Class requirements: at least this many of the four classes.
const MinClasses = 3

var (
	ErrTooShort        = errors.New("password must contain at least 10 characters")
	ErrNeedClasses     = errors.New("password must include at least 3 of: uppercase, lowercase, non-repeating digits, special characters")
	ErrWeak            = errors.New("password is too common or follows a simple pattern")
	ErrUsernameRelated = errors.New("password must not match or contain the username")
)

// ClassFlags reports which character classes are satisfied.
type ClassFlags struct {
	Upper             bool
	Lower             bool
	NonRepeatingDigit bool
	Special           bool
}

// Count returns how many classes are true.
func (c ClassFlags) Count() int {
	n := 0
	if c.Upper {
		n++
	}
	if c.Lower {
		n++
	}
	if c.NonRepeatingDigit {
		n++
	}
	if c.Special {
		n++
	}
	return n
}

// Validate checks password against the project policy. username may be empty.
func Validate(password, username string) error {
	if len([]rune(password)) < MinLength {
		return ErrTooShort
	}
	if usernameRelated(password, username) {
		return ErrUsernameRelated
	}
	if isWeak(password) {
		return ErrWeak
	}
	if Classify(password).Count() < MinClasses {
		return ErrNeedClasses
	}
	return nil
}

// Classify returns which of the four classes the password satisfies.
func Classify(password string) ClassFlags {
	var flags ClassFlags
	digitSeen := map[rune]int{}
	digitRun := make([]rune, 0, 8)

	for _, r := range password {
		switch {
		case unicode.IsUpper(r) && r <= unicode.MaxASCII:
			flags.Upper = true
		case unicode.IsLower(r) && r <= unicode.MaxASCII:
			flags.Lower = true
		case unicode.IsDigit(r):
			digitSeen[r]++
			digitRun = append(digitRun, r)
		case !unicode.IsLetter(r) && !unicode.IsDigit(r) && !unicode.IsSpace(r):
			flags.Special = true
		}
	}

	if len(digitSeen) > 0 {
		unique := true
		for _, count := range digitSeen {
			if count > 1 {
				unique = false
				break
			}
		}
		if unique && !hasSequentialDigitRun(digitRun, 4) {
			flags.NonRepeatingDigit = true
		}
	}
	return flags
}

func usernameRelated(password, username string) bool {
	username = strings.TrimSpace(username)
	if len(username) < 3 {
		return false
	}
	p := strings.ToLower(password)
	u := strings.ToLower(username)
	return p == u || strings.Contains(p, u)
}

func isWeak(password string) bool {
	lower := strings.ToLower(password)
	// Strip common separators for denylist matching.
	compact := stripNonAlnum(lower)

	for _, bad := range weakExact {
		if lower == bad || compact == bad {
			return true
		}
	}
	for _, bad := range weakContains {
		if strings.Contains(lower, bad) || strings.Contains(compact, bad) {
			return true
		}
	}

	// Pure letter+digit passwords with a long sequential digit block.
	if hasSequentialDigitRun(digitsOnly(password), 5) {
		return true
	}
	// Keyboard-ish runs after lowercasing alnum only.
	if hasKeyboardSequence(compact, 6) {
		return true
	}
	// All same character class repeated (aaaa..., 1111...).
	if isSingleRuneRepeat(password) {
		return true
	}
	return false
}

func stripNonAlnum(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func digitsOnly(password string) []rune {
	out := make([]rune, 0, 8)
	for _, r := range password {
		if unicode.IsDigit(r) {
			out = append(out, r)
		}
	}
	return out
}

// hasSequentialDigitRun reports ascending or descending runs of length >= minLen
// in the digit stream (not necessarily contiguous in original password positions,
// but consecutive in the extracted digit sequence — used for Admin123456).
func hasSequentialDigitRun(digits []rune, minLen int) bool {
	if len(digits) < minLen {
		return false
	}
	asc, desc := 1, 1
	for i := 1; i < len(digits); i++ {
		d0 := int(digits[i-1] - '0')
		d1 := int(digits[i] - '0')
		if d1 == d0+1 {
			asc++
			desc = 1
		} else if d1 == d0-1 {
			desc++
			asc = 1
		} else if d1 == d0 {
			// consecutive same digit breaks "non-repeating" already handled elsewhere
			asc, desc = 1, 1
		} else {
			asc, desc = 1, 1
		}
		if asc >= minLen || desc >= minLen {
			return true
		}
	}
	return false
}

func hasKeyboardSequence(compact string, minLen int) bool {
	if len(compact) < minLen {
		return false
	}
	rows := []string{
		"01234567890",
		"9876543210",
		"qwertyuiop",
		"asdfghjkl",
		"zxcvbnm",
		"abcdefghijklmnopqrstuvwxyz",
	}
	for _, row := range rows {
		if containsRun(compact, row, minLen) || containsRun(compact, reverseASCII(row), minLen) {
			return true
		}
	}
	return false
}

func containsRun(hay, row string, minLen int) bool {
	for i := 0; i+minLen <= len(row); i++ {
		if strings.Contains(hay, row[i:i+minLen]) {
			return true
		}
	}
	return false
}

func reverseASCII(s string) string {
	b := []byte(s)
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return string(b)
}

func isSingleRuneRepeat(password string) bool {
	runes := []rune(password)
	if len(runes) == 0 {
		return true
	}
	first := runes[0]
	for _, r := range runes[1:] {
		if r != first {
			return false
		}
	}
	return true
}

// Explain returns a short operator-facing summary of class coverage (for tests/debug).
func Explain(password string) string {
	c := Classify(password)
	return fmt.Sprintf("classes=%d upper=%v lower=%v non_repeat_digit=%v special=%v",
		c.Count(), c.Upper, c.Lower, c.NonRepeatingDigit, c.Special)
}

// Common weak passwords / stems (lowercase). Exact or contained matches after compacting.
var weakExact = []string{
	"admin123456",
	"admin12345",
	"admin1234",
	"password",
	"password1",
	"password123",
	"passw0rd",
	"1234567890",
	"0123456789",
	"qwerty123",
	"letmein",
	"welcome1",
	"changeme",
	"cheesewaf",
	"root123456",
	"administrator",
}

var weakContains = []string{
	"admin123456",
	"password123",
	"qwertyui",
	"iloveyou",
}
