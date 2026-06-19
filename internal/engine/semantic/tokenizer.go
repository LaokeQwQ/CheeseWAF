package semantic

import (
	"strings"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

// normalize applies NFKC normalization (compatibility decomposition + composition)
// to defeat homoglyph/confusable attacks (Cyrillic а → Latin a, etc.),
// then lowercases and strips control characters.
func normalize(raw string) string {
	// NFKC normalizes Unicode confusables: fullwidth → ASCII, superscript → plain, etc.
	normalized := norm.NFKC.String(raw)
	normalized = strings.ToLower(normalized)
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, normalized)
}

func tokens(raw string) []string {
	return strings.FieldsFunc(normalize(raw), func(r rune) bool {
		return !(unicode.IsLetter(r) || unicode.IsNumber(r) || r == '_' || r == '-')
	})
}

// NFKCNormalize is the public version used by external packages.
func NFKCNormalize(raw string) string {
	return normalize(raw)
}
