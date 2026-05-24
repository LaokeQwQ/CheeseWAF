package semantic

import (
	"strings"
	"unicode"
)

func normalize(raw string) string {
	raw = strings.ToLower(raw)
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, raw)
}

func tokens(raw string) []string {
	return strings.FieldsFunc(normalize(raw), func(r rune) bool {
		return !(unicode.IsLetter(r) || unicode.IsNumber(r) || r == '_' || r == '-')
	})
}
