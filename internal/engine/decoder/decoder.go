// Package decoder provides safe, bounded decoding helpers for the detection pipeline.
package decoder

import (
	"html"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

type Decoded struct {
	Raw    string
	Layers []string
	Text   string
}

// queryUnescapeReference and htmlUnescapeReference are the ungated primitives.
// Decode calls them behind cheap byte gates; the equivalence test calls them
// directly as the oracle, and also pins that the gates are exact.
func queryUnescapeReference(text string) (string, error) { return url.QueryUnescape(text) }
func htmlUnescapeReference(text string) string           { return html.UnescapeString(text) }

func Decode(raw string) Decoded {
	text := raw
	layers := []string{"raw"}
	for i := 0; i < 3; i++ {
		// QueryUnescape can only transform '%' escapes and '+'. Without either
		// byte it returns (text, nil) unchanged, so the loop would break on the
		// next == text check anyway. Skipping the call avoids net/url.unescape,
		// which profiled as the single hottest leaf in the analyzer benchmark.
		if !strings.ContainsAny(text, "%+") {
			break
		}
		next, err := url.QueryUnescape(text)
		if err != nil || next == text {
			break
		}
		text = next
		layers = append(layers, "url")
	}
	// Every HTML entity begins with '&', so without one UnescapeString is a
	// no-op and its scan is pure cost.
	if strings.IndexByte(text, '&') >= 0 {
		if unescaped := html.UnescapeString(text); unescaped != text {
			text = unescaped
			layers = append(layers, "html")
		}
	}
	if looksLikeEncodedPayload(text) {
		if b64, ok := TryBase64(strings.TrimSpace(text)); ok && printableRatio(b64) > 0.65 {
			text = b64
			layers = append(layers, "base64")
		}
	}
	if unescaped, changed := unescapeUnicode(text); changed {
		text = unescaped
		layers = append(layers, "unicode")
	}
	text = strings.TrimSpace(text)
	return Decoded{Raw: raw, Layers: layers, Text: text}
}

// DeepDecode performs aggressive multi-layer decoding to reveal obfuscated payloads.
func DeepDecode(raw string) Decoded {
	return deepDecodeFrom(Decode(raw))
}

// deepDecodeFrom is DeepDecode's second pass over an already-computed first
// pass. DecodeAll needs both the shallow and deep result, and previously got
// them by decoding raw twice; this lets it decode once and share.
func deepDecodeFrom(result Decoded) Decoded {
	if len(result.Layers) > 1 {
		second := Decode(result.Text)
		if len(second.Layers) > 1 {
			// Layers is shared with the caller's copy of the shallow result, so
			// append must not write into its backing array.
			merged := make([]string, 0, len(result.Layers)+len(second.Layers)-1)
			merged = append(merged, result.Layers...)
			merged = append(merged, second.Layers[1:]...)
			result.Text = second.Text
			result.Layers = merged
		}
	}
	return result
}

var unicodeEscPattern = regexp.MustCompile(`\\(?:u([0-9a-fA-F]{4})|x([0-9a-fA-F]{2}))`)

func unescapeUnicode(raw string) (string, bool) {
	if !strings.Contains(raw, `\u`) && !strings.Contains(raw, `\x`) {
		return raw, false
	}
	changed := false
	out := unicodeEscPattern.ReplaceAllStringFunc(raw, func(match string) string {
		parts := unicodeEscPattern.FindStringSubmatch(match)
		hex := parts[1]
		if hex == "" {
			hex = parts[2]
		}
		value, err := strconv.ParseInt(hex, 16, 32)
		if err != nil {
			return match
		}
		changed = true
		return string(rune(value))
	})
	return out, changed
}

var encodedPayloadPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)^[a-z0-9+/=]{20,}$`),
	regexp.MustCompile(`(?i)(?:%[0-9a-f]{2}){4,}`),
	regexp.MustCompile(`(?i)(?:(?:\\u[0-9a-f]{4}|\\x[0-9a-f]{2}){2,})`),
	regexp.MustCompile(`(?i)(?:&#x?[0-9a-f]+;){2,}`),
}

func looksLikeEncodedPayload(text string) bool {
	for _, p := range encodedPayloadPatterns {
		if p.MatchString(text) {
			return true
		}
	}
	return false
}

func printableRatio(text string) float64 {
	if len(text) == 0 {
		return 0
	}
	printable := 0
	for _, r := range text {
		if (r >= 0x20 && r < 0x7f) || r == '\n' || r == '\r' || r == '\t' {
			printable++
		}
	}
	return float64(printable) / float64(len(text))
}

// DecodeAll returns multiple decode variants for thorough scanning.
func DecodeAll(raw string) []Decoded {
	// One shallow pass, shared. DeepDecode(raw) used to redo Decode(raw) from
	// scratch, so every candidate paid the whole url/html/base64/unicode chain
	// twice. sqlCandidateTexts calls this per segment per field, which made it
	// the top cumulative cost in the analyzer profile.
	result := Decode(raw)
	deep := deepDecodeFrom(result)
	out := make([]Decoded, 0, 3)
	out = append(out, result)
	if deep.Text != result.Text {
		out = append(out, deep)
	}
	// Try base64 variants on the deeply decoded result
	trimmedDeep := strings.TrimSpace(deep.Text)
	for _, encoding := range base64Encodings {
		decoded, err := encoding.DecodeString(trimmedDeep)
		if err == nil && len(decoded) > 0 && printableRatio(string(decoded)) > 0.7 {
			layers := make([]string, 0, len(deep.Layers)+1)
			layers = append(layers, deep.Layers...)
			layers = append(layers, "base64")
			out = append(out, Decoded{Raw: deep.Text, Layers: layers, Text: string(decoded)})
			break
		}
	}
	return out
}
