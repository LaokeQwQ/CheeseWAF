// Package decoder provides safe, bounded decoding helpers for the detection pipeline.
package decoder

import (
	"encoding/base64"
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

func Decode(raw string) Decoded {
	text := raw
	layers := []string{"raw"}
	for i := 0; i < 3; i++ {
		next, err := url.QueryUnescape(text)
		if err != nil || next == text {
			break
		}
		text = next
		layers = append(layers, "url")
	}
	if unescaped := html.UnescapeString(text); unescaped != text {
		text = unescaped
		layers = append(layers, "html")
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
	result := Decode(raw)
	if len(result.Layers) > 1 {
		second := Decode(result.Text)
		if len(second.Layers) > 1 {
			result.Text = second.Text
			result.Layers = append(result.Layers, second.Layers[1:]...)
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
	result := Decode(raw)
	deep := DeepDecode(raw)
	out := []Decoded{result}
	if deep.Text != result.Text {
		out = append(out, deep)
	}
	// Try base64 variants on the deeply decoded result
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		decoded, err := encoding.DecodeString(strings.TrimSpace(deep.Text))
		if err == nil && len(decoded) > 0 && printableRatio(string(decoded)) > 0.7 {
			out = append(out, Decoded{Raw: deep.Text, Layers: append(deep.Layers, "base64"), Text: string(decoded)})
			break
		}
	}
	return out
}
