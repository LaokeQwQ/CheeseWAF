// Package decoder provides safe, bounded decoding helpers for the detection pipeline.
package decoder

import (
	"net/url"
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
	text = strings.TrimSpace(text)
	return Decoded{Raw: raw, Layers: layers, Text: text}
}
