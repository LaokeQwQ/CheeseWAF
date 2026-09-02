package decoder

import (
	"encoding/base64"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestDeepDecodeRevealsNestedBase64AndURLPayload(t *testing.T) {
	raw := base64.StdEncoding.EncodeToString([]byte("%3Cscript%3Ealert%281%29%3C%2Fscript%3E"))
	decoded := DeepDecode(raw)
	if decoded.Text != "<script>alert(1)</script>" {
		t.Fatalf("text = %q", decoded.Text)
	}
	if !reflect.DeepEqual(decoded.Layers, []string{"raw", "base64", "url"}) {
		t.Fatalf("layers = %v", decoded.Layers)
	}
}

func TestDeepDecodeRevealsSevenURLLayers(t *testing.T) {
	raw := "<script>alert(1)</script>"
	for range 7 {
		raw = url.QueryEscape(raw)
	}
	decoded := DeepDecode(raw)
	if decoded.Text != "<script>alert(1)</script>" {
		t.Fatalf("text = %q", decoded.Text)
	}
	urlLayers := 0
	for _, layer := range decoded.Layers {
		if layer == "url" {
			urlLayers++
		}
	}
	if urlLayers != 7 {
		t.Fatalf("URL layers = %d, want 7 (%v)", urlLayers, decoded.Layers)
	}
}

func TestDecodeWithDepthUsesDefaultAndHardCeiling(t *testing.T) {
	raw := "<script>"
	for range MaxDecodeDepth + 1 {
		raw = url.QueryEscape(raw)
	}
	if got := DecodeWithDepth(raw, MaxDecodeDepth+100); countLayerNamed(got.Layers, "url") != MaxDecodeDepth {
		t.Fatalf("ceiling layers=%v", got.Layers)
	}
	if got := DecodeWithDepth(raw, 0); countLayerNamed(got.Layers, "url") != DefaultDecodeDepth {
		t.Fatalf("default layers=%v", got.Layers)
	}
}

func TestDecodeWithDepthPreserveControlsRetainsDecodedNUL(t *testing.T) {
	for _, raw := range []string{"before%00after", `before\u0000after`, "before\x00after"} {
		t.Run(raw, func(t *testing.T) {
			preserved := DecodeWithDepthPreserveControls(raw, DefaultDecodeDepth)
			if !strings.ContainsRune(preserved.Text, 0) {
				t.Fatalf("preserved text = %q, want a NUL boundary", preserved.Text)
			}
			legacy := DecodeWithDepth(raw, DefaultDecodeDepth)
			if strings.ContainsRune(legacy.Text, 0) {
				t.Fatalf("legacy text = %q, want historical NUL stripping", legacy.Text)
			}
		})
	}
}

func countLayerNamed(layers []string, name string) int {
	count := 0
	for _, layer := range layers {
		if layer == name {
			count++
		}
	}
	return count
}

func TestDecodeHandlesUnicodeAndMalformedEscapes(t *testing.T) {
	decoded := Decode(`  \u003cscript\x3e\uZZZZ  `)
	if decoded.Text != `<script>\uZZZZ` {
		t.Fatalf("text = %q", decoded.Text)
	}
	if !reflect.DeepEqual(decoded.Layers, []string{"raw", "unicode"}) {
		t.Fatalf("layers = %v", decoded.Layers)
	}
}

func TestTryBase64VariantsAndEmpty(t *testing.T) {
	raw := base64.RawURLEncoding.EncodeToString([]byte("payload?yes"))
	decoded, ok := TryBase64(raw)
	if !ok || decoded != "payload?yes" {
		t.Fatalf("got %q, %v", decoded, ok)
	}
	if decoded, ok := TryBase64(""); ok || decoded != "" {
		t.Fatalf("empty got %q, %v", decoded, ok)
	}
}

func TestDecodeDoesNotPromoteBinaryBase64(t *testing.T) {
	raw := base64.StdEncoding.EncodeToString([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11})
	decoded := Decode(raw)
	if decoded.Text != raw || !reflect.DeepEqual(decoded.Layers, []string{"raw"}) {
		t.Fatalf("decoded = %#v", decoded)
	}
}

func TestDecodeAllAddsPrintableBase64VariantForShortInput(t *testing.T) {
	raw := base64.StdEncoding.EncodeToString([]byte("short text"))
	variants := DecodeAll(raw)
	if len(variants) != 2 || variants[1].Text != "short text" {
		t.Fatalf("variants = %#v", variants)
	}
}

func TestFlattenJSONIncludesNestedKeysAndScalarValues(t *testing.T) {
	flat, err := FlattenJSON([]byte(`{"user":{"name":"alice","active":true},"roles":["admin",2],"none":null}`))
	if err != nil {
		t.Fatalf("FlattenJSON error = %v", err)
	}
	got := strings.Fields(flat)
	sort.Strings(got)
	want := []string{"2", "active", "admin", "alice", "name", "none", "roles", "true", "user"}
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestFlattenJSONReturnsMalformedInputUnchanged(t *testing.T) {
	raw := []byte(`{"unterminated":`)
	got, err := FlattenJSON(raw)
	if err != nil {
		t.Fatalf("FlattenJSON error = %v", err)
	}
	if got != string(raw) {
		t.Fatalf("got %q", got)
	}
}

func TestURLReturnsErrorForMalformedEscape(t *testing.T) {
	got, err := URL("ok%20value%zz")
	if err == nil {
		t.Fatal("error = nil")
	}
	if got != "" {
		t.Fatalf("got %q", got)
	}
}

func TestDecodeStripsNULAfterURLEscape(t *testing.T) {
	decoded := Decode("before%00after")
	if strings.Contains(decoded.Text, "\x00") {
		t.Fatalf("decoded Text still contains NUL: %q", decoded.Text)
	}
	if !strings.Contains(decoded.Text, "before") || !strings.Contains(decoded.Text, "after") {
		t.Fatalf("surrounding payload lost: %q", decoded.Text)
	}
}

func TestDecodeStripsNULAfterHTMLEntity(t *testing.T) {
	for _, raw := range []string{"safe&#0;payload", "safe&#x00;payload", "safe&#x0;payload"} {
		decoded := Decode(raw)
		if strings.Contains(decoded.Text, "\x00") {
			t.Fatalf("Decode(%q) Text still contains NUL: %q", raw, decoded.Text)
		}
		if !strings.Contains(decoded.Text, "safe") || !strings.Contains(decoded.Text, "payload") {
			t.Fatalf("Decode(%q) lost surrounding text: %q", raw, decoded.Text)
		}
	}
}

func TestDecodeStripsNULAfterUnicodeEscape(t *testing.T) {
	for _, raw := range []string{`pre\u0000post`, `pre\x00post`} {
		decoded := Decode(raw)
		if strings.Contains(decoded.Text, "\x00") {
			t.Fatalf("Decode(%q) Text still contains NUL: %q", raw, decoded.Text)
		}
		if !strings.Contains(decoded.Text, "pre") || !strings.Contains(decoded.Text, "post") {
			t.Fatalf("Decode(%q) lost surrounding text: %q", raw, decoded.Text)
		}
	}
}

func TestDeepDecodeAndDecodeAllStripNUL(t *testing.T) {
	raw := "x%00y&#0;z\\u0000w"
	deep := DeepDecode(raw)
	if strings.Contains(deep.Text, "\x00") {
		t.Fatalf("DeepDecode Text still contains NUL: %q", deep.Text)
	}
	for i, v := range DecodeAll(raw) {
		if strings.Contains(v.Text, "\x00") {
			t.Fatalf("DecodeAll[%d] Text still contains NUL: %q", i, v.Text)
		}
	}
}
