package decoder

import (
	"encoding/base64"
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
	got := strings.Fields(FlattenJSON([]byte(`{"user":{"name":"alice","active":true},"roles":["admin",2],"none":null}`)))
	sort.Strings(got)
	want := []string{"2", "active", "admin", "alice", "name", "none", "roles", "true", "user"}
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestFlattenJSONReturnsMalformedInputUnchanged(t *testing.T) {
	raw := []byte(`{"unterminated":`)
	if got := FlattenJSON(raw); got != string(raw) {
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
