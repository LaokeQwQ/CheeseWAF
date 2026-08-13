package semantic

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"sort"
	"strings"
	"testing"
)

// normalizeInputs sorts InputPoints so the byte walker (document order) can be
// compared against the decoder walk (Go map iteration order is randomized).
func normalizeInputs(in []InputPoint) []string {
	out := make([]string, 0, len(in))
	for _, ip := range in {
		out = append(out, fmt.Sprintf("%s\x00%s\x00%s\x00%v", ip.Source, ip.Name, ip.Raw, ip.Layers))
	}
	sort.Strings(out)
	return out
}

func flattenViaFast(t *testing.T, body string) []InputPoint {
	t.Helper()
	var got []InputPoint
	flattenJSONInputs("body.json", "", []byte(body), &got)
	return got
}

func flattenViaDecoder(t *testing.T, body string) []InputPoint {
	t.Helper()
	var want []InputPoint
	flattenJSONInputsDecode("body.json", "", []byte(body), &want)
	return want
}

// assertSameFlattening is the core differential assertion: for any body, the
// production entry point must produce the same InputPoint multiset as the
// decoder-backed walk it replaced.
func assertSameFlattening(t *testing.T, body string) {
	t.Helper()
	got := normalizeInputs(flattenViaFast(t, body))
	want := normalizeInputs(flattenViaDecoder(t, body))
	if len(got) != len(want) {
		t.Fatalf("input count mismatch for %q:\n fast=%d %v\n dec =%d %v",
			body, len(got), got, len(want), want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("input mismatch for %q at %d:\n fast=%q\n dec =%q", body, i, got[i], want[i])
		}
	}
}

func TestJSONWalkerMatchesDecoderCurated(t *testing.T) {
	bodies := []string{
		// Shapes the fast path handles.
		`{}`,
		`[]`,
		`{"a":"b"}`,
		`{"q":"1 un/**/ion sel/**/ect password from users"}`,
		`{"a":1,"b":2.5,"c":-3,"d":1e10,"e":-1.5E-3,"f":0}`,
		`{"t":true,"f":false,"n":null}`,
		`{"nested":{"deep":{"deeper":"value"}}}`,
		`{"arr":["a","b","c"]}`,
		`{"arr":[{"k":"v"},{"k2":"v2"}]}`,
		`[1,2,3]`,
		`["x"]`,
		`"bare string"`,
		`123`,
		`true`,
		`null`,
		`  {  "spaced"  :  "out"  }  `,
		"{\n\t\"tabbed\": \"value\"\n}",
		`{"empty":"","zero":0}`,
		`{"a":{"b":[{"c":[1,2,{"d":"e"}]}]}}`,
		`{"username":{"$ne":null},"password":{"$ne":null}}`,
		`{"text":"MongoDB docs mention $ne, $regex, and $where operators."}`,

		// Shapes that MUST fall back to the decoder.
		`{"esc":"line\nbreak"}`,
		`{"esc":"quote\"inside"}`,
		`{"esc":"back\\slash"}`,
		`{"esc":"tab\there"}`,
		`{"uni":"\u0041\u00e9"}`,
		`{"uni":"\ud83d\ude00"}`,
		`{"nonascii":"héllo wörld"}`,
		`{"nonascii":"日本語"}`,
		`{"key\nwith":"escape"}`,
		`{"emoji":"😀"}`,

		// Malformed / edge: both paths must agree (decoder emits nothing).
		`{`,
		`}`,
		`{"a":}`,
		`{"a" "b"}`,
		`{"a":1,}`,
		`[1,]`,
		`{"a":1} trailing`,
		`01`,
		`+1`,
		`.5`,
		`1.`,
		`1e`,
		`-`,
		``,
		`   `,
		`tru`,
		`nul`,
		`"unterminated`,
		`{"a":01}`,
		`{"a":.5}`,
		`[[[[[[[[[[1]]]]]]]]]]`,
		`{"a":{"b":{"c":{"d":{"e":{"f":{"g":{"h":{"i":{"j":"deep"}}}}}}}}}}`,
	}
	for _, body := range bodies {
		assertSameFlattening(t, body)
	}
}

// TestJSONWalkerFallsBackOnEscapes pins the intended division of labour: bodies
// with escapes or non-ASCII bytes must be handled by the decoder, not guessed at
// by the byte walker.
func TestJSONWalkerFallsBackOnEscapes(t *testing.T) {
	cases := []string{
		`{"a":"has\ttab"}`,
		`{"a":"\u0041"}`,
		`{"a":"héllo"}`,
	}
	for _, body := range cases {
		var sink []InputPoint
		w := jsonWalker{src: []byte(body), source: "body.json", inputs: &sink}
		if w.value("", 0, false) && w.pos == len(body) {
			t.Fatalf("expected byte walker to decline %q, but it claimed success", body)
		}
		// The production entry point must still produce decoder-quality output.
		assertSameFlattening(t, body)
	}
}

// TestJSONWalkerBudgetParity drives both paths past the node/candidate budgets.
// Which fields survive truncation depends on iteration order (already randomized
// in the decoder path via Go map ordering), so this asserts the invariant that
// actually matters: neither path exceeds the caps.
func TestJSONWalkerBudgetParity(t *testing.T) {
	var sb strings.Builder
	sb.WriteByte('{')
	for i := 0; i < 400; i++ {
		if i > 0 {
			sb.WriteByte(',')
		}
		fmt.Fprintf(&sb, `"k%d":"v%d"`, i, i)
	}
	sb.WriteByte('}')
	body := sb.String()

	fast := flattenViaFast(t, body)
	dec := flattenViaDecoder(t, body)
	if len(fast) > maxCandidates {
		t.Fatalf("fast path exceeded maxCandidates: %d > %d", len(fast), maxCandidates)
	}
	if len(dec) > maxCandidates {
		t.Fatalf("decoder path exceeded maxCandidates: %d > %d", len(dec), maxCandidates)
	}
	if len(fast) != len(dec) {
		t.Fatalf("truncated input count differs: fast=%d dec=%d", len(fast), len(dec))
	}
	// Deep array nesting exercises the depth cap on both paths.
	deep := strings.Repeat(`[`, 40) + `"x"` + strings.Repeat(`]`, 40)
	fastDeep := flattenViaFast(t, deep)
	decDeep := flattenViaDecoder(t, deep)
	if len(fastDeep) != len(decDeep) {
		t.Fatalf("deep nesting count differs: fast=%d dec=%d", len(fastDeep), len(decDeep))
	}
}

func TestLargeEscapedJSONUsesBoundedStreamingTailCoverage(t *testing.T) {
	var body strings.Builder
	body.Grow(maxJSONTreeDecodeBytes + 4096)
	body.WriteByte('{')
	for i := 0; body.Len() <= maxJSONTreeDecodeBytes+1024; i++ {
		if i > 0 {
			body.WriteByte(',')
		}
		fmt.Fprintf(&body, `"field_%05d":"ordinary\u0020value"`, i)
	}
	body.WriteString(`,"cmd":"; whoami"}`)

	inputs := flattenViaFast(t, body.String())
	if len(inputs) > maxCandidates {
		t.Fatalf("streaming fallback retained %d inputs, max %d", len(inputs), maxCandidates)
	}
	found := false
	for _, input := range inputs {
		if input.Name == "cmd" && input.Raw == "; whoami" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("streaming fallback dropped the late attack field")
	}
}

// TestJSONWalkerMatchesDecoderRandom is a deterministic randomized differential
// run over generated JSON documents, including bodies the walker must decline.
func TestJSONWalkerMatchesDecoderRandom(t *testing.T) {
	rng := rand.New(rand.NewSource(20260809))
	for i := 0; i < 4000; i++ {
		body := randomJSON(rng, 0)
		// Only compare documents encoding/json itself accepts plus a slice of
		// mutated ones; both paths must agree either way.
		assertSameFlattening(t, body)
		if i%4 == 0 {
			assertSameFlattening(t, mutateJSON(rng, body))
		}
	}
}

func randomJSON(rng *rand.Rand, depth int) string {
	if depth > 4 {
		return randomJSONScalar(rng)
	}
	switch rng.Intn(6) {
	case 0, 1:
		n := rng.Intn(4)
		parts := make([]string, 0, n)
		for i := 0; i < n; i++ {
			parts = append(parts, fmt.Sprintf("%s:%s",
				randomJSONString(rng), randomJSON(rng, depth+1)))
		}
		return "{" + strings.Join(parts, ",") + "}"
	case 2:
		n := rng.Intn(4)
		parts := make([]string, 0, n)
		for i := 0; i < n; i++ {
			parts = append(parts, randomJSON(rng, depth+1))
		}
		return "[" + strings.Join(parts, ",") + "]"
	default:
		return randomJSONScalar(rng)
	}
}

func randomJSONScalar(rng *rand.Rand) string {
	switch rng.Intn(8) {
	case 0:
		return "true"
	case 1:
		return "false"
	case 2:
		return "null"
	case 3:
		return fmt.Sprintf("%d", rng.Intn(2000)-1000)
	case 4:
		return fmt.Sprintf("%.3f", (rng.Float64()-0.5)*1000)
	case 5:
		return fmt.Sprintf("%de%d", rng.Intn(9)+1, rng.Intn(6))
	default:
		return randomJSONString(rng)
	}
}

// randomJSONString deliberately mixes plain ASCII (fast path) with escapes and
// multi-byte runes (must fall back), always emitting valid JSON via Marshal.
func randomJSONString(rng *rand.Rand) string {
	alphabets := []string{
		"abcdefghijklmnopqrstuvwxyz0123456789-_. ",
		"abc\"\\\n\t\r",
		"héllo wörld 日本語 😀",
		"<script>alert(1)</script> 1' or 1=1-- /etc/passwd",
		"$ne $where {{7*7}} ../../ %2e%2e",
	}
	alpha := []rune(alphabets[rng.Intn(len(alphabets))])
	n := rng.Intn(12)
	var sb strings.Builder
	for i := 0; i < n; i++ {
		sb.WriteRune(alpha[rng.Intn(len(alpha))])
	}
	encoded, err := json.Marshal(sb.String())
	if err != nil {
		return `""`
	}
	return string(encoded)
}

// mutateJSON corrupts a document so malformed input is exercised too; both paths
// must still agree (typically by both emitting nothing).
func mutateJSON(rng *rand.Rand, body string) string {
	if body == "" {
		return body
	}
	b := []byte(body)
	switch rng.Intn(4) {
	case 0:
		return string(b[:rng.Intn(len(b))])
	case 1:
		i := rng.Intn(len(b))
		return string(b[:i]) + string(b[i+1:])
	case 2:
		i := rng.Intn(len(b))
		junk := []byte{'{', '}', '[', ']', ',', ':', '"', 'x', '\\'}
		return string(b[:i]) + string(junk[rng.Intn(len(junk))]) + string(b[i:])
	default:
		return body + " trailing"
	}
}
