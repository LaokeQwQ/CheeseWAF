package decoder

import (
	"math/rand"
	"strings"
	"testing"
)

// ungatedEncodedPayloadBattery is looksLikeEncodedPayload without the byte-level
// preconditions. It deliberately reuses the same compiled patterns as production
// so this oracle cannot drift from what it is checking: the only difference
// between the two is the gates themselves.
func ungatedEncodedPayloadBattery(text string) bool {
	return rxBase64Blob.MatchString(text) ||
		rxPercentRun.MatchString(text) ||
		rxEscapeRun.MatchString(text) ||
		rxEntityRun.MatchString(text)
}

// TestEncodedPayloadGateIsSuperset pins the invariant the gates rest on: a gate
// may never answer false where the pattern behind it answers true. This is the
// same class of mistake as fronting a regex battery with a literal pre-filter that
// is not a strict superset, which silently drops attacks.
func TestEncodedPayloadGateIsSuperset(t *testing.T) {
	check := func(t *testing.T, text string) {
		t.Helper()
		want := ungatedEncodedPayloadBattery(text)
		got := looksLikeEncodedPayload(text)
		if got != want {
			t.Errorf("looksLikeEncodedPayload(%q) = %v, ungated battery = %v", text, got, want)
		}
	}

	t.Run("corpus", func(t *testing.T) {
		for _, raw := range decoderCorpus {
			check(t, raw)
			// Also check the post-unescape text, which is what Decode actually
			// feeds the gate in production.
			check(t, Decode(raw).Text)
		}
	})

	t.Run("boundary lengths", func(t *testing.T) {
		// Inputs sitting exactly on and just under each gate's minimum length.
		cases := []string{
			"",
			strings.Repeat("A", 19),
			strings.Repeat("A", 20),
			strings.Repeat("A", 21),
			"%41%42%43",       // 3 units, 9 bytes: under the percent minimum
			"%41%42%43%44",    // 4 units, exactly 12 bytes
			"%41%42%43%44%45", // 5 units
			`\x41\x42`,        // exactly 8 bytes
			`\x41`,            // 1 unit only
			`AB`,
			"&#1;&#2;", // exactly 8 bytes
			"&#1;",     // 1 unit only
			"&#x41;&#x42;",
			"%",
			`\`,
			"&",
		}
		for _, text := range cases {
			check(t, text)
		}
	})

	t.Run("randomized", func(t *testing.T) {
		// Alphabet weighted toward the bytes the gates key on, so the fuzz spends
		// its time near the boundaries rather than on unrelated text.
		alphabet := []rune(`%\&#;0123456789abcdefABCDEF+/=xu <'"select`)
		rng := rand.New(rand.NewSource(20260810))
		var b strings.Builder
		for i := 0; i < 200000; i++ {
			b.Reset()
			n := rng.Intn(28)
			for j := 0; j < n; j++ {
				b.WriteRune(alphabet[rng.Intn(len(alphabet))])
			}
			check(t, b.String())
		}
	})
}

// The gated and ungated forms are both live in this binary, so the pair below
// measures the gates directly instead of comparing across builds.
var encodedGateBenchInputs = []struct {
	name string
	text string
}{
	{"CleanQuery", "/api/v2/orders?status=shipped&region=emea&sort=created_at&page=3"},
	{"CleanProse", "The quarterly report shows a modest increase in retained users."},
	{"PercentEncoded", "%3Cscript%3Ealert%281%29%3C%2Fscript%3E"},
	{"Base64Blob", "PD9waHAgQGV2YWwoJF9QT1NUWydjJ10pOyA/Pg=="},
}

func BenchmarkEncodedPayloadGate(b *testing.B) {
	for _, tc := range encodedGateBenchInputs {
		b.Run(tc.name+"/gated", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_ = looksLikeEncodedPayload(tc.text)
			}
		})
		b.Run(tc.name+"/ungated", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_ = ungatedEncodedPayloadBattery(tc.text)
			}
		})
	}
}
