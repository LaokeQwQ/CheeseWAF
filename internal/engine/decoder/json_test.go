package decoder

import (
	"errors"
	"strings"
	"testing"
)

// nestedJSON builds a document whose deepest scalar sits exactly `depth`
// levels below the root, using the given container kind. depth 0 is the bare
// scalar; depth N wraps it in N containers.
func nestedJSON(depth int, kind string) []byte {
	var open, close string
	switch kind {
	case "array":
		open, close = "[", "]"
	case "object":
		open, close = `{"k":`, "}"
	default:
		panic("unknown kind " + kind)
	}
	var b strings.Builder
	b.Grow(depth*(len(open)+len(close)) + 8)
	for i := 0; i < depth; i++ {
		b.WriteString(open)
	}
	b.WriteString(`"leaf"`)
	for i := 0; i < depth; i++ {
		b.WriteString(close)
	}
	return []byte(b.String())
}

// TestFlattenJSONRejectsNestingPastTheLimit pins the depth guard for documents
// that json.Unmarshal still accepts. The standard library only refuses past
// 10000 levels, so everything in 9..10000 is reachable and must be stopped here
// instead. Overshooting documents are returned verbatim alongside the error so
// a caller that mishandles it still hands the full payload to the detector
// rather than a truncated prefix.
func TestFlattenJSONRejectsNestingPastTheLimit(t *testing.T) {
	for _, kind := range []string{"array", "object"} {
		for _, depth := range []int{maxJSONDepth + 1, maxJSONDepth + 2, 100, 1000, 10000} {
			raw := nestedJSON(depth, kind)
			got, err := FlattenJSON(raw)
			if !errors.Is(err, errJSONTooDeep) {
				t.Fatalf("kind=%s depth=%d: err = %v, want errJSONTooDeep", kind, depth, err)
			}
			if got != string(raw) {
				t.Fatalf("kind=%s depth=%d: got %d bytes, want raw passthrough (%d bytes)", kind, depth, len(got), len(raw))
			}
		}
	}
}

// wantFlattened is the exact output nestedJSON(depth, kind) must produce.
// Objects emit one key token per level before descending, arrays emit none, so
// the expected length is itself a check that every level was retained.
func wantFlattened(depth int, kind string) string {
	if kind == "object" {
		return strings.Repeat("k ", depth) + "leaf"
	}
	return "leaf"
}

// TestFlattenJSONAcceptsNestingUpToTheLimit is the no-false-positive half of
// the boundary: legitimate payloads at or below the ceiling still flatten
// completely, with every level retained rather than truncated.
func TestFlattenJSONAcceptsNestingUpToTheLimit(t *testing.T) {
	for _, kind := range []string{"array", "object"} {
		for _, depth := range []int{0, 1, maxJSONDepth - 1, maxJSONDepth} {
			got, err := FlattenJSON(nestedJSON(depth, kind))
			if err != nil {
				t.Fatalf("kind=%s depth=%d: unexpected error %v", kind, depth, err)
			}
			if want := wantFlattened(depth, kind); got != want {
				t.Fatalf("kind=%s depth=%d: got %q, want %q", kind, depth, got, want)
			}
		}
	}
}

// TestFlattenJSONDepthBoundaryIsExact guards against an off-by-one in either
// direction. A ceiling that fires one level early silently drops real payloads;
// one that fires a level late weakens the bound.
func TestFlattenJSONDepthBoundaryIsExact(t *testing.T) {
	for _, kind := range []string{"array", "object"} {
		atLimit, err := FlattenJSON(nestedJSON(maxJSONDepth, kind))
		if err != nil {
			t.Fatalf("kind=%s: depth %d rejected: %v", kind, maxJSONDepth, err)
		}
		if want := wantFlattened(maxJSONDepth, kind); atLimit != want {
			t.Fatalf("kind=%s: depth %d got %q, want %q", kind, maxJSONDepth, atLimit, want)
		}

		raw := nestedJSON(maxJSONDepth+1, kind)
		pastLimit, err := FlattenJSON(raw)
		if !errors.Is(err, errJSONTooDeep) {
			t.Fatalf("kind=%s: depth %d err = %v, want errJSONTooDeep", kind, maxJSONDepth+1, err)
		}
		if pastLimit != string(raw) {
			t.Fatalf("kind=%s: depth %d got %q, want raw passthrough", kind, maxJSONDepth+1, pastLimit)
		}
	}
}

// TestFlattenJSONSurvivesStdlibRejectedNesting covers the outer defense: past
// 10000 levels json.Unmarshal refuses the document, so FlattenJSON returns it
// verbatim. This must stay non-fatal and, critically, must not recurse.
func TestFlattenJSONSurvivesStdlibRejectedNesting(t *testing.T) {
	for _, kind := range []string{"array", "object"} {
		for _, depth := range []int{10001, 200000} {
			raw := nestedJSON(depth, kind)
			got, err := FlattenJSON(raw)
			if err != nil {
				t.Fatalf("kind=%s depth=%d: err = %v", kind, depth, err)
			}
			if got != string(raw) {
				t.Fatalf("kind=%s depth=%d: got %d bytes, want raw passthrough (%d bytes)", kind, depth, len(got), len(raw))
			}
		}
	}
}

// TestFlattenJSONRejectsDeepNestingUnderARealisticRoot proves the guard counts
// total depth, not just a degenerate top-level chain: a payload buried under
// ordinary-looking keys must be caught too.
func TestFlattenJSONRejectsDeepNestingUnderARealisticRoot(t *testing.T) {
	raw := []byte(`{"user":{"profile":{"prefs":` + string(nestedJSON(maxJSONDepth, "object")) + `}}}`)
	if _, err := FlattenJSON(raw); !errors.Is(err, errJSONTooDeep) {
		t.Fatalf("err = %v, want errJSONTooDeep", err)
	}
}

// TestFlattenJSONDoesNotPartiallyFlattenRejectedInput makes sure a rejected
// subtree is never reduced to the fields that happened to fit above the cutoff,
// which would read to a detector as a clean document. The distinguishing mark
// of a partial flatten is that it has lost the original JSON syntax.
func TestFlattenJSONDoesNotPartiallyFlattenRejectedInput(t *testing.T) {
	raw := []byte(`{"safe":"harmless","deep":` + string(nestedJSON(maxJSONDepth+3, "array")) + `}`)
	got, err := FlattenJSON(raw)
	if !errors.Is(err, errJSONTooDeep) {
		t.Fatalf("err = %v, want errJSONTooDeep", err)
	}
	if got != string(raw) {
		t.Fatalf("got %q, want the untouched raw document", got)
	}
	if !strings.Contains(got, `"safe":"harmless"`) {
		t.Fatalf("rejected document lost its original content: %q", got)
	}
}

// TestFlattenJSONDepthCeilingIsEight pins the literal ceiling.
//
// The boundary tests above are all written relative to maxJSONDepth, so they
// hold for any value of it and cannot tell 8 from 64 — mutating the constant
// to either leaves them green. This one is absolute: it is what actually
// enforces the number, and it is the test that fails if someone raises the
// ceiling without meaning to. Keep it in step with maxJSONDepth in
// internal/engine/semantic, which bounds the same bodies inside the analyzer.
func TestFlattenJSONDepthCeilingIsEight(t *testing.T) {
	const want = 8
	if maxJSONDepth != want {
		t.Fatalf("maxJSONDepth = %d, want %d; it must stay equal to maxJSONDepth in internal/engine/semantic", maxJSONDepth, want)
	}
	for _, kind := range []string{"array", "object"} {
		got, err := FlattenJSON(nestedJSON(want, kind))
		if err != nil {
			t.Fatalf("kind=%s: depth %d rejected: %v", kind, want, err)
		}
		if exp := wantFlattened(want, kind); got != exp {
			t.Fatalf("kind=%s: depth %d got %q, want %q", kind, want, got, exp)
		}
		if _, err := FlattenJSON(nestedJSON(want+1, kind)); !errors.Is(err, errJSONTooDeep) {
			t.Fatalf("kind=%s: depth %d err = %v, want errJSONTooDeep", kind, want+1, err)
		}
	}
}

// TestFlattenJSONMalformedInputStaysNilError keeps the pre-existing malformed
// contract separate from the new depth contract: only the depth guard errors.
func TestFlattenJSONMalformedInputStaysNilError(t *testing.T) {
	raw := []byte(`{"unterminated":`)
	got, err := FlattenJSON(raw)
	if err != nil {
		t.Fatalf("err = %v, want nil for malformed input", err)
	}
	if got != string(raw) {
		t.Fatalf("got %q", got)
	}
}
