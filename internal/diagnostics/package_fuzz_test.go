package diagnostics

import (
	"testing"
)

// FuzzDecodePackage checks the fixed-schema diagnostic decoder. It must reject
// unknown fields, forbidden data and trailing JSON without panicking.
func FuzzDecodePackage(f *testing.F) {
	for _, seed := range []string{
		`{"kind":"metadata","metadata":{"component":"waf"}}`,
		`{"kind":"health","health":{"status":"ok"}}`,
		`{"kind":"sanitized","findings":[{"code":"test","severity":"low","message":"ok"}]}`,
		`{"kind":"raw"}`,
		`{}`,
		`null`,
		`[]`,
		`{"kind":"metadata","unknown":true}`,
		`{"kind":"metadata"} trailing`,
		`{"kind":"metadata","metadata":{"authorization":"secret"}}`,
	} {
		f.Add([]byte(seed))
	}

	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 1<<20 {
			t.Skip()
		}
		pkg, err := DecodePackage(raw)
		if err != nil {
			return
		}
		if !validKind(pkg.Kind) {
			t.Fatalf("accepted invalid kind %q", pkg.Kind)
		}
		if err := scanForbidden(pkg); err != nil {
			t.Fatalf("accepted forbidden package: %v", err)
		}
	})
}
