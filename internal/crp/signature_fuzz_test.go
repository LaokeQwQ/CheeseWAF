package crp

import (
	"encoding/json"
	"testing"
)

// FuzzParseArchiveSignatures checks the signature-array decoder used by CRP
// archives. It must reject unknown fields and trailing data without panicking.
func FuzzParseArchiveSignatures(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte(`[]`),
		[]byte(`null`),
		[]byte(`{}`),
		[]byte(`[{}]`),
		[]byte(`[{"key_id":"k","algorithm":"ed25519","value":"","signed_at":"2026-10-23T12:00:00Z"}]`),
		[]byte(`[{"key_id":"k","key_id":"k2"}]`),
		[]byte(`[] trailing`),
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		signatures, err := parseArchiveSignatures(data)
		if err != nil {
			return
		}
		if signatures == nil {
			t.Fatal("accepted nil signature slice")
		}
		if _, err := json.Marshal(signatures); err != nil {
			t.Fatalf("accepted signatures cannot be re-encoded: %v", err)
		}
	})
}
