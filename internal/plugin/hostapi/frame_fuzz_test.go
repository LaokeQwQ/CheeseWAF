package hostapi

import "testing"

// FuzzDecodeFrame checks the strict frame decoder. It must never panic and
// must not accept a frame with an unknown type or invalid schema version.
func FuzzDecodeFrame(f *testing.F) {
	for _, seed := range []string{
		`{"type":"hello","schema_version":"cheesewaf-plugin-host/v1"}`,
		`{"type":"event","schema_version":"cheesewaf-plugin-host/v1","sequence":1,"payload":{}}`,
		`{"type":"unknown"}`,
		`{"type":"event","schema_version":"cheesewaf-plugin-host/v1","sequence":1,"sequence":2}`,
		`{}`,
		`null`,
		`[]`,
		`{"type":"hello","schema_version":"cheesewaf-plugin-host/v1"} trailing`,
	} {
		f.Add([]byte(seed))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > MaxFrameBytes+1 {
			t.Skip()
		}
		frame, err := DecodeFrame(data, MaxFrameBytes)
		if err != nil {
			return
		}
		if !frame.Type.Valid() {
			t.Fatalf("accepted invalid type %q", frame.Type)
		}
		if frame.SchemaVersion != ProtocolVersion {
			t.Fatalf("accepted invalid schema %q", frame.SchemaVersion)
		}
		if frame.Type.NeedsSequence() && frame.Sequence == 0 {
			t.Fatal("accepted missing sequence")
		}
	})
}
