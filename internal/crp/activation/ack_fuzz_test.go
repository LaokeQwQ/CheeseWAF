package activation

import (
	"encoding/json"
	"testing"
)

// FuzzProcessAcknowledgementShape checks the strict wire shape of a sidecar
// acknowledgement frame. Unknown fields, duplicate fields, trailing data and
// non-object payloads must be rejected without panicking.
func FuzzProcessAcknowledgementShape(f *testing.F) {
	for _, seed := range []string{
		`{"schema_version":"cheesewaf-crp-sidecar-process.v1","sequence":1,"operation":"start","status":"ok","mode":"observe"}`,
		`{"schema_version":"cheesewaf-crp-sidecar-process.v1","sequence":1,"operation":"start","status":"error","mode":"observe","error_code":"bad_request"}`,
		`{}`,
		`null`,
		`[]`,
		`{"sequence":1,"sequence":2}`,
		`{"unknown":true}`,
		`{"schema_version":"x"} trailing`,
	} {
		f.Add([]byte(seed))
	}

	f.Fuzz(func(t *testing.T, line []byte) {
		if len(line) > 64<<10 {
			t.Skip()
		}
		if err := validateProcessAcknowledgementShape(line); err != nil {
			return
		}
		var ack processSidecarAcknowledgement
		if err := json.Unmarshal(line, &ack); err != nil {
			t.Fatalf("shape accepted but JSON decode failed: %v", err)
		}
	})
}
