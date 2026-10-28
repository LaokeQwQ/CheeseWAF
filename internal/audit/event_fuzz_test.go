package audit

import (
	"encoding/json"
	"testing"
	"time"
)

func fuzzValidEvent() []byte {
	event := Event{
		EventID:     "event-1",
		StreamID:    "stream-1",
		TenantID:    "tenant-1",
		Actor:       "user:test",
		Type:        EventTypeAudit,
		Action:      "test",
		Resource:    "resource:test",
		Outcome:     OutcomeSuccess,
		PolicyEpoch: 1,
		Class:       EventClassNormal,
		At:          time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC),
	}
	raw, err := json.Marshal(event)
	if err != nil {
		panic(err)
	}
	return raw
}

// FuzzDecodeEvent checks the strict, metadata-only audit event decoder. It
// must never panic; accepted events must still satisfy validateEvent.
func FuzzDecodeEvent(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`{"event_id":"x"}`))
	f.Add(fuzzValidEvent())

	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 8192 {
			t.Skip()
		}
		event, err := DecodeEvent(raw)
		if err != nil {
			return
		}
		if err := validateEvent(event); err != nil {
			t.Fatalf("accepted event is invalid: %v", err)
		}
	})
}
