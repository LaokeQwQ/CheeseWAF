package hostapi

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestDecodeFrameAcceptsHelloAndEvent(t *testing.T) {
	hello := []byte(`{"type":"hello","schema_version":"cheesewaf-plugin-host/v1","payload":{"plugin_id":"demo"}}`)
	frame, err := DecodeFrame(hello, MaxFrameBytes)
	if err != nil {
		t.Fatalf("hello rejected: %v", err)
	}
	if frame.Type != FrameHello {
		t.Fatalf("type = %q", frame.Type)
	}

	event := []byte(`{"type":"event","schema_version":"cheesewaf-plugin-host/v1","sequence":1,"payload":{"event_id":"evt-1"}}`)
	frame, err = DecodeFrame(event, MaxFrameBytes)
	if err != nil {
		t.Fatalf("event rejected: %v", err)
	}
	if frame.Sequence != 1 {
		t.Fatalf("sequence = %d", frame.Sequence)
	}
}

func TestDecodeFrameRejectsInvalidInputs(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want error
	}{
		{name: "empty", raw: ``, want: ErrInvalidFrame},
		{name: "not object", raw: `[]`, want: ErrInvalidFrame},
		{name: "unknown field", raw: `{"type":"hello","schema_version":"cheesewaf-plugin-host/v1","x":1}`, want: ErrInvalidFrame},
		{name: "duplicate field", raw: `{"type":"hello","type":"ready","schema_version":"cheesewaf-plugin-host/v1"}`, want: ErrDuplicateField},
		{name: "unknown type", raw: `{"type":"wat","schema_version":"cheesewaf-plugin-host/v1"}`, want: ErrUnknownType},
		{name: "missing sequence", raw: `{"type":"event","schema_version":"cheesewaf-plugin-host/v1"}`, want: ErrSequence},
		{name: "trailing", raw: `{"type":"hello","schema_version":"cheesewaf-plugin-host/v1"} trailing`, want: ErrInvalidFrame},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecodeFrame([]byte(tt.raw), MaxFrameBytes)
			if !errors.Is(err, tt.want) {
				t.Fatalf("error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestDecodeFrameRejectsOversize(t *testing.T) {
	raw := []byte(`{"type":"hello","schema_version":"cheesewaf-plugin-host/v1","payload":"` + strings.Repeat("a", 128) + `"}`)
	if _, err := DecodeFrame(raw, 64); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("error = %v, want ErrFrameTooLarge", err)
	}
}

func TestEncodeFrameRoundTrip(t *testing.T) {
	in := Frame{
		Type:          FrameEvent,
		SchemaVersion: ProtocolVersion,
		Sequence:      7,
		Payload:       json.RawMessage(`{"event_id":"evt-7"}`),
	}
	raw, err := EncodeFrame(in, MaxFrameBytes)
	if err != nil {
		t.Fatal(err)
	}
	out, err := DecodeFrame(raw, MaxFrameBytes)
	if err != nil {
		t.Fatal(err)
	}
	if out.Type != in.Type || out.Sequence != in.Sequence {
		t.Fatalf("round trip = %#v", out)
	}
}
