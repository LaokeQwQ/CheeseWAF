package hostapi

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"testing"
	"time"
)

func testIdentity() Identity {
	return Identity{PluginID: "demo", Namespace: "official/demo", Version: "1.0.0", ManifestIdentity: "m", ArtifactIdentity: "a"}
}

func readTestFrame(t *testing.T, reader *bufio.Reader) Frame {
	t.Helper()
	line, err := reader.ReadSlice('\n')
	if err != nil {
		t.Fatalf("read frame: %v", err)
	}
	frame, err := DecodeFrame(line[:len(line)-1], MaxFrameBytes)
	if err != nil {
		t.Fatalf("decode frame: %v", err)
	}
	return frame
}

func writeTestFrame(t *testing.T, writer io.Writer, frame Frame) {
	t.Helper()
	raw, err := EncodeFrame(frame, MaxFrameBytes)
	if err != nil {
		t.Fatalf("encode frame: %v", err)
	}
	if _, err := writer.Write(append(raw, '\n')); err != nil {
		t.Fatalf("write frame: %v", err)
	}
}

func TestSessionHandshakeEventAndHint(t *testing.T) {
	hostInR, hostInW := io.Pipe()
	hostOutR, hostOutW := io.Pipe()
	t.Cleanup(func() {
		_ = hostInR.Close()
		_ = hostInW.Close()
		_ = hostOutR.Close()
		_ = hostOutW.Close()
	})

	session, err := NewSession(hostInR, hostOutW, SessionOptions{
		Identity:     testIdentity(),
		Capabilities: []Capability{CapabilityEventsSubscribe, CapabilityHintsSubmit, CapabilityHealth},
		Challenge:    []byte("challenge"),
		AckTimeout:   2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}

	pluginDone := make(chan struct{})
	go func() {
		defer close(pluginDone)
		reader := bufio.NewReader(hostOutR)
		hello := readTestFrame(t, reader)
		if hello.Type != FrameHello {
			t.Errorf("first frame = %s", hello.Type)
			return
		}
		var helloPayload HelloPayload
		if err := json.Unmarshal(hello.Payload, &helloPayload); err != nil {
			t.Errorf("hello payload: %v", err)
			return
		}
		writeTestFrame(t, hostInW, Frame{
			Type: FrameReady, SchemaVersion: ProtocolVersion,
			Payload: mustJSON(t, ReadyPayload{
				Challenge: helloPayload.Challenge, PluginID: "demo", Version: "1.0.0",
				AcceptedCapabilities: []Capability{CapabilityEventsSubscribe, CapabilityHintsSubmit, CapabilityHealth},
			}),
		})
		event := readTestFrame(t, reader)
		if event.Type != FrameEvent {
			t.Errorf("event frame = %s", event.Type)
			return
		}
		writeTestFrame(t, hostInW, Frame{Type: FrameEventAck, SchemaVersion: ProtocolVersion, Sequence: event.Sequence})
		writeTestFrame(t, hostInW, Frame{
			Type: FrameHint, SchemaVersion: ProtocolVersion, Sequence: 1,
			Payload: json.RawMessage(`{"hint_id":"hint-1"}`),
		})
		receipt := readTestFrame(t, reader)
		if receipt.Type != FrameHintReceipt {
			t.Errorf("receipt frame = %s", receipt.Type)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := session.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := session.SendEvent(ctx, json.RawMessage(`{"event_id":"evt-1"}`)); err != nil {
		t.Fatalf("send event: %v", err)
	}
	select {
	case result := <-session.Results():
		if result.Kind != ResultHint || result.Sequence != 1 {
			t.Fatalf("result = %#v", result)
		}
		if err := session.SendHintReceipt(ctx, result.Sequence, true, ""); err != nil {
			t.Fatalf("send receipt: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for hint result")
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-pluginDone:
	case <-time.After(time.Second):
		t.Fatal("plugin goroutine did not exit")
	}
}

func TestSessionRejectsWrongChallenge(t *testing.T) {
	hostInR, hostInW := io.Pipe()
	hostOutR, hostOutW := io.Pipe()
	defer hostInR.Close()
	defer hostInW.Close()
	defer hostOutR.Close()
	defer hostOutW.Close()

	session, err := NewSession(hostInR, hostOutW, SessionOptions{
		Identity: testIdentity(), Capabilities: []Capability{CapabilityEventsSubscribe},
		Challenge: []byte("expected"), AckTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		reader := bufio.NewReader(hostOutR)
		_ = readTestFrame(t, reader)
		writeTestFrame(t, hostInW, Frame{
			Type: FrameReady, SchemaVersion: ProtocolVersion,
			Payload: mustJSON(t, ReadyPayload{Challenge: "wrong", PluginID: "demo", Version: "1.0.0", AcceptedCapabilities: []Capability{CapabilityEventsSubscribe}}),
		})
	}()
	err = session.Start(context.Background())
	if !errors.Is(err, ErrHandshake) {
		t.Fatalf("start error = %v, want ErrHandshake", err)
	}
}

func TestSessionRejectsCapabilityEscalation(t *testing.T) {
	hostInR, hostInW := io.Pipe()
	hostOutR, hostOutW := io.Pipe()
	defer hostInR.Close()
	defer hostInW.Close()
	defer hostOutR.Close()
	defer hostOutW.Close()

	session, err := NewSession(hostInR, hostOutW, SessionOptions{
		Identity: testIdentity(), Capabilities: []Capability{CapabilityEventsSubscribe},
		Challenge: []byte("c"), AckTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		reader := bufio.NewReader(hostOutR)
		_ = readTestFrame(t, reader)
		writeTestFrame(t, hostInW, Frame{
			Type: FrameReady, SchemaVersion: ProtocolVersion,
			Payload: mustJSON(t, ReadyPayload{Challenge: "Yw==", PluginID: "demo", Version: "1.0.0", AcceptedCapabilities: []Capability{CapabilityHintsSubmit}}),
		})
	}()
	err = session.Start(context.Background())
	if !errors.Is(err, ErrHandshake) {
		t.Fatalf("start error = %v, want ErrHandshake", err)
	}
}

func TestSessionEventAckTimeout(t *testing.T) {
	hostInR, hostInW := io.Pipe()
	hostOutR, hostOutW := io.Pipe()
	defer hostInR.Close()
	defer hostInW.Close()
	defer hostOutR.Close()
	defer hostOutW.Close()

	session, err := NewSession(hostInR, hostOutW, SessionOptions{
		Identity: testIdentity(), Capabilities: []Capability{CapabilityEventsSubscribe},
		Challenge: []byte("c"), AckTimeout: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		reader := bufio.NewReader(hostOutR)
		_ = readTestFrame(t, reader)
		writeTestFrame(t, hostInW, Frame{
			Type: FrameReady, SchemaVersion: ProtocolVersion,
			Payload: mustJSON(t, ReadyPayload{Challenge: "Yw==", PluginID: "demo", Version: "1.0.0", AcceptedCapabilities: []Capability{CapabilityEventsSubscribe}}),
		})
		_ = readTestFrame(t, reader) // consume event, never ack
	}()
	if err := session.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	err = session.SendEvent(context.Background(), json.RawMessage(`{"event_id":"e"}`))
	if !errors.Is(err, ErrAckTimeout) {
		t.Fatalf("send error = %v, want ErrAckTimeout", err)
	}
}

func mustJSON(t *testing.T, value any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
