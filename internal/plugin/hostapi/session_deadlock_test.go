package hostapi

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// blockingWriteCloser models a plugin that stopped reading its pipe: Write
// blocks until the connection is closed. The negotiated deadline must still
// release the caller.
type blockingWriteCloser struct {
	released chan struct{}
	once     sync.Once
}

func newBlockingWriteCloser() *blockingWriteCloser {
	return &blockingWriteCloser{released: make(chan struct{})}
}

func (b *blockingWriteCloser) Write([]byte) (int, error) {
	<-b.released
	return 0, io.ErrClosedPipe
}

func (b *blockingWriteCloser) Close() error {
	b.once.Do(func() { close(b.released) })
	return nil
}

func decodeTestFrame(reader *bufio.Reader) (Frame, error) {
	line, err := reader.ReadSlice('\n')
	if err != nil {
		return Frame{}, err
	}
	return DecodeFrame(line[:len(line)-1], MaxFrameBytes)
}

func TestSessionStartReleasesBlockedWriteOnDeadline(t *testing.T) {
	hostInR, hostInW := io.Pipe()
	t.Cleanup(func() { _ = hostInR.Close(); _ = hostInW.Close() })

	session, err := NewSession(hostInR, newBlockingWriteCloser(), SessionOptions{
		Identity: testIdentity(), Capabilities: []Capability{CapabilityEventsSubscribe},
		Challenge: []byte("c"), AckTimeout: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	started := time.Now()
	err = session.Start(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("start error = %v, want context.DeadlineExceeded", err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("blocked write returned after %s", elapsed)
	}
}

// A plugin reports a failed handler as accepted:false on a matching ack frame.
// Treating that as success would make the host believe a rejected event or
// config was applied.
func TestSessionSendEventReturnsRejectedAck(t *testing.T) {
	hostInR, hostInW := io.Pipe()
	hostOutR, hostOutW := io.Pipe()
	t.Cleanup(func() {
		_ = hostInR.Close()
		_ = hostInW.Close()
		_ = hostOutR.Close()
		_ = hostOutW.Close()
	})

	session, err := NewSession(hostInR, hostOutW, SessionOptions{
		Identity: testIdentity(), Capabilities: []Capability{CapabilityEventsSubscribe},
		Challenge: []byte("c"), AckTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		reader := bufio.NewReader(hostOutR)
		if _, err := reader.ReadSlice('\n'); err != nil {
			return
		}
		writeTestFrame(t, hostInW, Frame{
			Type: FrameReady, SchemaVersion: ProtocolVersion,
			Payload: mustJSON(t, ReadyPayload{Challenge: "Yw==", PluginID: "demo", Version: "1.0.0", AcceptedCapabilities: []Capability{CapabilityEventsSubscribe}}),
		})
		event, err := decodeTestFrame(reader)
		if err != nil {
			return
		}
		writeTestFrame(t, hostInW, Frame{
			Type: FrameEventAck, SchemaVersion: ProtocolVersion, Sequence: event.Sequence,
			Payload: json.RawMessage(`{"sequence":` + strconv.FormatUint(event.Sequence, 10) + `,"accepted":false,"error_code":"plugin_error"}`),
		})
	}()
	if err := session.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	err = session.SendEvent(context.Background(), json.RawMessage(`{"event_id":"e"}`))
	if !errors.Is(err, ErrAckRejected) {
		t.Fatalf("send error = %v, want ErrAckRejected", err)
	}
	if !strings.Contains(err.Error(), "plugin_error") {
		t.Fatalf("error must carry the plugin code, got %v", err)
	}
}

func TestSessionSendEventAcceptsOkAck(t *testing.T) {
	hostInR, hostInW := io.Pipe()
	hostOutR, hostOutW := io.Pipe()
	t.Cleanup(func() {
		_ = hostInR.Close()
		_ = hostInW.Close()
		_ = hostOutR.Close()
		_ = hostOutW.Close()
	})

	session, err := NewSession(hostInR, hostOutW, SessionOptions{
		Identity: testIdentity(), Capabilities: []Capability{CapabilityEventsSubscribe},
		Challenge: []byte("c"), AckTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		reader := bufio.NewReader(hostOutR)
		if _, err := reader.ReadSlice('\n'); err != nil {
			return
		}
		writeTestFrame(t, hostInW, Frame{
			Type: FrameReady, SchemaVersion: ProtocolVersion,
			Payload: mustJSON(t, ReadyPayload{Challenge: "Yw==", PluginID: "demo", Version: "1.0.0", AcceptedCapabilities: []Capability{CapabilityEventsSubscribe}}),
		})
		event, err := decodeTestFrame(reader)
		if err != nil {
			return
		}
		writeTestFrame(t, hostInW, Frame{
			Type: FrameEventAck, SchemaVersion: ProtocolVersion, Sequence: event.Sequence,
			Payload: json.RawMessage(`{"sequence":` + strconv.FormatUint(event.Sequence, 10) + `,"accepted":true}`),
		})
	}()
	if err := session.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := session.SendEvent(context.Background(), json.RawMessage(`{"event_id":"e"}`)); err != nil {
		t.Fatalf("accepted ack returned %v", err)
	}
}
