package hostapi

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

func requireBoundedSessionCall(t *testing.T, session *Session, call func() error, want error) {
	t.Helper()
	result := make(chan error, 1)
	go func() { result <- call() }()
	select {
	case err := <-result:
		if !errors.Is(err, want) {
			t.Fatalf("operation error = %v, want %v", err, want)
		}
	case <-time.After(time.Second):
		_ = session.Close()
		select {
		case <-result:
		case <-time.After(time.Second):
			t.Fatal("operation stayed blocked after Close")
		}
		t.Fatal("stalled peer bypassed operation deadline")
	}
	if !errors.Is(session.Err(), want) {
		t.Fatalf("session error = %v, want %v", session.Err(), want)
	}
}

func TestSessionStartWriteIsBounded(t *testing.T) {
	for _, callerDeadline := range []bool{false, true} {
		name := "ack_timeout"
		if callerDeadline {
			name = "caller_deadline"
		}
		t.Run(name, func(t *testing.T) {
			host, plugin := net.Pipe()
			defer host.Close()
			defer plugin.Close()
			opts := SessionOptions{Identity: testIdentity(), AckTimeout: 30 * time.Millisecond}
			ctx := context.Background()
			want := ErrAckTimeout
			if callerDeadline {
				opts.AckTimeout = time.Second
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 30*time.Millisecond)
				defer cancel()
				want = context.DeadlineExceeded
			}
			session, err := NewSession(host, host, opts)
			if err != nil {
				t.Fatal(err)
			}
			requireBoundedSessionCall(t, session, func() error { return session.Start(ctx) }, want)
		})
	}
}

func TestSessionWritesRespectCallerDeadline(t *testing.T) {
	for _, operation := range []struct {
		name string
		call func(*Session, context.Context) error
	}{
		{"event", func(s *Session, ctx context.Context) error { return s.SendEvent(ctx, json.RawMessage(`{}`)) }},
		{"drain", func(s *Session, ctx context.Context) error { return s.Drain(ctx) }},
		{"shutdown", func(s *Session, ctx context.Context) error { return s.Shutdown(ctx) }},
		{"hint_receipt", func(s *Session, ctx context.Context) error { return s.SendHintReceipt(ctx, 1, true, "") }},
		{"analysis_receipt", func(s *Session, ctx context.Context) error { return s.SendAnalysisReceipt(ctx, 1, true, "") }},
	} {
		t.Run(operation.name, func(t *testing.T) {
			caps := []Capability{CapabilityEventsSubscribe}
			session, _, _, _ := startCapabilitySession(t, SessionOptions{Capabilities: caps}, caps, nil)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
			defer cancel()
			requireBoundedSessionCall(t, session, func() error { return operation.call(session, ctx) }, context.DeadlineExceeded)
		})
	}
}

func TestSessionWriteAndQueueShareAckTimeout(t *testing.T) {
	caps := []Capability{CapabilityEventsSubscribe}
	session, _, _, _ := startCapabilitySession(t, SessionOptions{Capabilities: caps, AckTimeout: 30 * time.Millisecond}, caps, nil)
	results := make(chan error, 2)
	for range 2 {
		go func() { results <- session.SendEvent(context.Background(), json.RawMessage(`{}`)) }()
	}
	for range 2 {
		select {
		case err := <-results:
			if err == nil {
				t.Fatal("stalled peer unexpectedly acknowledged an event")
			}
		case <-time.After(time.Second):
			_ = session.Close()
			t.Fatal("writer or queued writer exceeded AckTimeout")
		}
	}
	if !errors.Is(session.Err(), ErrAckTimeout) {
		t.Fatalf("session error = %v, want ErrAckTimeout", session.Err())
	}
}

func TestSessionTimeoutClosesBlockedOSPipeWrite(t *testing.T) {
	hostOutR, hostOutW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	hostInR, hostInW, err := os.Pipe()
	if err != nil {
		_ = hostOutR.Close()
		_ = hostOutW.Close()
		t.Fatal(err)
	}
	defer hostOutR.Close()
	defer hostOutW.Close()
	defer hostInR.Close()
	defer hostInW.Close()
	session, err := NewSession(hostInR, hostOutW, SessionOptions{
		Identity: testIdentity(), Capabilities: []Capability{CapabilityEventsSubscribe}, AckTimeout: 30 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	go func() {
		hello := readTestFrame(t, bufio.NewReader(hostOutR))
		var payload HelloPayload
		if err := json.Unmarshal(hello.Payload, &payload); err != nil {
			t.Errorf("hello payload: %v", err)
			return
		}
		writeTestFrame(t, hostInW, Frame{Type: FrameReady, SchemaVersion: ProtocolVersion, Payload: mustJSON(t, ReadyPayload{
			Challenge: payload.Challenge, PluginID: "demo", Version: "1.0.0", AcceptedCapabilities: []Capability{CapabilityEventsSubscribe},
		})})
		// Leave hostOutR open without reading any events.
	}()
	if err := session.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	payload := json.RawMessage(`{"data":"` + strings.Repeat("x", 60<<10) + `"}`)
	requireBoundedSessionCall(t, session, func() error { return session.SendEvent(context.Background(), payload) }, ErrAckTimeout)
	select {
	case _, ok := <-session.Results():
		if ok {
			t.Fatal("unexpected result")
		}
	case <-time.After(time.Second):
		t.Fatal("read loop did not exit after cancellation closed the pipes")
	}
}

type shortSessionWriter struct{}

func (shortSessionWriter) Write(data []byte) (int, error) { return len(data) - 1, nil }
func (shortSessionWriter) Close() error                   { return nil }

func TestSessionRejectsShortWrite(t *testing.T) {
	session, err := NewSession(&emptySessionReader{}, shortSessionWriter{}, SessionOptions{Identity: testIdentity()})
	if err != nil {
		t.Fatal(err)
	}
	if err := session.Start(context.Background()); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("start error = %v, want io.ErrShortWrite", err)
	}
}

func TestSessionOneWayRejectsShortWrite(t *testing.T) {
	session, err := NewSession(&emptySessionReader{}, shortSessionWriter{}, SessionOptions{Identity: testIdentity()})
	if err != nil {
		t.Fatal(err)
	}
	session.state = StateReady
	if err := session.Shutdown(context.Background()); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("shutdown error = %v, want io.ErrShortWrite", err)
	}
	if !errors.Is(session.Err(), io.ErrShortWrite) {
		t.Fatalf("session error = %v, want io.ErrShortWrite", session.Err())
	}
}

type emptySessionReader struct{}

func (*emptySessionReader) Read([]byte) (int, error) { return 0, io.EOF }
