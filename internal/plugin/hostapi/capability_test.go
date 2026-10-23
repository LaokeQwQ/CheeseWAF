package hostapi

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"testing"
	"time"
)

func startCapabilitySession(t *testing.T, opts SessionOptions, accepted []Capability, beforeStart func()) (*Session, net.Conn, *bufio.Reader, HelloPayload) {
	t.Helper()
	host, plugin := net.Pipe()
	t.Cleanup(func() {
		_ = host.Close()
		_ = plugin.Close()
	})
	opts.Identity = testIdentity()
	session, err := NewSession(host, host, opts)
	if err != nil {
		t.Fatal(err)
	}
	if beforeStart != nil {
		beforeStart()
	}
	reader := bufio.NewReader(plugin)
	helloCh := make(chan HelloPayload, 1)
	go func() {
		hello := readTestFrame(t, reader)
		var payload HelloPayload
		if err := json.Unmarshal(hello.Payload, &payload); err != nil {
			t.Errorf("hello payload: %v", err)
			return
		}
		helloCh <- payload
		writeTestFrame(t, plugin, Frame{
			Type: FrameReady, SchemaVersion: ProtocolVersion,
			Payload: mustJSON(t, ReadyPayload{
				Challenge: payload.Challenge, PluginID: opts.Identity.PluginID, Version: opts.Identity.Version,
				AcceptedCapabilities: accepted,
			}),
		})
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := session.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session, plugin, reader, <-helloCh
}

func TestSessionRejectsUnnegotiatedResults(t *testing.T) {
	for _, frame := range []struct {
		typeName   FrameType
		capability Capability
	}{
		{FrameHint, CapabilityHintsSubmit},
		{FrameAnalysis, CapabilityAnalysisSubmit},
		{FrameHealth, CapabilityHealth},
	} {
		for _, declined := range []bool{false, true} {
			name := string(frame.typeName) + "/not_granted"
			var granted []Capability
			if declined {
				name = string(frame.typeName) + "/not_accepted"
				granted = []Capability{frame.capability}
			}
			t.Run(name, func(t *testing.T) {
				session, plugin, _, _ := startCapabilitySession(t, SessionOptions{Capabilities: granted}, nil, nil)
				writeTestFrame(t, plugin, Frame{Type: frame.typeName, SchemaVersion: ProtocolVersion, Sequence: 1, Payload: json.RawMessage(`{}`)})
				select {
				case result, ok := <-session.Results():
					if ok {
						t.Fatalf("unnegotiated result published: %#v", result)
					}
				case <-time.After(time.Second):
					t.Fatal("unauthorized frame did not terminate the session")
				}
				if !errors.Is(session.Err(), ErrCapabilityDenied) {
					t.Fatalf("session error = %v, want ErrCapabilityDenied", session.Err())
				}
			})
		}
	}
}

func TestSessionAllowsNegotiatedResultsAndProtocolErrors(t *testing.T) {
	for _, frame := range []struct {
		typeName   FrameType
		capability Capability
		kind       ResultKind
	}{
		{FrameHint, CapabilityHintsSubmit, ResultHint},
		{FrameAnalysis, CapabilityAnalysisSubmit, ResultAnalysis},
		{FrameHealth, CapabilityHealth, ResultHealth},
		{FrameError, "", ResultError},
	} {
		t.Run(string(frame.typeName), func(t *testing.T) {
			var capabilities []Capability
			if frame.capability != "" {
				capabilities = []Capability{frame.capability}
			}
			session, plugin, _, _ := startCapabilitySession(t, SessionOptions{Capabilities: capabilities}, capabilities, nil)
			writeTestFrame(t, plugin, Frame{Type: frame.typeName, SchemaVersion: ProtocolVersion, Sequence: 1, Payload: json.RawMessage(`{}`)})
			select {
			case result, ok := <-session.Results():
				if !ok || result.Kind != frame.kind {
					t.Fatalf("result = %#v, open = %v", result, ok)
				}
			case <-time.After(time.Second):
				t.Fatal("negotiated result not published")
			}
		})
	}
}

func TestSessionEnforcesOutboundCapabilities(t *testing.T) {
	for _, operation := range []struct {
		name       string
		capability Capability
		frameType  FrameType
		ackType    FrameType
		send       func(*Session, context.Context) error
	}{
		{"event", CapabilityEventsSubscribe, FrameEvent, FrameEventAck, func(s *Session, ctx context.Context) error { return s.SendEvent(ctx, json.RawMessage(`{}`)) }},
		{"job", CapabilityAnalysisSubmit, FrameJob, FrameJobAck, func(s *Session, ctx context.Context) error { return s.SendJob(ctx, json.RawMessage(`{}`)) }},
		{"config", CapabilityConfigRead, FrameConfig, FrameConfigAck, func(s *Session, ctx context.Context) error { return s.SendConfig(ctx, Config{Revision: 1}) }},
	} {
		for _, mode := range []string{"not_granted", "not_accepted", "accepted"} {
			t.Run(operation.name+"/"+mode, func(t *testing.T) {
				var granted, accepted []Capability
				if mode != "not_granted" {
					granted = []Capability{operation.capability}
				}
				if mode == "accepted" {
					accepted = granted
				}
				session, plugin, reader, _ := startCapabilitySession(t, SessionOptions{Capabilities: granted}, accepted, nil)
				if mode == "accepted" {
					go func() {
						frame := readTestFrame(t, reader)
						if frame.Type != operation.frameType {
							t.Errorf("frame = %s, want %s", frame.Type, operation.frameType)
						}
						writeTestFrame(t, plugin, Frame{Type: operation.ackType, SchemaVersion: ProtocolVersion, Sequence: frame.Sequence})
					}()
				}
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				result := make(chan error, 1)
				go func() { result <- operation.send(session, ctx) }()
				select {
				case err := <-result:
					if mode == "accepted" && err != nil {
						t.Fatalf("negotiated send: %v", err)
					}
					if mode != "accepted" && !errors.Is(err, ErrCapabilityDenied) {
						t.Fatalf("send error = %v, want ErrCapabilityDenied", err)
					}
				case <-time.After(2 * time.Second):
					t.Fatal("send did not return")
				}
				if session.State() != StateReady {
					t.Fatalf("state = %s, want ready", session.State())
				}
			})
		}
	}
}

func TestSessionCopiesHandshakeOptions(t *testing.T) {
	capabilities := []Capability{CapabilityEventsSubscribe}
	challenge := []byte("original")
	session, plugin, _, hello := startCapabilitySession(t, SessionOptions{Capabilities: capabilities, Challenge: challenge}, []Capability{CapabilityEventsSubscribe}, func() {
		capabilities[0] = CapabilityHintsSubmit
		challenge[0] = 'x'
	})
	if len(hello.Capabilities) != 1 || hello.Capabilities[0] != CapabilityEventsSubscribe || hello.Challenge != "b3JpZ2luYWw=" {
		t.Fatalf("caller mutation changed hello: %#v", hello)
	}
	writeTestFrame(t, plugin, Frame{Type: FrameHint, SchemaVersion: ProtocolVersion, Sequence: 1, Payload: json.RawMessage(`{}`)})
	select {
	case _, ok := <-session.Results():
		if ok || !errors.Is(session.Err(), ErrCapabilityDenied) {
			t.Fatalf("caller mutation granted hints: %v", session.Err())
		}
	case <-time.After(time.Second):
		t.Fatal("caller mutation was not rejected")
	}
}
