package hostapi

import (
	"context"
	"encoding/json"
	"io"
	"sync"
	"testing"
	"time"
)

type testHandler struct {
	events  chan json.RawMessage
	configs chan Config
	drained chan struct{}
	once    sync.Once
}

func newTestHandler() *testHandler {
	return &testHandler{
		events:  make(chan json.RawMessage, 8),
		configs: make(chan Config, 8),
		drained: make(chan struct{}),
	}
}

func (h *testHandler) OnConfig(_ context.Context, cfg Config) error {
	h.configs <- cfg
	return nil
}
func (h *testHandler) OnEvent(_ context.Context, event json.RawMessage) error {
	h.events <- event
	return nil
}
func (h *testHandler) OnJob(context.Context, json.RawMessage) error { return nil }
func (h *testHandler) OnDrain(context.Context) error {
	h.once.Do(func() { close(h.drained) })
	return nil
}
func (h *testHandler) OnShutdown(context.Context) error { return nil }

func TestClientAndSessionRoundTrip(t *testing.T) {
	hostToPluginR, hostToPluginW := io.Pipe()
	pluginToHostR, pluginToHostW := io.Pipe()
	t.Cleanup(func() {
		_ = hostToPluginR.Close()
		_ = hostToPluginW.Close()
		_ = pluginToHostR.Close()
		_ = pluginToHostW.Close()
	})

	identity := testIdentity()
	caps := []Capability{CapabilityEventsSubscribe, CapabilityHintsSubmit, CapabilityHealth}
	host, err := NewSession(pluginToHostR, hostToPluginW, SessionOptions{
		Identity: identity, Capabilities: caps, Challenge: []byte("round-trip"), AckTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(hostToPluginR, pluginToHostW, ClientOptions{Identity: identity, Capabilities: caps})
	if err != nil {
		t.Fatal(err)
	}
	handler := newTestHandler()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	clientErr := make(chan error, 1)
	go func() { clientErr <- client.Run(ctx, handler) }()
	if err := host.Start(ctx); err != nil {
		t.Fatalf("host start: %v", err)
	}

	if err := host.SendEvent(ctx, json.RawMessage(`{"event_id":"evt-1"}`)); err != nil {
		t.Fatalf("send event: %v", err)
	}
	select {
	case event := <-handler.events:
		if string(event) != `{"event_id":"evt-1"}` {
			t.Fatalf("event = %s", event)
		}
	case <-ctx.Done():
		t.Fatal("handler did not receive event")
	}

	if err := client.SendHint(json.RawMessage(`{"hint_id":"hint-1"}`)); err != nil {
		t.Fatalf("send hint: %v", err)
	}
	select {
	case result := <-host.Results():
		if result.Kind != ResultHint {
			t.Fatalf("result = %#v", result)
		}
		if err := host.SendHintReceipt(ctx, result.Sequence, true, ""); err != nil {
			t.Fatalf("receipt: %v", err)
		}
		select {
		case receipt := <-client.Receipts():
			if receipt.Kind != ResultHint || !receipt.Accepted {
				t.Fatalf("receipt = %#v", receipt)
			}
		case <-ctx.Done():
			t.Fatal("client did not receive receipt")
		}
	case <-ctx.Done():
		t.Fatal("host did not receive hint")
	}

	if err := host.Drain(ctx); err != nil {
		t.Fatalf("drain: %v", err)
	}
	select {
	case <-handler.drained:
	case <-ctx.Done():
		t.Fatal("handler did not drain")
	}
	if err := host.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	select {
	case err := <-clientErr:
		if err != nil {
			t.Fatalf("client run: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("client did not exit")
	}
}
