package realtime

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type testTransport struct {
	send  func(context.Context, *Message) error
	close func() error
}

func (t *testTransport) Send(ctx context.Context, msg *Message) error {
	if t.send == nil {
		return nil
	}
	return t.send(ctx, msg)
}

func (*testTransport) Receive(context.Context) (*Message, error) {
	return nil, errors.New("receive unsupported")
}

func (t *testTransport) Close() error {
	if t.close == nil {
		return nil
	}
	return t.close()
}

func (*testTransport) Type() string { return "test" }

func TestHubSlowClientCannotBlockHealthyClient(t *testing.T) {
	hub := newHub(1, 30*time.Millisecond)
	slowStarted := make(chan struct{})
	slowClosed := make(chan struct{})
	var startOnce sync.Once
	var closeOnce sync.Once
	slow := &testTransport{
		send: func(ctx context.Context, _ *Message) error {
			startOnce.Do(func() { close(slowStarted) })
			<-ctx.Done()
			return ctx.Err()
		},
		close: func() error {
			closeOnce.Do(func() { close(slowClosed) })
			return nil
		},
	}
	healthyMessages := make(chan *Message, 4)
	healthy := &testTransport{send: func(_ context.Context, msg *Message) error {
		healthyMessages <- msg
		return nil
	}}
	hub.Add(slow)
	hub.Add(healthy)
	t.Cleanup(func() {
		hub.Remove(slow)
		hub.Remove(healthy)
	})

	returned := make(chan struct{})
	go func() {
		hub.Broadcast(context.Background(), &Message{Type: MsgLog, Payload: "first"})
		close(returned)
	}()
	select {
	case <-returned:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("broadcast blocked on a slow client")
	}
	select {
	case <-slowStarted:
	case <-time.After(time.Second):
		t.Fatal("slow client did not begin sending")
	}
	select {
	case msg := <-healthyMessages:
		if msg.Type != MsgLog {
			t.Fatalf("healthy client message type = %q, want %q", msg.Type, MsgLog)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("healthy client was stalled by a slow client")
	}
	select {
	case <-slowClosed:
	case <-time.After(time.Second):
		t.Fatal("timed-out client was not disconnected")
	}
}

func TestHubDisconnectsClientWhenQueueIsFull(t *testing.T) {
	hub := newHub(1, time.Second)
	sendStarted := make(chan struct{})
	closed := make(chan struct{})
	var startOnce sync.Once
	var closeOnce sync.Once
	transport := &testTransport{
		send: func(ctx context.Context, _ *Message) error {
			startOnce.Do(func() { close(sendStarted) })
			<-ctx.Done()
			return ctx.Err()
		},
		close: func() error {
			closeOnce.Do(func() { close(closed) })
			return nil
		},
	}
	hub.Add(transport)
	t.Cleanup(func() { hub.Remove(transport) })
	hub.Broadcast(context.Background(), &Message{Type: MsgLog, Payload: "active"})
	select {
	case <-sendStarted:
	case <-time.After(time.Second):
		t.Fatal("client did not begin sending")
	}
	hub.Broadcast(context.Background(), &Message{Type: MsgLog, Payload: "queued"})

	started := time.Now()
	hub.Broadcast(context.Background(), &Message{Type: MsgLog, Payload: "overflow"})
	if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
		t.Fatalf("queue overflow blocked broadcast for %s", elapsed)
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("client with a full queue was not disconnected")
	}
}

func TestHubBrokenClientCannotBlockHealthyClient(t *testing.T) {
	hub := newHub(4, time.Second)
	brokenClosed := make(chan struct{})
	var closeOnce sync.Once
	broken := &testTransport{
		send: func(context.Context, *Message) error {
			return errors.New("broken transport")
		},
		close: func() error {
			closeOnce.Do(func() { close(brokenClosed) })
			return nil
		},
	}
	healthyMessages := make(chan *Message, 1)
	healthy := &testTransport{send: func(_ context.Context, msg *Message) error {
		healthyMessages <- msg
		return nil
	}}
	hub.Add(broken)
	hub.Add(healthy)
	t.Cleanup(func() {
		hub.Remove(broken)
		hub.Remove(healthy)
	})

	hub.Broadcast(context.Background(), &Message{Type: MsgAlert})
	select {
	case msg := <-healthyMessages:
		if msg.Type != MsgAlert {
			t.Fatalf("healthy client message type = %q, want %q", msg.Type, MsgAlert)
		}
	case <-time.After(time.Second):
		t.Fatal("healthy client was stalled by a broken client")
	}
	select {
	case <-brokenClosed:
	case <-time.After(time.Second):
		t.Fatal("broken client was not disconnected")
	}
}

func TestHubSerializesConcurrentWritesPerClient(t *testing.T) {
	hub := newHub(128, time.Second)
	var active atomic.Int32
	var overlap atomic.Bool
	var delivered atomic.Int32
	allDelivered := make(chan struct{})
	var deliveredOnce sync.Once
	transport := &testTransport{send: func(context.Context, *Message) error {
		if active.Add(1) != 1 {
			overlap.Store(true)
		}
		time.Sleep(time.Millisecond)
		active.Add(-1)
		if delivered.Add(1) == 64 {
			deliveredOnce.Do(func() { close(allDelivered) })
		}
		return nil
	}}
	hub.Add(transport)
	t.Cleanup(func() { hub.Remove(transport) })

	var broadcasts sync.WaitGroup
	for i := 0; i < 64; i++ {
		broadcasts.Add(1)
		go func() {
			defer broadcasts.Done()
			hub.Broadcast(context.Background(), &Message{Type: MsgStats})
		}()
	}
	broadcasts.Wait()
	select {
	case <-allDelivered:
	case <-time.After(2 * time.Second):
		t.Fatalf("delivered %d of 64 messages", delivered.Load())
	}
	if overlap.Load() {
		t.Fatal("hub invoked concurrent writes for one client")
	}
}

type concurrentResponseWriter struct {
	header  http.Header
	active  atomic.Int32
	overlap atomic.Bool
}

func (w *concurrentResponseWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}

func (*concurrentResponseWriter) WriteHeader(int) {}

func (w *concurrentResponseWriter) Write(data []byte) (int, error) {
	if w.active.Add(1) != 1 {
		w.overlap.Store(true)
	}
	time.Sleep(time.Millisecond)
	w.active.Add(-1)
	return len(data), nil
}

func (*concurrentResponseWriter) Flush() {}

func TestSSETransportSerializesConcurrentSend(t *testing.T) {
	writer := &concurrentResponseWriter{}
	transport := &SSETransport{w: writer, flusher: writer}
	var sends sync.WaitGroup
	for i := 0; i < 32; i++ {
		sends.Add(1)
		go func() {
			defer sends.Done()
			if err := transport.Send(context.Background(), &Message{Type: MsgStats}); err != nil {
				t.Errorf("send: %v", err)
			}
		}()
	}
	sends.Wait()
	if writer.overlap.Load() {
		t.Fatal("SSE transport wrote concurrently")
	}
}

type deadlineResponseWriter struct {
	header      http.Header
	deadlineSet chan struct{}
	release     chan struct{}
	once        sync.Once
}

func (w *deadlineResponseWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}

func (*deadlineResponseWriter) WriteHeader(int) {}

func (w *deadlineResponseWriter) Write([]byte) (int, error) {
	select {
	case <-w.deadlineSet:
		return 0, errors.New("write deadline reached")
	case <-w.release:
		return 0, errors.New("test released blocked write")
	}
}

func (*deadlineResponseWriter) Flush() {}

func (w *deadlineResponseWriter) SetWriteDeadline(time.Time) error {
	w.once.Do(func() { close(w.deadlineSet) })
	return nil
}

func TestSSETransportAppliesWriteDeadline(t *testing.T) {
	writer := &deadlineResponseWriter{deadlineSet: make(chan struct{}), release: make(chan struct{})}
	transport := &SSETransport{w: writer, flusher: writer}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		result <- transport.Send(ctx, &Message{Type: MsgStats})
	}()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("expected blocked SSE write to fail")
		}
	case <-time.After(100 * time.Millisecond):
		close(writer.release)
		<-result
		t.Fatal("SSE send ignored its context deadline")
	}
}
