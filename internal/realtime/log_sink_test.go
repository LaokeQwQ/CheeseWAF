package realtime

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

type realtimeSink struct {
	writeErr error
}

func (s *realtimeSink) Write(context.Context, *storage.LogEntry) error { return s.writeErr }
func (*realtimeSink) Query(context.Context, storage.LogFilter) ([]storage.LogEntry, int64, error) {
	return nil, 0, nil
}
func (*realtimeSink) Flush(context.Context) error { return nil }
func (*realtimeSink) Close() error                { return nil }

type countingRealtimeSink struct {
	realtimeSink
	count int64
}

func (s *countingRealtimeSink) Count(context.Context, storage.LogFilter) (int64, bool, error) {
	return s.count, true, nil
}

func TestPublishingLogSinkPublishesSuccessfulWrites(t *testing.T) {
	hub := newHub(4, time.Second)
	messages := make(chan *Message, 1)
	transport := &testTransport{send: func(_ context.Context, msg *Message) error {
		messages <- msg
		return nil
	}}
	hub.Add(transport)
	t.Cleanup(func() { hub.Remove(transport) })
	sink := NewPublishingLogSink(&realtimeSink{}, hub)
	entry := &storage.LogEntry{ID: "log-1", Action: "block"}
	if err := sink.Write(context.Background(), entry); err != nil {
		t.Fatal(err)
	}
	select {
	case msg := <-messages:
		published, ok := msg.Payload.(*storage.LogEntry)
		if msg.Type != MsgLog || !ok || published.ID != entry.ID || published.Action != entry.Action {
			t.Fatalf("unexpected realtime log message: %+v", msg)
		}
	case <-time.After(time.Second):
		t.Fatal("successful log write was not published")
	}
}

func TestPublishingLogSinkDoesNotPublishFailedWrites(t *testing.T) {
	hub := newHub(4, time.Second)
	messages := make(chan *Message, 1)
	transport := &testTransport{send: func(_ context.Context, msg *Message) error {
		messages <- msg
		return nil
	}}
	hub.Add(transport)
	t.Cleanup(func() { hub.Remove(transport) })
	sink := NewPublishingLogSink(&realtimeSink{writeErr: errors.New("write failed")}, hub)
	if err := sink.Write(context.Background(), &storage.LogEntry{ID: "log-1"}); err == nil {
		t.Fatal("expected sink write failure")
	}
	select {
	case msg := <-messages:
		t.Fatalf("failed log write was published: %+v", msg)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestPublishingLogSinkPreservesCountCapability(t *testing.T) {
	sink := NewPublishingLogSink(&countingRealtimeSink{count: 42}, NewHub())
	counter, ok := sink.(interface {
		Count(context.Context, storage.LogFilter) (int64, bool, error)
	})
	if !ok {
		t.Fatal("publishing sink discarded the underlying Count capability")
	}
	count, supported, err := counter.Count(context.Background(), storage.LogFilter{Action: "block"})
	if err != nil {
		t.Fatalf("count logs: %v", err)
	}
	if !supported || count != 42 {
		t.Fatalf("count = %d, supported = %v; want 42, true", count, supported)
	}
}
