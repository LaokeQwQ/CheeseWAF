package realtime

import (
	"context"

	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

type publishingLogSink struct {
	sink storage.LogSink
	hub  *Hub
}

func NewPublishingLogSink(sink storage.LogSink, hub *Hub) storage.LogSink {
	if sink == nil || hub == nil {
		return sink
	}
	return &publishingLogSink{sink: sink, hub: hub}
}

func (s *publishingLogSink) Write(ctx context.Context, entry *storage.LogEntry) error {
	if err := s.sink.Write(ctx, entry); err != nil {
		return err
	}
	if entry == nil {
		return nil
	}
	payload := cloneLogEntry(entry)
	s.hub.Broadcast(context.WithoutCancel(nonNilContext(ctx)), &Message{Type: MsgLog, Payload: payload})
	return nil
}

func (s *publishingLogSink) Query(ctx context.Context, filter storage.LogFilter) ([]storage.LogEntry, int64, error) {
	return s.sink.Query(ctx, filter)
}

func (s *publishingLogSink) Flush(ctx context.Context) error {
	return s.sink.Flush(ctx)
}

func (s *publishingLogSink) Close() error {
	return s.sink.Close()
}

func cloneLogEntry(entry *storage.LogEntry) *storage.LogEntry {
	if entry == nil {
		return nil
	}
	cloned := *entry
	cloned.Tags = append([]string(nil), entry.Tags...)
	if entry.Metadata != nil {
		cloned.Metadata = make(map[string]any, len(entry.Metadata))
		for key, value := range entry.Metadata {
			cloned.Metadata[key] = value
		}
	}
	return &cloned
}

func nonNilContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}
