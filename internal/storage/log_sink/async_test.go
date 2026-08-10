package log_sink

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

type asyncTestSink struct {
	writer *asyncLogWriter
}

func (s *asyncTestSink) Write(ctx context.Context, entry *storage.LogEntry) error {
	return s.writer.Write(ctx, entry)
}

func (s *asyncTestSink) Query(context.Context, storage.LogFilter) ([]storage.LogEntry, int64, error) {
	return nil, 0, nil
}

func (s *asyncTestSink) Flush(ctx context.Context) error { return s.writer.Flush(ctx) }
func (s *asyncTestSink) Close() error                    { return s.writer.Close() }

func TestAsyncLogWriterDoesNotBlockAndDeepCopiesEntry(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	var got storage.LogEntry
	writer := newAsyncLogWriter("test", func(ctx context.Context, entry *storage.LogEntry) error {
		once.Do(func() { close(started) })
		select {
		case <-release:
			got = *entry
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}, nil, nil, asyncLogWriterOptions{queueSize: 2, closeTimeout: time.Second})
	defer writer.Close()

	nested := map[string]any{"value": "original"}
	entry := &storage.LogEntry{
		ID:       "entry-1",
		Message:  "original",
		Tags:     []string{"original"},
		Metadata: map[string]any{"nested": nested},
	}
	writeDone := make(chan error, 1)
	go func() { writeDone <- writer.Write(context.Background(), entry) }()
	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatalf("enqueue: %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("asynchronous Write blocked on the remote backend")
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("worker did not start")
	}

	entry.Message = "mutated"
	entry.Tags[0] = "mutated"
	nested["value"] = "mutated"
	flushDone := make(chan error, 1)
	go func() { flushDone <- writer.Flush(context.Background()) }()
	select {
	case err := <-flushDone:
		t.Fatalf("Flush returned before queued write completed: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	close(release)
	if err := <-flushDone; err != nil {
		t.Fatalf("flush: %v", err)
	}
	if got.Message != "original" || fmt.Sprint(got.Tags) != "[original]" {
		t.Fatalf("worker observed caller mutation: %+v", got)
	}
	metadata, ok := got.Metadata["nested"].(map[string]any)
	if !ok || metadata["value"] != "original" {
		t.Fatalf("metadata was not deeply copied: %+v", got.Metadata)
	}
}

func TestAsyncLogWriterQueueFullReturnsSentinelAndCountsDrop(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	writer := newAsyncLogWriter("full", func(ctx context.Context, _ *storage.LogEntry) error {
		once.Do(func() { close(started) })
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}, nil, nil, asyncLogWriterOptions{queueSize: 1, closeTimeout: time.Second})
	defer writer.Close()

	if err := writer.Write(context.Background(), &storage.LogEntry{ID: "active"}); err != nil {
		t.Fatalf("enqueue active: %v", err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("worker did not start")
	}
	if err := writer.Write(context.Background(), &storage.LogEntry{ID: "queued"}); err != nil {
		t.Fatalf("enqueue queued: %v", err)
	}
	err := writer.Write(context.Background(), &storage.LogEntry{ID: "dropped"})
	if !errors.Is(err, ErrLogSinkQueueFull) {
		t.Fatalf("expected queue-full sentinel, got %v", err)
	}
	stats := writer.Stats()
	if stats.Dropped != 1 || stats.Pending != 2 || stats.QueueDepth != 1 {
		t.Fatalf("unexpected queue stats: %+v", stats)
	}
	close(release)
	if err := writer.Flush(context.Background()); err != nil {
		t.Fatalf("flush: %v", err)
	}
}

func TestMultiSinkRemoteFailureDoesNotPreventHealthyRemote(t *testing.T) {
	failed := newAsyncLogWriter("failed", func(context.Context, *storage.LogEntry) error {
		return errors.New("backend unavailable")
	}, nil, nil, asyncLogWriterOptions{queueSize: 2, closeTimeout: time.Second})
	var healthyWrites atomic.Int64
	healthy := newAsyncLogWriter("healthy", func(context.Context, *storage.LogEntry) error {
		healthyWrites.Add(1)
		return nil
	}, nil, nil, asyncLogWriterOptions{queueSize: 2, closeTimeout: time.Second})
	multi := &MultiSink{sinks: []storage.LogSink{
		&asyncTestSink{writer: failed},
		&asyncTestSink{writer: healthy},
	}}
	defer multi.Close()

	if err := multi.Write(context.Background(), &storage.LogEntry{ID: "isolated"}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	err := multi.Flush(context.Background())
	if err == nil || !containsError(err, "backend unavailable") {
		t.Fatalf("expected failed backend to be reported, got %v", err)
	}
	if healthyWrites.Load() != 1 {
		t.Fatalf("healthy backend was skipped: writes=%d", healthyWrites.Load())
	}
	if failed.Stats().Failed != 1 {
		t.Fatalf("failed write was not counted: %+v", failed.Stats())
	}
}

func TestMultiSinkQueueFullDoesNotSkipHealthyRemote(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	blocked := newAsyncLogWriter("blocked", func(ctx context.Context, _ *storage.LogEntry) error {
		once.Do(func() { close(started) })
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}, nil, nil, asyncLogWriterOptions{queueSize: 1, closeTimeout: time.Second})
	var healthyWrites atomic.Int64
	healthy := newAsyncLogWriter("healthy", func(context.Context, *storage.LogEntry) error {
		healthyWrites.Add(1)
		return nil
	}, nil, nil, asyncLogWriterOptions{queueSize: 2, closeTimeout: time.Second})
	multi := &MultiSink{sinks: []storage.LogSink{
		&asyncTestSink{writer: blocked},
		&asyncTestSink{writer: healthy},
	}}
	defer multi.Close()

	if err := blocked.Write(context.Background(), &storage.LogEntry{ID: "active"}); err != nil {
		t.Fatalf("enqueue active: %v", err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("blocked worker did not start")
	}
	if err := blocked.Write(context.Background(), &storage.LogEntry{ID: "queued"}); err != nil {
		t.Fatalf("enqueue queued: %v", err)
	}
	err := multi.Write(context.Background(), &storage.LogEntry{ID: "healthy-must-run"})
	if !errors.Is(err, ErrLogSinkQueueFull) {
		t.Fatalf("expected queue-full error from blocked sink, got %v", err)
	}
	close(release)
	if err := multi.Flush(context.Background()); err != nil {
		t.Fatalf("healthy sink should flush despite queue-full error: %v", err)
	}
	if healthyWrites.Load() != 1 {
		t.Fatalf("healthy remote was skipped after queue-full error: %d", healthyWrites.Load())
	}
}

func TestAsyncLogWriterCloseIsBoundedAndStopsWorker(t *testing.T) {
	started := make(chan struct{})
	var once sync.Once
	var backendClosed atomic.Bool
	writer := newAsyncLogWriter("bounded-close", func(ctx context.Context, _ *storage.LogEntry) error {
		once.Do(func() { close(started) })
		<-ctx.Done()
		return ctx.Err()
	}, nil, func() error {
		backendClosed.Store(true)
		return nil
	}, asyncLogWriterOptions{queueSize: 1, closeTimeout: 30 * time.Millisecond})
	if err := writer.Write(context.Background(), &storage.LogEntry{ID: "blocked"}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("worker did not start")
	}

	start := time.Now()
	err := writer.Close()
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("Close was not bounded: %s", elapsed)
	}
	if err == nil {
		t.Fatal("expected timeout/cancellation error from forced close")
	}
	select {
	case <-writer.workerDone:
	case <-time.After(time.Second):
		t.Fatal("worker goroutine did not exit")
	}
	if !backendClosed.Load() {
		t.Fatal("backend was not closed")
	}
}

func containsError(err error, text string) bool {
	return err != nil && strings.Contains(err.Error(), text)
}
