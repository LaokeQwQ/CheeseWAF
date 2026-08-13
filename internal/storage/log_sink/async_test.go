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

func TestAsyncLogWriterFlushSealsCurrentBatch(t *testing.T) {
	firstStarted := make(chan struct{})
	secondStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	releaseSecond := make(chan struct{})
	writer := newAsyncLogWriter("flush-barrier", func(ctx context.Context, entry *storage.LogEntry) error {
		switch entry.ID {
		case "first":
			close(firstStarted)
			select {
			case <-releaseFirst:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		case "second":
			close(secondStarted)
			select {
			case <-releaseSecond:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		default:
			return nil
		}
	}, nil, nil, asyncLogWriterOptions{queueSize: 4, closeTimeout: time.Second})
	defer func() {
		select {
		case <-releaseSecond:
		default:
			close(releaseSecond)
		}
		_ = writer.Close()
	}()

	if err := writer.Write(context.Background(), &storage.LogEntry{ID: "first"}); err != nil {
		t.Fatalf("enqueue first: %v", err)
	}
	select {
	case <-firstStarted:
	case <-time.After(time.Second):
		t.Fatal("first write did not start")
	}
	flushDone := make(chan error, 1)
	go func() { flushDone <- writer.Flush(context.Background()) }()
	deadline := time.Now().Add(time.Second)
	for {
		writer.mu.Lock()
		barrier := writer.latestBarrier
		sealed := barrier != nil && barrier.target == 1 && barrier.waiters == 1
		writer.mu.Unlock()
		if sealed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Flush did not seal the current batch")
		}
		time.Sleep(time.Millisecond)
	}
	if err := writer.Write(context.Background(), &storage.LogEntry{ID: "second"}); err != nil {
		t.Fatalf("enqueue second: %v", err)
	}
	close(releaseFirst)
	select {
	case err := <-flushDone:
		if err != nil {
			t.Fatalf("flush: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Flush waited for a write enqueued after its barrier")
	}
	select {
	case <-secondStarted:
	case <-time.After(time.Second):
		t.Fatal("second write did not start")
	}
	close(releaseSecond)
}

func TestAsyncLogWriterBoundsPendingBytes(t *testing.T) {
	entry := &storage.LogEntry{ID: "bounded", Payload: strings.Repeat("x", 1024)}
	data, _, err := marshalBoundedLogEntry(*entry, maxFileSinkWriteLineBytes)
	if err != nil {
		t.Fatalf("measure entry: %v", err)
	}
	release := make(chan struct{})
	started := make(chan struct{})
	var once sync.Once
	writer := newAsyncLogWriter("byte-budget", func(ctx context.Context, _ *storage.LogEntry) error {
		once.Do(func() { close(started) })
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}, nil, nil, asyncLogWriterOptions{
		queueSize:    10,
		queueBytes:   int64(len(data)*2 - 1),
		closeTimeout: time.Second,
	})
	defer writer.Close()

	if err := writer.Write(context.Background(), entry); err != nil {
		t.Fatalf("enqueue first: %v", err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("backend did not start")
	}
	err = writer.Write(context.Background(), entry)
	if !errors.Is(err, ErrLogSinkQueueFull) {
		t.Fatalf("expected byte-budget queue-full error, got %v", err)
	}
	stats := writer.Stats()
	if stats.Pending != 1 || stats.PendingBytes != int64(len(data)) || stats.Dropped != 1 {
		t.Fatalf("unexpected byte-budget stats: %+v entry_bytes=%d", stats, len(data))
	}
	close(release)
	if err := writer.Flush(context.Background()); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if stats := writer.Stats(); stats.Pending != 0 || stats.PendingBytes != 0 {
		t.Fatalf("pending budget was not released: %+v", stats)
	}
}

func TestAsyncLogWriterSerializesBackendOperations(t *testing.T) {
	firstStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	secondStarted := make(chan struct{})
	releaseSecond := make(chan struct{})
	flushStarted := make(chan struct{})
	var flushStartedOnce sync.Once
	var active atomic.Int64
	var concurrent atomic.Bool
	writer := newAsyncLogWriter("serialized", func(ctx context.Context, entry *storage.LogEntry) error {
		if active.Add(1) != 1 {
			concurrent.Store(true)
		}
		defer active.Add(-1)
		var started, release chan struct{}
		if entry.ID == "first" {
			started, release = firstStarted, releaseFirst
		} else {
			started, release = secondStarted, releaseSecond
		}
		close(started)
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}, func(context.Context) error {
		if active.Add(1) != 1 {
			concurrent.Store(true)
		}
		defer active.Add(-1)
		flushStartedOnce.Do(func() { close(flushStarted) })
		return nil
	}, nil, asyncLogWriterOptions{queueSize: 2, closeTimeout: time.Second})
	defer func() {
		select {
		case <-releaseFirst:
		default:
			close(releaseFirst)
		}
		select {
		case <-releaseSecond:
		default:
			close(releaseSecond)
		}
		_ = writer.Close()
	}()
	if err := writer.Write(context.Background(), &storage.LogEntry{ID: "first"}); err != nil {
		t.Fatalf("enqueue first: %v", err)
	}
	select {
	case <-firstStarted:
	case <-time.After(time.Second):
		t.Fatal("first backend write did not start")
	}
	flushDone := make(chan error, 1)
	go func() { flushDone <- writer.Flush(context.Background()) }()
	waitForAsyncBarrierWaiters(t, writer, 1)
	if err := writer.Write(context.Background(), &storage.LogEntry{ID: "second"}); err != nil {
		t.Fatalf("enqueue second: %v", err)
	}
	close(releaseFirst)
	select {
	case <-flushStarted:
	case <-time.After(time.Second):
		t.Fatal("backend Flush did not run")
	}
	if err := <-flushDone; err != nil {
		t.Fatalf("flush: %v", err)
	}
	select {
	case <-secondStarted:
	case <-time.After(time.Second):
		t.Fatal("second backend write did not start")
	}
	if concurrent.Load() {
		t.Fatal("backend operations overlapped")
	}
	close(releaseSecond)
}

func TestAsyncLogWriterConcurrentFlushesWaitAndShareWriteError(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	writer := newAsyncLogWriter("concurrent-flush", func(context.Context, *storage.LogEntry) error {
		close(started)
		<-release
		return errors.New("write failed")
	}, nil, nil, asyncLogWriterOptions{queueSize: 2, closeTimeout: time.Second})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
		_ = writer.Close()
	}()
	if err := writer.Write(context.Background(), &storage.LogEntry{ID: "failed"}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("backend write did not start")
	}
	first := make(chan error, 1)
	second := make(chan error, 1)
	go func() { first <- writer.Flush(context.Background()) }()
	go func() { second <- writer.Flush(context.Background()) }()
	waitForAsyncBarrierWaiters(t, writer, 2)
	close(release)
	for index, result := range []<-chan error{first, second} {
		select {
		case err := <-result:
			if !containsError(err, "write failed") {
				t.Fatalf("flush %d lost the shared write error: %v", index+1, err)
			}
		case <-time.After(time.Second):
			t.Fatalf("flush %d did not complete", index+1)
		}
	}
}

func TestAsyncLogWriterFlushRetryAfterTimeoutReportsEarlierFailure(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	writer := newAsyncLogWriter("flush-retry", func(context.Context, *storage.LogEntry) error {
		close(started)
		<-release
		return errors.New("retry-visible failure")
	}, nil, nil, asyncLogWriterOptions{queueSize: 2, closeTimeout: time.Second})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
		_ = writer.Close()
	}()
	if err := writer.Write(context.Background(), &storage.LogEntry{ID: "failed"}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("backend write did not start")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	err := writer.Flush(ctx)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected first Flush to time out, got %v", err)
	}
	close(release)
	if err := writer.Flush(context.Background()); !containsError(err, "retry-visible failure") {
		t.Fatalf("retry lost the earlier write failure: %v", err)
	}
}

func TestAsyncLogWriterAcknowledgedFailureIsNotRepeated(t *testing.T) {
	writer := newAsyncLogWriter("acknowledged", func(context.Context, *storage.LogEntry) error {
		return errors.New("reported once")
	}, nil, nil, asyncLogWriterOptions{queueSize: 2, closeTimeout: time.Second})
	if err := writer.Write(context.Background(), &storage.LogEntry{ID: "failed"}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if err := writer.Flush(context.Background()); !containsError(err, "reported once") {
		t.Fatalf("first Flush did not report the write failure: %v", err)
	}
	if err := writer.Flush(context.Background()); err != nil {
		t.Fatalf("acknowledged write failure was repeated: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close repeated an acknowledged write failure: %v", err)
	}
}

func TestAsyncLogWriterFlushContextIsBoundedWhenBackendIgnoresContext(t *testing.T) {
	flushStarted := make(chan struct{})
	releaseFlush := make(chan struct{})
	var flushOnce sync.Once
	var backendClosed atomic.Bool
	writer := newAsyncLogWriter("ignores-context", nil, func(context.Context) error {
		flushOnce.Do(func() { close(flushStarted) })
		<-releaseFlush
		return nil
	}, func() error {
		backendClosed.Store(true)
		return nil
	}, asyncLogWriterOptions{queueSize: 1, closeTimeout: 30 * time.Millisecond})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	start := time.Now()
	err := writer.Flush(ctx)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected Flush deadline, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("Flush was not bounded: %s", elapsed)
	}
	select {
	case <-flushStarted:
	case <-time.After(time.Second):
		t.Fatal("backend Flush did not start")
	}

	start = time.Now()
	if err := writer.Close(); err == nil {
		t.Fatal("expected Close to time out behind the stuck backend Flush")
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("Close was not bounded: %s", elapsed)
	}
	if backendClosed.Load() {
		t.Fatal("backend was closed while an earlier Flush was still running")
	}
	close(releaseFlush)
	select {
	case <-writer.workerDone:
	case <-time.After(time.Second):
		t.Fatal("worker did not finish after the backend Flush was released")
	}
	if !backendClosed.Load() {
		t.Fatal("backend close did not run after the final Flush")
	}
}

func TestAsyncLogWriterCloseFlushesBeforeBackendClose(t *testing.T) {
	var mu sync.Mutex
	var order []string
	record := func(step string) {
		mu.Lock()
		order = append(order, step)
		mu.Unlock()
	}
	writer := newAsyncLogWriter("close-order", func(context.Context, *storage.LogEntry) error {
		record("write")
		return nil
	}, func(context.Context) error {
		record("flush")
		return nil
	}, func() error {
		record("close")
		return nil
	}, asyncLogWriterOptions{queueSize: 2, closeTimeout: time.Second})
	if err := writer.Write(context.Background(), &storage.LogEntry{ID: "ordered"}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	mu.Lock()
	got := strings.Join(order, ",")
	mu.Unlock()
	if got != "write,flush,close" {
		t.Fatalf("unexpected backend lifecycle order: %s", got)
	}
}

func TestAsyncLogWriterFlushCloseLifecycleIsLinearized(t *testing.T) {
	firstFlushStarted := make(chan struct{})
	releaseFirstFlush := make(chan struct{})
	var flushCalls atomic.Int64
	var backendClosed atomic.Bool
	var flushAfterClose atomic.Bool
	writer := newAsyncLogWriter("flush-close-order", nil, func(context.Context) error {
		if backendClosed.Load() {
			flushAfterClose.Store(true)
		}
		if flushCalls.Add(1) == 1 {
			close(firstFlushStarted)
			<-releaseFirstFlush
		}
		return nil
	}, func() error {
		backendClosed.Store(true)
		return nil
	}, asyncLogWriterOptions{queueSize: 1, closeTimeout: time.Second})
	flushDone := make(chan error, 1)
	go func() { flushDone <- writer.Flush(context.Background()) }()
	select {
	case <-firstFlushStarted:
	case <-time.After(time.Second):
		t.Fatal("explicit backend Flush did not start")
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- writer.Close() }()
	select {
	case err := <-closeDone:
		t.Fatalf("Close returned before the earlier Flush completed: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	close(releaseFirstFlush)
	if err := <-flushDone; err != nil {
		t.Fatalf("explicit flush: %v", err)
	}
	if err := <-closeDone; err != nil {
		t.Fatalf("close: %v", err)
	}
	if flushCalls.Load() != 2 {
		t.Fatalf("expected explicit and final Flush calls, got %d", flushCalls.Load())
	}
	if flushAfterClose.Load() {
		t.Fatal("backend Flush ran after backend close")
	}
}

func TestAsyncLogWriterCloseIsBoundedWhenWriteIgnoresContext(t *testing.T) {
	writeStarted := make(chan struct{})
	releaseWrite := make(chan struct{})
	var backendClosed atomic.Bool
	writer := newAsyncLogWriter("stuck-write", func(context.Context, *storage.LogEntry) error {
		close(writeStarted)
		<-releaseWrite
		return nil
	}, nil, func() error {
		backendClosed.Store(true)
		return nil
	}, asyncLogWriterOptions{queueSize: 1, closeTimeout: 30 * time.Millisecond})
	if err := writer.Write(context.Background(), &storage.LogEntry{ID: "blocked"}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	select {
	case <-writeStarted:
	case <-time.After(time.Second):
		t.Fatal("backend write did not start")
	}
	start := time.Now()
	if err := writer.Close(); err == nil {
		t.Fatal("expected Close timeout")
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("Close was not bounded: %s", elapsed)
	}
	if backendClosed.Load() {
		t.Fatal("backend closed concurrently with an active write")
	}
	close(releaseWrite)
	select {
	case <-writer.workerDone:
	case <-time.After(time.Second):
		t.Fatal("worker did not finish after the stuck write was released")
	}
	if !backendClosed.Load() {
		t.Fatal("backend was not eventually closed")
	}
}

func waitForAsyncBarrierWaiters(t *testing.T, writer *asyncLogWriter, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		writer.mu.Lock()
		barrier := writer.latestBarrier
		got := 0
		if barrier != nil {
			got = barrier.waiters
		}
		writer.mu.Unlock()
		if got >= want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("Flush barrier waiters=%d, want at least %d", got, want)
		}
		time.Sleep(time.Millisecond)
	}
}

func containsError(err error, text string) bool {
	return err != nil && strings.Contains(err.Error(), text)
}
