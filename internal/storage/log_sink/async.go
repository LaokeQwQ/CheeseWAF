package log_sink

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

const (
	defaultAsyncLogSinkQueueSize    = 128
	defaultAsyncLogSinkCloseTimeout = 5 * time.Second
)

var (
	ErrLogSinkQueueFull = errors.New("remote log sink queue is full")
	ErrLogSinkClosed    = errors.New("remote log sink is closed")
)

type AsyncLogSinkStats struct {
	QueueDepth int
	Pending    int
	Dropped    uint64
	Failed     uint64
}

type asyncLogWriterOptions struct {
	queueSize    int
	closeTimeout time.Duration
}

type asyncLogWriter struct {
	name       string
	queue      chan asyncLogItem
	write      func(context.Context, *storage.LogEntry) error
	flush      func(context.Context) error
	close      func() error
	workerCtx  context.Context
	cancel     context.CancelFunc
	workerDone chan struct{}
	closeDone  chan struct{}

	mu              sync.Mutex
	currentBatch    *asyncLogBatch
	pendingErr      error
	backendCloseErr error
	closing         bool
	closeErr        error
	dropped         uint64
	failed          uint64

	lifecycleMu  sync.Mutex
	closeTimeout time.Duration
}

type asyncLogItem struct {
	entry *storage.LogEntry
	batch *asyncLogBatch
}

type asyncLogBatch struct {
	pending int
	done    chan struct{}
}

func newAsyncLogWriter(
	name string,
	write func(context.Context, *storage.LogEntry) error,
	flush func(context.Context) error,
	closeFn func() error,
	options asyncLogWriterOptions,
) *asyncLogWriter {
	if options.queueSize <= 0 {
		options.queueSize = defaultAsyncLogSinkQueueSize
	}
	if options.closeTimeout <= 0 {
		options.closeTimeout = defaultAsyncLogSinkCloseTimeout
	}
	workerCtx, cancel := context.WithCancel(context.Background())
	writer := &asyncLogWriter{
		name:         name,
		queue:        make(chan asyncLogItem, options.queueSize),
		write:        write,
		flush:        flush,
		close:        closeFn,
		workerCtx:    workerCtx,
		cancel:       cancel,
		workerDone:   make(chan struct{}),
		closeDone:    make(chan struct{}),
		closeTimeout: options.closeTimeout,
	}
	go writer.run()
	return writer
}

func (w *asyncLogWriter) Write(ctx context.Context, entry *storage.LogEntry) error {
	if entry == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	_, cloned, err := marshalBoundedLogEntry(*entry, maxFileSinkWriteLineBytes)
	if err != nil {
		return fmt.Errorf("clone %s log entry: %w", w.name, err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closing {
		return fmt.Errorf("%w: %s", ErrLogSinkClosed, w.name)
	}
	batch := w.currentBatch
	if batch == nil || batch.pending == 0 {
		batch = &asyncLogBatch{done: make(chan struct{})}
	}
	item := asyncLogItem{entry: &cloned, batch: batch}
	select {
	case w.queue <- item:
		if w.currentBatch != batch {
			w.currentBatch = batch
		}
		batch.pending++
		return nil
	default:
		w.dropped++
		return fmt.Errorf("%w: %s capacity=%d", ErrLogSinkQueueFull, w.name, cap(w.queue))
	}
}

func (w *asyncLogWriter) Flush(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	w.mu.Lock()
	if w.closing {
		w.mu.Unlock()
		return fmt.Errorf("%w: %s", ErrLogSinkClosed, w.name)
	}
	batch := w.currentBatch
	w.mu.Unlock()
	if batch != nil {
		select {
		case <-batch.done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	w.lifecycleMu.Lock()
	defer w.lifecycleMu.Unlock()
	w.mu.Lock()
	if w.closing {
		w.mu.Unlock()
		return fmt.Errorf("%w: %s", ErrLogSinkClosed, w.name)
	}
	writeErr := w.pendingErr
	w.pendingErr = nil
	w.mu.Unlock()
	var flushErr error
	if w.flush != nil {
		flushErr = w.flush(ctx)
	}
	return errors.Join(writeErr, flushErr)
}

func (w *asyncLogWriter) Close() error {
	w.mu.Lock()
	if w.closing {
		closeDone := w.closeDone
		closeTimeout := w.closeTimeout
		w.mu.Unlock()
		timer := time.NewTimer(closeTimeout)
		defer timer.Stop()
		select {
		case <-closeDone:
			w.mu.Lock()
			err := w.closeErr
			w.mu.Unlock()
			return err
		case <-timer.C:
			return fmt.Errorf("close %s log sink timed out after %s", w.name, closeTimeout)
		}
	}
	w.closing = true
	close(w.queue)
	closeTimeout := w.closeTimeout
	w.mu.Unlock()

	timer := time.NewTimer(closeTimeout)
	workerStopped := false
	var timeoutErr error
	select {
	case <-w.workerDone:
		workerStopped = true
		if !timer.Stop() {
			<-timer.C
		}
	case <-timer.C:
		timeoutErr = fmt.Errorf("close %s log sink timed out after %s", w.name, closeTimeout)
		w.cancel()
		grace := min(closeTimeout, time.Second)
		graceTimer := time.NewTimer(grace)
		select {
		case <-w.workerDone:
			workerStopped = true
			if !graceTimer.Stop() {
				<-graceTimer.C
			}
		case <-graceTimer.C:
		}
	}
	w.cancel()

	w.mu.Lock()
	closeErr := errors.Join(timeoutErr, w.pendingErr)
	if workerStopped {
		closeErr = errors.Join(closeErr, w.backendCloseErr)
	}
	w.closeErr = closeErr
	close(w.closeDone)
	w.mu.Unlock()
	return closeErr
}

func (w *asyncLogWriter) Stats() AsyncLogSinkStats {
	w.mu.Lock()
	defer w.mu.Unlock()
	pending := 0
	if w.currentBatch != nil {
		pending = w.currentBatch.pending
	}
	return AsyncLogSinkStats{
		QueueDepth: len(w.queue),
		Pending:    pending,
		Dropped:    w.dropped,
		Failed:     w.failed,
	}
}

func (w *asyncLogWriter) run() {
	defer func() {
		w.lifecycleMu.Lock()
		var closeErr error
		if w.close != nil {
			closeErr = w.close()
		}
		w.lifecycleMu.Unlock()
		w.mu.Lock()
		w.backendCloseErr = closeErr
		w.mu.Unlock()
		close(w.workerDone)
	}()

	for {
		select {
		case <-w.workerCtx.Done():
			w.abortQueued(w.workerCtx.Err())
			return
		default:
		}
		select {
		case <-w.workerCtx.Done():
			w.abortQueued(w.workerCtx.Err())
			return
		case item, ok := <-w.queue:
			if !ok {
				return
			}
			err := w.write(w.workerCtx, item.entry)
			w.finish(item.batch, err)
		}
	}
}

func (w *asyncLogWriter) abortQueued(err error) {
	for {
		select {
		case item, ok := <-w.queue:
			if !ok {
				return
			}
			w.finish(item.batch, err)
		default:
			return
		}
	}
}

func (w *asyncLogWriter) finish(batch *asyncLogBatch, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err != nil {
		w.failed++
		if w.pendingErr == nil {
			w.pendingErr = fmt.Errorf("%s asynchronous write failed: %w", w.name, err)
		}
	}
	batch.pending--
	if batch.pending == 0 {
		close(batch.done)
	}
}
