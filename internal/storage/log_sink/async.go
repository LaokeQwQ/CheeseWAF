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
	defaultAsyncLogSinkQueueBytes   = 16 << 20
	defaultAsyncLogSinkCloseTimeout = 5 * time.Second
	defaultAsyncLogCloneConcurrency = 8
)

var (
	ErrLogSinkQueueFull = errors.New("remote log sink queue is full")
	ErrLogSinkClosed    = errors.New("remote log sink is closed")

	// Cloning a bounded entry still performs reflection, JSON encoding and JSON
	// decoding. Limit that transient work across all remote sinks so concurrent
	// callers cannot bypass the per-sink queue byte budgets before admission.
	asyncLogCloneGate = make(chan struct{}, defaultAsyncLogCloneConcurrency)
)

type AsyncLogSinkStats struct {
	QueueDepth   int
	Pending      int
	PendingBytes int64
	Dropped      uint64
	Failed       uint64
}

type asyncLogWriterOptions struct {
	queueSize    int
	queueBytes   int64
	closeTimeout time.Duration
}

type asyncLogOperationKind uint8

const (
	asyncLogWriteOperation asyncLogOperationKind = iota
	asyncLogFlushOperation
	asyncLogCloseOperation
)

type asyncLogOperation struct {
	kind    asyncLogOperationKind
	entry   *storage.LogEntry
	size    int
	seq     uint64
	barrier *asyncLogBarrier
}

// asyncLogBarrier is immutable after done is closed, except for acknowledged
// and waiters, which are protected by asyncLogWriter.mu. Concurrent Flush
// callers for the same accepted sequence share a barrier and therefore see the
// same write and backend-flush result.
type asyncLogBarrier struct {
	target         uint64
	baseFailed     uint64
	failedAtTarget uint64
	done           chan struct{}
	writeErr       error
	flushErr       error
	acknowledged   bool
	waiters        int
}

type asyncLogWriter struct {
	name  string
	write func(context.Context, *storage.LogEntry) error
	flush func(context.Context) error
	close func() error

	workerCtx  context.Context
	cancel     context.CancelFunc
	workerDone chan struct{}
	wakeWorker chan struct{}

	mu         sync.Mutex
	operations []asyncLogOperation
	queueHead  int

	queueSize       int
	queueBytes      int64
	queuedWrites    int
	pending         int
	pendingBytes    int64
	acceptedSeq     uint64
	latestBarrier   *asyncLogBarrier
	ackedFailures   uint64
	latestFailure   error
	dropped         uint64
	failed          uint64
	closing         bool
	closeTimeout    time.Duration
	closeTimeoutErr error
	closeErr        error
	closeFinished   bool
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
	if options.queueBytes <= 0 {
		options.queueBytes = defaultAsyncLogSinkQueueBytes
	}
	if options.closeTimeout <= 0 {
		options.closeTimeout = defaultAsyncLogSinkCloseTimeout
	}
	workerCtx, cancel := context.WithCancel(context.Background())
	writer := &asyncLogWriter{
		name:         name,
		write:        write,
		flush:        flush,
		close:        closeFn,
		workerCtx:    workerCtx,
		cancel:       cancel,
		workerDone:   make(chan struct{}),
		wakeWorker:   make(chan struct{}, 1),
		queueSize:    options.queueSize,
		queueBytes:   options.queueBytes,
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
	if err := w.preflightWrite(); err != nil {
		return err
	}

	select {
	case asyncLogCloneGate <- struct{}{}:
		defer func() { <-asyncLogCloneGate }()
	case <-ctx.Done():
		return ctx.Err()
	}
	// State may have changed while this call waited for the global clone gate.
	if err := w.preflightWrite(); err != nil {
		return err
	}

	data, cloned, err := marshalBoundedLogEntry(*entry, maxFileSinkWriteLineBytes)
	if err != nil {
		return fmt.Errorf("clone %s log entry: %w", w.name, err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	w.mu.Lock()
	if w.closing {
		w.mu.Unlock()
		return fmt.Errorf("%w: %s", ErrLogSinkClosed, w.name)
	}
	if w.queuedWrites >= w.queueSize {
		w.dropped++
		w.mu.Unlock()
		return fmt.Errorf("%w: %s capacity=%d", ErrLogSinkQueueFull, w.name, w.queueSize)
	}
	entryBytes := int64(len(data))
	if entryBytes > w.queueBytes || entryBytes > w.queueBytes-w.pendingBytes {
		w.dropped++
		w.mu.Unlock()
		return fmt.Errorf("%w: %s byte_capacity=%d", ErrLogSinkQueueFull, w.name, w.queueBytes)
	}
	w.acceptedSeq++
	w.operations = append(w.operations, asyncLogOperation{
		kind:  asyncLogWriteOperation,
		entry: &cloned,
		size:  len(data),
		seq:   w.acceptedSeq,
	})
	w.queuedWrites++
	w.pending++
	w.pendingBytes += entryBytes
	w.mu.Unlock()
	w.signalWorker()
	return nil
}

func (w *asyncLogWriter) preflightWrite() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closing {
		return fmt.Errorf("%w: %s", ErrLogSinkClosed, w.name)
	}
	if w.queuedWrites >= w.queueSize {
		w.dropped++
		return fmt.Errorf("%w: %s capacity=%d", ErrLogSinkQueueFull, w.name, w.queueSize)
	}
	if w.pendingBytes >= w.queueBytes {
		w.dropped++
		return fmt.Errorf("%w: %s byte_capacity=%d", ErrLogSinkQueueFull, w.name, w.queueBytes)
	}
	return nil
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
	target := w.acceptedSeq
	barrier := w.latestBarrier
	created := barrier == nil || barrier.target != target || barrier.acknowledged
	if created {
		barrier = &asyncLogBarrier{
			target:     target,
			baseFailed: w.ackedFailures,
			done:       make(chan struct{}),
		}
		w.latestBarrier = barrier
		w.operations = append(w.operations, asyncLogOperation{
			kind:    asyncLogFlushOperation,
			seq:     target,
			barrier: barrier,
		})
	}
	barrier.waiters++
	w.mu.Unlock()
	if created {
		w.signalWorker()
	}

	completed := false
	defer func() {
		w.mu.Lock()
		barrier.waiters--
		if completed {
			barrier.acknowledged = true
			if barrier.failedAtTarget > w.ackedFailures {
				w.ackedFailures = barrier.failedAtTarget
			}
		}
		w.mu.Unlock()
	}()

	select {
	case <-barrier.done:
		completed = true
		return errors.Join(barrier.writeErr, barrier.flushErr)
	case <-ctx.Done():
		// Prefer a barrier that completed concurrently with cancellation. This
		// prevents losing a write failure at the context boundary.
		select {
		case <-barrier.done:
			completed = true
			return errors.Join(barrier.writeErr, barrier.flushErr)
		default:
			return ctx.Err()
		}
	}
}

func (w *asyncLogWriter) Close() error {
	w.mu.Lock()
	created := !w.closing
	if created {
		w.closing = true
		w.operations = append(w.operations, asyncLogOperation{
			kind: asyncLogCloseOperation,
			seq:  w.acceptedSeq,
		})
	}
	workerDone := w.workerDone
	closeTimeout := w.closeTimeout
	w.mu.Unlock()
	if created {
		w.signalWorker()
	}

	timer := time.NewTimer(closeTimeout)
	defer timer.Stop()
	select {
	case <-workerDone:
		return w.closedResult()
	case <-timer.C:
		// If completion and the timer raced, prefer the completed result.
		select {
		case <-workerDone:
			return w.closedResult()
		default:
		}
	}

	timeoutErr := fmt.Errorf("close %s log sink timed out after %s", w.name, closeTimeout)
	w.mu.Lock()
	if w.closeTimeoutErr == nil {
		w.closeTimeoutErr = timeoutErr
	}
	if w.closeFinished {
		w.closeErr = errors.Join(w.closeErr, w.closeTimeoutErr)
	}
	writeErr := w.unacknowledgedWriteErrorLocked(w.failed)
	w.mu.Unlock()
	w.cancel()
	w.signalWorker()
	return errors.Join(timeoutErr, writeErr)
}

func (w *asyncLogWriter) closedResult() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.closeErr
}

func (w *asyncLogWriter) Stats() AsyncLogSinkStats {
	w.mu.Lock()
	defer w.mu.Unlock()
	return AsyncLogSinkStats{
		QueueDepth:   w.queuedWrites,
		Pending:      w.pending,
		PendingBytes: w.pendingBytes,
		Dropped:      w.dropped,
		Failed:       w.failed,
	}
}

func (w *asyncLogWriter) run() {
	defer func() {
		w.cancel()
		close(w.workerDone)
	}()
	for {
		operation := w.nextOperation()
		switch operation.kind {
		case asyncLogWriteOperation:
			w.runWrite(operation)
		case asyncLogFlushOperation:
			w.runFlush(operation.barrier)
		case asyncLogCloseOperation:
			w.runClose()
			return
		}
	}
}

func (w *asyncLogWriter) nextOperation() asyncLogOperation {
	for {
		w.mu.Lock()
		if w.queueHead < len(w.operations) {
			operation := w.operations[w.queueHead]
			w.operations[w.queueHead] = asyncLogOperation{}
			w.queueHead++
			if operation.kind == asyncLogWriteOperation {
				w.queuedWrites--
			}
			w.compactOperationsLocked()
			w.mu.Unlock()
			return operation
		}
		w.compactOperationsLocked()
		w.mu.Unlock()
		<-w.wakeWorker
	}
}

func (w *asyncLogWriter) compactOperationsLocked() {
	if w.queueHead == len(w.operations) {
		w.operations = nil
		w.queueHead = 0
		return
	}
	if w.queueHead < 1024 || w.queueHead*2 < len(w.operations) {
		return
	}
	remaining := copy(w.operations, w.operations[w.queueHead:])
	clear(w.operations[remaining:])
	w.operations = w.operations[:remaining]
	w.queueHead = 0
}

func (w *asyncLogWriter) runWrite(operation asyncLogOperation) {
	err := w.workerCtx.Err()
	if err == nil && w.write != nil {
		err = w.write(w.workerCtx, operation.entry)
	}
	w.mu.Lock()
	if err != nil {
		w.failed++
		w.latestFailure = fmt.Errorf("%s asynchronous write failed: %w", w.name, err)
	}
	w.pending--
	w.pendingBytes -= int64(operation.size)
	w.mu.Unlock()
}

func (w *asyncLogWriter) runFlush(barrier *asyncLogBarrier) {
	if barrier == nil {
		return
	}
	w.mu.Lock()
	barrier.failedAtTarget = w.failed
	barrier.writeErr = w.writeErrorRangeLocked(barrier.baseFailed, barrier.failedAtTarget)
	w.mu.Unlock()
	if w.flush != nil {
		barrier.flushErr = w.flush(w.workerCtx)
	}
	close(barrier.done)
}

func (w *asyncLogWriter) runClose() {
	var flushErr error
	if w.flush != nil {
		// This is the final backend operation before close. It runs in the same
		// worker as writes and explicit Flush barriers, so no write or flush can
		// ever begin after close returns or even after close begins.
		flushErr = w.flush(w.workerCtx)
	}
	var backendCloseErr error
	if w.close != nil {
		backendCloseErr = w.close()
	}
	w.mu.Lock()
	writeErr := w.unacknowledgedWriteErrorLocked(w.failed)
	w.closeErr = errors.Join(w.closeTimeoutErr, writeErr, flushErr, backendCloseErr)
	w.closeFinished = true
	w.mu.Unlock()
}

func (w *asyncLogWriter) writeErrorRangeLocked(baseFailed, failedAtTarget uint64) error {
	if failedAtTarget <= baseFailed {
		return nil
	}
	count := failedAtTarget - baseFailed
	if w.latestFailure == nil {
		return fmt.Errorf("%s: %d asynchronous writes failed", w.name, count)
	}
	return fmt.Errorf("%s: %d asynchronous writes failed (latest: %w)", w.name, count, w.latestFailure)
}

func (w *asyncLogWriter) unacknowledgedWriteErrorLocked(failedAtTarget uint64) error {
	return w.writeErrorRangeLocked(w.ackedFailures, failedAtTarget)
}

func (w *asyncLogWriter) signalWorker() {
	select {
	case w.wakeWorker <- struct{}{}:
	default:
	}
}
