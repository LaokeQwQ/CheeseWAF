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

type asyncLogSinkAlert func(kind string, stats AsyncLogSinkStats, err error)

type asyncLogAlertEvent struct {
	kind  string
	stats AsyncLogSinkStats
	err   error
}

type asyncLogWriterOptions struct {
	queueSize        int
	queueBytes       int64
	closeTimeout     time.Duration
	operationTimeout time.Duration
	batchSize        int
	// writeBatch is accounted as all-or-nothing: an error marks every entry in
	// the submitted batch failed. Backends must preserve that contract.
	writeBatch    func(context.Context, []*storage.LogEntry) error
	alert         asyncLogSinkAlert
	alertCooldown time.Duration
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
	predecessor    *asyncLogBarrier
	done           chan struct{}
	writeErr       error
	flushErr       error
	acknowledged   bool
	waiters        int
}

type asyncLogWriter struct {
	name       string
	write      func(context.Context, *storage.LogEntry) error
	writeBatch func(context.Context, []*storage.LogEntry) error
	flush      func(context.Context) error
	close      func() error

	workerCtx  context.Context
	cancel     context.CancelFunc
	workerDone chan struct{}
	wakeWorker chan struct{}

	mu         sync.Mutex
	operations []asyncLogOperation
	queueHead  int

	queueSize        int
	queueBytes       int64
	queuedWrites     int
	pending          int
	pendingBytes     int64
	acceptedSeq      uint64
	latestBarrier    *asyncLogBarrier
	ackedFailures    uint64
	latestFailure    error
	dropped          uint64
	failed           uint64
	closing          bool
	closeTimeout     time.Duration
	operationTimeout time.Duration
	batchSize        int
	alert            asyncLogSinkAlert
	alertCooldown    time.Duration
	lastAlertAt      map[string]time.Time
	alertQueue       chan asyncLogAlertEvent
	alertStop        chan struct{}
	alertStopOnce    sync.Once
	closeTimeoutErr  error
	closeErr         error
	closeFinished    bool
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
	if options.batchSize <= 0 {
		options.batchSize = 1
	}
	if options.alert != nil && options.alertCooldown <= 0 {
		options.alertCooldown = time.Minute
	}
	workerCtx, cancel := context.WithCancel(context.Background())
	writer := &asyncLogWriter{
		name:             name,
		write:            write,
		writeBatch:       options.writeBatch,
		flush:            flush,
		close:            closeFn,
		workerCtx:        workerCtx,
		cancel:           cancel,
		workerDone:       make(chan struct{}),
		wakeWorker:       make(chan struct{}, 1),
		queueSize:        options.queueSize,
		queueBytes:       options.queueBytes,
		closeTimeout:     options.closeTimeout,
		operationTimeout: options.operationTimeout,
		batchSize:        options.batchSize,
		alert:            options.alert,
		alertCooldown:    options.alertCooldown,
		lastAlertAt:      make(map[string]time.Time),
	}
	if writer.alert != nil {
		writer.alertQueue = make(chan asyncLogAlertEvent, 32)
		writer.alertStop = make(chan struct{})
		go writer.runAlerts()
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
		err := fmt.Errorf("%w: %s capacity=%d", ErrLogSinkQueueFull, w.name, w.queueSize)
		w.dropped++
		w.mu.Unlock()
		w.emitAlert("queue_full", err)
		return err
	}
	entryBytes := int64(len(data))
	if entryBytes > w.queueBytes || entryBytes > w.queueBytes-w.pendingBytes {
		err := fmt.Errorf("%w: %s byte_capacity=%d", ErrLogSinkQueueFull, w.name, w.queueBytes)
		w.dropped++
		w.mu.Unlock()
		w.emitAlert("queue_full", err)
		return err
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
	if w.closing {
		w.mu.Unlock()
		return fmt.Errorf("%w: %s", ErrLogSinkClosed, w.name)
	}
	if w.queuedWrites >= w.queueSize {
		err := fmt.Errorf("%w: %s capacity=%d", ErrLogSinkQueueFull, w.name, w.queueSize)
		w.dropped++
		w.mu.Unlock()
		w.emitAlert("queue_full", err)
		return err
	}
	if w.pendingBytes >= w.queueBytes {
		err := fmt.Errorf("%w: %s byte_capacity=%d", ErrLogSinkQueueFull, w.name, w.queueBytes)
		w.dropped++
		w.mu.Unlock()
		w.emitAlert("queue_full", err)
		return err
	}
	w.mu.Unlock()
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
		predecessor := barrier
		barrier = &asyncLogBarrier{
			target:      target,
			baseFailed:  w.ackedFailures,
			predecessor: predecessor,
			done:        make(chan struct{}),
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
	if w.closeFinished {
		closeErr := w.closeErr
		w.mu.Unlock()
		return closeErr
	}
	if w.closeTimeoutErr == nil {
		w.closeTimeoutErr = timeoutErr
	}
	writeErr := w.unacknowledgedWriteErrorLocked(w.failed)
	w.mu.Unlock()
	w.cancel()
	w.signalWorker()
	w.emitAlert("close_timeout", timeoutErr)
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
	return w.statsLocked()
}

func (w *asyncLogWriter) statsLocked() AsyncLogSinkStats {
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
		w.stopAlerts()
		close(w.workerDone)
	}()
	for {
		operation := w.nextOperation()
		switch operation.kind {
		case asyncLogWriteOperation:
			w.runWriteBatch(w.takeWriteBatch(operation))
		case asyncLogFlushOperation:
			w.runFlush(operation.barrier)
		case asyncLogCloseOperation:
			w.runClose()
			return
		}
	}
}

func (w *asyncLogWriter) takeWriteBatch(first asyncLogOperation) []asyncLogOperation {
	batch := []asyncLogOperation{first}
	if w.batchSize <= 1 {
		return batch
	}

	w.mu.Lock()
	for len(batch) < w.batchSize && w.queueHead < len(w.operations) {
		operation := w.operations[w.queueHead]
		if operation.kind != asyncLogWriteOperation {
			break
		}
		w.operations[w.queueHead] = asyncLogOperation{}
		w.queueHead++
		w.queuedWrites--
		batch = append(batch, operation)
	}
	w.compactOperationsLocked()
	w.mu.Unlock()
	return batch
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
	w.runWriteBatch([]asyncLogOperation{operation})
}

func (w *asyncLogWriter) runWriteBatch(batch []asyncLogOperation) {
	if len(batch) == 0 {
		return
	}
	if w.writeBatch != nil {
		entries := make([]*storage.LogEntry, 0, len(batch))
		for _, operation := range batch {
			entries = append(entries, operation.entry)
		}
		err := w.workerCtx.Err()
		if err == nil {
			operationCtx, cancel := w.operationContext()
			err = w.writeBatch(operationCtx, entries)
			cancel()
		}
		w.finishWriteBatch(batch, err)
		return
	}
	for _, operation := range batch {
		err := w.workerCtx.Err()
		if err == nil && w.write != nil {
			operationCtx, cancel := w.operationContext()
			err = w.write(operationCtx, operation.entry)
			cancel()
		}
		w.finishWriteBatch([]asyncLogOperation{operation}, err)
	}
}

func (w *asyncLogWriter) finishWriteBatch(batch []asyncLogOperation, err error) {
	var alertErr error
	w.mu.Lock()
	if err != nil {
		alertErr = fmt.Errorf("%s asynchronous write failed: %w", w.name, err)
		w.failed += uint64(len(batch))
		w.latestFailure = alertErr
	}
	for _, operation := range batch {
		w.pending--
		w.pendingBytes -= int64(operation.size)
	}
	if w.pendingBytes < 0 {
		w.pendingBytes = 0
	}
	w.mu.Unlock()
	if alertErr != nil {
		w.emitAlert("write_failure", alertErr)
	}
}

func (w *asyncLogWriter) runFlush(barrier *asyncLogBarrier) {
	if barrier == nil {
		return
	}
	w.mu.Lock()
	baseFailed := barrier.baseFailed
	if predecessor := barrier.predecessor; predecessor != nil &&
		(predecessor.acknowledged || predecessor.waiters > 0) &&
		predecessor.failedAtTarget > baseFailed {
		baseFailed = predecessor.failedAtTarget
	}
	barrier.baseFailed = baseFailed
	barrier.failedAtTarget = w.failed
	barrier.writeErr = w.writeErrorRangeLocked(baseFailed, barrier.failedAtTarget)
	barrier.predecessor = nil
	w.mu.Unlock()
	var flushErr error
	if w.flush != nil {
		operationCtx, cancel := w.operationContext()
		flushErr = w.flush(operationCtx)
		cancel()
	}
	barrier.flushErr = flushErr
	close(barrier.done)
	if barrier.writeErr != nil {
		w.emitAlert("write_failure", barrier.writeErr)
	}
	if flushErr != nil {
		w.emitAlert("flush_failure", flushErr)
	}
}

func (w *asyncLogWriter) runClose() {
	var flushErr error
	if w.flush != nil {
		// This is the final backend operation before close. It runs in the same
		// worker as writes and explicit Flush barriers, so no write or flush can
		// ever begin after close returns or even after close begins.
		operationCtx, cancel := w.operationContext()
		flushErr = w.flush(operationCtx)
		cancel()
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
	if flushErr != nil {
		w.emitAlert("flush_failure", flushErr)
	}
	if backendCloseErr != nil {
		w.emitAlert("close_failure", backendCloseErr)
	}
}

func (w *asyncLogWriter) operationContext() (context.Context, context.CancelFunc) {
	if w.operationTimeout <= 0 {
		return w.workerCtx, func() {}
	}
	return context.WithTimeout(w.workerCtx, w.operationTimeout)
}

func (w *asyncLogWriter) emitAlert(kind string, err error) {
	if w.alert == nil {
		return
	}
	now := time.Now()
	w.mu.Lock()
	if last, ok := w.lastAlertAt[kind]; ok && now.Sub(last) < w.alertCooldown {
		w.mu.Unlock()
		return
	}
	w.lastAlertAt[kind] = now
	stats := w.statsLocked()
	alertQueue := w.alertQueue
	w.mu.Unlock()
	if alertQueue == nil {
		return
	}
	// Keep alert delivery bounded. A slow alert sink cannot block backend
	// progress, and a saturated alert queue drops telemetry rather than logs.
	select {
	case alertQueue <- asyncLogAlertEvent{kind: kind, stats: stats, err: err}:
	default:
	}
}

func (w *asyncLogWriter) runAlerts() {
	for {
		select {
		case event := <-w.alertQueue:
			func() {
				defer func() { _ = recover() }()
				w.alert(event.kind, event.stats, event.err)
			}()
		case <-w.alertStop:
			return
		}
	}
}

func (w *asyncLogWriter) stopAlerts() {
	if w.alertStop == nil {
		return
	}
	w.alertStopOnce.Do(func() { close(w.alertStop) })
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
