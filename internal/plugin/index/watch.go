package index

import (
	"context"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// defaultInterval is the poll period when the caller does not choose one.
// Polling keeps the package dependency-free and is cheap because the
// fingerprint only stats files; a full read happens only on real changes.
const defaultInterval = 2 * time.Second

// Watcher re-scans when the directory content changes.
type Watcher struct {
	dir         string
	hostVersion string
	interval    time.Duration
	onChange    func(*Snapshot)

	// latest is published with an atomic pointer so Snapshot never waits on
	// the scan loop or on user callbacks.
	latest atomic.Pointer[Snapshot]

	mu           sync.Mutex
	started      bool
	closed       bool
	cancel       context.CancelFunc
	loopDone     chan struct{}
	events       chan *Snapshot
	callbackDone chan struct{}
	closeQueue   sync.Once
	closeDone    chan struct{}
}

// NewWatcher builds a watcher. onChange runs on its own goroutine, one call at
// a time, and must not call Close (Close waits for the callback goroutine to
// drain); it must return promptly because only one callback runs at a time.
// A non-positive interval selects the 2s default.
func NewWatcher(dir, hostVersion string, interval time.Duration, onChange func(*Snapshot)) *Watcher {
	if interval <= 0 {
		interval = defaultInterval
	}
	watcher := &Watcher{
		dir:          dir,
		hostVersion:  hostVersion,
		interval:     interval,
		onChange:     onChange,
		events:       make(chan *Snapshot, 1),
		callbackDone: make(chan struct{}),
		closeDone:    make(chan struct{}),
	}
	// Snapshot must never be nil, even before Start is called.
	watcher.latest.Store(Scan(dir, hostVersion))
	return watcher
}

// Start begins watching and returns immediately. Calling Start twice is a no-op.
func (w *Watcher) Start(ctx context.Context) {
	w.mu.Lock()
	if w.started || w.closed {
		w.mu.Unlock()
		return
	}
	w.started = true
	loopCtx, cancel := context.WithCancel(ctx)
	w.cancel = cancel
	w.loopDone = make(chan struct{})
	loopDone := w.loopDone
	w.mu.Unlock()

	go w.deliver()
	go w.watch(loopCtx, loopDone)
}

// Close stops the watcher and waits for the loop to exit. Idempotent.
// No onChange call is running once Close returns.
func (w *Watcher) Close() error {
	w.mu.Lock()
	if w.closed {
		done := w.closeDone
		w.mu.Unlock()
		// A concurrent Close must not return while the first one is still
		// draining callbacks, otherwise a change could still fire afterwards.
		<-done
		return nil
	}
	w.closed = true
	cancel, loopDone := w.cancel, w.loopDone
	w.mu.Unlock()

	if cancel != nil {
		cancel()
		<-loopDone
		// The loop closes the queue on its way out; draining it before
		// returning guarantees no callback can be scheduled once Close is done.
		<-w.callbackDone
	}
	close(w.closeDone)
	return nil
}

// Snapshot returns the latest scan (never nil).
func (w *Watcher) Snapshot() *Snapshot {
	return w.latest.Load()
}

// watch polls the directory fingerprint and rescans only on changes.
func (w *Watcher) watch(ctx context.Context, done chan struct{}) {
	// The queue is closed here, not in Close, so a parent context that is
	// cancelled without Close still releases the callback goroutine.
	defer func() {
		w.closeQueue.Do(func() { close(w.events) })
		close(done)
	}()

	if ctx.Err() != nil {
		return
	}
	current := w.reload()

	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			next := fingerprintDir(w.dir)
			if next.equal(current) {
				continue
			}
			current = w.reload()
		}
	}
}

// reload publishes a fresh snapshot before notifying so a callback that reads
// Snapshot sees the state it was told about. It returns the directory
// fingerprint the snapshot corresponds to. If the directory changes while the
// scan runs, the scan is repeated so the returned fingerprint never describes a
// state newer than the published snapshot; otherwise a rename racing the scan
// could leave the watcher permanently one change behind.
func (w *Watcher) reload() dirFingerprint {
	const maxAttempts = 4
	for attempt := 0; attempt < maxAttempts; attempt++ {
		before := fingerprintDir(w.dir)
		snapshot := Scan(w.dir, w.hostVersion)
		after := fingerprintDir(w.dir)
		if !before.equal(after) {
			continue
		}
		w.latest.Store(snapshot)
		w.enqueue(snapshot)
		return after
	}
	// The directory kept changing; publish what we scanned and stay
	// conservative by returning the older fingerprint so the next tick retries.
	snapshot := Scan(w.dir, w.hostVersion)
	w.latest.Store(snapshot)
	w.enqueue(snapshot)
	return fingerprintDir(w.dir)
}

// enqueue hands the snapshot to the callback goroutine without blocking the
// scan loop. Capacity one keeps only the newest state, which is what
// consumers of an index want when callbacks are slower than the poll period.
func (w *Watcher) enqueue(snapshot *Snapshot) {
	select {
	case w.events <- snapshot:
		return
	default:
	}
	select {
	case <-w.events:
	default:
	}
	select {
	case w.events <- snapshot:
	default:
	}
}

// deliver runs user callbacks off the scan loop so a slow handler cannot delay
// change detection. It drains what the loop enqueued and exits once the queue
// is closed.
func (w *Watcher) deliver() {
	defer close(w.callbackDone)
	for snapshot := range w.events {
		if w.onChange != nil {
			w.onChange(snapshot)
		}
	}
}

// dirFingerprint is the cheap change detector: names, sizes, and mtimes.
type dirFingerprint struct {
	stamps []fileStamp
	err    string
}

type fileStamp struct {
	name  string
	size  int64
	mtime int64
	err   string
}

func (f dirFingerprint) equal(other dirFingerprint) bool {
	return f.err == other.err && slices.Equal(f.stamps, other.stamps)
}

// fingerprintDir stats only the files Scan would read. A directory-level error
// is part of the fingerprint so the watcher notices when the directory
// appears or becomes readable again.
func fingerprintDir(dir string) dirFingerprint {
	dirEntries, err := os.ReadDir(dir)
	if err != nil {
		return dirFingerprint{err: err.Error()}
	}
	stamps := make([]fileStamp, 0, len(dirEntries))
	for _, dirEntry := range dirEntries {
		if !isManifestCandidate(dirEntry) {
			continue
		}
		info, err := dirEntry.Info()
		if err != nil {
			stamps = append(stamps, fileStamp{name: dirEntry.Name(), err: err.Error()})
			continue
		}
		stamps = append(stamps, fileStamp{
			name:  dirEntry.Name(),
			size:  info.Size(),
			mtime: info.ModTime().UnixNano(),
		})
	}
	slices.SortFunc(stamps, func(a, b fileStamp) int { return strings.Compare(a.name, b.name) })
	return dirFingerprint{stamps: stamps}
}
