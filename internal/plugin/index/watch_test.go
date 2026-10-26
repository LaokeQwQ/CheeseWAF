package index

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// watchWait bounds every event wait so a broken watcher fails the test instead
// of hanging it.
const watchWait = 5 * time.Second

func waitSnapshot(t *testing.T, events <-chan *Snapshot) *Snapshot {
	t.Helper()
	select {
	case snapshot := <-events:
		return snapshot
	case <-time.After(watchWait):
		t.Fatal("timed out waiting for an onChange call")
		return nil
	}
}

func hasEntry(snapshot *Snapshot, path string) bool {
	for _, entry := range snapshot.Entries {
		if entry.Path == path {
			return true
		}
	}
	return false
}

func TestWatcherReloadsAfterAddAndRemove(t *testing.T) {
	dir := t.TempDir()
	events := make(chan *Snapshot, 8)
	watcher := NewWatcher(dir, testHostVersion, 50*time.Millisecond, func(snapshot *Snapshot) {
		events <- snapshot
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	watcher.Start(ctx)
	defer watcher.Close()

	initial := waitSnapshot(t, events)
	if len(initial.Entries) != 0 {
		t.Fatalf("initial scan should be empty: %+v", initial.Entries)
	}
	if watcher.Snapshot() != initial {
		t.Fatal("Snapshot must expose the snapshot passed to onChange")
	}

	added := writeFile(t, dir, "alpha.json", validManifestJSON("alpha", "1.0.0", nil))
	afterAdd := waitSnapshot(t, events)
	if !hasEntry(afterAdd, added) {
		t.Fatalf("snapshot after add does not contain %s: %+v", added, afterAdd.Entries)
	}
	if plugins := afterAdd.Plugins(testHostVersion); len(plugins) != 1 || plugins[0].Path != added {
		t.Fatalf("snapshot after add should index the plugin: %+v", plugins)
	}

	if err := os.Remove(added); err != nil {
		t.Fatalf("remove: %v", err)
	}
	afterRemove := waitSnapshot(t, events)
	if hasEntry(afterRemove, added) {
		t.Fatalf("snapshot after remove still contains %s: %+v", added, afterRemove.Entries)
	}
}

func TestWatcherCloseStopsCallbacks(t *testing.T) {
	dir := t.TempDir()
	events := make(chan *Snapshot, 8)
	watcher := NewWatcher(dir, testHostVersion, 50*time.Millisecond, func(snapshot *Snapshot) {
		events <- snapshot
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	watcher.Start(ctx)
	waitSnapshot(t, events)

	if err := watcher.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	// A repeated Close must not panic or return an error.
	if err := watcher.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}

	writeFile(t, dir, "late.json", validManifestJSON("late", "1.0.0", nil))

	select {
	case snapshot := <-events:
		t.Fatalf("onChange fired after Close: %+v", snapshot.Entries)
	case <-time.After(200 * time.Millisecond):
	}

	if watcher.Snapshot() == nil {
		t.Fatal("Snapshot returned nil after Close")
	}
}

func TestWatcherStartIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	events := make(chan *Snapshot, 8)
	watcher := NewWatcher(dir, testHostVersion, 50*time.Millisecond, func(snapshot *Snapshot) {
		events <- snapshot
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	watcher.Start(ctx)
	watcher.Start(ctx)
	defer watcher.Close()

	waitSnapshot(t, events)

	// With one loop only a single reload happens per change; a second loop
	// would deliver a duplicate snapshot.
	writeFile(t, dir, "alpha.json", validManifestJSON("alpha", "1.0.0", nil))
	waitSnapshot(t, events)
	select {
	case snapshot := <-events:
		t.Fatalf("second Start created another loop: %+v", snapshot.Entries)
	case <-time.After(300 * time.Millisecond):
	}
}

func TestWatcherDefaultInterval(t *testing.T) {
	watcher := NewWatcher(filepath.Join(t.TempDir(), "missing"), testHostVersion, 0, nil)
	defer watcher.Close()
	if watcher.interval != defaultInterval {
		t.Fatalf("interval = %v, want %v", watcher.interval, defaultInterval)
	}
	if watcher.Snapshot() == nil {
		t.Fatal("Snapshot must be non-nil before Start")
	}
}

func TestFingerprintTracksNamesSizesAndMtimes(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "alpha.json", []byte(`{}`))
	first := fingerprintDir(dir)

	again := fingerprintDir(dir)
	if !first.equal(again) {
		t.Fatal("fingerprint changed without a directory change")
	}

	path := filepath.Join(dir, "alpha.json")
	if err := os.WriteFile(path, []byte(`{"longer":true}`), 0o600); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	// The size change is deterministic; mtime is included as a second signal
	// but is not something the test should depend on.
	if first.equal(fingerprintDir(dir)) {
		t.Fatal("fingerprint ignored a size change")
	}

	other := fingerprintDir(filepath.Join(dir, "never-created"))
	if other.err == "" {
		t.Fatal("missing directory should be encoded in the fingerprint")
	}
}
