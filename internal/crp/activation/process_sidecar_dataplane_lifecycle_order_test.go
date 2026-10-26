//go:build !windows

package activation

import (
	"context"
	"errors"
	"sync"
	"testing"
)

type countingDataPlane struct {
	mu     sync.Mutex
	closes int
	err    error
}

func (d *countingDataPlane) Start(context.Context) error { return nil }

func (d *countingDataPlane) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.closes++
	return d.err
}

func (d *countingDataPlane) closeCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.closes
}

// Close-then-install is the shutdown race: the child exited before the data
// plane was installed. The late connection must be closed immediately instead
// of leaking, and the already-closed slot must stay closed.
func TestSetDataPlaneAfterCloseClosesImmediately(t *testing.T) {
	process := &processSidecarProcess{}
	process.closeDataPlane()

	late := &countingDataPlane{}
	process.setDataPlane(late)
	if got := late.closeCount(); got != 1 {
		t.Fatalf("late data plane close count = %d, want 1", got)
	}
	if process.DataPlane() != nil {
		t.Fatal("a closed process must not retain a data plane")
	}
	process.closeDataPlane()
	if got := late.closeCount(); got != 1 {
		t.Fatalf("second close count = %d, want 1", got)
	}
}

// Install-then-close is the normal path: exactly one close, and a second
// closeDataPlane call is a no-op rather than a second Close on the connection
// or a panic on the removed sync.Once.
func TestCloseDataPlaneClosesInstalledConnectionOnce(t *testing.T) {
	process := &processSidecarProcess{}
	plane := &countingDataPlane{}
	process.setDataPlane(plane)
	if process.DataPlane() != plane {
		t.Fatal("installed data plane was not retained")
	}
	process.closeDataPlane()
	if got := plane.closeCount(); got != 1 {
		t.Fatalf("close count = %d, want 1", got)
	}
	process.closeDataPlane()
	if got := plane.closeCount(); got != 1 {
		t.Fatalf("repeated close count = %d, want 1", got)
	}
}

// Close errors are reported by Close itself, not by the reaper; the reaper must
// still mark the slot closed even when the connection refuses to close.
func TestCloseDataPlaneMarksClosedWhenCloseFails(t *testing.T) {
	process := &processSidecarProcess{}
	plane := &countingDataPlane{err: errors.New("pipe already gone")}
	process.setDataPlane(plane)
	process.closeDataPlane()

	late := &countingDataPlane{}
	process.setDataPlane(late)
	if got := late.closeCount(); got != 1 {
		t.Fatalf("late data plane close count = %d, want 1", got)
	}
}
