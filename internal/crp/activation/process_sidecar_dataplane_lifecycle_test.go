//go:build !windows

package activation

import (
	"context"
	"errors"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

type lifecycleTestDataPlane struct {
	hostToPlugin *os.File
	pluginToHost *os.File
	closed       atomic.Int32
}

func (*lifecycleTestDataPlane) Start(context.Context) error { return nil }

func (p *lifecycleTestDataPlane) Close() error {
	p.closed.Add(1)
	return errors.Join(p.hostToPlugin.Close(), p.pluginToHost.Close())
}

func TestProcessSidecarBackendClosesDataPlaneAfterChildExit(t *testing.T) {
	for _, behavior := range []string{"normal", "crash"} {
		t.Run(behavior, func(t *testing.T) {
			var dataPlane *lifecycleTestDataPlane
			backend, err := NewProcessSidecarBackend(ProcessSidecarBackendOptions{
				Registry:  []ProcessSidecarRegistryEntry{processSidecarTestEntry(t, behavior)},
				Admission: allowProcessSidecarTestAdmission,
				DataPlaneFactory: func(_ ProcessSidecarIdentity, hostToPlugin, pluginToHost *os.File) (ProcessDataPlane, error) {
					dataPlane = &lifecycleTestDataPlane{hostToPlugin: hostToPlugin, pluginToHost: pluginToHost}
					return dataPlane, nil
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = backend.Close(context.Background()) })
			process, err := backend.Start(t.Context(), processSidecarTestSpec())
			if err != nil {
				t.Fatal(err)
			}
			if dataPlane.closed.Load() != 0 {
				t.Fatal("data plane closed while child was running")
			}
			if behavior == "crash" {
				if err := process.Probe(t.Context()); !errors.Is(err, ErrProcessSidecarProtocol) && !errors.Is(err, ErrProcessSidecarExited) {
					t.Fatalf("crash Probe() error = %v", err)
				}
			} else if err := process.Stop(t.Context()); err != nil {
				t.Fatal(err)
			}
			assertProcessSidecarReaped(t, process)
			if got := dataPlane.closed.Load(); got != 1 {
				t.Fatalf("data plane Close() calls after child exit = %d, want 1", got)
			}
		})
	}
}

func TestProcessSidecarClosesDataPlaneAttachedAfterExit(t *testing.T) {
	process := &processSidecarProcess{done: make(chan struct{})}
	process.closeDataPlane()
	dataPlane := &lifecycleTestDataPlane{}
	// A child may exit while its data-plane handshake is completing. The
	// backend must immediately close a session attached after exit cleanup.
	process.setDataPlane(dataPlane)
	if got := dataPlane.closed.Load(); got != 1 {
		t.Fatalf("late data plane Close() calls = %d, want 1", got)
	}
	process.closeDataPlane()
	if got := dataPlane.closed.Load(); got != 1 {
		t.Fatalf("repeated cleanup Close() calls = %d, want 1", got)
	}
}

func TestProcessSidecarDataPlaneAttachmentDoesNotMissConcurrentExit(t *testing.T) {
	for range 100 {
		process := &processSidecarProcess{done: make(chan struct{})}
		dataPlane := &lifecycleTestDataPlane{}
		finished := make(chan struct{})
		go func() {
			process.closeDataPlane()
			close(finished)
		}()
		process.setDataPlane(dataPlane)
		select {
		case <-finished:
		case <-time.After(time.Second):
			t.Fatal("exit cleanup blocked")
		}
		if got := dataPlane.closed.Load(); got != 1 {
			t.Fatalf("concurrent Close() calls = %d, want 1", got)
		}
	}
}
