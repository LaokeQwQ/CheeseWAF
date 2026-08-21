//go:build windows

package cli

import (
	"context"
	"errors"
	"testing"
	"time"

	"golang.org/x/sys/windows/svc"
)

func TestWindowsServiceStopsOnStopCommand(t *testing.T) {
	started := make(chan struct{})
	run := func(ctx context.Context) error {
		close(started)
		<-ctx.Done()
		return ctx.Err()
	}
	requests := make(chan svc.ChangeRequest, 1)
	changes := make(chan svc.Status, 8)
	done := make(chan struct{})
	var specific bool
	var errno uint32
	go func() {
		specific, errno = (&windowsService{run: run}).Execute(nil, requests, changes)
		close(done)
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("service run did not start")
	}
	requests <- svc.ChangeRequest{Cmd: svc.Stop, CurrentStatus: svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("service did not stop")
	}
	if specific || errno != 0 {
		t.Fatalf("specific=%v errno=%d", specific, errno)
	}
}

func TestWindowsServiceReportsStartFailure(t *testing.T) {
	run := func(context.Context) error {
		return errors.New("listen failed")
	}
	requests := make(chan svc.ChangeRequest)
	changes := make(chan svc.Status, 8)
	specific, errno := (&windowsService{run: run}).Execute(nil, requests, changes)
	if !specific || errno != 1 {
		t.Fatalf("specific=%v errno=%d", specific, errno)
	}
}
