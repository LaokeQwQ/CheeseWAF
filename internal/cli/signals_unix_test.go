//go:build !windows

package cli

import (
	"context"
	"os"
	"syscall"
	"testing"
	"time"
)

func TestListenServiceHangupInvokesCallback(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	got := make(chan struct{}, 1)
	listenServiceHangup(ctx, func() {
		select {
		case got <- struct{}{}:
		default:
		}
	})
	time.Sleep(20 * time.Millisecond)
	if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	select {
	case <-got:
	case <-time.After(2 * time.Second):
		t.Fatal("SIGHUP did not invoke reload callback")
	}
}
