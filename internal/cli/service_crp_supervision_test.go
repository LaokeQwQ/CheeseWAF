package cli

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/api/handler"
	"github.com/LaokeQwQ/CheeseWAF/internal/crp"
)

type supervisedCRPDependency struct {
	wait func(context.Context) error
}

func (*supervisedCRPDependency) Start() error                                      { return nil }
func (*supervisedCRPDependency) Shutdown(context.Context) error                    { return nil }
func (*supervisedCRPDependency) Close() error                                      { return nil }
func (*supervisedCRPDependency) Runtime() *crp.RuntimeStore                        { return nil }
func (*supervisedCRPDependency) ActivationExecutor() handler.CRPActivationExecutor { return nil }

func (d *supervisedCRPDependency) Wait(ctx context.Context) error {
	if d == nil || d.wait == nil {
		return nil
	}
	return d.wait(ctx)
}

func TestSuperviseProductionCRPReportsListenerFailure(t *testing.T) {
	want := errors.New("CRP listener failed")
	runtimeCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	var wg sync.WaitGroup
	superviseProductionCRP(runtimeCtx, &supervisedCRPDependency{wait: func(context.Context) error { return want }}, errCh, &wg)

	select {
	case got := <-errCh:
		if !errors.Is(got, want) {
			t.Fatalf("supervised error=%v, want %v", got, want)
		}
	case <-time.After(time.Second):
		t.Fatal("CRP listener failure did not terminate serve supervision")
	}
	cancel()
	wg.Wait()
}

func TestSuperviseProductionCRPRejectsUnexpectedCleanExit(t *testing.T) {
	runtimeCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	var wg sync.WaitGroup
	superviseProductionCRP(runtimeCtx, &supervisedCRPDependency{wait: func(context.Context) error { return nil }}, errCh, &wg)

	select {
	case got := <-errCh:
		if !errors.Is(got, ErrProductionCRPLifecycle) {
			t.Fatalf("clean listener exit error=%v, want ErrProductionCRPLifecycle", got)
		}
	case <-time.After(time.Second):
		t.Fatal("unexpected clean CRP listener exit was ignored")
	}
	cancel()
	wg.Wait()
}

func TestSuperviseProductionCRPIgnoresExitDuringRuntimeShutdown(t *testing.T) {
	release := make(chan struct{})
	runtimeCtx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	var wg sync.WaitGroup
	superviseProductionCRP(runtimeCtx, &supervisedCRPDependency{wait: func(context.Context) error {
		<-release
		return nil
	}}, errCh, &wg)

	cancel()
	close(release)
	wg.Wait()
	select {
	case got := <-errCh:
		t.Fatalf("planned runtime shutdown reported CRP error=%v", got)
	default:
	}
}
