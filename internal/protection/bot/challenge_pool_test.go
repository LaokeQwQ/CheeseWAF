package bot

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestChallengeWorkerPoolRejectsWhenFull(t *testing.T) {
	pool := NewChallengeWorkerPool(1)
	started := make(chan struct{})
	release := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = pool.TryRun(func() error {
			close(started)
			<-release
			return nil
		})
	}()
	<-started
	if err := pool.TryRun(func() error { return nil }); err != ErrChallengeBusy {
		t.Fatalf("expected ErrChallengeBusy, got %v", err)
	}
	close(release)
	wg.Wait()
	if err := pool.TryRun(func() error { return nil }); err != nil {
		t.Fatalf("expected free slot after release, got %v", err)
	}
}

func TestChallengeWorkerPoolAllowsParallelUpToCap(t *testing.T) {
	pool := NewChallengeWorkerPool(4)
	var inFlight atomic.Int32
	var max atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = pool.TryRun(func() error {
				n := inFlight.Add(1)
				for {
					cur := max.Load()
					if n <= cur || max.CompareAndSwap(cur, n) {
						break
					}
				}
				time.Sleep(20 * time.Millisecond)
				inFlight.Add(-1)
				return nil
			})
		}()
	}
	wg.Wait()
	if max.Load() > 4 {
		t.Fatalf("max in-flight %d > 4", max.Load())
	}
}
