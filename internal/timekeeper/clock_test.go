package timekeeper

import (
	"sync"
	"testing"
	"time"
)

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Set(now time.Time) {
	c.mu.Lock()
	c.now = now
	c.mu.Unlock()
}

func TestDisciplinedClockAppliesOffset(t *testing.T) {
	baseTime := time.Date(2026, time.July, 15, 10, 0, 0, 0, time.UTC)
	base := &fakeClock{now: baseTime}
	clock := NewDisciplinedClock(base)

	clock.SetOffset(1750 * time.Millisecond)

	if got, want := clock.Now(), baseTime.Add(1750*time.Millisecond); !got.Equal(want) {
		t.Fatalf("Now() = %v, want %v", got, want)
	}
	if got := clock.Offset(); got != 1750*time.Millisecond {
		t.Fatalf("Offset() = %v, want %v", got, 1750*time.Millisecond)
	}
}

func TestDisciplinedClockNeverMovesBackward(t *testing.T) {
	baseTime := time.Date(2026, time.July, 15, 10, 0, 0, 0, time.UTC)
	base := &fakeClock{now: baseTime}
	clock := NewDisciplinedClock(base)
	clock.SetOffset(10 * time.Second)
	first := clock.Now()

	clock.SetOffset(-10 * time.Second)
	base.Set(baseTime.Add(time.Second))
	second := clock.Now()
	if second.Before(first) {
		t.Fatalf("clock moved backward from %v to %v", first, second)
	}

	base.Set(baseTime.Add(21 * time.Second))
	third := clock.Now()
	if third.Before(second) {
		t.Fatalf("clock moved backward from %v to %v", second, third)
	}
	if want := baseTime.Add(11 * time.Second); third.Before(want) {
		t.Fatalf("Now() after catch-up = %v, want at least %v", third, want)
	}
}

func TestDisciplinedClockClampedOffsetStillAdvances(t *testing.T) {
	baseTime := time.Date(2026, time.July, 15, 10, 0, 0, 0, time.UTC)
	base := &fakeClock{now: baseTime}
	clock := NewDisciplinedClock(base)
	clock.SetOffset(10 * time.Second)
	first := clock.Now()

	clock.SetOffset(0)
	time.Sleep(15 * time.Millisecond)
	second := clock.Now()
	if !second.After(first) {
		t.Fatalf("clamped reading should advance with real elapsed time, got %v after %v", second, first)
	}
	// While still clamped, readings continue; they must not freeze at first forever.
	time.Sleep(15 * time.Millisecond)
	third := clock.Now()
	if !third.After(second) {
		t.Fatalf("clamped reading froze at %v", third)
	}
}

func TestDisciplinedClockResetToSourceFollowsBackingClock(t *testing.T) {
	baseTime := time.Date(2026, time.July, 15, 10, 0, 0, 0, time.UTC)
	base := &fakeClock{now: baseTime}
	clock := NewDisciplinedClock(base)
	clock.SetOffset(10 * time.Second)
	_ = clock.Now()

	clock.ResetToSource()
	base.Set(baseTime.Add(time.Second))
	if got, want := clock.Now(), baseTime.Add(time.Second); !got.Equal(want) {
		t.Fatalf("Now() after ResetToSource = %v, want %v", got, want)
	}
	if clock.Offset() != 0 {
		t.Fatalf("Offset() after ResetToSource = %v, want 0", clock.Offset())
	}
}

func TestDisciplinedClockConcurrentNowAndAdjustment(t *testing.T) {
	baseTime := time.Date(2026, time.July, 15, 10, 0, 0, 0, time.UTC)
	base := &fakeClock{now: baseTime}
	clock := NewDisciplinedClock(base)

	const workers = 32
	const calls = 500
	start := make(chan struct{})
	var wg sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			var previous time.Time
			for i := 0; i < calls; i++ {
				now := clock.Now()
				if !previous.IsZero() && now.Before(previous) {
					t.Errorf("clock moved backward from %v to %v", previous, now)
					return
				}
				previous = now
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < calls; i++ {
			clock.SetOffset(time.Duration((i%21)-10) * time.Second)
			base.Set(baseTime.Add(time.Duration(i) * time.Millisecond))
		}
	}()

	close(start)
	wg.Wait()
}
