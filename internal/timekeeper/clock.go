// Package timekeeper provides a process-wide disciplined clock and NTP service.
package timekeeper

import (
	"sync"
	"time"
)

// Clock returns wall-clock time.
type Clock interface {
	Now() time.Time
}

// SystemClock reads the operating system clock.
type SystemClock struct{}

// Now returns the current system time with Go's monotonic reading attached.
func (SystemClock) Now() time.Time {
	return time.Now()
}

// DisciplinedClock applies a synchronized offset without moving backward.
// When an offset reduction would jump the wall clock backward, Now() keeps
// advancing from the previous reading using real elapsed time so JWT/captcha
// TTLs still expire instead of freezing at the last disciplined value.
type DisciplinedClock struct {
	mu       sync.Mutex
	source   Clock
	offset   time.Duration
	last     time.Time
	lastMono time.Time
}

// NewDisciplinedClock creates a clock backed by source.
func NewDisciplinedClock(source Clock) *DisciplinedClock {
	if source == nil {
		source = SystemClock{}
	}
	return &DisciplinedClock{source: source}
}

// Now returns the offset-adjusted time and clamps backward corrections.
func (c *DisciplinedClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	mono := time.Now()
	candidate := c.source.Now().Add(c.offset)
	if !c.last.IsZero() && candidate.Before(c.last) {
		elapsed := mono.Sub(c.lastMono)
		if elapsed < 0 {
			elapsed = 0
		}
		candidate = c.last.Add(elapsed)
	}
	c.last = candidate
	c.lastMono = mono
	return candidate
}

// SetOffset atomically replaces the clock correction.
func (c *DisciplinedClock) SetOffset(offset time.Duration) {
	c.mu.Lock()
	c.offset = offset
	c.mu.Unlock()
}

// ResetToSource drops the correction and releases the clamp so subsequent
// readings follow the backing clock immediately (used when disabling sync).
func (c *DisciplinedClock) ResetToSource() {
	c.mu.Lock()
	c.offset = 0
	c.last = time.Time{}
	c.lastMono = time.Time{}
	c.mu.Unlock()
}

// Offset returns the currently configured correction.
func (c *DisciplinedClock) Offset() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.offset
}

var _ Clock = SystemClock{}
var _ Clock = (*DisciplinedClock)(nil)
