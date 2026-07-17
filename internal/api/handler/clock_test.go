package handler

import (
	"sync"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

type handlerTestClock struct {
	mu  sync.RWMutex
	now time.Time
}

func (c *handlerTestClock) Now() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.now
}

func (c *handlerTestClock) Set(now time.Time) {
	c.mu.Lock()
	c.now = now
	c.mu.Unlock()
}

func TestHandlerUsesInjectedClock(t *testing.T) {
	initial := time.Date(2026, time.July, 15, 9, 30, 0, 0, time.FixedZone("UTC+8", 8*60*60))
	clock := &handlerTestClock{now: initial}
	cfg := config.Default()
	cfg.CAPTCHAAssets.Local.Path = t.TempDir()
	h := New(Options{Config: &cfg, Clock: clock})

	if got := h.StartedAt; !got.Equal(initial.UTC()) || got.Location() != time.UTC {
		t.Fatalf("StartedAt = %v, want %v UTC", got, initial.UTC())
	}

	advanced := initial.Add(90 * time.Minute)
	clock.Set(advanced)
	if got := h.nowUTC(); !got.Equal(advanced.UTC()) || got.Location() != time.UTC {
		t.Fatalf("nowUTC() = %v, want %v UTC", got, advanced.UTC())
	}
}

func TestClusterIdentityUsesInjectedClock(t *testing.T) {
	initial := time.Date(2026, time.July, 15, 3, 30, 0, 0, time.UTC)
	clock := &handlerTestClock{now: initial}
	cfg := config.Default()
	cfg.Setup.DataDir = t.TempDir()
	cfg.CAPTCHAAssets.Local.Path = t.TempDir()
	h := New(Options{Config: &cfg, Clock: clock})

	service, err := h.clusterIdentityService()
	if err != nil {
		t.Fatalf("cluster identity service: %v", err)
	}
	token, err := service.CreateJoinToken("waf", time.Hour, 1)
	if err != nil {
		t.Fatalf("create join token: %v", err)
	}
	if !token.CreatedAt.Equal(initial) {
		t.Fatalf("token creation time = %s, want %s", token.CreatedAt, initial)
	}
	if want := initial.Add(time.Hour); !token.ExpiresAt.Equal(want) {
		t.Fatalf("token expiry = %s, want %s", token.ExpiresAt, want)
	}
}
