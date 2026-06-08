package ratelimit

import (
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

func TestLimiterBlocksAfterWindowQuota(t *testing.T) {
	limiter := New(config.RateLimitProfile{Requests: 1, Window: time.Minute, Burst: 1}, true)
	if !limiter.Allow("client") || !limiter.Allow("client") {
		t.Fatal("expected request and burst to pass")
	}
	if limiter.Allow("client") {
		t.Fatal("expected third request to be blocked")
	}
}
