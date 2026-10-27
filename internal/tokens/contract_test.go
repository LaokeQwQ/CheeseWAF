package tokens

import (
	"errors"
	"testing"
	"time"
)

func TestResolveLifetimeEnforcesSafeDefaultsAndBounds(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	resolved, err := ResolveLifetime(now, 0, time.Time{}, false, false)
	if err != nil {
		t.Fatalf("default lifetime: %v", err)
	}
	if !resolved.ExpiresAt.Equal(now.Add(DefaultTTL)) || resolved.NeverExpire {
		t.Fatalf("default lifetime = %+v", resolved)
	}
	if _, err := ResolveLifetime(now, MaxTTL+time.Second, time.Time{}, false, false); !errors.Is(err, ErrTTLExceeded) {
		t.Fatalf("overlong ttl error = %v", err)
	}
	if _, err := ResolveLifetime(now, 0, now.Add(MaxTTL+time.Second), false, false); !errors.Is(err, ErrTTLExceeded) {
		t.Fatalf("overlong absolute expiry error = %v", err)
	}
}

func TestResolveLifetimeNeverExpireRequiresExplicitConfirmation(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	if _, err := ResolveLifetime(now, 0, time.Time{}, true, false); !errors.Is(err, ErrSecondConfirmationRequired) {
		t.Fatalf("missing confirmation error = %v", err)
	}
	resolved, err := ResolveLifetime(now, 0, time.Time{}, true, true)
	if err != nil || !resolved.NeverExpire || !resolved.ExpiresAt.IsZero() {
		t.Fatalf("confirmed non-expiring lifetime = %+v err=%v", resolved, err)
	}
	if _, err := ResolveLifetime(now, time.Hour, time.Time{}, true, true); !errors.Is(err, ErrInvalidTTL) {
		t.Fatalf("non-expiring ttl accepted: %v", err)
	}
}
