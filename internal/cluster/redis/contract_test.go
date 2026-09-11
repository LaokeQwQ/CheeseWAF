package redis

import (
	"errors"
	"testing"
	"time"
)

func TestEvaluateRedisFailurePoliciesAreExplicitAndBounded(t *testing.T) {
	p := Policy{MaxLocalTTL: 30 * time.Second, MaxLocalEntries: 2}
	cases := []struct {
		name   string
		op     Operation
		status Status
		ttl    time.Duration
		mode   Mode
	}{
		{"available lease uses redis", OperationLease, StatusAvailable, time.Minute, ModeRedis},
		{"timeout lease uses bounded local", OperationLease, StatusTimeout, 10 * time.Second, ModeLocal},
		{"long unavailable lease fails closed", OperationLease, StatusUnavailable, time.Minute, ModeFailClosed},
		{"unknown lock fails closed", OperationLock, StatusUnknownInstance, time.Second, ModeFailClosed},
		{"timeout blacklist fails closed", OperationBlacklist, StatusTimeout, time.Second, ModeFailClosed},
		{"unknown cache is a miss", OperationCache, StatusUnknownInstance, time.Second, ModeCacheMiss},
		{"unavailable cache is a miss", OperationCache, StatusUnavailable, time.Second, ModeCacheMiss},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Evaluate(p, tc.op, tc.status, 9, tc.ttl)
			if err != nil {
				t.Fatal(err)
			}
			if got.Mode != tc.mode {
				t.Fatalf("mode=%s want %s", got.Mode, tc.mode)
			}
			if got.Mode == ModeLocal && got.TTL > p.MaxLocalTTL {
				t.Fatalf("local TTL escaped bound: %s", got.TTL)
			}
		})
	}
}

func TestEvaluateRejectsMissingEpochAndInvalidTTL(t *testing.T) {
	p := Policy{MaxLocalTTL: time.Minute, MaxLocalEntries: 1}
	if _, err := Evaluate(p, OperationLease, StatusAvailable, 0, time.Second); !errors.Is(err, ErrEpochRequired) {
		t.Fatalf("epoch: %v", err)
	}
	if _, err := Evaluate(p, OperationLock, StatusAvailable, 1, 0); !errors.Is(err, ErrInvalidTTL) {
		t.Fatalf("ttl: %v", err)
	}
}

func TestLocalStateIsBoundedAndEpochScoped(t *testing.T) {
	now := time.Unix(100, 0)
	s := NewLocalState(Policy{MaxLocalTTL: time.Minute, MaxLocalEntries: 1})
	token, err := s.Reserve(OperationLock, "resource", 7, 20*time.Second, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Reserve(OperationLock, "other", 7, time.Second, now); !errors.Is(err, ErrLocalCapacity) {
		t.Fatalf("capacity: %v", err)
	}
	if err := s.Release(token, OperationLock, "resource", 8); !errors.Is(err, ErrEpochMismatch) {
		t.Fatalf("epoch release: %v", err)
	}
	if err := s.Release(token, OperationLock, "resource", 7); err != nil {
		t.Fatal(err)
	}
}

func TestLocalReservationExpiresAndCannotBeReused(t *testing.T) {
	now := time.Unix(150, 0)
	s := NewLocalState(Policy{MaxLocalTTL: time.Minute, MaxLocalEntries: 1})
	token, err := s.Reserve(OperationLease, "target", 2, 5*time.Second, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Valid(token, OperationLease, "target", 2, now.Add(5*time.Second)); !errors.Is(err, ErrExpired) {
		t.Fatalf("expected expiry, got %v", err)
	}
	if _, err := s.Reserve(OperationLease, "target-2", 2, time.Second, now.Add(5*time.Second)); err != nil {
		t.Fatalf("expired reservation did not free capacity: %v", err)
	}
}

func TestLocalBlacklistAndCacheExpireWithoutDurableTruth(t *testing.T) {
	now := time.Unix(200, 0)
	s := NewLocalState(Policy{MaxLocalTTL: time.Minute, MaxLocalEntries: 4})
	if err := s.MarkBlacklist("ip:1", 3, 10*time.Second, now); err != nil {
		t.Fatal(err)
	}
	blocked, err := s.Blacklisted("ip:1", 3, now.Add(5*time.Second))
	if err != nil || !blocked {
		t.Fatalf("blacklist=%v err=%v", blocked, err)
	}
	blocked, err = s.Blacklisted("ip:1", 3, now.Add(11*time.Second))
	if err != nil || blocked {
		t.Fatalf("expired blacklist=%v err=%v", blocked, err)
	}
	if err := s.PutCache("k", []byte("v"), 3, 10*time.Second, now); err != nil {
		t.Fatal(err)
	}
	value, ok := s.GetCache("k", 4, now.Add(time.Second))
	if ok || value != nil {
		t.Fatalf("cross-epoch cache returned: %q", value)
	}
	value, ok = s.GetCache("k", 3, now.Add(11*time.Second))
	if ok || value != nil {
		t.Fatalf("expired cache returned: %q", value)
	}
}

func TestLocalStateCanRefreshAnExistingCacheAtCapacity(t *testing.T) {
	now := time.Unix(300, 0)
	s := NewLocalState(Policy{MaxLocalTTL: time.Minute, MaxLocalEntries: 1})
	if err := s.PutCache("k", []byte("v1"), 1, time.Second, now); err != nil {
		t.Fatal(err)
	}
	if err := s.PutCache("k", []byte("v2"), 1, time.Second, now); err != nil {
		t.Fatalf("refreshing an existing key should not consume another slot: %v", err)
	}
	value, ok := s.GetCache("k", 1, now)
	if !ok || string(value) != "v2" {
		t.Fatalf("cache=%q ok=%v, want v2/true", value, ok)
	}
}

func TestLocalStateReservationCanAdvanceEpoch(t *testing.T) {
	now := time.Unix(400, 0)
	s := NewLocalState(Policy{MaxLocalTTL: time.Minute, MaxLocalEntries: 2})
	if _, err := s.Reserve(OperationLease, "resource", 1, time.Second, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Reserve(OperationLease, "resource", 2, time.Second, now); err != nil {
		t.Fatalf("new epoch should not be blocked by old reservation: %v", err)
	}
}
