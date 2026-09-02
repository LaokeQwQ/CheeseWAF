package bot

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

// redisTestAddr is where the integration tests expect a Redis instance.
// Override with CHEESEWAF_REDIS_TEST_ADDR. When nothing is listening the Redis
// tests skip instead of failing, so CI without Redis stays green.
func redisTestAddr(t *testing.T) string {
	t.Helper()
	addr := os.Getenv("CHEESEWAF_REDIS_TEST_ADDR")
	if addr == "" {
		addr = "127.0.0.1:6399"
	}
	conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
	if err != nil {
		t.Skipf("redis not reachable at %s: %v", addr, err)
	}
	_ = conn.Close()
	return addr
}

func newTestRedisBackend(t *testing.T, limits ChallengeStoreConfig) *RedisBackend {
	t.Helper()
	addr := redisTestAddr(t)
	// Randomised prefix so repeated/concurrent runs never share keys.
	cfg := BackendConfig{
		Driver:   "redis",
		RedisURL: "redis://" + addr + "/0",
		// Distinct per test to avoid cross-test contamination.
		KeyPrefix: fmt.Sprintf("it:%d:%d:", time.Now().UnixNano(), os.Getpid()),
		Limits:    limits,
	}
	backend, err := NewRedisBackend(cfg)
	if err != nil {
		t.Fatalf("NewRedisBackend: %v", err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	return backend
}

// TestRedisBackendIssueConsumeLifecycle proves the Lua scripts actually execute:
// reserve -> start -> commit -> consume, with a second consume rejected.
// This backend had zero test coverage before, so a syntax or argument error in
// any of the five scripts surfaces here.
func TestRedisBackendIssueConsumeLifecycle(t *testing.T) {
	backend := newTestRedisBackend(t, ChallengeStoreConfig{
		Capacity:      16,
		UsedRetention: time.Minute,
	})
	ctx := context.Background()

	res, err := backend.ReserveScoped(ctx, "owner-1", "peer-1", time.Now().Add(time.Minute))
	if err != nil {
		t.Fatalf("ReserveScoped: %v", err)
	}
	if err := backend.Start(ctx, res); err != nil {
		t.Fatalf("Start: %v", err)
	}
	const jti = "jti-lifecycle-1"
	if err := backend.Commit(ctx, res, jti, time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	if !backend.Consume(ctx, jti) {
		t.Fatal("first Consume must succeed")
	}
	if backend.Consume(ctx, jti) {
		t.Fatal("second Consume must fail: jti is single-use")
	}
}

// TestRedisBackendConsumeIsSingleUseUnderConcurrency is the atomicity guarantee
// that motivated the Lua scripts: exactly one caller may consume a jti.
func TestRedisBackendConsumeIsSingleUseUnderConcurrency(t *testing.T) {
	backend := newTestRedisBackend(t, ChallengeStoreConfig{
		Capacity:      16,
		UsedRetention: time.Minute,
	})
	ctx := context.Background()

	const jti = "jti-concurrent-1"
	res, err := backend.ReserveScoped(ctx, "owner-1", "peer-1", time.Now().Add(time.Minute))
	if err != nil {
		t.Fatalf("ReserveScoped: %v", err)
	}
	if err := backend.Start(ctx, res); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := backend.Commit(ctx, res, jti, time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	const goroutines = 16
	var (
		mu      sync.Mutex
		success int
		startWG sync.WaitGroup
		startCh = make(chan struct{})
	)
	startWG.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer startWG.Done()
			<-startCh
			if backend.Consume(ctx, jti) {
				mu.Lock()
				success++
				mu.Unlock()
			}
		}()
	}
	close(startCh)
	startWG.Wait()

	if success != 1 {
		t.Fatalf("exactly one concurrent Consume must win, got %d", success)
	}
}

// TestRedisBackendReserveRespectsCapacity checks the reservation counter: once
// capacity is exhausted ReserveScoped must error rather than silently succeed.
func TestRedisBackendReserveRespectsCapacity(t *testing.T) {
	const capacity = 3
	backend := newTestRedisBackend(t, ChallengeStoreConfig{
		Capacity:           capacity,
		ConcurrentCapacity: capacity,
		UsedRetention:      time.Minute,
	})
	ctx := context.Background()

	var held []*ChallengeReservation
	for i := 0; i < capacity; i++ {
		res, err := backend.ReserveScoped(ctx, fmt.Sprintf("owner-%d", i), "", time.Now().Add(time.Minute))
		if err != nil {
			t.Fatalf("reservation %d should succeed: %v", i, err)
		}
		held = append(held, res)
	}

	if _, err := backend.ReserveScoped(ctx, "owner-overflow", "", time.Now().Add(time.Minute)); err == nil {
		t.Fatal("reservation beyond capacity must fail")
	}

	// Rolling back must give the slot back.
	if !backend.Rollback(ctx, held[0]) {
		t.Fatal("Rollback should report a release")
	}
	if _, err := backend.ReserveScoped(ctx, "owner-after-rollback", "", time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("reservation after rollback should succeed: %v", err)
	}
}
