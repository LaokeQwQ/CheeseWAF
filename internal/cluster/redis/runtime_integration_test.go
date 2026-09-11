package redis

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"testing"
	"time"
)

// TestRuntimeAdapterRedisServerRoundTrip is opt-in so normal CI remains
// dependency-free. Set CHEESEWAF_REDIS_RUNTIME_TEST_ADDR to a reachable
// redis-server address; the test seeds a unique identity key over raw RESP and
// then exercises the adapter's real pool and command framing.
func TestRuntimeAdapterRedisServerRoundTrip(t *testing.T) {
	addr := os.Getenv("CHEESEWAF_REDIS_RUNTIME_TEST_ADDR")
	if addr == "" {
		t.Skip("set CHEESEWAF_REDIS_RUNTIME_TEST_ADDR to run Redis integration")
	}
	prefix := fmt.Sprintf("cw-it:%d:", time.Now().UnixNano())
	identityKey := prefix + "instance_id"
	seedRedisValue(t, addr, identityKey, "node-it")

	adapter, err := Open(context.Background(), Config{
		Addr:        addr,
		Prefix:      prefix,
		IdentityKey: identityKey,
		InstanceID:  "node-it",
		PoolSize:    2,
		ReadTimeout: time.Second,
		Policy:      Policy{MaxLocalTTL: 100 * time.Millisecond, MaxLocalEntries: 8},
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = adapter.Close() })

	first, err := adapter.AcquireLock(context.Background(), "resource", 1, 2*time.Second)
	if err != nil {
		t.Fatalf("first lock: %v", err)
	}
	if _, err := adapter.AcquireLock(context.Background(), "resource", 1, time.Second); err != ErrLeaseBusy {
		t.Fatalf("second lock error=%v, want ErrLeaseBusy", err)
	}
	if err := adapter.Release(context.Background(), first); err != nil {
		t.Fatalf("release: %v", err)
	}
	if err := adapter.PutCache(context.Background(), "key", []byte{0, 1, 2, 255}, 1, time.Second); err != nil {
		t.Fatalf("put cache: %v", err)
	}
	value, ok, err := adapter.GetCache(context.Background(), "key", 1)
	if err != nil || !ok || string(value) != string([]byte{0, 1, 2, 255}) {
		t.Fatalf("get cache=(%v,%v,%v)", value, ok, err)
	}
	if err := adapter.MarkBlacklist(context.Background(), "ip", 1, time.Second); err != nil {
		t.Fatalf("mark blacklist: %v", err)
	}
	blocked, err := adapter.IsBlacklisted(context.Background(), "ip", 1)
	if err != nil || !blocked {
		t.Fatalf("blacklist=(%v,%v)", blocked, err)
	}
}

func seedRedisValue(t *testing.T, addr, key, value string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := writeRESP(conn, "SET", key, value, "PX", "60000"); err != nil {
		t.Fatal(err)
	}
	if _, err := readRESP(bufio.NewReader(conn)); err != nil {
		t.Fatal(err)
	}
}
