package redis

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestPoolRejectsUnapprovedEvalScripts(t *testing.T) {
	p, err := NewPool(PoolConfig{Addr: "127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if _, err := p.Do(context.Background(), "EVAL", "return 1", "0"); err == nil {
		t.Fatal("arbitrary EVAL script must be rejected before dialing")
	}
}

func TestPoolDoAcceptsNilContextAsBackground(t *testing.T) {
	p, err := NewPool(PoolConfig{Addr: "127.0.0.1:1", DialTimeout: 10 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if _, err := p.Do(nil, "PING"); err == nil || errors.Is(err, ErrProtocol) {
		t.Fatalf("nil context should be normalized, got %v", err)
	}
}

func TestRuntimeAdapterUsesInjectedClockForHandleExpiry(t *testing.T) {
	server := newFakeRedis(t)
	server.set("cw:instance_id", []byte("node-a"))
	now := time.Unix(1000, 0).UTC()
	adapter, err := Open(context.Background(), Config{
		Addr:       server.addr(),
		Prefix:     "cw:",
		InstanceID: "node-a",
		Now:        func() time.Time { return now },
		PoolSize:   1,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close()
	h, err := adapter.AcquireLease(context.Background(), "clock", 1, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(6 * time.Second)
	if err := adapter.Validate(context.Background(), h); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired handle error=%v, want ErrExpired", err)
	}
}

func TestRuntimeAdapterEpochSetterBindsSubsequentOperations(t *testing.T) {
	server := newFakeRedis(t)
	server.set("cw:instance_id", []byte("node-a"))
	adapter, err := Open(context.Background(), Config{Addr: server.addr(), Prefix: "cw:", InstanceID: "node-a", PoolSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close()
	if err := adapter.SetEpoch(9); err != nil {
		t.Fatal(err)
	}
	if got := adapter.Epoch(); got != 9 {
		t.Fatalf("epoch=%d, want 9", got)
	}
	if _, err := adapter.AcquireLease(context.Background(), "wrong", 8, time.Second); !errors.Is(err, ErrEpochMismatch) {
		t.Fatalf("wrong epoch error=%v, want ErrEpochMismatch", err)
	}
	if _, err := adapter.AcquireLease(context.Background(), "right", 9, time.Second); err != nil {
		t.Fatalf("current epoch acquire: %v", err)
	}
}

func TestRuntimeAdapterEpochCannotRegress(t *testing.T) {
	adapter, err := NewWithClient(Config{Addr: "127.0.0.1:6379", InstanceID: "node-a", Epoch: 9}, &stubCommandClient{})
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close()
	if err := adapter.SetEpoch(8); !errors.Is(err, ErrEpochRegression) {
		t.Fatalf("epoch regression error=%v, want ErrEpochRegression", err)
	}
	if got := adapter.Epoch(); got != 9 {
		t.Fatalf("epoch after rejected regression=%d, want 9", got)
	}
}

func TestPoolAcquireTimeoutWhenAllSlotsAreHeld(t *testing.T) {
	p, err := NewPool(PoolConfig{Addr: "127.0.0.1:1", Size: 1, AcquireTimeout: 20 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	<-p.tokens
	defer p.releaseToken()
	start := time.Now()
	if _, err := p.Do(context.Background(), "PING"); !errors.Is(err, ErrPoolTimeout) {
		t.Fatalf("pool error=%v, want ErrPoolTimeout", err)
	}
	if elapsed := time.Since(start); elapsed < 15*time.Millisecond || elapsed > 500*time.Millisecond {
		t.Fatalf("acquire timeout elapsed=%s, want bounded timeout", elapsed)
	}
}

func TestRuntimeAdapterRejectsWhitespaceInstanceIdentity(t *testing.T) {
	client := &stubCommandClient{}
	for _, instanceID := range []string{"node a", " node-a", "node-a ", "node-\u200b", "node-\u2060"} {
		if _, err := NewWithClient(Config{
			Addr:       "127.0.0.1:6379",
			InstanceID: instanceID,
		}, client); err == nil {
			t.Fatalf("instance identity %q was accepted", instanceID)
		}
	}
}

func TestRuntimeAdapterRejectsNilReceiverForHandleOperations(t *testing.T) {
	var adapter *RuntimeAdapter
	h := Handle{Token: "token", Key: "key", Epoch: 1, ExpiresAt: time.Now().Add(time.Minute), Operation: OperationLease}
	if err := adapter.Validate(context.Background(), h); !errors.Is(err, ErrAdapterClosed) {
		t.Fatalf("nil Validate error=%v, want ErrAdapterClosed", err)
	}
	if err := adapter.Release(context.Background(), h); !errors.Is(err, ErrAdapterClosed) {
		t.Fatalf("nil Release error=%v, want ErrAdapterClosed", err)
	}
}

func TestPoolRejectsOversizedRESPBulkReply(t *testing.T) {
	reader := bufio.NewReader(strings.NewReader("$999999999\r\n"))
	if _, err := readRESP(reader); !errors.Is(err, ErrProtocol) {
		t.Fatalf("oversized bulk reply error=%v, want ErrProtocol", err)
	}
}

func TestPoolBoundsRESPLineWithoutTerminator(t *testing.T) {
	reader := bufio.NewReaderSize(strings.NewReader(strings.Repeat("x", maxRESPLine*2)), 32)
	if _, err := readRESP(reader); !errors.Is(err, ErrProtocol) {
		t.Fatalf("unterminated oversized reply error=%v, want ErrProtocol", err)
	}
}

func TestGetCachePropagatesProtocolProbeError(t *testing.T) {
	client := &scriptedCommandClient{do: func(_ context.Context, args ...string) (any, error) {
		if len(args) > 0 && args[0] == "PING" {
			return nil, fmt.Errorf("%w: malformed PONG", ErrProtocol)
		}
		return nil, nil
	}}
	adapter, err := NewWithClient(Config{Addr: "127.0.0.1:6379", InstanceID: "node-a"}, client)
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close()
	if _, ok, err := adapter.GetCache(context.Background(), "key", 1); !errors.Is(err, ErrProtocol) || ok {
		t.Fatalf("protocol probe result=(ok=%v, err=%v), want ErrProtocol and miss", ok, err)
	}
}

func TestGetCachePropagatesCallerCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	client := &scriptedCommandClient{do: func(ctx context.Context, _ ...string) (any, error) {
		return nil, ctx.Err()
	}}
	adapter, err := NewWithClient(Config{Addr: "127.0.0.1:6379", InstanceID: "node-a"}, client)
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close()
	if _, ok, err := adapter.GetCache(ctx, "key", 1); !errors.Is(err, context.Canceled) || ok {
		t.Fatalf("canceled probe result=(ok=%v, err=%v), want context.Canceled and miss", ok, err)
	}
}

func TestNewWithClientRejectsTypedNilClient(t *testing.T) {
	var client *stubCommandClient
	if _, err := NewWithClient(Config{Addr: "127.0.0.1:6379", InstanceID: "node-a"}, client); err == nil {
		t.Fatal("typed nil command client was accepted")
	}
}

func TestRefreshDoesNotResurrectStatusAfterConcurrentClose(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	client := &scriptedCommandClient{do: func(_ context.Context, args ...string) (any, error) {
		if len(args) > 0 && args[0] == "PING" {
			close(started)
			<-release
		}
		return "PONG", nil
	}}
	adapter, err := NewWithClient(Config{Addr: "127.0.0.1:6379", InstanceID: "node-a"}, client)
	if err != nil {
		t.Fatal(err)
	}
	refreshDone := make(chan error, 1)
	go func() { refreshDone <- adapter.Refresh(context.Background()) }()
	<-started
	if err := adapter.Close(); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-refreshDone; !errors.Is(err, ErrAdapterClosed) {
		t.Fatalf("Refresh after close error=%v, want ErrAdapterClosed", err)
	}
	if got := adapter.Status(); got != StatusUnavailable {
		t.Fatalf("status after concurrent close=%v, want unavailable", got)
	}
}

type stubCommandClient struct{}

func (*stubCommandClient) Do(context.Context, ...string) (any, error) { return nil, nil }
func (*stubCommandClient) Close() error                               { return nil }

type scriptedCommandClient struct {
	mu sync.Mutex
	do func(context.Context, ...string) (any, error)
}

func (c *scriptedCommandClient) Do(ctx context.Context, args ...string) (any, error) {
	c.mu.Lock()
	do := c.do
	c.mu.Unlock()
	if do == nil {
		return nil, nil
	}
	return do(ctx, args...)
}

func (*scriptedCommandClient) Close() error { return nil }
