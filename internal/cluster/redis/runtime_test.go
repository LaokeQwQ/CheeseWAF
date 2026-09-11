package redis

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRuntimeAdapterPingsAndVerifiesInstanceIdentity(t *testing.T) {
	server := newFakeRedis(t)
	server.set("cw:instance_id", []byte("node-a"))

	adapter, err := Open(context.Background(), Config{
		Addr:       server.addr(),
		Prefix:     "cw:",
		InstanceID: "node-a",
		PoolSize:   2,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = adapter.Close() })

	if got := adapter.Status(); got != StatusAvailable {
		t.Fatalf("status=%v, want available", got)
	}
	if err := adapter.Ping(context.Background()); err != nil {
		t.Fatalf("Ping: %v", err)
	}

	server.set("cw:instance_id", []byte("node-b"))
	if err := adapter.Refresh(context.Background()); !errors.Is(err, ErrUnknownInstance) {
		t.Fatalf("identity change error=%v, want ErrUnknownInstance", err)
	}
	if got := adapter.Status(); got != StatusUnknownInstance {
		t.Fatalf("status after identity change=%v, want unknown", got)
	}
}

func TestRuntimeAdapterLeaseLockAndEpochBinding(t *testing.T) {
	server := newFakeRedis(t)
	server.set("cw:instance_id", []byte("node-a"))
	adapter, err := Open(context.Background(), Config{
		Addr:       server.addr(),
		Prefix:     "cw:",
		InstanceID: "node-a",
		PoolSize:   2,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = adapter.Close() })

	lease, err := adapter.AcquireLease(context.Background(), "resource-a", 7, time.Second)
	if err != nil {
		t.Fatalf("AcquireLease: %v", err)
	}
	if lease.Mode != ModeRedis || lease.Epoch != 7 || lease.Token == "" {
		t.Fatalf("unexpected lease: %+v", lease)
	}
	if err := adapter.Validate(context.Background(), lease); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	wrongEpoch := lease
	wrongEpoch.Epoch = 8
	if err := adapter.Validate(context.Background(), wrongEpoch); !errors.Is(err, ErrEpochMismatch) {
		t.Fatalf("wrong epoch validation=%v, want ErrEpochMismatch", err)
	}
	if err := adapter.Release(context.Background(), wrongEpoch); !errors.Is(err, ErrEpochMismatch) {
		t.Fatalf("wrong epoch release=%v, want ErrEpochMismatch", err)
	}
	if err := adapter.Release(context.Background(), lease); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if err := adapter.Release(context.Background(), lease); !errors.Is(err, ErrInvalidLease) {
		t.Fatalf("second release=%v, want ErrInvalidLease", err)
	}

	lock, err := adapter.AcquireLock(context.Background(), "resource-a", 7, time.Second)
	if err != nil {
		t.Fatalf("AcquireLock: %v", err)
	}
	if lock.Operation != OperationLock {
		t.Fatalf("operation=%v, want lock", lock.Operation)
	}
	if err := adapter.Release(context.Background(), lock); err != nil {
		t.Fatalf("Release lock: %v", err)
	}
}

func TestRuntimeAdapterUnknownInstanceFailsClosedAndCacheMisses(t *testing.T) {
	server := newFakeRedis(t)
	server.set("cw:instance_id", []byte("other-node"))
	adapter, err := Open(context.Background(), Config{
		Addr:       server.addr(),
		Prefix:     "cw:",
		InstanceID: "node-a",
		PoolSize:   1,
		Policy:     Policy{MaxLocalTTL: time.Second, MaxLocalEntries: 2},
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = adapter.Close() })

	if _, err := adapter.AcquireLease(context.Background(), "x", 1, 100*time.Millisecond); !errors.Is(err, ErrFailClosed) {
		t.Fatalf("unknown lease error=%v, want ErrFailClosed", err)
	}
	if err := adapter.MarkBlacklist(context.Background(), "ip:1", 1, time.Second); !errors.Is(err, ErrFailClosed) {
		t.Fatalf("unknown blacklist error=%v, want ErrFailClosed", err)
	}
	if value, ok, err := adapter.GetCache(context.Background(), "k", 1); err != nil || ok || value != nil {
		t.Fatalf("unknown cache=(%q,%v,%v), want miss", value, ok, err)
	}
}

func TestRuntimeAdapterUnavailableUsesBoundedLocalLeaseAndCacheMiss(t *testing.T) {
	adapter, err := Open(context.Background(), Config{
		Addr:        "127.0.0.1:1",
		Prefix:      "cw:",
		InstanceID:  "node-a",
		PoolSize:    1,
		DialTimeout: 20 * time.Millisecond,
		Policy:      Policy{MaxLocalTTL: 100 * time.Millisecond, MaxLocalEntries: 2},
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = adapter.Close() })

	lease, err := adapter.AcquireLease(context.Background(), "local", 4, 50*time.Millisecond)
	if err != nil {
		t.Fatalf("AcquireLease fallback: %v", err)
	}
	if lease.Mode != ModeLocal {
		t.Fatalf("fallback mode=%v, want local", lease.Mode)
	}
	if err := adapter.Validate(context.Background(), lease); err != nil {
		t.Fatalf("Validate local lease: %v", err)
	}
	if err := adapter.Release(context.Background(), lease); err != nil {
		t.Fatalf("Release local lease: %v", err)
	}
	if value, ok, err := adapter.GetCache(context.Background(), "k", 4); err != nil || ok || value != nil {
		t.Fatalf("unavailable cache=(%q,%v,%v), want miss", value, ok, err)
	}
	if err := adapter.MarkBlacklist(context.Background(), "ip:1", 4, 50*time.Millisecond); !errors.Is(err, ErrFailClosed) {
		t.Fatalf("unavailable blacklist error=%v, want ErrFailClosed", err)
	}
}

func TestRuntimeAdapterCacheAndBlacklistAreEpochScoped(t *testing.T) {
	server := newFakeRedis(t)
	server.set("cw:instance_id", []byte("node-a"))
	adapter, err := Open(context.Background(), Config{
		Addr:       server.addr(),
		Prefix:     "cw:",
		InstanceID: "node-a",
		Policy:     Policy{MaxLocalTTL: time.Second, MaxLocalEntries: 8},
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = adapter.Close() })

	if err := adapter.PutCache(context.Background(), "k", []byte("v"), 3, time.Second); err != nil {
		t.Fatalf("PutCache: %v", err)
	}
	if value, ok, err := adapter.GetCache(context.Background(), "k", 3); err != nil || !ok || string(value) != "v" {
		t.Fatalf("cache current=(%q,%v,%v)", value, ok, err)
	}
	if value, ok, err := adapter.GetCache(context.Background(), "k", 4); err != nil || ok || value != nil {
		t.Fatalf("cache stale=(%q,%v,%v), want miss", value, ok, err)
	}
	if err := adapter.MarkBlacklist(context.Background(), "ip:1", 3, time.Second); err != nil {
		t.Fatalf("MarkBlacklist: %v", err)
	}
	blocked, err := adapter.IsBlacklisted(context.Background(), "ip:1", 3)
	if err != nil || !blocked {
		t.Fatalf("blacklist current=(%v,%v)", blocked, err)
	}
	blocked, err = adapter.IsBlacklisted(context.Background(), "ip:1", 4)
	if err != nil || blocked {
		t.Fatalf("blacklist stale=(%v,%v), want false", blocked, err)
	}
}

func TestRuntimeAdapterBlacklistVerifiesInstanceAndEpochValue(t *testing.T) {
	server := newFakeRedis(t)
	server.set("cw:instance_id", []byte("node-a"))
	adapter, err := Open(context.Background(), Config{Addr: server.addr(), Prefix: "cw:", InstanceID: "node-a", PoolSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close()
	if err := adapter.MarkBlacklist(context.Background(), "ip:1", 3, time.Second); err != nil {
		t.Fatal(err)
	}
	server.set(adapter.stateKey(OperationBlacklist, "ip:1", 3), []byte("other-node\x003"))
	blocked, err := adapter.IsBlacklisted(context.Background(), "ip:1", 3)
	if err != nil || blocked {
		t.Fatalf("tampered blacklist=(%v,%v), want false without error", blocked, err)
	}
}

func TestRuntimeAdapterGetCacheRejectsMissingEpoch(t *testing.T) {
	server := newFakeRedis(t)
	server.set("cw:instance_id", []byte("node-a"))
	adapter, err := Open(context.Background(), Config{
		Addr:       server.addr(),
		Prefix:     "cw:",
		InstanceID: "node-a",
		PoolSize:   1,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close()
	if err := adapter.PutCache(context.Background(), "k", []byte("v"), 3, time.Second); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := adapter.GetCache(context.Background(), "k", 0); !errors.Is(err, ErrEpochRequired) || ok {
		t.Fatalf("missing epoch cache read=(ok=%v, err=%v), want ErrEpochRequired and miss", ok, err)
	}
}

func TestRuntimeAdapterPoolTimeoutAndCloseAreDeterministic(t *testing.T) {
	server := newFakeRedis(t)
	server.set("cw:instance_id", []byte("node-a"))
	server.stall = true
	adapter, err := Open(context.Background(), Config{
		Addr:        server.addr(),
		Prefix:      "cw:",
		InstanceID:  "node-a",
		PoolSize:    1,
		ReadTimeout: 30 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := adapter.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := adapter.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if _, err := adapter.AcquireLease(context.Background(), "x", 1, time.Second); !errors.Is(err, ErrAdapterClosed) {
		t.Fatalf("after close error=%v, want ErrAdapterClosed", err)
	}
}

// fakeRedisServer is intentionally tiny: it implements only the RESP2 commands
// exercised by the runtime adapter tests, while still exercising a real TCP
// connection, command framing, pooling and deadlines.
type fakeRedisServer struct {
	t      *testing.T
	ln     net.Listener
	mu     sync.Mutex
	values map[string][]byte
	stall  bool
}

func newFakeRedis(t *testing.T) *fakeRedisServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &fakeRedisServer{t: t, ln: ln, values: make(map[string][]byte)}
	t.Cleanup(func() { _ = ln.Close() })
	go s.serve()
	return s
}

func (s *fakeRedisServer) addr() string { return s.ln.Addr().String() }

func (s *fakeRedisServer) set(key string, value []byte) {
	s.mu.Lock()
	s.values[key] = append([]byte(nil), value...)
	s.mu.Unlock()
}

func (s *fakeRedisServer) serve() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(conn)
	}
}

func (s *fakeRedisServer) handle(conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	for {
		args, err := readFakeCommand(r)
		if err != nil {
			return
		}
		if s.stall {
			select {}
		}
		s.writeReply(conn, args)
	}
}

func (s *fakeRedisServer) writeReply(w io.Writer, args [][]byte) {
	if len(args) == 0 {
		_, _ = io.WriteString(w, "-ERR empty command\r\n")
		return
	}
	switch strings.ToUpper(string(args[0])) {
	case "PING":
		_, _ = io.WriteString(w, "+PONG\r\n")
	case "GET":
		s.mu.Lock()
		v, ok := s.values[string(args[1])]
		s.mu.Unlock()
		if !ok {
			_, _ = io.WriteString(w, "$-1\r\n")
			return
		}
		fmt.Fprintf(w, "$%d\r\n%s\r\n", len(v), v)
	case "SET":
		s.mu.Lock()
		_, exists := s.values[string(args[1])]
		if len(args) >= 5 && strings.EqualFold(string(args[4]), "NX") && exists {
			s.mu.Unlock()
			_, _ = io.WriteString(w, "$-1\r\n")
			return
		}
		s.values[string(args[1])] = append([]byte(nil), args[2]...)
		s.mu.Unlock()
		_, _ = io.WriteString(w, "+OK\r\n")
	case "EXISTS":
		s.mu.Lock()
		_, exists := s.values[string(args[1])]
		s.mu.Unlock()
		if exists {
			_, _ = io.WriteString(w, ":1\r\n")
		} else {
			_, _ = io.WriteString(w, ":0\r\n")
		}
	case "DEL":
		s.mu.Lock()
		_, exists := s.values[string(args[1])]
		delete(s.values, string(args[1]))
		s.mu.Unlock()
		if exists {
			_, _ = io.WriteString(w, ":1\r\n")
		} else {
			_, _ = io.WriteString(w, ":0\r\n")
		}
	case "EVAL":
		// The adapter's release script receives: EVAL script 1 key token.
		if len(args) < 5 {
			_, _ = io.WriteString(w, "-ERR malformed eval\r\n")
			return
		}
		key, token := string(args[3]), args[4]
		s.mu.Lock()
		v, exists := s.values[key]
		match := exists && string(v) == string(token)
		if match {
			delete(s.values, key)
		}
		s.mu.Unlock()
		if match {
			_, _ = io.WriteString(w, ":1\r\n")
		} else {
			_, _ = io.WriteString(w, ":0\r\n")
		}
	default:
		_, _ = io.WriteString(w, "-ERR unknown command\r\n")
	}
}

func readFakeCommand(r *bufio.Reader) ([][]byte, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return nil, err
	}
	if len(line) < 4 || line[0] != '*' {
		return nil, errors.New("bad array")
	}
	n, err := strconv.Atoi(strings.TrimSpace(line[1:]))
	if err != nil || n < 0 {
		return nil, errors.New("bad count")
	}
	args := make([][]byte, n)
	for i := range args {
		line, err = r.ReadString('\n')
		if err != nil || len(line) < 4 || line[0] != '$' {
			return nil, errors.New("bad bulk header")
		}
		length, err := strconv.Atoi(strings.TrimSpace(line[1:]))
		if err != nil || length < 0 {
			return nil, errors.New("bad bulk length")
		}
		args[i] = make([]byte, length)
		if _, err := io.ReadFull(r, args[i]); err != nil {
			return nil, err
		}
		if _, err := io.ReadFull(r, make([]byte, 2)); err != nil {
			return nil, err
		}
	}
	return args, nil
}
