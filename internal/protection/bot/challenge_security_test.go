package bot

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func solvePoW(t *testing.T, token string, work int) string {
	t.Helper()
	for i := 0; i < 12000000; i++ {
		answer := strconv.Itoa(i)
		sum := sha256.Sum256([]byte(token + "\x00" + answer))
		if hasLeadingZeroNibbles(sum[:], work) {
			return answer
		}
	}
	t.Fatal("proof not found")
	return ""
}

func TestChallengeStoreConcurrentConsumeOnce(t *testing.T) {
	now := time.Unix(100, 0)
	s := NewChallengeStore(ChallengeStoreConfig{Capacity: 2, UsedRetention: time.Minute, Now: func() time.Time { return now }})
	if err := s.Add("j", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, ok := s.Consume("j"); ok {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("wins=%d", wins.Load())
	}
	if s.Status("j") != ChallengeExpired || s.Len() != 0 {
		t.Fatal("consumed challenge tombstone was retained")
	}
}

func TestChallengeStoreLimitsPendingChallengesPerOwner(t *testing.T) {
	now := time.Unix(100, 0)
	s := NewChallengeStore(ChallengeStoreConfig{Capacity: 10, PerOwnerCapacity: 2, Now: func() time.Time { return now }})
	if err := s.AddScoped("a1", "site-a\x00client-a", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := s.AddScoped("a2", "site-a\x00client-a", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := s.AddScoped("a3", "site-a\x00client-a", now.Add(time.Minute)); !errors.Is(err, ErrChallengeCapacity) {
		t.Fatalf("same owner exceeded limit: %v", err)
	}
	if err := s.AddScoped("b1", "site-a\x00client-b", now.Add(time.Minute)); err != nil {
		t.Fatalf("one owner blocked another: %v", err)
	}
	if _, ok := s.Consume("a1"); !ok {
		t.Fatal("consume failed")
	}
	if err := s.AddScoped("a3", "site-a\x00client-a", now.Add(time.Minute)); err != nil {
		t.Fatalf("used entry still counted against pending limit: %v", err)
	}
}
func TestChallengeStoreExpiryAndCapacityCleanup(t *testing.T) {
	now := time.Unix(100, 0)
	s := NewChallengeStore(ChallengeStoreConfig{Capacity: 1, UsedRetention: time.Second, Now: func() time.Time { return now }})
	s.Add("a", now.Add(time.Second))
	if err := s.Add("b", now.Add(time.Minute)); err != ErrChallengeCapacity {
		t.Fatalf("err=%v", err)
	}
	now = now.Add(3 * time.Second)
	if s.Len() != 0 {
		t.Fatal("expired state retained")
	}
	if _, ok := s.Consume("a"); ok {
		t.Fatal("expired consumed")
	}
	if err := s.Add("b", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
}
func TestFailureTrackerRefreshIndependentEscalationBlockAndExpiry(t *testing.T) {
	now := time.Unix(100, 0)
	f, _ := NewFailureTracker(FailureTrackerConfig{Capacity: 2, Window: time.Minute, IdleTTL: 2 * time.Minute, LevelAt: []int{2, 3}, BlockAt: 3, BlockDuration: 30 * time.Second, Now: func() time.Time { return now }})
	k := FailureKey{"client", "site", "policy"}
	for i := 0; i < 3; i++ {
		d, e := f.RecordFailure(k)
		if e != nil {
			t.Fatal(e)
		}
		if d.Failures != i+1 {
			t.Fatal("refresh reset failures")
		}
	}
	d := f.Check(k)
	if d.Level != 2 || !d.Blocked {
		t.Fatalf("decision=%+v", d)
	}
	if other := f.Check(FailureKey{"client", "other", "policy"}); other.Failures != 0 {
		t.Fatal("cross-site state")
	}
	now = now.Add(61 * time.Second)
	d = f.Check(k)
	if d.Failures != 0 || d.Blocked {
		t.Fatalf("stale decision=%+v", d)
	}
	now = now.Add(2 * time.Minute)
	if f.Len() != 0 {
		t.Fatal("idle entry retained")
	}
}
func TestFailureTrackerConcurrentAndCapacity(t *testing.T) {
	now := time.Unix(100, 0)
	f, _ := NewFailureTracker(FailureTrackerConfig{Capacity: 1, Window: time.Minute, BlockDuration: time.Minute, Now: func() time.Time { return now }})
	k := FailureKey{"c", "s", "p"}
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, e := f.RecordFailure(k); e != nil {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
	if d := f.Check(k); d.Failures != 50 {
		t.Fatalf("failures=%d", d.Failures)
	}
	if _, e := f.RecordFailure(FailureKey{"x", "s", "p"}); e == nil {
		t.Fatal("capacity not enforced")
	}
}

func signerFixture(t *testing.T, now *time.Time) (*ClearanceSigner, ClearanceContext, ClearanceClaims) {
	t.Helper()
	ctx := ClearanceContext{Site: "site-a", Policy: "policy-a", PolicyVersion: "v1", ClientIP: "192.0.2.10", UserAgent: "UA", Path: "/api/private", RequestMethod: "GET", BindingMode: BindingStrictIPUA}
	b, e := ComputeClearanceBinding(ctx.BindingMode, ctx.ClientIP, ctx.UserAgent)
	if e != nil {
		t.Fatal(e)
	}
	s, e := NewClearanceSigner(ClearanceSignerConfig{Keys: map[string][]byte{"k1": []byte("01234567890123456789012345678901")}, ActiveKeyID: "k1", MaxTTL: time.Hour, Now: func() time.Time { return *now }})
	if e != nil {
		t.Fatal(e)
	}
	c := ClearanceClaims{JTI: "jti", Site: ctx.Site, Policy: ctx.Policy, PolicyVersion: ctx.PolicyVersion, Level: 2, Method: "pow", Path: "/api", RequestMethod: "GET", Binding: b, ExpiresAt: now.Add(time.Minute).Unix()}
	return s, ctx, c
}

func TestClearanceScopeAndRevocation(t *testing.T) {
	now := time.Unix(100, 0)
	s, ctx, c := signerFixture(t, &now)
	tok, err := s.Sign(c)
	if err != nil {
		t.Fatal(err)
	}
	child := ctx
	child.Path = "/api/private/items"
	if _, err = s.Verify(tok, child); err != nil {
		t.Fatal(err)
	}
	bad := ctx
	bad.Path = "/apix"
	if _, err = s.Verify(tok, bad); err == nil {
		t.Fatal("path escape accepted")
	}
	bad = ctx
	bad.RequestMethod = "POST"
	if _, err = s.Verify(tok, bad); err == nil {
		t.Fatal("method mismatch accepted")
	}
	state := NewClearanceStateStore(ChallengeStoreConfig{Capacity: 1, UsedRetention: time.Second, Now: func() time.Time { return now }})
	if err = state.Issue(c.JTI, "site-a/client-a", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if !state.Valid(c.JTI) {
		t.Fatal("issued clearance invalid")
	}
	if !state.Revoke(c.JTI) || state.Valid(c.JTI) {
		t.Fatal("revocation failed")
	}
}

func TestPathWithinScopeRejectsDotDotEscape(t *testing.T) {
	// Clearance scoped to /admin must not accept /admin/../secret after clean → /secret.
	if pathWithinScope("/admin/../secret", "/admin") {
		t.Fatal("expected /admin/../secret outside scope /admin after normalization")
	}
	if !pathWithinScope("/admin/./users", "/admin") {
		t.Fatal("expected cleaned /admin/./users to remain in /admin scope")
	}
	if !pathWithinScope("/admin/users", "/admin") {
		t.Fatal("expected child path in scope")
	}
	if pathWithinScope("/administrator", "/admin") {
		t.Fatal("segment boundary: /administrator is not under /admin")
	}
	if !pathWithinScope("/secret", "/") {
		t.Fatal("root scope should allow all cleaned absolute paths")
	}
}

func TestClearanceScopeRejectsDotDotPath(t *testing.T) {
	now := time.Unix(100, 0)
	s, ctx, c := signerFixture(t, &now)
	c.Path = "/admin"
	tok, err := s.Sign(c)
	if err != nil {
		t.Fatal(err)
	}
	// After clean, /admin/../secret becomes /secret — outside /admin.
	escape := ctx
	escape.Path = "/admin/../secret"
	if _, err = s.Verify(tok, escape); err == nil {
		t.Fatal("clearance scope /admin must reject /admin/../secret")
	}
	// Direct /secret is also outside.
	outside := ctx
	outside.Path = "/secret"
	if _, err = s.Verify(tok, outside); err == nil {
		t.Fatal("clearance scope /admin must reject /secret")
	}
	// Legitimate child remains accepted.
	child := ctx
	child.Path = "/admin/dashboard"
	if _, err = s.Verify(tok, child); err != nil {
		t.Fatalf("child path rejected: %v", err)
	}
}

func TestClearanceStateCapacityIsIsolatedPerOwner(t *testing.T) {
	now := time.Unix(100, 0)
	state := NewClearanceStateStore(ChallengeStoreConfig{
		Capacity:         4,
		PerOwnerCapacity: 2,
		Now:              func() time.Time { return now },
	})
	for _, jti := range []string{"a-1", "a-2"} {
		if err := state.Issue(jti, "owner-a", now.Add(time.Minute)); err != nil {
			t.Fatalf("issue %s: %v", jti, err)
		}
	}
	if err := state.Issue("a-3", "owner-a", now.Add(time.Minute)); !errors.Is(err, ErrChallengeCapacity) {
		t.Fatalf("owner capacity was not enforced: %v", err)
	}
	if err := state.Issue("b-1", "owner-b", now.Add(time.Minute)); err != nil {
		t.Fatalf("owner-a exhausted owner-b capacity: %v", err)
	}
}

func TestPoWManagerBindingsReplayAndDifficultyCap(t *testing.T) {
	now := time.Unix(100, 0)
	store := NewChallengeStore(ChallengeStoreConfig{Capacity: 10, Now: func() time.Time { return now }})
	m, err := NewPoWManager([]byte("01234567890123456789012345678901"), store, time.Minute, 1, 2, []string{"sha256", "md5"}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	x := PoWContext{Site: "a", Policy: "bot", PolicyVersion: "1", Path: "/api", ClientKey: "client", Risk: 99}
	ch, err := m.Issue(x)
	if err != nil {
		t.Fatal(err)
	}
	if ch.Work != 2 {
		t.Fatalf("work=%d", ch.Work)
	}
	answer := ""
	for i := 0; ; i++ {
		candidate := strconv.Itoa(i)
		sum := sha256.Sum256([]byte(ch.Token + "\x00" + candidate))
		if hasLeadingZeroNibbles(sum[:], ch.Work) {
			answer = candidate
			break
		}
	}
	other := x
	other.Site = "b"
	if m.Verify(ch.Token, answer, other) == nil {
		t.Fatal("cross-site proof accepted")
	}
	if err = m.Verify(ch.Token, answer, x); err != nil {
		t.Fatal(err)
	}
	if m.Verify(ch.Token, answer, x) == nil {
		t.Fatal("replay accepted")
	}
}

func TestPoWAEADBindsContextAndUsesNonceAsKDFSalt(t *testing.T) {
	secret := []byte("01234567890123456789012345678901")
	nonceA := bytes.Repeat([]byte{1}, powNonceBytes)
	nonceB := bytes.Repeat([]byte{2}, powNonceBytes)
	aeadA, err := derivePoWAEAD(secret, nonceA)
	if err != nil {
		t.Fatal(err)
	}
	aeadB, err := derivePoWAEAD(secret, nonceB)
	if err != nil {
		t.Fatal(err)
	}
	ctx := PoWContext{Site: "site-a", Policy: "bot", PolicyVersion: "v1", Path: "/admin", ClientKey: "client-a"}
	plain := []byte(`{"jti":"one"}`)
	sealed := aeadA.Seal(nil, nonceA, plain, powAdditionalData(ctx))

	other := ctx
	other.Path = "/public"
	if _, err := aeadA.Open(nil, nonceA, sealed, powAdditionalData(other)); err == nil {
		t.Fatal("ciphertext opened with a different request context")
	}
	if _, err := aeadB.Open(nil, nonceA, sealed, powAdditionalData(ctx)); err == nil {
		t.Fatal("ciphertext opened with a key derived from another nonce salt")
	}
}

func TestPoWManagerRejectsOversizedInputsBeforeParsing(t *testing.T) {
	store := NewChallengeStore(ChallengeStoreConfig{Capacity: 10})
	m, err := NewPoWManager([]byte("01234567890123456789012345678901"), store, time.Minute, 1, 2, []string{"sha256"}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	x := PoWContext{Site: "a", Policy: "bot", PolicyVersion: "1", Path: "/", ClientKey: "client"}
	if err := m.Verify(strings.Repeat("x", maxPoWTokenBytes+1), "0", x); !errors.Is(err, ErrPoWInvalid) {
		t.Fatalf("oversized token err=%v", err)
	}
	if err := m.Verify("x.y", strings.Repeat("0", maxPoWAnswerBytes+1), x); !errors.Is(err, ErrPoWInvalid) {
		t.Fatalf("oversized answer err=%v", err)
	}
}
func TestClearanceSignVerifyTamperScopePolicyVersionAndExpiry(t *testing.T) {
	now := time.Unix(1000, 0)
	s, ctx, c := signerFixture(t, &now)
	tok, e := s.Sign(c)
	if e != nil {
		t.Fatal(e)
	}
	got, e := s.Verify(tok, ctx)
	if e != nil || got.Version != 1 || got.KeyID != "k1" {
		t.Fatalf("got=%+v err=%v", got, e)
	}
	bad := tok[:len(tok)-1] + "A"
	if _, e = s.Verify(bad, ctx); e == nil {
		t.Fatal("tamper accepted")
	}
	x := ctx
	x.Site = "site-b"
	if _, e = s.Verify(tok, x); e == nil {
		t.Fatal("cross-site accepted")
	}
	x = ctx
	x.PolicyVersion = "v2"
	if _, e = s.Verify(tok, x); e == nil {
		t.Fatal("stale policy accepted")
	}
	now = now.Add(2 * time.Minute)
	if _, e = s.Verify(tok, ctx); e == nil {
		t.Fatal("expired accepted")
	}
}

// The tests below exercise the ChallengeBackend seam. The Redis ones drive a
// scripted RESP stub, so they cover the command/reply plumbing and the code
// mapping on the Go side. They do NOT execute the Lua scripts: verifying those
// needs a real redis-server, which is not available in this environment.

func TestMemoryBackendForwardsChallengeLifecycle(t *testing.T) {
	now := time.Unix(100, 0)
	store := NewChallengeStore(ChallengeStoreConfig{Capacity: 10, PerOwnerCapacity: 2, Now: func() time.Time { return now }})
	var backend ChallengeBackend = NewMemoryBackend(store)
	ctx := context.Background()

	if err := backend.AddScopedWithPeer(ctx, "j1", "owner", "peer", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if !backend.Consume(ctx, "j1") {
		t.Fatal("AddScopedWithPeer did not publish a consumable jti")
	}
	if backend.Consume(ctx, "j1") {
		t.Fatal("jti consumed twice")
	}

	reservation, err := backend.ReserveScoped(ctx, "owner", "peer", now.Add(time.Minute))
	if err != nil || reservation == nil {
		t.Fatalf("reserve: r=%v err=%v", reservation, err)
	}
	if err = backend.Start(ctx, reservation); err != nil {
		t.Fatal(err)
	}
	if err = backend.Commit(ctx, reservation, "j2", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if backend.Rollback(ctx, reservation) {
		t.Fatal("rollback after commit reported a release")
	}

	// Per-owner cap of 2: j2 is still pending and j1 was consumed, so exactly
	// one more fits.
	if err = backend.AddScopedWithPeer(ctx, "j3", "owner", "peer", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err = backend.AddScopedWithPeer(ctx, "j4", "owner", "peer", now.Add(time.Minute)); !errors.Is(err, ErrChallengeCapacity) {
		t.Fatalf("per-owner cap not enforced: %v", err)
	}
	if err = backend.AddScopedWithPeer(ctx, "j5", "other", "peer", now.Add(time.Minute)); err != nil {
		t.Fatalf("a different owner must not be blocked: %v", err)
	}

	var nilBackend *MemoryBackend
	if err = nilBackend.AddScopedWithPeer(ctx, "j", "o", "p", now.Add(time.Minute)); !errors.Is(err, ErrChallengeCapacity) {
		t.Fatalf("nil backend issued a challenge: %v", err)
	}
	if nilBackend.Consume(ctx, "j") || nilBackend.Rollback(ctx, reservation) {
		t.Fatal("nil backend reported success")
	}
	if _, err = nilBackend.ReserveScoped(ctx, "o", "p", now.Add(time.Minute)); !errors.Is(err, ErrChallengeCapacity) {
		t.Fatalf("nil backend reserved: %v", err)
	}
}

func TestNewChallengeBackendDriverSelection(t *testing.T) {
	store := NewChallengeStore(ChallengeStoreConfig{})
	empty, err := NewChallengeBackend(BackendConfig{}, store)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := empty.(*MemoryBackend); !ok {
		t.Fatal("empty driver must fall back to memory")
	}
	if broken, err := NewChallengeBackend(BackendConfig{Driver: "redis"}, store); err == nil {
		if _, ok := broken.(*MemoryBackend); ok {
			t.Fatal("redis driver silently downgraded to memory")
		}
	}
	unreachable, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := unreachable.Addr().String()
	_ = unreachable.Close()
	_, err = NewChallengeBackend(BackendConfig{Driver: "redis", RedisURL: "redis://" + addr + "/0"}, store)
	if !errors.Is(err, ErrRedisBackendUnavailable) {
		t.Fatalf("unreachable redis must surface ErrRedisBackendUnavailable, got %v", err)
	}
	if _, err = NewChallengeBackend(BackendConfig{Driver: "nope"}, store); err == nil {
		t.Fatal("unknown driver accepted")
	}
	if _, err = NewChallengeBackend(BackendConfig{Driver: "redis", RedisURL: "http://127.0.0.1:6379"}, store); err == nil {
		t.Fatal("non-redis scheme accepted")
	}
}

// scriptedRedis answers each command with the next canned RESP reply.
type scriptedRedis struct {
	ln      net.Listener
	mu      sync.Mutex
	replies []string
	got     []string
}

func newScriptedRedis(t *testing.T, replies ...string) *scriptedRedis {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &scriptedRedis{ln: ln, replies: replies}
	go s.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return s
}

func (s *scriptedRedis) serve() {
	conn, err := s.ln.Accept()
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	rd := bufio.NewReader(conn)
	for {
		args, err := readRESPRequest(rd)
		if err != nil {
			return
		}
		s.mu.Lock()
		// Join on NUL: Lua scripts contain spaces and newlines of their own.
		s.got = append(s.got, strings.Join(args, "\x00"))
		reply := "+OK\r\n"
		if len(s.replies) > 0 {
			reply = s.replies[0]
			s.replies = s.replies[1:]
		}
		s.mu.Unlock()
		if _, err := conn.Write([]byte(reply)); err != nil {
			return
		}
	}
}

func (s *scriptedRedis) commands() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.got...)
}

func readRESPRequest(rd *bufio.Reader) ([]string, error) {
	header, err := rd.ReadString('\n')
	if err != nil {
		return nil, err
	}
	header = strings.TrimRight(header, "\r\n")
	if !strings.HasPrefix(header, "*") {
		return nil, errors.New("bad request header")
	}
	count, err := strconv.Atoi(header[1:])
	if err != nil {
		return nil, err
	}
	args := make([]string, 0, count)
	for i := 0; i < count; i++ {
		bulk, err := rd.ReadString('\n')
		if err != nil {
			return nil, err
		}
		size, err := strconv.Atoi(strings.TrimRight(bulk, "\r\n")[1:])
		if err != nil {
			return nil, err
		}
		payload := make([]byte, size+2)
		if _, err = io.ReadFull(rd, payload); err != nil {
			return nil, err
		}
		args = append(args, string(payload[:size]))
	}
	return args, nil
}

func TestRedisBackendLifecycleUsesAtomicEval(t *testing.T) {
	srv := newScriptedRedis(t,
		"+PONG\r\n",     // handshake
		"$3\r\n0:7\r\n", // reserve -> ok, id 7
		":0\r\n",        // start
		":0\r\n",        // commit
		"$3\r\n1:0\r\n", // reserve -> capacity
		":0\r\n",        // rollback -> released
		":1\r\n",        // rollback -> unknown
		":1\r\n",        // consume -> consumed
		":0\r\n",        // consume -> missing
	)
	backend, err := NewRedisBackend(BackendConfig{RedisURL: "redis://" + srv.ln.Addr().String() + "/0", KeyPrefix: "t:"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = backend.Close() }()
	ctx := context.Background()
	exp := time.Now().Add(time.Minute)

	reservation, err := backend.ReserveScoped(ctx, "owner", "peer", exp)
	if err != nil {
		t.Fatal(err)
	}
	if reservation.id != 7 || reservation.owner != "owner" || reservation.peer != "peer" {
		t.Fatalf("reservation=%+v", reservation)
	}
	if err = backend.Start(ctx, reservation); err != nil {
		t.Fatal(err)
	}
	if err = backend.Commit(ctx, reservation, "jti-1", exp); err != nil {
		t.Fatal(err)
	}
	if _, err = backend.ReserveScoped(ctx, "owner", "peer", exp); !errors.Is(err, ErrChallengeCapacity) {
		t.Fatalf("capacity code not mapped: %v", err)
	}
	if !backend.Rollback(ctx, reservation) {
		t.Fatal("rollback reported nothing released")
	}
	if backend.Rollback(ctx, reservation) {
		t.Fatal("rollback reported a second release")
	}
	if !backend.Consume(ctx, "jti-1") {
		t.Fatal("consume returned false for a consumed jti")
	}
	if backend.Consume(ctx, "jti-1") {
		t.Fatal("consume returned true for a missing jti")
	}

	commands := srv.commands()
	if len(commands) < 9 {
		t.Fatalf("expected 9 commands, got %d", len(commands))
	}
	if commands[0] != "PING" {
		t.Fatalf("handshake did not ping: %q", commands[0])
	}
	// Every lifecycle step must be a single EVAL with no declared keys: the
	// scripts touch several counters and must run atomically.
	for i := 1; i < len(commands); i++ {
		fields := strings.Split(commands[i], "\x00")
		if len(fields) < 4 {
			t.Fatalf("command %d truncated: %q", i, commands[i])
		}
		if fields[0] != "EVAL" || fields[2] != "0" {
			t.Fatalf("command %d = %q, want EVAL with numkeys 0", i, fields[0])
		}
		if fields[3] != "t:" {
			t.Fatalf("command %d did not pass the key prefix: %q", i, fields[3])
		}
	}
}

func TestRedisBackendAddUsesNamespacedKey(t *testing.T) {
	srv := newScriptedRedis(t, "+PONG\r\n", "+OK\r\n")
	backend, err := NewRedisBackend(BackendConfig{RedisURL: "redis://" + srv.ln.Addr().String() + "/0", KeyPrefix: "t:"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = backend.Close() }()
	if err = backend.Add(context.Background(), "jti-1", "owner", time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	fields := strings.Split(srv.commands()[1], "\x00")
	if len(fields) != 6 || fields[0] != "SET" || fields[1] != "t:j:jti-1" || fields[2] != "owner" || fields[3] != "PX" || fields[5] != "NX" {
		t.Fatalf("unexpected SET: %q", srv.commands()[1])
	}
	if ttl, err := strconv.Atoi(fields[4]); err != nil || ttl <= 0 {
		t.Fatalf("missing or invalid TTL: %q", fields[4])
	}
}

func TestRedisBackendFailOpenOnlyMasksAvailability(t *testing.T) {
	dead, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := dead.Addr().String()
	_ = dead.Close()
	ctx := context.Background()
	exp := time.Now().Add(time.Minute)

	closed := &RedisBackend{addr: addr, prefix: "t:", resTTL: generationReservationTTL}
	if _, err = closed.ReserveScoped(ctx, "o", "p", exp); err == nil {
		t.Fatal("fail-closed reserve accepted an outage")
	}
	if closed.Consume(ctx, "j") {
		t.Fatal("fail-closed consume accepted an outage")
	}
	if err = closed.Add(ctx, "j", "o", exp); err == nil {
		t.Fatal("fail-closed add accepted an outage")
	}

	open := &RedisBackend{addr: addr, prefix: "t:", failOpen: true, resTTL: generationReservationTTL}
	reservation, err := open.ReserveScoped(ctx, "o", "p", exp)
	if err != nil || reservation == nil {
		t.Fatalf("fail-open reserve: r=%v err=%v", reservation, err)
	}
	if reservationTracked(reservation) {
		t.Fatal("fail-open reservation must not claim redis capacity")
	}
	if err = open.Start(ctx, reservation); err != nil {
		t.Fatal(err)
	}
	if err = open.Commit(ctx, reservation, "j", exp); err != nil {
		t.Fatal(err)
	}
	if !open.Consume(ctx, "j") {
		t.Fatal("fail-open consume rejected during an outage")
	}
	if !open.Rollback(ctx, reservation) {
		t.Fatal("fail-open rollback reported a failure")
	}
}

func TestRedisReservationReplyParsing(t *testing.T) {
	if code, id, ok := splitCodeID("0:42"); !ok || code != redisReserveOK || id != 42 {
		t.Fatalf("0:42 -> %d %d %v", code, id, ok)
	}
	if code, _, ok := splitCodeID("2:0"); !ok || code != redisReserveRateLimited {
		t.Fatalf("2:0 -> %d %v", code, ok)
	}
	if _, _, ok := splitCodeID("nope"); ok {
		t.Fatal("malformed reply accepted")
	}
	if _, _, ok := splitCodeID("x:1"); ok {
		t.Fatal("non numeric code accepted")
	}
}

func TestClearanceBindings(t *testing.T) {
	a, _ := ComputeClearanceBinding(BindingIPPrefixUA, "192.0.2.10", "UA")
	b, _ := ComputeClearanceBinding(BindingIPPrefixUA, "192.0.2.99", "UA")
	if a != b {
		t.Fatal("same prefix differs")
	}
	c, _ := ComputeClearanceBinding(BindingStrictIPUA, "192.0.2.10", "UA")
	d, _ := ComputeClearanceBinding(BindingStrictIPUA, "192.0.2.99", "UA")
	if c == d {
		t.Fatal("strict binding ignored IP")
	}
	if a == c {
		t.Fatal("binding modes collide")
	}
}
