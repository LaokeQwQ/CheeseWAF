package bot

import (
	"crypto/sha256"
	"errors"
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
