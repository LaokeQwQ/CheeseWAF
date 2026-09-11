package service

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/tokens"
)

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Set(now time.Time) {
	c.mu.Lock()
	c.now = now
	c.mu.Unlock()
}

type epochMap struct {
	mu     sync.RWMutex
	epochs map[string]uint64
}

func (e *epochMap) CurrentEpoch(_ context.Context, tenant string) (uint64, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.epochs[tenant], nil
}

func (e *epochMap) Set(tenant string, epoch uint64) {
	e.mu.Lock()
	if e.epochs == nil {
		e.epochs = make(map[string]uint64)
	}
	e.epochs[tenant] = epoch
	e.mu.Unlock()
}

type confirmationGate struct {
	mu    sync.Mutex
	calls int
}

type blockingConfirmationGate struct {
	entered chan struct{}
	release chan struct{}
}

func (g *blockingConfirmationGate) Confirm(_ context.Context, _ ConfirmationRequest) error {
	close(g.entered)
	<-g.release
	return nil
}

func (g *confirmationGate) Confirm(_ context.Context, _ ConfirmationRequest) error {
	g.mu.Lock()
	g.calls++
	g.mu.Unlock()
	return nil
}

type denyCache struct {
	blacklisted atomic.Bool
}

func (c *denyCache) IsBlacklisted(context.Context, CacheKey) (bool, error) {
	return c.blacklisted.Load(), nil
}
func (c *denyCache) Put(context.Context, CacheKey, CacheEntry, time.Duration) error { return nil }
func (c *denyCache) Blacklist(context.Context, CacheKey, time.Duration) error {
	c.blacklisted.Store(true)
	return nil
}

func serviceFixture(t *testing.T) (*Service, *testClock, *epochMap) {
	t.Helper()
	clock := &testClock{now: time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)}
	epochs := &epochMap{epochs: map[string]uint64{"tenant-a": 7}}
	s, err := New(Config{
		Persistence: tokens.NewMemoryPersistence(),
		Clock:       clock,
		Epochs:      epochs,
	})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	return s, clock, epochs
}

func issueRequest() IssueRequest {
	return IssueRequest{
		TenantID:       "tenant-a",
		IdempotencyKey: "issue-1",
		Request: tokens.CreateRequest{
			Owner:       "operator",
			Permissions: []string{"rules.read"},
			Resources:   []string{"site:alpha"},
			PolicyEpoch: 7,
			TTL:         time.Hour,
		},
	}
}

func TestIssuePersistsOpaqueSecretAndValidateUsesSnapshot(t *testing.T) {
	s, clock, _ := serviceFixture(t)
	issued, err := s.Issue(context.Background(), issueRequest())
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if issued.Secret == "" || issued.Metadata.ID == "" {
		t.Fatalf("issued credential missing: %+v", issued)
	}
	if got, err := s.Persistence().Load(context.Background(), "tenant-a", issued.Metadata.ID); err != nil {
		t.Fatalf("load persisted token: %v", err)
	} else if got.SecretDigest == issued.Secret {
		t.Fatal("plaintext secret crossed persistence boundary")
	}
	meta, err := s.Validate(context.Background(), ValidateRequest{
		TenantID:       "tenant-a",
		TokenID:        issued.Metadata.ID,
		Secret:         issued.Secret,
		Permission:     "rules.read",
		Resource:       "site:alpha",
		PolicyEpoch:    7,
		IdempotencyKey: "auth-1",
	})
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if !meta.LastActivityAt.Equal(clock.Now()) {
		t.Fatalf("activity timestamp=%s want %s", meta.LastActivityAt, clock.Now())
	}
	meta.Permissions[0] = "admin"
	meta.Resources[0] = "site:other"
	second, err := s.Validate(context.Background(), ValidateRequest{
		TenantID:       "tenant-a",
		TokenID:        issued.Metadata.ID,
		Secret:         issued.Secret,
		Permission:     "rules.read",
		Resource:       "site:alpha",
		PolicyEpoch:    7,
		IdempotencyKey: "auth-2",
	})
	if err != nil {
		t.Fatalf("snapshot validate: %v", err)
	}
	if second.Permissions[0] != "rules.read" || second.Resources[0] != "site:alpha" {
		t.Fatalf("mutable permission/resource snapshot: %+v", second)
	}
}

func TestIssueReplayIsRejectedAndConflictingReplayFails(t *testing.T) {
	s, _, _ := serviceFixture(t)
	first, err := s.Issue(context.Background(), issueRequest())
	if err != nil {
		t.Fatalf("first issue: %v", err)
	}
	if first.Metadata.ID == "" || first.Secret == "" {
		t.Fatalf("first issue returned empty credential: %+v", first)
	}
	retry, err := s.Issue(context.Background(), issueRequest())
	if !errors.Is(err, ErrReplayConflict) {
		t.Fatalf("same issue retry error=%v", err)
	}
	if retry.Metadata.ID != "" || retry.Secret != "" {
		t.Fatalf("replay returned credential: %+v", retry)
	}
	conflict := issueRequest()
	conflict.Request.Resources = []string{"site:other"}
	if _, err := s.Issue(context.Background(), conflict); !errors.Is(err, ErrReplayConflict) {
		t.Fatalf("conflicting replay error=%v", err)
	}
}

func TestEpochChangeImmediatelyRejectsOldToken(t *testing.T) {
	s, _, epochs := serviceFixture(t)
	issued, err := s.Issue(context.Background(), issueRequest())
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	epochs.Set("tenant-a", 8)
	_, err = s.Validate(context.Background(), ValidateRequest{
		TenantID:       "tenant-a",
		TokenID:        issued.Metadata.ID,
		Secret:         issued.Secret,
		Permission:     "rules.read",
		Resource:       "site:alpha",
		PolicyEpoch:    8,
		IdempotencyKey: "auth-epoch",
	})
	if !errors.Is(err, ErrEpochMismatch) {
		t.Fatalf("epoch change error=%v", err)
	}
}

func TestExpiryAndInactivityAreFailClosedBeforeCleanup(t *testing.T) {
	s, clock, _ := serviceFixture(t)
	issued, err := s.Issue(context.Background(), issueRequest())
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	clock.Set(clock.Now().Add(time.Hour))
	if _, err := s.Validate(context.Background(), ValidateRequest{
		TenantID:       "tenant-a",
		TokenID:        issued.Metadata.ID,
		Secret:         issued.Secret,
		Permission:     "rules.read",
		Resource:       "site:alpha",
		PolicyEpoch:    7,
		IdempotencyKey: "auth-expired",
	}); !errors.Is(err, tokens.ErrExpired) {
		t.Fatalf("expiry error=%v", err)
	}

	clock.Set(time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC))
	long := issueRequest()
	long.IdempotencyKey = "issue-inactive"
	long.Request.TTL = 365 * 24 * time.Hour
	inactive, err := s.Issue(context.Background(), long)
	if err != nil {
		t.Fatalf("inactive issue: %v", err)
	}
	clock.Set(clock.Now().Add(tokens.InactivityTTL))
	if _, err := s.Validate(context.Background(), ValidateRequest{
		TenantID:       "tenant-a",
		TokenID:        inactive.Metadata.ID,
		Secret:         inactive.Secret,
		Permission:     "rules.read",
		Resource:       "site:alpha",
		PolicyEpoch:    7,
		IdempotencyKey: "auth-inactive",
	}); !errors.Is(err, tokens.ErrInactive) {
		t.Fatalf("inactivity error=%v", err)
	}
}

func TestNeverExpireRequiresStrongConfirmationAdapter(t *testing.T) {
	s, _, _ := serviceFixture(t)
	req := issueRequest()
	req.IdempotencyKey = "issue-never"
	req.ConfirmationID = "confirm-1"
	req.Request.NeverExpire = true
	req.Request.ConfirmNeverExpire = true
	req.Request.TTL = 0
	if _, err := s.Issue(context.Background(), req); !errors.Is(err, ErrConfirmationUnavailable) {
		t.Fatalf("nil confirmation adapter error=%v", err)
	}
	gate := &confirmationGate{}
	s.SetConfirmationGate(gate)
	issued, err := s.Issue(context.Background(), req)
	if err != nil {
		t.Fatalf("confirmed issue: %v", err)
	}
	if !issued.Metadata.ExpiresAt.IsZero() || !issued.Metadata.NeverExpire || gate.calls != 1 {
		t.Fatalf("unexpected never-expire issue: %+v calls=%d", issued.Metadata, gate.calls)
	}
	if _, err := s.Issue(context.Background(), req); !errors.Is(err, ErrReplayConflict) {
		t.Fatalf("confirmed replay error=%v", err)
	}
	req.IdempotencyKey = "issue-never-2"
	if _, err := s.Issue(context.Background(), req); !errors.Is(err, ErrConfirmationReplay) {
		t.Fatalf("confirmation replay error=%v", err)
	}
}

func TestIssueRejectsEpochChangeAfterConfirmation(t *testing.T) {
	clock := &testClock{now: time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)}
	epochs := &epochMap{epochs: map[string]uint64{"tenant-a": 7}}
	gate := &blockingConfirmationGate{entered: make(chan struct{}), release: make(chan struct{})}
	s, err := New(Config{Persistence: tokens.NewMemoryPersistence(), Clock: clock, Epochs: epochs, ConfirmationGate: gate})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	req := issueRequest()
	req.IdempotencyKey = "issue-epoch-race"
	req.ConfirmationID = "confirm-epoch-race"
	req.Request.NeverExpire = true
	req.Request.ConfirmNeverExpire = true
	req.Request.TTL = 0
	result := make(chan error, 1)
	go func() {
		_, issueErr := s.Issue(context.Background(), req)
		result <- issueErr
	}()
	select {
	case <-gate.entered:
	case <-time.After(time.Second):
		t.Fatal("confirmation gate was not reached")
	}
	epochs.Set("tenant-a", 8)
	close(gate.release)
	if err := <-result; !errors.Is(err, ErrEpochMismatch) {
		t.Fatalf("epoch race error=%v", err)
	}
	if _, err := s.Persistence().List(context.Background(), "tenant-a"); err != nil {
		t.Fatalf("list persisted tokens: %v", err)
	} else if items, _ := s.Persistence().List(context.Background(), "tenant-a"); len(items) != 0 {
		t.Fatalf("stale epoch token persisted: %d", len(items))
	}
}

func TestRedisCacheCannotAuthorizeWithoutPersistenceTruth(t *testing.T) {
	s, _, _ := serviceFixture(t)
	cache := &denyCache{}
	s.SetCache(cache)
	issued, err := s.Issue(context.Background(), issueRequest())
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	cache.blacklisted.Store(false)
	if _, err := s.Validate(context.Background(), ValidateRequest{
		TenantID:       "tenant-a",
		TokenID:        issued.Metadata.ID,
		Secret:         issued.Secret,
		Permission:     "rules.read",
		Resource:       "site:alpha",
		PolicyEpoch:    7,
		IdempotencyKey: "auth-cache-1",
	}); err != nil {
		t.Fatalf("cache miss should use persistence truth: %v", err)
	}
	cache.blacklisted.Store(true)
	if _, err := s.Validate(context.Background(), ValidateRequest{
		TenantID:       "tenant-a",
		TokenID:        issued.Metadata.ID,
		Secret:         issued.Secret,
		Permission:     "rules.read",
		Resource:       "site:alpha",
		PolicyEpoch:    7,
		IdempotencyKey: "auth-cache-2",
	}); !errors.Is(err, ErrBlacklisted) {
		t.Fatalf("blacklist cache error=%v", err)
	}
}

func TestConcurrentSameIssueIsSingleCredential(t *testing.T) {
	s, _, _ := serviceFixture(t)
	const workers = 32
	results := make(chan tokens.Issued, workers)
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			issued, err := s.Issue(context.Background(), issueRequest())
			if err != nil {
				errs <- err
				return
			}
			results <- issued
		}()
	}
	wg.Wait()
	close(results)
	close(errs)
	var first tokens.Issued
	count := 0
	for issued := range results {
		if count == 0 {
			first = issued
		} else if issued.Metadata.ID != first.Metadata.ID || issued.Secret != first.Secret {
			t.Fatalf("concurrent issue diverged: first=%+v got=%+v", first, issued)
		}
		count++
	}
	if count != 1 {
		t.Fatalf("successful results=%d want=1", count)
	}
	for err := range errs {
		if !errors.Is(err, ErrReplayConflict) {
			t.Fatalf("unexpected concurrent replay error: %v", err)
		}
	}
}
