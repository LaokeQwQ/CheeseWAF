package bot

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/captcha"
)

func TestChallengeStoreReservationRollsBackCapacityAndRate(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	store := NewChallengeStore(ChallengeStoreConfig{
		Capacity:         2,
		PerOwnerCapacity: 1,
		PerPeerCapacity:  2,
		RateWindow:       time.Minute,
		GlobalRate:       2,
		PerOwnerRate:     1,
		PerPeerRate:      2,
		Now:              func() time.Time { return now },
	})
	expires := now.Add(time.Minute)

	reservation, err := store.ReserveScoped("owner-a", "peer-a", expires)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.ReserveScoped("owner-a", "peer-a", expires); !errors.Is(err, ErrChallengeCapacity) {
		t.Fatalf("concurrent owner reservation escaped quota: %v", err)
	}
	if !store.Rollback(reservation) {
		t.Fatal("reservation rollback failed")
	}

	reservation, err = store.ReserveScoped("owner-a", "peer-a", expires)
	if err != nil {
		t.Fatalf("rollback leaked capacity or rate: %v", err)
	}
	if err = store.Start(reservation); err != nil {
		t.Fatal(err)
	}
	if err = store.Commit(reservation, "challenge-a", expires); err != nil {
		t.Fatal(err)
	}
	if store.Rollback(reservation) {
		t.Fatal("committed reservation rolled back twice")
	}
	if got := store.Len(); got != 1 {
		t.Fatalf("committed challenge count = %d, want 1", got)
	}
}

func TestChallengeStoreConsumedOwnerCannotStarveAnotherOwner(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	store := NewChallengeStore(ChallengeStoreConfig{
		Capacity:         3,
		PerOwnerCapacity: 1,
		UsedRetention:    time.Hour,
		Now:              func() time.Time { return now },
	})
	for i := 0; i < store.cap; i++ {
		jti := fmt.Sprintf("owner-a-%d", i)
		if err := store.AddScoped(jti, "owner-a", now.Add(time.Minute)); err != nil {
			t.Fatalf("issue %d: %v", i, err)
		}
		if status, ok := store.Consume(jti); !ok || status != ChallengeUsed {
			t.Fatalf("consume %d: status=%q ok=%v", i, status, ok)
		}
	}
	if err := store.AddScoped("owner-b", "owner-b", now.Add(time.Minute)); err != nil {
		t.Fatalf("consumed owner-a challenges starved owner-b: %v", err)
	}
	if got := store.Len(); got > store.cap {
		t.Fatalf("challenge state exceeded capacity: got %d cap %d", got, store.cap)
	}
}

func TestChallengeStoreCommittedRateIsBoundedPerOwnerAndExpires(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	store := NewChallengeStore(ChallengeStoreConfig{
		Capacity:         4,
		PerOwnerCapacity: 2,
		RateWindow:       time.Minute,
		GlobalRate:       4,
		PerOwnerRate:     2,
		PerPeerRate:      4,
		Now:              func() time.Time { return now },
	})
	for i := 0; i < 2; i++ {
		jti := fmt.Sprintf("rate-a-%d", i)
		if err := store.AddScopedWithPeer(jti, "owner-a", "peer-a", now.Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
		store.Consume(jti)
	}
	if err := store.AddScopedWithPeer("rate-a-blocked", "owner-a", "peer-a", now.Add(time.Minute)); !errors.Is(err, ErrChallengeCapacity) {
		t.Fatalf("owner issue rate was not enforced: %v", err)
	}
	if err := store.AddScopedWithPeer("rate-b", "owner-b", "peer-b", now.Add(time.Minute)); err != nil {
		t.Fatalf("owner-a rate blocked owner-b: %v", err)
	}
	now = now.Add(time.Minute)
	if err := store.AddScopedWithPeer("rate-a-recovered", "owner-a", "peer-a", now.Add(time.Minute)); err != nil {
		t.Fatalf("owner rate did not recover after window: %v", err)
	}
}

func TestBehaviorPendingReservationPrecedesGenerationAndRollsBack(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	store := newBehaviorPendingStore(2, 1, func() time.Time { return now })
	expires := now.Add(time.Minute)

	first, err := store.Reserve("owner-a", "peer-a", expires)
	if err != nil {
		t.Fatal(err)
	}
	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			reservation, reserveErr := store.Reserve("owner-a", "peer-a", expires)
			if reserveErr == nil {
				wins.Add(1)
				store.Rollback(reservation)
			}
		}()
	}
	wg.Wait()
	if got := wins.Load(); got != 0 {
		t.Fatalf("same owner acquired %d excess generation reservations", got)
	}
	if !store.Rollback(first) {
		t.Fatal("behavior reservation rollback failed")
	}

	second, err := store.Reserve("owner-a", "peer-a", expires)
	if err != nil {
		t.Fatalf("rollback leaked behavior quota: %v", err)
	}
	pending := pendingFixture("owner-a", expires)
	pending.peer = "peer-a"
	if err = store.Start(second); err != nil {
		t.Fatal(err)
	}
	if err = store.Commit(second, "behavior-a", pending); err != nil {
		t.Fatal(err)
	}
	if got := store.Len(); got != 1 {
		t.Fatalf("committed behavior count = %d, want 1", got)
	}
}

func TestBehaviorPendingReservationPeerAndGlobalFairness(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	store := newBehaviorPendingStore(4, 1, func() time.Time { return now })
	store.perPeerCapacity = 2
	expires := now.Add(time.Minute)

	reservations := make([]*behaviorPendingReservation, 0, 2)
	for i := 0; i < 2; i++ {
		reservation, err := store.Reserve(fmt.Sprintf("owner-%d", i), "shared-peer", expires)
		if err != nil {
			t.Fatal(err)
		}
		reservations = append(reservations, reservation)
	}
	if _, err := store.Reserve("rotated-owner", "shared-peer", expires); !errors.Is(err, ErrChallengeCapacity) {
		t.Fatalf("rotating owner bypassed peer reservation: %v", err)
	}
	if _, err := store.Reserve("fair-owner", "other-peer", expires); err != nil {
		t.Fatalf("one peer blocked unrelated owner: %v", err)
	}
	for _, reservation := range reservations {
		store.Rollback(reservation)
	}
}

func TestBehaviorPendingCommittedRateSurvivesConsumptionButNotRollback(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	store := newBehaviorPendingStore(8, 2, func() time.Time { return now })
	store.rates.ownerLimit = 2
	expires := now.Add(time.Minute)

	for i := 0; i < 2; i++ {
		pending := pendingFixture("owner-a", expires)
		pending.peer = "peer-a"
		jti := fmt.Sprintf("behavior-rate-%d", i)
		if err := store.Add(jti, pending); err != nil {
			t.Fatal(err)
		}
		store.Revoke(jti)
	}
	reservation, err := store.Reserve("owner-a", "peer-a", expires)
	if !errors.Is(err, ErrChallengeCapacity) || reservation != nil {
		t.Fatalf("committed behavior rate was not enforced: reservation=%v err=%v", reservation, err)
	}

	for i := 0; i < 8; i++ {
		rolledBack, reserveErr := store.Reserve("owner-b", "peer-b", expires)
		if reserveErr != nil {
			t.Fatalf("rollback attempt %d leaked rate: %v", i, reserveErr)
		}
		if !store.Rollback(rolledBack) {
			t.Fatalf("rollback attempt %d failed", i)
		}
	}
}

func TestGenerationReservationRollbackDoesNotDependOnRateRetention(t *testing.T) {
	t.Run("pow", func(t *testing.T) {
		now := time.Unix(1_700_000_000, 0)
		store := NewChallengeStore(ChallengeStoreConfig{Capacity: 2, PerOwnerCapacity: 1, RateWindow: time.Second, GlobalRate: 2, PerOwnerRate: 1, PerPeerRate: 2, Now: func() time.Time { return now }})
		reservation, err := store.ReserveScoped("owner-a", "peer-a", now.Add(time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		if err = store.Start(reservation); err != nil {
			t.Fatal(err)
		}
		now = now.Add(2 * time.Second)
		store.mu.Lock()
		store.rates.clean(now, issuanceRateCleanupBudget)
		store.mu.Unlock()
		if !store.Rollback(reservation) {
			t.Fatal("rate expiry prevented PoW capacity rollback")
		}
		if len(store.reservations) != 0 || len(store.ownerReserved) != 0 || len(store.peerReserved) != 0 {
			t.Fatalf("PoW reservation indexes leaked: reservations=%d owners=%d peers=%d", len(store.reservations), len(store.ownerReserved), len(store.peerReserved))
		}
	})

	t.Run("behavior", func(t *testing.T) {
		now := time.Unix(1_700_000_000, 0)
		store := newBehaviorPendingStore(2, 1, func() time.Time { return now })
		store.rates.window = time.Second
		reservation, err := store.Reserve("owner-a", "peer-a", now.Add(time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		if err = store.Start(reservation); err != nil {
			t.Fatal(err)
		}
		now = now.Add(2 * time.Second)
		store.mu.Lock()
		store.rates.clean(now, issuanceRateCleanupBudget)
		store.mu.Unlock()
		if !store.Rollback(reservation) {
			t.Fatal("rate expiry prevented Behavior capacity rollback")
		}
		if len(store.reservations) != 0 || len(store.ownerReserved) != 0 || len(store.peerReserved) != 0 {
			t.Fatalf("Behavior reservation indexes leaked: reservations=%d owners=%d peers=%d", len(store.reservations), len(store.ownerReserved), len(store.peerReserved))
		}
	})
}

func TestBehaviorGenerationAdmissionHappensBeforeWork(t *testing.T) {
	policy := newBehaviorPolicy(t, nil)
	request := httptest.NewRequest(http.MethodGet, "https://tenant.example/protected", nil)
	request.Header.Set("User-Agent", "curl/8.0")
	_, ownerCookie, err := policy.behaviorOwner(request, "site-a", true, cookieSecure(request))
	if err != nil {
		t.Fatal(err)
	}

	entered := make(chan struct{}, 8)
	release := make(chan struct{})
	var active, peak atomic.Int32
	policy.issueBehaviorChallenge = func(options captcha.BehaviorOptions) (captcha.BehaviorChallenge, error) {
		current := active.Add(1)
		for {
			observed := peak.Load()
			if current <= observed || peak.CompareAndSwap(observed, current) {
				break
			}
		}
		entered <- struct{}{}
		<-release
		active.Add(-1)
		return captcha.IssueBehaviorChallenge(options)
	}

	const requests = 8
	statuses := make(chan int, requests)
	var wg sync.WaitGroup
	for i := 0; i < requests; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodGet, "https://tenant.example/protected", nil)
			req.Header.Set("User-Agent", "curl/8.0")
			req.AddCookie(ownerCookie)
			recorder := httptest.NewRecorder()
			policy.ServeChallengeForSite(recorder, req, "203.0.113.10", "site-a")
			statuses <- recorder.Code
		}()
	}
	for i := 0; i < policy.behaviorPending.perOwnerConcurrent; i++ {
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("expected admitted Behavior generation did not start")
		}
	}
	select {
	case <-entered:
		t.Fatal("Behavior generation exceeded per-owner in-flight limit")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	wg.Wait()
	close(statuses)

	issued := 0
	for status := range statuses {
		if status == http.StatusForbidden {
			issued++
		} else if status != http.StatusServiceUnavailable {
			t.Fatalf("unexpected status %d", status)
		}
	}
	if issued != policy.behaviorPending.perOwnerConcurrent || peak.Load() > int32(policy.behaviorPending.perOwnerConcurrent) {
		t.Fatalf("issued=%d peak=%d concurrent limit=%d", issued, peak.Load(), policy.behaviorPending.perOwnerConcurrent)
	}
}

func TestBehaviorGenerationFailureKeepsRateButReleasesCapacity(t *testing.T) {
	policy := newBehaviorPolicy(t, nil)
	policy.behaviorPending.rates.ownerLimit = 2
	request := httptest.NewRequest(http.MethodGet, "https://tenant.example/protected", nil)
	request.Header.Set("User-Agent", "curl/8.0")
	_, ownerCookie, err := policy.behaviorOwner(request, "site-a", true, cookieSecure(request))
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	policy.issueBehaviorChallenge = func(captcha.BehaviorOptions) (captcha.BehaviorChallenge, error) {
		calls.Add(1)
		return captcha.BehaviorChallenge{}, errors.New("generation failed")
	}
	for i := 0; i < 4; i++ {
		req := httptest.NewRequest(http.MethodGet, "https://tenant.example/protected", nil)
		req.Header.Set("User-Agent", "curl/8.0")
		req.AddCookie(ownerCookie)
		recorder := httptest.NewRecorder()
		policy.ServeChallengeForSite(recorder, req, "203.0.113.10", "site-a")
		if i < 2 && recorder.Code != http.StatusInternalServerError {
			t.Fatalf("generation failure %d status=%d", i, recorder.Code)
		}
		if i >= 2 && recorder.Code != http.StatusServiceUnavailable {
			t.Fatalf("rate rejection %d status=%d", i, recorder.Code)
		}
	}
	if calls.Load() != 2 {
		t.Fatalf("generator calls=%d, want 2 before rate rejection", calls.Load())
	}
	if policy.behaviorPending.Len() != 0 || len(policy.behaviorPending.reservations) != 0 || len(policy.behaviorPending.ownerReserved) != 0 {
		t.Fatal("generation failure leaked Behavior capacity")
	}
}

func TestCanceledBehaviorRequestRollsBackBeforeWork(t *testing.T) {
	policy := newBehaviorPolicy(t, nil)
	request := httptest.NewRequest(http.MethodGet, "https://tenant.example/protected", nil)
	request.Header.Set("User-Agent", "curl/8.0")
	_, ownerCookie, err := policy.behaviorOwner(request, "site-a", true, cookieSecure(request))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	request = request.WithContext(ctx)
	request.AddCookie(ownerCookie)
	var calls atomic.Int32
	policy.issueBehaviorChallenge = func(options captcha.BehaviorOptions) (captcha.BehaviorChallenge, error) {
		calls.Add(1)
		return captcha.IssueBehaviorChallenge(options)
	}
	recorder := httptest.NewRecorder()
	policy.ServeChallengeForSite(recorder, request, "203.0.113.10", "site-a")
	if recorder.Code != http.StatusServiceUnavailable || calls.Load() != 0 {
		t.Fatalf("canceled request status=%d generator calls=%d", recorder.Code, calls.Load())
	}
	if policy.behaviorPending.Len() != 0 || len(policy.behaviorPending.reservations) != 0 || len(policy.behaviorPending.rates.records) != 0 {
		t.Fatal("canceled request leaked capacity or provisional rate")
	}
}
