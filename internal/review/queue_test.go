package review

import (
	"context"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/ai"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

func TestQueueBoundsConcurrentAnalysisByQueueAndSiteQuota(t *testing.T) {
	ctx := context.Background()
	store, err := storage.OpenSQLite(filepath.Join(t.TempDir(), "reviews.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	site := &storage.Site{ID: "site-a", Name: "site-a", Domains: []string{"a.test"}, Upstreams: []string{"127.0.0.1:9"}, Enabled: true}
	if err := store.CreateSite(ctx, site); err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{}, 4)
	release := make(chan struct{})
	var calls atomic.Int32
	q := &Queue{
		Store:        store,
		Workers:      1,
		MaxQueued:    2,
		PerSiteQuota: 2,
		AnalyzeItem: func(context.Context, *storage.ReviewItem) *ai.AttackAnalysis {
			calls.Add(1)
			started <- struct{}{}
			<-release
			return nil
		},
	}
	for i := 0; i < 4; i++ {
		q.Enqueue(ctx, &storage.ReviewItem{SiteID: site.ID, Category: "sqli", Payload: "payload-" + string(rune('a'+i)), URI: "/search", Status: "pending"})
	}
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("bounded worker did not start")
	}
	q.mu.Lock()
	inFlight := q.queued + q.runningBySite[site.ID]
	q.mu.Unlock()
	if inFlight > 2 {
		t.Fatalf("in-flight site analysis exceeded quota: %d", inFlight)
	}
	if got := calls.Load(); got > 1 {
		t.Fatalf("one worker should have at most one active analysis while blocked, got %d", got)
	}
	close(release)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		q.mu.Lock()
		remaining := q.queued + q.runningBySite[site.ID]
		q.mu.Unlock()
		if remaining == 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	q.mu.Lock()
	remaining := q.queued + q.runningBySite[site.ID]
	q.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("analysis workers did not drain: %d", remaining)
	}
}
