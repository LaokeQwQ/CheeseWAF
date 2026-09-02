package review

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/ai"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

// Queue writes detected-but-not-blocked items and asks the configured model later.
type Queue struct {
	Store          storage.ReviewStore
	Client         *ai.Client
	AutoAgree      func(siteID string) bool
	PromoteSeconds func(siteID string) int
	ApplyBlock     func(ctx context.Context, item *storage.ReviewItem) (string, error)
	RollbackBlock  func(ctx context.Context, item *storage.ReviewItem, ruleID string) error
	Notify         func(ctx context.Context, title, message, target string)
	// AnalyzeItem is an optional test/integration hook. Production uses the
	// bounded AI client path below.
	AnalyzeItem func(context.Context, *storage.ReviewItem) *ai.AttackAnalysis
	// Workers, MaxQueued, and PerSiteQuota are optional operational limits. Zero
	// values use conservative defaults so a literal Queue remains bounded.
	Workers      int
	MaxQueued    int
	PerSiteQuota int
	Now          func() time.Time
	AutoAgreeTTL time.Duration

	initOnce      sync.Once
	mu            sync.Mutex
	jobs          chan *storage.ReviewItem
	queued        int
	queuedBySite  map[string]int
	runningBySite map[string]int
	pendingKeys   map[string]struct{}
}

const (
	defaultReviewWorkers   = 2
	defaultReviewQueue     = 128
	defaultReviewSiteQuota = 16
	defaultReviewTimeout   = 5 * time.Minute
	defaultAutoAgreeTTL    = 15 * time.Minute
)

func (q *Queue) Enqueue(ctx context.Context, item *storage.ReviewItem) {
	if q == nil || q.Store == nil || item == nil {
		return
	}
	exists, err := q.Store.HasSimilarReview(ctx, item.SiteID, item.Category, item.Payload, item.URI)
	if err != nil {
		log.Printf("review pending check failed: %v", err)
		return
	}
	if exists {
		return
	}
	if err := q.Store.CreateReviewItem(ctx, item); err != nil {
		log.Printf("review enqueue failed: %v", err)
		return
	}
	if item.ProtectionLevel == 4 && item.Shape == "embedded" && q.Notify != nil && q.PromoteSeconds != nil {
		if seconds := q.PromoteSeconds(item.SiteID); seconds > 0 {
			q.Notify(ctx, "站点短时按 5 档待审", item.SiteID, "/review")
		}
	}
	q.submitAnalysis(item)
}

func (q *Queue) initWorkers() {
	workers := q.Workers
	if workers <= 0 {
		workers = defaultReviewWorkers
	}
	queueSize := q.MaxQueued
	if queueSize <= 0 {
		queueSize = defaultReviewQueue
	}
	q.jobs = make(chan *storage.ReviewItem, queueSize)
	q.queuedBySite = make(map[string]int)
	q.runningBySite = make(map[string]int)
	q.pendingKeys = make(map[string]struct{})
	for i := 0; i < workers; i++ {
		go q.worker()
	}
}

func (q *Queue) submitAnalysis(item *storage.ReviewItem) {
	if q == nil || item == nil {
		return
	}
	q.initOnce.Do(q.initWorkers)
	siteID := strings.TrimSpace(item.SiteID)
	key := reviewAnalysisKey(item)
	q.mu.Lock()
	defer q.mu.Unlock()
	if _, exists := q.pendingKeys[key]; exists {
		return
	}
	quota := q.PerSiteQuota
	if quota <= 0 {
		quota = defaultReviewSiteQuota
	}
	if q.MaxQueued > 0 && q.queued >= q.MaxQueued {
		log.Printf("review analysis queue full; retaining item %s for manual review", item.ID)
		return
	}
	if q.queuedBySite[siteID]+q.runningBySite[siteID] >= quota {
		log.Printf("review analysis site quota reached site=%s; retaining item %s for manual review", siteID, item.ID)
		return
	}
	select {
	case q.jobs <- item:
		q.pendingKeys[key] = struct{}{}
		q.queued++
		q.queuedBySite[siteID]++
	default:
		log.Printf("review analysis queue full; retaining item %s for manual review", item.ID)
	}
}

func (q *Queue) worker() {
	for item := range q.jobs {
		siteID := strings.TrimSpace(item.SiteID)
		key := reviewAnalysisKey(item)
		q.mu.Lock()
		q.queued--
		q.queuedBySite[siteID]--
		q.runningBySite[siteID]++
		q.mu.Unlock()

		q.analyze(item)

		q.mu.Lock()
		q.runningBySite[siteID]--
		delete(q.pendingKeys, key)
		q.mu.Unlock()
	}
}

func reviewAnalysisKey(item *storage.ReviewItem) string {
	if item == nil {
		return ""
	}
	key := strings.Join([]string{
		strings.TrimSpace(item.SiteID), strings.TrimSpace(item.Category),
		strings.TrimSpace(item.Payload), strings.TrimSpace(item.URI),
	}, "\x00")
	sum := sha256.Sum256([]byte(key))
	return string(sum[:])
}

func (q *Queue) analyze(item *storage.ReviewItem) {
	if q == nil || q.Store == nil || item == nil || item.ID == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), defaultReviewTimeout)
	defer cancel()
	var analysis *ai.AttackAnalysis
	if q.AnalyzeItem != nil {
		analysis = q.AnalyzeItem(ctx, item)
	} else {
		analysis = ai.AnalyzeLogBestEffortWithLanguage(ctx, q.Client, storage.LogEntry{
			ID:       item.ID,
			TraceID:  item.TraceID,
			SiteID:   item.SiteID,
			ClientIP: item.ClientIP,
			Method:   item.Method,
			URI:      item.URI,
			Action:   "log",
			Category: item.Category,
			Severity: item.Severity,
			Payload:  item.Payload,
		}, "")
	}
	if err := q.Store.SetReviewAIVerdict(ctx, item.ID, formatVerdict(analysis)); err != nil {
		log.Printf("review verdict write failed id=%s: %v", item.ID, err)
	}
	q.maybeAutoAgree(ctx, item, analysis)
}

func (q *Queue) maybeAutoAgree(ctx context.Context, item *storage.ReviewItem, analysis *ai.AttackAnalysis) {
	if q == nil || q.Store == nil || item == nil || analysis == nil || q.AutoAgree == nil || q.ApplyBlock == nil {
		return
	}
	if !q.AutoAgree(item.SiteID) || !HighConfidence(analysis.Risk, analysis.AIUsed) {
		return
	}
	latest, err := q.Store.GetReviewItem(ctx, item.ID)
	if err != nil || latest == nil || latest.Status != "pending" {
		return
	}
	maxAge := q.AutoAgreeTTL
	if maxAge <= 0 {
		maxAge = defaultAutoAgreeTTL
	}
	if !latest.CreatedAt.IsZero() {
		now := time.Now().UTC()
		if q.Now != nil {
			now = q.Now().UTC()
		}
		if now.Before(latest.CreatedAt) || now.Sub(latest.CreatedAt) > maxAge {
			log.Printf("review auto-agree skipped stale item id=%s", item.ID)
			return
		}
	}
	ruleID, err := q.ApplyBlock(ctx, latest)
	if err != nil {
		log.Printf("review auto-agree apply failed id=%s: %v", item.ID, err)
		return
	}
	if _, err := q.Store.DecideReviewItem(ctx, item.ID, storage.ReviewDecision{
		Decision:      "block_payload",
		AppliedRuleID: ruleID,
		DecidedByName: "auto-agree",
		DecidedByRole: "system",
	}); err != nil {
		if q.RollbackBlock != nil {
			if rollbackErr := q.RollbackBlock(ctx, latest, ruleID); rollbackErr != nil {
				log.Printf("review auto-agree rollback failed id=%s rule=%s: %v", item.ID, ruleID, rollbackErr)
			}
		}
		log.Printf("review auto-agree decide failed id=%s: %v", item.ID, err)
		return
	}
	if q.Notify != nil {
		q.Notify(ctx, "待确认已自动转拦截", latest.URI+" "+latest.Category, "/review")
	}
}

func formatVerdict(analysis *ai.AttackAnalysis) string {
	if analysis == nil {
		return ""
	}
	payload, err := json.Marshal(map[string]any{
		"risk":    strings.TrimSpace(analysis.Risk),
		"summary": strings.TrimSpace(analysis.Summary),
		"ai_used": analysis.AIUsed,
	})
	if err != nil {
		return strings.TrimSpace(analysis.Summary)
	}
	text := string(payload)
	if len(text) > 2000 {
		return text[:2000]
	}
	return text
}
