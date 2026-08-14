package review

import (
	"context"
	"encoding/json"
	"log"
	"strings"

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
	Notify         func(ctx context.Context, title, message, target string)
}

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
	go q.analyze(item)
}

func (q *Queue) analyze(item *storage.ReviewItem) {
	if q == nil || q.Store == nil || item == nil || item.ID == "" {
		return
	}
	analysis := ai.AnalyzeLogBestEffortWithLanguage(context.Background(), q.Client, storage.LogEntry{
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
	ctx := context.Background()
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
