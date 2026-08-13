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
	Store  storage.ReviewStore
	Client *ai.Client
}

func (q *Queue) Enqueue(ctx context.Context, item *storage.ReviewItem) {
	if q == nil || q.Store == nil || item == nil {
		return
	}
	pending, err := q.Store.HasPendingReview(ctx, item.SiteID, item.Category, item.Payload, item.URI)
	if err != nil {
		log.Printf("review pending check failed: %v", err)
		return
	}
	if pending {
		return
	}
	if err := q.Store.CreateReviewItem(ctx, item); err != nil {
		log.Printf("review enqueue failed: %v", err)
		return
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
	if err := q.Store.SetReviewAIVerdict(context.Background(), item.ID, formatVerdict(analysis)); err != nil {
		log.Printf("review verdict write failed id=%s: %v", item.ID, err)
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
