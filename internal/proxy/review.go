package proxy

import (
	"context"
	"fmt"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

// ReviewQueue receives detections that were not blocked.
type ReviewQueue interface {
	Enqueue(ctx context.Context, item *storage.ReviewItem)
}

func (s *Server) SetReviewQueue(queue ReviewQueue) {
	if s == nil {
		return
	}
	s.reviews = queue
}

func (s *Server) enqueueReview(ctx context.Context, reqCtx *engine.RequestContext, action string) {
	if s == nil || s.reviews == nil || reqCtx == nil {
		return
	}
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "block", "challenge":
		return
	}
	item := reviewItemFromContext(reqCtx)
	if item == nil {
		return
	}
	s.reviews.Enqueue(ctx, item)
	if item.ProtectionLevel == 4 && item.Shape == "embedded" {
		s.promotes.Arm(item.SiteID, s.sitePromoteSeconds(item.SiteID), s.wallNow())
	}
}

func (s *Server) sitePromoteSeconds(siteID string) int {
	if s == nil {
		return 0
	}
	set := s.siteRuntimes.Load()
	if set == nil || set.byID[siteID] == nil {
		return 0
	}
	return set.byID[siteID].site.WAF.SemanticPolicy.PromoteSeconds
}

func detectionFromReviewCandidate(reqCtx *engine.RequestContext) *engine.DetectionResult {
	if reqCtx == nil {
		return nil
	}
	cand, ok := reqCtx.Metadata["review_candidate"].(map[string]any)
	if !ok || cand == nil {
		return nil
	}
	category := anyString(cand["category"])
	if !reviewableCategory(category) {
		return nil
	}
	return &engine.DetectionResult{
		Detected:   true,
		DetectorID: "semantic.analyzer." + category,
		Category:   category,
		Severity:   parseReviewSeverity(anyString(cand["severity"])),
		Action:     engine.ActionBlock,
		Message:    "promoted protection window",
		Confidence: 0.9,
		Payload:    anyString(cand["payload"]),
	}
}

func parseReviewSeverity(value string) engine.Severity {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "critical":
		return engine.SeverityCritical
	case "medium":
		return engine.SeverityMedium
	case "low":
		return engine.SeverityLow
	default:
		return engine.SeverityHigh
	}
}

func reviewItemFromContext(reqCtx *engine.RequestContext) *storage.ReviewItem {
	if reqCtx == nil || reqCtx.Request == nil {
		return nil
	}
	item := &storage.ReviewItem{
		TraceID:  reqCtx.TraceID,
		SiteID:   reqCtx.SiteID,
		ClientIP: reqCtx.ClientIP,
		Method:   reqCtx.Request.Method,
		URI:      reqCtx.Request.URL.RequestURI(),
		Status:   "pending",
	}
	if cand, ok := reqCtx.Metadata["review_candidate"].(map[string]any); ok && cand != nil {
		item.Category = anyString(cand["category"])
		item.Severity = anyString(cand["severity"])
		item.Payload = anyString(cand["payload"])
		item.Shape = anyString(cand["shape"])
		item.Source = anyString(cand["source"])
		item.ParamName = anyString(cand["name"])
		item.ProtectionLevel = anyInt(cand["protection_level"])
	} else if result, ok := reqCtx.Metadata["detection"].(*engine.DetectionResult); ok && result != nil && result.Detected {
		item.Category = result.Category
		item.Severity = result.Severity.String()
		item.Payload = result.Payload
	} else {
		return nil
	}
	if !reviewableCategory(item.Category) {
		return nil
	}
	if item.Payload == "" && item.URI == "" {
		return nil
	}
	return item
}

func reviewableCategory(category string) bool {
	switch strings.ToLower(strings.TrimSpace(category)) {
	case "sqli", "xss", "rce", "lfi", "xxe", "ssrf", "nosqli", "ssti", "webshell", "log4shell", "shellshock":
		return true
	default:
		return false
	}
}

func anyString(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case fmt.Stringer:
		return typed.String()
	default:
		return ""
	}
}

func anyInt(value any) int {
	switch typed := value.(type) {
	case int:
		return typed
	case int64:
		return int(typed)
	case float64:
		return int(typed)
	default:
		return 0
	}
}
