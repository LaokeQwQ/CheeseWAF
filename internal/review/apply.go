package review

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
	"github.com/google/uuid"
)

func AddPayloadRule(ctx context.Context, store storage.Store, item *storage.ReviewItem) (string, error) {
	if store == nil || item == nil {
		return "", fmt.Errorf("review apply requires store and item")
	}
	payload := strings.TrimSpace(item.Payload)
	if payload == "" {
		return "", fmt.Errorf("payload is empty")
	}
	if strings.TrimSpace(item.SiteID) == "" {
		return "", fmt.Errorf("site_id is required")
	}
	site, err := store.GetSite(ctx, item.SiteID)
	if err != nil {
		return "", err
	}
	if site == nil {
		return "", fmt.Errorf("site not found")
	}
	rule := storage.SiteCustomRule{
		ID:       "review-" + uuid.NewString(),
		Name:     "待确认转拦截（payload）",
		Pattern:  regexp.QuoteMeta(payload),
		Location: ruleLocation(item.Source),
		Action:   "block",
		Severity: "high",
		Enabled:  true,
		Priority: 20,
	}
	if strings.TrimSpace(item.Severity) != "" {
		rule.Severity = item.Severity
	}
	site.Advanced.CustomRules = append(append([]storage.SiteCustomRule(nil), site.Advanced.CustomRules...), rule)
	if err := store.UpdateSite(ctx, site); err != nil {
		return "", err
	}
	return rule.ID, nil
}

func HighConfidence(risk string, aiUsed bool) bool {
	if !aiUsed {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(risk)) {
	case "high", "critical":
		return true
	default:
		return false
	}
}

func ruleLocation(source string) string {
	switch strings.ToLower(strings.TrimSpace(source)) {
	case "cookie":
		return "cookie"
	case "header":
		return "header"
	case "uri", "query":
		return "uri"
	default:
		return "body"
	}
}
