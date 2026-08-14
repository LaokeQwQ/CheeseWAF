package handler

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/api/middleware"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type reviewDecideRequest struct {
	Decision string `json:"decision"`
}

func (h *Handler) ListReviewItems(w http.ResponseWriter, r *http.Request) {
	if h.Store == nil {
		writeData(w, map[string]any{"items": []storage.ReviewItem{}, "total": 0})
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	startTime, ok := parseLogTimeQuery(w, r, "start")
	if !ok {
		return
	}
	endTime, ok := parseLogTimeQuery(w, r, "end")
	if !ok {
		return
	}
	items, total, err := h.Store.ListReviewItems(r.Context(), storage.ReviewFilter{
		SiteID:   r.URL.Query().Get("site_id"),
		Category: r.URL.Query().Get("category"),
		Status:   r.URL.Query().Get("status"),
		Start:    startTime,
		End:      endTime,
		Limit:    limit,
		Offset:   offset,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "REVIEW_QUERY_ERROR", err.Error())
		return
	}
	writeData(w, map[string]any{"items": items, "total": total})
}

func (h *Handler) GetReviewItem(w http.ResponseWriter, r *http.Request) {
	if h.Store == nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "review item not found")
		return
	}
	item, err := h.Store.GetReviewItem(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "REVIEW_QUERY_ERROR", err.Error())
		return
	}
	if item == nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "review item not found")
		return
	}
	writeData(w, item)
}

func (h *Handler) DecideReviewItem(w http.ResponseWriter, r *http.Request) {
	if h.rejectClusterConfigWriteIfFrozen(w, r) {
		return
	}
	if h.Store == nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "review item not found")
		return
	}
	var req reviewDecideRequest
	if !decode(w, r, &req) {
		return
	}
	decision := strings.ToLower(strings.TrimSpace(req.Decision))
	if !validReviewDecision(decision) {
		writeError(w, http.StatusBadRequest, "REVIEW_DECISION_INVALID", "decision must be block_payload, block_uri, block_ip, block_fingerprint, allow, or allow_whitelist")
		return
	}
	item, err := h.Store.GetReviewItem(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "REVIEW_QUERY_ERROR", err.Error())
		return
	}
	if item == nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "review item not found")
		return
	}
	if !reviewAllowsDecision(item.Status, decision) {
		if item.Status == "blocked" {
			writeError(w, http.StatusConflict, "REVIEW_ALREADY_DECIDED", "blocked items only accept a lasting intercept")
			return
		}
		writeError(w, http.StatusConflict, "REVIEW_ALREADY_DECIDED", "review item is already decided")
		return
	}
	appliedID, err := h.applyReviewDecision(r, item, decision)
	if err != nil {
		writeError(w, http.StatusBadRequest, "REVIEW_APPLY_ERROR", err.Error())
		return
	}
	claims, _ := r.Context().Value(middleware.UserContextKey).(*middleware.Claims)
	decided, err := h.Store.DecideReviewItem(r.Context(), item.ID, storage.ReviewDecision{
		Decision:         decision,
		AppliedRuleID:    appliedID,
		DecidedBySubject: reviewSubject(claims),
		DecidedByName:    reviewUser(claims),
		DecidedByRole:    reviewRole(claims),
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "REVIEW_DECIDE_ERROR", err.Error())
		return
	}
	if decided == nil {
		writeError(w, http.StatusConflict, "REVIEW_ALREADY_DECIDED", "review item is already decided")
		return
	}
	h.writeReviewAudit(r, claims, decided)
	writeData(w, decided)
}

func (h *Handler) applyReviewDecision(r *http.Request, item *storage.ReviewItem, decision string) (string, error) {
	switch decision {
	case "allow":
		return "", nil
	case "block_payload":
		payload := strings.TrimSpace(item.Payload)
		if payload == "" {
			return "", fmt.Errorf("payload is empty")
		}
		return h.addSiteCustomRule(r, item, storage.SiteCustomRule{
			Name:     "待确认转拦截（payload）",
			Pattern:  regexp.QuoteMeta(payload),
			Location: reviewRuleLocation(item.Source),
			Action:   "block",
			Severity: reviewSeverity(item.Severity),
			Enabled:  true,
			Priority: 20,
		})
	case "block_uri":
		path := reviewPath(item.URI)
		if path == "" {
			return "", fmt.Errorf("uri is empty")
		}
		return h.addSiteCustomRule(r, item, storage.SiteCustomRule{
			Name:     "待确认转拦截（URL）",
			Pattern:  "^" + regexp.QuoteMeta(path) + `(\?|$)`,
			Location: "uri",
			Action:   "block",
			Severity: reviewSeverity(item.Severity),
			Enabled:  true,
			Priority: 20,
		})
	case "block_ip":
		return h.addIPBlockRule(r, item)
	case "block_fingerprint":
		return h.addFingerprintDeny(r, item)
	case "allow_whitelist":
		return h.addSiteAllowlist(r, item)
	default:
		return "", fmt.Errorf("unsupported decision")
	}
}

func (h *Handler) addSiteCustomRule(r *http.Request, item *storage.ReviewItem, rule storage.SiteCustomRule) (string, error) {
	if strings.TrimSpace(item.SiteID) == "" {
		return "", fmt.Errorf("site_id is required")
	}
	if rule.ID == "" {
		rule.ID = "review-" + uuid.NewString()
	}
	h.siteMutationMu.Lock()
	defer h.siteMutationMu.Unlock()
	site, err := h.Store.GetSite(r.Context(), item.SiteID)
	if err != nil {
		return "", err
	}
	if site == nil {
		return "", fmt.Errorf("site not found")
	}
	existingRules := append([]storage.SiteCustomRule(nil), site.Advanced.CustomRules...)
	existing := *site
	existing.Advanced.CustomRules = existingRules
	site.Advanced.CustomRules = append(append([]storage.SiteCustomRule(nil), existingRules...), rule)
	if err := h.validateCandidateSites(r, func(sites []storage.Site) []storage.Site {
		for index := range sites {
			if sites[index].ID == site.ID {
				sites[index] = *site
				return sites
			}
		}
		return append(sites, *site)
	}); err != nil {
		return "", err
	}
	if err := h.Store.UpdateSite(r.Context(), site); err != nil {
		return "", err
	}
	if err := h.syncSitesOrRollback(r, func() error {
		return h.Store.UpdateSite(r.Context(), &existing)
	}); err != nil {
		return "", err
	}
	return rule.ID, nil
}

func (h *Handler) addFingerprintDeny(r *http.Request, item *storage.ReviewItem) (string, error) {
	if strings.TrimSpace(item.SiteID) == "" {
		return "", fmt.Errorf("site_id is required")
	}
	fp := strings.TrimSpace(item.Fingerprint)
	if fp == "" {
		return "", fmt.Errorf("fingerprint is empty")
	}
	h.siteMutationMu.Lock()
	defer h.siteMutationMu.Unlock()
	site, err := h.Store.GetSite(r.Context(), item.SiteID)
	if err != nil {
		return "", err
	}
	if site == nil {
		return "", fmt.Errorf("site not found")
	}
	existingDeny := append([]string(nil), site.Advanced.SemanticPolicy.FingerprintDeny...)
	existing := *site
	existing.Advanced.SemanticPolicy.FingerprintDeny = existingDeny
	site.Advanced.SemanticPolicy.FingerprintDeny = appendUnique(existingDeny, fp)
	if err := h.validateCandidateSites(r, func(sites []storage.Site) []storage.Site {
		for index := range sites {
			if sites[index].ID == site.ID {
				sites[index] = *site
				return sites
			}
		}
		return append(sites, *site)
	}); err != nil {
		return "", err
	}
	if err := h.Store.UpdateSite(r.Context(), site); err != nil {
		return "", err
	}
	if err := h.syncSitesOrRollback(r, func() error {
		return h.Store.UpdateSite(r.Context(), &existing)
	}); err != nil {
		return "", err
	}
	return "fingerprint:" + fp, nil
}

func (h *Handler) addSiteAllowlist(r *http.Request, item *storage.ReviewItem) (string, error) {
	if strings.TrimSpace(item.SiteID) == "" {
		return "", fmt.Errorf("site_id is required")
	}
	h.siteMutationMu.Lock()
	defer h.siteMutationMu.Unlock()
	site, err := h.Store.GetSite(r.Context(), item.SiteID)
	if err != nil {
		return "", err
	}
	if site == nil {
		return "", fmt.Errorf("site not found")
	}
	existingPaths := append([]string(nil), site.Advanced.SemanticPolicy.PathAllowlist...)
	existingParams := append([]string(nil), site.Advanced.SemanticPolicy.ParamAllowlist...)
	existing := *site
	existing.Advanced.SemanticPolicy.PathAllowlist = existingPaths
	existing.Advanced.SemanticPolicy.ParamAllowlist = existingParams
	if param := strings.TrimSpace(item.ParamName); param != "" {
		site.Advanced.SemanticPolicy.ParamAllowlist = appendUnique(existingParams, param)
	} else {
		path := reviewPath(item.URI)
		if path == "" {
			return "", fmt.Errorf("uri is empty")
		}
		site.Advanced.SemanticPolicy.PathAllowlist = appendUnique(existingPaths, path)
	}
	if err := h.validateCandidateSites(r, func(sites []storage.Site) []storage.Site {
		for index := range sites {
			if sites[index].ID == site.ID {
				sites[index] = *site
				return sites
			}
		}
		return append(sites, *site)
	}); err != nil {
		return "", err
	}
	if err := h.Store.UpdateSite(r.Context(), site); err != nil {
		return "", err
	}
	if err := h.syncSitesOrRollback(r, func() error {
		return h.Store.UpdateSite(r.Context(), &existing)
	}); err != nil {
		return "", err
	}
	if strings.TrimSpace(item.ParamName) != "" {
		return "param:" + item.ParamName, nil
	}
	return "path:" + reviewPath(item.URI), nil
}

func (h *Handler) addIPBlockRule(r *http.Request, item *storage.ReviewItem) (string, error) {
	ip := strings.TrimSpace(item.ClientIP)
	if net.ParseIP(ip) == nil {
		return "", fmt.Errorf("client ip is invalid")
	}
	ruleID := "review-ip-" + uuid.NewString()
	rule := config.IPAccessRuleConfig{
		ID:      ruleID,
		Name:    "待确认转拦截（IP）",
		Action:  "block",
		Scope:   "global",
		Entries: []string{ip},
		Enabled: true,
	}
	if siteID := strings.TrimSpace(item.SiteID); siteID != "" {
		rule.Scope = "site"
		rule.SiteID = siteID
	}
	_, err := h.commitConfigMutation(func(candidate *config.Config) error {
		candidate.Protection.IP.AccessRules = append(append([]config.IPAccessRuleConfig(nil), candidate.Protection.IP.AccessRules...), rule)
		return nil
	}, func(candidate *config.Config) error {
		return h.notifyProtectionConfigChanged(candidate.Protection)
	})
	if err != nil {
		return "", err
	}
	return rule.ID, nil
}

func (h *Handler) writeReviewAudit(r *http.Request, claims *middleware.Claims, item *storage.ReviewItem) {
	if h == nil || h.Auditor == nil || item == nil {
		return
	}
	entry := middleware.AuditEntry{
		User:     reviewUser(claims),
		Role:     reviewRole(claims),
		Method:   r.Method,
		Path:     r.URL.Path,
		Status:   http.StatusOK,
		RemoteIP: r.RemoteAddr,
		Target:   item.SiteID,
		Message: fmt.Sprintf(
			"review decide=%s site=%s level=%d shape=%s category=%s uri=%s payload=%s ai=%s",
			item.Decision, item.SiteID, item.ProtectionLevel, item.Shape, item.Category, item.URI, truncateReview(item.Payload, 200), truncateReview(item.AIVerdict, 200),
		),
	}
	if claims != nil {
		entry.Subject = claims.Subject
	}
	_ = h.Auditor.Write(r.Context(), entry)
}

func validReviewDecision(decision string) bool {
	switch decision {
	case "block_payload", "block_uri", "block_ip", "block_fingerprint", "allow", "allow_whitelist":
		return true
	default:
		return false
	}
}

func reviewAllowsDecision(status, decision string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "pending":
		return validReviewDecision(decision)
	case "blocked":
		switch decision {
		case "block_payload", "block_uri", "block_ip", "block_fingerprint":
			return true
		}
	}
	return false
}

func reviewRuleLocation(source string) string {
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

func reviewPath(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if parsed, err := url.Parse(raw); err == nil && parsed.Path != "" {
		return parsed.Path
	}
	if i := strings.Index(raw, "?"); i >= 0 {
		return raw[:i]
	}
	return raw
}

func appendUnique(values []string, next string) []string {
	next = strings.TrimSpace(next)
	if next == "" {
		return values
	}
	for _, value := range values {
		if strings.EqualFold(value, next) {
			return values
		}
	}
	return append(values, next)
}

func reviewSeverity(value string) string {
	if strings.TrimSpace(value) != "" {
		return value
	}
	return "high"
}

func truncateReview(value string, limit int) string {
	if limit <= 0 || len(value) <= limit {
		return value
	}
	return value[:limit]
}

func reviewSubject(claims *middleware.Claims) string {
	if claims == nil {
		return ""
	}
	return claims.Subject
}

func reviewUser(claims *middleware.Claims) string {
	if claims == nil {
		return ""
	}
	return claims.Username
}

func reviewRole(claims *middleware.Claims) string {
	if claims == nil {
		return ""
	}
	return claims.Role
}
