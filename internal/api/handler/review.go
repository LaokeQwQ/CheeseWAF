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

type reviewDecisionApplication struct {
	appliedRuleID string
	rollback      func() error
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
	afterTime, ok := parseLogTimeQuery(w, r, "after")
	if !ok {
		return
	}
	beforeTime, ok := parseLogTimeQuery(w, r, "before")
	if !ok {
		return
	}
	watermarkTime, ok := parseLogTimeQuery(w, r, "watermark")
	if !ok {
		return
	}
	items, total, err := h.Store.ListReviewItems(r.Context(), storage.ReviewFilter{
		SiteID:        r.URL.Query().Get("site_id"),
		Category:      r.URL.Query().Get("category"),
		Status:        r.URL.Query().Get("status"),
		Search:        r.URL.Query().Get("search"),
		Start:         startTime,
		End:           endTime,
		AfterTime:     afterTime,
		AfterID:       r.URL.Query().Get("after_id"),
		BeforeTime:    beforeTime,
		BeforeID:      r.URL.Query().Get("before_id"),
		WatermarkTime: watermarkTime,
		WatermarkID:   r.URL.Query().Get("watermark_id"),
		Limit:         limit,
		Offset:        offset,
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
	claim, err := h.Store.ClaimReviewItem(r.Context(), item.ID, decision)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "REVIEW_CLAIM_ERROR", err.Error())
		return
	}
	if claim == nil || claim.Item == nil {
		writeError(w, http.StatusConflict, "REVIEW_ALREADY_DECIDED", "review item is already being decided")
		return
	}
	item = claim.Item
	application, err := h.applyReviewDecision(r, item, decision)
	if err != nil {
		if releaseErr := h.Store.ReleaseReviewItem(r.Context(), item.ID, claim.Token); releaseErr != nil {
			writeError(w, http.StatusInternalServerError, "REVIEW_CLEANUP_ERROR", fmt.Sprintf("%v; release decision claim: %v", err, releaseErr))
			return
		}
		writeError(w, http.StatusBadRequest, "REVIEW_APPLY_ERROR", err.Error())
		return
	}
	claims, _ := r.Context().Value(middleware.UserContextKey).(*middleware.Claims)
	decided, err := h.Store.CompleteReviewItem(r.Context(), item.ID, claim.Token, storage.ReviewDecision{
		Decision:         decision,
		AppliedRuleID:    application.appliedRuleID,
		DecidedBySubject: reviewSubject(claims),
		DecidedByName:    reviewUser(claims),
		DecidedByRole:    reviewRole(claims),
	})
	if err != nil {
		_ = h.rollbackReviewDecision(r, item, application, claim.Token)
		writeError(w, http.StatusInternalServerError, "REVIEW_DECIDE_ERROR", err.Error())
		return
	}
	if decided == nil {
		_ = h.rollbackReviewDecision(r, item, application, claim.Token)
		writeError(w, http.StatusConflict, "REVIEW_ALREADY_DECIDED", "review item is already decided")
		return
	}
	h.writeReviewAudit(r, claims, decided)
	writeData(w, decided)
}

func (h *Handler) applyReviewDecision(r *http.Request, item *storage.ReviewItem, decision string) (reviewDecisionApplication, error) {
	switch decision {
	case "allow":
		return reviewDecisionApplication{}, nil
	case "block_payload":
		payload := strings.TrimSpace(item.Payload)
		if payload == "" {
			return reviewDecisionApplication{}, fmt.Errorf("payload is empty")
		}
		id, err := h.addSiteCustomRule(r, item, storage.SiteCustomRule{
			Name:     "待确认转拦截（payload）",
			Pattern:  regexp.QuoteMeta(payload),
			Location: reviewRuleLocation(item.Source),
			Action:   "block",
			Severity: reviewSeverity(item.Severity),
			Enabled:  true,
			Priority: 20,
		})
		if err != nil {
			return reviewDecisionApplication{}, err
		}
		return reviewDecisionApplication{appliedRuleID: id, rollback: func() error {
			return h.rollbackSiteDecision(r, item.SiteID, func(site *storage.Site) bool {
				filtered := make([]storage.SiteCustomRule, 0, len(site.Advanced.CustomRules))
				removed := false
				for _, candidate := range site.Advanced.CustomRules {
					if candidate.ID == id {
						removed = true
						continue
					}
					filtered = append(filtered, candidate)
				}
				if removed {
					site.Advanced.CustomRules = filtered
				}
				return removed
			})
		}}, nil
	case "block_uri":
		path := reviewPath(item.URI)
		if path == "" {
			return reviewDecisionApplication{}, fmt.Errorf("uri is empty")
		}
		id, err := h.addSiteCustomRule(r, item, storage.SiteCustomRule{
			Name:     "待确认转拦截（URL）",
			Pattern:  "^" + regexp.QuoteMeta(path) + `(\?|$)`,
			Location: "uri",
			Action:   "block",
			Severity: reviewSeverity(item.Severity),
			Enabled:  true,
			Priority: 20,
		})
		if err != nil {
			return reviewDecisionApplication{}, err
		}
		return reviewDecisionApplication{appliedRuleID: id, rollback: func() error {
			return h.rollbackSiteDecision(r, item.SiteID, func(site *storage.Site) bool {
				filtered := make([]storage.SiteCustomRule, 0, len(site.Advanced.CustomRules))
				removed := false
				for _, candidate := range site.Advanced.CustomRules {
					if candidate.ID == id {
						removed = true
						continue
					}
					filtered = append(filtered, candidate)
				}
				if removed {
					site.Advanced.CustomRules = filtered
				}
				return removed
			})
		}}, nil
	case "block_ip":
		id, err := h.addIPBlockRule(r, item)
		if err != nil {
			return reviewDecisionApplication{}, err
		}
		return reviewDecisionApplication{appliedRuleID: id, rollback: func() error {
			return h.rollbackIPRule(r, id)
		}}, nil
	case "block_fingerprint":
		id, err := h.addFingerprintDeny(r, item)
		if err != nil {
			return reviewDecisionApplication{}, err
		}
		return reviewDecisionApplication{appliedRuleID: id, rollback: func() error {
			return h.rollbackSiteDecision(r, item.SiteID, func(site *storage.Site) bool {
				fingerprint := strings.TrimSpace(item.Fingerprint)
				filtered := make([]string, 0, len(site.Advanced.SemanticPolicy.FingerprintDeny))
				removed := false
				for _, candidate := range site.Advanced.SemanticPolicy.FingerprintDeny {
					if strings.EqualFold(candidate, fingerprint) {
						removed = true
						continue
					}
					filtered = append(filtered, candidate)
				}
				if removed {
					site.Advanced.SemanticPolicy.FingerprintDeny = filtered
				}
				return removed
			})
		}}, nil
	case "allow_whitelist":
		id, err := h.addSiteAllowlist(r, item)
		if err != nil {
			return reviewDecisionApplication{}, err
		}
		return reviewDecisionApplication{appliedRuleID: id, rollback: func() error {
			param := strings.TrimSpace(item.ParamName)
			path := reviewPath(item.URI)
			return h.rollbackSiteDecision(r, item.SiteID, func(site *storage.Site) bool {
				if param != "" {
					filtered := make([]string, 0, len(site.Advanced.SemanticPolicy.ParamAllowlist))
					removed := false
					for _, candidate := range site.Advanced.SemanticPolicy.ParamAllowlist {
						if strings.EqualFold(candidate, param) {
							removed = true
							continue
						}
						filtered = append(filtered, candidate)
					}
					if removed {
						site.Advanced.SemanticPolicy.ParamAllowlist = filtered
					}
					return removed
				}
				filtered := make([]string, 0, len(site.Advanced.SemanticPolicy.PathAllowlist))
				removed := false
				for _, candidate := range site.Advanced.SemanticPolicy.PathAllowlist {
					if strings.EqualFold(candidate, path) {
						removed = true
						continue
					}
					filtered = append(filtered, candidate)
				}
				if removed {
					site.Advanced.SemanticPolicy.PathAllowlist = filtered
				}
				return removed
			})
		}}, nil
	default:
		return reviewDecisionApplication{}, fmt.Errorf("unsupported decision")
	}
}

func (h *Handler) rollbackReviewDecision(r *http.Request, item *storage.ReviewItem, application reviewDecisionApplication, claimToken string) error {
	if application.rollback != nil {
		if err := application.rollback(); err != nil {
			return err
		}
	}
	return h.Store.ReleaseReviewItem(r.Context(), item.ID, claimToken)
}

func (h *Handler) rollbackSiteDecision(r *http.Request, siteID string, mutate func(*storage.Site) bool) error {
	h.siteMutationMu.Lock()
	defer h.siteMutationMu.Unlock()
	site, err := h.Store.GetSite(r.Context(), siteID)
	if err != nil || site == nil {
		return err
	}
	if !mutate(site) {
		return nil
	}
	if err := h.Store.UpdateSite(r.Context(), site); err != nil {
		return err
	}
	return h.syncSites(r)
}

func (h *Handler) rollbackIPRule(r *http.Request, ruleID string) error {
	_, err := h.commitConfigMutation(func(candidate *config.Config) error {
		filtered := candidate.Protection.IP.AccessRules[:0]
		for _, rule := range candidate.Protection.IP.AccessRules {
			if rule.ID != ruleID {
				filtered = append(filtered, rule)
			}
		}
		candidate.Protection.IP.AccessRules = filtered
		return nil
	}, func(candidate *config.Config) error {
		return h.notifyProtectionConfigChanged(candidate.Protection)
	})
	return err
}

func (h *Handler) rollbackAppliedReviewChange(r *http.Request, item *storage.ReviewItem, appliedID string) error {
	if item == nil || appliedID == "" {
		return nil
	}
	if strings.HasPrefix(appliedID, "review-ip-") {
		_, err := h.commitConfigMutation(func(candidate *config.Config) error {
			filtered := candidate.Protection.IP.AccessRules[:0]
			for _, rule := range candidate.Protection.IP.AccessRules {
				if rule.ID != appliedID {
					filtered = append(filtered, rule)
				}
			}
			candidate.Protection.IP.AccessRules = filtered
			return nil
		}, func(candidate *config.Config) error { return h.notifyProtectionConfigChanged(candidate.Protection) })
		return err
	}
	if strings.TrimSpace(item.SiteID) == "" {
		return nil
	}
	h.siteMutationMu.Lock()
	defer h.siteMutationMu.Unlock()
	site, err := h.Store.GetSite(r.Context(), item.SiteID)
	if err != nil || site == nil {
		return err
	}
	if strings.HasPrefix(appliedID, "fingerprint:") {
		value := strings.TrimPrefix(appliedID, "fingerprint:")
		filtered := site.Advanced.SemanticPolicy.FingerprintDeny[:0]
		for _, entry := range site.Advanced.SemanticPolicy.FingerprintDeny {
			if entry != value {
				filtered = append(filtered, entry)
			}
		}
		site.Advanced.SemanticPolicy.FingerprintDeny = filtered
	} else if strings.HasPrefix(appliedID, "param:") {
		value := strings.TrimPrefix(appliedID, "param:")
		filtered := site.Advanced.SemanticPolicy.ParamAllowlist[:0]
		for _, entry := range site.Advanced.SemanticPolicy.ParamAllowlist {
			if entry != value {
				filtered = append(filtered, entry)
			}
		}
		site.Advanced.SemanticPolicy.ParamAllowlist = filtered
	} else if strings.HasPrefix(appliedID, "path:") {
		value := strings.TrimPrefix(appliedID, "path:")
		filtered := site.Advanced.SemanticPolicy.PathAllowlist[:0]
		for _, entry := range site.Advanced.SemanticPolicy.PathAllowlist {
			if entry != value {
				filtered = append(filtered, entry)
			}
		}
		site.Advanced.SemanticPolicy.PathAllowlist = filtered
	} else {
		filtered := site.Advanced.CustomRules[:0]
		for _, rule := range site.Advanced.CustomRules {
			if rule.ID != appliedID {
				filtered = append(filtered, rule)
			}
		}
		site.Advanced.CustomRules = filtered
	}
	if err := h.Store.UpdateSite(r.Context(), site); err != nil {
		return err
	}
	return h.syncSites(r)
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
