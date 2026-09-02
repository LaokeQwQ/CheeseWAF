package handler

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

var (
	errCustomRuleNotFound = errors.New("rule not found")
	errCustomRuleExists   = errors.New("rule id already exists")
)

func (h *Handler) ListRules(w http.ResponseWriter, r *http.Request) {
	siteID := strings.TrimSpace(r.URL.Query().Get("site_id"))
	rules, err := h.listSiteCustomRules(r, siteID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "STORE_ERROR", err.Error())
		return
	}
	writeData(w, rules)
}

func (h *Handler) CreateRule(w http.ResponseWriter, r *http.Request) {
	if h.rejectClusterConfigWriteIfFrozen(w, r) {
		return
	}
	var rule storage.Rule
	if !decode(w, r, &rule) {
		return
	}
	if !h.validateRule(w, r, &rule) {
		return
	}
	if strings.TrimSpace(rule.ID) == "" {
		rule.ID = uuid.NewString()
	}
	if err := h.mutateSiteCustomRules(r, rule.SiteID, "", func(site *storage.Site) error {
		for _, existing := range site.Advanced.CustomRules {
			if existing.ID == rule.ID {
				return errCustomRuleExists
			}
		}
		site.Advanced.CustomRules = append(append([]storage.SiteCustomRule(nil), site.Advanced.CustomRules...), storage.SiteCustomRule{
			ID:          rule.ID,
			Name:        rule.Name,
			Description: rule.Description,
			Pattern:     rule.Pattern,
			Location:    rule.Location,
			Action:      rule.Action,
			Severity:    rule.Severity,
			Enabled:     rule.Enabled,
			Priority:    rule.Priority,
		})
		return nil
	}); err != nil {
		writeRuleMutationError(w, err)
		return
	}
	writeData(w, rule)
}

func (h *Handler) UpdateRule(w http.ResponseWriter, r *http.Request) {
	if h.rejectClusterConfigWriteIfFrozen(w, r) {
		return
	}
	var rule storage.Rule
	if !decode(w, r, &rule) {
		return
	}
	rule.ID = chi.URLParam(r, "id")
	if !h.validateRule(w, r, &rule) {
		return
	}
	if err := h.mutateSiteCustomRules(r, rule.SiteID, "", func(site *storage.Site) error {
		next := append([]storage.SiteCustomRule(nil), site.Advanced.CustomRules...)
		found := false
		for index, existing := range next {
			if existing.ID != rule.ID {
				continue
			}
			next[index] = storage.SiteCustomRule{
				ID:          rule.ID,
				Name:        rule.Name,
				Description: rule.Description,
				Pattern:     rule.Pattern,
				Location:    rule.Location,
				Action:      rule.Action,
				Severity:    rule.Severity,
				Enabled:     rule.Enabled,
				Priority:    rule.Priority,
			}
			found = true
			break
		}
		if !found {
			return errCustomRuleNotFound
		}
		site.Advanced.CustomRules = next
		return nil
	}); err != nil {
		writeRuleMutationError(w, err)
		return
	}
	writeData(w, rule)
}

func (h *Handler) validateRule(w http.ResponseWriter, r *http.Request, rule *storage.Rule) bool {
	if rule == nil {
		writeError(w, http.StatusBadRequest, "RULE_INVALID", "rule is required")
		return false
	}
	rule.SiteID = strings.TrimSpace(rule.SiteID)
	rule.Pattern = strings.TrimSpace(rule.Pattern)
	rule.Location = strings.ToLower(strings.TrimSpace(rule.Location))
	rule.Action = strings.ToLower(strings.TrimSpace(rule.Action))
	rule.Severity = strings.ToLower(strings.TrimSpace(rule.Severity))
	if rule.Severity == "" {
		rule.Severity = "medium"
	}
	if rule.SiteID == "" {
		writeError(w, http.StatusBadRequest, "RULE_INVALID", "site_id is required")
		return false
	}
	site, err := h.Store.GetSite(r.Context(), rule.SiteID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "STORE_ERROR", err.Error())
		return false
	}
	if site == nil {
		writeError(w, http.StatusBadRequest, "RULE_INVALID", "site_id does not reference an existing site")
		return false
	}
	if err := config.ValidateCustomRule(config.CustomRuleConfig{
		ID: rule.ID, Name: rule.Name, Pattern: rule.Pattern, Location: rule.Location,
		Action: rule.Action, Severity: rule.Severity, Enabled: rule.Enabled, Priority: rule.Priority,
	}); err != nil {
		writeError(w, http.StatusBadRequest, "RULE_INVALID", err.Error())
		return false
	}
	return true
}

func (h *Handler) DeleteRule(w http.ResponseWriter, r *http.Request) {
	if h.rejectClusterConfigWriteIfFrozen(w, r) {
		return
	}
	ruleID := chi.URLParam(r, "id")
	siteID := strings.TrimSpace(r.URL.Query().Get("site_id"))
	if err := h.mutateSiteCustomRules(r, siteID, ruleID, func(site *storage.Site) error {
		next := make([]storage.SiteCustomRule, 0, len(site.Advanced.CustomRules))
		for _, rule := range site.Advanced.CustomRules {
			if rule.ID != ruleID {
				next = append(next, rule)
			}
		}
		if len(next) == len(site.Advanced.CustomRules) {
			return errCustomRuleNotFound
		}
		site.Advanced.CustomRules = next
		return nil
	}); err != nil {
		writeRuleMutationError(w, err)
		return
	}
	writeData(w, map[string]bool{"deleted": true})
}

func (h *Handler) ImportCustomRules(w http.ResponseWriter, r *http.Request) {
	if h.rejectClusterConfigWriteIfFrozen(w, r) {
		return
	}
	siteID := strings.TrimSpace(r.URL.Query().Get("site_id"))
	if siteID == "" {
		writeError(w, http.StatusBadRequest, "RULE_INVALID", "site_id is required")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, defaultJSONBodyLimit)
	data, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "RULES_IMPORT_INVALID", err.Error())
		return
	}
	parsed, err := config.ParseCustomRules(data)
	if err != nil {
		writeError(w, http.StatusBadRequest, "RULES_IMPORT_INVALID", err.Error())
		return
	}
	prepared, err := config.PrepareCustomRules(parsed)
	if err != nil {
		writeError(w, http.StatusBadRequest, "RULES_IMPORT_INVALID", err.Error())
		return
	}
	if err := h.mutateSiteCustomRules(r, siteID, "", func(site *storage.Site) error {
		site.Advanced.CustomRules = storage.SiteCustomRulesFromConfig(prepared)
		return nil
	}); err != nil {
		writeRuleMutationError(w, err)
		return
	}
	writeData(w, map[string]any{
		"site_id":      siteID,
		"custom_rules": prepared,
		"count":        len(prepared),
	})
}

func (h *Handler) ExportCustomRules(w http.ResponseWriter, r *http.Request) {
	siteID := strings.TrimSpace(r.URL.Query().Get("site_id"))
	if siteID == "" {
		writeError(w, http.StatusBadRequest, "RULE_INVALID", "site_id is required")
		return
	}
	site, err := h.Store.GetSite(r.Context(), siteID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "STORE_ERROR", err.Error())
		return
	}
	if site == nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "site not found")
		return
	}
	h.writeCustomRulesDocument(w, storage.SiteCustomRulesToConfig(site.Advanced.CustomRules), r.URL.Query().Get("format"), "custom_rules-"+siteID)
}

func (h *Handler) ExampleCustomRules(w http.ResponseWriter, r *http.Request) {
	h.writeCustomRulesDocument(w, config.ExampleCustomRules(), r.URL.Query().Get("format"), "custom_rules.example")
}

func (h *Handler) writeCustomRulesDocument(w http.ResponseWriter, rules []config.CustomRuleConfig, format, filenameBase string) {
	normalized := config.NormalizeCustomRulesFormat(format)
	body, err := config.EncodeCustomRules(rules, normalized)
	if err != nil {
		writeError(w, http.StatusBadRequest, "RULES_EXPORT_INVALID", err.Error())
		return
	}
	filename := config.CustomRuleFilename(filenameBase, normalized)
	contentType := "application/yaml; charset=utf-8"
	if normalized == config.CustomRulesFormatJSON {
		contentType = "application/json; charset=utf-8"
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func (h *Handler) listSiteCustomRules(r *http.Request, siteID string) ([]storage.Rule, error) {
	if siteID != "" {
		site, err := h.Store.GetSite(r.Context(), siteID)
		if err != nil {
			return nil, err
		}
		if site == nil {
			return []storage.Rule{}, nil
		}
		return storage.RulesFromSiteCustomRules(site.ID, site.Advanced.CustomRules), nil
	}
	sites, err := h.Store.ListSites(r.Context())
	if err != nil {
		return nil, err
	}
	var out []storage.Rule
	for _, site := range sites {
		out = append(out, storage.RulesFromSiteCustomRules(site.ID, site.Advanced.CustomRules)...)
	}
	if out == nil {
		out = []storage.Rule{}
	}
	return out, nil
}

// ListCustomRules exposes the live site-scoped rules to internal automation.
func (h *Handler) ListCustomRules(ctx context.Context) ([]storage.Rule, error) {
	if h == nil || h.Store == nil {
		return nil, fmt.Errorf("rule service is unavailable")
	}
	sites, err := h.Store.ListSites(ctx)
	if err != nil {
		return nil, err
	}
	var out []storage.Rule
	for _, site := range sites {
		out = append(out, storage.RulesFromSiteCustomRules(site.ID, site.Advanced.CustomRules)...)
	}
	return out, nil
}

// ApplyGeneratedCustomRule is the only internal path for automated rule
// creation. It uses the same validation, persistence, hot reload and rollback
// flow as the management API.
func (h *Handler) ApplyGeneratedCustomRule(ctx context.Context, rule *storage.Rule) error {
	if h == nil || rule == nil {
		return fmt.Errorf("generated rule is required")
	}
	if err := h.selfLearningRuleWriteAllowed(nil); err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "/internal/generated-rule", nil)
	if err != nil {
		return err
	}
	if err := config.ValidateCustomRule(config.CustomRuleConfig{
		ID: rule.ID, Name: rule.Name, Description: rule.Description, Pattern: rule.Pattern,
		Location: rule.Location, Action: rule.Action, Severity: rule.Severity,
		Enabled: rule.Enabled, Priority: rule.Priority,
	}); err != nil {
		return err
	}
	return h.mutateSiteCustomRules(request, rule.SiteID, "", func(site *storage.Site) error {
		for _, existing := range site.Advanced.CustomRules {
			if existing.ID == rule.ID {
				return errCustomRuleExists
			}
		}
		site.Advanced.CustomRules = append(site.Advanced.CustomRules, storage.SiteCustomRule{
			ID: rule.ID, Name: rule.Name, Description: rule.Description, Pattern: rule.Pattern,
			Location: rule.Location, Action: rule.Action, Severity: rule.Severity,
			Enabled: rule.Enabled, Priority: rule.Priority,
		})
		return nil
	})
}

func (h *Handler) mutateSiteCustomRules(r *http.Request, siteID, hintRuleID string, mutate func(*storage.Site) error) error {
	h.siteMutationMu.Lock()
	defer h.siteMutationMu.Unlock()
	site, err := h.resolveSiteForRuleMutation(r, siteID, hintRuleID)
	if err != nil {
		return err
	}
	if site == nil {
		return fmt.Errorf("site not found")
	}
	existing, err := cloneSite(site)
	if err != nil {
		return err
	}
	if err := mutate(site); err != nil {
		return err
	}
	prepared, err := config.PrepareCustomRules(storage.SiteCustomRulesToConfig(site.Advanced.CustomRules))
	if err != nil {
		return err
	}
	site.Advanced.CustomRules = storage.SiteCustomRulesFromConfig(prepared)
	if err := h.validateCandidateSites(r, func(sites []storage.Site) []storage.Site {
		for index := range sites {
			if sites[index].ID != site.ID {
				continue
			}
			sites[index].Advanced.CustomRules = storage.SiteCustomRulesFromConfig(prepared)
			return sites
		}
		return sites
	}); err != nil {
		return err
	}
	if err := h.Store.UpdateSite(r.Context(), site); err != nil {
		return err
	}
	return h.syncSitesOrRollback(r, func() error {
		if restorer, ok := h.Store.(interface {
			RestoreSite(context.Context, *storage.Site) error
		}); ok {
			return restorer.RestoreSite(r.Context(), existing)
		}
		return h.Store.UpdateSite(r.Context(), existing)
	})
}

func (h *Handler) resolveSiteForRuleMutation(r *http.Request, siteID, hintRuleID string) (*storage.Site, error) {
	if siteID != "" {
		return h.Store.GetSite(r.Context(), siteID)
	}
	sites, err := h.Store.ListSites(r.Context())
	if err != nil {
		return nil, err
	}
	if hintRuleID != "" {
		for index := range sites {
			for _, rule := range sites[index].Advanced.CustomRules {
				if rule.ID != hintRuleID {
					continue
				}
				site := sites[index]
				return &site, nil
			}
		}
		return nil, errCustomRuleNotFound
	}
	if len(sites) == 1 {
		site := sites[0]
		return &site, nil
	}
	return nil, fmt.Errorf("site not found")
}

func writeRuleMutationError(w http.ResponseWriter, err error) {
	if err == nil {
		return
	}
	switch {
	case errors.Is(err, errCustomRuleNotFound), strings.Contains(err.Error(), "site not found"):
		writeError(w, http.StatusNotFound, "NOT_FOUND", err.Error())
	case errors.Is(err, errCustomRuleExists):
		writeError(w, http.StatusBadRequest, "RULE_INVALID", err.Error())
	case strings.Contains(err.Error(), "invalid"), strings.Contains(err.Error(), "custom rules"):
		writeError(w, http.StatusBadRequest, "RULES_IMPORT_INVALID", err.Error())
	default:
		writeError(w, http.StatusInternalServerError, "CONFIG_SYNC_ERROR", err.Error())
	}
}
