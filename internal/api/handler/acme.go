package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/acme"
	"github.com/LaokeQwQ/CheeseWAF/internal/api/dto"
	"github.com/LaokeQwQ/CheeseWAF/internal/blockpage"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/monitor"
	monitornotify "github.com/LaokeQwQ/CheeseWAF/internal/monitor/notifier"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
	"github.com/go-chi/chi/v5"
)

type acmeIssuePayload struct {
	ProviderID   string            `json:"provider_id"`
	DNSAPI       string            `json:"dns_api"`
	DNSEnv       map[string]string `json:"dns_env"`
	AccountEmail string            `json:"account_email"`
	Server       string            `json:"server"`
	KeyType      string            `json:"key_type"`
	AutoRenew    bool              `json:"auto_renew"`
	Notify       bool              `json:"notify"`
}

func (h *Handler) ACMEDNSProviders(w http.ResponseWriter, r *http.Request) {
	issuer := h.ensureACMEIssuer()
	if issuer == nil {
		writeData(w, []acme.DNSProvider{})
		return
	}
	writeData(w, issuer.Providers())
}

func (h *Handler) IssueSiteACME(w http.ResponseWriter, r *http.Request) {
	issuer := h.ensureACMEIssuer()
	if issuer == nil {
		writeError(w, http.StatusServiceUnavailable, "ACME_DISABLED", "acme issuer is not configured")
		return
	}
	siteID := chi.URLParam(r, "id")
	site, err := h.Store.GetSite(r.Context(), siteID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "STORE_ERROR", err.Error())
		return
	}
	if site == nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "site not found")
		return
	}
	var req acmeIssuePayload
	if !decode(w, r, &req) {
		return
	}
	runtime := h.trustedSiteACMERuntime(site)
	certReq := acme.IssueRequest{
		SiteID:       site.ID,
		Domains:      append([]string(nil), site.Domains...),
		ProviderID:   req.ProviderID,
		DNSAPI:       req.DNSAPI,
		DNSEnv:       req.DNSEnv,
		AccountEmail: req.AccountEmail,
		Server:       req.Server,
		KeyType:      req.KeyType,
		ACMESHPath:   runtime.ACMESHPath,
		Home:         runtime.Home,
		CertDir:      runtime.CertDir,
		ReloadCmd:    runtime.ReloadCmd,
		AutoRenew:    req.AutoRenew,
		Notify:       req.Notify,
	}
	result, err := issuer.Issue(r.Context(), certReq)
	if err != nil {
		h.notifyACMEIssue(r, site, result, err)
		writeErrorWithData(w, http.StatusBadRequest, "ACME_ISSUE_FAILED", err.Error(), map[string]any{
			"result": result,
			"events": result.Events,
		})
		return
	}
	site.EnableSSL = true
	site.CertFile = result.CertFile
	site.KeyFile = result.KeyFile
	cert := site.Advanced.Certificate
	cert.Mode = "acme"
	cert.AutoRenew = req.AutoRenew
	cert.ForceHTTPS = true
	cert.HSTS = true
	if cert.MinTLSVersion == "" {
		cert.MinTLSVersion = "1.2"
	}
	cert.ACME = storage.SiteACMEConfig{
		ProviderID:    req.ProviderID,
		DNSAPI:        req.DNSAPI,
		AccountEmail:  req.AccountEmail,
		Server:        req.Server,
		KeyType:       req.KeyType,
		ACMESHPath:    runtime.ACMESHPath,
		Home:          runtime.Home,
		CertDir:       runtime.CertDir,
		ReloadCommand: runtime.ReloadCmd,
		Domains:       append([]string(nil), site.Domains...),
		Env:           cloneStringMap(req.DNSEnv),
		Notify:        req.Notify,
		LastStatus:    "issued",
		LastRunID:     result.RunID,
		LastIssuedAt:  result.IssuedAt,
		ExpiresAt:     result.RenewAfter,
	}
	site.Advanced.Certificate = cert
	if err := h.Store.UpdateSite(r.Context(), site); err != nil {
		h.notifyACMEIssue(r, site, result, err)
		writeError(w, http.StatusInternalServerError, "STORE_ERROR", err.Error())
		return
	}
	if err := h.syncSites(r); err != nil {
		h.notifyACMEIssue(r, site, result, err)
		writeError(w, http.StatusInternalServerError, "CONFIG_SYNC_ERROR", err.Error())
		return
	}
	h.notifyACMEIssue(r, site, result, nil)
	writeData(w, map[string]any{
		"site":    siteView(*site),
		"result":  result,
		"events":  result.Events,
		"cert":    map[string]any{"cert_file": result.CertFile, "key_file": result.KeyFile},
		"issued":  true,
		"acme":    siteACMEConfigView(site.Advanced.Certificate.ACME),
		"summary": map[string]any{"site_id": site.ID, "domains": result.Domains, "run_id": result.RunID},
	})
}

type trustedACMERuntime struct {
	ACMESHPath string
	Home       string
	CertDir    string
	ReloadCmd  string
}

func (h *Handler) trustedSiteACMERuntime(site *storage.Site) trustedACMERuntime {
	cfg := config.Default()
	if h != nil && h.Config != nil {
		cfg = *h.Config
	}
	acmeCfg := cfg.ACME
	baseDir := cfg.Setup.DataDir
	primary := "site"
	if site != nil {
		primary = firstNonEmpty(firstSiteDomain(site), site.ID, site.Name, "site")
	}
	if strings.TrimSpace(acmeCfg.ACMESHPath) == "" {
		acmeCfg.ACMESHPath = "acme.sh"
	}
	if strings.TrimSpace(acmeCfg.Home) == "" {
		acmeCfg.Home = filepath.Join(firstNonEmpty(baseDir, "."), "acme")
	}
	if strings.TrimSpace(acmeCfg.CertDir) == "" {
		acmeCfg.CertDir = filepath.Join(firstNonEmpty(baseDir, "."), "certs")
	}
	return trustedACMERuntime{
		ACMESHPath: acmeCfg.ACMESHPath,
		Home:       acmeCfg.Home,
		CertDir:    trustedSiteCertDir(acmeCfg.CertDir, primary),
		ReloadCmd:  acmeCfg.ReloadCommand,
	}
}

func trustedSiteCertDir(base string, primary string) string {
	segment := safeACMEPathSegment(primary)
	if filepath.Base(filepath.Clean(base)) == segment {
		return base
	}
	return filepath.Join(base, segment)
}

func firstSiteDomain(site *storage.Site) string {
	if site == nil {
		return ""
	}
	for _, domain := range site.Domains {
		if strings.TrimSpace(domain) != "" {
			return domain
		}
	}
	return ""
}

func (h *Handler) ensureACMEIssuer() acme.Issuer {
	if h != nil && h.ACMEIssuer != nil {
		return h.ACMEIssuer
	}
	if h == nil || h.Config == nil {
		return nil
	}
	return acme.NewIssuer(acme.IssuerOptions{Config: h.Config})
}

func (h *Handler) notifyACMEIssue(r *http.Request, site *storage.Site, result acme.IssueResult, cause error) {
	if h == nil || h.Config == nil || !result.Notify {
		return
	}
	severity := "info"
	message := fmt.Sprintf("ACME certificate issued for site %s domains=%v run=%s", result.SiteID, result.Domains, result.RunID)
	if cause != nil {
		severity = "high"
		message = fmt.Sprintf("ACME certificate issuance failed for site %s domains=%v run=%s: %s", result.SiteID, result.Domains, result.RunID, cause.Error())
	}
	name := result.SiteID
	if site != nil && site.Name != "" {
		name = site.Name
	}
	startsAt := result.IssuedAt
	if startsAt.IsZero() {
		startsAt = time.Now().UTC()
	}
	alert := monitor.Alert{
		RuleID:    "acme.issue",
		Name:      "ACME certificate pipeline",
		Metric:    "cheesewaf_acme_issue",
		Value:     1,
		Threshold: 1,
		Severity:  severity,
		Message:   message,
		StartsAt:  startsAt,
	}
	alert.Name = "ACME certificate pipeline: " + name
	manager := monitornotify.NewManager(h.Config.Monitor.Notifiers)
	_ = manager.Notify(r.Context(), []monitor.Alert{alert})
}

func writeErrorWithData(w http.ResponseWriter, status int, code, message string, data any) {
	traceID := blockpage.NewTraceID()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-CheeseWAF-Trace-ID", traceID)
	w.Header().Set("X-CheeseWAF-Event-ID", traceID)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(dto.Response{
		Data:  data,
		Error: &dto.APIError{Code: code, Message: message, TraceID: traceID, EventID: traceID},
	})
}

func cloneStringMap(values map[string]string) map[string]string {
	if values == nil {
		return map[string]string{}
	}
	out := make(map[string]string, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}

func safeACMEPathSegment(value string) string {
	value = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(value)), "*.")
	var b strings.Builder
	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '.' {
			b.WriteRune(r)
			continue
		}
		b.WriteRune('-')
	}
	out := strings.Trim(b.String(), ".-")
	if out == "" {
		return "site"
	}
	return out
}
