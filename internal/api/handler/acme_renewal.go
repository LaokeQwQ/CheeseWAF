package handler

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/acme"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

const (
	defaultACMERenewalInterval = time.Hour
	defaultACMERenewBefore     = 30 * 24 * time.Hour
)

// StartACMERenewal starts the in-process ACME renewal worker. The first scan
// runs immediately; subsequent scans use a conservative hourly interval. The
// caller owns ctx and should cancel it with the rest of the serving runtime.
func (h *Handler) StartACMERenewal(ctx context.Context) context.CancelFunc {
	if h == nil || ctx == nil {
		return func() {}
	}
	h.acmeRenewMu.Lock()
	if h.acmeRenewCancel != nil {
		h.acmeRenewCancel()
	}
	workerCtx, cancel := context.WithCancel(ctx)
	h.acmeRenewCancel = cancel
	h.acmeRenewMu.Unlock()
	worker := &acmeRenewalWorker{handler: h, interval: defaultACMERenewalInterval, renewBefore: defaultACMERenewBefore}
	go worker.run(workerCtx)
	return cancel
}

// StopACMERenewal stops the currently running renewal worker, if any.
func (h *Handler) StopACMERenewal() {
	if h == nil {
		return
	}
	h.acmeRenewMu.Lock()
	if h.acmeRenewCancel != nil {
		h.acmeRenewCancel()
		h.acmeRenewCancel = nil
	}
	h.acmeRenewMu.Unlock()
}

// RenewACMEOnce performs one deterministic renewal/expiry scan. It is exposed
// for startup checks and tests; it never starts a background goroutine.
func (h *Handler) RenewACMEOnce(ctx context.Context) error {
	if h == nil || h.Store == nil {
		return errors.New("acme renewal store is unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	worker := &acmeRenewalWorker{handler: h, interval: defaultACMERenewalInterval, renewBefore: defaultACMERenewBefore}
	return worker.scan(ctx)
}

type acmeRenewalWorker struct {
	handler     *Handler
	interval    time.Duration
	renewBefore time.Duration
	mu          sync.Mutex
	inFlight    map[string]struct{}
}

func (w *acmeRenewalWorker) run(ctx context.Context) {
	if w == nil || w.handler == nil {
		return
	}
	_ = w.scan(ctx)
	interval := w.interval
	if interval <= 0 {
		interval = defaultACMERenewalInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = w.scan(ctx)
		}
	}
}

func (w *acmeRenewalWorker) scan(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	cfg := w.handler.currentConfig()
	if cfg == nil || !cfg.ACME.Enabled {
		return nil
	}
	sites, err := w.handler.Store.ListSites(ctx)
	if err != nil {
		return err
	}
	var firstErr error
	for i := range sites {
		if err := w.scanSite(ctx, &sites[i]); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (w *acmeRenewalWorker) scanSite(ctx context.Context, site *storage.Site) error {
	if site == nil || !site.Enabled || !site.EnableSSL {
		return nil
	}
	cert := site.Advanced.Certificate
	if cert.Mode != "acme" || !cert.AutoRenew {
		return nil
	}
	domains := append([]string(nil), site.Domains...)
	if len(domains) == 0 {
		domains = append(domains, cert.ACME.Domains...)
	}
	if len(domains) == 0 {
		return w.recordFailure(ctx, site, errors.New("no domains configured for ACME renewal"))
	}
	if !w.begin(site.ID) {
		return nil
	}
	defer w.end(site.ID)

	now := w.handler.nowUTC()
	if strings.TrimSpace(site.CertFile) == "" || strings.TrimSpace(site.KeyFile) == "" {
		return w.renew(ctx, site, domains)
	}
	certExpiry, certErr := validateACMECertificateFiles(site.CertFile, site.KeyFile, domains, now, false)
	renewAt := cert.ACME.ExpiresAt
	if !certExpiry.IsZero() {
		deadline := certExpiry.Add(-w.renewBefore)
		if renewAt.IsZero() || deadline.Before(renewAt) {
			renewAt = deadline
		}
	}
	if certErr != nil {
		return w.renew(ctx, site, domains)
	}
	if !renewAt.IsZero() && now.Before(renewAt) {
		return nil
	}

	return w.renew(ctx, site, domains)
}

func (w *acmeRenewalWorker) begin(siteID string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.inFlight == nil {
		w.inFlight = make(map[string]struct{})
	}
	if _, exists := w.inFlight[siteID]; exists {
		return false
	}
	w.inFlight[siteID] = struct{}{}
	return true
}

func (w *acmeRenewalWorker) end(siteID string) {
	w.mu.Lock()
	delete(w.inFlight, siteID)
	w.mu.Unlock()
}

func (w *acmeRenewalWorker) renew(ctx context.Context, site *storage.Site, domains []string) error {
	// Site mutations and the manual issuance API share this lock so a renewal
	// cannot overwrite a concurrent operator update with stale metadata.
	w.handler.siteMutationMu.Lock()
	defer w.handler.siteMutationMu.Unlock()
	current, err := w.handler.Store.GetSite(ctx, site.ID)
	if err != nil {
		return err
	}
	if current == nil || !current.Advanced.Certificate.AutoRenew || current.Advanced.Certificate.Mode != "acme" {
		return nil
	}
	runtime := w.handler.trustedSiteACMERuntime(current)
	acmeCfg := current.Advanced.Certificate.ACME
	previous, cloneErr := cloneSite(current)
	if cloneErr != nil {
		return cloneErr
	}
	snapshot, snapshotErr := snapshotACMECertificate(runtime.CertDir)
	if snapshotErr != nil {
		return w.recordFailure(ctx, current, snapshotErr)
	}
	restore := func(cause error) error {
		if restoreErr := snapshot.restore(); restoreErr != nil {
			return fmt.Errorf("%v; restore previous certificate: %w", cause, restoreErr)
		}
		return cause
	}
	issuer := w.handler.ensureACMEIssuer()
	if issuer == nil {
		return w.recordFailure(ctx, current, errors.New("acme issuer is unavailable"))
	}
	result, issueErr := issuer.Issue(ctx, acme.IssueRequest{
		SiteID:       current.ID,
		Domains:      append([]string(nil), domains...),
		ProviderID:   acmeCfg.ProviderID,
		DNSAPI:       acmeCfg.DNSAPI,
		DNSEnv:       cloneStringMap(acmeCfg.Env),
		AccountEmail: acmeCfg.AccountEmail,
		Server:       acmeCfg.Server,
		KeyType:      acmeCfg.KeyType,
		ACMESHPath:   runtime.ACMESHPath,
		Home:         runtime.Home,
		CertDir:      runtime.CertDir,
		ReloadCmd:    runtime.ReloadCmd,
		AutoRenew:    true,
		Notify:       acmeCfg.Notify,
	})
	if issueErr != nil {
		issueErr = restore(issueErr)
		_ = w.recordFailure(ctx, current, issueErr)
		return issueErr
	}
	if _, err := validateACMECertificateFiles(result.CertFile, result.KeyFile, domains, w.handler.nowUTC(), true); err != nil {
		err = restore(err)
		_ = w.recordFailure(ctx, current, err)
		return err
	}
	current.CertFile = result.CertFile
	current.KeyFile = result.KeyFile
	current.EnableSSL = true
	current.Advanced.Certificate.Mode = "acme"
	current.Advanced.Certificate.AutoRenew = true
	current.Advanced.Certificate.ACME.LastStatus = "renewed"
	current.Advanced.Certificate.ACME.LastRunID = result.RunID
	current.Advanced.Certificate.ACME.LastIssuedAt = result.IssuedAt
	current.Advanced.Certificate.ACME.ExpiresAt = result.RenewAfter
	if err := w.handler.Store.UpdateSite(ctx, current); err != nil {
		return restore(err)
	}
	if err := w.handler.syncSites(newACMERequest(ctx)); err != nil {
		_ = w.handler.Store.UpdateSite(ctx, previous)
		_ = snapshot.restore()
		_ = w.handler.syncSites(newACMERequest(ctx))
		return err
	}
	w.handler.notifyACMEIssue(newACMERequest(ctx), current, result, nil)
	return nil
}

func (w *acmeRenewalWorker) recordFailure(ctx context.Context, site *storage.Site, cause error) error {
	if site == nil || cause == nil {
		return cause
	}
	copySite, err := cloneSite(site)
	if err != nil {
		return cause
	}
	copySite.Advanced.Certificate.ACME.LastStatus = "renew_failed"
	if updateErr := w.handler.Store.UpdateSite(ctx, copySite); updateErr != nil {
		return fmt.Errorf("%v; persist renewal failure: %w", cause, updateErr)
	}
	w.handler.notifyACMEIssue(newACMERequest(ctx), copySite, acme.IssueResult{SiteID: site.ID, Domains: site.Domains, Notify: copySite.Advanced.Certificate.ACME.Notify}, cause)
	return cause
}

func newACMERequest(ctx context.Context) *http.Request {
	request, _ := http.NewRequest(http.MethodPost, "http://localhost/internal/acme/renew", nil)
	return request.WithContext(ctx)
}

// validateACMECertificateFiles checks the installed certificate and key before
// they are published to the proxy. When required is false, an absent pair is
// tolerated for compatibility with injected/test issuers; a partial pair is
// always rejected. Real acme.sh output is present and therefore fully checked.
func validateACMECertificateFiles(certPath, keyPath string, domains []string, now time.Time, required bool) (time.Time, error) {
	certInfo, certErr := os.Lstat(certPath)
	keyInfo, keyErr := os.Lstat(keyPath)
	if os.IsNotExist(certErr) && os.IsNotExist(keyErr) && !required {
		return time.Time{}, nil
	}
	if certErr != nil {
		return time.Time{}, fmt.Errorf("inspect certificate: %w", certErr)
	}
	if keyErr != nil {
		return time.Time{}, fmt.Errorf("inspect private key: %w", keyErr)
	}
	if certInfo.Mode()&os.ModeSymlink != 0 || keyInfo.Mode()&os.ModeSymlink != 0 {
		return time.Time{}, errors.New("certificate and private key must not be symlinks")
	}
	if !certInfo.Mode().IsRegular() || !keyInfo.Mode().IsRegular() {
		return time.Time{}, errors.New("certificate and private key must be regular files")
	}
	if err := os.Chmod(keyPath, 0o600); err != nil {
		return time.Time{}, fmt.Errorf("restrict private key permissions: %w", err)
	}
	keyInfo, err := os.Lstat(keyPath)
	if err != nil || keyInfo.Mode().Perm()&0o077 != 0 {
		return time.Time{}, errors.New("private key permissions must be owner-only")
	}
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return time.Time{}, fmt.Errorf("load certificate and private key: %w", err)
	}
	if len(pair.Certificate) == 0 {
		return time.Time{}, errors.New("certificate chain is empty")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return time.Time{}, fmt.Errorf("parse leaf certificate: %w", err)
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if !now.Before(leaf.NotAfter) {
		return time.Time{}, fmt.Errorf("certificate expired at %s", leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	if len(leaf.DNSNames) == 0 && len(leaf.IPAddresses) == 0 {
		return time.Time{}, errors.New("certificate has no SAN entries")
	}
	for _, domain := range domains {
		domain = strings.TrimSpace(domain)
		if domain == "" {
			continue
		}
		probe := domain
		if strings.HasPrefix(probe, "*.") {
			probe = "acme-check." + strings.TrimPrefix(probe, "*.")
		}
		if err := leaf.VerifyHostname(probe); err != nil {
			return time.Time{}, fmt.Errorf("certificate does not cover %q: %w", domain, err)
		}
	}
	return leaf.NotAfter, nil
}
