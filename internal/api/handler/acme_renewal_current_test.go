package handler

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestACMERenewalUsesCurrentDomainsAfterSiteChanges(t *testing.T) {
	h, store, site := newSiteTestHandler(t)
	h.Config.ACME.CertDir = t.TempDir()
	site.EnableSSL = true
	site.Advanced.Certificate.Mode = "acme"
	site.Advanced.Certificate.AutoRenew = true
	if err := store.UpdateSite(context.Background(), &site); err != nil {
		t.Fatal(err)
	}
	stale, err := cloneSite(&site)
	if err != nil {
		t.Fatal(err)
	}
	site.Domains = []string{"current.example.test"}
	if err := store.UpdateSite(context.Background(), &site); err != nil {
		t.Fatal(err)
	}
	issuer := &renewingACMEIssuer{}
	h.ACMEIssuer = issuer
	worker := &acmeRenewalWorker{handler: h, renewBefore: defaultACMERenewBefore}
	if err := worker.scanSite(context.Background(), stale); err != nil {
		t.Fatalf("renew stale scan after domain update: %v", err)
	}
	if issuer.calls != 1 {
		t.Fatalf("issuer calls = %d, want 1", issuer.calls)
	}
	current, err := store.GetSite(context.Background(), site.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validateACMECertificateFiles(current.CertFile, current.KeyFile, []string{"current.example.test"}, time.Now(), true); err != nil {
		t.Fatalf("renewed certificate must cover current domains: %v", err)
	}
}

func TestACMERenewalRechecksCurrentSiteStillNeedsRenewal(t *testing.T) {
	for _, change := range []string{"disabled site", "disabled TLS", "renewed certificate"} {
		t.Run(change, func(t *testing.T) {
			h, store, site := newSiteTestHandler(t)
			h.Config.ACME.CertDir = t.TempDir()
			site.EnableSSL = true
			site.Advanced.Certificate.Mode = "acme"
			site.Advanced.Certificate.AutoRenew = true
			site.Advanced.Certificate.ACME.ExpiresAt = time.Now().Add(-time.Hour)
			if err := store.UpdateSite(context.Background(), &site); err != nil {
				t.Fatal(err)
			}
			stale, err := cloneSite(&site)
			if err != nil {
				t.Fatal(err)
			}
			switch change {
			case "disabled site":
				site.Enabled = false
			case "disabled TLS":
				site.EnableSSL = false
			case "renewed certificate":
				site.CertFile, site.KeyFile = writeRenewalTestCertificate(t, t.TempDir(), site.Domains, time.Now().Add(90*24*time.Hour))
				site.Advanced.Certificate.ACME.ExpiresAt = time.Now().Add(60 * 24 * time.Hour)
			}
			if err := store.UpdateSite(context.Background(), &site); err != nil {
				t.Fatal(err)
			}
			issuer := &renewingACMEIssuer{}
			h.ACMEIssuer = issuer
			worker := &acmeRenewalWorker{handler: h, renewBefore: defaultACMERenewBefore}
			if err := worker.scanSite(context.Background(), stale); err != nil {
				t.Fatalf("recheck stale renewal scan: %v", err)
			}
			if issuer.calls != 0 {
				t.Fatalf("issuer calls = %d, want 0 after %s", issuer.calls, change)
			}
			current, err := store.GetSite(context.Background(), site.ID)
			if err != nil {
				t.Fatal(err)
			}
			if current.Enabled != site.Enabled || current.EnableSSL != site.EnableSSL || current.CertFile != site.CertFile || current.KeyFile != site.KeyFile {
				t.Fatal("stale renewal changed the current site deployment")
			}
		})
	}
}

func TestACMERenewalRejectsRemovedDomainsAfterSiteChanges(t *testing.T) {
	h, store, site := newSiteTestHandler(t)
	h.Config.ACME.CertDir = filepath.Join(t.TempDir(), "certificates")
	site.EnableSSL = true
	site.Advanced.Certificate.Mode = "acme"
	site.Advanced.Certificate.AutoRenew = true
	stale, err := cloneSite(&site)
	if err != nil {
		t.Fatal(err)
	}
	site.Domains = nil
	site.Advanced.Certificate.ACME.Domains = nil
	if err := store.UpdateSite(context.Background(), &site); err != nil {
		t.Fatal(err)
	}
	issuer := &renewingACMEIssuer{}
	h.ACMEIssuer = issuer
	worker := &acmeRenewalWorker{handler: h, renewBefore: defaultACMERenewBefore}
	if err := worker.scanSite(context.Background(), stale); err == nil {
		t.Fatal("renewal accepted a current site without any domains")
	}
	if issuer.calls != 0 {
		t.Fatalf("issuer calls = %d, want 0 after domains were removed", issuer.calls)
	}
	current, err := store.GetSite(context.Background(), site.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(current.Domains) != 0 || current.Advanced.Certificate.ACME.LastStatus != "renew_failed" {
		t.Fatalf("renewal failure did not preserve current site state: %+v", current)
	}
}
