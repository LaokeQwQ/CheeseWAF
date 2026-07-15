package storage

import (
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

func TestSiteConfigRoundTripPreservesNoSQLSemanticSwitch(t *testing.T) {
	original := config.SiteConfig{
		ID:        "site-a",
		Name:      "site-a",
		Enabled:   true,
		Domains:   []string{"example.test"},
		Upstreams: []config.UpstreamConfig{{Address: "127.0.0.1:9000", Weight: 1}},
		WAF: config.WAFConfig{
			Enabled: true,
			Mode:    "block",
			SemanticEngines: config.SemanticEngineSwitches{
				NoSQL: true,
				SSTI:  true,
			},
			SemanticPolicy: config.SemanticPolicyConfig{
				BudgetExhaustedPolicy: "closed",
				PathAllowlist:         []string{"/health", "/static/*"},
				ParamAllowlist:        []string{"content"},
			},
		},
	}
	site := SiteFromConfig(original)
	if !site.Advanced.Protection.SemanticNoSQL {
		t.Fatalf("expected storage site to preserve NoSQL semantic switch: %+v", site.Advanced.Protection)
	}
	if !site.Advanced.Protection.SemanticSSTI {
		t.Fatalf("expected storage site to preserve SSTI semantic switch: %+v", site.Advanced.Protection)
	}
	if site.Advanced.SemanticPolicy.BudgetExhaustedPolicy != "closed" {
		t.Fatalf("expected budget policy closed, got %+v", site.Advanced.SemanticPolicy)
	}
	if len(site.Advanced.SemanticPolicy.PathAllowlist) != 2 || site.Advanced.SemanticPolicy.ParamAllowlist[0] != "content" {
		t.Fatalf("expected allowlists preserved: %+v", site.Advanced.SemanticPolicy)
	}
	converted := SiteToConfig(site)
	if !converted.WAF.SemanticEngines.NoSQL {
		t.Fatalf("expected config site to preserve NoSQL semantic switch: %+v", converted.WAF.SemanticEngines)
	}
	if !converted.WAF.SemanticEngines.SSTI {
		t.Fatalf("expected config site to preserve SSTI semantic switch: %+v", converted.WAF.SemanticEngines)
	}
	if converted.WAF.SemanticPolicy.BudgetExhaustedPolicy != "closed" {
		t.Fatalf("expected semantic policy round-trip: %+v", converted.WAF.SemanticPolicy)
	}
	if len(converted.WAF.SemanticPolicy.PathAllowlist) != 2 {
		t.Fatalf("expected path allowlist round-trip: %+v", converted.WAF.SemanticPolicy)
	}
}

func TestSiteConfigRoundTripPreservesACMECertificate(t *testing.T) {
	issuedAt := time.Date(2026, 6, 17, 12, 30, 0, 0, time.UTC)
	original := config.SiteConfig{
		ID:        "site-acme",
		Name:      "site-acme",
		Enabled:   true,
		Domains:   []string{"example.com", "www.example.com"},
		Upstreams: []config.UpstreamConfig{{Address: "127.0.0.1:9000", Weight: 1}},
		EnableSSL: true,
		CertFile:  "/var/lib/cheesewaf/certs/example/fullchain.cer",
		KeyFile:   "/var/lib/cheesewaf/certs/example/site.key",
		Certificate: config.SiteCertificateConfig{
			Mode:          "acme",
			AutoRenew:     true,
			ForceHTTPS:    true,
			HSTS:          true,
			MinTLSVersion: "1.3",
			ACME: config.SiteACMEConfig{
				ProviderID:    "cloudflare",
				DNSAPI:        "dns_cf",
				AccountEmail:  "ops@example.com",
				Server:        "letsencrypt",
				KeyType:       "ec-256",
				ACMESHPath:    "/usr/local/bin/acme.sh",
				Home:          "/var/lib/cheesewaf/acme",
				CertDir:       "/var/lib/cheesewaf/certs/example",
				ReloadCommand: "systemctl reload cheesewaf",
				Domains:       []string{"example.com", "www.example.com"},
				Env:           map[string]string{"CF_TOKEN": "secret"},
				Notify:        true,
			},
		},
		WAF: config.WAFConfig{Enabled: true, Mode: "block"},
	}
	site := SiteFromConfig(original)
	site.Advanced.Certificate.ACME.LastStatus = "issued"
	site.Advanced.Certificate.ACME.LastRunID = "acme-test"
	site.Advanced.Certificate.ACME.LastIssuedAt = issuedAt
	site.Advanced.Certificate.ACME.ExpiresAt = issuedAt.Add(60 * 24 * time.Hour)

	if site.Advanced.Certificate.Mode != "acme" {
		t.Fatalf("expected acme mode, got %q", site.Advanced.Certificate.Mode)
	}
	if site.Advanced.Certificate.ACME.Env["CF_TOKEN"] != "secret" {
		t.Fatalf("expected acme env to round trip into storage: %+v", site.Advanced.Certificate.ACME)
	}

	converted := SiteToConfig(site)
	if converted.Certificate.Mode != "acme" {
		t.Fatalf("expected config acme mode, got %q", converted.Certificate.Mode)
	}
	if converted.Certificate.ACME.ProviderID != "cloudflare" || converted.Certificate.ACME.DNSAPI != "dns_cf" {
		t.Fatalf("expected acme provider metadata: %+v", converted.Certificate.ACME)
	}
	if converted.Certificate.ACME.ACMESHPath != "/usr/local/bin/acme.sh" {
		t.Fatalf("expected acme.sh path to round trip: %+v", converted.Certificate.ACME)
	}
	if converted.Certificate.ACME.Env["CF_TOKEN"] != "secret" {
		t.Fatalf("expected acme env to round trip back to config: %+v", converted.Certificate.ACME.Env)
	}
	if !converted.Certificate.AutoRenew || !converted.Certificate.ForceHTTPS || !converted.Certificate.HSTS {
		t.Fatalf("expected TLS policy flags preserved: %+v", converted.Certificate)
	}
}
