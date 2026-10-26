package storage

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

// The pre-0.4.5 SiteFromConfig writer always persisted false module switches
// and origin.scheme=http, although SiteToConfig did not read those fields.
const legacyStoredSiteAdvanced = `{
	"certificate":{"mode":"file"},
	"origin":{"scheme":"http","pass_host":true,"proxy_timeout":"30s"},
	"protection":{"bot":false,"ratelimit":false,"acl":false,"apisec":false,"semantic_sql":true}
}`

func TestLegacyStoredSiteInheritsProtection(t *testing.T) {
	site := loadStoredSiteFixture(t, legacyStoredSiteAdvanced, "https://origin.example.test:8443")
	converted := SiteToConfig(site)
	for name, value := range map[string]*bool{
		"bot": converted.WAF.BotEnabled, "ratelimit": converted.WAF.RateLimitEnabled,
		"acl": converted.WAF.ACLEnabled, "apisec": converted.WAF.APISecurityEnabled,
	} {
		if value != nil {
			t.Errorf("legacy %s override = %v, want nil to inherit either global value", name, *value)
		}
	}
}

func TestLegacyStoredSitePreservesSecureUpstreamTransport(t *testing.T) {
	site := loadStoredSiteFixture(t, legacyStoredSiteAdvanced, "https://origin.example.test:8443")
	if got := SiteToConfig(site).OriginScheme; got != "https" {
		t.Fatalf("legacy secure upstream transport = %q, want https", got)
	}
}

func TestLegacyStoredSitePreservesMixedUpstreamTransports(t *testing.T) {
	for _, insecure := range []string{"http://plain.example.test:8080", "plain.example.test:8080"} {
		site := loadStoredSiteFixture(t, legacyStoredSiteAdvanced, "https://secure.example.test:8443", insecure)
		if got := SiteToConfig(site).OriginScheme; got != "" {
			t.Fatalf("mixed upstream transport override = %q, want empty to retain each URL transport", got)
		}
	}
}

func TestModernStoredSitePreservesExplicitProtectionAndOriginOverrides(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		raw := `{"websocket_enabled":false,"grpc_enabled":false,"origin":{"scheme":"http"},"protection":{"bot":false,"ratelimit":false,"acl":false,"apisec":false}}`
		if enabled {
			raw = `{"websocket_enabled":false,"grpc_enabled":false,"origin":{"scheme":"http"},"protection":{"bot":true,"ratelimit":true,"acl":true,"apisec":true}}`
		}
		site := loadStoredSiteFixture(t, raw, "https://origin.example.test:8443")
		converted := SiteToConfig(site)
		for name, value := range map[string]*bool{
			"bot": converted.WAF.BotEnabled, "ratelimit": converted.WAF.RateLimitEnabled,
			"acl": converted.WAF.ACLEnabled, "apisec": converted.WAF.APISecurityEnabled,
		} {
			if value == nil || *value != enabled {
				t.Errorf("modern %s override = %v, want %v", name, value, enabled)
			}
		}
		if converted.OriginScheme != "http" {
			t.Fatalf("modern explicit origin transport = %q, want http", converted.OriginScheme)
		}
	}
}

func TestVersionedStoredSitePreservesExplicitOverridesWithoutProtocolFields(t *testing.T) {
	raw := `{"schema_version":1,"origin":{"scheme":"http"},"protection":{"bot":false,"ratelimit":false,"acl":false,"apisec":false}}`
	converted := SiteToConfig(loadStoredSiteFixture(t, raw, "https://origin.example.test:8443"))
	if converted.WAF.BotEnabled == nil || *converted.WAF.BotEnabled || converted.OriginScheme != "http" {
		t.Fatalf("versioned overrides changed: bot=%v scheme=%q", converted.WAF.BotEnabled, converted.OriginScheme)
	}
}

func TestStoredSiteWithOneProtocolFieldPreservesModernOverrides(t *testing.T) {
	for _, protocol := range []string{"websocket_enabled", "grpc_enabled"} {
		raw := `{"` + protocol + `":false,"origin":{"scheme":"http"},"protection":{"bot":false}}`
		converted := SiteToConfig(loadStoredSiteFixture(t, raw, "https://origin.example.test:8443"))
		if converted.WAF.BotEnabled == nil || *converted.WAF.BotEnabled || converted.OriginScheme != "http" {
			t.Fatalf("modern row with %s changed: bot=%v scheme=%q", protocol, converted.WAF.BotEnabled, converted.OriginScheme)
		}
	}
}

func TestLegacyStoredSiteRetainsInheritanceAfterReserialization(t *testing.T) {
	site := loadStoredSiteFixture(t, legacyStoredSiteAdvanced, "https://origin.example.test:8443")
	raw, err := json.Marshal(site.Advanced)
	if err != nil {
		t.Fatal(err)
	}
	site.Advanced = decodeSiteAdvanced(string(raw))
	converted := SiteToConfig(site)
	if converted.WAF.BotEnabled != nil || converted.WAF.RateLimitEnabled != nil || converted.WAF.ACLEnabled != nil || converted.WAF.APISecurityEnabled != nil || converted.OriginScheme != "https" {
		t.Fatalf("reserialization changed legacy runtime behavior: %+v", converted)
	}
}

func TestSiteAPIJSONPreservesExplicitOverridesWithoutProtocolFields(t *testing.T) {
	var site Site
	if err := json.Unmarshal([]byte(`{"upstreams":["https://origin.example.test:8443"],"advanced":{"origin":{"scheme":"http"},"protection":{"bot":false,"ratelimit":false,"acl":false,"apisec":false}}}`), &site); err != nil {
		t.Fatal(err)
	}
	converted := SiteToConfig(site)
	if converted.WAF.BotEnabled == nil || *converted.WAF.BotEnabled || converted.OriginScheme != "http" {
		t.Fatalf("API overrides changed: bot=%v scheme=%q", converted.WAF.BotEnabled, converted.OriginScheme)
	}
}

func TestSiteConfigRoundTripPreservesInheritedProtection(t *testing.T) {
	converted := SiteToConfig(SiteFromConfig(config.SiteConfig{}))
	for name, value := range map[string]*bool{
		"bot": converted.WAF.BotEnabled, "ratelimit": converted.WAF.RateLimitEnabled,
		"acl": converted.WAF.ACLEnabled, "apisec": converted.WAF.APISecurityEnabled,
	} {
		if value != nil {
			t.Errorf("inherited %s override = %v, want nil", name, *value)
		}
	}
}

func loadStoredSiteFixture(t *testing.T, rawAdvanced string, upstreams ...string) Site {
	t.Helper()
	store, err := OpenSQLite(filepath.Join(t.TempDir(), "legacy-site.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	ctx := context.Background()
	if err := store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	site := Site{ID: "legacy-site", Name: "legacy-site", Upstreams: upstreams, WAFEnabled: true, WAFMode: "block"}
	if err := store.CreateSite(ctx, &site); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE sites SET advanced=? WHERE id=?`, rawAdvanced, site.ID); err != nil {
		t.Fatal(err)
	}
	stored, err := store.GetSite(ctx, site.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored == nil {
		t.Fatal("stored site is missing")
	}
	return *stored
}

func TestSiteConfigRoundTripPreservesNoSQLSemanticSwitch(t *testing.T) {
	original := config.SiteConfig{
		ID:        "site-a",
		Name:      "site-a",
		Enabled:   true,
		Domains:   []string{"example.test"},
		Upstreams: []config.UpstreamConfig{{Address: "127.0.0.1:9000", Weight: 1}},
		WAF: config.WAFConfig{
			Enabled:       true,
			Mode:          "block",
			ParanoiaLevel: 3,
			Rewrite: []config.RewriteRuleConfig{{
				ID: "rewrite-1", Pattern: "^/old$", Replacement: "/new", RedirectCode: 308, Enabled: true,
			}},
			SemanticEngines: config.SemanticEngineSwitches{
				NoSQL: true,
				SSTI:  true,
			},
			SemanticPolicy: config.SemanticPolicyConfig{
				BudgetExhaustedPolicy: "closed",
				DecodeDepth:           8,
				PathAllowlist:         []string{"/health", "/static/*"},
				ParamAllowlist:        []string{"content"},
				PromoteSeconds:        45,
				AutoAgree:             true,
				FingerprintDeny:       []string{"aabbccddeeff0011"},
			},
			CustomRules: []config.CustomRuleConfig{{
				ID: "review-1", Name: "block payload", Pattern: `eval\(`, Location: "body", Action: "block", Severity: "high", Enabled: true, Priority: 10,
			}},
		},
	}
	site := SiteFromConfig(original)
	if !site.Advanced.Protection.SemanticNoSQL {
		t.Fatalf("expected storage site to preserve NoSQL semantic switch: %+v", site.Advanced.Protection)
	}
	if !site.Advanced.Protection.SemanticSSTI {
		t.Fatalf("expected storage site to preserve SSTI semantic switch: %+v", site.Advanced.Protection)
	}
	if site.ParanoiaLevel != 3 {
		t.Fatalf("expected storage site to preserve paranoia level 3, got %d", site.ParanoiaLevel)
	}
	if site.Advanced.SemanticPolicy.BudgetExhaustedPolicy != "closed" {
		t.Fatalf("expected budget policy closed, got %+v", site.Advanced.SemanticPolicy)
	}
	if site.Advanced.SemanticPolicy.DecodeDepth != 8 {
		t.Fatalf("expected decode depth 8, got %+v", site.Advanced.SemanticPolicy)
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
	if converted.WAF.ParanoiaLevel != 3 {
		t.Fatalf("expected paranoia level to round-trip, got %d", converted.WAF.ParanoiaLevel)
	}
	if converted.WAF.SemanticPolicy.BudgetExhaustedPolicy != "closed" {
		t.Fatalf("expected semantic policy round-trip: %+v", converted.WAF.SemanticPolicy)
	}
	if converted.WAF.SemanticPolicy.DecodeDepth != 8 {
		t.Fatalf("expected decode depth round-trip: %+v", converted.WAF.SemanticPolicy)
	}
	if len(converted.WAF.SemanticPolicy.PathAllowlist) != 2 {
		t.Fatalf("expected path allowlist round-trip: %+v", converted.WAF.SemanticPolicy)
	}
	if len(converted.WAF.CustomRules) != 1 || converted.WAF.CustomRules[0].ID != "review-1" {
		t.Fatalf("expected custom rules round-trip: %+v", converted.WAF.CustomRules)
	}
	if len(converted.WAF.Rewrite) != 1 || converted.WAF.Rewrite[0].Replacement != "/new" || converted.WAF.Rewrite[0].RedirectCode != 308 {
		t.Fatalf("expected rewrite rules round-trip: %+v", converted.WAF.Rewrite)
	}
	if converted.WAF.SemanticPolicy.PromoteSeconds != 45 || !converted.WAF.SemanticPolicy.AutoAgree {
		t.Fatalf("expected promote/auto-agree round-trip: %+v", converted.WAF.SemanticPolicy)
	}
	if len(converted.WAF.SemanticPolicy.FingerprintDeny) != 1 || converted.WAF.SemanticPolicy.FingerprintDeny[0] != "aabbccddeeff0011" {
		t.Fatalf("expected fingerprint deny round-trip: %+v", converted.WAF.SemanticPolicy)
	}
}

func TestSiteConfigRoundTripPreservesOriginSettings(t *testing.T) {
	passHost := false
	original := config.SiteConfig{
		ID:           "site-origin",
		Name:         "site-origin",
		OriginScheme: "https",
		PassHost:     &passHost,
		HostHeader:   "origin.example.test",
	}

	stored := SiteFromConfig(original)
	if stored.Advanced.Origin.Scheme != "https" || stored.Advanced.Origin.PassHost || stored.Advanced.Origin.HostHeader != original.HostHeader {
		t.Fatalf("origin settings not mapped to storage: %+v", stored.Advanced.Origin)
	}
	converted := SiteToConfig(stored)
	if converted.OriginScheme != original.OriginScheme || converted.PassHost == nil || *converted.PassHost != *original.PassHost || converted.HostHeader != original.HostHeader {
		t.Fatalf("origin settings did not round trip: scheme=%q pass_host=%v host_header=%q", converted.OriginScheme, converted.PassHost, converted.HostHeader)
	}

	defaults := SiteFromConfig(config.SiteConfig{})
	if defaults.Advanced.Origin.Scheme != "http" || !defaults.Advanced.Origin.PassHost {
		t.Fatalf("origin defaults not applied: %+v", defaults.Advanced.Origin)
	}
	if got := SiteToConfig(Site{}).OriginScheme; got != "http" {
		t.Fatalf("storage origin scheme default not applied: %q", got)
	}
	secure := SiteToConfig(Site{Upstreams: []string{"https://origin.example.test"}})
	if secure.OriginScheme != "https" {
		t.Fatalf("storage conversion downgraded secure upstream to %q", secure.OriginScheme)
	}
}

func TestSiteFromConfigInfersOriginSchemeFromUpstream(t *testing.T) {
	for _, test := range []struct {
		name    string
		address string
		want    string
	}{
		{name: "https URL", address: "https://origin.example.test:8443", want: "https"},
		{name: "secure websocket URL", address: "wss://origin.example.test:8443", want: "https"},
		{name: "unqualified host", address: "origin.example.test:8080", want: "http"},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := SiteFromConfig(config.SiteConfig{Upstreams: []config.UpstreamConfig{{Address: test.address}}})
			if got.Advanced.Origin.Scheme != test.want {
				t.Fatalf("inferred origin scheme = %q, want %q", got.Advanced.Origin.Scheme, test.want)
			}
		})
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

func TestSiteConfigRoundTripPreservesTrustedProxyProviderBindings(t *testing.T) {
	original := config.SiteConfig{
		ID:        "site-proxy",
		Name:      "site-proxy",
		Enabled:   true,
		Domains:   []string{"example.test"},
		Upstreams: []config.UpstreamConfig{{Address: "127.0.0.1:9000", Weight: 1}},
		WAF: config.WAFConfig{
			Enabled: true,
			Mode:    "block",
			AccessControl: config.SiteAccessControlConfig{
				TrustedCIDRs: []string{"10.0.0.0/8"},
				TrustedProxyProviders: map[string][]string{
					"cloudflare": {"198.51.100.0/24"},
				},
			},
		},
	}

	site := SiteFromConfig(original)
	original.WAF.AccessControl.TrustedProxyProviders["cloudflare"][0] = "192.0.2.0/24"
	if got := site.Advanced.AccessControl.TrustedProxyProviders["cloudflare"][0]; got != "198.51.100.0/24" {
		t.Fatalf("storage conversion must clone provider CIDRs, got %q", got)
	}

	converted := SiteToConfig(site)
	site.Advanced.AccessControl.TrustedProxyProviders["cloudflare"][0] = "203.0.113.0/24"
	if got := converted.WAF.AccessControl.TrustedProxyProviders["cloudflare"][0]; got != "198.51.100.0/24" {
		t.Fatalf("config conversion must clone provider CIDRs, got %q", got)
	}
}

func TestSiteConfigRoundTripPreservesTamperSnapshots(t *testing.T) {
	capturedAt := time.Unix(100, 0).UTC()
	original := config.SiteConfig{
		ID: "site-tamper", Name: "site-tamper", Enabled: true,
		Domains: []string{"example.test"}, Upstreams: []config.UpstreamConfig{{Address: "127.0.0.1:9000", Weight: 1}},
		WAF: config.WAFConfig{
			Enabled: true, Mode: "block",
			Response: config.ResponseInspectionConfig{
				Enabled: true, MaxBodyBytes: 1024, TamperKey: "01234567890123456789012345678901",
				Inspection: config.ResponseInspectionPolicy{FailMode: config.ResponseFailModeClosed},
				TamperSnapshots: []config.TamperSnapshotConfig{{
					URL: "/index.html", MAC: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", Size: 5, CapturedAt: capturedAt,
				}},
			},
		},
	}

	stored := SiteFromConfig(original)
	original.WAF.Response.TamperSnapshots[0].URL = "/mutated"
	if got := stored.Advanced.Response.TamperSnapshots[0].URL; got != "/index.html" {
		t.Fatalf("storage conversion did not clone snapshots: %q", got)
	}
	if got := stored.Advanced.Response.Inspection.FailMode; got != config.ResponseFailModeClosed {
		t.Fatalf("stored fail_mode = %q, want %q", got, config.ResponseFailModeClosed)
	}
	converted := SiteToConfig(stored)
	stored.Advanced.Response.TamperSnapshots[0].URL = "/changed-again"
	if got := converted.WAF.Response.TamperSnapshots[0]; got.URL != "/index.html" || got.CapturedAt != capturedAt {
		t.Fatalf("tamper snapshot did not round trip: %+v", got)
	}
	if converted.WAF.Response.TamperKey != original.WAF.Response.TamperKey {
		t.Fatal("tamper key did not round trip")
	}
	if got := converted.WAF.Response.Inspection.FailMode; got != config.ResponseFailModeClosed {
		t.Fatalf("fail_mode round trip = %q, want %q", got, config.ResponseFailModeClosed)
	}
}

// Storage must not invent a fail mode when the config never set one: the
// default lives in internal/config.NormalizeResponseFailMode, and a stored
// default would make an operator's unset value indistinguishable from an
// explicit choice.
func TestSiteConfigRoundTripPreservesUnsetResponseFailMode(t *testing.T) {
	original := config.SiteConfig{
		ID: "site-response-default", Name: "site-response-default", Enabled: true,
		Domains: []string{"example.test"}, Upstreams: []config.UpstreamConfig{{Address: "127.0.0.1:9000", Weight: 1}},
		WAF: config.WAFConfig{
			Enabled: true, Mode: "block",
			Response: config.ResponseInspectionConfig{Enabled: true, MaxBodyBytes: 1024},
		},
	}

	stored := SiteFromConfig(original)
	if got := stored.Advanced.Response.Inspection.FailMode; got != "" {
		t.Fatalf("storage filled fail_mode = %q, want empty", got)
	}
	converted := SiteToConfig(stored)
	if got := converted.WAF.Response.Inspection.FailMode; got != "" {
		t.Fatalf("config read back fail_mode = %q, want empty", got)
	}
}

// A console site edit rewrites the whole config document from storage
// (internal/api/handler/site.go). If the semantic action policy is not
// persisted, editing any unrelated site field silently drops the operator's
// waf.semantic_policy.action_thresholds and route_overrides.
func TestSiteConfigRoundTripPreservesSemanticActionPolicy(t *testing.T) {
	original := config.SiteConfig{
		ID:      "site-policy",
		Name:    "site-policy",
		Domains: []string{"policy.example"},
		WAF: config.WAFConfig{
			Enabled: true,
			Mode:    "block",
			SemanticPolicy: config.SemanticPolicyConfig{
				ActionThresholds: config.SemanticActionThresholds{Block: 0.92, Challenge: 0.85, Log: 0.65},
				RouteOverrides: []config.SemanticRouteOverride{
					{Path: `^/search$`, Params: []string{"q"}, Block: 0.97, Challenge: 0.90},
					{Path: `^/legacy/report$`, Action: config.SemanticActionObserve},
				},
			},
		},
	}

	stored := SiteFromConfig(original)
	if stored.Advanced.SemanticPolicy.ActionThresholds == nil {
		t.Fatalf("action_thresholds were not persisted: %+v", stored.Advanced.SemanticPolicy)
	}
	if got := *stored.Advanced.SemanticPolicy.ActionThresholds; got != (SiteSemanticActionThresholds{Block: 0.92, Challenge: 0.85, Log: 0.65}) {
		t.Fatalf("stored action_thresholds = %+v", got)
	}
	if len(stored.Advanced.SemanticPolicy.RouteOverrides) != 2 {
		t.Fatalf("route_overrides were not persisted: %+v", stored.Advanced.SemanticPolicy.RouteOverrides)
	}

	converted := SiteToConfig(stored)
	if got := converted.WAF.SemanticPolicy.ActionThresholds; got != original.WAF.SemanticPolicy.ActionThresholds {
		t.Fatalf("action_thresholds round trip = %+v, want %+v", got, original.WAF.SemanticPolicy.ActionThresholds)
	}
	if len(converted.WAF.SemanticPolicy.RouteOverrides) != 2 {
		t.Fatalf("route_overrides round trip = %+v", converted.WAF.SemanticPolicy.RouteOverrides)
	}
	search := converted.WAF.SemanticPolicy.RouteOverrides[0]
	if search.Path != `^/search$` || len(search.Params) != 1 || search.Params[0] != "q" || search.Block != 0.97 || search.Challenge != 0.90 {
		t.Fatalf("search override round trip = %+v", search)
	}
	observe := converted.WAF.SemanticPolicy.RouteOverrides[1]
	if observe.Path != `^/legacy/report$` || observe.Action != config.SemanticActionObserve || len(observe.Params) != 0 {
		t.Fatalf("observe override round trip = %+v", observe)
	}

	// The params slice must be a copy: mutating the stored site afterwards must
	// not reach back into the source config (and vice versa).
	stored.Advanced.SemanticPolicy.RouteOverrides[0].Params[0] = "mutated"
	if original.WAF.SemanticPolicy.RouteOverrides[0].Params[0] != "q" {
		t.Fatal("stored params alias the source config slice")
	}
	original.WAF.SemanticPolicy.RouteOverrides[0].Params[0] = "source-mutated"
	if got := SiteFromConfig(original).Advanced.SemanticPolicy.RouteOverrides[0].Params[0]; got != "source-mutated" {
		t.Fatalf("config params did not reach storage: %q", got)
	}
	if stored.Advanced.SemanticPolicy.RouteOverrides[0].Params[0] != "mutated" {
		t.Fatal("previously stored params changed when the source config was mutated")
	}
}

// An unset ladder must stay unset so a round trip cannot turn "inherit the
// web_attack preset" into an explicit zero threshold.
func TestSiteConfigOmitsUnsetSemanticActionPolicy(t *testing.T) {
	stored := SiteFromConfig(config.SiteConfig{ID: "plain", Name: "plain", Domains: []string{"plain.example"}})
	if stored.Advanced.SemanticPolicy.ActionThresholds != nil {
		t.Fatalf("unset action_thresholds must stay nil: %+v", stored.Advanced.SemanticPolicy.ActionThresholds)
	}
	if stored.Advanced.SemanticPolicy.RouteOverrides != nil {
		t.Fatalf("unset route_overrides must stay nil: %+v", stored.Advanced.SemanticPolicy.RouteOverrides)
	}
	raw, err := json.Marshal(stored.Advanced.SemanticPolicy)
	if err != nil {
		t.Fatalf("marshal stored policy: %v", err)
	}
	for _, key := range []string{"action_thresholds", "route_overrides"} {
		if strings.Contains(string(raw), key) {
			t.Fatalf("unset %s leaked into stored JSON: %s", key, raw)
		}
	}
	converted := SiteToConfig(stored)
	if !converted.WAF.SemanticPolicy.ActionThresholds.IsZero() || len(converted.WAF.SemanticPolicy.RouteOverrides) != 0 {
		t.Fatalf("unset policy must round trip as the preset: %+v", converted.WAF.SemanticPolicy)
	}
}
