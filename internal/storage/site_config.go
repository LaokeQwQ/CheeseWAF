package storage

import (
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

func SiteFromConfig(site config.SiteConfig) Site {
	upstreams := make([]string, 0, len(site.Upstreams))
	for _, upstream := range site.Upstreams {
		upstreams = append(upstreams, upstream.Address)
	}
	return Site{
		ID:          site.ID,
		Name:        site.Name,
		Domains:     site.Domains,
		Upstreams:   upstreams,
		ListenPort:  site.ListenPort,
		LoadBalance: site.LoadBalance,
		EnableSSL:   site.EnableSSL,
		CertFile:    site.CertFile,
		KeyFile:     site.KeyFile,
		WAFEnabled:  site.WAF.Enabled,
		WAFMode:     site.WAF.Mode,
		Enabled:     site.Enabled,
		Advanced: SiteAdvanced{
			Certificate: CertificateConfig{
				Mode:          site.Certificate.Mode,
				CertPEM:       site.Certificate.CertPEM,
				KeyPEM:        site.Certificate.KeyPEM,
				AutoRenew:     site.Certificate.AutoRenew,
				ForceHTTPS:    site.Certificate.ForceHTTPS,
				HSTS:          site.Certificate.HSTS,
				MinTLSVersion: site.Certificate.MinTLSVersion,
				ACME: SiteACMEConfig{
					ProviderID:    site.Certificate.ACME.ProviderID,
					DNSAPI:        site.Certificate.ACME.DNSAPI,
					AccountEmail:  site.Certificate.ACME.AccountEmail,
					Server:        site.Certificate.ACME.Server,
					KeyType:       site.Certificate.ACME.KeyType,
					ACMESHPath:    site.Certificate.ACME.ACMESHPath,
					Home:          site.Certificate.ACME.Home,
					CertDir:       site.Certificate.ACME.CertDir,
					ReloadCommand: site.Certificate.ACME.ReloadCommand,
					Domains:       cloneStrings(site.Certificate.ACME.Domains),
					Env:           cloneStringMap(site.Certificate.ACME.Env),
					Notify:        site.Certificate.ACME.Notify,
				},
			},
			Origin: OriginConfig{
				ProxyTimeout:  site.WAF.Performance.ProxyTimeout.String(),
				MaxBodyBytes:  site.WAF.Performance.MaxBodyBytes,
				MaxHeaderSize: site.WAF.Performance.MaxHeaderBytes,
				Scheme:        "http",
				PassHost:      true,
			},
			Protection: SiteProtectionConfig{
				SemanticSQL:   site.WAF.SemanticEngines.SQL,
				SemanticXSS:   site.WAF.SemanticEngines.XSS,
				SemanticRCE:   site.WAF.SemanticEngines.RCE,
				SemanticLFI:   site.WAF.SemanticEngines.LFI,
				SemanticXXE:   site.WAF.SemanticEngines.XXE,
				SemanticSSRF:  site.WAF.SemanticEngines.SSRF,
				SemanticNoSQL: site.WAF.SemanticEngines.NoSQL,
				SemanticSSTI:  site.WAF.SemanticEngines.SSTI,
			},
			SemanticPolicy: SiteSemanticPolicy{
				BudgetExhaustedPolicy: site.WAF.SemanticPolicy.BudgetExhaustedPolicy,
				PathAllowlist:         cloneStrings(site.WAF.SemanticPolicy.PathAllowlist),
				ParamAllowlist:        cloneStrings(site.WAF.SemanticPolicy.ParamAllowlist),
			},
			Policy: SiteProtectionPolicy{
				WebAttack:   site.WAF.ProtectionPolicy.WebAttack,
				APISecurity: site.WAF.ProtectionPolicy.APISecurity,
				BotCC:       site.WAF.ProtectionPolicy.BotCC,
				ThreatIntel: site.WAF.ProtectionPolicy.ThreatIntel,
			},
			Response: SiteResponseConfig{
				Enabled:           site.WAF.Response.Enabled,
				MaxBodyBytes:      site.WAF.Response.MaxBodyBytes,
				SensitivePatterns: site.WAF.Response.SensitivePatterns,
			},
			HealthCheck: SiteHealthCheckConfig{
				Enabled:            site.WAF.HealthCheck.Enabled,
				Path:               site.WAF.HealthCheck.Path,
				Interval:           site.WAF.HealthCheck.Interval.String(),
				Timeout:            site.WAF.HealthCheck.Timeout.String(),
				HealthyThreshold:   site.WAF.HealthCheck.HealthyThreshold,
				UnhealthyThreshold: site.WAF.HealthCheck.UnhealthyThreshold,
			},
			AccessControl: SiteAccessControl{
				AuthEnabled:  site.WAF.AccessControl.AuthEnabled,
				WaitingRoom:  site.WAF.AccessControl.WaitingRoom,
				DynamicGuard: site.WAF.AccessControl.DynamicGuard,
				TrustedCIDRs: cloneStrings(site.WAF.AccessControl.TrustedCIDRs),
			},
			AccessLogEnabled: cloneBoolPtr(site.WAF.AccessLogEnabled),
		},
	}
}

func SiteToConfig(site Site) config.SiteConfig {
	upstreams := make([]config.UpstreamConfig, 0, len(site.Upstreams))
	for _, upstream := range site.Upstreams {
		upstreams = append(upstreams, config.UpstreamConfig{Address: upstream, Weight: 1})
	}
	mode := site.WAFMode
	if mode == "" {
		mode = "block"
	}
	timeout := parseDuration(site.Advanced.Origin.ProxyTimeout, 30*time.Second)
	return config.SiteConfig{
		ID:          site.ID,
		Name:        site.Name,
		Domains:     site.Domains,
		Upstreams:   upstreams,
		ListenPort:  site.ListenPort,
		LoadBalance: site.LoadBalance,
		Enabled:     site.Enabled,
		EnableSSL:   site.EnableSSL,
		CertFile:    site.CertFile,
		KeyFile:     site.KeyFile,
		Certificate: config.SiteCertificateConfig{
			Mode:          site.Advanced.Certificate.Mode,
			CertPEM:       site.Advanced.Certificate.CertPEM,
			KeyPEM:        site.Advanced.Certificate.KeyPEM,
			AutoRenew:     site.Advanced.Certificate.AutoRenew,
			ForceHTTPS:    site.Advanced.Certificate.ForceHTTPS,
			HSTS:          site.Advanced.Certificate.HSTS,
			MinTLSVersion: site.Advanced.Certificate.MinTLSVersion,
			ACME: config.SiteACMEConfig{
				ProviderID:    site.Advanced.Certificate.ACME.ProviderID,
				DNSAPI:        site.Advanced.Certificate.ACME.DNSAPI,
				AccountEmail:  site.Advanced.Certificate.ACME.AccountEmail,
				Server:        site.Advanced.Certificate.ACME.Server,
				KeyType:       site.Advanced.Certificate.ACME.KeyType,
				ACMESHPath:    site.Advanced.Certificate.ACME.ACMESHPath,
				Home:          site.Advanced.Certificate.ACME.Home,
				CertDir:       site.Advanced.Certificate.ACME.CertDir,
				ReloadCommand: site.Advanced.Certificate.ACME.ReloadCommand,
				Domains:       cloneStrings(site.Advanced.Certificate.ACME.Domains),
				Env:           cloneStringMap(site.Advanced.Certificate.ACME.Env),
				Notify:        site.Advanced.Certificate.ACME.Notify,
			},
		},
		WAF: config.WAFConfig{
			Enabled:          site.WAFEnabled,
			Mode:             mode,
			AccessLogEnabled: cloneBoolPtr(site.Advanced.AccessLogEnabled),
			SemanticEngines: config.SemanticEngineSwitches{
				SQL:   site.Advanced.Protection.SemanticSQL,
				XSS:   site.Advanced.Protection.SemanticXSS,
				RCE:   site.Advanced.Protection.SemanticRCE,
				LFI:   site.Advanced.Protection.SemanticLFI,
				XXE:   site.Advanced.Protection.SemanticXXE,
				SSRF:  site.Advanced.Protection.SemanticSSRF,
				NoSQL: site.Advanced.Protection.SemanticNoSQL,
				SSTI:  site.Advanced.Protection.SemanticSSTI,
			},
			SemanticPolicy: config.SemanticPolicyConfig{
				BudgetExhaustedPolicy: site.Advanced.SemanticPolicy.BudgetExhaustedPolicy,
				PathAllowlist:         cloneStrings(site.Advanced.SemanticPolicy.PathAllowlist),
				ParamAllowlist:        cloneStrings(site.Advanced.SemanticPolicy.ParamAllowlist),
			},
			ProtectionPolicy: config.ProtectionPolicyConfig{
				WebAttack:   site.Advanced.Policy.WebAttack,
				APISecurity: site.Advanced.Policy.APISecurity,
				BotCC:       site.Advanced.Policy.BotCC,
				ThreatIntel: site.Advanced.Policy.ThreatIntel,
			},
			Performance: config.PerformanceTuningConfig{
				MaxBodyBytes:   site.Advanced.Origin.MaxBodyBytes,
				MaxHeaderBytes: site.Advanced.Origin.MaxHeaderSize,
				ProxyTimeout:   timeout,
			},
			Response: config.ResponseInspectionConfig{
				Enabled:           site.Advanced.Response.Enabled,
				MaxBodyBytes:      site.Advanced.Response.MaxBodyBytes,
				SensitivePatterns: site.Advanced.Response.SensitivePatterns,
			},
			HealthCheck: config.HealthCheckConfig{
				Enabled:            site.Advanced.HealthCheck.Enabled,
				Path:               site.Advanced.HealthCheck.Path,
				Interval:           parseDuration(site.Advanced.HealthCheck.Interval, 30*time.Second),
				Timeout:            parseDuration(site.Advanced.HealthCheck.Timeout, 3*time.Second),
				HealthyThreshold:   site.Advanced.HealthCheck.HealthyThreshold,
				UnhealthyThreshold: site.Advanced.HealthCheck.UnhealthyThreshold,
			},
			Rewrite: siteRewriteToConfig(site.Advanced.Rewrite),
			AccessControl: config.SiteAccessControlConfig{
				AuthEnabled:  site.Advanced.AccessControl.AuthEnabled,
				WaitingRoom:  site.Advanced.AccessControl.WaitingRoom,
				DynamicGuard: site.Advanced.AccessControl.DynamicGuard,
				TrustedCIDRs: cloneStrings(site.Advanced.AccessControl.TrustedCIDRs),
			},
		},
	}
}

func SitesToConfig(sites []Site) []config.SiteConfig {
	out := make([]config.SiteConfig, 0, len(sites))
	for _, site := range sites {
		out = append(out, SiteToConfig(site))
	}
	return out
}

func siteRewriteToConfig(rules []SiteRewriteRule) []config.RewriteRuleConfig {
	out := make([]config.RewriteRuleConfig, 0, len(rules))
	for _, rule := range rules {
		out = append(out, config.RewriteRuleConfig{
			ID:           rule.ID,
			Pattern:      rule.Pattern,
			Replacement:  rule.Replacement,
			RedirectCode: rule.RedirectCode,
			Enabled:      rule.Enabled,
		})
	}
	return out
}

func cloneStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	out := make([]string, len(values))
	copy(out, values)
	return out
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

func parseDuration(value string, fallback time.Duration) time.Duration {
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}

func cloneBoolPtr(value *bool) *bool {
	if value == nil {
		return nil
	}
	copied := *value
	return &copied
}
