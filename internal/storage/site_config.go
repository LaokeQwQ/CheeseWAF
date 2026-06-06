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
		WAFEnabled:  site.WAF.Enabled,
		WAFMode:     site.WAF.Mode,
		Enabled:     site.Enabled,
		Advanced: SiteAdvanced{
			Origin: OriginConfig{
				ProxyTimeout:  site.WAF.Performance.ProxyTimeout.String(),
				MaxBodyBytes:  site.WAF.Performance.MaxBodyBytes,
				MaxHeaderSize: site.WAF.Performance.MaxHeaderBytes,
				Scheme:        "http",
				PassHost:      true,
			},
			Protection: SiteProtectionConfig{
				SemanticSQL:  site.WAF.SemanticEngines.SQL,
				SemanticXSS:  site.WAF.SemanticEngines.XSS,
				SemanticRCE:  site.WAF.SemanticEngines.RCE,
				SemanticLFI:  site.WAF.SemanticEngines.LFI,
				SemanticXXE:  site.WAF.SemanticEngines.XXE,
				SemanticSSRF: site.WAF.SemanticEngines.SSRF,
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
		WAF: config.WAFConfig{
			Enabled: site.WAFEnabled,
			Mode:    mode,
			SemanticEngines: config.SemanticEngineSwitches{
				SQL:  site.Advanced.Protection.SemanticSQL,
				XSS:  site.Advanced.Protection.SemanticXSS,
				RCE:  site.Advanced.Protection.SemanticRCE,
				LFI:  site.Advanced.Protection.SemanticLFI,
				XXE:  site.Advanced.Protection.SemanticXXE,
				SSRF: site.Advanced.Protection.SemanticSSRF,
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
