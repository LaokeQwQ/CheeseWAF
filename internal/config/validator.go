package config

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

func Validate(cfg *Config) error {
	if cfg == nil {
		return fmt.Errorf("config is nil")
	}
	if cfg.Server.Listen == "" {
		return fmt.Errorf("server.listen is required")
	}
	if cfg.Server.AdminListen == "" {
		return fmt.Errorf("server.admin_listen is required")
	}
	if cfg.Storage.SQLite.Path == "" {
		return fmt.Errorf("storage.sqlite.path is required")
	}
	if len(cfg.Sites) == 0 {
		return fmt.Errorf("at least one site is required")
	}
	for _, site := range cfg.Sites {
		if !site.Enabled {
			continue
		}
		if site.Name == "" {
			return fmt.Errorf("site.name is required")
		}
		if len(site.Domains) == 0 {
			return fmt.Errorf("site %q must define at least one domain", site.Name)
		}
		if len(site.Upstreams) == 0 {
			return fmt.Errorf("site %q must define at least one upstream", site.Name)
		}
		for _, upstream := range site.Upstreams {
			if strings.TrimSpace(upstream.Address) == "" {
				return fmt.Errorf("site %q has an empty upstream address", site.Name)
			}
		}
		if site.WAF.Mode != "" && site.WAF.Mode != "block" && site.WAF.Mode != "monitor" && site.WAF.Mode != "off" {
			return fmt.Errorf("site %q has invalid waf.mode %q", site.Name, site.WAF.Mode)
		}
		for _, rule := range site.WAF.CustomRules {
			if strings.TrimSpace(rule.Pattern) == "" {
				return fmt.Errorf("site %q has custom rule %q with empty pattern", site.Name, rule.Name)
			}
			if _, err := regexp.Compile(rule.Pattern); err != nil {
				return fmt.Errorf("site %q has invalid custom rule %q: %w", site.Name, rule.Name, err)
			}
		}
		for _, rewrite := range site.WAF.Rewrite {
			if !rewrite.Enabled {
				continue
			}
			if _, err := regexp.Compile(rewrite.Pattern); err != nil {
				return fmt.Errorf("site %q has invalid rewrite rule %q: %w", site.Name, rewrite.ID, err)
			}
		}
	}
	for _, entry := range append([]string{}, cfg.Protection.IP.Blacklist...) {
		if err := validateIPEntry(entry); err != nil {
			return fmt.Errorf("invalid blacklist entry %q: %w", entry, err)
		}
	}
	for _, entry := range append([]string{}, cfg.Protection.IP.Whitelist...) {
		if err := validateIPEntry(entry); err != nil {
			return fmt.Errorf("invalid whitelist entry %q: %w", entry, err)
		}
	}
	for country, cidrs := range cfg.Protection.IP.GeoIP.CountryCIDRs {
		if strings.TrimSpace(country) == "" {
			return fmt.Errorf("geoip country code is required")
		}
		for _, cidr := range cidrs {
			if err := validateIPEntry(cidr); err != nil {
				return fmt.Errorf("invalid geoip cidr %q for %s: %w", cidr, country, err)
			}
		}
	}
	for _, rule := range cfg.Protection.ACL.Rules {
		if !rule.Enabled {
			continue
		}
		if rule.PathPrefix == "" && rule.Method == "" && rule.Header == "" {
			return fmt.Errorf("acl rule %q must define a method, path_prefix, or header", rule.ID)
		}
		if rule.Action != "" && rule.Action != "block" && rule.Action != "log" && rule.Action != "challenge" {
			return fmt.Errorf("acl rule %q has invalid action %q", rule.ID, rule.Action)
		}
	}
	return nil
}

func validateIPEntry(entry string) error {
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return nil
	}
	if strings.Contains(entry, "/") {
		if _, _, err := net.ParseCIDR(entry); err != nil {
			return err
		}
		return nil
	}
	if net.ParseIP(entry) == nil {
		return fmt.Errorf("not an IP or CIDR")
	}
	return nil
}
