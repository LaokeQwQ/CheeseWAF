package config

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
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
	adminPublic, err := isPublicAdminListen(cfg.Server.AdminListen)
	if err != nil {
		return fmt.Errorf("server.admin_listen is invalid: %w", err)
	}
	if adminPublic && !cfg.Server.AdminPublic {
		return fmt.Errorf("server.admin_listen %q is public; bind admin to localhost/private access or set server.admin_public with server.admin_tls enabled", cfg.Server.AdminListen)
	}
	if cfg.Server.AdminPublic && adminPublic && !cfg.Server.AdminTLS.Enabled {
		return fmt.Errorf("server.admin_tls.enabled is required when admin listener is public")
	}
	if cfg.Server.AdminTLS.Enabled && (strings.TrimSpace(cfg.Server.AdminTLS.CertFile) == "" || strings.TrimSpace(cfg.Server.AdminTLS.KeyFile) == "") {
		return fmt.Errorf("server.admin_tls.cert_file and server.admin_tls.key_file are required when admin TLS is enabled")
	}
	if cfg.Server.ListenTLS != "" && (cfg.TLS.CertFile == "" || cfg.TLS.KeyFile == "") {
		return fmt.Errorf("tls.cert_file and tls.key_file are required when server.listen_tls is set")
	}
	if cfg.Server.HTTP3.Enabled {
		if cfg.TLS.CertFile == "" || cfg.TLS.KeyFile == "" {
			return fmt.Errorf("tls.cert_file and tls.key_file are required when HTTP/3 is enabled")
		}
		if _, err := net.ResolveUDPAddr("udp", http3ListenAddr(cfg.Server)); err != nil {
			return fmt.Errorf("server.listen_http3 is invalid: %w", err)
		}
	}
	if cfg.Storage.SQLite.Path == "" {
		return fmt.Errorf("storage.sqlite.path is required")
	}
	if cfg.Storage.PostgreSQL.Enabled {
		if strings.TrimSpace(cfg.Storage.PostgreSQL.DSN) == "" {
			return fmt.Errorf("storage.postgresql.dsn is required when PostgreSQL log sink is enabled")
		}
		if err := validateSQLIdentifierPath(cfg.Storage.PostgreSQL.Table); err != nil {
			return fmt.Errorf("storage.postgresql.table is invalid: %w", err)
		}
	}
	if cfg.Storage.Elasticsearch.Enabled {
		if strings.TrimSpace(cfg.Storage.Elasticsearch.Endpoint) == "" {
			return fmt.Errorf("storage.elasticsearch.endpoint is required when Elasticsearch log sink is enabled")
		}
		if _, err := url.ParseRequestURI(cfg.Storage.Elasticsearch.Endpoint); err != nil {
			return fmt.Errorf("storage.elasticsearch.endpoint is invalid: %w", err)
		}
		if strings.TrimSpace(cfg.Storage.Elasticsearch.Index) == "" {
			return fmt.Errorf("storage.elasticsearch.index is required when Elasticsearch log sink is enabled")
		}
	}
	if len(cfg.Sites) == 0 {
		return fmt.Errorf("at least one site is required")
	}
	if err := validateProtectionPolicy("protection.policy", cfg.Protection.Policy, false); err != nil {
		return err
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
		if err := validateProtectionPolicy("site "+site.Name+" waf.protection_policy", site.WAF.ProtectionPolicy, true); err != nil {
			return err
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
	for _, indicator := range cfg.Protection.IP.ThreatIntel {
		if !indicator.Enabled {
			continue
		}
		if strings.TrimSpace(indicator.Value) == "" {
			return fmt.Errorf("threat intel indicator %q must define value", indicator.ID)
		}
		if err := validateIPEntry(indicator.Value); err != nil {
			return fmt.Errorf("invalid threat intel indicator %q: %w", indicator.Value, err)
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
	if cfg.Protection.Bot.Enabled {
		if strings.TrimSpace(cfg.Protection.Bot.CookieName) == "" {
			return fmt.Errorf("bot.cookie_name is required when bot protection is enabled")
		}
		if cfg.Protection.Bot.ChallengeTTL <= 0 {
			return fmt.Errorf("bot.challenge_ttl must be positive")
		}
		if cfg.Protection.Bot.ChallengeDifficulty < 1 || cfg.Protection.Bot.ChallengeDifficulty > 6 {
			return fmt.Errorf("bot.challenge_difficulty must be between 1 and 6")
		}
		if cfg.Protection.Bot.CAPTCHA {
			if cfg.Protection.Bot.AltchaMaxNumber < 1000 || cfg.Protection.Bot.AltchaMaxNumber > 50000000 {
				return fmt.Errorf("bot.altcha_max_number must be between 1000 and 50000000")
			}
			if strings.TrimSpace(cfg.Protection.Bot.AltchaHeaderName) == "" {
				return fmt.Errorf("bot.altcha_header_name is required when captcha is enabled")
			}
		}
		if cfg.Protection.Bot.WaitingRoom && cfg.Protection.Bot.WaitingRoomMaxActive <= 0 {
			return fmt.Errorf("bot.waiting_room_max_active must be positive when waiting room is enabled")
		}
		if cfg.Protection.Bot.WaitingRoom && cfg.Protection.Bot.WaitingRoomTTL <= 0 {
			return fmt.Errorf("bot.waiting_room_ttl must be positive when waiting room is enabled")
		}
	}
	for _, prefix := range append([]string{}, cfg.Protection.Bot.PathPrefixes...) {
		if prefix != "" && !strings.HasPrefix(prefix, "/") {
			return fmt.Errorf("bot path prefix %q must start with /", prefix)
		}
	}
	for _, prefix := range append([]string{}, cfg.Protection.Bot.ExemptPathPrefixes...) {
		if prefix != "" && !strings.HasPrefix(prefix, "/") {
			return fmt.Errorf("bot exempt path prefix %q must start with /", prefix)
		}
	}
	for _, rule := range cfg.Edge.Headers.Rules {
		if !rule.Enabled {
			continue
		}
		if strings.TrimSpace(rule.Header) == "" {
			return fmt.Errorf("edge header rule %q must define header", rule.ID)
		}
		switch strings.ToLower(rule.Operation) {
		case "set", "add", "delete":
		default:
			return fmt.Errorf("edge header rule %q has invalid operation %q", rule.ID, rule.Operation)
		}
	}
	for _, status := range cfg.Edge.Cache.StatusCodes {
		if status < http.StatusOK || status > 599 {
			return fmt.Errorf("edge cache status code %d is invalid", status)
		}
	}
	for _, algorithm := range cfg.Edge.Compression.Algorithms {
		switch strings.ToLower(algorithm) {
		case "gzip", "identity", "none":
		default:
			return fmt.Errorf("edge compression algorithm %q is not supported yet", algorithm)
		}
	}
	if cfg.Monitor.Prometheus.Enabled && !strings.HasPrefix(cfg.Monitor.Prometheus.Path, "/") {
		return fmt.Errorf("monitor.prometheus.path must start with /")
	}
	if cfg.Monitor.RemoteWrite.Enabled {
		if _, err := url.ParseRequestURI(cfg.Monitor.RemoteWrite.Endpoint); err != nil {
			return fmt.Errorf("monitor.remote_write.endpoint is invalid: %w", err)
		}
	}
	for _, rule := range cfg.Monitor.Alerts.Rules {
		if !rule.Enabled {
			continue
		}
		if strings.TrimSpace(rule.ID) == "" || strings.TrimSpace(rule.Metric) == "" {
			return fmt.Errorf("alert rule must define id and metric")
		}
		switch rule.Operator {
		case ">", ">=", "<", "<=", "==", "!=":
		default:
			return fmt.Errorf("alert rule %q has invalid operator %q", rule.ID, rule.Operator)
		}
	}
	for _, notifier := range cfg.Monitor.Notifiers {
		if !notifier.Enabled {
			continue
		}
		switch notifier.Type {
		case "webhook", "email", "telegram", "dingtalk", "wecom":
		default:
			return fmt.Errorf("notifier %q has invalid type %q", notifier.ID, notifier.Type)
		}
	}
	for _, schema := range cfg.APISec.Validation.Schemas {
		if !schema.Enabled {
			continue
		}
		if strings.TrimSpace(schema.PathPattern) == "" {
			return fmt.Errorf("api schema %q must define path_pattern", schema.ID)
		}
		if _, err := regexp.Compile(schema.PathPattern); err != nil {
			return fmt.Errorf("api schema %q has invalid path_pattern: %w", schema.ID, err)
		}
	}
	for _, limit := range cfg.APISec.RateLimits {
		if !limit.Enabled {
			continue
		}
		if limit.Requests <= 0 || limit.Window <= 0 {
			return fmt.Errorf("api rate limit %q must define positive requests and window", limit.ID)
		}
		if _, err := regexp.Compile(limit.PathPattern); err != nil {
			return fmt.Errorf("api rate limit %q has invalid path_pattern: %w", limit.ID, err)
		}
	}
	if cfg.APISec.Auth.Enabled {
		for _, alg := range cfg.APISec.Auth.JWTAlgorithms {
			switch strings.ToUpper(strings.TrimSpace(alg)) {
			case "", "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512":
			case "NONE":
				return fmt.Errorf("api auth jwt_algorithms must not allow none")
			default:
				return fmt.Errorf("api auth jwt_algorithms contains unsupported algorithm %q", alg)
			}
		}
		if len(cfg.APISec.Auth.JWTAlgorithms) > 0 && strings.TrimSpace(cfg.APISec.Auth.JWTSharedSecret) == "" && strings.TrimSpace(cfg.APISec.Auth.JWTPublicKeyFile) == "" && strings.TrimSpace(cfg.APISec.Auth.JWTPublicKeyPEM) == "" && strings.TrimSpace(cfg.APISec.Auth.JWKSFile) == "" && strings.TrimSpace(cfg.APISec.Auth.JWKSJSON) == "" {
			return fmt.Errorf("api auth jwt_algorithms requires jwt_shared_secret, jwt_public_key_file, jwt_public_key_pem, jwks_file, or jwks_json")
		}
		for _, policy := range cfg.APISec.Auth.EndpointPolicies {
			if !policy.Enabled {
				continue
			}
			if strings.TrimSpace(policy.PathPattern) == "" {
				return fmt.Errorf("api auth endpoint policy %q must define path_pattern", policy.ID)
			}
			if _, err := regexp.Compile(policy.PathPattern); err != nil {
				return fmt.Errorf("api auth endpoint policy %q has invalid path_pattern: %w", policy.ID, err)
			}
			if method := strings.ToUpper(strings.TrimSpace(policy.Method)); method != "" {
				switch method {
				case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions:
				default:
					return fmt.Errorf("api auth endpoint policy %q has invalid method %q", policy.ID, policy.Method)
				}
			}
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

func isPublicAdminListen(addr string) (bool, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		if strings.HasPrefix(addr, ":") {
			host = ""
		} else {
			host = addr
		}
	}
	host = strings.Trim(host, "[]")
	if host == "" || host == "0.0.0.0" || host == "::" {
		return true, nil
	}
	if strings.EqualFold(host, "localhost") {
		return false, nil
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return true, nil
	}
	return !ip.IsLoopback(), nil
}

func validateProtectionPolicy(name string, policy ProtectionPolicyConfig, allowEmpty bool) error {
	values := map[string]string{
		"web_attack":   policy.WebAttack,
		"api_security": policy.APISecurity,
		"bot_cc":       policy.BotCC,
		"threat_intel": policy.ThreatIntel,
	}
	for key, value := range values {
		if allowEmpty && value == "" {
			continue
		}
		if !IsProtectionLevel(value) || value == "" {
			return fmt.Errorf("%s.%s has invalid protection level %q", name, key, value)
		}
	}
	return nil
}

func http3ListenAddr(cfg ServerConfig) string {
	if cfg.ListenHTTP3 != "" {
		return cfg.ListenHTTP3
	}
	if cfg.ListenTLS != "" {
		return cfg.ListenTLS
	}
	return ":443"
}

func validateSQLIdentifierPath(value string) error {
	if value == "" {
		return fmt.Errorf("identifier is required")
	}
	parts := strings.Split(value, ".")
	if len(parts) > 2 {
		return fmt.Errorf("only schema.table identifiers are supported")
	}
	ident := regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	for _, part := range parts {
		if !ident.MatchString(part) {
			return fmt.Errorf("%q is not a safe SQL identifier", part)
		}
	}
	return nil
}
