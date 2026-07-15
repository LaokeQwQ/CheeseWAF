package config

import (
	"encoding/hex"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/netguard"
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
	if cfg.Server.ListenTLS != "" && !hasAnyTLSCertificate(cfg) {
		return fmt.Errorf("tls.cert_file/key_file or at least one site certificate is required when server.listen_tls is set")
	}
	if cfg.Server.HTTP3.Enabled {
		if !hasAnyTLSCertificate(cfg) {
			return fmt.Errorf("tls.cert_file/key_file or at least one site certificate is required when HTTP/3 is enabled")
		}
		if _, err := net.ResolveUDPAddr("udp", http3ListenAddr(cfg.Server)); err != nil {
			return fmt.Errorf("server.listen_http3 is invalid: %w", err)
		}
	}
	if cfg.Storage.SQLite.Path == "" {
		return fmt.Errorf("storage.sqlite.path is required")
	}
	if err := validateCluster(cfg); err != nil {
		return err
	}
	if cfg.Console.Login.CAPTCHA.Enabled {
		switch strings.ToLower(strings.TrimSpace(cfg.Console.Login.CAPTCHA.Mode)) {
		case "", "slider", "pow":
		default:
			return fmt.Errorf("console.login.captcha.mode must be slider or pow")
		}
		if cfg.Console.Login.CAPTCHA.MaxNumber < 1000 || cfg.Console.Login.CAPTCHA.MaxNumber > 50000000 {
			return fmt.Errorf("console.login.captcha.max_number must be between 1000 and 50000000")
		}
		if cfg.Console.Login.CAPTCHA.TTL < 30*time.Second || cfg.Console.Login.CAPTCHA.TTL > 10*time.Minute {
			return fmt.Errorf("console.login.captcha.ttl must be between 30s and 10m")
		}
		if err := validateSliderCAPTCHA(cfg.Console.Login.CAPTCHA.Slider); err != nil {
			return err
		}
	}
	if err := validateSecurityEntry(cfg.Console.Login.SecurityEntry); err != nil {
		return err
	}
	if err := validateLoginBackground(cfg.Console.Login.Background); err != nil {
		return err
	}
	if err := validateConsoleMap(cfg.Console.Map); err != nil {
		return err
	}
	if err := validateCAPTCHAAssets(cfg.CAPTCHAAssets); err != nil {
		return err
	}
	if err := validateBlockPage(cfg.BlockPage); err != nil {
		return err
	}
	if err := validateBotProtection(cfg.Protection.Bot); err != nil {
		return err
	}
	if err := validateACME(cfg.ACME); err != nil {
		return err
	}
	if cfg.Storage.ClickHouse.Enabled {
		if strings.TrimSpace(cfg.Storage.ClickHouse.Endpoint) == "" {
			return fmt.Errorf("storage.clickhouse.endpoint is required when ClickHouse log sink is enabled")
		}
		if err := validateLogSinkEndpoint(cfg.Storage.ClickHouse.Endpoint, cfg.Storage.ClickHouse.AllowPrivateEndpoint, "clickhouse endpoint"); err != nil {
			return fmt.Errorf("storage.clickhouse.endpoint is invalid: %w", err)
		}
		if err := validateSQLIdentifierPath(cfg.Storage.ClickHouse.Table); err != nil {
			return fmt.Errorf("storage.clickhouse.table is invalid: %w", err)
		}
	}
	if cfg.Storage.VictoriaLogs.Enabled {
		if strings.TrimSpace(cfg.Storage.VictoriaLogs.Endpoint) == "" {
			return fmt.Errorf("storage.victorialogs.endpoint is required when VictoriaLogs log sink is enabled")
		}
		if err := validateLogSinkEndpoint(cfg.Storage.VictoriaLogs.Endpoint, cfg.Storage.VictoriaLogs.AllowPrivateEndpoint, "victorialogs endpoint"); err != nil {
			return fmt.Errorf("storage.victorialogs.endpoint is invalid: %w", err)
		}
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
		if err := validateLogSinkEndpoint(cfg.Storage.Elasticsearch.Endpoint, cfg.Storage.Elasticsearch.AllowPrivateEndpoint, "elasticsearch endpoint"); err != nil {
			return fmt.Errorf("storage.elasticsearch.endpoint is invalid: %w", err)
		}
		if strings.TrimSpace(cfg.Storage.Elasticsearch.Index) == "" {
			return fmt.Errorf("storage.elasticsearch.index is required when Elasticsearch log sink is enabled")
		}
	}
	switch strings.ToLower(strings.TrimSpace(cfg.AI.Provider)) {
	case "", "openai", "anthropic":
	default:
		return fmt.Errorf("ai.provider must be openai or anthropic")
	}
	if cfg.AI.Enabled {
		if err := validateAIModelConfig("ai", cfg.AI.RuntimeModelConfig(), true); err != nil {
			return err
		}
		assistant := cfg.AI.AssistantRuntimeConfig()
		if err := validateAIModelConfig("ai.assistant", assistant.RuntimeModelConfig(), true); err != nil {
			return err
		}
		reasoning := cfg.AI.ReasoningRuntimeConfig()
		if err := validateAIModelConfig("ai.reasoning", reasoning.RuntimeModelConfig(), true); err != nil {
			return err
		}
	}
	if err := validateAISelfLearning(cfg.AI.SelfLearning); err != nil {
		return err
	}
	if err := validateUpdateConfig(cfg.Update); err != nil {
		return err
	}
	if err := validateVulnerabilityConfig(cfg.Vulnerability); err != nil {
		return err
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
		if err := validateSiteCertificate(site); err != nil {
			return err
		}
		if err := validateProtectionPolicy("site "+site.Name+" waf.protection_policy", site.WAF.ProtectionPolicy, true); err != nil {
			return err
		}
		if !IsBudgetExhaustedPolicy(site.WAF.SemanticPolicy.BudgetExhaustedPolicy) {
			return fmt.Errorf("site %q has invalid waf.semantic_policy.budget_exhausted_policy %q", site.Name, site.WAF.SemanticPolicy.BudgetExhaustedPolicy)
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
		for _, cidr := range site.WAF.AccessControl.TrustedCIDRs {
			if err := validateIPEntry(cidr); err != nil {
				return fmt.Errorf("site %q has invalid trusted_cidrs entry %q: %w", site.Name, cidr, err)
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
	for _, rule := range cfg.Protection.IP.AccessRules {
		if err := validateIPAccessRule(rule); err != nil {
			return err
		}
	}
	for ip, score := range cfg.Protection.IP.ReputationOverrides {
		if err := validateIPEntry(ip); err != nil {
			return fmt.Errorf("invalid reputation override IP %q: %w", ip, err)
		}
		if score < 0 || score > 100 {
			return fmt.Errorf("reputation override for %q must be between 0 and 100", ip)
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
		if cfg.Protection.Bot.ClearanceStateCapacity < 1 || cfg.Protection.Bot.ClearanceStateCapacity > 1000000 {
			return fmt.Errorf("bot.clearance_state_capacity must be between 1 and 1000000")
		}
		if cfg.Protection.Bot.ClearanceHeaderEnabled && strings.TrimSpace(cfg.Protection.Bot.ClearanceHeaderName) == "" {
			return fmt.Errorf("bot.clearance_header_name is required when clearance header is enabled")
		}
		if cfg.Protection.Bot.PoWMaxDifficulty < cfg.Protection.Bot.ChallengeDifficulty || cfg.Protection.Bot.PoWMaxDifficulty > 8 {
			return fmt.Errorf("bot.pow_max_difficulty must be between challenge_difficulty and 8")
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
		case "br", "brotli", "gzip", "identity", "none":
		default:
			return fmt.Errorf("edge compression algorithm %q is not supported yet", algorithm)
		}
	}
	if cfg.Monitor.Prometheus.Enabled && !strings.HasPrefix(cfg.Monitor.Prometheus.Path, "/") {
		return fmt.Errorf("monitor.prometheus.path must start with /")
	}
	if cfg.Monitor.Prometheus.Enabled && cfg.Monitor.Prometheus.Public {
		path := cfg.Monitor.Prometheus.Path
		if path == "/health" || path == "/api" || strings.HasPrefix(path, "/api/") {
			return fmt.Errorf("monitor.prometheus.path %q conflicts with protected admin routes", path)
		}
	}
	if cfg.Monitor.RemoteWrite.Enabled {
		if strings.TrimSpace(cfg.Monitor.RemoteWrite.Endpoint) == "" {
			return fmt.Errorf("monitor.remote_write.endpoint is required when remote write is enabled")
		}
		if err := validateRemoteWriteEndpoint(cfg.Monitor.RemoteWrite.Endpoint, cfg.Monitor.RemoteWrite.AllowPrivateEndpoint); err != nil {
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
		if strings.TrimSpace(notifier.Endpoint) != "" {
			if err := validateNotifierEndpoint(notifier.Endpoint, notifier.AllowPrivateEndpoint); err != nil {
				return fmt.Errorf("notifier %q endpoint is invalid: %w", notifier.ID, err)
			}
		}
	}
	seenTaskIDs := make(map[string]struct{}, len(cfg.Scheduler.Tasks))
	for _, task := range cfg.Scheduler.Tasks {
		if err := validateScheduledTask(task); err != nil {
			return err
		}
		normalized := normalizeScheduledTaskForValidation(task)
		id := strings.ToLower(strings.TrimSpace(normalized.ID))
		if _, exists := seenTaskIDs[id]; exists {
			return fmt.Errorf("scheduled task id %q is duplicated", normalized.ID)
		}
		seenTaskIDs[id] = struct{}{}
		if strings.EqualFold(strings.TrimSpace(normalized.Type), "cleanup") {
			if err := validateManagedSchedulerPath(normalized.Target, cfg.Setup.DataDir, filepath.Dir(cfg.Logging.Output.File.Path)); err != nil {
				return fmt.Errorf("scheduled task %q target is invalid: %w", normalized.ID, err)
			}
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
		if jwksURL := strings.TrimSpace(cfg.APISec.Auth.JWKSURL); jwksURL != "" {
			if err := validateRemoteJWKSURL(jwksURL); err != nil {
				return fmt.Errorf("api auth jwks_url is invalid: %w", err)
			}
			if cfg.APISec.Auth.JWKSRefresh > 0 && cfg.APISec.Auth.JWKSRefresh < time.Minute {
				return fmt.Errorf("api auth jwks_refresh_interval must be at least 1m")
			}
		}
		// Fail closed: auth enabled without verification material is an auth bypass.
		if strings.TrimSpace(cfg.APISec.Auth.JWTSharedSecret) == "" && strings.TrimSpace(cfg.APISec.Auth.JWTPublicKeyFile) == "" && strings.TrimSpace(cfg.APISec.Auth.JWTPublicKeyPEM) == "" && strings.TrimSpace(cfg.APISec.Auth.JWKSFile) == "" && strings.TrimSpace(cfg.APISec.Auth.JWKSJSON) == "" && strings.TrimSpace(cfg.APISec.Auth.JWKSURL) == "" && strings.TrimSpace(cfg.APISec.Auth.JWKSCacheFile) == "" {
			return fmt.Errorf("api auth enabled requires jwt_shared_secret, jwt_public_key_file, jwt_public_key_pem, jwks_file, jwks_json, jwks_url, or jwks_cache_file")
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
	if err := validateManagementAPI(cfg.APISec.ManagementAPI); err != nil {
		return err
	}
	return nil
}

func validateCAPTCHAAssets(cfg CAPTCHAAssetsConfig) error {
	switch strings.ToLower(strings.TrimSpace(cfg.Backend)) {
	case "local", "s3":
	default:
		return fmt.Errorf("captcha_assets.backend must be local or s3")
	}
	if cfg.Limits.MaxImageBytes < 64<<10 || cfg.Limits.MaxImageBytes > 64<<20 {
		return fmt.Errorf("captcha_assets.limits.max_image_bytes must be between 64KiB and 64MiB")
	}
	if cfg.Limits.MaxFontBytes < 64<<10 || cfg.Limits.MaxFontBytes > 64<<20 {
		return fmt.Errorf("captcha_assets.limits.max_font_bytes must be between 64KiB and 64MiB")
	}
	if cfg.Limits.MaxPixels < 1_000_000 || cfg.Limits.MaxPixels > 64_000_000 {
		return fmt.Errorf("captcha_assets.limits.max_pixels must be between 1000000 and 64000000")
	}
	if strings.EqualFold(cfg.Backend, "local") && strings.TrimSpace(cfg.Local.Path) == "" {
		return fmt.Errorf("captcha_assets.local.path is required")
	}
	if strings.EqualFold(cfg.Backend, "s3") {
		if strings.TrimSpace(cfg.S3.Endpoint) == "" || strings.TrimSpace(cfg.S3.Bucket) == "" || strings.TrimSpace(cfg.S3.Region) == "" || strings.TrimSpace(cfg.S3.CredentialFile) == "" || strings.TrimSpace(cfg.S3.MetadataKeyFile) == "" {
			return fmt.Errorf("captcha_assets.s3 endpoint, bucket, region, credential_file and metadata_key_file are required")
		}
		if cfg.S3.RequestTimeout < time.Second || cfg.S3.RequestTimeout > time.Minute {
			return fmt.Errorf("captcha_assets.s3.request_timeout must be between 1s and 1m")
		}
		if _, err := netguard.ValidateURL(cfg.S3.Endpoint, netguard.URLPolicy{Purpose: "CAPTCHA S3 endpoint", HostPurpose: "CAPTCHA S3 endpoint", AllowedSchemes: []string{"http", "https"}, AllowPrivate: cfg.S3.AllowPrivateEndpoint}); err != nil {
			return fmt.Errorf("captcha_assets.s3.endpoint is invalid: %w", err)
		}
		if cfg.S3.UseTLS && !strings.HasPrefix(strings.ToLower(strings.TrimSpace(cfg.S3.Endpoint)), "https://") {
			return fmt.Errorf("captcha_assets.s3.endpoint must use https when use_tls is enabled")
		}
	}
	return nil
}

func validateManagedSchedulerPath(target string, roots ...string) error {
	cleanTarget := filepath.Clean(strings.TrimSpace(target))
	if !filepath.IsAbs(cleanTarget) {
		matchedRoot := false
		for _, root := range roots {
			cleanRoot := filepath.Clean(strings.TrimSpace(root))
			if cleanRoot != "." && cleanRoot != "" && strings.EqualFold(cleanTarget, filepath.Base(cleanRoot)) {
				cleanTarget = cleanRoot
				matchedRoot = true
				break
			}
		}
		if !matchedRoot {
			for _, root := range roots {
				cleanRoot := filepath.Clean(strings.TrimSpace(root))
				if cleanRoot != "." && cleanRoot != "" {
					cleanTarget = filepath.Join(cleanRoot, cleanTarget)
					break
				}
			}
		}
	}
	targetAbs, err := filepath.Abs(cleanTarget)
	if err != nil {
		return err
	}
	for _, root := range roots {
		if strings.TrimSpace(root) == "" {
			continue
		}
		rootAbs, err := filepath.Abs(filepath.Clean(root))
		if err != nil {
			continue
		}
		rel, err := filepath.Rel(rootAbs, targetAbs)
		if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return nil
		}
	}
	return fmt.Errorf("must be inside the configured data or log directory")
}

func validateManagementAPI(api ManagementAPIConfig) error {
	seen := map[string]struct{}{}
	for _, token := range api.Tokens {
		id := strings.TrimSpace(token.ID)
		if id == "" {
			return fmt.Errorf("management api token id is required")
		}
		if _, ok := seen[id]; ok {
			return fmt.Errorf("management api token %q is duplicated", id)
		}
		seen[id] = struct{}{}
		if strings.TrimSpace(token.Name) == "" {
			return fmt.Errorf("management api token %q name is required", id)
		}
		if strings.TrimSpace(token.Hash) == "" {
			return fmt.Errorf("management api token %q hash is required", id)
		}
		digest := strings.TrimPrefix(token.Hash, "sha256:")
		if !strings.HasPrefix(token.Hash, "sha256:") || len(digest) != 64 {
			return fmt.Errorf("management api token %q hash must be sha256 digest", id)
		}
		if _, err := hex.DecodeString(digest); err != nil {
			return fmt.Errorf("management api token %q hash must be hexadecimal sha256 digest", id)
		}
		if len(token.Scopes) == 0 {
			return fmt.Errorf("management api token %q must define at least one scope", id)
		}
		for _, scope := range token.Scopes {
			if err := validatePermissionExpression(scope); err != nil {
				return fmt.Errorf("management api token %q scope is invalid: %w", id, err)
			}
		}
		if !token.CreatedAt.IsZero() && !token.ExpiresAt.IsZero() && !token.ExpiresAt.After(token.CreatedAt) {
			return fmt.Errorf("management api token %q expires_at must be after created_at", id)
		}
	}
	return nil
}

func validatePermissionExpression(scope string) error {
	scope = strings.TrimSpace(scope)
	if scope == "" {
		return fmt.Errorf("scope is required")
	}
	if scope == "*" {
		return nil
	}
	if strings.Count(scope, ":") != 1 {
		return fmt.Errorf("scope must use action:resource format")
	}
	parts := strings.Split(scope, ":")
	switch parts[0] {
	case "read", "write", "approve":
	default:
		return fmt.Errorf("scope action must be read, write, or approve")
	}
	resource := parts[1]
	if resource == "" {
		return fmt.Errorf("scope resource is required")
	}
	if strings.ContainsAny(resource, " \t\r\n") {
		return fmt.Errorf("scope resource must not contain whitespace")
	}
	if strings.Contains(resource, "*") && !strings.HasSuffix(resource, "*") {
		return fmt.Errorf("scope wildcard is only allowed at the end")
	}
	return nil
}

func validateCluster(cfg *Config) error {
	mode := strings.ToLower(strings.TrimSpace(cfg.Deployment.Mode))
	if mode == "" {
		mode = "standalone"
		cfg.Deployment.Mode = mode
	}
	switch mode {
	case "standalone", "cluster":
	default:
		return fmt.Errorf("deployment.mode must be standalone or cluster")
	}
	if mode == "standalone" {
		if cfg.Cluster.Enabled {
			return fmt.Errorf("cluster.enabled requires deployment.mode=cluster")
		}
		return nil
	}
	if !cfg.Cluster.Enabled {
		return fmt.Errorf("deployment.mode=cluster requires cluster.enabled=true")
	}
	if cfg.Cluster.Consensus.Provider == "" {
		cfg.Cluster.Consensus.Provider = "builtin"
	}
	switch cfg.Cluster.Consensus.Provider {
	case "builtin", "etcd":
	default:
		return fmt.Errorf("cluster.consensus.provider must be builtin or etcd")
	}
	if cfg.Cluster.Consensus.Provider == "etcd" && len(cfg.Cluster.Consensus.EtcdEndpoints) == 0 {
		return fmt.Errorf("cluster.consensus.etcd_endpoints is required when provider is etcd")
	}
	if cfg.Cluster.Join.TokenTTL <= 0 || cfg.Cluster.Join.TokenTTL > 24*time.Hour {
		return fmt.Errorf("cluster.join.token_ttl must be between 1s and 24h")
	}
	if listen := strings.TrimSpace(cfg.Cluster.Interconnect.Listen); listen != "" {
		if _, err := net.ResolveTCPAddr("tcp", listen); err != nil {
			return fmt.Errorf("cluster.interconnect.listen is invalid: %w", err)
		}
	}
	if cfg.Cluster.Interconnect.MTLSRequired {
		hasPartialMaterial := strings.TrimSpace(cfg.Cluster.Interconnect.CAFile) != "" ||
			strings.TrimSpace(cfg.Cluster.Interconnect.CertFile) != "" ||
			strings.TrimSpace(cfg.Cluster.Interconnect.KeyFile) != ""
		if hasPartialMaterial {
			if strings.TrimSpace(cfg.Cluster.Interconnect.CAFile) == "" ||
				strings.TrimSpace(cfg.Cluster.Interconnect.CertFile) == "" ||
				strings.TrimSpace(cfg.Cluster.Interconnect.KeyFile) == "" {
				return fmt.Errorf("cluster.interconnect ca_file, cert_file and key_file must be set together")
			}
		}
	}
	wafNodes := 0
	monitorNodes := 0
	seen := map[string]struct{}{}
	for _, node := range cfg.Cluster.Nodes {
		id := strings.TrimSpace(node.ID)
		if id == "" {
			return fmt.Errorf("cluster node id is required")
		}
		if _, ok := seen[id]; ok {
			return fmt.Errorf("duplicate cluster node id %q", id)
		}
		seen[id] = struct{}{}
		switch node.Role {
		case "waf":
			wafNodes++
		case "monitor":
			monitorNodes++
		default:
			return fmt.Errorf("cluster node %q role must be waf or monitor", id)
		}
		if strings.TrimSpace(node.AdvertiseAddr) == "" {
			return fmt.Errorf("cluster node %q advertise_addr is required", id)
		}
		if _, err := net.ResolveTCPAddr("tcp", node.AdvertiseAddr); err != nil {
			return fmt.Errorf("cluster node %q advertise_addr is invalid: %w", id, err)
		}
	}
	switch strings.TrimSpace(cfg.Cluster.HAMode) {
	case "", "single-node":
		return nil
	case "dual-node-load-balancing":
		if wafNodes < 2 {
			return fmt.Errorf("dual-node-load-balancing requires at least two WAF nodes")
		}
	case "minimum-ha":
		if wafNodes < 2 || monitorNodes < 1 {
			return fmt.Errorf("minimum-ha requires at least two WAF nodes and one monitor node")
		}
	case "multi-node-ha":
		if wafNodes < 3 {
			return fmt.Errorf("multi-node-ha requires at least three WAF nodes")
		}
	default:
		return fmt.Errorf("unknown cluster.ha_mode %q", cfg.Cluster.HAMode)
	}
	return nil
}

func validateAIAPIBaseHost(raw string, allowPrivate bool) error {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("ai.api_base is invalid: %w", err)
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return fmt.Errorf("ai.api_base must start with http:// or https://")
	}
	if allowPrivate {
		return nil
	}
	host := strings.Trim(strings.ToLower(parsed.Hostname()), "[]")
	if host == "" {
		return fmt.Errorf("ai.api_base host is required")
	}
	switch host {
	case "localhost", "localhost.localdomain":
		return fmt.Errorf("ai.api_base points to a private, loopback, link-local, or unspecified host; enable ai.allow_private_api_base only for trusted local model gateways")
	}
	if ip := net.ParseIP(host); ip != nil {
		if isUnsafeAIAPIBaseIP(ip) {
			return fmt.Errorf("ai.api_base points to a private, loopback, link-local, or unspecified host; enable ai.allow_private_api_base only for trusted local model gateways")
		}
		return nil
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil
	}
	for _, ip := range ips {
		if isUnsafeAIAPIBaseIP(ip) {
			return fmt.Errorf("ai.api_base resolves to a private, loopback, link-local, or unspecified host; enable ai.allow_private_api_base only for trusted local model gateways")
		}
	}
	return nil
}

func validateAIModelConfig(prefix string, model AIModelConfig, enabled bool) error {
	switch strings.ToLower(strings.TrimSpace(model.Provider)) {
	case "", "openai", "anthropic":
	default:
		return fmt.Errorf("%s.provider must be openai or anthropic", prefix)
	}
	if !enabled && strings.TrimSpace(model.APIBase) == "" && strings.TrimSpace(model.Model) == "" {
		return nil
	}
	if strings.TrimSpace(model.APIBase) == "" {
		return fmt.Errorf("%s.api_base is required when ai is enabled", prefix)
	}
	if _, err := url.ParseRequestURI(model.APIBase); err != nil {
		return fmt.Errorf("%s.api_base is invalid: %w", prefix, err)
	}
	if err := validateAIAPIBaseHost(model.APIBase, model.AllowPrivateAPIBase); err != nil {
		return fmt.Errorf("%s.%w", prefix, err)
	}
	if strings.TrimSpace(model.Model) == "" {
		return fmt.Errorf("%s.model is required when ai is enabled", prefix)
	}
	return nil
}

func validateAISelfLearning(cfg AISelfLearningConfig) error {
	if cfg.Interval != 0 && (cfg.Interval < time.Hour || cfg.Interval > 30*24*time.Hour) {
		return fmt.Errorf("ai.self_learning.interval must be between 1h and 30d")
	}
	if cfg.MinConfidence != 0 && (cfg.MinConfidence < 0.9 || cfg.MinConfidence > 1) {
		return fmt.Errorf("ai.self_learning.min_confidence must be between 0.9 and 1")
	}
	if cfg.MinEvents != 0 && (cfg.MinEvents < 2 || cfg.MinEvents > 1000) {
		return fmt.Errorf("ai.self_learning.min_events must be between 2 and 1000")
	}
	if cfg.MaxEvents != 0 && (cfg.MaxEvents < 10 || cfg.MaxEvents > 5000) {
		return fmt.Errorf("ai.self_learning.max_events must be between 10 and 5000")
	}
	if cfg.MaxRulesPerRun != 0 && (cfg.MaxRulesPerRun < 1 || cfg.MaxRulesPerRun > 20) {
		return fmt.Errorf("ai.self_learning.max_rules_per_run must be between 1 and 20")
	}
	switch strings.ToLower(strings.TrimSpace(cfg.Action)) {
	case "", "block", "log", "challenge":
		return nil
	default:
		return fmt.Errorf("ai.self_learning.action must be block, log, or challenge")
	}
}

func validateUpdateConfig(cfg UpdateConfig) error {
	ota := cfg.OTA
	if !ota.Enabled && strings.TrimSpace(ota.Server) == "" {
		return nil
	}
	if strings.TrimSpace(ota.Server) == "" {
		return fmt.Errorf("update.ota.server is required when OTA updates are enabled")
	}
	if err := validateOutboundPublicURL(ota.Server, "OTA update server", []string{"https"}); err != nil {
		return fmt.Errorf("update.ota.server is invalid: %w", err)
	}
	if ota.CheckInterval != 0 && (ota.CheckInterval < time.Hour || ota.CheckInterval > 30*24*time.Hour) {
		return fmt.Errorf("update.ota.check_interval must be between 1h and 30d")
	}
	switch strings.ToLower(strings.TrimSpace(ota.Channel)) {
	case "", "stable", "canary", "dev":
	default:
		return fmt.Errorf("update.ota.channel must be stable, canary, or dev")
	}
	return nil
}

func validateVulnerabilityConfig(cfg VulnerabilityConfig) error {
	for _, feed := range cfg.Feeds {
		if !feed.Enabled {
			continue
		}
		if strings.TrimSpace(feed.ID) == "" {
			return fmt.Errorf("vulnerability feed must define id")
		}
		if strings.TrimSpace(feed.URL) == "" {
			return fmt.Errorf("vulnerability feed %q must define url", feed.ID)
		}
		if err := validateOutboundPublicURL(feed.URL, "vulnerability feed", []string{"https"}); err != nil {
			return fmt.Errorf("vulnerability feed %q url is invalid: %w", feed.ID, err)
		}
		if feed.Interval != 0 && (feed.Interval < time.Hour || feed.Interval > 30*24*time.Hour) {
			return fmt.Errorf("vulnerability feed %q interval must be between 1h and 30d", feed.ID)
		}
		switch strings.ToLower(strings.TrimSpace(feed.Type)) {
		case "", "json", "csv", "stix", "taxii", "nvd", "osv", "cve":
		default:
			return fmt.Errorf("vulnerability feed %q has invalid type %q", feed.ID, feed.Type)
		}
		switch strings.ToLower(strings.TrimSpace(feed.MinSeverity)) {
		case "", "info", "low", "medium", "high", "critical":
		default:
			return fmt.Errorf("vulnerability feed %q has invalid min_severity %q", feed.ID, feed.MinSeverity)
		}
	}
	return nil
}

func validateScheduledTask(task ScheduledTaskConfig) error {
	if !task.Enabled {
		return nil
	}
	task = normalizeScheduledTaskForValidation(task)
	if strings.TrimSpace(task.ID) == "" {
		return fmt.Errorf("scheduled task must define id")
	}
	switch strings.ToLower(strings.TrimSpace(task.Type)) {
	case "backup", "cleanup", "security_report", "ai_self_learning", "self_learning_rules":
	default:
		return fmt.Errorf("scheduled task %q has invalid type %q", task.ID, task.Type)
	}
	switch strings.ToLower(strings.TrimSpace(task.Frequency)) {
	case "", "interval", "daily", "weekly", "monthly":
	default:
		return fmt.Errorf("scheduled task %q has invalid frequency %q", task.ID, task.Frequency)
	}
	if task.Every != 0 && (task.Every < time.Minute || task.Every > 365*24*time.Hour) {
		return fmt.Errorf("scheduled task %q every must be between 1m and 365d", task.ID)
	}
	switch strings.ToLower(strings.TrimSpace(task.Type)) {
	case "cleanup":
		if strings.TrimSpace(task.Target) == "" {
			return fmt.Errorf("scheduled task %q target is required for cleanup", task.ID)
		}
	case "security_report":
		channel := strings.ToLower(strings.TrimSpace(task.Channel))
		if channel == "" {
			channel = "file"
		}
		switch channel {
		case "file":
			if strings.TrimSpace(task.Recipient) == "" {
				return fmt.Errorf("scheduled task %q recipient directory is required for file reports", task.ID)
			}
		case "webhook":
			if err := validateOutboundPublicURL(task.Recipient, "security report webhook", []string{"https"}); err != nil {
				return fmt.Errorf("scheduled task %q recipient is invalid: %w", task.ID, err)
			}
		default:
			return fmt.Errorf("scheduled task %q has invalid report channel %q", task.ID, task.Channel)
		}
		switch strings.ToLower(strings.TrimSpace(task.Format)) {
		case "", "markdown", "md", "json":
		default:
			return fmt.Errorf("scheduled task %q has invalid report format %q", task.ID, task.Format)
		}
		switch strings.ToLower(strings.TrimSpace(task.Period)) {
		case "", "daily", "weekly", "monthly":
		default:
			return fmt.Errorf("scheduled task %q has invalid report period %q", task.ID, task.Period)
		}
	}
	return nil
}

func normalizeScheduledTaskForValidation(task ScheduledTaskConfig) ScheduledTaskConfig {
	task.ID = strings.TrimSpace(task.ID)
	task.Name = strings.TrimSpace(task.Name)
	task.Type = strings.TrimSpace(task.Type)
	task.Schedule = strings.TrimSpace(task.Schedule)
	task.Frequency = strings.TrimSpace(task.Frequency)
	task.At = strings.TrimSpace(task.At)
	task.Target = strings.TrimSpace(task.Target)
	task.Channel = strings.TrimSpace(task.Channel)
	task.Recipient = strings.TrimSpace(task.Recipient)
	task.Period = strings.TrimSpace(task.Period)
	task.Format = strings.TrimSpace(task.Format)
	if task.Type == "" {
		task.Type = "cleanup"
	}
	if task.ID == "" {
		target := strings.NewReplacer("/", "-", "\\", "-").Replace(task.Target)
		task.ID = strings.Trim(task.Type+"-"+target, "-")
		if task.ID == "" {
			task.ID = task.Type
		}
	}
	if task.Name == "" {
		task.Name = task.ID
	}
	if task.Keep <= 0 {
		task.Keep = 7
	}
	if task.Frequency == "" {
		if task.Schedule != "" {
			task.Frequency = task.Schedule
		} else if task.Type == "security_report" || task.Type == "ai_self_learning" || task.Type == "self_learning_rules" {
			task.Frequency = "daily"
		} else {
			task.Frequency = "interval"
		}
	}
	if (task.Frequency == "daily" || task.Frequency == "weekly" || task.Frequency == "monthly") && task.At == "" {
		task.At = "08:00"
	}
	if task.Frequency == "interval" && task.Every <= 0 {
		task.Every = 24 * time.Hour
	}
	if task.Type == "security_report" {
		if task.Channel == "" {
			task.Channel = "file"
		}
		if task.Recipient == "" {
			task.Recipient = "./data/reports"
		}
		if task.Period == "" {
			task.Period = "daily"
		}
		if task.Format == "" {
			task.Format = "markdown"
		}
	}
	return task
}

func isUnsafeAIAPIBaseIP(ip net.IP) bool {
	return !netguard.IsPublicIP(ip)
}

func validateBlockPage(page BlockPageConfig) error {
	if strings.TrimSpace(page.TemplateID) == "" {
		return fmt.Errorf("block_page.template_id is required")
	}
	if len(page.CustomHTML) > MaxBlockPageHTMLBytes {
		return fmt.Errorf("block_page.custom_html exceeds %d bytes", MaxBlockPageHTMLBytes)
	}
	if strings.TrimSpace(page.CustomHTML) == "" {
		return nil
	}
	if _, err := template.New("block_page").Parse(page.CustomHTML); err != nil {
		return fmt.Errorf("block_page.custom_html has invalid template syntax: %w", err)
	}
	return nil
}

func validateSliderCAPTCHA(slider LoginSliderCAPTCHAConfig) error {
	if slider.Width < 240 || slider.Width > 640 {
		return fmt.Errorf("console.login.captcha.slider.width must be between 240 and 640")
	}
	if slider.Height < 100 || slider.Height > 360 {
		return fmt.Errorf("console.login.captcha.slider.height must be between 100 and 360")
	}
	if slider.PieceSize < 28 || slider.PieceSize > 96 {
		return fmt.Errorf("console.login.captcha.slider.piece_size must be between 28 and 96")
	}
	if slider.PieceSize*2 >= slider.Width || slider.PieceSize+20 >= slider.Height {
		return fmt.Errorf("console.login.captcha.slider piece_size is too large for the configured image")
	}
	if slider.Tolerance < 2 || slider.Tolerance > 20 {
		return fmt.Errorf("console.login.captcha.slider.tolerance must be between 2 and 20")
	}
	if slider.MinDrag < 100*time.Millisecond || slider.MinDrag > 10*time.Second {
		return fmt.Errorf("console.login.captcha.slider.min_drag must be between 100ms and 10s")
	}
	if slider.PowMaxNumber != 0 && (slider.PowMaxNumber < 1000 || slider.PowMaxNumber > 50000000) {
		return fmt.Errorf("console.login.captcha.slider.pow_max_number must be between 1000 and 50000000")
	}
	if slider.PowEnabled && slider.PowMaxNumber == 0 {
		return fmt.Errorf("console.login.captcha.slider.pow_max_number is required when slider auxiliary PoW is enabled")
	}
	return nil
}

func validateBotProtection(bot BotProtectionConfig) error {
	if bot.RiskLevel < 1 || bot.RiskLevel > 5 {
		return fmt.Errorf("protection.bot.risk_level must be between 1 and 5")
	}
	if bot.RiskLowThreshold < 1 || bot.RiskBlockThreshold > 100 || !(bot.RiskLowThreshold < bot.RiskMediumThreshold && bot.RiskMediumThreshold < bot.RiskHighThreshold && bot.RiskHighThreshold < bot.RiskBlockThreshold) {
		return fmt.Errorf("protection.bot risk thresholds must be ordered values between 1 and 100")
	}
	if bot.RiskConfidenceMin < 0.5 || bot.RiskConfidenceMin > 1 {
		return fmt.Errorf("protection.bot.risk_confidence_min must be between 0.5 and 1")
	}
	if err := validateBehaviorCAPTCHAType("protection.bot.captcha_type", bot.CAPTCHAType, true); err != nil {
		return err
	}
	for idx, kind := range bot.CAPTCHATypes {
		if err := validateBehaviorCAPTCHAType(fmt.Sprintf("protection.bot.captcha_types[%d]", idx), kind, false); err != nil {
			return err
		}
	}
	for idx, kind := range bot.CAPTCHAEscalationTypes {
		if err := validateBehaviorCAPTCHAType(fmt.Sprintf("protection.bot.captcha_escalation_types[%d]", idx), kind, false); err != nil {
			return err
		}
	}
	switch strings.ToLower(strings.TrimSpace(bot.CAPTCHAMobileType)) {
	case "", "off", "none", "inherit", "same", "pow", "image", "graphic":
	default:
		return fmt.Errorf("protection.bot.captcha_mobile_type must be pow, image, or empty")
	}
	if bot.CAPTCHAChallengeTTL < 10*time.Second || bot.CAPTCHAChallengeTTL > 10*time.Minute {
		return fmt.Errorf("protection.bot.captcha_challenge_ttl must be between 10s and 10m")
	}
	if bot.CAPTCHAFailureWindow < time.Minute || bot.CAPTCHAFailureWindow > 24*time.Hour {
		return fmt.Errorf("protection.bot.captcha_failure_window must be between 1m and 24h")
	}
	if bot.CAPTCHABlockDuration < time.Minute || bot.CAPTCHABlockDuration > 24*time.Hour {
		return fmt.Errorf("protection.bot.captcha_block_duration must be between 1m and 24h")
	}
	switch strings.ToLower(strings.TrimSpace(bot.CAPTCHABindingMode)) {
	case "strict_ip_ua", "ip_prefix_ua":
	default:
		return fmt.Errorf("protection.bot.captcha_binding_mode must be strict_ip_ua or ip_prefix_ua")
	}
	if strings.TrimSpace(bot.CAPTCHAPolicyVersion) == "" || len(bot.CAPTCHAPolicyVersion) > 64 {
		return fmt.Errorf("protection.bot.captcha_policy_version must be between 1 and 64 characters")
	}
	if bot.CAPTCHAMaxAttempts < 1 || bot.CAPTCHAMaxAttempts > 20 {
		return fmt.Errorf("protection.bot.captcha_max_attempts must be between 1 and 20")
	}
	if bot.ImageCAPTCHALength < 4 || bot.ImageCAPTCHALength > 8 {
		return fmt.Errorf("protection.bot.image_captcha_length must be between 4 and 8")
	}
	if bot.ImageCAPTCHAWidth < 160 || bot.ImageCAPTCHAWidth > 640 {
		return fmt.Errorf("protection.bot.image_captcha_width must be between 160 and 640")
	}
	if bot.ImageCAPTCHAHeight < 60 || bot.ImageCAPTCHAHeight > 260 {
		return fmt.Errorf("protection.bot.image_captcha_height must be between 60 and 260")
	}
	if bot.ImageCAPTCHAAudioLimit < 1 || bot.ImageCAPTCHAAudioLimit > 20 {
		return fmt.Errorf("protection.bot.image_captcha_audio_limit must be between 1 and 20")
	}
	if bot.SliderCAPTCHAWidth < 240 || bot.SliderCAPTCHAWidth > 640 {
		return fmt.Errorf("protection.bot.slider_captcha_width must be between 240 and 640")
	}
	if bot.SliderCAPTCHAHeight < 100 || bot.SliderCAPTCHAHeight > 360 {
		return fmt.Errorf("protection.bot.slider_captcha_height must be between 100 and 360")
	}
	if bot.SliderCAPTCHAPiece < 28 || bot.SliderCAPTCHAPiece > 96 {
		return fmt.Errorf("protection.bot.slider_captcha_piece must be between 28 and 96")
	}
	if bot.SliderCAPTCHAPiece*2 >= bot.SliderCAPTCHAWidth || bot.SliderCAPTCHAPiece+20 >= bot.SliderCAPTCHAHeight {
		return fmt.Errorf("protection.bot.slider_captcha_piece is too large for the configured image")
	}
	if bot.SliderCAPTCHATolerance < 2 || bot.SliderCAPTCHATolerance > 20 {
		return fmt.Errorf("protection.bot.slider_captcha_tolerance must be between 2 and 20")
	}
	if bot.SliderCAPTCHAMinDrag < 100*time.Millisecond || bot.SliderCAPTCHAMinDrag > 10*time.Second {
		return fmt.Errorf("protection.bot.slider_captcha_min_drag must be between 100ms and 10s")
	}
	if bot.ChallengeDifficulty < 1 || bot.ChallengeDifficulty > 6 {
		return fmt.Errorf("protection.bot.challenge_difficulty must be between 1 and 6")
	}
	if bot.AltchaMaxNumber < 1000 || bot.AltchaMaxNumber > 50000000 {
		return fmt.Errorf("protection.bot.altcha_max_number must be between 1000 and 50000000")
	}
	if bot.WaitingRoomMaxActive < 1 || bot.WaitingRoomMaxActive > 1000000 {
		return fmt.Errorf("protection.bot.waiting_room_max_active must be between 1 and 1000000")
	}
	if bot.WaitingRoomTTL < 30*time.Second || bot.WaitingRoomTTL > 24*time.Hour {
		return fmt.Errorf("protection.bot.waiting_room_ttl must be between 30s and 24h")
	}
	if bot.ChallengeTTL < 30*time.Second || bot.ChallengeTTL > 24*time.Hour {
		return fmt.Errorf("protection.bot.challenge_ttl must be between 30s and 24h")
	}
	return nil
}

func validateBehaviorCAPTCHAType(field, value string, allowAliases bool) error {
	kind := strings.ToLower(strings.TrimSpace(value))
	valid := map[string]struct{}{
		"pow": {}, "image": {}, "curve_draw": {}, "curve_slider": {}, "curve_slider_v2": {}, "curve_slider_v3": {},
		"shape_slider": {}, "slider_v2": {}, "rotate": {}, "restore_slider": {}, "angle": {}, "scratch": {},
		"text_click": {}, "icon_click": {}, "random": {},
	}
	if allowAliases {
		valid[""] = struct{}{}
		valid["graphic"] = struct{}{}
		valid["slider"] = struct{}{}
		valid["puzzle"] = struct{}{}
	}
	if _, ok := valid[kind]; !ok {
		return fmt.Errorf("%s contains unsupported CAPTCHA type %q", field, value)
	}
	return nil
}

func validateSecurityEntry(entry LoginSecurityEntryConfig) error {
	if !entry.Enabled && strings.TrimSpace(entry.Path) == "" && strings.TrimSpace(entry.CookieName) == "" {
		return nil
	}
	path := strings.TrimSpace(entry.Path)
	if path == "" {
		return fmt.Errorf("console.login.security_entry.path is required")
	}
	if !strings.HasPrefix(path, "/") || strings.Contains(path, "..") || strings.ContainsAny(path, "?#") {
		return fmt.Errorf("console.login.security_entry.path must be an absolute clean path without query or fragment")
	}
	cleaned := "/" + strings.Trim(strings.TrimPrefix(path, "/"), "/")
	if cleaned == "/" || cleaned == "/login" || cleaned == "/api" || strings.HasPrefix(cleaned, "/api/") || cleaned == "/health" {
		return fmt.Errorf("console.login.security_entry.path conflicts with admin routes")
	}
	cookieName := strings.TrimSpace(entry.CookieName)
	if cookieName == "" {
		return fmt.Errorf("console.login.security_entry.cookie_name is required")
	}
	if strings.ContainsAny(cookieName, " \t\r\n=;,") {
		return fmt.Errorf("console.login.security_entry.cookie_name is invalid")
	}
	return nil
}

func validateLoginBackground(background LoginBackgroundConfig) error {
	switch strings.ToLower(strings.TrimSpace(background.Type)) {
	case "", "auto", "image", "video":
	default:
		return fmt.Errorf("console.login.background.type must be auto, image, or video")
	}
	rawURL := strings.TrimSpace(background.URL)
	if rawURL == "" {
		return nil
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("console.login.background.url is invalid: %w", err)
	}
	switch strings.ToLower(parsed.Scheme) {
	case "http", "https":
	default:
		return fmt.Errorf("console.login.background.url must use http or https")
	}
	if parsed.Host == "" {
		return fmt.Errorf("console.login.background.url must include a host")
	}
	if parsed.User != nil {
		return fmt.Errorf("console.login.background.url must not include credentials")
	}
	return nil
}

func validateConsoleMap(consoleMap ConsoleMapConfig) error {
	return validateMapBoundary("console.map.china_boundary", consoleMap.ChinaBoundary)
}

func validateMapBoundary(prefix string, boundary MapBoundaryConfig) error {
	sourceType := strings.ToLower(strings.TrimSpace(boundary.SourceType))
	if sourceType == "" {
		sourceType = "file"
	}
	switch sourceType {
	case "file", "url":
	default:
		return fmt.Errorf("%s.source_type must be file or url", prefix)
	}
	if !boundary.Enabled && strings.TrimSpace(boundary.Source) == "" {
		return nil
	}
	source := strings.TrimSpace(boundary.Source)
	if source == "" {
		return fmt.Errorf("%s.source is required when boundary rendering is enabled", prefix)
	}
	if strings.TrimSpace(boundary.License) == "" && strings.TrimSpace(boundary.ReviewID) == "" {
		return fmt.Errorf("%s.license or %s.review_id is required before rendering administrative boundaries", prefix, prefix)
	}
	if sourceType == "url" {
		if err := validateMapBoundaryURL(source, boundary); err != nil {
			return fmt.Errorf("%s.source is invalid: %w", prefix, err)
		}
		return nil
	}
	lower := strings.ToLower(source)
	if !(strings.HasSuffix(lower, ".geojson") || strings.HasSuffix(lower, ".json")) {
		return fmt.Errorf("%s.source file must be .geojson or .json", prefix)
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

func validateIPAccessRule(rule IPAccessRuleConfig) error {
	if !rule.Enabled {
		return nil
	}
	if strings.TrimSpace(rule.ID) == "" {
		return fmt.Errorf("ip access rule must define id")
	}
	action := strings.ToLower(strings.TrimSpace(rule.Action))
	if action != "allow" && action != "block" && action != "monitor" {
		return fmt.Errorf("ip access rule %q has invalid action %q", rule.ID, rule.Action)
	}
	scope := strings.ToLower(strings.TrimSpace(rule.Scope))
	if scope == "" {
		scope = "global"
	}
	if scope != "global" && scope != "site" && scope != "path" && scope != "directory" {
		return fmt.Errorf("ip access rule %q has invalid scope %q", rule.ID, rule.Scope)
	}
	if scope == "site" && strings.TrimSpace(rule.SiteID) == "" {
		return fmt.Errorf("ip access rule %q with site scope must define site_id", rule.ID)
	}
	if (scope == "path" || scope == "directory") && strings.TrimSpace(rule.PathPrefix) == "" {
		return fmt.Errorf("ip access rule %q with path scope must define path_prefix", rule.ID)
	}
	if len(rule.Entries) == 0 {
		return fmt.Errorf("ip access rule %q must define entries", rule.ID)
	}
	for _, entry := range rule.Entries {
		if err := validateIPEntry(entry); err != nil {
			return fmt.Errorf("ip access rule %q has invalid entry %q: %w", rule.ID, entry, err)
		}
	}
	return nil
}

func validateRemoteJWKSURL(raw string) error {
	_, err := netguard.ValidateURL(raw, netguard.URLPolicy{
		Purpose:        "JWKS",
		HostPurpose:    "remote JWKS",
		AllowedSchemes: []string{"https"},
	})
	return err
}

func validateOutboundPublicURL(raw, purpose string, schemes []string) error {
	_, err := netguard.ValidateURL(raw, netguard.URLPolicy{
		Purpose:        purpose,
		HostPurpose:    purpose,
		AllowedSchemes: schemes,
	})
	return err
}

func validateRemoteWriteEndpoint(raw string, allowPrivate bool) error {
	_, err := netguard.ValidateURL(raw, netguard.URLPolicy{
		Purpose:        "remote_write",
		HostPurpose:    "remote_write endpoint",
		AllowedSchemes: []string{"http", "https"},
		AllowPrivate:   allowPrivate,
	})
	return err
}

func validateNotifierEndpoint(raw string, allowPrivate bool) error {
	_, err := netguard.ValidateURL(raw, netguard.URLPolicy{
		Purpose:        "notifier",
		HostPurpose:    "notifier endpoint",
		AllowedSchemes: []string{"http", "https"},
		AllowPrivate:   allowPrivate,
	})
	return err
}

func validateLogSinkEndpoint(raw string, allowPrivate bool, purpose string) error {
	_, err := netguard.ValidateURL(raw, netguard.URLPolicy{
		Purpose:        purpose,
		HostPurpose:    purpose,
		AllowedSchemes: []string{"http", "https"},
		AllowPrivate:   allowPrivate,
	})
	return err
}

func validateMapBoundaryURL(raw string, boundary MapBoundaryConfig) error {
	schemes := []string{"https"}
	if boundary.AllowInsecure {
		schemes = []string{"http", "https"}
	}
	_, err := netguard.ValidateURL(raw, netguard.URLPolicy{
		Purpose:        "map boundary",
		HostPurpose:    "map boundary",
		AllowedSchemes: schemes,
		AllowPrivate:   boundary.AllowPrivate,
	})
	return err
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

func hasAnyTLSCertificate(cfg *Config) bool {
	if cfg == nil {
		return false
	}
	if cfg.TLS.CertFile != "" && cfg.TLS.KeyFile != "" {
		return true
	}
	for _, site := range cfg.Sites {
		if site.EnableSSL && site.Certificate.Mode != "inline" && site.CertFile != "" && site.KeyFile != "" {
			return true
		}
		if site.EnableSSL && site.Certificate.Mode == "inline" && site.Certificate.CertPEM != "" && site.Certificate.KeyPEM != "" {
			return true
		}
	}
	return false
}

func validateACME(cfg ACMEConfig) error {
	if !cfg.Enabled {
		return nil
	}
	if strings.TrimSpace(cfg.ACMESHPath) == "" {
		return fmt.Errorf("acme.acme_sh_path is required when ACME is enabled")
	}
	if strings.TrimSpace(cfg.Home) == "" {
		return fmt.Errorf("acme.home is required when ACME is enabled")
	}
	if strings.TrimSpace(cfg.CertDir) == "" {
		return fmt.Errorf("acme.cert_dir is required when ACME is enabled")
	}
	if err := validateACMEServer(cfg.Server); err != nil {
		return fmt.Errorf("acme.server is invalid: %w", err)
	}
	if err := validateACMEReloadCommand(cfg.ReloadCommand); err != nil {
		return fmt.Errorf("acme.reload_command is invalid: %w", err)
	}
	switch strings.ToLower(strings.TrimSpace(cfg.KeyType)) {
	case "", "ec-256", "ec-384", "2048", "3072", "4096":
	default:
		return fmt.Errorf("acme.key_type has unsupported value %q", cfg.KeyType)
	}
	for _, provider := range cfg.DNSProviders {
		if !provider.Enabled {
			continue
		}
		if strings.TrimSpace(provider.ID) == "" || strings.TrimSpace(provider.API) == "" {
			return fmt.Errorf("acme dns provider must define id and api")
		}
		if !regexp.MustCompile(`^dns_[a-z0-9_]+$`).MatchString(strings.TrimSpace(provider.API)) {
			return fmt.Errorf("acme dns provider %q has invalid api %q", provider.ID, provider.API)
		}
		for key := range provider.Env {
			if !regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`).MatchString(key) {
				return fmt.Errorf("acme dns provider %q has invalid env key %q", provider.ID, key)
			}
		}
	}
	return nil
}

func validateACMEServer(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	switch strings.ToLower(value) {
	case "letsencrypt", "zerossl", "buypass", "ssl.com", "google", "letsencrypt_test", "zerossl_test", "buypass_test", "google_test":
		return nil
	}
	_, err := netguard.ValidateURL(value, netguard.URLPolicy{
		Purpose:        "ACME directory",
		HostPurpose:    "ACME directory",
		AllowedSchemes: []string{"https"},
	})
	return err
}

func validateACMEReloadCommand(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	if strings.ContainsAny(value, "\x00\r\n") {
		return fmt.Errorf("must not contain control characters")
	}
	// Reject shell metacharacters and require an absolute executable path.
	// acme.sh executes --reloadcmd through a shell, so free-form strings are RCE.
	if strings.ContainsAny(value, ";|&<>$`\\!*?\n\r") {
		return fmt.Errorf("must not contain shell metacharacters")
	}
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return fmt.Errorf("must not be empty")
	}
	exe := fields[0]
	// Accept Unix absolute paths even when validating on Windows.
	if !filepath.IsAbs(exe) && !strings.HasPrefix(exe, "/") {
		return fmt.Errorf("executable must be an absolute path")
	}
	return nil
}

func validateSiteCertificate(site SiteConfig) error {
	if strings.TrimSpace(site.Certificate.Mode) == "" {
		return nil
	}
	switch site.Certificate.Mode {
	case "file":
		if site.EnableSSL && (strings.TrimSpace(site.CertFile) == "" || strings.TrimSpace(site.KeyFile) == "") {
			return fmt.Errorf("site %q requires cert_file and key_file in file certificate mode", site.Name)
		}
	case "inline":
		if site.EnableSSL && (strings.TrimSpace(site.Certificate.CertPEM) == "" || strings.TrimSpace(site.Certificate.KeyPEM) == "") {
			return fmt.Errorf("site %q requires cert_pem and key_pem in inline certificate mode", site.Name)
		}
	case "acme":
		if site.EnableSSL && len(site.Certificate.ACME.Domains) == 0 && len(site.Domains) == 0 {
			return fmt.Errorf("site %q requires acme domains or site domains", site.Name)
		}
	default:
		return fmt.Errorf("site %q has unsupported certificate mode %q", site.Name, site.Certificate.Mode)
	}
	return nil
}
