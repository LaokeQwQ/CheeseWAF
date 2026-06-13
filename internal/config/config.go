// Package config handles YAML configuration loading, validation, and hot-reloading.
// 负责 YAML 配置加载、校验和热重载。
package config

import (
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server        ServerConfig        `yaml:"server" json:"server"`
	TLS           TLSConfig           `yaml:"tls" json:"tls"`
	Setup         SetupConfig         `yaml:"setup" json:"setup"`
	Console       ConsoleConfig       `yaml:"console" json:"console"`
	Sites         []SiteConfig        `yaml:"sites" json:"sites"`
	Protection    ProtectionConfig    `yaml:"protection" json:"protection"`
	Storage       StorageConfig       `yaml:"storage" json:"storage"`
	Logging       LoggingConfig       `yaml:"logging" json:"logging"`
	AI            AIConfig            `yaml:"ai" json:"ai"`
	Update        UpdateConfig        `yaml:"update" json:"update"`
	Vulnerability VulnerabilityConfig `yaml:"vulnerability" json:"vulnerability"`
	Scheduler     SchedulerConfig     `yaml:"scheduler" json:"scheduler"`
	Edge          EdgeConfig          `yaml:"edge" json:"edge"`
	Monitor       MonitorConfig       `yaml:"monitor" json:"monitor"`
	APISec        APISecConfig        `yaml:"apisec" json:"apisec"`
	BlockPage     BlockPageConfig     `yaml:"block_page" json:"block_page"`
}

const MaxBlockPageHTMLBytes = 512 * 1024

type BlockPageConfig struct {
	TemplateID    string `yaml:"template_id" json:"template_id"`
	CustomEnabled bool   `yaml:"custom_enabled" json:"custom_enabled"`
	CustomHTML    string `yaml:"custom_html" json:"custom_html"`
}

type ServerConfig struct {
	Listen       string         `yaml:"listen" json:"listen"`
	ListenTLS    string         `yaml:"listen_tls" json:"listen_tls"`
	ListenHTTP3  string         `yaml:"listen_http3" json:"listen_http3"`
	AdminListen  string         `yaml:"admin_listen" json:"admin_listen"`
	AdminPublic  bool           `yaml:"admin_public" json:"admin_public"`
	AdminTLS     AdminTLSConfig `yaml:"admin_tls" json:"admin_tls"`
	ReadTimeout  time.Duration  `yaml:"read_timeout" json:"read_timeout"`
	WriteTimeout time.Duration  `yaml:"write_timeout" json:"write_timeout"`
	IdleTimeout  time.Duration  `yaml:"idle_timeout" json:"idle_timeout"`
	HTTP3        HTTP3Config    `yaml:"http3" json:"http3"`
}

type AdminTLSConfig struct {
	Enabled    bool   `yaml:"enabled" json:"enabled"`
	CertFile   string `yaml:"cert_file" json:"cert_file"`
	KeyFile    string `yaml:"key_file" json:"key_file"`
	SelfSigned bool   `yaml:"self_signed" json:"self_signed"`
}

type HTTP3Config struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
	ZeroRTT bool `yaml:"zero_rtt" json:"zero_rtt"`
}

type TLSConfig struct {
	AutoCert   bool   `yaml:"auto_cert" json:"auto_cert"`
	CertFile   string `yaml:"cert_file" json:"cert_file"`
	KeyFile    string `yaml:"key_file" json:"key_file"`
	MinVersion string `yaml:"min_version" json:"min_version"`
	HSTS       bool   `yaml:"hsts" json:"hsts"`
}

type SetupConfig struct {
	DataDir         string `yaml:"data_dir" json:"data_dir"`
	RuntimeDir      string `yaml:"runtime_dir" json:"runtime_dir"`
	ThreeEndUnified bool   `yaml:"three_end_unified" json:"three_end_unified"`
}

type ConsoleConfig struct {
	Login ConsoleLoginConfig `yaml:"login" json:"login"`
}

type ConsoleLoginConfig struct {
	CAPTCHA       LoginCAPTCHAConfig       `yaml:"captcha" json:"captcha"`
	SecurityEntry LoginSecurityEntryConfig `yaml:"security_entry" json:"security_entry"`
	Background    LoginBackgroundConfig    `yaml:"background" json:"background"`
}

type LoginCAPTCHAConfig struct {
	Enabled   bool                     `yaml:"enabled" json:"enabled"`
	Mode      string                   `yaml:"mode" json:"mode"` // slider/pow
	MaxNumber int                      `yaml:"max_number" json:"max_number"`
	TTL       time.Duration            `yaml:"ttl" json:"ttl"`
	Slider    LoginSliderCAPTCHAConfig `yaml:"slider" json:"slider"`
}

type LoginSliderCAPTCHAConfig struct {
	Width        int           `yaml:"width" json:"width"`
	Height       int           `yaml:"height" json:"height"`
	PieceSize    int           `yaml:"piece_size" json:"piece_size"`
	Tolerance    int           `yaml:"tolerance" json:"tolerance"`
	MinDrag      time.Duration `yaml:"min_drag" json:"min_drag"`
	PowEnabled   bool          `yaml:"pow_enabled" json:"pow_enabled"`
	PowMaxNumber int           `yaml:"pow_max_number" json:"pow_max_number"`
}

type LoginSecurityEntryConfig struct {
	Enabled    bool   `yaml:"enabled" json:"enabled"`
	Path       string `yaml:"path" json:"path"`
	CookieName string `yaml:"cookie_name" json:"cookie_name"`
}

type LoginBackgroundConfig struct {
	Enabled bool   `yaml:"enabled" json:"enabled"`
	Type    string `yaml:"type" json:"type"` // auto/image/video
	URL     string `yaml:"url" json:"url"`
}

type SiteConfig struct {
	ID          string           `yaml:"id" json:"id"`
	Name        string           `yaml:"name" json:"name"`
	Domains     []string         `yaml:"domains" json:"domains"`
	Upstreams   []UpstreamConfig `yaml:"upstreams" json:"upstreams"`
	ListenPort  int              `yaml:"listen_port" json:"listen_port"`
	LoadBalance string           `yaml:"loadbalance" json:"loadbalance"`
	WAF         WAFConfig        `yaml:"waf" json:"waf"`
	Enabled     bool             `yaml:"enabled" json:"enabled"`
}

type UpstreamConfig struct {
	Address string `yaml:"address" json:"address"`
	Weight  int    `yaml:"weight" json:"weight"`
}

type WAFConfig struct {
	Enabled          bool                     `yaml:"enabled" json:"enabled"`
	Mode             string                   `yaml:"mode" json:"mode"`
	SemanticEngines  SemanticEngineSwitches   `yaml:"semantic_engines" json:"semantic_engines"`
	ProtectionPolicy ProtectionPolicyConfig   `yaml:"protection_policy" json:"protection_policy"`
	CustomRules      []CustomRuleConfig       `yaml:"custom_rules" json:"custom_rules"`
	Performance      PerformanceTuningConfig  `yaml:"performance" json:"performance"`
	Response         ResponseInspectionConfig `yaml:"response" json:"response"`
	Rewrite          []RewriteRuleConfig      `yaml:"rewrite" json:"rewrite"`
	HealthCheck      HealthCheckConfig        `yaml:"health_check" json:"health_check"`
	AccessControl    SiteAccessControlConfig  `yaml:"access_control" json:"access_control"`
}

type SemanticEngineSwitches struct {
	SQL   bool `yaml:"sql" json:"sql"`
	XSS   bool `yaml:"xss" json:"xss"`
	RCE   bool `yaml:"rce" json:"rce"`
	LFI   bool `yaml:"lfi" json:"lfi"`
	XXE   bool `yaml:"xxe" json:"xxe"`
	SSRF  bool `yaml:"ssrf" json:"ssrf"`
	NoSQL bool `yaml:"nosql" json:"nosql"`
	SSTI  bool `yaml:"ssti" json:"ssti"`
}

func (s *SemanticEngineSwitches) UnmarshalYAML(value *yaml.Node) error {
	defaults := SemanticEngineSwitches{
		SQL:   true,
		XSS:   true,
		RCE:   true,
		LFI:   true,
		XXE:   true,
		SSRF:  true,
		NoSQL: true,
		SSTI:  true,
	}
	if value == nil || (value.Kind == yaml.ScalarNode && value.Tag == "!!null") {
		*s = defaults
		return nil
	}
	var raw struct {
		SQL   *bool `yaml:"sql"`
		XSS   *bool `yaml:"xss"`
		RCE   *bool `yaml:"rce"`
		LFI   *bool `yaml:"lfi"`
		XXE   *bool `yaml:"xxe"`
		SSRF  *bool `yaml:"ssrf"`
		NoSQL *bool `yaml:"nosql"`
		SSTI  *bool `yaml:"ssti"`
	}
	if err := value.Decode(&raw); err != nil {
		return err
	}
	*s = defaults
	if raw.SQL != nil {
		s.SQL = *raw.SQL
	}
	if raw.XSS != nil {
		s.XSS = *raw.XSS
	}
	if raw.RCE != nil {
		s.RCE = *raw.RCE
	}
	if raw.LFI != nil {
		s.LFI = *raw.LFI
	}
	if raw.XXE != nil {
		s.XXE = *raw.XXE
	}
	if raw.SSRF != nil {
		s.SSRF = *raw.SSRF
	}
	if raw.NoSQL != nil {
		s.NoSQL = *raw.NoSQL
	}
	if raw.SSTI != nil {
		s.SSTI = *raw.SSTI
	}
	return nil
}

type CustomRuleConfig struct {
	ID       string `yaml:"id" json:"id"`
	Name     string `yaml:"name" json:"name"`
	Pattern  string `yaml:"pattern" json:"pattern"`
	Location string `yaml:"location" json:"location"`
	Action   string `yaml:"action" json:"action"`
	Severity string `yaml:"severity" json:"severity"`
	Enabled  bool   `yaml:"enabled" json:"enabled"`
	Priority int    `yaml:"priority" json:"priority"`
}

type PerformanceTuningConfig struct {
	MaxBodyBytes   int64         `yaml:"max_body_bytes" json:"max_body_bytes"`
	MaxHeaderBytes int           `yaml:"max_header_bytes" json:"max_header_bytes"`
	ProxyTimeout   time.Duration `yaml:"proxy_timeout" json:"proxy_timeout"`
}

type ProtectionConfig struct {
	Policy    ProtectionPolicyConfig    `yaml:"policy" json:"policy"`
	IP        IPProtectionConfig        `yaml:"ip" json:"ip"`
	RateLimit RateLimitProtectionConfig `yaml:"ratelimit" json:"ratelimit"`
	Bot       BotProtectionConfig       `yaml:"bot" json:"bot"`
	ACL       ACLProtectionConfig       `yaml:"acl" json:"acl"`
}

type ProtectionPolicyConfig struct {
	WebAttack   string `yaml:"web_attack" json:"web_attack"`
	APISecurity string `yaml:"api_security" json:"api_security"`
	BotCC       string `yaml:"bot_cc" json:"bot_cc"`
	ThreatIntel string `yaml:"threat_intel" json:"threat_intel"`
}

type IPProtectionConfig struct {
	Blacklist           []string                    `yaml:"blacklist" json:"blacklist"`
	Whitelist           []string                    `yaml:"whitelist" json:"whitelist"`
	AccessRules         []IPAccessRuleConfig        `yaml:"access_rules" json:"access_rules"`
	ReputationOverrides map[string]int              `yaml:"reputation_overrides" json:"reputation_overrides"`
	GeoIP               GeoIPConfig                 `yaml:"geoip" json:"geoip"`
	Tags                map[string][]string         `yaml:"tags" json:"tags"`
	ThreatIntel         []ThreatIntelConfig         `yaml:"threat_intel" json:"threat_intel"`
	Providers           []ThreatIntelProviderConfig `yaml:"providers" json:"providers"`
}

type IPAccessRuleConfig struct {
	ID          string   `yaml:"id" json:"id"`
	Name        string   `yaml:"name" json:"name"`
	Description string   `yaml:"description" json:"description"`
	Action      string   `yaml:"action" json:"action"` // allow/block
	Scope       string   `yaml:"scope" json:"scope"`   // global/site/path
	SiteID      string   `yaml:"site_id" json:"site_id"`
	PathPrefix  string   `yaml:"path_prefix" json:"path_prefix"`
	Entries     []string `yaml:"entries" json:"entries"`
	Enabled     bool     `yaml:"enabled" json:"enabled"`
}

type ThreatIntelConfig struct {
	ID         string    `yaml:"id" json:"id"`
	Value      string    `yaml:"value" json:"value"`
	Type       string    `yaml:"type" json:"type"`
	Severity   string    `yaml:"severity" json:"severity"`
	Source     string    `yaml:"source" json:"source"`
	Labels     []string  `yaml:"labels" json:"labels"`
	Action     string    `yaml:"action" json:"action"`
	Confidence float64   `yaml:"confidence" json:"confidence"`
	ExpiresAt  time.Time `yaml:"expires_at" json:"expires_at"`
	Enabled    bool      `yaml:"enabled" json:"enabled"`
}

type ThreatIntelProviderConfig struct {
	ID          string            `yaml:"id" json:"id"`
	Name        string            `yaml:"name" json:"name"`
	Type        string            `yaml:"type" json:"type"`
	Endpoint    string            `yaml:"endpoint" json:"endpoint"`
	APIKey      string            `yaml:"api_key" json:"api_key"`
	Format      string            `yaml:"format" json:"format"`
	Action      string            `yaml:"action" json:"action"`
	MinSeverity string            `yaml:"min_severity" json:"min_severity"`
	Interval    time.Duration     `yaml:"interval" json:"interval"`
	Headers     map[string]string `yaml:"headers" json:"headers"`
	Enabled     bool              `yaml:"enabled" json:"enabled"`
}

type GeoIPConfig struct {
	Enabled           bool                `yaml:"enabled" json:"enabled"`
	Database          string              `yaml:"database" json:"database"`
	PrecisionDatabase string              `yaml:"precision_database" json:"precision_database"`
	BlockedCountries  []string            `yaml:"blocked_countries" json:"blocked_countries"`
	CountryCIDRs      map[string][]string `yaml:"country_cidrs" json:"country_cidrs"`
}

type RateLimitProtectionConfig struct {
	Enabled bool             `yaml:"enabled" json:"enabled"`
	Default RateLimitProfile `yaml:"default" json:"default"`
}

type RateLimitProfile struct {
	Requests int           `yaml:"requests" json:"requests"`
	Window   time.Duration `yaml:"window" json:"window"`
	Burst    int           `yaml:"burst" json:"burst"`
}

type BotProtectionConfig struct {
	Enabled                bool          `yaml:"enabled" json:"enabled"`
	JSChallenge            bool          `yaml:"js_challenge" json:"js_challenge"`
	CAPTCHA                bool          `yaml:"captcha" json:"captcha"`
	CAPTCHAType            string        `yaml:"captcha_type" json:"captcha_type"`
	CAPTCHAMaxAttempts     int           `yaml:"captcha_max_attempts" json:"captcha_max_attempts"`
	ImageCAPTCHALength     int           `yaml:"image_captcha_length" json:"image_captcha_length"`
	ImageCAPTCHAWidth      int           `yaml:"image_captcha_width" json:"image_captcha_width"`
	ImageCAPTCHAHeight     int           `yaml:"image_captcha_height" json:"image_captcha_height"`
	ImageCAPTCHAAudioLimit int           `yaml:"image_captcha_audio_limit" json:"image_captcha_audio_limit"`
	SliderCAPTCHAWidth     int           `yaml:"slider_captcha_width" json:"slider_captcha_width"`
	SliderCAPTCHAHeight    int           `yaml:"slider_captcha_height" json:"slider_captcha_height"`
	SliderCAPTCHAPiece     int           `yaml:"slider_captcha_piece" json:"slider_captcha_piece"`
	SliderCAPTCHATolerance int           `yaml:"slider_captcha_tolerance" json:"slider_captcha_tolerance"`
	SliderCAPTCHAMinDrag   time.Duration `yaml:"slider_captcha_min_drag" json:"slider_captcha_min_drag"`
	ChallengeDifficulty    int           `yaml:"challenge_difficulty" json:"challenge_difficulty"`
	AltchaMaxNumber        int           `yaml:"altcha_max_number" json:"altcha_max_number"`
	AltchaHeaderName       string        `yaml:"altcha_header_name" json:"altcha_header_name"`
	WaitingRoom            bool          `yaml:"waiting_room" json:"waiting_room"`
	WaitingRoomMaxActive   int           `yaml:"waiting_room_max_active" json:"waiting_room_max_active"`
	WaitingRoomTTL         time.Duration `yaml:"waiting_room_ttl" json:"waiting_room_ttl"`
	ChallengeTTL           time.Duration `yaml:"challenge_ttl" json:"challenge_ttl"`
	CookieName             string        `yaml:"cookie_name" json:"cookie_name"`
	Secret                 string        `yaml:"secret" json:"secret"`
	PathPrefixes           []string      `yaml:"path_prefixes" json:"path_prefixes"`
	ExemptPathPrefixes     []string      `yaml:"exempt_path_prefixes" json:"exempt_path_prefixes"`
	AllowedUserAgents      []string      `yaml:"allowed_user_agents" json:"allowed_user_agents"`
	SuspiciousUserAgents   []string      `yaml:"suspicious_user_agents" json:"suspicious_user_agents"`
}

type ACLProtectionConfig struct {
	Enabled bool            `yaml:"enabled" json:"enabled"`
	Rules   []ACLRuleConfig `yaml:"rules" json:"rules"`
}

type ACLRuleConfig struct {
	ID          string `yaml:"id" json:"id"`
	Name        string `yaml:"name" json:"name"`
	Method      string `yaml:"method" json:"method"`
	PathPrefix  string `yaml:"path_prefix" json:"path_prefix"`
	Header      string `yaml:"header" json:"header"`
	HeaderValue string `yaml:"header_value" json:"header_value"`
	Action      string `yaml:"action" json:"action"`
	Severity    string `yaml:"severity" json:"severity"`
	Enabled     bool   `yaml:"enabled" json:"enabled"`
}

type ResponseInspectionConfig struct {
	Enabled           bool     `yaml:"enabled" json:"enabled"`
	MaxBodyBytes      int64    `yaml:"max_body_bytes" json:"max_body_bytes"`
	SensitivePatterns []string `yaml:"sensitive_patterns" json:"sensitive_patterns"`
}

type RewriteRuleConfig struct {
	ID           string `yaml:"id" json:"id"`
	Pattern      string `yaml:"pattern" json:"pattern"`
	Replacement  string `yaml:"replacement" json:"replacement"`
	RedirectCode int    `yaml:"redirect_code" json:"redirect_code"`
	Enabled      bool   `yaml:"enabled" json:"enabled"`
}

type HealthCheckConfig struct {
	Enabled            bool          `yaml:"enabled" json:"enabled"`
	Path               string        `yaml:"path" json:"path"`
	Interval           time.Duration `yaml:"interval" json:"interval"`
	Timeout            time.Duration `yaml:"timeout" json:"timeout"`
	HealthyThreshold   int           `yaml:"healthy_threshold" json:"healthy_threshold"`
	UnhealthyThreshold int           `yaml:"unhealthy_threshold" json:"unhealthy_threshold"`
}

type SiteAccessControlConfig struct {
	AuthEnabled  bool     `yaml:"auth_enabled" json:"auth_enabled"`
	WaitingRoom  bool     `yaml:"waiting_room" json:"waiting_room"`
	DynamicGuard bool     `yaml:"dynamic_guard" json:"dynamic_guard"`
	TrustedCIDRs []string `yaml:"trusted_cidrs" json:"trusted_cidrs"`
}

type EdgeConfig struct {
	Headers     HeaderPolicyConfig      `yaml:"headers" json:"headers"`
	Cache       CachePolicyConfig       `yaml:"cache" json:"cache"`
	Compression CompressionPolicyConfig `yaml:"compression" json:"compression"`
}

type HeaderPolicyConfig struct {
	Enabled bool               `yaml:"enabled" json:"enabled"`
	Rules   []HeaderRuleConfig `yaml:"rules" json:"rules"`
}

type HeaderRuleConfig struct {
	ID         string `yaml:"id" json:"id"`
	Name       string `yaml:"name" json:"name"`
	Operation  string `yaml:"operation" json:"operation"`
	Header     string `yaml:"header" json:"header"`
	Value      string `yaml:"value" json:"value"`
	PathPrefix string `yaml:"path_prefix" json:"path_prefix"`
	Enabled    bool   `yaml:"enabled" json:"enabled"`
}

type CachePolicyConfig struct {
	Enabled      bool          `yaml:"enabled" json:"enabled"`
	Mode         string        `yaml:"mode" json:"mode"`
	TTL          time.Duration `yaml:"ttl" json:"ttl"`
	StatusCodes  []int         `yaml:"status_codes" json:"status_codes"`
	PathPrefixes []string      `yaml:"path_prefixes" json:"path_prefixes"`
	MaxBodyBytes int64         `yaml:"max_body_bytes" json:"max_body_bytes"`
}

type CompressionPolicyConfig struct {
	Enabled      bool     `yaml:"enabled" json:"enabled"`
	Algorithms   []string `yaml:"algorithms" json:"algorithms"`
	Level        int      `yaml:"level" json:"level"`
	MinBytes     int64    `yaml:"min_bytes" json:"min_bytes"`
	ContentTypes []string `yaml:"content_types" json:"content_types"`
}

type StorageConfig struct {
	SQLite        SQLiteConfig        `yaml:"sqlite" json:"sqlite"`
	Redis         RedisConfig         `yaml:"redis" json:"redis"`
	ClickHouse    ClickHouseConfig    `yaml:"clickhouse" json:"clickhouse"`
	VictoriaLogs  VictoriaLogsConfig  `yaml:"victorialogs" json:"victorialogs"`
	PostgreSQL    PostgreSQLConfig    `yaml:"postgresql" json:"postgresql"`
	Elasticsearch ElasticsearchConfig `yaml:"elasticsearch" json:"elasticsearch"`
}

type SQLiteConfig struct {
	Path string `yaml:"path" json:"path"`
}

type RedisConfig struct {
	Enabled bool   `yaml:"enabled" json:"enabled"`
	Address string `yaml:"address" json:"address"`
}

type ClickHouseConfig struct {
	Enabled  bool          `yaml:"enabled" json:"enabled"`
	Endpoint string        `yaml:"endpoint" json:"endpoint"`
	Database string        `yaml:"database" json:"database"`
	Table    string        `yaml:"table" json:"table"`
	Username string        `yaml:"username" json:"username"`
	Password string        `yaml:"password" json:"password"`
	Timeout  time.Duration `yaml:"timeout" json:"timeout"`
}

type VictoriaLogsConfig struct {
	Enabled  bool          `yaml:"enabled" json:"enabled"`
	Endpoint string        `yaml:"endpoint" json:"endpoint"`
	Timeout  time.Duration `yaml:"timeout" json:"timeout"`
}

type PostgreSQLConfig struct {
	Enabled bool          `yaml:"enabled" json:"enabled"`
	DSN     string        `yaml:"dsn" json:"dsn"`
	Table   string        `yaml:"table" json:"table"`
	Timeout time.Duration `yaml:"timeout" json:"timeout"`
}

type ElasticsearchConfig struct {
	Enabled  bool              `yaml:"enabled" json:"enabled"`
	Endpoint string            `yaml:"endpoint" json:"endpoint"`
	Index    string            `yaml:"index" json:"index"`
	Username string            `yaml:"username" json:"username"`
	Password string            `yaml:"password" json:"password"`
	APIKey   string            `yaml:"api_key" json:"api_key"`
	Headers  map[string]string `yaml:"headers" json:"headers"`
	Timeout  time.Duration     `yaml:"timeout" json:"timeout"`
}

type LoggingConfig struct {
	Level  string          `yaml:"level" json:"level"`
	Format string          `yaml:"format" json:"format"`
	Output LogOutputConfig `yaml:"output" json:"output"`
}

type LogOutputConfig struct {
	Type string        `yaml:"type" json:"type"`
	File FileLogConfig `yaml:"file" json:"file"`
}

type FileLogConfig struct {
	Path       string `yaml:"path" json:"path"`
	MaxSize    string `yaml:"max_size" json:"max_size"`
	MaxBackups int    `yaml:"max_backups" json:"max_backups"`
}

type AIConfig struct {
	Enabled      bool   `yaml:"enabled" json:"enabled"`
	Provider     string `yaml:"provider" json:"provider"`
	APIBase      string `yaml:"api_base" json:"api_base"`
	APIKey       string `yaml:"api_key" json:"api_key"`
	APIKeyHeader string `yaml:"api_key_header" json:"api_key_header"`
	Model        string `yaml:"model" json:"model"`
	Async        bool   `yaml:"async" json:"async"`
}

type UpdateConfig struct {
	OTA OTAConfig `yaml:"ota" json:"ota"`
}

type OTAConfig struct {
	Enabled          bool          `yaml:"enabled" json:"enabled"`
	Server           string        `yaml:"server" json:"server"`
	Channel          string        `yaml:"channel" json:"channel"`
	CheckInterval    time.Duration `yaml:"check_interval" json:"check_interval"`
	AutoUpdateRules  bool          `yaml:"auto_update_rules" json:"auto_update_rules"`
	AutoUpdateBinary bool          `yaml:"auto_update_binary" json:"auto_update_binary"`
	VerifySignature  bool          `yaml:"verify_signature" json:"verify_signature"`
	PublicKey        string        `yaml:"public_key" json:"public_key"`
}

type VulnerabilityConfig struct {
	Enabled bool                      `yaml:"enabled" json:"enabled"`
	Feeds   []VulnerabilityFeedConfig `yaml:"feeds" json:"feeds"`
}

type VulnerabilityFeedConfig struct {
	ID          string        `yaml:"id" json:"id"`
	Name        string        `yaml:"name" json:"name"`
	Type        string        `yaml:"type" json:"type"`
	URL         string        `yaml:"url" json:"url"`
	Interval    time.Duration `yaml:"interval" json:"interval"`
	MinSeverity string        `yaml:"min_severity" json:"min_severity"`
	Notify      bool          `yaml:"notify" json:"notify"`
	Enabled     bool          `yaml:"enabled" json:"enabled"`
}

type SchedulerConfig struct {
	Enabled bool                  `yaml:"enabled" json:"enabled"`
	Tasks   []ScheduledTaskConfig `yaml:"tasks" json:"tasks"`
}

type ScheduledTaskConfig struct {
	ID        string        `yaml:"id" json:"id"`
	Name      string        `yaml:"name" json:"name"`
	Type      string        `yaml:"type" json:"type"`
	Schedule  string        `yaml:"schedule" json:"schedule"`
	Every     time.Duration `yaml:"every" json:"every"`
	Frequency string        `yaml:"frequency" json:"frequency"`
	At        string        `yaml:"at" json:"at"`
	Target    string        `yaml:"target" json:"target"`
	Channel   string        `yaml:"channel" json:"channel"`
	Recipient string        `yaml:"recipient" json:"recipient"`
	Period    string        `yaml:"period" json:"period"`
	Format    string        `yaml:"format" json:"format"`
	Keep      int           `yaml:"keep" json:"keep"`
	Enabled   bool          `yaml:"enabled" json:"enabled"`
	CreatedAt time.Time     `yaml:"created_at" json:"created_at"`
}

type MonitorConfig struct {
	Prometheus  PrometheusConfig  `yaml:"prometheus" json:"prometheus"`
	RemoteWrite RemoteWriteConfig `yaml:"remote_write" json:"remote_write"`
	Alerts      AlertEngineConfig `yaml:"alerts" json:"alerts"`
	Notifiers   []NotifierConfig  `yaml:"notifiers" json:"notifiers"`
}

type PrometheusConfig struct {
	Enabled bool   `yaml:"enabled" json:"enabled"`
	Path    string `yaml:"path" json:"path"`
	Public  bool   `yaml:"public" json:"public"`
}

type RemoteWriteConfig struct {
	Enabled  bool          `yaml:"enabled" json:"enabled"`
	Endpoint string        `yaml:"endpoint" json:"endpoint"`
	Interval time.Duration `yaml:"interval" json:"interval"`
	Timeout  time.Duration `yaml:"timeout" json:"timeout"`
}

type AlertEngineConfig struct {
	Enabled bool              `yaml:"enabled" json:"enabled"`
	Rules   []AlertRuleConfig `yaml:"rules" json:"rules"`
}

type AlertRuleConfig struct {
	ID        string        `yaml:"id" json:"id"`
	Name      string        `yaml:"name" json:"name"`
	Metric    string        `yaml:"metric" json:"metric"`
	Operator  string        `yaml:"operator" json:"operator"`
	Threshold float64       `yaml:"threshold" json:"threshold"`
	For       time.Duration `yaml:"for" json:"for"`
	Severity  string        `yaml:"severity" json:"severity"`
	Enabled   bool          `yaml:"enabled" json:"enabled"`
}

type NotifierConfig struct {
	ID       string            `yaml:"id" json:"id"`
	Name     string            `yaml:"name" json:"name"`
	Type     string            `yaml:"type" json:"type"`
	Endpoint string            `yaml:"endpoint" json:"endpoint"`
	To       string            `yaml:"to" json:"to"`
	Token    string            `yaml:"token" json:"token"`
	Headers  map[string]string `yaml:"headers" json:"headers"`
	Enabled  bool              `yaml:"enabled" json:"enabled"`
}

type APISecConfig struct {
	Enabled     bool                     `yaml:"enabled" json:"enabled"`
	Discovery   APIDiscoveryConfig       `yaml:"discovery" json:"discovery"`
	Validation  APIValidationConfig      `yaml:"validation" json:"validation"`
	Auth        APIAuthConfig            `yaml:"auth" json:"auth"`
	RateLimits  []APIEndpointLimitConfig `yaml:"rate_limits" json:"rate_limits"`
	Permissions map[string][]string      `yaml:"permissions" json:"permissions"`
	Audit       AuditConfig              `yaml:"audit" json:"audit"`
}

type APIDiscoveryConfig struct {
	Enabled        bool          `yaml:"enabled" json:"enabled"`
	SampleLimit    int           `yaml:"sample_limit" json:"sample_limit"`
	Window         time.Duration `yaml:"window" json:"window"`
	IgnorePrefixes []string      `yaml:"ignore_prefixes" json:"ignore_prefixes"`
}

type APIValidationConfig struct {
	Enabled bool                      `yaml:"enabled" json:"enabled"`
	Schemas []APIEndpointSchemaConfig `yaml:"schemas" json:"schemas"`
}

type APIEndpointSchemaConfig struct {
	ID              string   `yaml:"id" json:"id"`
	Method          string   `yaml:"method" json:"method"`
	PathPattern     string   `yaml:"path_pattern" json:"path_pattern"`
	RequiredParams  []string `yaml:"required_params" json:"required_params"`
	RequiredHeaders []string `yaml:"required_headers" json:"required_headers"`
	MaxBodyBytes    int64    `yaml:"max_body_bytes" json:"max_body_bytes"`
	Enabled         bool     `yaml:"enabled" json:"enabled"`
}

type APIAuthConfig struct {
	Enabled          bool                          `yaml:"enabled" json:"enabled"`
	JWTIssuers       []string                      `yaml:"jwt_issuers" json:"jwt_issuers"`
	JWTAudiences     []string                      `yaml:"jwt_audiences" json:"jwt_audiences"`
	RequiredScopes   []string                      `yaml:"required_scopes" json:"required_scopes"`
	EndpointPolicies []APIAuthEndpointPolicyConfig `yaml:"endpoint_policies" json:"endpoint_policies"`
	JWTAlgorithms    []string                      `yaml:"jwt_algorithms" json:"jwt_algorithms"`
	JWTSharedSecret  string                        `yaml:"jwt_shared_secret" json:"jwt_shared_secret"`
	JWTPublicKeyFile string                        `yaml:"jwt_public_key_file" json:"jwt_public_key_file"`
	JWTPublicKeyPEM  string                        `yaml:"jwt_public_key_pem" json:"jwt_public_key_pem"`
	JWKSFile         string                        `yaml:"jwks_file" json:"jwks_file"`
	JWKSJSON         string                        `yaml:"jwks_json" json:"jwks_json"`
	JWKSURL          string                        `yaml:"jwks_url" json:"jwks_url"`
	JWKSCacheFile    string                        `yaml:"jwks_cache_file" json:"jwks_cache_file"`
	JWKSRefresh      time.Duration                 `yaml:"jwks_refresh_interval" json:"jwks_refresh_interval"`
}

type APIAuthEndpointPolicyConfig struct {
	ID             string   `yaml:"id" json:"id"`
	Method         string   `yaml:"method" json:"method"`
	PathPattern    string   `yaml:"path_pattern" json:"path_pattern"`
	JWTIssuers     []string `yaml:"jwt_issuers" json:"jwt_issuers"`
	JWTAudiences   []string `yaml:"jwt_audiences" json:"jwt_audiences"`
	RequiredScopes []string `yaml:"required_scopes" json:"required_scopes"`
	Enabled        bool     `yaml:"enabled" json:"enabled"`
}

type APIEndpointLimitConfig struct {
	ID          string        `yaml:"id" json:"id"`
	Method      string        `yaml:"method" json:"method"`
	PathPattern string        `yaml:"path_pattern" json:"path_pattern"`
	Requests    int           `yaml:"requests" json:"requests"`
	Window      time.Duration `yaml:"window" json:"window"`
	Enabled     bool          `yaml:"enabled" json:"enabled"`
}

type AuditConfig struct {
	Enabled bool   `yaml:"enabled" json:"enabled"`
	Path    string `yaml:"path" json:"path"`
}
