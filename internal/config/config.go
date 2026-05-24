// Package config handles YAML configuration loading, validation, and hot-reloading.
// 负责 YAML 配置加载、校验和热重载。
package config

import "time"

type Config struct {
	Server     ServerConfig     `yaml:"server" json:"server"`
	TLS        TLSConfig        `yaml:"tls" json:"tls"`
	Setup      SetupConfig      `yaml:"setup" json:"setup"`
	Sites      []SiteConfig     `yaml:"sites" json:"sites"`
	Protection ProtectionConfig `yaml:"protection" json:"protection"`
	Storage    StorageConfig    `yaml:"storage" json:"storage"`
	Logging    LoggingConfig    `yaml:"logging" json:"logging"`
	AI         AIConfig         `yaml:"ai" json:"ai"`
	Update     UpdateConfig     `yaml:"update" json:"update"`
	Scheduler  SchedulerConfig  `yaml:"scheduler" json:"scheduler"`
}

type ServerConfig struct {
	Listen       string        `yaml:"listen" json:"listen"`
	ListenTLS    string        `yaml:"listen_tls" json:"listen_tls"`
	AdminListen  string        `yaml:"admin_listen" json:"admin_listen"`
	ReadTimeout  time.Duration `yaml:"read_timeout" json:"read_timeout"`
	WriteTimeout time.Duration `yaml:"write_timeout" json:"write_timeout"`
	IdleTimeout  time.Duration `yaml:"idle_timeout" json:"idle_timeout"`
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
	Enabled         bool                     `yaml:"enabled" json:"enabled"`
	Mode            string                   `yaml:"mode" json:"mode"`
	SemanticEngines SemanticEngineSwitches   `yaml:"semantic_engines" json:"semantic_engines"`
	CustomRules     []CustomRuleConfig       `yaml:"custom_rules" json:"custom_rules"`
	Performance     PerformanceTuningConfig  `yaml:"performance" json:"performance"`
	Response        ResponseInspectionConfig `yaml:"response" json:"response"`
	Rewrite         []RewriteRuleConfig      `yaml:"rewrite" json:"rewrite"`
	HealthCheck     HealthCheckConfig        `yaml:"health_check" json:"health_check"`
}

type SemanticEngineSwitches struct {
	SQL  bool `yaml:"sql" json:"sql"`
	XSS  bool `yaml:"xss" json:"xss"`
	RCE  bool `yaml:"rce" json:"rce"`
	LFI  bool `yaml:"lfi" json:"lfi"`
	XXE  bool `yaml:"xxe" json:"xxe"`
	SSRF bool `yaml:"ssrf" json:"ssrf"`
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
	IP        IPProtectionConfig        `yaml:"ip" json:"ip"`
	RateLimit RateLimitProtectionConfig `yaml:"ratelimit" json:"ratelimit"`
	Bot       BotProtectionConfig       `yaml:"bot" json:"bot"`
	ACL       ACLProtectionConfig       `yaml:"acl" json:"acl"`
}

type IPProtectionConfig struct {
	Blacklist []string            `yaml:"blacklist" json:"blacklist"`
	Whitelist []string            `yaml:"whitelist" json:"whitelist"`
	GeoIP     GeoIPConfig         `yaml:"geoip" json:"geoip"`
	Tags      map[string][]string `yaml:"tags" json:"tags"`
}

type GeoIPConfig struct {
	Enabled          bool                `yaml:"enabled" json:"enabled"`
	Database         string              `yaml:"database" json:"database"`
	BlockedCountries []string            `yaml:"blocked_countries" json:"blocked_countries"`
	CountryCIDRs     map[string][]string `yaml:"country_cidrs" json:"country_cidrs"`
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
	Enabled     bool `yaml:"enabled" json:"enabled"`
	JSChallenge bool `yaml:"js_challenge" json:"js_challenge"`
	CAPTCHA     bool `yaml:"captcha" json:"captcha"`
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

type StorageConfig struct {
	SQLite SQLiteConfig `yaml:"sqlite" json:"sqlite"`
	Redis  RedisConfig  `yaml:"redis" json:"redis"`
}

type SQLiteConfig struct {
	Path string `yaml:"path" json:"path"`
}

type RedisConfig struct {
	Enabled bool   `yaml:"enabled" json:"enabled"`
	Address string `yaml:"address" json:"address"`
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
	Enabled bool   `yaml:"enabled" json:"enabled"`
	APIBase string `yaml:"api_base" json:"api_base"`
	APIKey  string `yaml:"api_key" json:"api_key"`
	Model   string `yaml:"model" json:"model"`
	Async   bool   `yaml:"async" json:"async"`
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
	Target    string        `yaml:"target" json:"target"`
	Keep      int           `yaml:"keep" json:"keep"`
	Enabled   bool          `yaml:"enabled" json:"enabled"`
	CreatedAt time.Time     `yaml:"created_at" json:"created_at"`
}
