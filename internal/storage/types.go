// Package storage defines interfaces for data persistence.
package storage

import (
	"context"
	"time"
)

// LogEntry represents a single WAF log entry (attack or access).
// WAF 日志条目（攻击日志或访问日志）。
type LogEntry struct {
	ID         string         `json:"id"`
	Timestamp  time.Time      `json:"timestamp"`
	TraceID    string         `json:"trace_id"` // 溯源 ID / Trace ID
	SiteID     string         `json:"site_id"`
	ClientIP   string         `json:"client_ip"`
	Method     string         `json:"method"`
	URI        string         `json:"uri"`
	StatusCode int            `json:"status_code"`
	Action     string         `json:"action"` // pass/block/challenge/log
	DetectorID string         `json:"detector_id"`
	Category   string         `json:"category"` // sqli/xss/rce/lfi...
	Severity   string         `json:"severity"`
	Message    string         `json:"message"`
	Payload    string         `json:"payload"`
	UserAgent  string         `json:"user_agent"`
	Country    string         `json:"country"` // GeoIP 国家
	Latency    time.Duration  `json:"latency"`
	Tags       []string       `json:"tags"` // IP 行为标注标签 / Behavior tags
	Metadata   map[string]any `json:"metadata"`
}

// LogSink is the interface for log output backends.
// Implementations include: local file, ClickHouse, VictoriaLogs, PostgreSQL.
// 日志输出后端接口。实现包括：本地文件、ClickHouse、VictoriaLogs、PostgreSQL。
type LogSink interface {
	// Write writes a log entry to the sink.
	// 写入一条日志。
	Write(ctx context.Context, entry *LogEntry) error

	// Query queries log entries with filters.
	// 按条件查询日志。
	Query(ctx context.Context, filter LogFilter) ([]LogEntry, int64, error)

	// Flush forces pending writes to be committed.
	// 强制提交挂起的写入。
	Flush(ctx context.Context) error

	// Close gracefully shuts down the sink.
	// 优雅关闭。
	Close() error
}

// LogFilter defines query filters for log entries.
// 日志查询过滤条件。
type LogFilter struct {
	SiteID    string    `json:"site_id,omitempty"`
	ClientIP  string    `json:"client_ip,omitempty"`
	Category  string    `json:"category,omitempty"`
	Action    string    `json:"action,omitempty"`
	TraceID   string    `json:"trace_id,omitempty"`
	Tags      []string  `json:"tags,omitempty"`
	StartTime time.Time `json:"start_time,omitempty"`
	EndTime   time.Time `json:"end_time,omitempty"`
	Offset    int       `json:"offset,omitempty"`
	Limit     int       `json:"limit,omitempty"`
}

// Store is the interface for configuration data persistence (SQLite).
// 配置数据持久化接口（SQLite）。
type Store interface {
	// Migrate runs database migrations.
	// 执行数据库迁移。
	Migrate(ctx context.Context) error

	// Close gracefully shuts down the store.
	// 优雅关闭。
	Close() error

	// Sites
	SiteStore

	// Rules
	RuleStore

	// Users
	UserStore

	// Sessions
	SessionStore

	// Notifications
	NotificationStore
}

// NotificationStore manages persistent, user-scoped management notifications.
type NotificationStore interface {
	ListNotifications(ctx context.Context, userID string, filter NotificationFilter) ([]Notification, int64, int64, int64, error)
	UpdateNotification(ctx context.Context, userID, id string, patch NotificationPatch) (*Notification, error)
	MarkAllNotificationsRead(ctx context.Context, userID string) (int64, error)
	ClearNotifications(ctx context.Context, userID string) (int64, error)
	CreateNotification(ctx context.Context, notification *Notification) error
}

type Notification struct {
	ID        string    `json:"id"`
	UserID    string    `json:"-"`
	Type      string    `json:"type"`
	Title     string    `json:"title"`
	Message   string    `json:"message"`
	Target    string    `json:"target,omitempty"`
	Read      bool      `json:"read"`
	Pinned    bool      `json:"pinned"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type NotificationFilter struct {
	State  string
	Offset int
	Limit  int
}

type NotificationPatch struct {
	Read   *bool
	Pinned *bool
}

// SiteStore manages site configurations.
// 站点配置管理。
type SiteStore interface {
	ListSites(ctx context.Context) ([]Site, error)
	GetSite(ctx context.Context, id string) (*Site, error)
	CreateSite(ctx context.Context, site *Site) error
	UpdateSite(ctx context.Context, site *Site) error
	DeleteSite(ctx context.Context, id string) error
}

// RuleStore manages WAF rules.
// WAF 规则管理。
type RuleStore interface {
	ListRules(ctx context.Context, siteID string) ([]Rule, error)
	GetRule(ctx context.Context, id string) (*Rule, error)
	CreateRule(ctx context.Context, rule *Rule) error
	UpdateRule(ctx context.Context, rule *Rule) error
	DeleteRule(ctx context.Context, id string) error
}

// UserStore manages admin users.
// 管理员用户管理。
type UserStore interface {
	GetUserByUsername(ctx context.Context, username string) (*User, error)
	CreateUser(ctx context.Context, user *User) error
	UpdateUser(ctx context.Context, user *User) error
	DeleteUser(ctx context.Context, id string) error
	ListUsers(ctx context.Context) ([]User, error)
}

// SessionStore manages admin bearer-token sessions.
// 管理端 Bearer token 会话管理。
type SessionStore interface {
	CreateSession(ctx context.Context, session *Session) error
	RotateSession(ctx context.Context, oldID, userID string, next *Session) error
	RevokeSession(ctx context.Context, id, userID string) error
	RevokeUserSessions(ctx context.Context, userID string, exceptID string) error
	IsSessionActive(ctx context.Context, id, userID string, now time.Time) (bool, error)
	PruneSessions(ctx context.Context, before time.Time) (int64, error)
}

// Site represents a protected site configuration.
// 受保护站点配置。
type Site struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Domains     []string     `json:"domains"`   // 监听域名
	Upstreams   []string     `json:"upstreams"` // 上游服务器
	ListenPort  int          `json:"listen_port"`
	LoadBalance string       `json:"loadbalance"`
	EnableSSL   bool         `json:"enable_ssl"`
	CertFile    string       `json:"cert_file,omitempty"`
	KeyFile     string       `json:"key_file,omitempty"`
	WAFEnabled  bool         `json:"waf_enabled"`
	WAFMode     string       `json:"waf_mode"`
	Advanced    SiteAdvanced `json:"advanced"`
	Enabled     bool         `json:"enabled"`
	CreatedAt   time.Time    `json:"created_at"`
	UpdatedAt   time.Time    `json:"updated_at"`
}

type SiteAdvanced struct {
	Certificate   CertificateConfig     `json:"certificate"`
	Origin        OriginConfig          `json:"origin"`
	HealthCheck   SiteHealthCheckConfig `json:"health_check"`
	Protection    SiteProtectionConfig  `json:"protection"`
	Policy        SiteProtectionPolicy  `json:"policy"`
	Response      SiteResponseConfig    `json:"response"`
	Rewrite       []SiteRewriteRule     `json:"rewrite"`
	AccessControl SiteAccessControl     `json:"access_control"`
}

type CertificateConfig struct {
	Mode          string         `json:"mode"`
	CertPEM       string         `json:"cert_pem,omitempty"`
	KeyPEM        string         `json:"key_pem,omitempty"`
	AutoRenew     bool           `json:"auto_renew"`
	ForceHTTPS    bool           `json:"force_https"`
	HSTS          bool           `json:"hsts"`
	MinTLSVersion string         `json:"min_tls_version"`
	ACME          SiteACMEConfig `json:"acme"`
}

type SiteACMEConfig struct {
	ProviderID    string            `json:"provider_id"`
	DNSAPI        string            `json:"dns_api"`
	AccountEmail  string            `json:"account_email"`
	Server        string            `json:"server"`
	KeyType       string            `json:"key_type"`
	ACMESHPath    string            `json:"acme_sh_path"`
	Home          string            `json:"home"`
	CertDir       string            `json:"cert_dir"`
	ReloadCommand string            `json:"reload_command"`
	Domains       []string          `json:"domains"`
	Env           map[string]string `json:"env"`
	Notify        bool              `json:"notify"`
	LastStatus    string            `json:"last_status"`
	LastRunID     string            `json:"last_run_id"`
	LastIssuedAt  time.Time         `json:"last_issued_at,omitempty"`
	ExpiresAt     time.Time         `json:"expires_at,omitempty"`
}

type OriginConfig struct {
	Scheme        string `json:"scheme"`
	PassHost      bool   `json:"pass_host"`
	HostHeader    string `json:"host_header"`
	ProxyTimeout  string `json:"proxy_timeout"`
	MaxBodyBytes  int64  `json:"max_body_bytes"`
	MaxHeaderSize int    `json:"max_header_size"`
}

type SiteHealthCheckConfig struct {
	Enabled            bool   `json:"enabled"`
	Path               string `json:"path"`
	Interval           string `json:"interval"`
	Timeout            string `json:"timeout"`
	HealthyThreshold   int    `json:"healthy_threshold"`
	UnhealthyThreshold int    `json:"unhealthy_threshold"`
}

type SiteProtectionConfig struct {
	SemanticSQL   bool `json:"semantic_sql"`
	SemanticXSS   bool `json:"semantic_xss"`
	SemanticRCE   bool `json:"semantic_rce"`
	SemanticLFI   bool `json:"semantic_lfi"`
	SemanticXXE   bool `json:"semantic_xxe"`
	SemanticSSRF  bool `json:"semantic_ssrf"`
	SemanticNoSQL bool `json:"semantic_nosql"`
	SemanticSSTI  bool `json:"semantic_ssti"`
	Bot           bool `json:"bot"`
	RateLimit     bool `json:"ratelimit"`
	ACL           bool `json:"acl"`
	APISecurity   bool `json:"apisec"`
}

type SiteProtectionPolicy struct {
	WebAttack   string `json:"web_attack"`
	APISecurity string `json:"api_security"`
	BotCC       string `json:"bot_cc"`
	ThreatIntel string `json:"threat_intel"`
}

type SiteResponseConfig struct {
	Enabled           bool     `json:"enabled"`
	MaxBodyBytes      int64    `json:"max_body_bytes"`
	SensitivePatterns []string `json:"sensitive_patterns"`
}

type SiteRewriteRule struct {
	ID           string `json:"id"`
	Pattern      string `json:"pattern"`
	Replacement  string `json:"replacement"`
	RedirectCode int    `json:"redirect_code"`
	Enabled      bool   `json:"enabled"`
}

type SiteAccessControl struct {
	AuthEnabled  bool     `json:"auth_enabled"`
	WaitingRoom  bool     `json:"waiting_room"`
	DynamicGuard bool     `json:"dynamic_guard"`
	TrustedCIDRs []string `json:"trusted_cidrs"`
}

// Rule represents a custom WAF rule.
// 自定义 WAF 规则。
type Rule struct {
	ID          string `json:"id"`
	SiteID      string `json:"site_id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Pattern     string `json:"pattern"`
	Location    string `json:"location"` // uri/header/body/cookie
	Action      string `json:"action"`   // block/log/challenge
	Severity    string `json:"severity"`
	Enabled     bool   `json:"enabled"`
	Priority    int    `json:"priority"`
}

// User represents an admin user.
// 管理员用户。
type User struct {
	ID           string    `json:"id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"-"`
	Role         string    `json:"role"` // admin/readonly/custom
	TwoFAEnabled bool      `json:"two_fa_enabled"`
	TwoFASecret  string    `json:"-"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// Session represents a revocable admin API session.
// 可撤销的管理端 API 会话。
type Session struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	Username  string    `json:"username"`
	Role      string    `json:"role"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	RevokedAt time.Time `json:"revoked_at,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}
