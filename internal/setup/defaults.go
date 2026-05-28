package setup

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	DefaultConfigFile = "cheesewaf.yaml"
	DefaultCertDir    = "certs"
	DefaultLogDir     = "logs"
	DefaultRuntimeDir = "run"
	DefaultSQLiteFile = "cheesewaf.db"

	DefaultAdminCertFile = "admin.crt"
	DefaultAdminKeyFile  = "admin.key"

	DefaultAdminListen = "127.0.0.1:9443"
	DefaultHTTPListen  = ":80"
	DefaultHTTPSListen = ":443"

	defaultCertificateYears = 10
)

// DefaultCertificateHosts are included in the admin self-signed certificate.
// 默认管理端自签名证书 SAN。
var DefaultCertificateHosts = []string{"127.0.0.1", "::1", "localhost"}

// DefaultOptions controls default file generation.
// 默认文件生成参数。
type DefaultOptions struct {
	DataDir    string
	ConfigPath string
	Hostnames  []string
	ValidFor   time.Duration
	Overwrite  bool
}

// DefaultPaths contains the resolved paths used by setup.
// 初始化使用的解析后路径。
type DefaultPaths struct {
	DataDir    string
	ConfigFile string
	CertDir    string
	CertFile   string
	KeyFile    string
	LogDir     string
	RuntimeDir string
	SQLiteFile string
}

// DefaultBundle reports files created or reused by EnsureDefaults.
// EnsureDefaults 创建或复用的默认文件集合。
type DefaultBundle struct {
	Paths DefaultPaths
}

// EnsureDefaults creates the runtime layout, default config, and admin TLS pair.
// It avoids overwriting existing files unless Overwrite is set.
// 创建运行目录、默认配置和管理端 TLS 证书；默认不覆盖已有文件。
func EnsureDefaults(opts DefaultOptions) (*DefaultBundle, error) {
	opts = normalizeDefaultOptions(opts)
	paths := ResolveDefaultPaths(opts)

	for _, dir := range []string{paths.DataDir, paths.CertDir, paths.LogDir, paths.RuntimeDir} {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return nil, fmt.Errorf("create directory %s: %w", dir, err)
		}
	}

	if err := writeFile(paths.ConfigFile, DefaultConfigYAML(paths), 0o640, opts.Overwrite); err != nil {
		return nil, fmt.Errorf("write default config: %w", err)
	}

	if opts.Overwrite || missing(paths.CertFile) || missing(paths.KeyFile) {
		if err := GenerateSelfSignedCertificate(paths.CertFile, paths.KeyFile, opts.Hostnames, opts.ValidFor); err != nil {
			return nil, err
		}
	}

	return &DefaultBundle{Paths: paths}, nil
}

// ResolveDefaultPaths returns setup paths without touching the filesystem.
// 仅解析默认路径，不写入文件。
func ResolveDefaultPaths(opts DefaultOptions) DefaultPaths {
	opts = normalizeDefaultOptions(opts)
	return DefaultPaths{
		DataDir:    opts.DataDir,
		ConfigFile: opts.ConfigPath,
		CertDir:    filepath.Join(opts.DataDir, DefaultCertDir),
		CertFile:   filepath.Join(opts.DataDir, DefaultCertDir, DefaultAdminCertFile),
		KeyFile:    filepath.Join(opts.DataDir, DefaultCertDir, DefaultAdminKeyFile),
		LogDir:     filepath.Join(opts.DataDir, DefaultLogDir),
		RuntimeDir: filepath.Join(opts.DataDir, DefaultRuntimeDir),
		SQLiteFile: filepath.Join(opts.DataDir, DefaultSQLiteFile),
	}
}

// DefaultConfigYAML returns the bootstrap configuration used before the
// database-backed configuration store is initialized.
// 返回数据库配置存储初始化前使用的启动配置。
func DefaultConfigYAML(paths DefaultPaths) []byte {
	return []byte(fmt.Sprintf(`# CheeseWAF bootstrap configuration.
# Runtime changes will be stored in SQLite after the setup wizard completes.
server:
  listen: %s
  listen_tls: %s
  listen_http3: ""
  admin_listen: %s
  http3:
    enabled: false
    zero_rtt: false

tls:
  auto_cert: false
  cert_file: %s
  key_file: %s
  min_version: "1.3"
  hsts: true

setup:
  data_dir: %s
  runtime_dir: %s
  three_end_unified: true

storage:
  sqlite:
    path: %s
  clickhouse:
    enabled: false
    database: "default"
    table: "cheesewaf_logs"
    timeout: "10s"
  victorialogs:
    enabled: false
    timeout: "10s"
  postgresql:
    enabled: false
    table: "cheesewaf_logs"
    timeout: "10s"

logging:
  level: "info"
  format: "json"
  output:
    type: "file"
    file:
      path: %s
      max_size: "100MB"
      max_backups: 10

protection:
  ip:
    whitelist:
      - "127.0.0.1"
      - "::1"
    blacklist: []
    tags: {}
    threat_intel: []
  ratelimit:
    enabled: true
    default:
      requests: 100
      window: "60s"
      burst: 20
  bot:
    enabled: false
    js_challenge: true
    captcha: false
    challenge_ttl: "30m"
    cookie_name: "cheesewaf_js_clearance"
    secret: "change-me-in-production"
    path_prefixes:
      - "/"
    exempt_path_prefixes:
      - "/health"
      - "/api/"
    allowed_user_agents: []
    suspicious_user_agents:
      - "curl"
      - "python-requests"
      - "sqlmap"
      - "nikto"
      - "nuclei"
      - "masscan"
      - "zgrab"
      - "httpclient"
  acl:
    enabled: true
    rules: []

ai:
  enabled: false

update:
  ota:
    enabled: false
    channel: "stable"
    check_interval: "6h"
    auto_update_rules: true
    auto_update_binary: false
    verify_signature: true

scheduler:
  enabled: true
  tasks:
    - id: "log-cleanup"
      name: "Log cleanup"
      type: "cleanup"
      every: "24h"
      target: %s
      keep: 14
      enabled: true
    - id: "security-daily-report"
      name: "Security daily report"
      type: "security_report"
      frequency: "daily"
      at: "08:00"
      channel: "file"
      recipient: %s
      period: "daily"
      format: "markdown"
      enabled: false

edge:
  headers:
    enabled: true
    rules:
      - id: "set-edge-marker"
        name: "Set edge marker"
        operation: "set"
        header: "X-CheeseWAF"
        value: "edge"
        enabled: true
  cache:
    enabled: true
    mode: "public"
    ttl: "5m"
    status_codes: [200, 304]
    path_prefixes: ["/assets/", "/static/"]
    max_body_bytes: 2097152
  compression:
    enabled: true
    algorithms: ["gzip"]
    level: 5
    min_bytes: 1024
    content_types:
      - "text/"
      - "application/json"
      - "application/javascript"
      - "application/xml"
      - "image/svg+xml"

monitor:
  prometheus:
    enabled: true
    path: "/metrics"
  remote_write:
    enabled: false
    interval: "30s"
    timeout: "10s"
  alerts:
    enabled: true
    rules:
      - id: "high-block-rate"
        name: "High block rate"
        metric: "cheesewaf_blocked_total"
        operator: ">"
        threshold: 100
        for: "5m"
        severity: "high"
        enabled: true
  notifiers:
    - id: "default-webhook"
      name: "Default webhook"
      type: "webhook"
      enabled: false

apisec:
  enabled: true
  discovery:
    enabled: true
    sample_limit: 500
    window: "1h"
    ignore_prefixes: ["/assets/", "/static/", "/favicon"]
  validation:
    enabled: true
    schemas: []
  auth:
    enabled: false
  rate_limits:
    - id: "login-api"
      method: "POST"
      path_pattern: "^/api/auth/login$"
      requests: 10
      window: "1m"
      enabled: true
  permissions:
    admin: ["*"]
    readonly: ["read:*"]
  audit:
    enabled: true
    path: %s
`, quoteYAML(DefaultHTTPListen),
		quoteYAML(DefaultHTTPSListen),
		quoteYAML(DefaultAdminListen),
		quoteYAML(paths.CertFile),
		quoteYAML(paths.KeyFile),
		quoteYAML(paths.DataDir),
		quoteYAML(paths.RuntimeDir),
		quoteYAML(paths.SQLiteFile),
		quoteYAML(filepath.Join(paths.LogDir, "access.log")),
		quoteYAML(paths.LogDir),
		quoteYAML(filepath.Join(paths.DataDir, "reports")),
		quoteYAML(filepath.Join(paths.LogDir, "audit.log")),
	))
}

// GenerateSelfSignedCertificate writes an ECDSA P-256 self-signed certificate
// for the admin interface.
// 为管理端生成 ECDSA P-256 自签名证书。
func GenerateSelfSignedCertificate(certFile, keyFile string, hosts []string, validFor time.Duration) error {
	if certFile == "" || keyFile == "" {
		return errors.New("cert and key paths are required")
	}
	if validFor <= 0 {
		validFor = time.Hour * 24 * 365 * defaultCertificateYears
	}
	if len(hosts) == 0 {
		hosts = DefaultCertificateHosts
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate private key: %w", err)
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return fmt.Errorf("generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "CheeseWAF Admin",
			Organization: []string{"CheeseWAF"},
		},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(validFor),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	for _, host := range hosts {
		host = strings.TrimSpace(host)
		if host == "" {
			continue
		}
		if ip := net.ParseIP(host); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
			continue
		}
		template.DNSNames = append(template.DNSNames, host)
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("create certificate: %w", err)
	}

	keyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("marshal private key: %w", err)
	}

	var certPEM bytes.Buffer
	if err := pem.Encode(&certPEM, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return fmt.Errorf("encode certificate: %w", err)
	}

	var keyPEM bytes.Buffer
	if err := pem.Encode(&keyPEM, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}); err != nil {
		return fmt.Errorf("encode private key: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(certFile), 0o750); err != nil {
		return fmt.Errorf("create cert directory: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(keyFile), 0o750); err != nil {
		return fmt.Errorf("create key directory: %w", err)
	}
	if err := os.WriteFile(certFile, certPEM.Bytes(), 0o644); err != nil {
		return fmt.Errorf("write certificate: %w", err)
	}
	if err := os.WriteFile(keyFile, keyPEM.Bytes(), 0o600); err != nil {
		return fmt.Errorf("write private key: %w", err)
	}
	return nil
}

func normalizeDefaultOptions(opts DefaultOptions) DefaultOptions {
	if opts.DataDir == "" {
		opts.DataDir = DefaultDataDir
	}
	if opts.ConfigPath == "" {
		opts.ConfigPath = filepath.Join(opts.DataDir, DefaultConfigFile)
	}
	if len(opts.Hostnames) == 0 {
		opts.Hostnames = append([]string(nil), DefaultCertificateHosts...)
	}
	if opts.ValidFor <= 0 {
		opts.ValidFor = time.Hour * 24 * 365 * defaultCertificateYears
	}
	return opts
}

func writeFile(path string, contents []byte, perm os.FileMode, overwrite bool) error {
	if !overwrite && !missing(path) {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	return os.WriteFile(path, contents, perm)
}

func missing(path string) bool {
	_, err := os.Stat(path)
	return errors.Is(err, os.ErrNotExist)
}

func quoteYAML(value string) string {
	return fmt.Sprintf("%q", filepath.ToSlash(value))
}
