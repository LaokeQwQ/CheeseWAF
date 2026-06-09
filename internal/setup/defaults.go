package setup

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
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

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

const (
	DefaultConfigFile = "cheesewaf.yaml"
	DefaultCertDir    = "certs"
	DefaultLogDir     = "logs"
	DefaultRuntimeDir = "run"
	DefaultSQLiteFile = "cheesewaf.db"

	DefaultAdminCertFile  = "admin.crt"
	DefaultAdminKeyFile   = "admin.key"
	DefaultAdminCAFile    = "admin-ca.crt"
	DefaultAdminCAKeyFile = "admin-ca.key"

	DefaultAdminListen = "127.0.0.1:9443"
	DefaultHTTPListen  = ":80"
	DefaultHTTPSListen = ":443"

	defaultLeafCertificateDays = 397
	defaultCACertificateYears  = 10
	defaultCACommonName        = "CheeseWAF Sign SSL CA"
	defaultOrganization        = "CheeseCloud Technology Ltc."
)

// DefaultCertificateHosts are included in the admin certificate SAN.
// 默认管理端证书 SAN。
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
	CAFile     string
	CAKeyFile  string
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

	if opts.Overwrite || missing(paths.CertFile) || missing(paths.KeyFile) || missing(paths.CAFile) || missing(paths.CAKeyFile) {
		if err := GenerateAdminCertificateBundle(paths.CertFile, paths.KeyFile, paths.CAFile, paths.CAKeyFile, opts.Hostnames, opts.ValidFor); err != nil {
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
		CAFile:     filepath.Join(opts.DataDir, DefaultCertDir, DefaultAdminCAFile),
		CAKeyFile:  filepath.Join(opts.DataDir, DefaultCertDir, DefaultAdminCAKeyFile),
		LogDir:     filepath.Join(opts.DataDir, DefaultLogDir),
		RuntimeDir: filepath.Join(opts.DataDir, DefaultRuntimeDir),
		SQLiteFile: filepath.Join(opts.DataDir, DefaultSQLiteFile),
	}
}

// DefaultConfigYAML returns the bootstrap configuration used before the
// database-backed configuration store is initialized.
// 返回数据库配置存储初始化前使用的启动配置。
func DefaultConfigYAML(paths DefaultPaths) []byte {
	botSecret := bootstrapSecret()
	return []byte(fmt.Sprintf(`# CheeseWAF bootstrap configuration.
# Runtime changes will be stored in SQLite after the setup wizard completes.
server:
  listen: %s
  listen_tls: %s
  listen_http3: ""
  admin_listen: %s
  admin_public: false
  admin_tls:
    enabled: false
    cert_file: %s
    key_file: %s
    self_signed: true
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

console:
  login:
    captcha:
      enabled: true
      max_number: 75000
      ttl: "120s"
    background:
      enabled: false
      type: "auto"
      url: ""

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
  policy:
    web_attack: "smart"
    api_security: "smart"
    bot_cc: "smart"
    threat_intel: "smart"
  ip:
    whitelist:
      - "127.0.0.1"
      - "::1"
    blacklist: []
    access_rules: []
    reputation_overrides: {}
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
    challenge_difficulty: 4
    altcha_max_number: 75000
    altcha_header_name: "X-CheeseWAF-Altcha"
    waiting_room: false
    waiting_room_max_active: 1000
    waiting_room_ttl: "5m"
    challenge_ttl: "30m"
    cookie_name: "cheesewaf_js_clearance"
    secret: %s
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
  provider: "openai"
  api_base: "https://api.openai.com/v1"
  api_key: ""
  model: "gpt-4o-mini"
  async: true

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
    public: false
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
    jwt_issuers: []
    jwt_audiences: []
    required_scopes: []
    endpoint_policies: []
    jwt_algorithms: []
    jwt_shared_secret: ""
    jwt_public_key_file: ""
    jwt_public_key_pem: ""
    jwks_file: ""
    jwks_json: ""
    jwks_url: ""
    jwks_cache_file: "./data/apisec-jwks-cache.json"
    jwks_refresh_interval: "1h"
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
		quoteYAML(paths.CertFile),
		quoteYAML(paths.KeyFile),
		quoteYAML(paths.DataDir),
		quoteYAML(paths.RuntimeDir),
		quoteYAML(paths.SQLiteFile),
		quoteYAML(filepath.Join(paths.LogDir, "access.log")),
		quoteYAML(botSecret),
		quoteYAML(paths.LogDir),
		quoteYAML(filepath.Join(paths.DataDir, "reports")),
		quoteYAML(filepath.Join(paths.LogDir, "audit.log")),
	))
}

// GenerateSelfSignedCertificate writes an ECDSA P-256 admin certificate chain
// signed by a local self-signed CheeseWAF CA.
// 为管理端生成由本地 CheeseWAF CA 签发的 ECDSA P-256 证书链。
func GenerateSelfSignedCertificate(certFile, keyFile string, hosts []string, validFor time.Duration) error {
	caFile := filepath.Join(filepath.Dir(certFile), DefaultAdminCAFile)
	caKeyFile := filepath.Join(filepath.Dir(keyFile), DefaultAdminCAKeyFile)
	return GenerateAdminCertificateBundle(certFile, keyFile, caFile, caKeyFile, hosts, validFor)
}

// GenerateAdminCertificateBundle writes a local CA certificate/key plus a
// server-auth leaf certificate/key for the admin interface. The leaf cert file
// contains the leaf first and CA second, matching common TLS chain layout.
// 生成本地 CA 与管理端叶子证书；叶子证书文件按 leaf + CA 链顺序写入。
func GenerateAdminCertificateBundle(certFile, keyFile, caFile, caKeyFile string, hosts []string, validFor time.Duration) error {
	if certFile == "" || keyFile == "" {
		return errors.New("cert and key paths are required")
	}
	if caFile == "" || caKeyFile == "" {
		return errors.New("ca cert and ca key paths are required")
	}
	if validFor <= 0 {
		validFor = time.Hour * 24 * defaultLeafCertificateDays
	}
	if len(hosts) == 0 {
		hosts = DefaultCertificateHosts
	}

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate ca private key: %w", err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate leaf private key: %w", err)
	}

	caSerial, err := certificateSerial()
	if err != nil {
		return err
	}
	leafSerial, err := certificateSerial()
	if err != nil {
		return err
	}
	now := time.Now()
	caSKI, err := subjectKeyID(&caKey.PublicKey)
	if err != nil {
		return err
	}
	leafSKI, err := subjectKeyID(&leafKey.PublicKey)
	if err != nil {
		return err
	}

	caTemplate := x509.Certificate{
		SerialNumber: caSerial,
		Subject: pkix.Name{
			CommonName:   defaultCACommonName,
			Organization: []string{defaultOrganization},
		},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour * 24 * 365 * defaultCACertificateYears),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		SubjectKeyId:          caSKI,
	}

	leafTemplate := x509.Certificate{
		SerialNumber: leafSerial,
		Subject: pkix.Name{
			CommonName:   "CheeseWAF Admin",
			Organization: []string{defaultOrganization},
		},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(validFor),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		SubjectKeyId:          leafSKI,
		AuthorityKeyId:        caSKI,
	}

	for _, host := range hosts {
		host = strings.TrimSpace(host)
		if host == "" {
			continue
		}
		if ip := net.ParseIP(host); ip != nil {
			leafTemplate.IPAddresses = append(leafTemplate.IPAddresses, ip)
			continue
		}
		leafTemplate.DNSNames = append(leafTemplate.DNSNames, host)
	}

	caDER, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("create ca certificate: %w", err)
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, &leafTemplate, &caTemplate, &leafKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("create leaf certificate: %w", err)
	}

	leafKeyBytes, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		return fmt.Errorf("marshal leaf private key: %w", err)
	}
	caKeyBytes, err := x509.MarshalECPrivateKey(caKey)
	if err != nil {
		return fmt.Errorf("marshal ca private key: %w", err)
	}

	var certPEM bytes.Buffer
	if err := pem.Encode(&certPEM, &pem.Block{Type: "CERTIFICATE", Bytes: leafDER}); err != nil {
		return fmt.Errorf("encode leaf certificate: %w", err)
	}
	if err := pem.Encode(&certPEM, &pem.Block{Type: "CERTIFICATE", Bytes: caDER}); err != nil {
		return fmt.Errorf("encode ca chain certificate: %w", err)
	}

	var caPEM bytes.Buffer
	if err := pem.Encode(&caPEM, &pem.Block{Type: "CERTIFICATE", Bytes: caDER}); err != nil {
		return fmt.Errorf("encode ca certificate: %w", err)
	}

	var keyPEM bytes.Buffer
	if err := pem.Encode(&keyPEM, &pem.Block{Type: "EC PRIVATE KEY", Bytes: leafKeyBytes}); err != nil {
		return fmt.Errorf("encode leaf private key: %w", err)
	}

	var caKeyPEM bytes.Buffer
	if err := pem.Encode(&caKeyPEM, &pem.Block{Type: "EC PRIVATE KEY", Bytes: caKeyBytes}); err != nil {
		return fmt.Errorf("encode ca private key: %w", err)
	}

	for _, path := range []string{certFile, keyFile, caFile, caKeyFile} {
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			return fmt.Errorf("create cert directory: %w", err)
		}
	}
	if err := os.WriteFile(certFile, certPEM.Bytes(), 0o644); err != nil {
		return fmt.Errorf("write certificate: %w", err)
	}
	if err := os.WriteFile(keyFile, keyPEM.Bytes(), 0o600); err != nil {
		return fmt.Errorf("write private key: %w", err)
	}
	if err := os.WriteFile(caFile, caPEM.Bytes(), 0o644); err != nil {
		return fmt.Errorf("write ca certificate: %w", err)
	}
	if err := os.WriteFile(caKeyFile, caKeyPEM.Bytes(), 0o600); err != nil {
		return fmt.Errorf("write ca private key: %w", err)
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
		opts.ValidFor = time.Hour * 24 * defaultLeafCertificateDays
	}
	return opts
}

func certificateSerial() (*big.Int, error) {
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, fmt.Errorf("generate serial number: %w", err)
	}
	return serial, nil
}

func subjectKeyID(publicKey *ecdsa.PublicKey) ([]byte, error) {
	encoded, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal public key: %w", err)
	}
	sum := sha1.Sum(encoded)
	return sum[:], nil
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

func bootstrapSecret() string {
	secret, err := config.GenerateSecret()
	if err != nil {
		return ""
	}
	return secret
}
