package cli

import (
	"compress/gzip"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/ai"
	"github.com/LaokeQwQ/CheeseWAF/internal/api"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
	enginerules "github.com/LaokeQwQ/CheeseWAF/internal/engine/rules"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine/semantic"
	"github.com/LaokeQwQ/CheeseWAF/internal/monitor"
	monitornotify "github.com/LaokeQwQ/CheeseWAF/internal/monitor/notifier"
	"github.com/LaokeQwQ/CheeseWAF/internal/proxy"
	"github.com/LaokeQwQ/CheeseWAF/internal/realtime"
	"github.com/LaokeQwQ/CheeseWAF/internal/scheduler"
	"github.com/LaokeQwQ/CheeseWAF/internal/setup"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
	logsink "github.com/LaokeQwQ/CheeseWAF/internal/storage/log_sink"
)

var readAdminEntryNonce = rand.Read
var executablePath = os.Executable

func runServe(ctx context.Context) error {
	cfg, loadedConfigPath, err := loadConfig()
	if err != nil {
		return err
	}
	if err := ensureAdminTLSCertificate(cfg); err != nil {
		return err
	}
	if cfg.Setup.DataDir == "" {
		cfg.Setup.DataDir = dataDir
	}
	if err := os.MkdirAll(cfg.Setup.DataDir, 0o750); err != nil {
		return err
	}
	if err := writePID(cfg.Setup.RuntimeDir); err != nil {
		return err
	}
	defer removePID(cfg.Setup.RuntimeDir)

	store, err := storage.OpenSQLite(cfg.Storage.SQLite.Path)
	if err != nil {
		return err
	}
	defer store.Close()
	if err := store.Migrate(ctx); err != nil {
		return err
	}
	if err := validateStartupUsers(ctx, cfg.Setup.DataDir, store); err != nil {
		return err
	}
	if err := seedSites(ctx, store, cfg); err != nil {
		return err
	}

	sink, err := logsink.NewFromConfig(cfg.Storage, cfg.Logging.Output.File.Path)
	if err != nil {
		return err
	}
	defer sink.Close()

	pipeline, err := buildPipeline(cfg)
	if err != nil {
		return err
	}
	proxyServer, err := proxy.NewServer(cfg, pipeline, sink)
	if err != nil {
		return err
	}
	reloadSites := func(sites []config.SiteConfig) error {
		next := *cfg
		next.Sites = append([]config.SiteConfig(nil), sites...)
		nextPipeline, err := buildPipeline(&next)
		if err != nil {
			return err
		}
		proxyServer.UpdateSites(sites)
		proxyServer.UpdatePipeline(nextPipeline)
		return nil
	}
	proxy.NewHealthChecker(cfg.Sites, proxyServer.HealthRegistry()).Start(ctx)
	startRemoteWrite(ctx, cfg, store, sink, time.Now())
	var schedulerAIClient *ai.Client
	if cfg.AI.Enabled && cfg.AI.ReasoningRuntimeConfig().APIKey != "" {
		schedulerAIClient = ai.NewClient(cfg.AI.ReasoningRuntimeConfig(), nil)
	}
	schedulerEngine := scheduler.NewEngine(scheduler.FromConfigWithRuntime(cfg.Scheduler, cfg.Setup.DataDir, loadedConfigPath, cfg.Logging.Output.File.Path, scheduler.Runtime{
		AIConfig: cfg.AI,
		Sink:     sink,
		Store:    store,
		Client:   schedulerAIClient,
	}))
	schedulerEngine.Start(ctx)
	hub := realtime.NewHub()
	authSecret, err := ensureAuthSecret(cfg.Setup.DataDir)
	if err != nil {
		return err
	}
	adminTLS, adminScheme, err := adminTLSConfig(cfg.Server.AdminTLS)
	if err != nil {
		return err
	}
	admin := &http.Server{
		Addr:              cfg.Server.AdminListen,
		Handler:           adminHandler(cfg, api.NewRouter(api.Options{Config: cfg, ConfigPath: loadedConfigPath, Store: store, Sink: sink, Hub: hub, Secret: authSecret, OnSitesChanged: reloadSites, OnProtectionChanged: proxyServer.UpdateProtection, OnAPISecChanged: proxyServer.UpdateAPISec, OnBlockPageChanged: proxyServer.UpdateBlockPage}), authSecret),
		TLSConfig:         adminTLS,
		ReadHeaderTimeout: cfg.Server.ReadTimeout,
		ReadTimeout:       cfg.Server.ReadTimeout,
		WriteTimeout:      cfg.Server.WriteTimeout,
		IdleTimeout:       cfg.Server.IdleTimeout,
		MaxHeaderBytes:    1 << 20,
	}

	http3Server, altSvc, err := proxyServer.HTTP3Server()
	if err != nil {
		return err
	}
	tlsServer, err := proxyServer.TLSServer(altSvc)
	if err != nil {
		return err
	}

	fmt.Printf("CheeseWAF proxy listening on %s\n", cfg.Server.Listen)
	if tlsServer != nil {
		fmt.Printf("CheeseWAF TLS proxy listening on %s\n", cfg.Server.ListenTLS)
	}
	if http3Server != nil {
		fmt.Printf("CheeseWAF HTTP/3 proxy listening on %s\n", http3Server.Addr)
	}
	fmt.Printf("CheeseWAF admin API listening on %s://%s\n", adminScheme, cfg.Server.AdminListen)

	var wg sync.WaitGroup
	errCh := make(chan error, 4)
	wg.Add(2)
	go func() {
		defer wg.Done()
		if err := proxy.ListenAndServe(ctx, proxyServer.HTTPServer()); err != nil && !errors.Is(err, context.Canceled) {
			errCh <- err
		}
	}()
	go func() {
		defer wg.Done()
		if err := proxy.ListenAndServe(ctx, admin); err != nil && !errors.Is(err, context.Canceled) {
			errCh <- err
		}
	}()
	if tlsServer != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := proxy.ListenAndServe(ctx, tlsServer); err != nil && !errors.Is(err, context.Canceled) {
				errCh <- err
			}
		}()
	}
	if http3Server != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := proxy.ListenAndServeHTTP3(ctx, http3Server); err != nil && !errors.Is(err, context.Canceled) {
				errCh <- err
			}
		}()
	}

	select {
	case <-ctx.Done():
	case err := <-errCh:
		return err
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = admin.Shutdown(shutdownCtx)
	if tlsServer != nil {
		_ = tlsServer.Shutdown(shutdownCtx)
	}
	if http3Server != nil {
		_ = http3Server.Shutdown(shutdownCtx)
	}
	wg.Wait()
	return nil
}

func validateStartupUsers(ctx context.Context, dataDir string, store storage.UserStore) error {
	users, err := store.ListUsers(ctx)
	if err != nil {
		return fmt.Errorf(`startup user integrity check: %w`, err)
	}
	if setup.NeedsSetup(dataDir) {
		return nil
	}
	for _, user := range users {
		if strings.EqualFold(strings.TrimSpace(user.Role), `admin`) {
			return nil
		}
	}
	return fmt.Errorf(`startup user integrity check failed: setup is complete but no administrator exists; run waf-cli user ensure-admin USERNAME --password-stdin before starting the service`)
}

func adminHandler(cfg *config.Config, apiHandler http.Handler, authSecret string) http.Handler {
	webDir := resolveWebDir()
	if webDir == "" {
		return adminSecurityHeaders(adminEntranceGate(cfg, authSecret, apiHandler))
	}
	spa := http.FileServer(http.Dir(webDir))
	metricsPath := "/metrics"
	metricsPublic := false
	if cfg != nil && cfg.Monitor.Prometheus.Path != "" {
		metricsPath = cfg.Monitor.Prometheus.Path
		metricsPublic = cfg.Monitor.Prometheus.Public
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !allowAdminEntrance(cfg, authSecret, metricsPath, metricsPublic, w, r) {
			return
		}
		if r.URL.Path == metricsPath && !metricsPublic {
			apiHandler.ServeHTTP(w, r)
			return
		}
		if isAdminAPIPath(r.URL.Path, metricsPath, metricsPublic) {
			apiHandler.ServeHTTP(w, r)
			return
		}
		path := strings.TrimPrefix(filepath.Clean("/"+strings.TrimPrefix(r.URL.Path, "/")), string(os.PathSeparator))
		if path == "." {
			path = "index.html"
		}
		fullPath := filepath.Join(webDir, path)
		if info, err := os.Stat(fullPath); err == nil && !info.IsDir() {
			setAdminStaticCacheHeaders(w, path)
			spa.ServeHTTP(w, r)
			return
		}
		if isAdminStaticAssetPath(r.URL.Path) {
			http.NotFound(w, r)
			return
		}
		index := filepath.Join(webDir, "index.html")
		if _, err := os.Stat(index); err == nil {
			setAdminStaticCacheHeaders(w, "index.html")
			http.ServeFile(w, r, index)
			return
		}
		apiHandler.ServeHTTP(w, r)
	})
	return adminSecurityHeaders(adminGzip(handler, metricsPath))
}

func isAdminStaticAssetPath(path string) bool {
	path = strings.TrimSpace(path)
	return strings.HasPrefix(path, "/assets/") ||
		path == "/favicon.ico" ||
		path == "/cheesewaf-logo.png" ||
		path == "/manifest.webmanifest"
}

func adminEntranceGate(cfg *config.Config, authSecret string, next http.Handler) http.Handler {
	metricsPath := "/metrics"
	metricsPublic := false
	if cfg != nil && cfg.Monitor.Prometheus.Path != "" {
		metricsPath = cfg.Monitor.Prometheus.Path
		metricsPublic = cfg.Monitor.Prometheus.Public
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !allowAdminEntrance(cfg, authSecret, metricsPath, metricsPublic, w, r) {
			return
		}
		next.ServeHTTP(w, r)
	})
}

func adminSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", adminContentSecurityPolicy())
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
		if r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

func allowAdminEntrance(cfg *config.Config, authSecret, metricsPath string, metricsPublic bool, w http.ResponseWriter, r *http.Request) bool {
	login := config.Default().Console.Login
	if cfg != nil {
		login = cfg.Console.Login
	}
	entry := login.SecurityEntry
	if !entry.Enabled {
		return true
	}
	if entry.Path == "" {
		entry.Path = config.Default().Console.Login.SecurityEntry.Path
	}
	if entry.CookieName == "" {
		entry.CookieName = config.Default().Console.Login.SecurityEntry.CookieName
	}
	if r.URL.Path == "/health" || strings.HasPrefix(r.URL.Path, "/health/") || (metricsPublic && r.URL.Path == metricsPath) {
		return true
	}
	entryPath := cleanAdminEntryPath(entry.Path)
	requestPath := cleanAdminEntryPath(r.URL.Path)
	secret := adminEntrySecret(authSecret, cfg)
	if secret == "" {
		writeAdminTeapot(w)
		return false
	}
	if requestPath == entryPath {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeAdminTeapot(w)
			return false
		}
		if !issueAdminEntryCookie(w, r, entry.CookieName, secret) {
			writeAdminTeapot(w)
			return false
		}
		http.Redirect(w, r, "/login", http.StatusFound)
		return false
	}
	if validAdminEntryCookie(r, entry.CookieName, secret, time.Now) {
		return true
	}
	writeAdminTeapot(w)
	return false
}

func cleanAdminEntryPath(path string) string {
	cleaned := filepath.ToSlash(filepath.Clean("/" + strings.TrimSpace(strings.TrimPrefix(path, "/"))))
	if cleaned == "." || cleaned == "" {
		return "/"
	}
	return cleaned
}

func issueAdminEntryCookie(w http.ResponseWriter, r *http.Request, name, secret string) bool {
	expires := time.Now().UTC().Add(config.AdminSessionTTL)
	nonceBytes := make([]byte, 16)
	if _, err := readAdminEntryNonce(nonceBytes); err != nil {
		return false
	}
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)
	value := signedAdminEntryValue(secret, r.UserAgent(), expires.Unix(), nonce)
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		Expires:  expires,
		MaxAge:   int(config.AdminSessionTTL / time.Second),
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
	})
	return true
}

func validAdminEntryCookie(r *http.Request, name, secret string, now func() time.Time) bool {
	if now == nil {
		now = time.Now
	}
	cookie, err := r.Cookie(name)
	if err != nil {
		return false
	}
	parts := strings.Split(cookie.Value, ".")
	if len(parts) != 3 {
		return false
	}
	expiresUnix, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || expiresUnix <= now().UTC().Unix() {
		return false
	}
	want := signedAdminEntryValue(secret, r.UserAgent(), expiresUnix, parts[1])
	return hmac.Equal([]byte(want), []byte(cookie.Value))
}

func signedAdminEntryValue(secret, userAgent string, expires int64, nonce string) string {
	base := fmt.Sprintf("%d.%s", expires, nonce)
	mac := hmac.New(sha256.New, []byte(secret))
	for _, item := range []string{"cheesewaf-admin-entry-v1", userAgent, base} {
		_, _ = mac.Write([]byte(item))
		_, _ = mac.Write([]byte{'\n'})
	}
	return base + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func adminEntrySecret(authSecret string, cfg *config.Config) string {
	if authSecret != "" {
		return authSecret
	}
	if cfg != nil && !config.IsWeakBotSecret(cfg.Protection.Bot.Secret) {
		return cfg.Protection.Bot.Secret
	}
	return ""
}

func writeAdminTeapot(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusTeapot)
	_, _ = w.Write([]byte(`<!DOCTYPE html>
<html>
<head><title>418 I'm a teapot</title></head>
<body>
<center><h1>418 I'm a teapot</h1></center>
<hr><center>nginx</center>
</body>
</html>`))
}

func setAdminStaticCacheHeaders(w http.ResponseWriter, path string) {
	normalized := filepath.ToSlash(path)
	if strings.HasPrefix(normalized, "assets/") {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		return
	}
	w.Header().Set("Cache-Control", "no-cache")
}

func adminGzip(next http.Handler, metricsPath string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !adminShouldGzip(r, metricsPath) {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Add("Vary", "Accept-Encoding")
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Del("Content-Length")
		gz, err := gzip.NewWriterLevel(w, gzip.BestSpeed)
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}
		defer gz.Close()
		next.ServeHTTP(gzipResponseWriter{ResponseWriter: w, writer: gz}, r)
	})
}

type gzipResponseWriter struct {
	http.ResponseWriter
	writer *gzip.Writer
}

func (w gzipResponseWriter) WriteHeader(status int) {
	w.Header().Del("Content-Length")
	w.ResponseWriter.WriteHeader(status)
}

func (w gzipResponseWriter) Write(data []byte) (int, error) {
	w.Header().Del("Content-Length")
	return w.writer.Write(data)
}

func (w gzipResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func adminShouldGzip(r *http.Request, metricsPath string) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		return false
	}
	if r.URL.Path == "/health" || strings.HasPrefix(r.URL.Path, "/health/") || r.URL.Path == metricsPath || strings.HasPrefix(r.URL.Path, "/api/") {
		return false
	}
	ext := strings.ToLower(filepath.Ext(r.URL.Path))
	switch ext {
	case "", ".html", ".js", ".css", ".json", ".svg", ".txt", ".wasm":
		return true
	default:
		return false
	}
}

func adminContentSecurityPolicy() string {
	return strings.Join([]string{
		"default-src 'self'",
		"base-uri 'none'",
		"object-src 'none'",
		"frame-ancestors 'none'",
		"form-action 'self'",
		"script-src 'self'",
		"style-src 'self' 'unsafe-inline'",
		"img-src 'self' data: blob: https: http:",
		"font-src 'self' data:",
		"connect-src 'self' ws: wss:",
		"worker-src 'self' blob:",
		"manifest-src 'self'",
		"media-src 'self' data: blob: https: http:",
	}, "; ")
}

func isAdminAPIPath(path, metricsPath string, metricsPublic bool) bool {
	if path == "/api" || strings.HasPrefix(path, "/api/") {
		return true
	}
	if path == "/health" || strings.HasPrefix(path, "/health/") {
		return true
	}
	if metricsPublic && path == metricsPath {
		return true
	}
	return false
}

func resolveWebDir() string {
	candidates := []string{
		os.Getenv("CHEESEWAF_WEB_DIR"),
	}
	if executable, err := executablePath(); err == nil && strings.TrimSpace(executable) != "" {
		executableDir := filepath.Dir(executable)
		candidates = append(candidates,
			filepath.Join(executableDir, "web", "dist"),
			filepath.Join(executableDir, "web"),
		)
	}
	candidates = append(candidates,
		"/usr/share/cheesewaf/web",
		filepath.Join("web", "dist"),
		filepath.Join(".", "web", "dist"),
	)
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		index := filepath.Join(candidate, "index.html")
		if info, err := os.Stat(index); err == nil && !info.IsDir() {
			return candidate
		}
	}
	return ""
}

func startRemoteWrite(ctx context.Context, cfg *config.Config, store storage.Store, sink storage.LogSink, startedAt time.Time) {
	if cfg == nil || (!cfg.Monitor.RemoteWrite.Enabled && !cfg.Monitor.Alerts.Enabled) {
		return
	}
	writer := monitor.NewRemoteWriter(cfg.Monitor.RemoteWrite, nil)
	alerter := monitor.NewAlerter(cfg.Monitor.Alerts)
	notifiers := monitornotify.NewManager(cfg.Monitor.Notifiers)
	interval := cfg.Monitor.RemoteWrite.Interval
	if interval <= 0 {
		interval = 30 * time.Second
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				logs, _, _ := sink.Query(ctx, storage.LogFilter{Limit: 1000})
				snapshot := monitor.Collect(startedAt, len(cfg.Sites), logs, map[string]int64{
					"data": serviceDirSize(cfg.Setup.DataDir),
					"logs": serviceDirSize(filepath.Dir(cfg.Logging.Output.File.Path)),
				})
				_ = writer.Push(ctx, snapshot)
				alerts := alerter.Evaluate(snapshot)
				_ = monitornotify.PersistAlerts(ctx, store, alerts)
				_ = notifiers.Notify(ctx, alerts)
			}
		}
	}()
}

func serviceDirSize(root string) int64 {
	if root == "" {
		return 0
	}
	var total int64
	_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err == nil {
			total += info.Size()
		}
		_ = path
		return nil
	})
	return total
}

func buildPipeline(cfg *config.Config) (*engine.Pipeline, error) {
	// Wire budget metrics once; safe to re-assign.
	engine.OnDetectionBudgetExhausted = func() {
		semantic.ProcessMetrics().RecordBudgetExhausted()
	}
	var detectors []engine.Detector
	if len(cfg.Sites) == 0 {
		return engine.NewPipeline(), nil
	}
	for _, site := range cfg.Sites {
		if !site.Enabled || !site.WAF.Enabled || site.WAF.Mode == "off" {
			continue
		}
		if compiled, err := enginerules.FromConfig(site.WAF.CustomRules); err != nil {
			return nil, err
		} else if len(compiled) > 0 {
			detectors = append(detectors, siteScopedDetector{siteID: site.ID, detector: enginerules.New(compiled)})
		}
		switches := site.WAF.SemanticEngines
		// Single decision path: staged Analyzer covers all enabled categories.
		// Standalone SQL/XSS/RCE/LFI/XXE/SSRF detectors are intentionally not
		// mounted here to avoid double-scan cost and divergent FP behavior.
		var semanticCategories []string
		if switches.SQL {
			semanticCategories = append(semanticCategories, "sqli")
		}
		if switches.XSS {
			semanticCategories = append(semanticCategories, "xss")
		}
		if switches.RCE {
			semanticCategories = append(semanticCategories, "rce")
		}
		if switches.LFI {
			semanticCategories = append(semanticCategories, "lfi")
		}
		if switches.XXE {
			semanticCategories = append(semanticCategories, "xxe")
		}
		if switches.SSRF {
			semanticCategories = append(semanticCategories, "ssrf")
		}
		if switches.NoSQL {
			semanticCategories = append(semanticCategories, "nosqli")
		}
		if switches.SSTI {
			semanticCategories = append(semanticCategories, "ssti")
		}
		if len(semanticCategories) > 0 {
			detectors = append(detectors, siteScopedDetector{
				siteID:   site.ID,
				detector: semantic.NewAnalyzer(site.WAF.Mode, semanticCategories...),
			})
		}
	}
	return engine.NewPipeline(detectors...), nil
}

type siteScopedDetector struct {
	siteID   string
	detector engine.Detector
}

func (d siteScopedDetector) ID() string {
	return d.detector.ID()
}

func (d siteScopedDetector) Name() string {
	return d.detector.Name()
}

func (d siteScopedDetector) Priority() int {
	return d.detector.Priority()
}

func (d siteScopedDetector) Detect(ctx context.Context, reqCtx *engine.RequestContext) (*engine.DetectionResult, error) {
	if reqCtx == nil || reqCtx.SiteID != d.siteID {
		return nil, nil
	}
	return d.detector.Detect(ctx, reqCtx)
}

func loadConfig() (*config.Config, string, error) {
	if _, err := os.Stat(configPath); err == nil {
		cfg, err := config.Load(configPath)
		if err != nil {
			return nil, configPath, err
		}
		if err := repairRuntimeConfig(configPath, cfg); err != nil {
			return nil, configPath, err
		}
		return cfg, configPath, nil
	}
	if configPath != "" {
		fmt.Printf("config %s not found, using built-in defaults\n", configPath)
	}
	bundle, err := setup.EnsureDefaults(setup.DefaultOptions{
		DataDir:    dataDir,
		ConfigPath: filepath.Join(dataDir, setup.DefaultConfigFile),
	})
	if err != nil {
		return nil, "", err
	}
	cfg, err := config.Load(bundle.Paths.ConfigFile)
	if err != nil {
		return nil, bundle.Paths.ConfigFile, err
	}
	if err := repairRuntimeConfig(bundle.Paths.ConfigFile, cfg); err != nil {
		return nil, bundle.Paths.ConfigFile, err
	}
	return cfg, bundle.Paths.ConfigFile, nil
}

func adminTLSConfig(cfg config.AdminTLSConfig) (*tls.Config, string, error) {
	if !cfg.Enabled {
		return nil, "http", nil
	}
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, "", fmt.Errorf("load admin TLS certificate: %w", err)
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
	}, "https", nil
}

func ensureAdminTLSCertificate(cfg *config.Config) error {
	if cfg == nil || !cfg.Server.AdminTLS.Enabled || !cfg.Server.AdminTLS.SelfSigned {
		return nil
	}
	certExists, err := regularFileExists(cfg.Server.AdminTLS.CertFile)
	if err != nil {
		return fmt.Errorf("inspect admin TLS certificate: %w", err)
	}
	keyExists, err := regularFileExists(cfg.Server.AdminTLS.KeyFile)
	if err != nil {
		return fmt.Errorf("inspect admin TLS private key: %w", err)
	}
	if certExists && keyExists {
		return nil
	}

	hosts := append([]string(nil), setup.DefaultCertificateHosts...)
	if host, _, splitErr := net.SplitHostPort(cfg.Server.AdminListen); splitErr == nil {
		host = strings.TrimSpace(strings.Trim(host, "[]"))
		if ip := net.ParseIP(host); ip == nil || !ip.IsUnspecified() {
			if host != "" {
				hosts = append(hosts, host)
			}
		}
	}
	if hostname, hostnameErr := os.Hostname(); hostnameErr == nil && strings.TrimSpace(hostname) != "" {
		hosts = append(hosts, hostname)
	}
	if err := setup.GenerateSelfSignedCertificate(
		cfg.Server.AdminTLS.CertFile,
		cfg.Server.AdminTLS.KeyFile,
		hosts,
		825*24*time.Hour,
	); err != nil {
		return fmt.Errorf("generate self-signed admin TLS certificate: %w", err)
	}
	return nil
}

func regularFileExists(path string) (bool, error) {
	info, err := os.Lstat(strings.TrimSpace(path))
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return false, fmt.Errorf("%s is not a regular file", path)
	}
	return true, nil
}

func repairRuntimeConfig(path string, cfg *config.Config) error {
	if cfg == nil || !config.IsWeakBotSecret(cfg.Protection.Bot.Secret) {
		return nil
	}
	runtimeSecretPath := filepath.Join(cfg.Setup.RuntimeDir, "bot_secret")
	if secret, err := readRuntimeBotSecret(runtimeSecretPath); err == nil {
		cfg.Protection.Bot.Secret = secret
		return nil
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("load runtime Bot challenge secret: %w", err)
	}

	changed, err := config.EnsureRuntimeSecrets(cfg)
	if err != nil {
		return err
	}
	if !changed || path == "" {
		return nil
	}
	if err := config.Save(path, cfg); err == nil {
		fmt.Printf("CheeseWAF rotated weak Bot challenge secret and saved %s\n", path)
		return nil
	} else if persistErr := writeRuntimeBotSecret(runtimeSecretPath, cfg.Protection.Bot.Secret); persistErr != nil {
		return errors.Join(fmt.Errorf("save runtime config repair: %w", err), fmt.Errorf("persist runtime Bot challenge secret: %w", persistErr))
	}
	fmt.Printf("CheeseWAF rotated weak Bot challenge secret and stored it in the runtime directory\n")
	return nil
}

func readRuntimeBotSecret(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", fmt.Errorf("runtime Bot challenge secret is not a regular file")
	}
	if info.Size() < 32 || info.Size() > 256 {
		return "", fmt.Errorf("runtime Bot challenge secret has invalid size")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	secret := strings.TrimSpace(string(raw))
	if len(secret) < 32 || len(secret) > 256 || config.IsWeakBotSecret(secret) {
		return "", fmt.Errorf("runtime Bot challenge secret is invalid")
	}
	return secret, nil
}

func writeRuntimeBotSecret(path, secret string) error {
	if len(strings.TrimSpace(secret)) < 32 || len(secret) > 256 || config.IsWeakBotSecret(secret) {
		return fmt.Errorf("runtime Bot challenge secret is invalid")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, writeErr := file.WriteString(secret + "\n")
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		_ = os.Remove(path)
		return errors.Join(writeErr, closeErr)
	}
	return nil
}

func seedSites(ctx context.Context, store storage.Store, cfg *config.Config) error {
	existing, err := store.ListSites(ctx)
	if err != nil {
		return err
	}
	if len(existing) > 0 {
		return nil
	}
	for _, siteCfg := range cfg.Sites {
		upstreams := make([]string, 0, len(siteCfg.Upstreams))
		for _, upstream := range siteCfg.Upstreams {
			upstreams = append(upstreams, upstream.Address)
		}
		site := storage.SiteFromConfig(siteCfg)
		site.Upstreams = upstreams
		if err := store.CreateSite(ctx, &site); err != nil {
			return err
		}
	}
	return nil
}

func pidPath(runtimeDir string) string {
	if runtimeDir == "" {
		runtimeDir = filepath.Join(dataDir, "run")
	}
	return filepath.Join(runtimeDir, "cheesewaf.pid")
}

func writePID(runtimeDir string) error {
	if err := os.MkdirAll(runtimeDir, 0o750); err != nil {
		return err
	}
	return os.WriteFile(pidPath(runtimeDir), []byte(strconv.Itoa(os.Getpid())), 0o640)
}

func removePID(runtimeDir string) {
	_ = os.Remove(pidPath(runtimeDir))
}

// ServiceStatusSnapshot is the CLI/GUI-visible process state for CheeseWAF.
// GUI and TUI must use this rather than inventing a second status model.
type ServiceStatusSnapshot struct {
	RuntimeDir string
	PIDPath    string
	PID        int
	HasPIDFile bool
	Running    bool
	Stale      bool
}

// serviceStatusSnapshot is the historical unexported alias used inside this package.
type serviceStatusSnapshot = ServiceStatusSnapshot

// ConfigurePaths sets the package-level config/data paths used by status/stop
// helpers. Desktop controllers must call this before InspectServiceStatus.
func ConfigurePaths(configFile, dataDirectory string) {
	if configFile != "" {
		configPath = configFile
	}
	if dataDirectory != "" {
		dataDir = dataDirectory
	}
}

// InspectServiceStatus returns whether CheeseWAF appears to be running based on
// the configured runtime PID file. Safe for concurrent GUI polling.
func InspectServiceStatus() (ServiceStatusSnapshot, error) {
	return inspectServiceStatus()
}

// StopRunningService stops a live CheeseWAF process (or cleans a stale PID file).
// It reuses the same semantics as `cheesewaf stop`.
func StopRunningService() (ServiceStatusSnapshot, error) {
	snapshot, err := inspectServiceStatus()
	if err != nil {
		return snapshot, err
	}
	if !snapshot.HasPIDFile {
		return snapshot, nil
	}
	if snapshot.Stale {
		removePID(snapshot.RuntimeDir)
		snapshot.HasPIDFile = false
		snapshot.Stale = false
		snapshot.Running = false
		snapshot.PID = 0
		return snapshot, nil
	}
	if err := stopProcess(snapshot.PID); err != nil {
		return snapshot, err
	}
	return snapshot, nil
}

func authSecretPath(baseDir string) string {
	if baseDir == "" {
		baseDir = dataDir
	}
	return filepath.Join(baseDir, "auth.key")
}

func ensureAuthSecret(baseDir string) (string, error) {
	path := authSecretPath(baseDir)
	if raw, err := os.ReadFile(path); err == nil {
		secret := string(raw)
		if secret != "" {
			return secret, nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return "", err
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	secret := base64.RawURLEncoding.EncodeToString(buf)
	if err := os.WriteFile(path, []byte(secret), 0o600); err != nil {
		return "", err
	}
	return secret, nil
}

func readPID() (int, error) {
	runtimeDir, err := resolveRuntimeDirForCLI()
	if err != nil {
		return 0, err
	}
	return readPIDFromRuntimeDir(runtimeDir)
}

func readPIDFromRuntimeDir(runtimeDir string) (int, error) {
	raw, err := os.ReadFile(pidPath(runtimeDir))
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(string(raw))
}

func resolveRuntimeDirForCLI() (string, error) {
	if configPath != "" {
		if _, err := os.Stat(configPath); err == nil {
			cfg, err := config.Load(configPath)
			if err != nil {
				return "", err
			}
			if cfg.Setup.RuntimeDir != "" {
				return filepath.Clean(cfg.Setup.RuntimeDir), nil
			}
			if cfg.Setup.DataDir != "" {
				return filepath.Join(filepath.Clean(cfg.Setup.DataDir), "run"), nil
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
	}
	return filepath.Join(dataDir, "run"), nil
}

func inspectServiceStatus() (serviceStatusSnapshot, error) {
	runtimeDir, err := resolveRuntimeDirForCLI()
	if err != nil {
		return serviceStatusSnapshot{}, err
	}
	snapshot := serviceStatusSnapshot{
		RuntimeDir: runtimeDir,
		PIDPath:    pidPath(runtimeDir),
	}
	pid, err := readPIDFromRuntimeDir(runtimeDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return snapshot, nil
		}
		return snapshot, err
	}
	snapshot.HasPIDFile = true
	snapshot.PID = pid
	running, err := processRunning(pid)
	if err != nil {
		return snapshot, err
	}
	snapshot.Running = running
	snapshot.Stale = !running
	return snapshot, nil
}
