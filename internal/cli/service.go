package cli

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

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

func runServe(ctx context.Context) error {
	cfg, err := loadConfig()
	if err != nil {
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
	proxy.NewHealthChecker(cfg.Sites, proxyServer.HealthRegistry()).Start(ctx)
	startRemoteWrite(ctx, cfg, sink, time.Now())
	schedulerEngine := scheduler.NewEngine(scheduler.FromConfig(cfg.Scheduler, cfg.Setup.DataDir, configPath, cfg.Logging.Output.File.Path))
	schedulerEngine.Start(ctx)
	hub := realtime.NewHub()
	authSecret, err := ensureAuthSecret(cfg.Setup.DataDir)
	if err != nil {
		return err
	}
	admin := &http.Server{
		Addr:         cfg.Server.AdminListen,
		Handler:      api.NewRouter(api.Options{Config: cfg, Store: store, Sink: sink, Hub: hub, Secret: authSecret}),
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
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
	fmt.Printf("CheeseWAF admin API listening on http://%s\n", cfg.Server.AdminListen)

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

func startRemoteWrite(ctx context.Context, cfg *config.Config, sink storage.LogSink, startedAt time.Time) {
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
				_ = notifiers.Notify(ctx, alerter.Evaluate(snapshot))
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
	var detectors []engine.Detector
	if len(cfg.Sites) == 0 {
		return engine.NewPipeline(), nil
	}
	site := cfg.Sites[0]
	if compiled, err := enginerules.FromConfig(site.WAF.CustomRules); err != nil {
		return nil, err
	} else if len(compiled) > 0 {
		detectors = append(detectors, enginerules.New(compiled))
	}
	switches := site.WAF.SemanticEngines
	if switches.SQL {
		detectors = append(detectors, semantic.NewSQLDetector(site.WAF.Mode))
	}
	if switches.XSS {
		detectors = append(detectors, semantic.NewXSSDetector(site.WAF.Mode))
	}
	if switches.RCE {
		detectors = append(detectors, semantic.NewRCEDetector(site.WAF.Mode))
	}
	if switches.LFI {
		detectors = append(detectors, semantic.NewLFIDetector(site.WAF.Mode))
	}
	if switches.XXE {
		detectors = append(detectors, semantic.NewXXEDetector(site.WAF.Mode))
	}
	if switches.SSRF {
		detectors = append(detectors, semantic.NewSSRFDetector(site.WAF.Mode))
	}
	return engine.NewPipeline(detectors...), nil
}

func loadConfig() (*config.Config, error) {
	if _, err := os.Stat(configPath); err == nil {
		return config.Load(configPath)
	}
	if configPath != "" {
		fmt.Printf("config %s not found, using built-in defaults\n", configPath)
	}
	bundle, err := setup.EnsureDefaults(setup.DefaultOptions{
		DataDir:    dataDir,
		ConfigPath: filepath.Join(dataDir, setup.DefaultConfigFile),
	})
	if err != nil {
		return nil, err
	}
	return config.Load(bundle.Paths.ConfigFile)
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
		site := &storage.Site{
			ID:         siteCfg.ID,
			Name:       siteCfg.Name,
			Domains:    siteCfg.Domains,
			Upstreams:  upstreams,
			ListenPort: siteCfg.ListenPort,
			Enabled:    siteCfg.Enabled,
		}
		if err := store.CreateSite(ctx, site); err != nil {
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
	raw, err := os.ReadFile(pidPath(filepath.Join(dataDir, "run")))
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(string(raw))
}
