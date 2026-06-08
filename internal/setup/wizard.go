// Package setup handles first-launch initialization: setup wizard, default config,
// and local CA-signed admin certificate generation.
// 首次启动初始化：安装向导、默认配置、本地 CA 签发管理端证书生成。
package setup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultDataDir is the default data directory for CheeseWAF.
	// 默认数据目录。
	DefaultDataDir = "/var/lib/cheesewaf"

	// SetupLockFile indicates that initial setup has been completed.
	// 标识初始化已完成的锁文件。
	SetupLockFile = ".setup_complete"
)

// Wizard handles the first-launch setup process.
// If a Web UI is available, it serves a browser-based wizard.
// Otherwise, it falls back to a TUI-based setup.
// 首次启动安装向导。优先使用 Web UI 向导，否则回退到 TUI 向导。
type Wizard struct {
	DataDir      string        // 数据目录 / Data directory
	ConfigPath   string        // 配置文件路径 / Config file path
	AdminAPI     string        // 管理 API 地址 / Admin API address
	CertHosts    []string      // 管理端证书 SAN / Admin certificate SANs
	CertValidFor time.Duration // 管理端叶子证书有效期 / Admin leaf certificate lifetime
}

// NewWizard creates a first-launch wizard with safe defaults.
// 创建带安全默认值的首次启动向导。
func NewWizard(dataDir string) *Wizard {
	return &Wizard{DataDir: dataDir}
}

// NeedsSetup checks if the initial setup has been completed.
// 检查是否需要初始化。
func (w *Wizard) NeedsSetup() bool {
	return NeedsSetup(w.dataDir())
}

// MarkComplete marks the setup as complete by creating the lock file.
// 标记初始化完成。
func (w *Wizard) MarkComplete() error {
	return MarkComplete(w.dataDir())
}

// PrepareDefaults creates the default directory layout, config file, and
// local CA-signed admin certificate bundle. It is safe to call repeatedly.
// 准备默认目录、配置文件和本地 CA 签发管理端证书包，可重复调用。
func (w *Wizard) PrepareDefaults() (*DefaultBundle, error) {
	return EnsureDefaults(DefaultOptions{
		DataDir:    w.dataDir(),
		ConfigPath: w.ConfigPath,
		Hostnames:  w.CertHosts,
		ValidFor:   w.CertValidFor,
	})
}

// RunWebWizard starts the web-based setup wizard on the admin port.
// The wizard collects: admin username, password, optional 2FA, and basic site config.
// 启动 Web 安装向导（管理端口），收集管理员账号、密码、可选 2FA 和基础站点配置。
func (w *Wizard) RunWebWizard(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	bundle, err := w.PrepareDefaults()
	if err != nil {
		return err
	}

	done := make(chan struct{})
	handler := w.setupHTTPHandler(bundle, done)
	server := &http.Server{
		Addr:         w.adminListenAddr(),
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.ListenAndServeTLS(bundle.Paths.CertFile, bundle.Paths.KeyFile)
	}()

	fmt.Println("🧀 首次启动 — 请在浏览器中完成初始化向导")
	fmt.Printf("   → 打开 https://%s/setup\n", w.adminAPI())
	fmt.Printf("   → 默认配置: %s\n", bundle.Paths.ConfigFile)
	fmt.Printf("   → 管理端证书: %s\n", bundle.Paths.CertFile)

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
		return ctx.Err()
	case <-done:
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
		return nil
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func (w *Wizard) setupHTTPHandler(bundle *DefaultBundle, done chan struct{}) http.Handler {
	mux := http.NewServeMux()
	var completeOnce sync.Once
	complete := func() {
		completeOnce.Do(func() {
			close(done)
		})
	}

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		http.Redirect(w, r, "/setup", http.StatusFound)
	})
	mux.HandleFunc("/setup", func(resp http.ResponseWriter, req *http.Request) {
		switch req.Method {
		case http.MethodGet:
			resp.Header().Set("Content-Type", "text/html; charset=utf-8")
			_ = setupPageTemplate.Execute(resp, map[string]string{
				"AdminListen": w.adminAPI(),
				"ConfigFile":  bundle.Paths.ConfigFile,
				"CertFile":    bundle.Paths.CertFile,
			})
		case http.MethodPost:
			w.handleSetupSubmit(resp, req, bundle, complete)
		default:
			http.Error(resp, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/api/setup/status", func(resp http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet {
			http.Error(resp, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		writeSetupJSON(resp, http.StatusOK, map[string]any{
			"needs_setup": w.NeedsSetup(),
			"config_file": bundle.Paths.ConfigFile,
			"cert_file":   bundle.Paths.CertFile,
			"sqlite_file": bundle.Paths.SQLiteFile,
		})
	})
	mux.HandleFunc("/api/setup", func(resp http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost {
			http.Error(resp, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.handleSetupSubmit(resp, req, bundle, complete)
	})
	return mux
}

func (w *Wizard) handleSetupSubmit(resp http.ResponseWriter, req *http.Request, bundle *DefaultBundle, complete func()) {
	payload, err := readSetupPayload(req)
	if err != nil {
		writeSetupError(resp, http.StatusBadRequest, err.Error())
		return
	}
	if err := w.completeSetup(req.Context(), bundle, payload); err != nil {
		writeSetupError(resp, SetupErrorStatus(err), err.Error())
		return
	}
	writeSetupJSON(resp, http.StatusOK, map[string]any{"ok": true})
	complete()
}

func (w *Wizard) completeSetup(ctx context.Context, bundle *DefaultBundle, payload SetupPayload) error {
	_, err := CompleteSetup(ctx, CompleteOptions{
		DataDir:            w.dataDir(),
		ConfigPath:         bundle.Paths.ConfigFile,
		DefaultAdminListen: w.adminAPI(),
		Paths:              bundle.Paths,
	}, payload)
	return err
}

func readSetupPayload(req *http.Request) (SetupPayload, error) {
	var payload SetupPayload
	contentType := strings.ToLower(req.Header.Get("Content-Type"))
	if strings.Contains(contentType, "application/json") {
		if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
			return payload, err
		}
		return payload, nil
	}
	if err := req.ParseForm(); err != nil {
		return payload, err
	}
	payload.Username = req.Form.Get("username")
	payload.Password = req.Form.Get("password")
	payload.AdminListen = req.Form.Get("admin_listen")
	if payload.AdminListen == "" {
		payload.AdminListen = req.Form.Get("adminListen")
	}
	payload.AdminStrategy = req.Form.Get("admin_strategy")
	payload.AdminPublic = req.Form.Get("admin_public") == "true" || req.Form.Get("admin_public") == "on"
	return payload, nil
}

func writeSetupJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
}

func writeSetupError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"message": message}})
}

func (w *Wizard) adminListenAddr() string {
	raw := w.adminAPI()
	if parsed, err := url.Parse(raw); err == nil && parsed.Host != "" {
		return parsed.Host
	}
	return raw
}

func (w *Wizard) dataDir() string {
	if w != nil && w.DataDir != "" {
		return w.DataDir
	}
	return DefaultDataDir
}

func (w *Wizard) adminAPI() string {
	if w != nil && w.AdminAPI != "" {
		return w.AdminAPI
	}
	return DefaultAdminListen
}

var setupPageTemplate = template.Must(template.New("setup-page").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>CheeseWAF Setup</title>
  <style>
    body{margin:0;min-height:100vh;display:grid;place-items:center;background:#f8fafc;color:#0f172a;font-family:Inter,Segoe UI,Arial,sans-serif}
    main{width:min(560px,calc(100% - 32px));background:#fff;border:1px solid #dbe3ef;border-radius:8px;padding:28px;box-shadow:0 24px 70px rgba(15,23,42,.14)}
    h1{margin:0 0 8px;font-size:24px}p{margin:0 0 20px;color:#475569;line-height:1.6}
    label{display:grid;gap:6px;margin:0 0 14px;font-size:14px;color:#334155}
    input,select{height:38px;border:1px solid #cbd5e1;border-radius:6px;padding:0 10px;font:inherit;background:#fff}
    button{height:40px;border:0;border-radius:6px;background:#0f766e;color:white;font-weight:700;padding:0 16px;cursor:pointer}
    code{display:block;background:#f1f5f9;border-radius:6px;padding:8px;margin:10px 0;color:#334155;overflow:auto}
    .error{color:#b91c1c}.ok{color:#047857}
  </style>
</head>
<body>
  <main>
    <h1>CheeseWAF Setup</h1>
    <p>Create the first administrator account and confirm the admin listener. The temporary setup service will stop after completion.</p>
    <code>Config: {{.ConfigFile}}</code>
    <code>Certificate: {{.CertFile}}</code>
    <form method="post" action="/setup">
      <label>Username<input name="username" autocomplete="username" required minlength="3" value="admin"></label>
      <label>Password<input name="password" type="password" autocomplete="new-password" required minlength="10"></label>
      <label>Admin listener<input name="admin_listen" required value="{{.AdminListen}}"></label>
      <label>Admin access strategy
        <select name="admin_strategy">
          <option value="local">Local listener, reverse proxy, jump host, or SSH tunnel</option>
          <option value="public_tls">Public HTTPS with generated local CA-signed certificate</option>
        </select>
      </label>
      <button type="submit">Complete setup</button>
    </form>
  </main>
</body>
</html>`))
