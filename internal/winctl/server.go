package winctl

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ListenAndServe starts the loopback control plane and blocks until ctx is done.
func (c *Controller) ListenAndServe(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", c.handleUI)
	mux.HandleFunc("/api/status", c.handleStatus)
	mux.HandleFunc("/api/start", c.handleAction(c.Start))
	mux.HandleFunc("/api/stop", c.handleAction(c.Stop))
	mux.HandleFunc("/api/restart", c.handleAction(c.Restart))
	mux.HandleFunc("/api/open-admin", c.handleAction(c.OpenAdmin))
	mux.HandleFunc("/api/open-config", c.handleAction(c.OpenConfigDir))
	mux.HandleFunc("/api/autostart", c.handleAutostart)

	ln, err := net.Listen("tcp", c.opts.Listen)
	if err != nil {
		return err
	}
	c.server = &http.Server{
		Handler:           withLocalOnly(mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		errCh <- c.server.Serve(ln)
	}()
	// Best-effort open the local UI once.
	_ = openURL("http://" + c.opts.Listen + "/")
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = c.server.Shutdown(shutdownCtx)
		return ctx.Err()
	case err := <-errCh:
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	}
}

func withLocalOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			http.Error(w, "loopback only", http.StatusForbidden)
			return
		}
		// Mutating endpoints: reject non-loopback browser origins (CSRF-ish).
		if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodDelete {
			if origin := strings.TrimSpace(r.Header.Get("Origin")); origin != "" && !isLoopbackHTTPOrigin(origin) {
				http.Error(w, "origin not allowed", http.StatusForbidden)
				return
			}
		}
		// No secrets in controller UI; still avoid being embedded.
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func isLoopbackHTTPOrigin(origin string) bool {
	// http://127.0.0.1:17943 or http://localhost:17943
	origin = strings.TrimSpace(origin)
	if origin == "null" {
		// Some browsers send Origin: null for sandboxed contexts — reject mutations.
		return false
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	host := u.Hostname()
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (c *Controller) handleUI(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(controlHTML))
}

func (c *Controller) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	view, err := c.View()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "data": view})
}

func (c *Controller) handleAction(fn func() error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := fn(); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		view, err := c.View()
		if err != nil {
			writeJSON(w, http.StatusOK, map[string]any{"ok": true})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "data": view})
	}
}

func (c *Controller) handleAutostart(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "enabled": IsAutostartEnabled()})
	case http.MethodPost:
		var body struct {
			Enabled bool `json:"enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid json"})
			return
		}
		if err := c.SetAutostart(body.Enabled); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "enabled": IsAutostartEnabled()})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// controlHTML is a minimal embedded controller page (no external assets).
const controlHTML = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>CheeseWAF 本地服务控制器</title>
<style>
:root{--bg:#0f1419;--card:#1a2332;--text:#e7ecf3;--muted:#8b9bb4;--ok:#3dd68c;--bad:#f07178;--btn:#2b6cb0;--border:#2a3548}
*{box-sizing:border-box}body{margin:0;font-family:Segoe UI,system-ui,sans-serif;background:var(--bg);color:var(--text)}
main{max-width:720px;margin:32px auto;padding:0 16px}
h1{font-size:1.35rem;margin:0 0 4px}p{color:var(--muted);margin:0 0 16px;line-height:1.5}
.meta{color:var(--muted);font-size:.9rem;margin-bottom:18px}
.card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:16px 18px;margin-bottom:14px}
.row{display:flex;flex-wrap:wrap;gap:10px;margin-top:12px}
button{appearance:none;border:0;border-radius:8px;padding:10px 14px;background:var(--btn);color:#fff;font-weight:600;cursor:pointer}
button.secondary{background:#334155}button.danger{background:#9f1239}
button:disabled{opacity:.5;cursor:not-allowed}
.badge{display:inline-block;padding:2px 10px;border-radius:999px;font-size:.85rem;font-weight:700}
.badge.on{background:rgba(61,214,140,.15);color:var(--ok)}.badge.off{background:rgba(240,113,120,.15);color:var(--bad)}
code,pre{font-family:ui-monospace,Consolas,monospace;font-size:.85rem;color:#cbd5e1}
pre{white-space:pre-wrap;word-break:break-all;margin:8px 0 0}
.err{color:var(--bad);min-height:1.2em;margin-top:10px}
label{display:flex;align-items:center;gap:8px;color:var(--muted)}
.hint{font-size:.85rem;color:var(--muted);margin-top:10px;line-height:1.45}
</style>
</head>
<body>
<main>
  <h1>CheeseWAF 本地服务控制器</h1>
  <div class="meta" id="version">版本检查中…</div>
  <p>仅绑定本机回环（loopback）。启动/停止复用 CLI 语义，不是第二套管理后台。复杂配置请打开 Web 控制台或编辑 YAML。</p>
  <div class="card">
    <div>状态：<span id="status" class="badge off">检查中…</span> <span id="pid"></span></div>
    <div class="row">
      <button id="btn-start">启动服务</button>
      <button id="btn-stop" class="danger">停止服务</button>
      <button id="btn-restart" class="secondary">重启</button>
      <button id="btn-admin" class="secondary">打开 Web 控制台</button>
      <button id="btn-config" class="secondary">打开配置目录</button>
    </div>
    <label style="margin-top:14px"><input type="checkbox" id="autostart"/> 开机自启本控制器</label>
    <p class="hint">若已通过 NSIS 注册 Windows 服务，也可在「服务」中管理 CheeseWAF；本控制器默认以 CLI 进程方式启停。</p>
    <div class="err" id="err"></div>
  </div>
  <div class="card">
    <div>路径 / 版本 / 监听</div>
    <pre id="paths">—</pre>
  </div>
</main>
<script>
const $ = (id) => document.getElementById(id);
const err = (m) => { $('err').textContent = m || ''; };
async function api(path, opts) {
  const res = await fetch(path, Object.assign({ credentials: 'same-origin' }, opts || {}));
  const body = await res.json().catch(() => ({}));
  if (!res.ok || body.ok === false) throw new Error(body.error || res.statusText);
  return body;
}
function paint(data) {
  if (!data) return;
  const st = data.status || {};
  const paths = data.paths || {};
  const on = !!st.Running;
  const badge = $('status');
  badge.textContent = on ? '运行中' : (st.Stale ? 'PID 陈旧' : '已停止');
  badge.className = 'badge ' + (on ? 'on' : 'off');
  $('pid').textContent = st.PID ? ('pid=' + st.PID) : '';
  const ver = [paths.version, paths.channel, paths.edition].filter(Boolean).join(' · ');
  $('version').textContent = ver ? ('CheeseWAF ' + ver + (paths.platform ? ' (' + paths.platform + ')' : '')) : 'CheeseWAF';
  $('paths').textContent = JSON.stringify(paths, null, 2);
  if (paths.autostart != null) {
    $('autostart').checked = paths.autostart === 'true';
  }
}
async function refresh() {
  try {
    const body = await api('/api/status');
    paint(body.data);
    err('');
  } catch (e) { err(String(e.message || e)); }
}
async function act(path) {
  try {
    err('');
    const body = await api(path, { method: 'POST' });
    paint(body.data);
  } catch (e) { err(String(e.message || e)); await refresh(); }
}
$('btn-start').onclick = () => act('/api/start');
$('btn-stop').onclick = () => act('/api/stop');
$('btn-restart').onclick = () => act('/api/restart');
$('btn-admin').onclick = () => act('/api/open-admin');
$('btn-config').onclick = () => act('/api/open-config');
$('autostart').onchange = async (ev) => {
  try {
    await api('/api/autostart', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled: !!ev.target.checked }),
    });
    err('');
  } catch (e) {
    err(String(e.message || e));
    ev.target.checked = !ev.target.checked;
  }
};
refresh();
setInterval(refresh, 3000);
</script>
</body>
</html>
`
