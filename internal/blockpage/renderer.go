package blockpage

import (
	"bytes"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

type Data struct {
	EventID    string
	TraceID    string
	AttackType string
	ClientIP   string
	Timestamp  time.Time
	Message    string
	Status     int
	StatusText string
}

type Renderer struct {
	template *template.Template
}

func NewRenderer() *Renderer {
	renderer, err := NewRendererFromConfig(config.BlockPageConfig{TemplateID: "minimal"})
	if err != nil {
		return &Renderer{template: template.Must(template.New("block").Parse(defaultBlockTemplate))}
	}
	return renderer
}

func NewRendererFromConfig(cfg config.BlockPageConfig) (*Renderer, error) {
	html := ResolveTemplateHTML(cfg)
	parsed, err := template.New("block").Parse(html)
	if err != nil {
		return nil, err
	}
	return &Renderer{template: parsed}, nil
}

func (r *Renderer) Render(w http.ResponseWriter, status int, data Data) {
	if data.Timestamp.IsZero() {
		data.Timestamp = time.Now().UTC()
	}
	if data.TraceID == "" && data.EventID != "" {
		data.TraceID = data.EventID
	}
	if data.TraceID == "" {
		data.TraceID = NewTraceID()
	}
	if data.EventID == "" {
		data.EventID = data.TraceID
	}
	if data.Status == 0 {
		data.Status = status
	}
	if data.StatusText == "" {
		data.StatusText = http.StatusText(data.Status)
	}
	var buf bytes.Buffer
	tmpl := r.template
	if tmpl == nil {
		tmpl = template.Must(template.New("block").Parse(defaultBlockTemplate))
	}
	if err := tmpl.Execute(&buf, data); err != nil {
		buf.Reset()
		_ = template.Must(template.New("block").Parse(defaultBlockTemplate)).Execute(&buf, data)
	}
	ensureVisibleEventID(&buf, data.EventID)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-CheeseWAF-Trace-ID", data.TraceID)
	w.Header().Set("X-CheeseWAF-Event-ID", data.EventID)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

func ResolveTemplateHTML(cfg config.BlockPageConfig) string {
	if cfg.CustomEnabled && strings.TrimSpace(cfg.CustomHTML) != "" {
		return cfg.CustomHTML
	}
	if info, ok := TemplateByID(cfg.TemplateID); ok {
		return info.HTML
	}
	return defaultBlockTemplate
}

func ensureVisibleEventID(buf *bytes.Buffer, eventID string) {
	eventID = strings.TrimSpace(eventID)
	if buf == nil || eventID == "" || bytes.Contains(buf.Bytes(), []byte(eventID)) {
		return
	}
	badge := `<div style="position:fixed;right:16px;bottom:16px;z-index:2147483647;max-width:min(420px,calc(100vw - 32px));padding:10px 12px;border:1px solid rgba(148,163,184,.45);border-radius:10px;background:rgba(15,23,42,.92);color:#f8fafc;box-shadow:0 16px 40px rgba(15,23,42,.24);font:12px/1.5 ui-monospace,SFMono-Regular,Consolas,Liberation Mono,monospace;overflow-wrap:anywhere">Event / Trace ID: <strong style="color:#93c5fd">` + template.HTMLEscapeString(eventID) + `</strong></div>`
	body := buf.String()
	lower := strings.ToLower(body)
	if idx := strings.LastIndex(lower, "</body>"); idx >= 0 {
		buf.Reset()
		buf.WriteString(body[:idx])
		buf.WriteString(badge)
		buf.WriteString(body[idx:])
		return
	}
	buf.WriteString(badge)
}

const defaultBlockTemplate = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="noindex,nofollow">
  <title>{{if ge .Status 500}}Service error{{else}}Access blocked{{end}} | CheeseWAF</title>
  <style>
    :root{color-scheme:light dark;--bg:#f4f7fb;--panel:#ffffff;--panel-soft:#f8fafc;--text:#172033;--muted:#667085;--line:#d8e1ec;--line-strong:#c4cfdd;--accent:#f2a922;--accent-dark:#b76b00;--teal:#087776;--teal-dark:#0b4d50;--ok:#0f9f60;--danger:#b42318;--shadow:0 26px 80px rgba(15,23,42,.14)}
    @media (prefers-color-scheme:dark){:root{--bg:#0f1724;--panel:#151f2d;--panel-soft:#101928;--text:#eef4fb;--muted:#9aa8ba;--line:#2b394b;--line-strong:#3b4a60;--accent:#ffbd4a;--accent-dark:#ffcf72;--teal:#35c7c0;--teal-dark:#2aa9a4;--ok:#52d48d;--danger:#ff8b7f;--shadow:0 26px 80px rgba(0,0,0,.38)}}
    *{box-sizing:border-box}
    body{margin:0;min-height:100vh;background:var(--bg);color:var(--text);font-family:ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
    main{width:min(1040px,100%);min-height:100vh;margin:0 auto;padding:42px 28px 34px;display:grid;align-content:center;gap:22px}
    .top{display:flex;align-items:center;justify-content:space-between;gap:18px;flex-wrap:wrap}
    .brand{display:flex;align-items:center;gap:12px;color:var(--text);font-size:15px;font-weight:850}
    .logo{width:48px;height:48px;display:grid;place-items:center;background:var(--panel);border:1px solid var(--line-strong);border-radius:10px;box-shadow:0 12px 30px rgba(15,23,42,.1)}
    .logo svg{width:38px;height:38px;display:block}
    .status-chip{padding:8px 11px;border:1px solid var(--line);border-radius:999px;background:var(--panel);color:var(--muted);font-size:12px;font-weight:800}
    .card{background:var(--panel);border:1px solid var(--line);border-top:4px solid var(--accent);border-radius:8px;box-shadow:var(--shadow);overflow:hidden}
    .summary{padding:36px 40px 30px;border-bottom:1px solid var(--line)}
    .eyebrow{margin:0 0 12px;color:var(--accent-dark);font-size:12px;font-weight:900;text-transform:uppercase;letter-spacing:.06em}
    h1{margin:0;color:var(--text);font-size:clamp(34px,5vw,54px);line-height:1.05;letter-spacing:0}
    .lead{max-width:70ch;margin:18px 0 0;color:var(--muted);font-size:16px;line-height:1.7}
    .checks{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));border-bottom:1px solid var(--line);background:linear-gradient(180deg,var(--panel),var(--panel-soft))}
    .check{min-width:0;padding:20px 24px;border-right:1px solid var(--line)}
    .check:last-child{border-right:0}
    .check strong{display:block;margin-bottom:6px;color:var(--text);font-size:15px}
    .check span{display:flex;align-items:center;gap:8px;color:var(--muted);font-size:13px}
    .dot{width:9px;height:9px;flex:none;border-radius:50%;background:var(--ok);box-shadow:0 0 0 4px color-mix(in srgb,var(--ok) 14%,transparent)}
    .dot-warning{background:var(--accent);box-shadow:0 0 0 4px color-mix(in srgb,var(--accent) 20%,transparent)}
    .notice{padding:20px 40px;border-bottom:1px solid var(--line);color:var(--muted);line-height:1.65}
    .notice strong{color:var(--text)}
    .details{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:0;padding:10px 40px 28px}
    .item{min-width:0;padding:18px 0;border-bottom:1px solid var(--line)}
    .item:nth-last-child(-n+2){border-bottom:0}
    .label{display:block;margin-bottom:7px;color:var(--muted);font-size:12px;font-weight:800;text-transform:uppercase}
    .value{min-width:0;overflow-wrap:anywhere;font-size:15px;line-height:1.45}
    code{display:inline-block;max-width:100%;padding:8px 10px;overflow-wrap:anywhere;color:#0b65c2;background:var(--panel-soft);border:1px solid var(--line-strong);border-radius:6px;font-family:"SFMono-Regular",Consolas,"Liberation Mono",monospace;font-size:13px}
    .help{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px;padding:0 40px 30px}
    .help div{padding:16px;border:1px solid var(--line);border-radius:8px;background:var(--panel-soft)}
    .help h2{margin:0 0 8px;color:var(--text);font-size:15px}
    .help p{margin:0;color:var(--muted);font-size:13px;line-height:1.65}
    footer{padding:18px 40px 28px;border-top:1px solid var(--line);color:var(--muted);font-size:13px;line-height:1.65}
    @media (max-width:720px){main{padding:24px 14px}.summary{padding:26px 22px}.top{gap:12px}.status-chip{width:100%;text-align:center}.checks{grid-template-columns:1fr}.check{border-right:0;border-bottom:1px solid var(--line)}.check:last-child{border-bottom:0}.notice{padding:18px 22px}.details{grid-template-columns:1fr;padding:8px 22px 20px}.item:nth-last-child(-n+2){border-bottom:1px solid var(--line)}.item:last-child{border-bottom:0}.help{grid-template-columns:1fr;padding:0 22px 24px}footer{padding:16px 22px 24px}h1{font-size:34px}}
  </style>
</head>
<body>
  <main>
    <div class="top">
      <div class="brand">
        <span class="logo" aria-hidden="true">
          <svg viewBox="0 0 64 64" role="img" focusable="false"><defs><linearGradient id="shield" x1="7" y1="10" x2="58" y2="56"><stop stop-color="#0c8887"/><stop offset="1" stop-color="#06383f"/></linearGradient><linearGradient id="cheese" x1="15" y1="14" x2="32" y2="52"><stop stop-color="#ffe56a"/><stop offset="1" stop-color="#f5a400"/></linearGradient><linearGradient id="fire" x1="42" y1="22" x2="42" y2="47"><stop stop-color="#8ef3ec"/><stop offset="1" stop-color="#16938f"/></linearGradient></defs><path fill="url(#shield)" d="M32 4 57 15v17c0 15-10 24-25 29C17 56 7 47 7 32V15L32 4Z"/><path fill="#0b595f" d="M32 9v46c12-5 20-12 20-23V18L32 9Z"/><path fill="url(#cheese)" d="M14 19 32 10v44C21 49 14 42 14 31V19Z"/><path fill="#fff4a8" opacity=".78" d="M18 22 32 15v6c-4 1-8 3-11 6-3 4-5 9-5 15-1-3-2-7-2-11v-8Z"/><circle cx="24" cy="26" r="5" fill="#d88400"/><circle cx="28" cy="40" r="4" fill="#d88400"/><circle cx="17" cy="35" r="3" fill="#d88400"/><path fill="url(#fire)" d="M41 47c-7-3-9-8-7-14 1-4 5-7 7-12 3 4 3 8 2 11 3-1 5-4 6-7 5 8 4 18-8 22Z"/><path fill="#128782" d="M35 42h16v4H35v-4Zm0-9h8v4h-8v-4Zm13 0h6v4h-6v-4Z" opacity=".8"/><path fill="none" stroke="#50d6cf" stroke-opacity=".55" stroke-width="2" d="M12 18 32 9l20 9v14c0 12-8 20-20 24-12-4-20-12-20-24V18Z"/></svg>
        </span>
        <span>CheeseWAF</span>
      </div>
      <div class="status-chip">{{.Status}} {{.StatusText}}</div>
    </div>
    <section class="card" aria-label="CheeseWAF security response">
      <div class="summary">
        <p class="eyebrow">{{if ge .Status 500}}Service error{{else}}Security response{{end}}</p>
        <h1>{{if ge .Status 500}}The protected service returned an error{{else}}Access was blocked{{end}}</h1>
        <p class="lead">{{if .Message}}{{.Message}}{{else}}{{if ge .Status 500}}CheeseWAF could not complete the request to the protected origin.{{else}}The request matched an active CheeseWAF security policy before it reached the protected origin.{{end}}{{end}}</p>
      </div>
      <div class="checks" aria-label="Connection status">
        <div class="check"><strong>Client</strong><span><i class="dot"></i>Request received</span></div>
        <div class="check"><strong>CheeseWAF</strong><span><i class="dot dot-warning"></i>{{if ge .Status 500}}Error recorded{{else}}Security policy applied{{end}}</span></div>
        <div class="check"><strong>Origin</strong><span><i class="dot"></i>{{if ge .Status 500}}Needs operator review{{else}}Protected{{end}}</span></div>
      </div>
      <div class="notice"><strong>When contacting support, include the Event / Trace ID.</strong> It is the exact lookup key for the corresponding CheeseWAF security or upstream error event.</div>
      <div class="details" aria-label="Request details">
        <div class="item">
          <span class="label">Event / Trace ID</span>
          <code>{{.EventID}}</code>
        </div>
        <div class="item">
          <span class="label">HTTP status</span>
          <span class="value">{{.Status}} {{.StatusText}}</span>
        </div>
        <div class="item">
          <span class="label">Event type</span>
          <span class="value">{{if .AttackType}}{{.AttackType}}{{else}}waf_block{{end}}</span>
        </div>
        <div class="item">
          <span class="label">Client IP</span>
          <span class="value">{{if .ClientIP}}{{.ClientIP}}{{else}}unknown{{end}}</span>
        </div>
        <div class="item">
          <span class="label">Time</span>
          <span class="value">{{.Timestamp.Format "2006-01-02 15:04:05 UTC"}}</span>
        </div>
        <div class="item">
          <span class="label">Action</span>
          <span class="value">{{if ge .Status 500}}Recorded{{else}}Blocked{{end}}</span>
        </div>
      </div>
      <div class="help" aria-label="Next steps">
        <div><h2>Visitor</h2><p>If you believe this is a mistake, contact the site owner and provide the Event / Trace ID shown above.</p></div>
        <div><h2>Site operator</h2><p>Search CheeseWAF logs for the Event / Trace ID to review the matched policy, request metadata, and action taken.</p></div>
      </div>
      <footer>This page was generated by CheeseWAF. No origin application details are exposed on this response.</footer>
    </section>
  </main>
</body>
</html>`
