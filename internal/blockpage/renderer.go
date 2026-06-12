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
  <title>Request blocked | CheeseWAF</title>
  <style>
    :root{color-scheme:light dark;--bg:#f6f8fb;--panel:#ffffff;--panel-soft:#f9fafb;--text:#1f2937;--muted:#687385;--line:#d9e1ea;--line-strong:#c7d2df;--accent:#f6a821;--accent-dark:#c77800;--ok:#12a150;--danger:#b42318;--shadow:0 24px 70px rgba(15,23,42,.12)}
    @media (prefers-color-scheme:dark){:root{--bg:#101722;--panel:#161f2c;--panel-soft:#111a26;--text:#edf2f8;--muted:#9ca8b8;--line:#2b394b;--line-strong:#3b4a60;--accent:#ffbd4a;--accent-dark:#f6a821;--ok:#52d48d;--danger:#ff8b7f;--shadow:0 24px 70px rgba(0,0,0,.36)}}
    *{box-sizing:border-box}
    body{margin:0;min-height:100vh;background:var(--bg);color:var(--text);font-family:ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
    main{width:min(980px,100%);min-height:100vh;margin:0 auto;padding:46px 28px 34px;display:grid;align-content:center;gap:26px}
    .brand{display:flex;align-items:center;gap:12px;width:max-content;color:var(--text);font-size:15px;font-weight:800}
    .logo{width:44px;height:44px;display:grid;place-items:center;background:var(--panel);border:1px solid var(--line-strong);border-radius:8px;box-shadow:0 10px 28px rgba(15,23,42,.08)}
    .logo svg{width:32px;height:32px;display:block}
    .card{background:var(--panel);border:1px solid var(--line);border-top:4px solid var(--accent);border-radius:6px;box-shadow:var(--shadow);overflow:hidden}
    .summary{padding:34px 38px 30px;border-bottom:1px solid var(--line)}
    .eyebrow{margin:0 0 12px;color:var(--accent-dark);font-size:13px;font-weight:800;text-transform:uppercase}
    h1{margin:0;color:var(--text);font-size:clamp(34px,5vw,52px);line-height:1.05;letter-spacing:0}
    .lead{max-width:70ch;margin:18px 0 0;color:var(--muted);font-size:16px;line-height:1.7}
    .checks{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));border-bottom:1px solid var(--line)}
    .check{min-width:0;padding:20px 24px;border-right:1px solid var(--line)}
    .check:last-child{border-right:0}
    .check strong{display:block;margin-bottom:6px;color:var(--text);font-size:15px}
    .check span{display:flex;align-items:center;gap:8px;color:var(--muted);font-size:13px}
    .dot{width:9px;height:9px;flex:none;border-radius:50%;background:var(--ok);box-shadow:0 0 0 4px color-mix(in srgb,var(--ok) 14%,transparent)}
    .dot-warning{background:var(--accent);box-shadow:0 0 0 4px color-mix(in srgb,var(--accent) 20%,transparent)}
    .details{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:0;padding:10px 38px 28px}
    .item{min-width:0;padding:18px 0;border-bottom:1px solid var(--line)}
    .item:nth-last-child(-n+2){border-bottom:0}
    .label{display:block;margin-bottom:7px;color:var(--muted);font-size:12px;font-weight:800;text-transform:uppercase}
    .value{min-width:0;overflow-wrap:anywhere;font-size:15px;line-height:1.45}
    code{display:inline-block;max-width:100%;padding:8px 10px;overflow-wrap:anywhere;color:#0b65c2;background:var(--panel-soft);border:1px solid var(--line-strong);border-radius:6px;font-family:"SFMono-Regular",Consolas,"Liberation Mono",monospace;font-size:13px}
    footer{padding:18px 38px 28px;color:var(--muted);font-size:13px;line-height:1.65}
    @media (max-width:720px){main{padding:28px 16px}.summary{padding:26px 22px}.checks{grid-template-columns:1fr}.check{border-right:0;border-bottom:1px solid var(--line)}.check:last-child{border-bottom:0}.details{grid-template-columns:1fr;padding:8px 22px 20px}.item:nth-last-child(-n+2){border-bottom:1px solid var(--line)}.item:last-child{border-bottom:0}footer{padding:16px 22px 24px}h1{font-size:34px}}
  </style>
</head>
<body>
  <main>
    <div class="brand">
      <span class="logo" aria-hidden="true">
        <svg viewBox="0 0 48 48" role="img" focusable="false"><path fill="#f4b23d" d="M7 13 24 5l17 8v12c0 10-7 16-17 20C14 41 7 35 7 25V13Z"/><path fill="#fff2bf" d="M13 16 24 11l11 5v8c0 7-4 11-11 14-7-3-11-7-11-14v-8Z"/><path fill="#1f2937" d="M17 21h14v4H17v-4Zm0 7h10v4H17v-4Z"/><circle cx="31" cy="18" r="2.2" fill="#d18400"/><circle cx="22" cy="34" r="1.8" fill="#d18400"/></svg>
      </span>
      <span>CheeseWAF</span>
    </div>
    <section class="card" aria-label="CheeseWAF security response">
      <div class="summary">
        <p class="eyebrow">Security response</p>
        <h1>Request could not be completed</h1>
        <p class="lead">{{if .Message}}{{.Message}}{{else}}The request was stopped by an active CheeseWAF security policy before it reached the protected origin. If you believe this action is incorrect, contact the site operator and provide the Event / Trace ID below.{{end}}</p>
      </div>
      <div class="checks" aria-label="Connection status">
        <div class="check"><strong>Client</strong><span><i class="dot"></i>Request received</span></div>
        <div class="check"><strong>CheeseWAF</strong><span><i class="dot dot-warning"></i>Security policy applied</span></div>
        <div class="check"><strong>Origin</strong><span><i class="dot"></i>Protected</span></div>
      </div>
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
      </div>
      <footer>This page was generated by CheeseWAF. The Event / Trace ID maps to the corresponding security or upstream error event in the WAF logs.</footer>
    </section>
  </main>
</body>
</html>`
