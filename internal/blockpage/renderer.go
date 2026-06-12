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

const defaultBlockTemplate = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Request blocked | CheeseWAF</title>
  <style>
    :root{color-scheme:light dark;--bg:#f4f7fb;--panel:#ffffff;--panel-soft:#f8fafc;--text:#152033;--muted:#64748b;--line:#dbe4ee;--accent:#2563eb;--danger:#b42318;--danger-soft:#fff1f0;--shadow:0 24px 70px rgba(15,23,42,.14)}
    @media (prefers-color-scheme:dark){:root{--bg:#0e141d;--panel:#151d29;--panel-soft:#101824;--text:#e6edf7;--muted:#96a3b7;--line:#263446;--accent:#6ea8ff;--danger:#ff8b7f;--danger-soft:#2a1718;--shadow:0 24px 70px rgba(0,0,0,.36)}}
    *{box-sizing:border-box}
    body{margin:0;min-height:100vh;display:grid;place-items:center;padding:28px;background:radial-gradient(circle at top left,rgba(37,99,235,.12),transparent 32rem),linear-gradient(135deg,var(--bg),var(--panel-soft));color:var(--text);font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
    main{width:min(920px,100%);display:grid;grid-template-columns:minmax(0,1.05fr) minmax(280px,.95fr);gap:0;overflow:hidden;background:var(--panel);border:1px solid var(--line);border-radius:18px;box-shadow:var(--shadow)}
    section{padding:34px}
    .hero{display:grid;align-content:space-between;gap:42px;background:linear-gradient(160deg,var(--danger-soft),var(--panel));border-right:1px solid var(--line)}
    .brand{display:flex;align-items:center;gap:10px;color:var(--muted);font-size:13px;font-weight:700;letter-spacing:.04em;text-transform:uppercase}
    .mark{width:32px;height:32px;display:grid;place-items:center;color:#fff;background:linear-gradient(135deg,#f7c948,#e2a100 42%,#2563eb);border-radius:10px;box-shadow:0 12px 24px rgba(37,99,235,.18)}
    h1{margin:0;color:var(--text);font-size:clamp(32px,6vw,56px);line-height:1.02;letter-spacing:0}
    .lead{max-width:58ch;margin:16px 0 0;color:var(--muted);font-size:16px;line-height:1.65}
    .status{display:inline-flex;align-items:center;gap:8px;width:max-content;padding:8px 12px;color:var(--danger);font-weight:700;background:var(--danger-soft);border:1px solid color-mix(in srgb,var(--danger) 28%,var(--line));border-radius:999px}
    .dot{width:9px;height:9px;background:currentColor;border-radius:50%;box-shadow:0 0 0 6px color-mix(in srgb,currentColor 12%,transparent)}
    .details{display:grid;gap:12px;background:var(--panel)}
    .item{display:grid;gap:6px;padding:14px 0;border-bottom:1px solid var(--line)}
    .item:last-child{border-bottom:0}
    .label{color:var(--muted);font-size:12px;font-weight:700;letter-spacing:.04em;text-transform:uppercase}
    .value{min-width:0;overflow-wrap:anywhere;font-size:15px;line-height:1.45}
    code{display:inline-block;max-width:100%;padding:9px 11px;overflow-wrap:anywhere;color:var(--accent);background:var(--panel-soft);border:1px solid var(--line);border-radius:10px;font-family:"SFMono-Regular",Consolas,"Liberation Mono",monospace;font-size:13px}
    footer{margin-top:18px;color:var(--muted);font-size:12px;line-height:1.55}
    @media (max-width:720px){body{padding:16px}main{grid-template-columns:1fr;border-radius:14px}.hero{border-right:0;border-bottom:1px solid var(--line)}section{padding:24px}h1{font-size:36px}}
  </style>
</head>
<body>
  <main>
    <section class="hero">
      <div class="brand"><span class="mark">CW</span><span>CheeseWAF Protection</span></div>
      <div>
        <span class="status"><span class="dot"></span>Request blocked</span>
        <h1>Your request was stopped before it reached the origin.</h1>
        <p class="lead">{{if .Message}}{{.Message}}{{else}}CheeseWAF matched this request against an active protection rule. If you believe this was a mistake, share the Event / Trace ID with the site operator.{{end}}</p>
      </div>
      <footer>This response was generated by CheeseWAF. The Event / Trace ID below maps to the security event stored by the WAF.</footer>
    </section>
    <section class="details" aria-label="Block details">
      <div class="item">
        <span class="label">Event / Trace ID</span>
        <code>{{.EventID}}</code>
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
        <span class="label">HTTP status</span>
        <span class="value">{{.Status}} {{.StatusText}}</span>
      </div>
    </section>
  </main>
</body>
</html>`
