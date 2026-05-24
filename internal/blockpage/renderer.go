package blockpage

import (
	"bytes"
	"html/template"
	"net/http"
	"time"
)

type Data struct {
	TraceID    string
	AttackType string
	ClientIP   string
	Timestamp  time.Time
	Message    string
}

type Renderer struct {
	template *template.Template
}

func NewRenderer() *Renderer {
	return &Renderer{template: template.Must(template.New("block").Parse(defaultBlockTemplate))}
}

func (r *Renderer) Render(w http.ResponseWriter, status int, data Data) {
	if data.Timestamp.IsZero() {
		data.Timestamp = time.Now().UTC()
	}
	var buf bytes.Buffer
	if err := r.template.Execute(&buf, data); err != nil {
		http.Error(w, "blocked", status)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-CheeseWAF-Trace-ID", data.TraceID)
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

const defaultBlockTemplate = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Request blocked</title>
  <style>
    body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0f1720;color:#edf2f7;font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
    main{max-width:560px;padding:32px}
    h1{font-size:28px;margin:0 0 10px}
    p{color:#aab6c5;line-height:1.6}
    code{display:inline-block;margin-top:16px;padding:10px 12px;border:1px solid #2d3a4b;border-radius:8px;color:#75dcc6}
  </style>
</head>
<body>
  <main>
    <h1>Request blocked</h1>
    <p>CheeseWAF blocked this request because it matched a protection rule.</p>
    <p>Type: {{.AttackType}} · Source: {{.ClientIP}}</p>
    <code>TraceID: {{.TraceID}}</code>
  </main>
</body>
</html>`
