package blockpage

type TemplateInfo struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	HTML        string `json:"html"`
}

func DefaultTemplate() string {
	return defaultBlockTemplate
}

func TemplateByID(id string) (TemplateInfo, bool) {
	for _, item := range TemplateLibrary() {
		if item.ID == id {
			return item, true
		}
	}
	return TemplateInfo{}, false
}

func TemplateLibrary() []TemplateInfo {
	return []TemplateInfo{
		{
			ID:          "minimal",
			Name:        "Operational",
			Description: "Polished responsive block page with event details and Trace ID.",
			HTML:        defaultBlockTemplate,
		},
		{
			ID:          "brand",
			Name:        "Brand",
			Description: "Readable branded response for public sites.",
			HTML: `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Access protected</title>
<style>body{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px;background:#f6f9fc;color:#172033;font-family:system-ui,-apple-system,"Segoe UI",sans-serif}main{width:min(760px,100%);padding:34px;background:#fff;border:1px solid #d9e3ef;border-radius:16px;box-shadow:0 22px 60px rgba(16,24,40,.12)}.eyebrow{color:#2563eb;font-size:13px;font-weight:800;text-transform:uppercase;letter-spacing:.06em}h1{margin:12px 0 10px;font-size:42px;line-height:1.05}p{color:#64748b;line-height:1.65}.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px;margin-top:24px}.box{padding:12px;background:#f8fafc;border:1px solid #e2e8f0;border-radius:10px}.label{display:block;color:#64748b;font-size:12px;font-weight:700}.value{overflow-wrap:anywhere;font-weight:700}code{color:#1d4ed8}@media(max-width:640px){h1{font-size:34px}.grid{grid-template-columns:1fr}}</style></head>
<body><main><span class="eyebrow">CheeseWAF protected this site</span><h1>Access was blocked</h1><p>{{if .Message}}{{.Message}}{{else}}This request matched an active security rule. Contact the site operator with the Trace ID if you need help.{{end}}</p><div class="grid"><div class="box"><span class="label">Trace ID</span><code class="value">{{.TraceID}}</code></div><div class="box"><span class="label">Status</span><span class="value">{{.Status}} {{.StatusText}}</span></div><div class="box"><span class="label">Type</span><span class="value">{{.AttackType}}</span></div><div class="box"><span class="label">Client</span><span class="value">{{.ClientIP}}</span></div></div></main></body></html>`,
		},
		{
			ID:          "technical",
			Name:        "Technical",
			Description: "Detailed page for private operations teams.",
			HTML: `<!doctype html>
<html><head><meta charset="utf-8"><title>CheeseWAF block</title></head>
<body style="font-family:ui-monospace,Consolas,monospace;background:#0b0f14;color:#d5e4ff;padding:32px">
<h1>CheeseWAF block</h1>
<pre>trace={{.TraceID}}
status={{.Status}} {{.StatusText}}
type={{.AttackType}}
client={{.ClientIP}}
time={{.Timestamp}}</pre>
<p>{{.Message}}</p>
</body></html>`,
		},
	}
}
