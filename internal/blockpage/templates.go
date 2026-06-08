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

func TemplateLibrary() []TemplateInfo {
	return []TemplateInfo{
		{
			ID:          "minimal",
			Name:        "Minimal",
			Description: "Compact operational block page with TraceID.",
			HTML:        defaultBlockTemplate,
		},
		{
			ID:          "brand",
			Name:        "Brand",
			Description: "Readable branded response for public sites.",
			HTML: `<!doctype html>
<html><head><meta charset="utf-8"><title>Request blocked</title></head>
<body style="font-family:system-ui;margin:0;min-height:100vh;display:grid;place-items:center;background:#101820;color:#fff">
<main style="max-width:560px;padding:32px">
<h1 style="margin:0 0 12px">Request blocked</h1>
<p style="color:#cad2dc">CheeseWAF stopped this request before it reached the origin.</p>
<p>TraceID: <code>{{.TraceID}}</code></p>
<p>Type: {{.AttackType}} | Client: {{.ClientIP}}</p>
</main></body></html>`,
		},
		{
			ID:          "technical",
			Name:        "Technical",
			Description: "Detailed page for private operations teams.",
			HTML: `<!doctype html>
<html><head><meta charset="utf-8"><title>CheeseWAF block</title></head>
<body style="font-family:ui-monospace,Consolas,monospace;background:#0b0f14;color:#d5e4ff;padding:32px">
<h1>403 CheeseWAF</h1>
<pre>trace={{.TraceID}}
type={{.AttackType}}
client={{.ClientIP}}
time={{.Timestamp}}</pre>
<p>{{.Message}}</p>
</body></html>`,
		},
	}
}
