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
			Description: "Formal Cloudflare-style response with CheeseWAF logo, status flow, and Event / Trace ID.",
			HTML:        defaultBlockTemplate,
		},
		{
			ID:          "brand",
			Name:        "Brand",
			Description: "Compact public-facing response with logo, incident details, and support instructions.",
			HTML: `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>Access blocked | CheeseWAF</title>
<style>:root{color-scheme:light dark;--bg:#f5f8fc;--card:#fff;--text:#172033;--muted:#667085;--line:#d8e1ec;--accent:#f2a922;--teal:#0a7978;--shadow:0 24px 70px rgba(15,23,42,.14)}@media(prefers-color-scheme:dark){:root{--bg:#0f1724;--card:#151f2d;--text:#eef4fb;--muted:#9aa8ba;--line:#2b394b;--accent:#ffbd4a;--teal:#35c7c0;--shadow:0 24px 70px rgba(0,0,0,.38)}}*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px;background:var(--bg);color:var(--text);font-family:ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}main{width:min(820px,100%);background:var(--card);border:1px solid var(--line);border-top:4px solid var(--accent);border-radius:8px;box-shadow:var(--shadow);overflow:hidden}.head{padding:30px 34px 22px}.brand{display:flex;align-items:center;gap:12px;margin-bottom:18px;font-weight:850}.logo{width:44px;height:44px;display:grid;place-items:center;border:1px solid var(--line);border-radius:10px}.logo svg{width:35px;height:35px}.eyebrow{margin:0 0 10px;color:var(--teal);font-size:12px;font-weight:900;text-transform:uppercase;letter-spacing:.06em}h1{margin:0;font-size:clamp(32px,5vw,48px);line-height:1.05}p{margin:16px 0 0;color:var(--muted);line-height:1.7}.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));border-top:1px solid var(--line)}.box{min-width:0;padding:16px 20px;border-right:1px solid var(--line);border-bottom:1px solid var(--line)}.box:nth-child(2n){border-right:0}.box:nth-last-child(-n+2){border-bottom:0}.label{display:block;margin-bottom:7px;color:var(--muted);font-size:12px;font-weight:800;text-transform:uppercase}.value{overflow-wrap:anywhere;font-weight:750}code{display:inline-block;max-width:100%;padding:7px 9px;overflow-wrap:anywhere;color:#0b65c2;background:rgba(148,163,184,.12);border:1px solid var(--line);border-radius:6px;font-family:"SFMono-Regular",Consolas,monospace;font-size:13px}.foot{padding:18px 34px 26px;border-top:1px solid var(--line);color:var(--muted);font-size:13px;line-height:1.65}@media(max-width:640px){body{padding:14px}.head{padding:24px 22px 20px}.grid{grid-template-columns:1fr}.box,.box:nth-child(2n),.box:nth-last-child(-n+2){border-right:0;border-bottom:1px solid var(--line)}.box:last-child{border-bottom:0}.foot{padding:16px 22px 22px}}</style></head>
<body><main><div class="head"><div class="brand"><span class="logo" aria-hidden="true"><svg viewBox="0 0 64 64" role="img" focusable="false"><path fill="#0a7978" d="M32 4 57 15v17c0 15-10 24-25 29C17 56 7 47 7 32V15L32 4Z"/><path fill="#073f45" d="M32 9v46c12-5 20-12 20-23V18L32 9Z"/><path fill="#ffc928" d="M14 19 32 10v44C21 49 14 42 14 31V19Z"/><circle cx="24" cy="26" r="5" fill="#d88400"/><circle cx="28" cy="40" r="4" fill="#d88400"/><path fill="#35c7c0" d="M41 47c-7-3-9-8-7-14 1-4 5-7 7-12 3 4 3 8 2 11 3-1 5-4 6-7 5 8 4 18-8 22Z"/><path fill="#128782" d="M35 42h16v4H35v-4Zm0-9h8v4h-8v-4Zm13 0h6v4h-6v-4Z"/></svg></span><span>CheeseWAF</span></div><p class="eyebrow">Security response</p><h1>Access was blocked</h1><p>{{if .Message}}{{.Message}}{{else}}This request matched an active security rule. Contact the site operator with the Event / Trace ID if you need help.{{end}}</p></div><div class="grid"><div class="box"><span class="label">Event / Trace ID</span><code class="value">{{.EventID}}</code></div><div class="box"><span class="label">Status</span><span class="value">{{.Status}} {{.StatusText}}</span></div><div class="box"><span class="label">Type</span><span class="value">{{if .AttackType}}{{.AttackType}}{{else}}waf_block{{end}}</span></div><div class="box"><span class="label">Client</span><span class="value">{{if .ClientIP}}{{.ClientIP}}{{else}}unknown{{end}}</span></div></div><div class="foot">Provide the Event / Trace ID to the site operator. It maps to the matching CheeseWAF security event and is safe to share for troubleshooting.</div></main></body></html>`,
		},
		{
			ID:          "technical",
			Name:        "Technical",
			Description: "Detailed page for private operations teams.",
			HTML: `<!doctype html>
<html><head><meta charset="utf-8"><title>CheeseWAF block</title></head>
<body style="font-family:ui-monospace,Consolas,monospace;background:#0b0f14;color:#d5e4ff;padding:32px">
<h1>CheeseWAF block</h1>
<pre>event={{.EventID}}
trace={{.TraceID}}
status={{.Status}} {{.StatusText}}
type={{.AttackType}}
client={{.ClientIP}}
time={{.Timestamp}}</pre>
<p>{{.Message}}</p>
</body></html>`,
		},
	}
}
