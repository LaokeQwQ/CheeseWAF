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
			Description: "Operational response with CheeseWAF logo, status flow, and Event / Trace ID.",
			HTML:        defaultBlockTemplate,
		},
		{
			ID:          "brand",
			Name:        "Brand",
			Description: "Compact public-facing response with logo, incident details, and support instructions.",
			HTML: `<!doctype html>
<html lang="{{.Text.HTMLLang}}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>{{if ge .Status 500}}{{.Text.EyebrowError}}{{else}}{{.Text.Title}}{{end}} | CheeseWAF</title>
<style>:root{color-scheme:light dark;--bg:#f5f8fc;--card:#fff;--text:#172033;--muted:#667085;--line:#d8e1ec;--accent:#f2a922;--teal:#0a7978;--shadow:0 24px 70px rgba(15,23,42,.14)}@media(prefers-color-scheme:dark){:root{--bg:#0f1724;--card:#151f2d;--text:#eef4fb;--muted:#9aa8ba;--line:#2b394b;--accent:#ffbd4a;--teal:#35c7c0;--shadow:0 24px 70px rgba(0,0,0,.38)}}*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:start center;padding:32px 24px 24px;background:var(--bg);color:var(--text);font-family:ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}main{width:min(820px,100%);background:var(--card);border:1px solid var(--line);border-top:4px solid var(--accent);border-radius:8px;box-shadow:var(--shadow);overflow:hidden}.head{padding:30px 34px 22px}.brand{display:flex;align-items:center;gap:12px;margin-bottom:18px;font-weight:850}.logo{width:44px;height:44px;display:grid;place-items:center;border:1px solid var(--line);border-radius:10px}.logo svg{width:35px;height:35px}.eyebrow{margin:0 0 10px;color:var(--teal);font-size:12px;font-weight:900;text-transform:uppercase;letter-spacing:.06em}h1{margin:0;font-size:clamp(32px,5vw,48px);line-height:1.05}p{margin:16px 0 0;color:var(--muted);line-height:1.7}.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));border-top:1px solid var(--line)}.box{min-width:0;padding:16px 20px;border-right:1px solid var(--line);border-bottom:1px solid var(--line)}.box:nth-child(2n){border-right:0}.box:nth-last-child(-n+2){border-bottom:0}.label{display:block;margin-bottom:7px;color:var(--muted);font-size:12px;font-weight:800;text-transform:uppercase}.value{overflow-wrap:anywhere;font-weight:750}code{display:inline-block;max-width:100%;padding:7px 9px;overflow-wrap:anywhere;color:#0b65c2;background:rgba(148,163,184,.12);border:1px solid var(--line);border-radius:6px;font-family:"SFMono-Regular",Consolas,monospace;font-size:13px}.foot{padding:18px 34px 26px;border-top:1px solid var(--line);color:var(--muted);font-size:13px;line-height:1.65}.attr{display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:10px 16px;padding:14px 34px 22px;border-top:1px solid var(--line);color:var(--muted);font-size:12px}.attr-row{display:flex;flex-wrap:wrap;align-items:center;gap:6px 12px}.attr-brand{display:inline-flex;align-items:center;gap:6px;color:var(--text);font-weight:750;text-decoration:none}.attr-logo{width:18px;height:18px;display:inline-grid;place-items:center}.attr-logo svg{width:18px;height:18px;display:block}.attr-copy{color:var(--muted);text-decoration:none}.attr-copy:hover{color:var(--text);text-decoration:underline}@media(max-width:640px){body{padding:16px 14px 14px}.head{padding:24px 22px 20px}.grid{grid-template-columns:1fr}.box,.box:nth-child(2n),.box:nth-last-child(-n+2){border-right:0;border-bottom:1px solid var(--line)}.box:last-child{border-bottom:0}.foot,.attr{padding:16px 22px 22px}}</style></head>
<body><main><div class="head"><div class="brand"><span class="logo" aria-hidden="true"><svg viewBox="0 0 64 64" role="img" focusable="false"><defs><linearGradient id="cw-shield" x1="12" y1="8" x2="54" y2="58" gradientUnits="userSpaceOnUse"><stop stop-color="#0f8f77"/><stop offset="1" stop-color="#075e64"/></linearGradient><linearGradient id="cw-cheese" x1="17" y1="13" x2="39" y2="50" gradientUnits="userSpaceOnUse"><stop stop-color="#ffe98a"/><stop offset=".52" stop-color="#ffc928"/><stop offset="1" stop-color="#f3a51b"/></linearGradient></defs><path fill="url(#cw-shield)" d="M32 4 56 14.7v16.6C56 45.6 46.6 55.1 32 60 17.4 55.1 8 45.6 8 31.3V14.7L32 4Z"/><path fill="#f8fffb" fill-opacity=".86" d="M32 9.7 14.5 17.4v13.2c0 10.8 6.5 18.2 17.5 22.4 11-4.2 17.5-11.6 17.5-22.4V17.4L32 9.7Z"/><path fill="url(#cw-cheese)" d="M18.4 20.2 32 14.4v37.2c-8.7-3.8-13.6-10-13.6-19.4v-12Z"/><path fill="#0f8f77" d="M35.5 23.5h9.8v4.4h-9.8v-4.4Zm0 8.1h13.1V36H35.5v-4.4Zm0 8.1h8.4V44h-8.4v-4.3Z"/><circle cx="25.2" cy="27" r="3.7" fill="#d88400"/><circle cx="28.7" cy="40.3" r="2.9" fill="#d88400"/><circle cx="21.8" cy="35.3" r="1.9" fill="#d88400"/></svg></span><span>CheeseWAF</span></div><p class="eyebrow">{{if ge .Status 500}}{{.Text.EyebrowError}}{{else}}{{.Text.EyebrowSecurity}}{{end}}</p><h1>{{if ge .Status 500}}{{.Text.HeadlineError}}{{else}}{{.Text.HeadlineBlocked}}{{end}}</h1><p>{{if ge .Status 500}}{{.Text.DefaultError}}{{else}}{{.Text.DefaultBlocked}}{{end}}</p></div><div class="grid"><div class="box"><span class="label">{{.Text.EventTraceID}}</span><code class="value">{{.EventID}}</code></div><div class="box"><span class="label">{{.Text.HTTPStatus}}</span><span class="value">{{.Status}} {{.StatusText}}</span></div><div class="box"><span class="label">{{.Text.EventType}}</span><span class="value">{{if .AttackType}}{{.AttackType}}{{else}}waf_block{{end}}</span></div><div class="box"><span class="label">{{.Text.ClientIP}}</span><span class="value">{{if .ClientIP}}{{.ClientIP}}{{else}}{{.Text.Unknown}}{{end}}</span></div></div><div class="foot"><strong>{{.Text.NoticePrefix}}</strong> {{.Text.NoticeBody}}</div><div class="attr" aria-label="Attribution"><div class="attr-row"><span>{{.Text.YourIP}}: <strong>{{if .ClientIP}}{{.ClientIP}}{{else}}{{.Text.Unknown}}{{end}}</strong></span><span aria-hidden="true">·</span><span class="attr-row"><span>{{.Text.PerfSecBy}}</span><a class="attr-brand" href="{{.Text.RepoURL}}" rel="noopener noreferrer" target="_blank"><span class="attr-logo" aria-hidden="true"><svg viewBox="0 0 64 64" role="img" focusable="false"><defs><linearGradient id="cw-ft-shield" x1="12" y1="8" x2="54" y2="58" gradientUnits="userSpaceOnUse"><stop stop-color="#0f8f77"/><stop offset="1" stop-color="#075e64"/></linearGradient><linearGradient id="cw-ft-cheese" x1="17" y1="13" x2="39" y2="50" gradientUnits="userSpaceOnUse"><stop stop-color="#ffe98a"/><stop offset=".52" stop-color="#ffc928"/><stop offset="1" stop-color="#f3a51b"/></linearGradient></defs><path fill="url(#cw-ft-shield)" d="M32 4 56 14.7v16.6C56 45.6 46.6 55.1 32 60 17.4 55.1 8 45.6 8 31.3V14.7L32 4Z"/><path fill="#f8fffb" fill-opacity=".86" d="M32 9.7 14.5 17.4v13.2c0 10.8 6.5 18.2 17.5 22.4 11-4.2 17.5-11.6 17.5-22.4V17.4L32 9.7Z"/><path fill="url(#cw-ft-cheese)" d="M18.4 20.2 32 14.4v37.2c-8.7-3.8-13.6-10-13.6-19.4v-12Z"/><circle cx="25.2" cy="27" r="3.7" fill="#d88400"/></svg></span><span>{{.Text.BrandName}}</span></a></span></div><a class="attr-copy" href="{{.Text.RepoURL}}" rel="noopener noreferrer" target="_blank">{{.Text.Copyright}}</a></div></main></body></html>`,
		},
		{
			ID:          "technical",
			Name:        "Technical",
			Description: "Detailed page for private operations teams.",
			HTML: `<!doctype html>
<html lang="{{.Text.HTMLLang}}"><head><meta charset="utf-8"><title>{{if ge .Status 500}}{{.Text.EyebrowError}}{{else}}{{.Text.Title}}{{end}} | CheeseWAF</title></head>
<body style="font-family:ui-monospace,Consolas,monospace;background:#0b0f14;color:#d5e4ff;padding:32px">
<h1>{{if ge .Status 500}}{{.Text.HeadlineError}}{{else}}{{.Text.HeadlineBlocked}}{{end}}</h1>
<p>{{if ge .Status 500}}{{.Text.DefaultError}}{{else}}{{.Text.DefaultBlocked}}{{end}}</p>
<pre>{{.Text.EventTraceID}}={{.EventID}}
trace={{.TraceID}}
{{.Text.HTTPStatus}}={{.Status}} {{.StatusText}}
{{.Text.EventType}}={{.AttackType}}
{{.Text.ClientIP}}={{if .ClientIP}}{{.ClientIP}}{{else}}{{.Text.Unknown}}{{end}}
{{.Text.Time}}={{.TimestampLocal}}</pre>
<p>{{.Text.Footer}}</p>
<p>{{.Text.YourIP}}: {{if .ClientIP}}{{.ClientIP}}{{else}}{{.Text.Unknown}}{{end}} · {{.Text.PerfSecBy}} <a href="{{.Text.RepoURL}}" rel="noopener noreferrer" target="_blank">{{.Text.BrandName}}</a> · <a href="{{.Text.RepoURL}}" rel="noopener noreferrer" target="_blank">{{.Text.Copyright}}</a></p>
</body></html>`,
		},
	}
}
