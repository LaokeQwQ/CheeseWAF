// Package bot implements lightweight bot scoring and JS clearance challenges.
package bot

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

type Policy struct {
	enabled              bool
	jsChallenge          bool
	captcha              bool
	ttl                  time.Duration
	cookieName           string
	secret               []byte
	pathPrefixes         []string
	exemptPathPrefixes   []string
	allowedUserAgents    []string
	suspiciousUserAgents []string
	now                  func() time.Time
}

func NewPolicy(cfg config.BotProtectionConfig) *Policy {
	if cfg.ChallengeTTL <= 0 {
		cfg.ChallengeTTL = 30 * time.Minute
	}
	if cfg.CookieName == "" {
		cfg.CookieName = "cheesewaf_js_clearance"
	}
	if cfg.Secret == "" {
		cfg.Secret = "change-me-in-production"
	}
	if len(cfg.PathPrefixes) == 0 {
		cfg.PathPrefixes = []string{"/"}
	}
	if len(cfg.ExemptPathPrefixes) == 0 {
		cfg.ExemptPathPrefixes = []string{"/health", "/api/"}
	}
	if len(cfg.SuspiciousUserAgents) == 0 {
		cfg.SuspiciousUserAgents = []string{"curl", "python-requests", "sqlmap", "nikto", "nuclei", "masscan", "zgrab", "httpclient"}
	}
	return &Policy{
		enabled:              cfg.Enabled,
		jsChallenge:          cfg.JSChallenge,
		captcha:              cfg.CAPTCHA,
		ttl:                  cfg.ChallengeTTL,
		cookieName:           cfg.CookieName,
		secret:               []byte(cfg.Secret),
		pathPrefixes:         cleanList(cfg.PathPrefixes),
		exemptPathPrefixes:   cleanList(cfg.ExemptPathPrefixes),
		allowedUserAgents:    lowerList(cfg.AllowedUserAgents),
		suspiciousUserAgents: lowerList(cfg.SuspiciousUserAgents),
		now:                  time.Now,
	}
}

func (p *Policy) Evaluate(r *http.Request, clientIP string) *engine.DetectionResult {
	if p == nil || !p.enabled || r == nil || !p.applies(r.URL.Path) {
		return nil
	}
	if p.allowed(r.UserAgent()) || p.hasClearance(r, clientIP) {
		return nil
	}
	if !p.suspicious(r) {
		return nil
	}
	action := engine.ActionBlock
	message := "bot traffic blocked"
	if p.jsChallenge || p.captcha {
		action = engine.ActionChallenge
		message = "bot traffic requires browser verification"
	}
	return &engine.DetectionResult{
		Detected:   true,
		DetectorID: "bot.policy",
		Category:   "bot",
		Severity:   engine.SeverityMedium,
		Action:     action,
		Message:    message,
		Confidence: 0.82,
		Payload:    r.UserAgent(),
	}
}

func (p *Policy) ServeChallenge(w http.ResponseWriter, r *http.Request, clientIP string) {
	if p == nil {
		http.Error(w, "bot challenge unavailable", http.StatusForbidden)
		return
	}
	value, maxAge := p.clearance(r, clientIP)
	data := challengeData{
		CookieName:  p.cookieName,
		CookieValue: url.QueryEscape(value),
		MaxAge:      maxAge,
		ReturnURL:   r.URL.RequestURI(),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusForbidden)
	_ = challengeTemplate.Execute(w, data)
}

func (p *Policy) clearance(r *http.Request, clientIP string) (string, int) {
	expires := p.now().Add(p.ttl).Unix()
	signature := p.sign(r, clientIP, expires)
	return fmt.Sprintf("%d:%s", expires, signature), int(p.ttl.Seconds())
}

func (p *Policy) hasClearance(r *http.Request, clientIP string) bool {
	cookie, err := r.Cookie(p.cookieName)
	if err != nil {
		return false
	}
	parts := strings.SplitN(cookie.Value, ":", 2)
	if len(parts) != 2 {
		return false
	}
	expires, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || expires <= p.now().Unix() {
		return false
	}
	want := p.sign(r, clientIP, expires)
	return hmac.Equal([]byte(want), []byte(parts[1]))
}

func (p *Policy) sign(r *http.Request, clientIP string, expires int64) string {
	mac := hmac.New(sha256.New, p.secret)
	_, _ = mac.Write([]byte(clientIP))
	_, _ = mac.Write([]byte{'\n'})
	_, _ = mac.Write([]byte(r.UserAgent()))
	_, _ = mac.Write([]byte{'\n'})
	_, _ = mac.Write([]byte(strconv.FormatInt(expires, 10)))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (p *Policy) applies(path string) bool {
	for _, prefix := range p.exemptPathPrefixes {
		if prefix != "" && strings.HasPrefix(path, prefix) {
			return false
		}
	}
	for _, prefix := range p.pathPrefixes {
		if prefix == "" || strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

func (p *Policy) allowed(userAgent string) bool {
	ua := strings.ToLower(userAgent)
	for _, item := range p.allowedUserAgents {
		if item != "" && strings.Contains(ua, item) {
			return true
		}
	}
	return false
}

func (p *Policy) suspicious(r *http.Request) bool {
	ua := strings.ToLower(strings.TrimSpace(r.UserAgent()))
	if ua == "" {
		return true
	}
	for _, item := range p.suspiciousUserAgents {
		if item != "" && strings.Contains(ua, item) {
			return true
		}
	}
	if r.Header.Get("Accept") == "" && r.Header.Get("Accept-Language") == "" {
		return true
	}
	return false
}

func cleanList(items []string) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}

func lowerList(items []string) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.ToLower(strings.TrimSpace(item))
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}

type challengeData struct {
	CookieName  string
	CookieValue string
	MaxAge      int
	ReturnURL   string
}

var challengeTemplate = template.Must(template.New("bot-challenge").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Browser verification</title>
  <style>
    body{margin:0;font-family:Inter,Segoe UI,Arial,sans-serif;background:#0f172a;color:#e2e8f0;display:grid;min-height:100vh;place-items:center}
    main{width:min(520px,calc(100% - 32px));border:1px solid #334155;border-radius:8px;background:#111827;padding:28px;box-shadow:0 24px 80px rgba(0,0,0,.35)}
    h1{margin:0 0 8px;font-size:22px;line-height:1.2}
    p{margin:0 0 18px;color:#94a3b8;line-height:1.6}
    .bar{height:6px;border-radius:999px;background:#1e293b;overflow:hidden}
    .bar span{display:block;width:45%;height:100%;background:#22c55e;animation:load 1.2s ease-in-out infinite alternate}
    @keyframes load{from{transform:translateX(-30%)}to{transform:translateX(140%)}}
    noscript{display:block;margin-top:16px;color:#fca5a5}
  </style>
</head>
<body>
  <main>
    <h1>Browser verification</h1>
    <p>CheeseWAF is checking that this request comes from a browser. This page reloads automatically.</p>
    <div class="bar"><span></span></div>
    <noscript>JavaScript is required to pass this challenge.</noscript>
  </main>
  <script>
    document.cookie = "{{.CookieName}}={{.CookieValue}}; Path=/; Max-Age={{.MaxAge}}; SameSite=Lax";
    window.setTimeout(function(){ window.location.replace("{{.ReturnURL}}"); }, 350);
  </script>
</body>
</html>`))
