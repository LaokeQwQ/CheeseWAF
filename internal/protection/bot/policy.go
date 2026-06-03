// Package bot implements lightweight bot scoring and JS clearance challenges.
package bot

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

type Policy struct {
	enabled              bool
	jsChallenge          bool
	captcha              bool
	challengeDifficulty  int
	altchaMaxNumber      int
	altchaHeaderName     string
	waitingRoom          bool
	waitingRoomMaxActive int
	waitingRoomTTL       time.Duration
	ttl                  time.Duration
	cookieName           string
	waitingCookieName    string
	secret               []byte
	pathPrefixes         []string
	exemptPathPrefixes   []string
	allowedUserAgents    []string
	suspiciousUserAgents []string
	now                  func() time.Time
	mu                   sync.Mutex
	active               map[string]int64
}

func NewPolicy(cfg config.BotProtectionConfig) *Policy {
	if cfg.ChallengeTTL <= 0 {
		cfg.ChallengeTTL = 30 * time.Minute
	}
	if cfg.CookieName == "" {
		cfg.CookieName = "cheesewaf_js_clearance"
	}
	if cfg.ChallengeDifficulty <= 0 {
		cfg.ChallengeDifficulty = 4
	}
	if cfg.ChallengeDifficulty > 6 {
		cfg.ChallengeDifficulty = 6
	}
	if cfg.AltchaMaxNumber <= 0 {
		cfg.AltchaMaxNumber = altchaMaxNumberForDifficulty(cfg.ChallengeDifficulty)
	}
	if cfg.AltchaHeaderName == "" {
		cfg.AltchaHeaderName = "X-CheeseWAF-Altcha"
	}
	if cfg.WaitingRoomMaxActive <= 0 {
		cfg.WaitingRoomMaxActive = 1000
	}
	if cfg.WaitingRoomTTL <= 0 {
		cfg.WaitingRoomTTL = 5 * time.Minute
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
		challengeDifficulty:  cfg.ChallengeDifficulty,
		altchaMaxNumber:      cfg.AltchaMaxNumber,
		altchaHeaderName:     cfg.AltchaHeaderName,
		waitingRoom:          cfg.WaitingRoom,
		waitingRoomMaxActive: cfg.WaitingRoomMaxActive,
		waitingRoomTTL:       cfg.WaitingRoomTTL,
		ttl:                  cfg.ChallengeTTL,
		cookieName:           cfg.CookieName,
		waitingCookieName:    cfg.CookieName + "_queue",
		secret:               []byte(cfg.Secret),
		pathPrefixes:         cleanList(cfg.PathPrefixes),
		exemptPathPrefixes:   cleanList(cfg.ExemptPathPrefixes),
		allowedUserAgents:    lowerList(cfg.AllowedUserAgents),
		suspiciousUserAgents: lowerList(cfg.SuspiciousUserAgents),
		now:                  time.Now,
		active:               map[string]int64{},
	}
}

func (p *Policy) Evaluate(r *http.Request, clientIP string) *engine.DetectionResult {
	if p == nil || !p.enabled || r == nil || !p.applies(r.URL.Path) {
		return nil
	}
	if p.waitingRoom && !p.hasWaitingTicket(r, clientIP) {
		return &engine.DetectionResult{
			Detected:   true,
			DetectorID: "bot.waiting_room",
			Category:   "waiting_room",
			Severity:   engine.SeverityLow,
			Action:     engine.ActionChallenge,
			Message:    "request is waiting for an available browser slot",
			Confidence: 0.7,
			Payload:    r.URL.Path,
		}
	}
	if p.allowed(r.UserAgent()) || p.hasClearance(r, clientIP) || p.validAltchaHeaderAnswer(r, clientIP) {
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
	if p.waitingRoom && !p.hasWaitingTicket(r, clientIP) {
		p.serveWaitingRoom(w, r, clientIP)
		return
	}
	if p.validChallengeAnswer(r, clientIP) {
		value, maxAge := p.clearance(r, clientIP)
		http.SetCookie(w, &http.Cookie{
			Name:     p.cookieName,
			Value:    value,
			Path:     "/",
			MaxAge:   maxAge,
			SameSite: http.SameSiteLaxMode,
		})
		http.Redirect(w, r, cleanChallengeURL(r), http.StatusFound)
		return
	}
	var altcha *altchaChallenge
	if p.captcha {
		challenge, err := p.newAltchaChallenge(r, clientIP)
		if err != nil {
			http.Error(w, "bot challenge unavailable", http.StatusInternalServerError)
			return
		}
		altcha = &challenge
		challengeJSON, _ := json.Marshal(challenge)
		w.Header().Set("WWW-Authenticate", "Altcha challenge="+string(challengeJSON))
		w.Header().Set("X-Altcha-Authorization-Header", p.altchaHeaderName)
	}
	nonce, err := randomToken(18)
	if err != nil {
		http.Error(w, "bot challenge unavailable", http.StatusInternalServerError)
		return
	}
	expires := p.now().Add(2 * time.Minute).Unix()
	value, maxAge := p.clearance(r, clientIP)
	data := challengeData{
		CookieName:  p.cookieName,
		CookieValue: url.QueryEscape(value),
		MaxAge:      maxAge,
		ReturnURL:   cleanChallengeURL(r),
		Nonce:       nonce,
		Expires:     expires,
		Signature:   p.signChallenge(r, clientIP, nonce, expires),
		Difficulty:  p.challengeDifficulty,
		UseAltcha:   altcha != nil,
	}
	if altcha != nil {
		data.AltchaAlgorithm = altcha.Algorithm
		data.AltchaChallenge = altcha.Challenge
		data.AltchaMaxNumber = altcha.MaxNumber
		data.AltchaSalt = altcha.Salt
		data.AltchaSignature = altcha.Signature
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusForbidden)
	_ = challengeTemplate.Execute(w, data)
}

func (p *Policy) serveWaitingRoom(w http.ResponseWriter, r *http.Request, clientIP string) {
	value, maxAge, admitted, active, capacity := p.waitingTicket(r, clientIP)
	data := waitingData{
		CookieName:  p.waitingCookieName,
		CookieValue: url.QueryEscape(value),
		MaxAge:      maxAge,
		ReturnURL:   r.URL.RequestURI(),
		Admitted:    admitted,
		Active:      active,
		Capacity:    capacity,
		RetryAfter:  3,
	}
	if !admitted {
		w.Header().Set("Retry-After", strconv.Itoa(data.RetryAfter))
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusTooManyRequests)
	_ = waitingTemplate.Execute(w, data)
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

func (p *Policy) hasWaitingTicket(r *http.Request, clientIP string) bool {
	cookie, err := r.Cookie(p.waitingCookieName)
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
	want := p.signWaiting(r, clientIP, expires)
	if !hmac.Equal([]byte(want), []byte(parts[1])) {
		return false
	}
	key := waitingKey(clientIP, r.UserAgent())
	p.mu.Lock()
	p.active[key] = expires
	p.mu.Unlock()
	return true
}

func (p *Policy) waitingTicket(r *http.Request, clientIP string) (string, int, bool, int, int) {
	p.purgeWaiting()
	p.mu.Lock()
	defer p.mu.Unlock()
	active := len(p.active)
	if active >= p.waitingRoomMaxActive {
		return "", int(p.waitingRoomTTL.Seconds()), false, active, p.waitingRoomMaxActive
	}
	expires := p.now().Add(p.waitingRoomTTL).Unix()
	key := waitingKey(clientIP, r.UserAgent())
	p.active[key] = expires
	signature := p.signWaiting(r, clientIP, expires)
	return fmt.Sprintf("%d:%s", expires, signature), int(p.waitingRoomTTL.Seconds()), true, active + 1, p.waitingRoomMaxActive
}

func (p *Policy) purgeWaiting() {
	now := p.now().Unix()
	p.mu.Lock()
	defer p.mu.Unlock()
	for key, expires := range p.active {
		if expires <= now {
			delete(p.active, key)
		}
	}
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

func (p *Policy) signWaiting(r *http.Request, clientIP string, expires int64) string {
	mac := hmac.New(sha256.New, p.secret)
	_, _ = mac.Write([]byte("waiting-room"))
	_, _ = mac.Write([]byte{'\n'})
	_, _ = mac.Write([]byte(clientIP))
	_, _ = mac.Write([]byte{'\n'})
	_, _ = mac.Write([]byte(r.UserAgent()))
	_, _ = mac.Write([]byte{'\n'})
	_, _ = mac.Write([]byte(strconv.FormatInt(expires, 10)))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (p *Policy) signChallenge(r *http.Request, clientIP, nonce string, expires int64) string {
	mac := hmac.New(sha256.New, p.secret)
	_, _ = mac.Write([]byte("pow-challenge"))
	_, _ = mac.Write([]byte{'\n'})
	_, _ = mac.Write([]byte(clientIP))
	_, _ = mac.Write([]byte{'\n'})
	_, _ = mac.Write([]byte(r.UserAgent()))
	_, _ = mac.Write([]byte{'\n'})
	_, _ = mac.Write([]byte(r.URL.Path))
	_, _ = mac.Write([]byte{'\n'})
	_, _ = mac.Write([]byte(nonce))
	_, _ = mac.Write([]byte{'\n'})
	_, _ = mac.Write([]byte(strconv.FormatInt(expires, 10)))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (p *Policy) newAltchaChallenge(r *http.Request, clientIP string) (altchaChallenge, error) {
	maxNumber := p.altchaMaxNumber
	if maxNumber <= 0 {
		maxNumber = altchaMaxNumberForDifficulty(p.challengeDifficulty)
	}
	number, err := randomNumber(maxNumber)
	if err != nil {
		return altchaChallenge{}, err
	}
	nonce, err := randomToken(18)
	if err != nil {
		return altchaChallenge{}, err
	}
	salt := fmt.Sprintf("%s:%d", nonce, p.now().Add(2*time.Minute).Unix())
	challenge := altchaHash(salt, number)
	out := altchaChallenge{
		Algorithm: "SHA-256",
		Challenge: challenge,
		MaxNumber: maxNumber,
		Salt:      salt,
	}
	out.Signature = p.signAltcha(r, clientIP, out)
	return out, nil
}

func (p *Policy) signAltcha(r *http.Request, clientIP string, challenge altchaChallenge) string {
	mac := hmac.New(sha256.New, p.secret)
	_, _ = mac.Write([]byte("altcha-challenge"))
	_, _ = mac.Write([]byte{'\n'})
	_, _ = mac.Write([]byte(clientIP))
	_, _ = mac.Write([]byte{'\n'})
	_, _ = mac.Write([]byte(r.UserAgent()))
	_, _ = mac.Write([]byte{'\n'})
	_, _ = mac.Write([]byte(r.URL.Path))
	_, _ = mac.Write([]byte{'\n'})
	_, _ = mac.Write([]byte(challenge.Algorithm))
	_, _ = mac.Write([]byte{'\n'})
	_, _ = mac.Write([]byte(challenge.Challenge))
	_, _ = mac.Write([]byte{'\n'})
	_, _ = mac.Write([]byte(challenge.Salt))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (p *Policy) validChallengeAnswer(r *http.Request, clientIP string) bool {
	if p.validAltchaQueryAnswer(r, clientIP) {
		return true
	}
	query := r.URL.Query()
	nonce := query.Get("cw_nonce")
	rawExpires := query.Get("cw_expires")
	signature := query.Get("cw_sig")
	answer := query.Get("cw_pow")
	if nonce == "" || rawExpires == "" || signature == "" || answer == "" {
		return false
	}
	expires, err := strconv.ParseInt(rawExpires, 10, 64)
	if err != nil || expires <= p.now().Unix() {
		return false
	}
	want := p.signChallenge(r, clientIP, nonce, expires)
	if !hmac.Equal([]byte(want), []byte(signature)) {
		return false
	}
	return validProof(nonce, answer, p.challengeDifficulty)
}

func (p *Policy) validAltchaHeaderAnswer(r *http.Request, clientIP string) bool {
	if p == nil || r == nil || !p.captcha {
		return false
	}
	return p.validAltchaPayload(r, clientIP, altchaPayloadFromHeaders(r, p.altchaHeaderName))
}

func (p *Policy) validAltchaQueryAnswer(r *http.Request, clientIP string) bool {
	if p == nil || r == nil || !p.captcha {
		return false
	}
	return p.validAltchaPayload(r, clientIP, r.URL.Query().Get("cw_altcha"))
}

func (p *Policy) validAltchaPayload(r *http.Request, clientIP, raw string) bool {
	payload, ok := parseAltchaPayload(raw)
	if !ok {
		return false
	}
	if !strings.EqualFold(payload.Algorithm, "SHA-256") || payload.Challenge == "" || payload.Salt == "" || payload.Signature == "" {
		return false
	}
	if payload.Number < 0 {
		return false
	}
	if maxNumber := p.altchaMaxNumber; maxNumber > 0 && payload.Number > maxNumber {
		return false
	}
	expires, ok := altchaSaltExpires(payload.Salt)
	if !ok || expires <= p.now().Unix() {
		return false
	}
	challenge := altchaChallenge{
		Algorithm: payload.Algorithm,
		Challenge: payload.Challenge,
		Salt:      payload.Salt,
	}
	want := p.signAltcha(r, clientIP, challenge)
	if !hmac.Equal([]byte(want), []byte(payload.Signature)) {
		return false
	}
	return hmac.Equal([]byte(altchaHash(payload.Salt, payload.Number)), []byte(payload.Challenge))
}

func altchaPayloadFromHeaders(r *http.Request, headerName string) string {
	if r == nil {
		return ""
	}
	if headerName != "" {
		if value := strings.TrimSpace(r.Header.Get(headerName)); value != "" {
			return value
		}
	}
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if strings.HasPrefix(strings.ToLower(auth), "altcha ") {
		return strings.TrimSpace(auth[7:])
	}
	return ""
}

func parseAltchaPayload(raw string) (altchaPayload, bool) {
	raw = strings.TrimSpace(raw)
	raw = strings.TrimPrefix(raw, "challenge=")
	raw = strings.Trim(raw, `"`)
	if raw == "" {
		return altchaPayload{}, false
	}
	var data []byte
	if strings.HasPrefix(raw, "{") {
		data = []byte(raw)
	} else {
		for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
			decoded, err := encoding.DecodeString(raw)
			if err == nil {
				data = decoded
				break
			}
		}
	}
	if len(data) == 0 {
		return altchaPayload{}, false
	}
	var payload altchaPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return altchaPayload{}, false
	}
	return payload, true
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
	CookieName      string
	CookieValue     string
	MaxAge          int
	ReturnURL       string
	Nonce           string
	Expires         int64
	Signature       string
	Difficulty      int
	UseAltcha       bool
	AltchaAlgorithm string
	AltchaChallenge string
	AltchaMaxNumber int
	AltchaSalt      string
	AltchaSignature string
}

type waitingData struct {
	CookieName  string
	CookieValue string
	MaxAge      int
	ReturnURL   string
	Admitted    bool
	Active      int
	Capacity    int
	RetryAfter  int
}

type altchaChallenge struct {
	Algorithm string `json:"algorithm"`
	Challenge string `json:"challenge"`
	MaxNumber int    `json:"maxnumber"`
	Salt      string `json:"salt"`
	Signature string `json:"signature"`
}

type altchaPayload struct {
	Algorithm string `json:"algorithm"`
	Challenge string `json:"challenge"`
	Number    int    `json:"number"`
	Salt      string `json:"salt"`
	Signature string `json:"signature"`
}

func waitingKey(clientIP, userAgent string) string {
	return clientIP + "\x00" + userAgent
}

func randomToken(size int) (string, error) {
	buf := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func randomNumber(max int) (int, error) {
	if max <= 0 {
		max = 1
	}
	value, err := rand.Int(rand.Reader, big.NewInt(int64(max+1)))
	if err != nil {
		return 0, err
	}
	return int(value.Int64()), nil
}

func validProof(nonce, answer string, difficulty int) bool {
	if difficulty <= 0 {
		difficulty = 4
	}
	if len(answer) > 32 {
		return false
	}
	for _, char := range answer {
		if char < '0' || char > '9' {
			return false
		}
	}
	sum := sha256.Sum256([]byte(nonce + ":" + answer))
	return strings.HasPrefix(hex.EncodeToString(sum[:]), strings.Repeat("0", difficulty))
}

func altchaHash(salt string, number int) string {
	sum := sha256.Sum256([]byte(salt + strconv.Itoa(number)))
	return hex.EncodeToString(sum[:])
}

func altchaSaltExpires(salt string) (int64, bool) {
	idx := strings.LastIndexByte(salt, ':')
	if idx < 0 || idx == len(salt)-1 {
		return 0, false
	}
	expires, err := strconv.ParseInt(salt[idx+1:], 10, 64)
	return expires, err == nil
}

func altchaMaxNumberForDifficulty(difficulty int) int {
	switch {
	case difficulty <= 1:
		return 1000
	case difficulty == 2:
		return 5000
	case difficulty == 3:
		return 25000
	case difficulty == 4:
		return 75000
	case difficulty == 5:
		return 250000
	default:
		return 1000000
	}
}

func cleanChallengeURL(r *http.Request) string {
	if r == nil || r.URL == nil {
		return "/"
	}
	next := *r.URL
	query := next.Query()
	for _, key := range []string{"cw_nonce", "cw_expires", "cw_sig", "cw_pow", "cw_altcha"} {
		query.Del(key)
	}
	next.RawQuery = query.Encode()
	return next.RequestURI()
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
    {{if .UseAltcha}}
      <p>CheeseWAF is running an Altcha-compatible proof-of-work CAPTCHA for this protected request. Verification runs locally in your browser.</p>
    {{else}}
      <p>CheeseWAF is checking that this request comes from a browser. This page solves a short proof-of-work challenge and reloads automatically.</p>
    {{end}}
    <div class="bar"><span></span></div>
    <noscript>JavaScript is required to pass this challenge.</noscript>
  </main>
  <script>
    {{if .UseAltcha}}
    const challenge = {
      algorithm: "{{.AltchaAlgorithm}}",
      challenge: "{{.AltchaChallenge}}",
      maxnumber: {{.AltchaMaxNumber}},
      salt: "{{.AltchaSalt}}",
      signature: "{{.AltchaSignature}}"
    };
    async function sha256Hex(input) {
      const data = new TextEncoder().encode(input);
      const digest = await crypto.subtle.digest("SHA-256", data);
      return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, "0")).join("");
    }
    async function solve() {
      for (let i = 0; i <= challenge.maxnumber; i++) {
        const hash = await sha256Hex(challenge.salt + String(i));
        if (hash === challenge.challenge) {
          const payload = btoa(JSON.stringify({
            algorithm: challenge.algorithm,
            challenge: challenge.challenge,
            number: i,
            salt: challenge.salt,
            signature: challenge.signature
          }));
          const target = new URL(window.location.href);
          target.searchParams.set("cw_altcha", payload);
          window.location.replace(target.toString());
          return;
        }
        if (i > 0 && i % 500 === 0) {
          await new Promise((resolve) => window.setTimeout(resolve, 0));
        }
      }
      window.setTimeout(function(){ window.location.reload(); }, 1000);
    }
    if (window.crypto && window.crypto.subtle) {
      solve();
    }
    {{else}}
    const nonce = "{{.Nonce}}";
    const expires = "{{.Expires}}";
    const signature = "{{.Signature}}";
    const difficulty = {{.Difficulty}};
    const prefix = "0".repeat(difficulty);
    async function sha256Hex(input) {
      const data = new TextEncoder().encode(input);
      const digest = await crypto.subtle.digest("SHA-256", data);
      return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, "0")).join("");
    }
    async function solve() {
      for (let i = 0; i < 12000000; i++) {
        const hash = await sha256Hex(nonce + ":" + i);
        if (hash.startsWith(prefix)) {
          const target = new URL(window.location.href);
          target.searchParams.set("cw_nonce", nonce);
          target.searchParams.set("cw_expires", expires);
          target.searchParams.set("cw_sig", signature);
          target.searchParams.set("cw_pow", String(i));
          window.location.replace(target.toString());
          return;
        }
      }
      window.setTimeout(function(){ window.location.reload(); }, 1000);
    }
    if (window.crypto && window.crypto.subtle) {
      solve();
    }
    {{end}}
  </script>
</body>
</html>`))

var waitingTemplate = template.Must(template.New("waiting-room").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Waiting room</title>
  <style>
    body{margin:0;font-family:Inter,Segoe UI,Arial,sans-serif;background:#f8fafc;color:#0f172a;display:grid;min-height:100vh;place-items:center}
    main{width:min(560px,calc(100% - 32px));border:1px solid #cbd5e1;border-radius:8px;background:#fff;padding:28px;box-shadow:0 24px 70px rgba(15,23,42,.16)}
    h1{margin:0 0 8px;font-size:22px;line-height:1.2}
    p{margin:0 0 16px;color:#475569;line-height:1.6}
    .meter{height:8px;border-radius:999px;background:#e2e8f0;overflow:hidden}
    .meter span{display:block;height:100%;background:#2563eb;width:calc({{.Active}} / {{.Capacity}} * 100%)}
    small{display:block;margin-top:12px;color:#64748b}
  </style>
</head>
<body>
  <main>
    <h1>Waiting room</h1>
    {{if .Admitted}}
      <p>A browser slot is available. You will enter automatically.</p>
      <div class="meter"><span></span></div>
      <script>
        document.cookie = "{{.CookieName}}={{.CookieValue}}; Path=/; Max-Age={{.MaxAge}}; SameSite=Lax";
        window.setTimeout(function(){ window.location.replace("{{.ReturnURL}}"); }, 350);
      </script>
    {{else}}
      <p>The protected service is busy. This page will retry automatically.</p>
      <div class="meter"><span></span></div>
      <small>{{.Active}} / {{.Capacity}} active slots</small>
      <script>
        window.setTimeout(function(){ window.location.reload(); }, {{.RetryAfter}} * 1000);
      </script>
    {{end}}
  </main>
</body>
</html>`))
