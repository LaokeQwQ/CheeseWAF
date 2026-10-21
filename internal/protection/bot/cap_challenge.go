package bot

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"html/template"
	"net/http"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/captcha"
)

const (
	maxBotCapTokenBytes       = 8192
	maxBotCapChallengeIDBytes = 128
	maxBotCapContextBytes     = 4096
	maxBotCapFormBytes        = 24 << 10
)

func (p *Policy) serveCapChallenge(w http.ResponseWriter, r *http.Request, clientIP, site, returnURL string, failed bool) {
	if p == nil || p.capVerifier == nil || p.capAPIEndpoint == "" || p.capWidgetURL == "" || p.capWASMURL == "" || p.capHashWXURL == "" {
		http.Error(w, "bot challenge unavailable", http.StatusServiceUnavailable)
		return
	}
	releaseWorker, ok := p.tryAcquireChallengeWorker()
	if !ok {
		http.Error(w, "bot challenge unavailable", http.StatusServiceUnavailable)
		return
	}
	defer releaseWorker()
	challengeRequest := challengeRequestForReturnURL(r, returnURL)
	method := capTargetMethod(challengeRequest.Method)
	if failed {
		// An expired or invalid context cannot safely restore the original method.
		method = http.MethodGet
	}
	if r.Method == http.MethodPost {
		if submittedMethod, ok := p.capChallengeMethodFromForm(r, clientIP, site); ok {
			method = submittedMethod
		}
	}
	challengeID, contextToken, err := p.newCapChallengeForSite(challengeRequest, clientIP, site, method)
	if err != nil {
		http.Error(w, "bot challenge unavailable", http.StatusServiceUnavailable)
		return
	}
	nonce, err := randomToken(18)
	if err != nil {
		http.Error(w, "bot challenge unavailable", http.StatusInternalServerError)
		return
	}
	data := challengeData{
		ChallengeText:  localizedChallengeText(r),
		ReturnURL:      returnURL,
		Nonce:          nonce,
		UseCap:         true,
		CapAPIEndpoint: p.capAPIEndpoint,
		CapWidgetURL:   templateURL(p.capWidgetURL),
		CapWASMURL:     p.capWASMURL,
		CapHashWXURL:   p.capHashWXURL,
		CapChallengeID: challengeID,
		CapContext:     contextToken,
		CapMethod:      method,
		Failed:         failed,
	}
	p.recordChallengeMetric(ChallengeMetricIssued, site, "cap", clientIP)
	setCapChallengeDocumentSecurityHeaders(w, nonce, p.capWidgetURL, p.capAPIEndpoint, p.capWASMURL, p.capHashWXURL)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusForbidden)
	_ = challengeTemplate.Execute(w, data)
}

func (p *Policy) newCapChallengeForSite(r *http.Request, clientIP, site, method string) (string, string, error) {
	if p == nil || !p.secretReady || p.challengeStore == nil || r == nil {
		return "", "", fmt.Errorf("Cap challenge unavailable")
	}
	method = capTargetMethod(method)
	path := mustRequestPath(r)
	challengeID, err := randomToken(24)
	if err != nil {
		return "", "", err
	}
	contextToken, expires, err := captcha.NewReceipt(p.capChallengeReceiptOptions(r, clientIP, site, path, method), "cap")
	if err != nil {
		return "", "", err
	}
	owner := capChallengeOwner(site, clientIP, r.UserAgent(), path)
	peer := strings.TrimSpace(site) + "\x00" + strings.TrimSpace(clientIP)
	reservation, err := p.challengeStore.ReserveScoped(owner, peer, expires)
	if err != nil {
		return "", "", err
	}
	if err := p.challengeStore.Start(reservation); err != nil {
		p.challengeStore.Rollback(reservation)
		return "", "", err
	}
	if err := p.challengeStore.Commit(reservation, captchaChallengeJTI("cap", challengeID), expires); err != nil {
		p.challengeStore.Rollback(reservation)
		return "", "", err
	}
	return challengeID, contextToken, nil
}

func (p *Policy) verifyCapChallengeForSite(r *http.Request, clientIP, site string) (string, bool, error) {
	if p == nil || p.capVerifier == nil || r == nil || r.Method != http.MethodPost {
		return "", false, nil
	}
	if r.ContentLength > maxBotCapFormBytes {
		return "", false, nil
	}
	if err := r.ParseForm(); err != nil {
		return "", false, nil
	}
	challengeID := strings.TrimSpace(r.PostForm.Get("cw_cap_challenge_id"))
	token := r.PostForm.Get("cw_cap_token")
	contextToken := strings.TrimSpace(r.PostForm.Get("cw_cap_context"))
	method := capTargetMethod(r.PostForm.Get("cw_cap_method"))
	if challengeID == "" || len(challengeID) > maxBotCapChallengeIDBytes ||
		strings.TrimSpace(token) == "" || len(token) > maxBotCapTokenBytes ||
		contextToken == "" || len(contextToken) > maxBotCapContextBytes {
		return "", false, nil
	}
	path := mustRequestPath(r)
	if !captcha.VerifyReceipt(p.capChallengeReceiptOptions(r, clientIP, site, path, method), contextToken, "cap") {
		return "", false, nil
	}
	owner := capChallengeOwner(site, clientIP, r.UserAgent(), path)
	peer := strings.TrimSpace(site) + "\x00" + strings.TrimSpace(clientIP)
	if _, consumed := p.challengeStore.ConsumeScoped(captchaChallengeJTI("cap", challengeID), owner, peer); !consumed {
		return "", false, nil
	}
	valid, err := p.capVerifier.VerifyForPeer(r.Context(), token, clientIP)
	if err != nil {
		return "", false, err
	}
	return method, valid, nil
}

func (p *Policy) capChallengeMethodFromForm(r *http.Request, clientIP, site string) (string, bool) {
	if r == nil || r.Method != http.MethodPost || r.ContentLength > maxBotCapFormBytes || r.ParseForm() != nil {
		return "", false
	}
	method := capTargetMethod(r.PostForm.Get("cw_cap_method"))
	contextToken := strings.TrimSpace(r.PostForm.Get("cw_cap_context"))
	if contextToken == "" || len(contextToken) > maxBotCapContextBytes {
		return "", false
	}
	path := mustRequestPath(r)
	if !captcha.VerifyReceipt(p.capChallengeReceiptOptions(r, clientIP, site, path, method), contextToken, "cap") {
		return "", false
	}
	return method, true
}

func (p *Policy) capChallengeReceiptOptions(r *http.Request, clientIP, site, path, method string) captcha.ReceiptOptions {
	return captcha.ReceiptOptions{
		Secret:    string(p.secret),
		Purpose:   "bot-cap-challenge",
		ClientKey: capChallengeClientKey(site, clientIP, r.UserAgent()),
		Path:      path,
		Subject:   method,
		TTL:       p.behaviorTTL,
		Now:       p.now,
	}
}

func capChallengeClientKey(site, clientIP, userAgent string) string {
	digest := sha256.Sum256([]byte("bot-cap-client-v1\x00" + strings.TrimSpace(site) + "\x00" + strings.TrimSpace(clientIP) + "\x00" + userAgent))
	return hex.EncodeToString(digest[:])
}

func capChallengeOwner(site, clientIP, userAgent, path string) string {
	digest := sha256.Sum256([]byte("bot-cap-owner-v1\x00" + capChallengeClientKey(site, clientIP, userAgent) + "\x00" + path))
	return hex.EncodeToString(digest[:])
}

func capTargetMethod(method string) string {
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" || len(method) > 16 {
		return http.MethodGet
	}
	for _, r := range method {
		if !(r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", r)) {
			return http.MethodGet
		}
	}
	return method
}

func setCapChallengeDocumentSecurityHeaders(w http.ResponseWriter, nonce string, urls ...string) {
	if w == nil {
		return
	}
	quotedNonce := "'nonce-" + nonce + "'"
	var widgetSource string
	if len(urls) > 0 {
		widgetSource = capOrigin(urls[0])
	}
	connectSources := []string{"'self'"}
	for _, raw := range urls[1:] {
		if source := capOrigin(raw); source != "" {
			connectSources = append(connectSources, source)
		}
	}
	styleSources := []string{quotedNonce}
	if widgetSource != "" {
		styleSources = append(styleSources, widgetSource)
	}
	scriptSources := []string{quotedNonce, "'wasm-unsafe-eval'"}
	if widgetSource != "" {
		scriptSources = append(scriptSources, widgetSource)
	}
	w.Header().Set("Content-Security-Policy", "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; script-src "+strings.Join(scriptSources, " ")+"; style-src "+strings.Join(styleSources, " ")+"; img-src data:; connect-src "+strings.Join(connectSources, " ")+"; worker-src blob:")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
}

func capOrigin(raw string) string {
	return captcha.CapResourceOrigin(raw)
}

func templateURL(raw string) template.URL {
	return template.URL(raw)
}
