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

	"github.com/LaokeQwQ/CheeseWAF/internal/captcha"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

type Policy struct {
	enabled                bool
	jsChallenge            bool
	captcha                bool
	captchaType            string
	captchaMaxAttempts     int
	imageCAPTCHALength     int
	imageCAPTCHAWidth      int
	imageCAPTCHAHeight     int
	imageCAPTCHAAudioLimit int
	sliderCAPTCHAWidth     int
	sliderCAPTCHAHeight    int
	sliderCAPTCHAPiece     int
	sliderCAPTCHATolerance int
	sliderCAPTCHAMinDrag   time.Duration
	captchaMobileType      string
	sliderTrackRequired    bool
	challengeDifficulty    int
	altchaMaxNumber        int
	altchaHeaderName       string
	waitingRoom            bool
	waitingRoomMaxActive   int
	waitingRoomTTL         time.Duration
	ttl                    time.Duration
	cookieName             string
	waitingCookieName      string
	secret                 []byte
	secretReady            bool
	pathPrefixes           []string
	exemptPathPrefixes     []string
	allowedUserAgents      []string
	suspiciousUserAgents   []string
	now                    func() time.Time
	mu                     sync.Mutex
	active                 map[string]int64
	attempts               map[string]captchaAttempt
}

type captchaAttempt struct {
	expires    int64
	failures   int
	audioReads int
}

const maxCAPTCHAAttemptEntries = 20000

var generateBotPolicySecret = config.GenerateSecret

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
	cfg.CAPTCHAType = normalizeCAPTCHAType(cfg.CAPTCHAType)
	if cfg.CAPTCHAMaxAttempts <= 0 {
		cfg.CAPTCHAMaxAttempts = 5
	}
	if cfg.CAPTCHAMaxAttempts > 20 {
		cfg.CAPTCHAMaxAttempts = 20
	}
	if cfg.ImageCAPTCHALength <= 0 {
		cfg.ImageCAPTCHALength = 6
	}
	if cfg.ImageCAPTCHAWidth <= 0 {
		cfg.ImageCAPTCHAWidth = 220
	}
	if cfg.ImageCAPTCHAHeight <= 0 {
		cfg.ImageCAPTCHAHeight = 86
	}
	if cfg.ImageCAPTCHAAudioLimit <= 0 {
		cfg.ImageCAPTCHAAudioLimit = 6
	}
	if cfg.ImageCAPTCHAAudioLimit > 20 {
		cfg.ImageCAPTCHAAudioLimit = 20
	}
	if cfg.SliderCAPTCHAWidth <= 0 {
		cfg.SliderCAPTCHAWidth = 320
	}
	if cfg.SliderCAPTCHAHeight <= 0 {
		cfg.SliderCAPTCHAHeight = 150
	}
	if cfg.SliderCAPTCHAPiece <= 0 {
		cfg.SliderCAPTCHAPiece = 42
	}
	if cfg.SliderCAPTCHATolerance <= 0 {
		cfg.SliderCAPTCHATolerance = 6
	}
	if cfg.SliderCAPTCHAMinDrag <= 0 {
		cfg.SliderCAPTCHAMinDrag = 450 * time.Millisecond
	}
	cfg.CAPTCHAMobileType = normalizeMobileCAPTCHAType(cfg.CAPTCHAMobileType)
	if cfg.WaitingRoomMaxActive <= 0 {
		cfg.WaitingRoomMaxActive = 1000
	}
	if cfg.WaitingRoomTTL <= 0 {
		cfg.WaitingRoomTTL = 5 * time.Minute
	}
	secretReady := true
	if config.IsWeakBotSecret(cfg.Secret) {
		if secret, err := generateBotPolicySecret(); err == nil {
			cfg.Secret = secret
		} else {
			cfg.Secret = ""
			secretReady = false
		}
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
		enabled:                cfg.Enabled,
		jsChallenge:            cfg.JSChallenge,
		captcha:                cfg.CAPTCHA,
		captchaType:            cfg.CAPTCHAType,
		captchaMaxAttempts:     cfg.CAPTCHAMaxAttempts,
		imageCAPTCHALength:     cfg.ImageCAPTCHALength,
		imageCAPTCHAWidth:      cfg.ImageCAPTCHAWidth,
		imageCAPTCHAHeight:     cfg.ImageCAPTCHAHeight,
		imageCAPTCHAAudioLimit: cfg.ImageCAPTCHAAudioLimit,
		sliderCAPTCHAWidth:     cfg.SliderCAPTCHAWidth,
		sliderCAPTCHAHeight:    cfg.SliderCAPTCHAHeight,
		sliderCAPTCHAPiece:     cfg.SliderCAPTCHAPiece,
		sliderCAPTCHATolerance: cfg.SliderCAPTCHATolerance,
		sliderCAPTCHAMinDrag:   cfg.SliderCAPTCHAMinDrag,
		captchaMobileType:      cfg.CAPTCHAMobileType,
		sliderTrackRequired:    cfg.SliderCAPTCHATrackRequired,
		challengeDifficulty:    cfg.ChallengeDifficulty,
		altchaMaxNumber:        cfg.AltchaMaxNumber,
		altchaHeaderName:       cfg.AltchaHeaderName,
		waitingRoom:            cfg.WaitingRoom,
		waitingRoomMaxActive:   cfg.WaitingRoomMaxActive,
		waitingRoomTTL:         cfg.WaitingRoomTTL,
		ttl:                    cfg.ChallengeTTL,
		cookieName:             cfg.CookieName,
		waitingCookieName:      cfg.CookieName + "_queue",
		secret:                 []byte(cfg.Secret),
		secretReady:            secretReady,
		pathPrefixes:           cleanList(cfg.PathPrefixes),
		exemptPathPrefixes:     cleanList(cfg.ExemptPathPrefixes),
		allowedUserAgents:      lowerList(cfg.AllowedUserAgents),
		suspiciousUserAgents:   lowerList(cfg.SuspiciousUserAgents),
		now:                    time.Now,
		active:                 map[string]int64{},
		attempts:               map[string]captchaAttempt{},
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
	if p.allowed(r.UserAgent()) || p.hasClearance(r, clientIP) || (p.effectiveCAPTCHAType(r) == "pow" && p.validAltchaHeaderAnswer(r, clientIP)) {
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
	if !p.secretReady {
		http.Error(w, "bot challenge unavailable", http.StatusServiceUnavailable)
		return
	}
	if p.waitingRoom && !p.hasWaitingTicket(r, clientIP) {
		p.serveWaitingRoom(w, r, clientIP)
		return
	}
	if token := strings.TrimSpace(r.URL.Query().Get("cw_audio")); token != "" {
		p.serveImageAudio(w, r, clientIP, token)
		return
	}
	if p.validChallengeAnswer(r, clientIP) {
		value, maxAge := p.clearance(r, clientIP)
		http.SetCookie(w, &http.Cookie{
			Name:     p.cookieName,
			Value:    value,
			Path:     "/",
			MaxAge:   maxAge,
			Secure:   requestIsHTTPS(r),
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})
		redirectTarget := strings.ReplaceAll(cleanChallengeURL(r), "\\", "/")
		target, err := url.Parse(redirectTarget)
		if err != nil || target.Hostname() != "" || target.IsAbs() {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		if target.Path == "" || !strings.HasPrefix(target.Path, "/") {
			target.Path = "/" + target.Path
		}
		http.Redirect(w, r, target.String(), http.StatusFound)
		return
	}
	var altcha *altchaChallenge
	var imageChallenge *captcha.ImageChallenge
	var sliderChallenge *captcha.SliderChallenge
	failedCaptcha := r.URL.Query().Get("cw_image_token") != "" || r.URL.Query().Get("cw_slider_token") != "" || r.URL.Query().Get("cw_altcha") != "" || r.URL.Query().Get("cw_pow") != ""
	captchaType := p.effectiveCAPTCHAType(r)
	if p.captcha && captchaType == "pow" {
		challenge, err := p.newAltchaChallenge(r, clientIP)
		if err != nil {
			http.Error(w, "bot challenge unavailable", http.StatusInternalServerError)
			return
		}
		altcha = &challenge
		challengeJSON, _ := json.Marshal(challenge)
		w.Header().Set("WWW-Authenticate", "Altcha challenge="+string(challengeJSON))
		w.Header().Set("X-Altcha-Authorization-Header", p.altchaHeaderName)
	} else if p.captcha && captchaType == "image" {
		challenge, err := p.newImageChallenge(r, clientIP)
		if err != nil {
			http.Error(w, "bot challenge unavailable", http.StatusInternalServerError)
			return
		}
		imageChallenge = &challenge
	} else if p.captcha && captchaType == "slider" {
		challenge, err := p.newSliderChallenge(r, clientIP)
		if err != nil {
			http.Error(w, "bot challenge unavailable", http.StatusInternalServerError)
			return
		}
		sliderChallenge = &challenge
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
		Failed:      failedCaptcha,
	}
	if altcha != nil {
		data.AltchaAlgorithm = altcha.Algorithm
		data.AltchaChallenge = altcha.Challenge
		data.AltchaMaxNumber = altcha.MaxNumber
		data.AltchaSalt = altcha.Salt
		data.AltchaSignature = altcha.Signature
	}
	if imageChallenge != nil {
		data.UseImage = true
		data.ImageWidth = imageChallenge.Width
		data.ImageHeight = imageChallenge.Height
		data.ImageLength = imageChallenge.Length
		data.ImageData = template.URL(imageChallenge.Image)
		data.ImageToken = imageChallenge.Token
		data.AudioURL = template.URL(imageAudioURL(r, imageChallenge.Token))
	}
	if sliderChallenge != nil {
		data.UseSlider = true
		data.SliderWidth = sliderChallenge.Width
		data.SliderHeight = sliderChallenge.Height
		data.SliderPieceSize = sliderChallenge.PieceSize
		data.SliderTrackWidth = sliderChallenge.TrackWidth
		data.SliderTargetY = sliderChallenge.TargetY
		data.SliderImage = template.URL(sliderChallenge.Image)
		data.SliderPiece = template.URL(sliderChallenge.Piece)
		data.SliderToken = sliderChallenge.Token
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
	if p == nil || !p.secretReady {
		return false
	}
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
	if p == nil || !p.secretReady {
		return false
	}
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

func (p *Policy) allowCAPTCHAAudio(r *http.Request, clientIP, token string) bool {
	if p == nil || r == nil || strings.TrimSpace(token) == "" {
		return false
	}
	key := p.captchaAttemptKey(r, clientIP, "image-audio", token)
	now := p.now().Unix()
	expires := now + int64((2 * time.Minute).Seconds())
	p.mu.Lock()
	defer p.mu.Unlock()
	p.purgeCAPTCHAAttemptsLocked(now)
	if len(p.attempts) >= maxCAPTCHAAttemptEntries {
		return false
	}
	attempt := p.attempts[key]
	if attempt.expires <= now {
		attempt = captchaAttempt{expires: expires}
	}
	if attempt.audioReads >= p.imageCAPTCHAAudioLimit {
		p.attempts[key] = attempt
		return false
	}
	attempt.audioReads++
	attempt.expires = expires
	p.attempts[key] = attempt
	return true
}

func (p *Policy) captchaLocked(r *http.Request, clientIP, kind, token string) bool {
	if p == nil || r == nil || strings.TrimSpace(token) == "" {
		return true
	}
	key := p.captchaAttemptKey(r, clientIP, kind, token)
	now := p.now().Unix()
	p.mu.Lock()
	defer p.mu.Unlock()
	p.purgeCAPTCHAAttemptsLocked(now)
	attempt, ok := p.attempts[key]
	return ok && attempt.expires > now && attempt.failures >= p.captchaMaxAttempts
}

func (p *Policy) recordCAPTCHAAnswer(r *http.Request, clientIP, kind, token string, success bool) {
	if p == nil || r == nil || strings.TrimSpace(token) == "" {
		return
	}
	key := p.captchaAttemptKey(r, clientIP, kind, token)
	now := p.now().Unix()
	expires := now + int64((2 * time.Minute).Seconds())
	p.mu.Lock()
	defer p.mu.Unlock()
	p.purgeCAPTCHAAttemptsLocked(now)
	if success {
		delete(p.attempts, key)
		return
	}
	if len(p.attempts) >= maxCAPTCHAAttemptEntries {
		return
	}
	attempt := p.attempts[key]
	if attempt.expires <= now {
		attempt = captchaAttempt{expires: expires}
	}
	attempt.failures++
	attempt.expires = expires
	p.attempts[key] = attempt
}

func (p *Policy) purgeCAPTCHAAttemptsLocked(now int64) {
	for key, attempt := range p.attempts {
		if attempt.expires <= now {
			delete(p.attempts, key)
		}
	}
}

func (p *Policy) captchaAttemptKey(r *http.Request, clientIP, kind, token string) string {
	mac := hmac.New(sha256.New, p.secret)
	for _, item := range []string{"captcha-attempt-v1", kind, clientIP, r.UserAgent(), r.URL.Path, token} {
		_, _ = mac.Write([]byte(item))
		_, _ = mac.Write([]byte{'\n'})
	}
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
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

func (p *Policy) imageOptions(r *http.Request, clientIP string) captcha.ImageOptions {
	return captcha.ImageOptions{
		Secret:    string(p.secret),
		Purpose:   "waf-bot-image",
		ClientKey: clientIP + "\n" + r.UserAgent(),
		Path:      r.URL.Path,
		TTL:       2 * time.Minute,
		Width:     p.imageCAPTCHAWidth,
		Height:    p.imageCAPTCHAHeight,
		Length:    p.imageCAPTCHALength,
		Now:       p.now,
	}
}

func (p *Policy) newImageChallenge(r *http.Request, clientIP string) (captcha.ImageChallenge, error) {
	return captcha.NewImageChallenge(p.imageOptions(r, clientIP))
}

func (p *Policy) serveImageAudio(w http.ResponseWriter, r *http.Request, clientIP, token string) {
	if !p.allowCAPTCHAAudio(r, clientIP, token) {
		http.Error(w, "audio challenge rate limited", http.StatusTooManyRequests)
		return
	}
	data, ok, err := captcha.RenderImageAudio(p.imageOptions(r, clientIP), token)
	if err != nil {
		http.Error(w, "audio challenge unavailable", http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(w, "audio challenge expired", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "audio/wav")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (p *Policy) sliderOptions(r *http.Request, clientIP string) captcha.SliderOptions {
	return captcha.SliderOptions{
		Secret:    string(p.secret),
		Purpose:   "waf-bot-slider",
		ClientKey: clientIP + "\n" + r.UserAgent(),
		Path:      r.URL.Path,
		TTL:       2 * time.Minute,
		Width:     p.sliderCAPTCHAWidth,
		Height:    p.sliderCAPTCHAHeight,
		PieceSize: p.sliderCAPTCHAPiece,
		Tolerance: p.sliderCAPTCHATolerance,
		MinDrag:   p.sliderCAPTCHAMinDrag,
		Now:       p.now,
	}
}

func (p *Policy) newSliderChallenge(r *http.Request, clientIP string) (captcha.SliderChallenge, error) {
	return captcha.NewSliderChallenge(p.sliderOptions(r, clientIP))
}

func (p *Policy) validChallengeAnswer(r *http.Request, clientIP string) bool {
	if p == nil || !p.secretReady {
		return false
	}
	captchaType := p.effectiveCAPTCHAType(r)
	if captchaType == "pow" && p.validAltchaQueryAnswer(r, clientIP) {
		return true
	}
	if captchaType == "image" && p.validImageQueryAnswer(r, clientIP) {
		return true
	}
	if captchaType == "slider" && p.validSliderQueryAnswer(r, clientIP) {
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

func (p *Policy) validImageQueryAnswer(r *http.Request, clientIP string) bool {
	if p == nil || r == nil || !p.captcha || !p.secretReady {
		return false
	}
	query := r.URL.Query()
	token := query.Get("cw_image_token")
	answer := query.Get("cw_image_answer")
	if strings.TrimSpace(token) == "" || strings.TrimSpace(answer) == "" || p.captchaLocked(r, clientIP, "image", token) {
		return false
	}
	ok := captcha.VerifyImage(p.imageOptions(r, clientIP), captcha.ImagePayload{Token: token, Answer: answer})
	p.recordCAPTCHAAnswer(r, clientIP, "image", token, ok)
	return ok
}

func (p *Policy) validSliderQueryAnswer(r *http.Request, clientIP string) bool {
	if p == nil || r == nil || !p.captcha || !p.secretReady {
		return false
	}
	query := r.URL.Query()
	token := query.Get("cw_slider_token")
	if strings.TrimSpace(token) == "" || p.captchaLocked(r, clientIP, "slider", token) {
		return false
	}
	x, err := strconv.Atoi(query.Get("cw_slider_x"))
	if err != nil {
		p.recordCAPTCHAAnswer(r, clientIP, "slider", token, false)
		return false
	}
	dragMS, err := strconv.Atoi(query.Get("cw_slider_drag_ms"))
	if err != nil {
		p.recordCAPTCHAAnswer(r, clientIP, "slider", token, false)
		return false
	}
	track := query.Get("cw_slider_track")
	if p.sliderTrackRequired && strings.TrimSpace(track) == "" {
		p.recordCAPTCHAAnswer(r, clientIP, "slider", token, false)
		return false
	}
	ok := captcha.VerifySlider(p.sliderOptions(r, clientIP), captcha.SliderPayload{Token: token, X: x, DragMS: dragMS, Track: track})
	p.recordCAPTCHAAnswer(r, clientIP, "slider", token, ok)
	return ok
}

func (p *Policy) validAltchaHeaderAnswer(r *http.Request, clientIP string) bool {
	if p == nil || r == nil || !p.captcha || !p.secretReady {
		return false
	}
	return p.validAltchaPayload(r, clientIP, altchaPayloadFromHeaders(r, p.altchaHeaderName))
}

func (p *Policy) validAltchaQueryAnswer(r *http.Request, clientIP string) bool {
	if p == nil || r == nil || !p.captcha || !p.secretReady {
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

func (p *Policy) effectiveCAPTCHAType(r *http.Request) string {
	captchaType := p.captchaType
	if captchaType == "slider" && p.captchaMobileType != "" && isMobileClient(r) {
		return p.captchaMobileType
	}
	return captchaType
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

func normalizeCAPTCHAType(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "image", "graphic":
		return "image"
	case "slider", "puzzle":
		return "slider"
	default:
		return "pow"
	}
}

func normalizeMobileCAPTCHAType(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "off", "none", "inherit", "same":
		return ""
	case "image", "graphic":
		return "image"
	default:
		return "pow"
	}
}

func isMobileClient(r *http.Request) bool {
	if r == nil {
		return false
	}
	ua := strings.ToLower(r.UserAgent())
	if ua == "" {
		return false
	}
	for _, marker := range []string{"mobile", "android", "iphone", "ipad", "ipod", "windows phone", "harmonyos", "micromessenger"} {
		if strings.Contains(ua, marker) {
			return true
		}
	}
	return false
}

type challengeData struct {
	CookieName       string
	CookieValue      string
	MaxAge           int
	ReturnURL        string
	Nonce            string
	Expires          int64
	Signature        string
	Difficulty       int
	UseAltcha        bool
	AltchaAlgorithm  string
	AltchaChallenge  string
	AltchaMaxNumber  int
	AltchaSalt       string
	AltchaSignature  string
	UseImage         bool
	ImageWidth       int
	ImageHeight      int
	ImageLength      int
	ImageData        template.URL
	ImageToken       string
	AudioURL         template.URL
	UseSlider        bool
	SliderWidth      int
	SliderHeight     int
	SliderPieceSize  int
	SliderTrackWidth int
	SliderTargetY    int
	SliderImage      template.URL
	SliderPiece      template.URL
	SliderToken      string
	Failed           bool
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
	for _, key := range []string{"cw_nonce", "cw_expires", "cw_sig", "cw_pow", "cw_altcha", "cw_image_token", "cw_image_answer", "cw_slider_token", "cw_slider_x", "cw_slider_drag_ms", "cw_slider_track", "cw_audio"} {
		query.Del(key)
	}
	next.RawQuery = query.Encode()
	return next.RequestURI()
}

func safeChallengeReturnURL(r *http.Request) string {
	cleaned := strings.ReplaceAll(cleanChallengeURL(r), "\\", "/")
	if cleaned == "" || strings.HasPrefix(cleaned, "//") {
		return "/"
	}
	parsed, err := url.Parse(cleaned)
	if err != nil || parsed.IsAbs() || parsed.Host != "" {
		return "/"
	}
	if !strings.HasPrefix(parsed.Path, "/") {
		parsed.Path = "/" + parsed.Path
	}
	return parsed.RequestURI()
}

func requestIsHTTPS(r *http.Request) bool {
	if r == nil {
		return false
	}
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https") ||
		strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Scheme")), "https")
}

func imageAudioURL(r *http.Request, token string) string {
	if r == nil || r.URL == nil {
		return "?cw_audio=" + url.QueryEscape(token)
	}
	next := *r.URL
	query := next.Query()
	query.Set("cw_audio", token)
	next.RawQuery = query.Encode()
	return next.RequestURI()
}

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

var challengeTemplate = template.Must(template.New("bot-challenge").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Browser verification</title>
  <style>
    :root{color-scheme:light dark;--bg:#f5f7fb;--panel:#fff;--soft:#f2f5f8;--line:#d8e0ea;--text:#172033;--muted:#66758a;--accent:#11a58d;--accent-strong:#07836f;--success:#15936e;--warning:#b66a14;--warning-bg:#fff4df;--danger:#c44545;--shadow:0 26px 78px rgba(24,34,52,.18),0 8px 24px rgba(24,34,52,.08)}
    *{box-sizing:border-box}
    body{margin:0;font-family:Inter,Segoe UI,Arial,sans-serif;background:radial-gradient(circle at 18% 10%,rgba(17,165,141,.18),transparent 28%),linear-gradient(180deg,#f8fafc,var(--bg));color:var(--text);display:grid;min-height:100vh;place-items:center;padding:16px;overflow-x:hidden}
    main{width:min(368px,calc(100vw - 28px));max-width:100%;border:1px solid var(--line);border-radius:14px;background:var(--panel);padding:12px 18px 14px;box-shadow:var(--shadow)}
    header{display:grid;justify-items:center;gap:4px;margin:0 0 10px;text-align:center}
    .mark{width:42px;height:42px;display:grid;place-items:center;border:1px solid rgba(17,165,141,.22);border-radius:10px;background:linear-gradient(180deg,#fff,#edf8f5);color:var(--accent);font-weight:800;letter-spacing:.02em}
    h1{margin:0;font-size:18px;line-height:1.25}
    p{margin:0;color:var(--muted);line-height:1.55;font-size:13px}
    .bar{height:7px;border-radius:999px;background:#e7edf5;overflow:hidden}
    .bar span{display:block;width:45%;height:100%;background:var(--accent);animation:load 1.2s ease-in-out infinite alternate}
    .captcha{display:grid;gap:10px}
    .captcha-img,.slider-stage{border:1px solid var(--line);border-radius:10px;background:#dbe9e8;overflow:hidden;box-shadow:0 10px 22px rgba(24,34,52,.13),0 3px 9px rgba(24,34,52,.08),inset 0 1px 0 rgba(255,255,255,.55)}
    .captcha-img{display:block;width:100%;height:auto}
    .captcha-row{display:flex;gap:10px;align-items:center}
    input{min-width:0;width:100%;height:42px;border:1px solid var(--line);border-radius:999px;background:var(--panel);color:var(--text);padding:0 14px;font-size:15px}
    input:focus{outline:2px solid rgba(17,165,141,.22);border-color:rgba(17,165,141,.46)}
    button{height:42px;border:0;border-radius:999px;background:var(--accent);color:white;padding:0 16px;font-weight:700;cursor:pointer;transition:background .15s ease,transform .15s ease,box-shadow .15s ease}
    button:hover:not(:disabled){background:var(--accent-strong);box-shadow:0 10px 22px rgba(17,165,141,.22);transform:translateY(-1px)}
    button:disabled{opacity:.55;cursor:not-allowed}
    audio{width:100%;height:36px}
    .hint{font-size:12px;color:var(--muted);margin:0;text-align:center}
    .notice{display:grid;gap:2px;min-height:42px;align-items:center;padding:8px 12px;border:1px solid var(--line);border-radius:10px;background:var(--soft);text-align:center}
    .notice strong{font-size:13px;line-height:1.35}
    .notice span{color:var(--muted);font-size:11px;line-height:1.35}
    .notice.warning{color:var(--warning);background:var(--warning-bg);border-color:rgba(182,106,20,.36)}
    .notice.warning span{color:var(--warning)}
    .notice.success{color:var(--success);background:#e9f8f2;border-color:rgba(21,147,110,.34)}
    .notice.success span{color:var(--success)}
    .slider-stage{position:relative;width:min(100%,var(--slider-width,100%));height:auto;line-height:0;user-select:none}
    .slider-stage img{display:block;width:100%;height:auto;user-select:none;-webkit-user-drag:none}
    .slider-stage::after{position:absolute;inset:0;content:"";pointer-events:none;border-radius:inherit;box-shadow:inset 0 1px 0 rgba(255,255,255,.55),inset 0 0 0 1px rgba(255,255,255,.12)}
    .slider-piece{position:absolute;left:0;top:0;width:var(--piece);height:var(--piece);filter:drop-shadow(0 0 .8px rgba(255,255,255,.96)) drop-shadow(0 0 .7px rgba(15,23,42,.7)) drop-shadow(1.2px 0 0 rgba(255,255,255,.72)) drop-shadow(-1.2px 0 0 rgba(15,23,42,.5)) drop-shadow(0 -1.2px 0 rgba(15,23,42,.36)) drop-shadow(0 1.2px 0 rgba(255,255,255,.62)) drop-shadow(0 8px 12px rgba(15,23,42,.2));pointer-events:none;transition:transform .18s cubic-bezier(.22,.8,.22,1)}
    .stage-tip{position:absolute;left:50%;bottom:10px;z-index:3;max-width:calc(100% - 28px);padding:7px 11px;border:1px solid rgba(182,106,20,.38);border-radius:999px;background:var(--warning-bg);color:var(--warning);box-shadow:0 12px 28px rgba(182,106,20,.12);font-size:12px;font-weight:700;line-height:1.35;text-align:center;transform:translateX(-50%)}
    .slider-track{position:relative;width:min(100%,var(--slider-width,100%));height:40px;border:1px solid var(--line);border-radius:999px;background:linear-gradient(180deg,#fff,var(--soft));overflow:hidden;touch-action:none;cursor:grab;box-shadow:inset 0 1px 0 rgba(255,255,255,.52),0 8px 18px rgba(24,34,52,.08)}
    .slider-track::after{position:absolute;inset:1px;content:"";border-radius:inherit;background:linear-gradient(100deg,transparent 0%,rgba(255,255,255,.56) 46%,transparent 58%);opacity:.28;pointer-events:none;transform:translateX(-100%);animation:shimmer 2.6s ease-in-out infinite}
    .slider-fill{position:absolute;inset:0 auto 0 0;background:linear-gradient(90deg,rgba(17,165,141,.16),rgba(17,165,141,.26));border-right:1px solid rgba(17,165,141,.28);transition:width .18s cubic-bezier(.22,.8,.22,1)}
    .slider-thumb{position:absolute;left:0;top:2px;width:54px;height:34px;display:grid;place-items:center;border:1px solid rgba(255,255,255,.24);border-radius:999px;background:var(--accent);box-shadow:0 9px 18px rgba(17,165,141,.24),inset 0 1px 0 rgba(255,255,255,.34);cursor:grab;touch-action:none;color:#fff;font-size:18px;transition:transform .18s cubic-bezier(.22,.8,.22,1)}
    .slider-copy{position:absolute;inset:0 14px 0 56px;display:flex;align-items:center;justify-content:center;color:var(--muted);font-size:13px;pointer-events:none;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
    .captcha-foot{min-height:34px;display:grid;grid-template-columns:minmax(0,1fr) auto;align-items:center;gap:12px;color:var(--muted);font-size:12px}
    .captcha-brand{min-width:0;display:inline-flex;align-items:center;gap:7px;color:var(--text);font-weight:700}
    .captcha-brand-mark{width:18px;height:18px;display:inline-grid;place-items:center;flex:0 0 18px;border:1px solid rgba(17,165,141,.24);border-radius:5px;background:linear-gradient(180deg,#fff,#edf8f5);color:var(--accent);font-size:9px;font-weight:800}
    .captcha-foot button{width:32px;height:32px;display:inline-grid;place-items:center;padding:0;background:var(--soft);border:1px solid var(--line);color:var(--muted)}
    .captcha-foot button:hover:not(:disabled){background:var(--panel);color:var(--text);box-shadow:none}
    noscript{display:block;margin-top:16px;color:var(--danger)}
    @keyframes load{from{transform:translateX(-30%)}to{transform:translateX(140%)}}
    @keyframes shimmer{0%{transform:translateX(-110%)}55%,100%{transform:translateX(110%)}}
    @media(prefers-color-scheme:dark){:root{--bg:#0e1523;--panel:#111827;--soft:#172033;--line:#2d3b51;--text:#e5edf7;--muted:#9aa8bc;--warning-bg:#2b2114;--shadow:0 28px 82px rgba(0,0,0,.38)}body{background:radial-gradient(circle at 18% 10%,rgba(17,165,141,.22),transparent 28%),linear-gradient(180deg,#101827,#090e18)}.mark{background:linear-gradient(180deg,#172033,#111827)}input{background:#0b1220}.slider-track{background:linear-gradient(180deg,#172033,#0b1220)}}
    @media(max-width:460px){main{padding:14px}.captcha-row{display:grid}button{width:100%}.slider-copy{font-size:12px}}
  </style>
</head>
<body>
  <main>
    <header><div class="mark">CW</div><h1>Browser verification</h1><p>CheeseWAF is protecting this request.</p></header>
    {{if .Failed}}<div class="notice warning" role="alert"><strong>Verification failed</strong><span>A new challenge has been generated. Please try again.</span></div>{{end}}
    {{if .UseImage}}
      <p>Enter the digits shown in the image, or use the audio challenge if the image is unclear.</p>
      <form class="captcha" method="get" action="{{.ReturnURL}}" autocomplete="off">
        <img class="captcha-img" src="{{.ImageData}}" width="{{.ImageWidth}}" height="{{.ImageHeight}}" alt="CAPTCHA image with {{.ImageLength}} digits">
        <audio controls preload="none" src="{{.AudioURL}}"></audio>
        <p class="hint">Audio is generated server-side from an opaque challenge token; the URL does not contain the answer.</p>
        <input type="hidden" name="cw_image_token" value="{{.ImageToken}}">
        <div class="captcha-row">
          <input name="cw_image_answer" inputmode="numeric" pattern="[0-9]*" maxlength="{{.ImageLength}}" aria-label="CAPTCHA answer" placeholder="Enter digits" required>
          <button type="submit">Verify</button>
        </div>
      </form>
    {{else if .UseSlider}}
      <p>Drag the slider so the puzzle piece fits the image gap. Verification is checked when you release it.</p>
      <form id="slider-form" class="captcha" method="get" action="{{.ReturnURL}}" autocomplete="off">
        <div class="slider-stage" style="--piece:{{.SliderPieceSize}}px;--slider-width:{{.SliderWidth}}px">
          <img src="{{.SliderImage}}" width="{{.SliderWidth}}" height="{{.SliderHeight}}" alt="Puzzle slider CAPTCHA image" draggable="false">
          <img id="slider-piece" class="slider-piece" src="{{.SliderPiece}}" width="{{.SliderPieceSize}}" height="{{.SliderPieceSize}}" alt="" draggable="false">
          <div id="stage-tip" class="stage-tip" hidden>Checking verification</div>
        </div>
        <div id="slider-notice" class="notice" hidden><strong>Drag to fill the image gap</strong><span>Security verification</span></div>
        <div id="slider-track" class="slider-track" role="slider" aria-label="Puzzle slider" aria-valuemin="0" aria-valuemax="{{.SliderTrackWidth}}" aria-valuenow="0" style="--piece:{{.SliderPieceSize}}px;--slider-width:{{.SliderWidth}}px">
          <span id="slider-fill" class="slider-fill"></span>
          <button id="slider-thumb" class="slider-thumb" type="button" aria-label="Drag slider">&rarr;</button>
          <span id="slider-copy" class="slider-copy">Drag to fit the puzzle piece</span>
        </div>
        <input type="hidden" name="cw_slider_token" value="{{.SliderToken}}">
        <input id="slider-x" type="hidden" name="cw_slider_x" value="">
        <input id="slider-drag-ms" type="hidden" name="cw_slider_drag_ms" value="">
        <input id="slider-track-data" type="hidden" name="cw_slider_track" value="">
        <div class="captcha-foot"><span class="captcha-brand"><span class="captcha-brand-mark">CW</span><strong>CheeseWAF</strong></span><button type="button" id="slider-refresh" aria-label="Refresh challenge">&#8635;</button></div>
      </form>
    {{else if .UseAltcha}}
      <p>CheeseWAF is running an Altcha-compatible proof-of-work challenge locally in your browser.</p>
      <div class="bar"><span></span></div>
    {{else}}
      <p>CheeseWAF is checking that this request comes from a browser. This page solves a short proof-of-work challenge and reloads automatically.</p>
      <div class="bar"><span></span></div>
    {{end}}
    <noscript>JavaScript is required for PoW and slider verification. Use image CAPTCHA mode if JavaScript-free access is required.</noscript>
  </main>
  <script>
    {{if .UseSlider}}
    (function(){
      const piece = document.getElementById("slider-piece");
      const track = document.getElementById("slider-track");
      const fill = document.getElementById("slider-fill");
      const thumb = document.getElementById("slider-thumb");
      const copy = document.getElementById("slider-copy");
      const notice = document.getElementById("slider-notice");
      const tip = document.getElementById("stage-tip");
      const refresh = document.getElementById("slider-refresh");
      const inputX = document.getElementById("slider-x");
      const inputMS = document.getElementById("slider-drag-ms");
      const inputTrack = document.getElementById("slider-track-data");
      const pieceSize = {{.SliderPieceSize}};
      const targetY = {{.SliderTargetY}};
      const trackWidth = {{.SliderTrackWidth}};
      let drag = null;
      let locked = false;
      let trackPoints = [];
      function apply(x){
        const next = Math.max(0, Math.min(trackWidth, Math.round(x)));
        thumb.style.transform = "translateX(" + next + "px)";
        piece.style.transform = "translate3d(" + next + "px," + targetY + "px,0)";
        fill.style.width = (next + pieceSize / 2) + "px";
        track.setAttribute("aria-valuenow", String(next));
        return next;
      }
      function setNotice(kind, title, body){
        notice.className = "notice" + (kind ? " " + kind : "");
        notice.hidden = false;
        notice.querySelector("strong").textContent = title;
        notice.querySelector("span").textContent = body;
      }
      function rel(event, x, type){
        const rect = track.getBoundingClientRect();
        const scaledX = rect.width > 0 ? Math.round(Math.max(0, Math.min(trackWidth, x))) : Math.round(x);
        const scaledY = rect.height > 0 ? Math.round(event.clientY - rect.top) : 0;
        return {x: scaledX, y: scaledY, t: drag ? Math.max(0, Math.round(performance.now() - drag.at)) : 0, type: type};
      }
      function start(event){
        if (locked) return;
        track.setPointerCapture(event.pointerId);
        event.preventDefault();
        drag = {id:event.pointerId, origin:event.clientX, start: Number(track.getAttribute("aria-valuenow") || "0"), at: performance.now()};
        trackPoints = [rel(event, drag.start, "down")];
        setNotice("", "Release after aligning the piece", "Security verification");
      }
      function move(event){
        if (!drag || drag.id !== event.pointerId) return;
        const x = apply(drag.start + event.clientX - drag.origin);
        trackPoints.push(rel(event, x, "move"));
        if (trackPoints.length > 96) trackPoints.splice(1, trackPoints.length - 96);
      }
      function finish(event){
        if (!drag || drag.id !== event.pointerId) return;
        const x = apply(drag.start + event.clientX - drag.origin);
        trackPoints.push(rel(event, x, "up"));
        inputX.value = String(x);
        inputMS.value = String(Math.max(0, Math.round(performance.now() - drag.at)));
        inputTrack.value = JSON.stringify(trackPoints);
        drag = null;
        if (x <= 0) {
          setNotice("warning", "Drag the slider first", "Move the puzzle piece to the image gap.");
          apply(0);
          return;
        }
        locked = true;
        tip.hidden = false;
        setNotice("success", "Verification submitted", "Elapsed " + (Number(inputMS.value) / 1000).toFixed(2) + "s");
        copy.textContent = "Verification submitted";
        window.setTimeout(function(){ document.getElementById("slider-form").submit(); }, 120);
      }
      apply(0);
      track.addEventListener("pointerdown", start);
      track.addEventListener("pointermove", move);
      track.addEventListener("pointerup", finish);
      track.addEventListener("pointercancel", finish);
      refresh.addEventListener("click", function(){ window.location.replace("{{.ReturnURL}}"); });
    })();
    {{else if .UseAltcha}}
    const challenge = {algorithm:"{{.AltchaAlgorithm}}",challenge:"{{.AltchaChallenge}}",maxnumber:{{.AltchaMaxNumber}},salt:"{{.AltchaSalt}}",signature:"{{.AltchaSignature}}"};
    async function sha256Hex(input){const data=new TextEncoder().encode(input);const digest=await crypto.subtle.digest("SHA-256",data);return Array.from(new Uint8Array(digest)).map((b)=>b.toString(16).padStart(2,"0")).join("")}
    async function solve(){for(let i=0;i<=challenge.maxnumber;i++){const hash=await sha256Hex(challenge.salt+String(i));if(hash===challenge.challenge){const payload=btoa(JSON.stringify({algorithm:challenge.algorithm,challenge:challenge.challenge,number:i,salt:challenge.salt,signature:challenge.signature}));const target=new URL(window.location.href);target.searchParams.set("cw_altcha",payload);window.location.replace(target.toString());return}if(i>0&&i%500===0){await new Promise((resolve)=>window.setTimeout(resolve,0))}}window.setTimeout(function(){window.location.reload()},1000)}
    if(window.crypto&&window.crypto.subtle){solve()}
    {{else if not .UseImage}}
    const nonce="{{.Nonce}}";const expires="{{.Expires}}";const signature="{{.Signature}}";const difficulty={{.Difficulty}};const prefix="0".repeat(difficulty);
    async function sha256Hex(input){const data=new TextEncoder().encode(input);const digest=await crypto.subtle.digest("SHA-256",data);return Array.from(new Uint8Array(digest)).map((b)=>b.toString(16).padStart(2,"0")).join("")}
    async function solve(){for(let i=0;i<12000000;i++){const hash=await sha256Hex(nonce+":"+i);if(hash.startsWith(prefix)){const target=new URL(window.location.href);target.searchParams.set("cw_nonce",nonce);target.searchParams.set("cw_expires",expires);target.searchParams.set("cw_sig",signature);target.searchParams.set("cw_pow",String(i));window.location.replace(target.toString());return}}window.setTimeout(function(){window.location.reload()},1000)}
    if(window.crypto&&window.crypto.subtle){solve()}
    {{end}}
  </script>
</body>
</html>`))
