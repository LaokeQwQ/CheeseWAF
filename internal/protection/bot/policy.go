// Package bot implements lightweight bot scoring and JS clearance challenges.
package bot

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/captcha"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
	"github.com/LaokeQwQ/CheeseWAF/internal/fsguard"
	"github.com/LaokeQwQ/CheeseWAF/internal/timekeeper"
)

type Policy struct {
	enabled                bool
	jsChallenge            bool
	captcha                bool
	captchaType            string
	captchaTypes           []string
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
	clearanceHeaderEnabled bool
	clearanceHeaderName    string
	clearanceMethodScope   bool
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
	riskLevel              int
	riskLowThreshold       int
	riskMediumThreshold    int
	riskHighThreshold      int
	riskBlockThreshold     int
	riskConfidenceMin      float64
	now                    func() time.Time
	mu                     sync.Mutex
	active                 map[string]int64
	attempts               map[string]captchaAttempt
	escalationTypes        []captcha.BehaviorType
	behaviorTTL            time.Duration
	policyVersion          string
	bindingMode            BindingMode
	challengeStore         *ChallengeStore
	failureTracker         *FailureTracker
	clearanceSigner        *ClearanceSigner
	clearanceState         *ClearanceStateStore
	powManager             *PoWManager
	powAcceptLegacy        bool
	clearanceAcceptLegacy  bool
	behaviorRenderer       *BehaviorPageRenderer
	behaviorPending        *behaviorPendingStore
	issueBehaviorChallenge func(captcha.BehaviorOptions) (captcha.BehaviorChallenge, error)
	metrics                *ChallengeMetrics
}

type behaviorPending struct {
	path, method string
	kind         captcha.BehaviorType
	level        int
	owner        string
	peer         string
	expires      time.Time
}

const behaviorOwnerCookieSuffix = "_behavior_owner"

type captchaAttempt struct {
	expires    int64
	failures   int
	audioReads int
}

const maxCAPTCHAAttemptEntries = 20000

const (
	maxCAPTCHATokenBytes  = 8192
	maxCAPTCHAAnswerBytes = 256
	maxSliderNumberBytes  = 16
	maxSliderTrackBytes   = 16384
)

var generateBotPolicySecret = config.GenerateSecret

func NewPolicy(cfg config.BotProtectionConfig) *Policy {
	return NewPolicyWithClock(cfg, timekeeper.SystemClock{})
}

func NewPolicyWithClock(cfg config.BotProtectionConfig, clock timekeeper.Clock) *Policy {
	if cfg.RiskLevel == 0 {
		cfg.RiskLevel = 2
	}
	if cfg.RiskLowThreshold == 0 {
		cfg.RiskLowThreshold = 35
	}
	if cfg.RiskMediumThreshold == 0 {
		cfg.RiskMediumThreshold = 55
	}
	if cfg.RiskHighThreshold == 0 {
		cfg.RiskHighThreshold = 75
	}
	if cfg.RiskBlockThreshold == 0 {
		cfg.RiskBlockThreshold = 95
	}
	if cfg.RiskConfidenceMin == 0 {
		cfg.RiskConfidenceMin = 0.6
	}
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
	if cfg.ClearanceHeaderName == "" {
		cfg.ClearanceHeaderName = "X-CheeseWAF-Clearance"
	}
	if cfg.ClearanceStateCapacity <= 0 {
		cfg.ClearanceStateCapacity = 20000
	}
	if cfg.PoWMaxDifficulty < cfg.ChallengeDifficulty {
		cfg.PoWMaxDifficulty = cfg.ChallengeDifficulty
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
	if cfg.CAPTCHAChallengeTTL <= 0 {
		cfg.CAPTCHAChallengeTTL = 2 * time.Minute
	}
	if cfg.CAPTCHAFailureWindow <= 0 {
		cfg.CAPTCHAFailureWindow = 10 * time.Minute
	}
	if cfg.CAPTCHABlockDuration <= 0 {
		cfg.CAPTCHABlockDuration = 15 * time.Minute
	}
	if strings.TrimSpace(cfg.CAPTCHAPolicyVersion) == "" {
		cfg.CAPTCHAPolicyVersion = "1"
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
		cfg.ExemptPathPrefixes = []string{"/health"}
	}
	if len(cfg.SuspiciousUserAgents) == 0 {
		cfg.SuspiciousUserAgents = []string{"curl", "python-requests", "sqlmap", "nikto", "nuclei", "masscan", "zgrab", "httpclient"}
	}
	if clock == nil {
		clock = timekeeper.SystemClock{}
	}
	now := clock.Now
	levels := make([]int, 0, cfg.CAPTCHAMaxAttempts-1)
	for i := 1; i < cfg.CAPTCHAMaxAttempts; i++ {
		levels = append(levels, i)
	}
	failures, _ := NewFailureTracker(FailureTrackerConfig{Window: cfg.CAPTCHAFailureWindow, BlockDuration: cfg.CAPTCHABlockDuration, LevelAt: levels, BlockAt: cfg.CAPTCHAMaxAttempts, Now: now})
	powStore := NewChallengeStore(ChallengeStoreConfig{
		Capacity:      cfg.ClearanceStateCapacity,
		UsedRetention: 5 * time.Minute,
		RateWindow:    time.Minute,
		Now:           now,
	})
	powKey := sha256.Sum256(append(append([]byte(nil), []byte(cfg.Secret)...), []byte("\x00cheesewaf-pow-v1")...))
	powManager, powErr := NewPoWManager(powKey[:], powStore, 2*time.Minute, cfg.ChallengeDifficulty, cfg.PoWMaxDifficulty, []string{"sha256"}, now)
	if powErr != nil {
		secretReady = false
	}
	derivedKey := sha256.Sum256(append(append([]byte(nil), []byte(cfg.Secret)...), []byte("\x00cheesewaf-clearance-v1")...))
	signer, signerErr := NewClearanceSigner(ClearanceSignerConfig{Keys: map[string][]byte{"bot-v1": derivedKey[:]}, ActiveKeyID: "bot-v1", MaxTTL: cfg.ChallengeTTL, Now: now})
	if signerErr != nil {
		secretReady = false
	}
	bindingMode := BindingIPPrefixUA
	if strings.EqualFold(strings.TrimSpace(cfg.CAPTCHABindingMode), string(BindingStrictIPUA)) {
		bindingMode = BindingStrictIPUA
	}
	return &Policy{
		enabled:                cfg.Enabled,
		jsChallenge:            cfg.JSChallenge,
		captcha:                cfg.CAPTCHA,
		captchaType:            cfg.CAPTCHAType,
		captchaTypes:           configuredCAPTCHATypes(cfg.CAPTCHATypes),
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
		// WAF slider challenges always require a movement track (anti-solver). Config flag is ignored.
		sliderTrackRequired:    true,
		challengeDifficulty:    cfg.ChallengeDifficulty,
		altchaMaxNumber:        cfg.AltchaMaxNumber,
		altchaHeaderName:       cfg.AltchaHeaderName,
		clearanceHeaderEnabled: cfg.ClearanceHeaderEnabled,
		clearanceHeaderName:    cfg.ClearanceHeaderName,
		clearanceMethodScope:   cfg.ClearanceMethodScope,
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
		riskLevel:              cfg.RiskLevel,
		riskLowThreshold:       cfg.RiskLowThreshold,
		riskMediumThreshold:    cfg.RiskMediumThreshold,
		riskHighThreshold:      cfg.RiskHighThreshold,
		riskBlockThreshold:     cfg.RiskBlockThreshold,
		riskConfidenceMin:      cfg.RiskConfidenceMin,
		now:                    now,
		active:                 map[string]int64{},
		attempts:               map[string]captchaAttempt{},
		escalationTypes:        behaviorTypes(cfg.CAPTCHAEscalationTypes),
		behaviorTTL:            cfg.CAPTCHAChallengeTTL,
		policyVersion:          cfg.CAPTCHAPolicyVersion,
		bindingMode:            bindingMode,
		challengeStore: NewChallengeStore(ChallengeStoreConfig{
			Capacity:   cfg.ClearanceStateCapacity,
			RateWindow: time.Minute,
			Now:        now,
		}),
		failureTracker:         failures,
		clearanceSigner:        signer,
		clearanceState:         NewClearanceStateStore(ChallengeStoreConfig{Capacity: cfg.ClearanceStateCapacity, UsedRetention: 5 * time.Minute, Now: now}),
		powManager:             powManager,
		powAcceptLegacy:        cfg.PoWAcceptLegacy,
		clearanceAcceptLegacy:  cfg.ClearanceAcceptLegacy,
		behaviorRenderer:       NewBehaviorPageRenderer(),
		behaviorPending:        newBehaviorPendingStore(10000, 8, now),
		issueBehaviorChallenge: captcha.IssueBehaviorChallenge,
		metrics:                ProcessChallengeMetrics(),
	}
}

func (p *Policy) recordChallengeMetric(event ChallengeMetricEventType, site, kind, clientIP string) {
	if p != nil && p.metrics != nil {
		p.metrics.Record(event, site, kind, clientIP)
	}
}

func (p *Policy) Evaluate(r *http.Request, clientIP string) *engine.DetectionResult {
	return p.EvaluateForSite(r, clientIP, canonicalSite(r.Host))
}

func (p *Policy) EvaluateForSite(r *http.Request, clientIP, site string) *engine.DetectionResult {
	if p == nil || !p.enabled || r == nil {
		return nil
	}
	path, ok := requestPath(r)
	if !ok {
		return &engine.DetectionResult{Detected: true, DetectorID: "bot.policy", Category: "bot", Severity: engine.SeverityHigh, Action: engine.ActionBlock, Message: "invalid request path", Confidence: 1, Payload: r.URL.Path}
	}
	if !p.applies(path) {
		return nil
	}
	site = strings.TrimSpace(site)
	if site == "" {
		return &engine.DetectionResult{Detected: true, DetectorID: "bot.policy", Category: "bot", Severity: engine.SeverityHigh, Action: engine.ActionBlock, Message: "bot policy site binding unavailable", Confidence: 1, Payload: path}
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
			Payload:    path,
		}
	}
	if p.allowed(r.UserAgent()) || (p.powAcceptLegacy && p.effectiveCAPTCHAType(r) == "pow" && p.validAltchaHeaderAnswerForSite(r, clientIP, site)) {
		return nil
	}
	risk := p.assessRisk(r, clientIP, site)
	if p.hasClearanceForRisk(r, clientIP, site, risk.band) {
		return nil
	}
	if p.suspicious(r) && risk.band == riskTrusted {
		risk.band = riskLow
		risk.confidence = max(risk.confidence, p.riskConfidenceMin)
	}
	if risk.band == riskTrusted || risk.confidence < p.riskConfidenceMin {
		return nil
	}
	action := engine.ActionBlock
	message := "bot traffic blocked"
	if risk.band != riskExtreme && (p.jsChallenge || p.captcha) {
		action = engine.ActionChallenge
		message = "bot traffic requires adaptive browser verification"
	} else {
		p.recordChallengeMetric(ChallengeMetricBlocked, site, "policy", clientIP)
	}
	severity := engine.SeverityLow
	if risk.band >= riskHigh {
		severity = engine.SeverityHigh
	} else if risk.band >= riskMedium {
		severity = engine.SeverityMedium
	}
	return &engine.DetectionResult{
		Detected:   true,
		DetectorID: "bot.policy",
		Category:   "bot",
		Severity:   severity,
		Action:     action,
		Message:    message,
		Confidence: risk.confidence,
		Payload:    fmt.Sprintf("score=%d band=%s ua=%s", risk.score, risk.band, r.UserAgent()),
	}
}

func (p *Policy) ServeChallenge(w http.ResponseWriter, r *http.Request, clientIP string) {
	p.ServeChallengeForSite(w, r, clientIP, canonicalSite(r.Host))
}

func (p *Policy) ServeChallengeForSite(w http.ResponseWriter, r *http.Request, clientIP, site string) {
	if p == nil || r == nil || r.URL == nil {
		http.Error(w, "bot challenge unavailable", http.StatusForbidden)
		return
	}
	site = strings.TrimSpace(site)
	if site == "" {
		http.Error(w, "bot challenge unavailable", http.StatusServiceUnavailable)
		return
	}
	if !p.secretReady {
		http.Error(w, "bot challenge unavailable", http.StatusServiceUnavailable)
		return
	}
	returnURL := safeChallengeReturnURL(r)
	challengeRequest := challengeRequestForReturnURL(r, returnURL)
	if p.waitingRoom && !p.hasWaitingTicket(r, clientIP) {
		p.serveWaitingRoom(w, r, clientIP)
		return
	}
	if token := strings.TrimSpace(r.URL.Query().Get("cw_audio")); token != "" {
		p.serveImageAudioForSite(w, r, clientIP, site, token)
		return
	}
	submittedType := submittedClassicCAPTCHAType(r)
	selection := p.adaptiveCAPTCHASelection(r, clientIP, site)
	if submittedType == "" && p.usesBehaviorChallenge(selection, clientIP, site) {
		p.serveBehaviorChallenge(w, r, clientIP, site, selection.kind)
		return
	}
	if p.validChallengeAnswerForSite(r, clientIP, site) {
		p.recordChallengeMetric(ChallengeMetricSuccess, site, p.challengeAnswerType(r), clientIP)
		value, maxAge, err := p.issueClearanceForSite(r, clientIP, site)
		if err != nil {
			http.Error(w, "bot clearance unavailable", http.StatusServiceUnavailable)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:     p.cookieName,
			Value:    value,
			Path:     "/",
			MaxAge:   maxAge,
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})
		status := http.StatusFound
		if r.Method == http.MethodPost {
			status = http.StatusSeeOther
		}
		// Same-origin only. Barrier shape matches CodeQL go-queries regression tests:
		// len>1 && [0]=='/' && [1]!='/' && [1]!='\\' (go/unvalidated-url-redirection).
		loc := fsguard.SanitizeLocalRedirect(returnURL)
		if len(loc) > 1 && loc[0] == '/' && loc[1] != '/' && loc[1] != '\\' {
			http.Redirect(w, r, loc, status)
			return
		}
		http.Redirect(w, r, "/", status)
		return
	}
	if submittedType != "" && p.usesBehaviorChallenge(selection, clientIP, site) {
		p.serveBehaviorChallenge(w, r, clientIP, site, selection.kind)
		return
	}
	nonce, err := randomToken(18)
	if err != nil {
		http.Error(w, "bot challenge unavailable", http.StatusInternalServerError)
		return
	}
	if err := r.Context().Err(); err != nil {
		http.Error(w, "bot challenge unavailable", http.StatusServiceUnavailable)
		return
	}
	var altcha *altchaChallenge
	var powChallenge *PoWChallenge
	var imageChallenge *captcha.ImageChallenge
	var sliderChallenge *captcha.SliderChallenge
	powDelivered := false
	defer func() {
		if powChallenge != nil && !powDelivered && p.powManager != nil {
			p.powManager.Revoke(*powChallenge)
		}
	}()
	failedCaptcha := submittedType != ""
	captchaType := selection.kind
	usePoW := (p.jsChallenge && !p.captcha) || (p.captcha && captchaType == "pow")
	if failedCaptcha {
		p.recordChallengeMetric(ChallengeMetricFailure, site, submittedType, clientIP)
	}
	if usePoW {
		if p.powManager == nil {
			http.Error(w, "bot challenge unavailable", http.StatusServiceUnavailable)
			return
		}
		risk := p.assessRisk(r, clientIP, site)
		pow, err := p.powManager.Issue(PoWContext{Site: site, Policy: "bot", PolicyVersion: p.policyVersion, Path: mustRequestPath(challengeRequest), ClientKey: clientIP + "\n" + r.UserAgent(), PeerKey: site + "\x00" + clientIP, Risk: powRiskLevel(risk.band)})
		if err != nil {
			http.Error(w, "bot challenge unavailable", http.StatusServiceUnavailable)
			return
		}
		powChallenge = &pow
		if p.powAcceptLegacy {
			challenge, legacyErr := p.newAltchaChallengeForSite(challengeRequest, clientIP, site)
			if legacyErr != nil {
				http.Error(w, "bot challenge unavailable", http.StatusInternalServerError)
				return
			}
			altcha = &challenge
			challengeJSON, _ := json.Marshal(challenge)
			w.Header().Set("WWW-Authenticate", "Altcha challenge="+string(challengeJSON))
			w.Header().Set("X-Altcha-Authorization-Header", p.altchaHeaderName)
		}
		w.Header().Add("WWW-Authenticate", fmt.Sprintf(`CheeseWAF-Compute challenge="%s", target=%d`, pow.Token, pow.Work))
	} else if p.captcha && captchaType == "image" {
		challenge, err := p.newImageChallengeForSite(challengeRequest, clientIP, site)
		if err != nil {
			http.Error(w, "bot challenge unavailable", http.StatusInternalServerError)
			return
		}
		imageChallenge = &challenge
	} else if p.captcha && captchaType == "slider" {
		challenge, err := p.newSliderChallengeForSite(challengeRequest, clientIP, site)
		if err != nil {
			http.Error(w, "bot challenge unavailable", http.StatusInternalServerError)
			return
		}
		sliderChallenge = &challenge
	}
	data := challengeData{
		ChallengeText: localizedChallengeText(r),
		CookieName:    p.cookieName,
		ReturnURL:     returnURL,
		Difficulty:    p.challengeDifficulty,
		UsePoW:        powChallenge != nil,
		UseAltcha:     altcha != nil,
		Failed:        failedCaptcha,
	}
	data.Nonce = nonce
	if powChallenge != nil {
		data.PoWToken = powChallenge.Token
		data.PoWWork = powChallenge.Work
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
		data.SliderMinDragMS = int(p.sliderCAPTCHAMinDrag / time.Millisecond)
		if data.SliderMinDragMS < 1 {
			data.SliderMinDragMS = 1
		}
	}
	if powChallenge == nil && altcha == nil && imageChallenge == nil && sliderChallenge == nil {
		http.Error(w, "bot challenge unavailable", http.StatusServiceUnavailable)
		return
	}
	if err := r.Context().Err(); err != nil {
		http.Error(w, "bot challenge unavailable", http.StatusServiceUnavailable)
		return
	}
	p.recordChallengeMetric(ChallengeMetricIssued, site, captchaType, clientIP)
	setChallengeDocumentSecurityHeaders(w, nonce)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusForbidden)
	if err := challengeTemplate.Execute(w, data); err != nil {
		return
	}
	if err := r.Context().Err(); err != nil {
		return
	}
	powDelivered = true
}

func (p *Policy) usesBehaviorChallenge(selection captchaSelection, clientIP, site string) bool {
	if p == nil || !p.captcha {
		return false
	}
	decision := p.failureTracker.Check(p.failureKey(clientIP, site))
	if decision.Level > 0 && len(p.escalationTypes) > 0 {
		return true
	}
	return selection.behavior
}

func (p *Policy) serveBehaviorChallenge(w http.ResponseWriter, r *http.Request, clientIP, site, selectedType string) {
	if p.behaviorPending == nil || p.failureTracker == nil || p.behaviorRenderer == nil || p.issueBehaviorChallenge == nil {
		http.Error(w, "bot challenge unavailable", http.StatusServiceUnavailable)
		return
	}
	decision := p.failureTracker.Check(p.failureKey(clientIP, site))
	if decision.Blocked {
		p.recordChallengeMetric(ChallengeMetricCAPTCHABlocked, site, "behavior", clientIP)
		http.Error(w, "verification temporarily unavailable", http.StatusTooManyRequests)
		return
	}
	owner, ownerCookie, err := p.behaviorOwner(r, site, true, cookieSecure(r))
	if err != nil {
		http.Error(w, "bot challenge unavailable", http.StatusInternalServerError)
		return
	}
	peer := site + "\x00" + clientIP
	reservation, err := p.behaviorPending.Reserve(owner, peer, p.now().Add(p.behaviorTTL))
	if err != nil {
		http.Error(w, "bot challenge unavailable", http.StatusServiceUnavailable)
		return
	}
	committed, delivered := false, false
	var committedJTI string
	defer func() {
		if !committed {
			p.behaviorPending.Rollback(reservation)
		} else if !delivered && committedJTI != "" {
			p.behaviorPending.Revoke(committedJTI)
		}
	}()
	if err := r.Context().Err(); err != nil {
		http.Error(w, "bot challenge unavailable", http.StatusServiceUnavailable)
		return
	}
	if err := p.behaviorPending.Start(reservation); err != nil {
		http.Error(w, "bot challenge unavailable", http.StatusServiceUnavailable)
		return
	}
	returnURL := safeChallengeReturnURL(r)
	challengeRequest := challengeRequestForReturnURL(r, returnURL)
	kind := p.behaviorTypeForSelection(selectedType, decision.Level)
	challengePath := mustRequestPath(challengeRequest)
	opts := p.behaviorOptions(challengeRequest, clientIP, site, kind, challengePath)
	challenge, err := p.issueBehaviorChallenge(opts)
	if err != nil {
		http.Error(w, "bot challenge unavailable", http.StatusInternalServerError)
		return
	}
	expires, err := time.Parse(time.RFC3339, challenge.ExpiresAt)
	if err != nil {
		http.Error(w, "bot challenge unavailable", http.StatusInternalServerError)
		return
	}
	jti := behaviorTokenJTI(challenge.Token)
	nonce, err := randomToken(18)
	if err != nil {
		http.Error(w, "bot challenge unavailable", http.StatusInternalServerError)
		return
	}
	html, err := p.behaviorRenderer.RenderHTML(BehaviorPageInput{Challenge: challenge, Nonce: nonce, ReturnURL: returnURL, Method: r.Method, AcceptLanguage: r.Header.Get("Accept-Language")})
	if err != nil {
		http.Error(w, "bot challenge unavailable", http.StatusInternalServerError)
		return
	}
	risk := p.assessRisk(r, clientIP, site)
	pending := behaviorPending{path: challengePath, method: r.Method, kind: challenge.Type, level: int(risk.band), owner: owner, peer: peer, expires: expires}
	if err := r.Context().Err(); err != nil {
		http.Error(w, "bot challenge unavailable", http.StatusServiceUnavailable)
		return
	}
	if err := p.behaviorPending.Commit(reservation, jti, pending); err != nil {
		http.Error(w, "bot challenge unavailable", http.StatusServiceUnavailable)
		return
	}
	committed = true
	committedJTI = jti
	if err := r.Context().Err(); err != nil {
		http.Error(w, "bot challenge unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if ownerCookie != nil {
		http.SetCookie(w, ownerCookie)
	}
	setChallengeDocumentSecurityHeaders(w, nonce)
	w.WriteHeader(http.StatusForbidden)
	if _, err := io.WriteString(w, html); err != nil {
		return
	}
	if err := r.Context().Err(); err != nil {
		return
	}
	delivered = true
	p.recordChallengeMetric(ChallengeMetricIssued, site, string(challenge.Type), clientIP)
}

func (p *Policy) VerifyBehaviorChallenge(w http.ResponseWriter, r *http.Request, clientIP, site string, secure bool) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	site = strings.TrimSpace(site)
	if p == nil || site == "" || !p.secretReady || p.behaviorPending == nil || p.failureTracker == nil || p.clearanceSigner == nil || p.clearanceState == nil {
		writeBehaviorVerifyError(w, http.StatusUnauthorized)
		return
	}
	var response captcha.BehaviorResponse
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&response); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeBehaviorVerifyError(w, http.StatusRequestEntityTooLarge)
			return
		}
		writeBehaviorVerifyError(w, http.StatusUnauthorized)
		return
	}
	if strings.TrimSpace(response.Token) == "" {
		writeBehaviorVerifyError(w, http.StatusUnauthorized)
		return
	}
	jti := behaviorTokenJTI(response.Token)
	owner, _, ownerErr := p.behaviorOwner(r, site, false, secure)
	if ownerErr != nil {
		writeBehaviorVerifyError(w, http.StatusUnauthorized)
		return
	}
	pending, claimed := p.behaviorPending.Claim(jti, owner)
	key := p.failureKey(clientIP, site)
	if !claimed {
		decision, _ := p.failureTracker.RecordFailure(key)
		p.recordChallengeMetric(ChallengeMetricFailure, site, "behavior", clientIP)
		if decision.Blocked {
			p.recordChallengeMetric(ChallengeMetricCAPTCHABlocked, site, "behavior", clientIP)
		}
		writeBehaviorVerifyError(w, behaviorFailureStatus(decision))
		return
	}
	opts := p.behaviorOptions(r, clientIP, site, pending.kind, pending.path)
	result := captcha.VerifyBehaviorChallenge(opts, response)
	if !result.Valid {
		p.behaviorPending.Finalize(jti)
		decision, _ := p.failureTracker.RecordFailure(key)
		p.recordChallengeMetric(ChallengeMetricFailure, site, string(pending.kind), clientIP)
		if decision.Blocked {
			p.recordChallengeMetric(ChallengeMetricCAPTCHABlocked, site, string(pending.kind), clientIP)
		}
		writeBehaviorVerifyError(w, behaviorFailureStatus(decision))
		return
	}
	binding, err := ComputeClearanceBinding(p.bindingMode, clientIP, r.UserAgent())
	if err != nil {
		p.behaviorPending.Finalize(jti)
		writeBehaviorVerifyError(w, http.StatusUnauthorized)
		return
	}
	now := p.now()
	clearanceJTI, err := randomToken(18)
	if err != nil {
		p.behaviorPending.Release(jti)
		writeBehaviorVerifyError(w, http.StatusServiceUnavailable)
		return
	}
	requestMethod := ""
	if p.clearanceMethodScope {
		requestMethod = pending.method
	}
	token, err := p.clearanceSigner.Sign(ClearanceClaims{JTI: clearanceJTI, Site: site, Policy: "bot", PolicyVersion: p.policyVersion, Level: pending.level, Method: string(pending.kind), Path: pending.path, RequestMethod: requestMethod, Binding: binding, IssuedAt: now.Unix(), ExpiresAt: now.Add(p.ttl).Unix()})
	if err != nil {
		p.behaviorPending.Release(jti)
		writeBehaviorVerifyError(w, http.StatusServiceUnavailable)
		return
	}
	if err = p.clearanceState.Issue(clearanceJTI, clearanceCapacityOwner(site, binding), now.Add(p.ttl)); err != nil {
		p.behaviorPending.Release(jti)
		writeBehaviorVerifyError(w, http.StatusServiceUnavailable)
		return
	}
	p.behaviorPending.Finalize(jti)
	p.failureTracker.Reset(key)
	p.recordChallengeMetric(ChallengeMetricSuccess, site, string(pending.kind), clientIP)
	http.SetCookie(w, &http.Cookie{Name: p.cookieName, Value: token, Path: "/", MaxAge: int(p.ttl.Seconds()), Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, `{"data":{"valid":true,"clearance":true}}`)
}

func (p *Policy) behaviorOwner(r *http.Request, site string, issue, secure bool) (string, *http.Cookie, error) {
	name := p.cookieName + behaviorOwnerCookieSuffix
	if cookie, err := r.Cookie(name); err == nil {
		if owner, ok := p.verifyBehaviorOwner(cookie.Value, site); ok {
			return owner, nil, nil
		}
	}
	if !issue {
		return "", nil, errors.New("valid behavior owner cookie required")
	}
	owner, err := randomToken(18)
	if err != nil {
		return "", nil, err
	}
	expires := p.now().Add(p.ttl)
	_ = secure // callers still pass TLS intent for logging; cookies always set Secure.
	return owner, &http.Cookie{Name: name, Value: p.signBehaviorOwner(owner, site, expires), Path: "/", Expires: expires, MaxAge: int(p.ttl.Seconds()), Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode}, nil
}
func (p *Policy) signBehaviorOwner(owner, site string, expires time.Time) string {
	payload := owner + "." + strconv.FormatInt(expires.Unix(), 10)
	mac := hmac.New(sha256.New, p.secret)
	_, _ = mac.Write([]byte("behavior-owner-v1\x00" + strings.TrimSpace(site) + "\x00" + payload))
	return payload + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
func (p *Policy) verifyBehaviorOwner(value, site string) (string, bool) {
	parts := strings.Split(value, ".")
	if len(parts) != 3 || parts[0] == "" {
		return "", false
	}
	exp, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || !p.now().Before(time.Unix(exp, 0)) {
		return "", false
	}
	if !hmac.Equal([]byte(value), []byte(p.signBehaviorOwner(parts[0], site, time.Unix(exp, 0)))) {
		return "", false
	}
	return parts[0], true
}

func writeBehaviorVerifyError(w http.ResponseWriter, status int) {
	w.WriteHeader(status)
	_, _ = io.WriteString(w, `{"data":{"valid":false,"clearance":false}}`)
}

func behaviorFailureStatus(decision FailureDecision) int {
	if decision.Blocked {
		return http.StatusTooManyRequests
	}
	return http.StatusUnauthorized
}

func (p *Policy) behaviorOptions(r *http.Request, clientIP, site string, kind captcha.BehaviorType, path string) captcha.BehaviorOptions {
	return captcha.BehaviorOptions{Secret: string(p.secret), Purpose: "waf-bot-behavior-v1", ClientKey: clientIP + "\n" + r.UserAgent(), Path: path, Site: site, TTL: p.behaviorTTL, Type: kind, Now: p.now}
}

func (p *Policy) behaviorTypeFor(r *http.Request, clientIP, site string, level int) captcha.BehaviorType {
	selection := p.adaptiveCAPTCHASelection(r, clientIP, site)
	return p.behaviorTypeForSelection(selection.kind, level)
}

func (p *Policy) behaviorTypeForSelection(selectedType string, level int) captcha.BehaviorType {
	if level > 0 && len(p.escalationTypes) > 0 {
		index := level - 1
		if index >= len(p.escalationTypes) {
			index = len(p.escalationTypes) - 1
		}
		return p.escalationTypes[index]
	}
	return behaviorType(selectedType)
}

type riskBand int

const (
	riskTrusted riskBand = iota
	riskLow
	riskMedium
	riskHigh
	riskExtreme
)

func (b riskBand) String() string {
	return [...]string{"trusted", "low", "medium", "high", "extreme"}[b]
}

type botRisk struct {
	score      int
	confidence float64
	band       riskBand
}

const lowRiskClearanceTTL = 5 * time.Minute

func powRiskLevel(band riskBand) int {
	switch band {
	case riskMedium:
		return 1
	case riskHigh, riskExtreme:
		return 2
	default:
		return 0
	}
}

func (p *Policy) assessRisk(r *http.Request, clientIP, site string) botRisk {
	score, evidence := 0, 0
	strongSuspicion := false
	ua := strings.ToLower(strings.TrimSpace(r.UserAgent()))
	if ua == "" {
		score += 35
		evidence++
	}
	for _, marker := range p.suspiciousUserAgents {
		if marker != "" && strings.Contains(ua, marker) {
			score += 40
			evidence++
			strongSuspicion = true
			break
		}
	}
	for _, marker := range []string{"sqlmap", "nikto", "nuclei", "masscan", "zgrab"} {
		if strings.Contains(ua, marker) {
			score += 35
			evidence++
			strongSuspicion = true
			break
		}
	}
	if r.Header.Get("Accept") == "" && r.Header.Get("Accept-Language") == "" {
		score += 20
		evidence++
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
		score += 10
		evidence++
	}
	path := strings.ToLower(mustRequestPath(r))
	for _, prefix := range []string{"/login", "/signin", "/admin", "/wp-login", "/xmlrpc", "/.env"} {
		if engine.PathMatchesPrefix(path, prefix) {
			score += 15
			evidence++
			break
		}
	}
	if p.failureTracker != nil {
		failure := p.failureTracker.Check(p.failureKey(clientIP, site))
		score += failure.Failures * 15
		if failure.Failures > 0 {
			evidence++
		}
		if failure.Blocked {
			score = 100
		}
	}
	if ip := net.ParseIP(strings.TrimSpace(clientIP)); ip == nil {
		score += 10
		evidence++
	} else if (ip.IsLoopback() || ip.IsPrivate()) && !strongSuspicion {
		score -= 30
		evidence++
	}
	if isMobileClient(r) {
		score -= 5
	}
	if weakNetworkClient(r) {
		score -= 8
		evidence++
	}
	if score < 0 {
		score = 0
	} else if score > 100 {
		score = 100
	}
	adjustment := map[int]int{1: 10, 2: 0, 3: -5, 4: -10, 5: -15}[p.riskLevel]
	low := p.riskLowThreshold + adjustment
	medium := p.riskMediumThreshold + adjustment
	high := p.riskHighThreshold + adjustment
	block := p.riskBlockThreshold + adjustment
	band := riskTrusted
	switch {
	case score >= block:
		band = riskExtreme
	case score >= high:
		band = riskHigh
	case score >= medium:
		band = riskMedium
	case score >= low:
		band = riskLow
	}
	confidence := 0.5 + float64(evidence)*0.1
	if strongSuspicion && confidence < 0.85 {
		confidence = 0.85
	}
	if confidence > 0.95 {
		confidence = 0.95
	}
	return botRisk{score: score, confidence: confidence, band: band}
}

// adaptiveCAPTCHAType selects the challenge type from risk and configuration.
// It never downgrades to PoW based on spoofable client signals (UA, ECT, Save-Data).
// High-risk clients may escalate to the strongest configured escalation type.
// Mobile UX for classic slider remains via effectiveCAPTCHAType (captchaMobileType).
type captchaSelection struct {
	kind     string
	behavior bool
}

func (p *Policy) adaptiveCAPTCHASelection(r *http.Request, clientIP, site string) captchaSelection {
	risk := p.assessRisk(r, clientIP, site)
	if risk.band >= riskHigh && len(p.escalationTypes) > 0 {
		return captchaSelection{kind: string(p.escalationTypes[len(p.escalationTypes)-1]), behavior: true}
	}
	kind := p.effectiveCAPTCHAType(r)
	if kind == string(captcha.BehaviorRandom) {
		kind = p.randomConfiguredCAPTCHAType()
		// PoW selected from the random pool uses the shared Behavior shell;
		// an explicitly configured PoW keeps the lightweight compute page.
		return captchaSelection{kind: kind, behavior: kind != "image" && kind != "slider"}
	}
	return captchaSelection{kind: kind, behavior: isBehaviorCAPTCHAType(kind)}
}

func (p *Policy) adaptiveCAPTCHAType(r *http.Request, clientIP, site string) string {
	return p.adaptiveCAPTCHASelection(r, clientIP, site).kind
}

func (p *Policy) randomConfiguredCAPTCHAType() string {
	if len(p.captchaTypes) == 0 {
		return "pow"
	}
	index, err := randomNumber(len(p.captchaTypes) - 1)
	if err != nil {
		return p.captchaTypes[0]
	}
	return p.captchaTypes[index]
}

func (p *Policy) failureKey(clientIP, site string) FailureKey {
	return FailureKey{Client: clientIP, Site: site, Policy: "bot:" + p.policyVersion}
}

func behaviorTokenJTI(token string) string {
	digest := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func canonicalSite(host string) string {
	if parsed, err := url.Parse("//" + strings.TrimSpace(host)); err == nil && parsed.Hostname() != "" {
		return strings.ToLower(parsed.Hostname())
	}
	return strings.ToLower(strings.TrimSpace(host))
}

func isBehaviorCAPTCHAType(value string) bool {
	switch behaviorType(value) {
	case captcha.BehaviorRandom, captcha.BehaviorCurveDraw, captcha.BehaviorCurveSlider,
		captcha.BehaviorShapeSlider, captcha.BehaviorRotate, captcha.BehaviorRestoreSlider,
		captcha.BehaviorAngle, captcha.BehaviorScratch, captcha.BehaviorTextClick,
		captcha.BehaviorIconClick:
		return true
	default:
		return false
	}
}

func behaviorType(value string) captcha.BehaviorType {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "curve_slider", "curve_slider_v2", "curve_slider_v3":
		// Legacy v1/v2 aliases collapse to the single V3 drag-to-align product.
		return captcha.BehaviorCurveSlider
	case "slider_v2":
		return captcha.BehaviorShapeSlider
	}
	return captcha.BehaviorType(value)
}

func behaviorTypes(values []string) []captcha.BehaviorType {
	out := make([]captcha.BehaviorType, 0, len(values))
	for _, value := range configuredCAPTCHATypes(values) {
		kind := behaviorType(value)
		if kind == captcha.BehaviorPOW || isBehaviorCAPTCHAType(string(kind)) {
			out = append(out, kind)
		}
	}
	return out
}

func configuredCAPTCHATypes(values []string) []string {
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, raw := range values {
		value := normalizeCAPTCHAType(raw)
		kind := behaviorType(value)
		switch {
		case value == "pow" || value == "image" || value == "slider":
		case kind != captcha.BehaviorRandom && isBehaviorCAPTCHAType(string(kind)):
			value = string(kind)
		default:
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func (p *Policy) serveWaitingRoom(w http.ResponseWriter, r *http.Request, clientIP string) {
	nonce, err := randomToken(18)
	if err != nil {
		http.Error(w, "waiting room unavailable", http.StatusServiceUnavailable)
		return
	}
	value, maxAge, admitted, active, capacity := p.waitingTicket(r, clientIP)
	data := waitingData{
		Text:       localizedWaitingText(r),
		ReturnURL:  safeChallengeReturnURL(r),
		Admitted:   admitted,
		Active:     active,
		Capacity:   capacity,
		RetryAfter: 3,
		Nonce:      nonce,
	}
	if !admitted {
		w.Header().Set("Retry-After", strconv.Itoa(data.RetryAfter))
	}
	if admitted && value != "" {
		// Set waiting-room ticket server-side (Secure/HttpOnly) — do not rely on document.cookie.
		http.SetCookie(w, &http.Cookie{
			Name:     p.waitingCookieName,
			Value:    value,
			Path:     "/",
			MaxAge:   maxAge,
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	setChallengeDocumentSecurityHeaders(w, nonce)
	w.WriteHeader(http.StatusTooManyRequests)
	_ = waitingTemplate.Execute(w, data)
}

func (p *Policy) clearance(r *http.Request, clientIP string) (string, int) {
	token, maxAge, _ := p.issueClearance(r, clientIP)
	return token, maxAge
}

func (p *Policy) issueClearance(r *http.Request, clientIP string) (string, int, error) {
	return p.issueClearanceForSite(r, clientIP, canonicalSite(r.Host))
}

func (p *Policy) issueClearanceForSite(r *http.Request, clientIP, site string) (string, int, error) {
	site = strings.TrimSpace(site)
	if r == nil || site == "" {
		return "", 0, errors.New("request and site required")
	}
	risk := p.assessRisk(r, clientIP, site)
	return p.issueClearanceForRiskAndSite(r, clientIP, site, risk.band, "pow")
}

func (p *Policy) issueClearanceForRisk(r *http.Request, clientIP string, band riskBand, methodName string) (string, int, error) {
	return p.issueClearanceForRiskAndSite(r, clientIP, canonicalSite(r.Host), band, methodName)
}

func (p *Policy) issueClearanceForRiskAndSite(r *http.Request, clientIP, site string, band riskBand, methodName string) (string, int, error) {
	if p.clearanceSigner == nil || p.clearanceState == nil {
		return "", 0, errors.New("clearance signer unavailable")
	}
	site = strings.TrimSpace(site)
	if r == nil || site == "" {
		return "", 0, errors.New("request and site required")
	}
	now := p.now()
	ttl := p.ttl
	if band == riskLow && ttl > lowRiskClearanceTTL {
		ttl = lowRiskClearanceTTL
	}
	jti, err := randomToken(18)
	if err != nil {
		return "", 0, err
	}
	binding, err := ComputeClearanceBinding(p.bindingMode, clientIP, r.UserAgent())
	if err != nil {
		return "", 0, err
	}
	method := ""
	if p.clearanceMethodScope {
		method = r.Method
	}
	token, err := p.clearanceSigner.Sign(ClearanceClaims{JTI: jti, Site: site, Policy: "bot", PolicyVersion: p.policyVersion, Level: int(band), Method: methodName, Path: mustRequestPath(r), RequestMethod: method, Binding: binding, IssuedAt: now.Unix(), ExpiresAt: now.Add(ttl).Unix()})
	if err != nil {
		return "", 0, err
	}
	if err = p.clearanceState.Issue(jti, clearanceCapacityOwner(site, binding), now.Add(ttl)); err != nil {
		return "", 0, err
	}
	return token, int(ttl.Seconds()), nil
}

func clearanceCapacityOwner(site, binding string) string {
	digest := sha256.Sum256([]byte("clearance-owner-v1\x00" + site + "\x00" + binding))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func (p *Policy) hasClearance(r *http.Request, clientIP string) bool {
	return p.hasClearanceForSite(r, clientIP, canonicalSite(r.Host))
}

func (p *Policy) RevokeClearance(token string) bool {
	if p == nil || p.clearanceSigner == nil || p.clearanceState == nil {
		return false
	}
	claims, err := p.clearanceSigner.Authenticate(token)
	if err != nil {
		return false
	}
	return p.clearanceState.Revoke(claims.JTI)
}

func (p *Policy) hasClearanceForSite(r *http.Request, clientIP, site string) bool {
	return p.hasClearanceForRisk(r, clientIP, site, riskTrusted)
}

func (p *Policy) hasClearanceForRisk(r *http.Request, clientIP, site string, current riskBand) bool {
	site = strings.TrimSpace(site)
	if p == nil || r == nil || site == "" || !p.secretReady {
		return false
	}
	var token string
	if p.clearanceHeaderEnabled {
		token = strings.TrimSpace(r.Header.Get(p.clearanceHeaderName))
	}
	if token == "" {
		if cookie, err := r.Cookie(p.cookieName); err == nil {
			token = cookie.Value
		}
	}
	if token == "" {
		return false
	}
	if strings.Count(token, ".") == 1 && p.clearanceSigner != nil {
		if claims, err := p.clearanceSigner.Verify(token, ClearanceContext{Site: site, Policy: "bot", PolicyVersion: p.policyVersion, ClientIP: clientIP, UserAgent: r.UserAgent(), Path: mustRequestPath(r), RequestMethod: r.Method, BindingMode: p.bindingMode}); err == nil && p.clearanceState.Valid(claims.JTI) && int(current) <= claims.Level {
			return true
		}
		return false
	}
	if !p.clearanceAcceptLegacy || strings.Count(token, ":") != 1 {
		return false
	}
	parts := strings.SplitN(token, ":", 2)
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
	if !ok && len(p.attempts) >= maxCAPTCHAAttemptEntries {
		return true
	}
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
	if _, exists := p.attempts[key]; !exists && len(p.attempts) >= maxCAPTCHAAttemptEntries {
		p.evictOldestCAPTCHAAttemptLocked()
	}
	attempt := p.attempts[key]
	if attempt.expires <= now {
		attempt = captchaAttempt{expires: expires}
	}
	attempt.failures++
	attempt.expires = expires
	p.attempts[key] = attempt
}

func (p *Policy) evictOldestCAPTCHAAttemptLocked() {
	var oldestKey string
	var oldestExpires int64
	for key, attempt := range p.attempts {
		if oldestKey == "" || attempt.expires < oldestExpires {
			oldestKey = key
			oldestExpires = attempt.expires
		}
	}
	if oldestKey != "" {
		delete(p.attempts, oldestKey)
	}
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
	for _, item := range []string{"captcha-attempt-v1", kind, clientIP, r.UserAgent(), mustRequestPath(r), token} {
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
	return p.signChallengeForSite(r, clientIP, canonicalSite(r.Host), nonce, expires)
}

func (p *Policy) signChallengeForSite(r *http.Request, clientIP, site, nonce string, expires int64) string {
	mac := hmac.New(sha256.New, p.secret)
	_, _ = mac.Write([]byte("pow-challenge"))
	_, _ = mac.Write([]byte{'\n'})
	_, _ = mac.Write([]byte(strings.TrimSpace(site)))
	_, _ = mac.Write([]byte{'\n'})
	_, _ = mac.Write([]byte(clientIP))
	_, _ = mac.Write([]byte{'\n'})
	_, _ = mac.Write([]byte(r.UserAgent()))
	_, _ = mac.Write([]byte{'\n'})
	_, _ = mac.Write([]byte(mustRequestPath(r)))
	_, _ = mac.Write([]byte{'\n'})
	_, _ = mac.Write([]byte(nonce))
	_, _ = mac.Write([]byte{'\n'})
	_, _ = mac.Write([]byte(strconv.FormatInt(expires, 10)))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (p *Policy) newAltchaChallenge(r *http.Request, clientIP string) (altchaChallenge, error) {
	return p.newAltchaChallengeForSite(r, clientIP, canonicalSite(r.Host))
}

func (p *Policy) newAltchaChallengeForSite(r *http.Request, clientIP, site string) (altchaChallenge, error) {
	site = strings.TrimSpace(site)
	if r == nil || site == "" {
		return altchaChallenge{}, errors.New("request and site required")
	}
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
	expires := p.now().Add(2 * time.Minute)
	salt := fmt.Sprintf("%s:%d", nonce, expires.Unix())
	challenge := altchaHash(salt, number)
	out := altchaChallenge{
		Algorithm: "SHA-256",
		Challenge: challenge,
		MaxNumber: maxNumber,
		Salt:      salt,
	}
	out.Signature = p.signAltchaForSite(r, clientIP, site, out)
	owner := site + "\x00" + clientIP + "\x00" + r.UserAgent()
	if err = p.challengeStore.AddScopedWithPeer("legacy-altcha:"+nonce, owner, site+"\x00"+clientIP, time.Unix(expires.Unix(), 0)); err != nil {
		return altchaChallenge{}, err
	}
	return out, nil
}

func (p *Policy) signAltcha(r *http.Request, clientIP string, challenge altchaChallenge) string {
	return p.signAltchaForSite(r, clientIP, canonicalSite(r.Host), challenge)
}

func (p *Policy) signAltchaForSite(r *http.Request, clientIP, site string, challenge altchaChallenge) string {
	mac := hmac.New(sha256.New, p.secret)
	_, _ = mac.Write([]byte("altcha-challenge"))
	_, _ = mac.Write([]byte{'\n'})
	_, _ = mac.Write([]byte(strings.TrimSpace(site)))
	_, _ = mac.Write([]byte{'\n'})
	_, _ = mac.Write([]byte(clientIP))
	_, _ = mac.Write([]byte{'\n'})
	_, _ = mac.Write([]byte(r.UserAgent()))
	_, _ = mac.Write([]byte{'\n'})
	_, _ = mac.Write([]byte(mustRequestPath(r)))
	_, _ = mac.Write([]byte{'\n'})
	_, _ = mac.Write([]byte(challenge.Algorithm))
	_, _ = mac.Write([]byte{'\n'})
	_, _ = mac.Write([]byte(challenge.Challenge))
	_, _ = mac.Write([]byte{'\n'})
	_, _ = mac.Write([]byte(challenge.Salt))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (p *Policy) imageOptions(r *http.Request, clientIP string) captcha.ImageOptions {
	return p.imageOptionsForSite(r, clientIP, canonicalSite(r.Host))
}

func (p *Policy) imageOptionsForSite(r *http.Request, clientIP, site string) captcha.ImageOptions {
	return captcha.ImageOptions{
		Secret:    string(p.secret),
		Purpose:   "waf-bot-image",
		ClientKey: strings.TrimSpace(site) + "\n" + clientIP + "\n" + r.UserAgent(),
		Path:      mustRequestPath(r),
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

func (p *Policy) newImageChallengeForSite(r *http.Request, clientIP, site string) (captcha.ImageChallenge, error) {
	exp := p.now().Add(2 * time.Minute)
	owner := clientIP + "\n" + r.UserAgent()
	peer := strings.TrimSpace(site) + "\x00" + clientIP
	reservation, err := p.challengeStore.ReserveScoped(owner, peer, exp)
	if err != nil {
		return captcha.ImageChallenge{}, err
	}
	if err := p.challengeStore.Start(reservation); err != nil {
		p.challengeStore.Rollback(reservation)
		return captcha.ImageChallenge{}, err
	}
	challenge, err := captcha.NewImageChallenge(p.imageOptionsForSite(r, clientIP, site))
	if err != nil {
		p.challengeStore.Rollback(reservation)
		return captcha.ImageChallenge{}, err
	}
	if err := p.challengeStore.Commit(reservation, captchaChallengeJTI("image", challenge.Token), exp); err != nil {
		p.challengeStore.Rollback(reservation)
		return captcha.ImageChallenge{}, err
	}
	return challenge, nil
}

func (p *Policy) serveImageAudio(w http.ResponseWriter, r *http.Request, clientIP, token string) {
	p.serveImageAudioForSite(w, r, clientIP, canonicalSite(r.Host), token)
}

func (p *Policy) serveImageAudioForSite(w http.ResponseWriter, r *http.Request, clientIP, site, token string) {
	if !p.allowCAPTCHAAudio(r, clientIP, token) {
		http.Error(w, "audio challenge rate limited", http.StatusTooManyRequests)
		return
	}
	data, ok, err := captcha.RenderImageAudio(p.imageOptionsForSite(r, clientIP, site), token)
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
	w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; sandbox")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (p *Policy) sliderOptions(r *http.Request, clientIP string) captcha.SliderOptions {
	return p.sliderOptionsForSite(r, clientIP, canonicalSite(r.Host))
}

func (p *Policy) sliderOptionsForSite(r *http.Request, clientIP, site string) captcha.SliderOptions {
	return captcha.SliderOptions{
		Secret:    string(p.secret),
		Purpose:   "waf-bot-slider",
		ClientKey: strings.TrimSpace(site) + "\n" + clientIP + "\n" + r.UserAgent(),
		Path:      mustRequestPath(r),
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

func (p *Policy) newSliderChallengeForSite(r *http.Request, clientIP, site string) (captcha.SliderChallenge, error) {
	exp := p.now().Add(2 * time.Minute)
	owner := clientIP + "\n" + r.UserAgent()
	peer := strings.TrimSpace(site) + "\x00" + clientIP
	reservation, err := p.challengeStore.ReserveScoped(owner, peer, exp)
	if err != nil {
		return captcha.SliderChallenge{}, err
	}
	if err := p.challengeStore.Start(reservation); err != nil {
		p.challengeStore.Rollback(reservation)
		return captcha.SliderChallenge{}, err
	}
	challenge, err := captcha.NewSliderChallenge(p.sliderOptionsForSite(r, clientIP, site))
	if err != nil {
		p.challengeStore.Rollback(reservation)
		return captcha.SliderChallenge{}, err
	}
	if err := p.challengeStore.Commit(reservation, captchaChallengeJTI("slider", challenge.Token), exp); err != nil {
		p.challengeStore.Rollback(reservation)
		return captcha.SliderChallenge{}, err
	}
	return challenge, nil
}

func captchaChallengeJTI(kind, token string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(token)))
	return kind + "-captcha:" + hex.EncodeToString(sum[:16])
}

func captchaFormValue(r *http.Request, key string) string {
	if r == nil {
		return ""
	}
	// Image/slider answers must not live in query strings (access logs / history).
	// Only accept POST body (forms already use method=post).
	if r.Method != http.MethodPost {
		return ""
	}
	if err := r.ParseForm(); err != nil {
		return ""
	}
	if value := strings.TrimSpace(r.PostForm.Get(key)); value != "" {
		return value
	}
	return strings.TrimSpace(r.Form.Get(key))
}

func (p *Policy) validChallengeAnswer(r *http.Request, clientIP string) bool {
	return p.validChallengeAnswerForSite(r, clientIP, canonicalSite(r.Host))
}

func (p *Policy) validChallengeAnswerForSite(r *http.Request, clientIP, site string) bool {
	site = strings.TrimSpace(site)
	if p == nil || r == nil || r.URL == nil || site == "" || !p.secretReady {
		return false
	}
	captchaType := p.challengeAnswerType(r)
	if captchaType == "pow" && p.powAcceptLegacy && p.validAltchaQueryAnswerForSite(r, clientIP, site) {
		return true
	}
	if captchaType == "image" && p.validImageQueryAnswerForSite(r, clientIP, site) {
		return true
	}
	if captchaType == "slider" && p.validSliderQueryAnswerForSite(r, clientIP, site) {
		return true
	}
	// Sealed PoW tokens are POST-only. Query-param legacy PoW (cw_nonce/cw_sig) is retired.
	if r.Method != http.MethodPost || p.powManager == nil {
		return false
	}
	if err := r.ParseForm(); err != nil {
		return false
	}
	token, answer := r.PostForm.Get("cw_pow_token"), r.PostForm.Get("cw_pow_answer")
	if token == "" || answer == "" {
		return false
	}
	if len(token) > maxPoWTokenBytes || len(answer) > maxPoWAnswerBytes {
		return false
	}
	x := PoWContext{Site: site, Policy: "bot", PolicyVersion: p.policyVersion, Path: mustRequestPath(r), ClientKey: clientIP + "\n" + r.UserAgent(), PeerKey: site + "\x00" + clientIP}
	return p.powManager.Verify(token, answer, x) == nil
}

func (p *Policy) challengeAnswerType(r *http.Request) string {
	kind := p.effectiveCAPTCHAType(r)
	if kind == string(captcha.BehaviorRandom) {
		if submitted := submittedClassicCAPTCHAType(r); submitted != "" {
			return submitted
		}
	}
	return kind
}

func submittedClassicCAPTCHAType(r *http.Request) string {
	if r == nil {
		return ""
	}
	switch {
	case captchaFormValue(r, "cw_image_token") != "":
		return "image"
	case captchaFormValue(r, "cw_slider_token") != "":
		return "slider"
	case captchaFormValue(r, "cw_pow_token") != "" || captchaFormValue(r, "cw_altcha") != "" || captchaFormValue(r, "cw_pow") != "":
		return "pow"
	default:
		return ""
	}
}

func (p *Policy) validImageQueryAnswer(r *http.Request, clientIP string) bool {
	return p.validImageQueryAnswerForSite(r, clientIP, canonicalSite(r.Host))
}

func (p *Policy) validImageQueryAnswerForSite(r *http.Request, clientIP, site string) bool {
	if p == nil || r == nil || !p.captcha || !p.secretReady {
		return false
	}
	token := captchaFormValue(r, "cw_image_token")
	answer := captchaFormValue(r, "cw_image_answer")
	if len(token) > maxCAPTCHATokenBytes || len(answer) > maxCAPTCHAAnswerBytes {
		return false
	}
	if strings.TrimSpace(token) == "" || strings.TrimSpace(answer) == "" {
		return false
	}
	if p.captchaLocked(r, clientIP, "image", token) {
		p.recordChallengeMetric(ChallengeMetricCAPTCHABlocked, site, "image", clientIP)
		return false
	}
	ok := captcha.VerifyImage(p.imageOptionsForSite(r, clientIP, site), captcha.ImagePayload{Token: token, Answer: answer})
	if ok {
		status, consumed := p.challengeStore.Consume(captchaChallengeJTI("image", token))
		if !consumed || status != ChallengeUsed {
			ok = false
		}
	}
	p.recordCAPTCHAAnswer(r, clientIP, "image", token, ok)
	return ok
}

func (p *Policy) validSliderQueryAnswer(r *http.Request, clientIP string) bool {
	return p.validSliderQueryAnswerForSite(r, clientIP, canonicalSite(r.Host))
}

func (p *Policy) validSliderQueryAnswerForSite(r *http.Request, clientIP, site string) bool {
	if p == nil || r == nil || !p.captcha || !p.secretReady {
		return false
	}
	token := captchaFormValue(r, "cw_slider_token")
	rawX := captchaFormValue(r, "cw_slider_x")
	rawDragMS := captchaFormValue(r, "cw_slider_drag_ms")
	track := captchaFormValue(r, "cw_slider_track")
	if len(token) > maxCAPTCHATokenBytes || len(rawX) > maxSliderNumberBytes || len(rawDragMS) > maxSliderNumberBytes || len(track) > maxSliderTrackBytes {
		return false
	}
	if strings.TrimSpace(token) == "" {
		return false
	}
	if p.captchaLocked(r, clientIP, "slider", token) {
		p.recordChallengeMetric(ChallengeMetricCAPTCHABlocked, site, "slider", clientIP)
		return false
	}
	x, err := strconv.Atoi(rawX)
	if err != nil {
		p.recordCAPTCHAAnswer(r, clientIP, "slider", token, false)
		return false
	}
	dragMS, err := strconv.Atoi(rawDragMS)
	if err != nil {
		p.recordCAPTCHAAnswer(r, clientIP, "slider", token, false)
		return false
	}
	if p.sliderTrackRequired && strings.TrimSpace(track) == "" {
		p.recordCAPTCHAAnswer(r, clientIP, "slider", token, false)
		return false
	}
	ok := captcha.VerifySlider(p.sliderOptionsForSite(r, clientIP, site), captcha.SliderPayload{Token: token, X: x, DragMS: dragMS, Track: track})
	if ok {
		status, consumed := p.challengeStore.Consume(captchaChallengeJTI("slider", token))
		if !consumed || status != ChallengeUsed {
			ok = false
		}
	}
	p.recordCAPTCHAAnswer(r, clientIP, "slider", token, ok)
	return ok
}

func (p *Policy) validAltchaHeaderAnswer(r *http.Request, clientIP string) bool {
	return p.validAltchaHeaderAnswerForSite(r, clientIP, canonicalSite(r.Host))
}

func (p *Policy) validAltchaHeaderAnswerForSite(r *http.Request, clientIP, site string) bool {
	if p == nil || r == nil || !p.captcha || !p.secretReady || !p.powAcceptLegacy {
		return false
	}
	return p.validAltchaPayloadForSite(r, clientIP, site, altchaPayloadFromHeaders(r, p.altchaHeaderName))
}

func (p *Policy) validAltchaQueryAnswer(r *http.Request, clientIP string) bool {
	return p.validAltchaQueryAnswerForSite(r, clientIP, canonicalSite(r.Host))
}

func (p *Policy) validAltchaQueryAnswerForSite(r *http.Request, clientIP, site string) bool {
	if p == nil || r == nil || !p.captcha || !p.secretReady || !p.powAcceptLegacy {
		return false
	}
	return p.validAltchaPayloadForSite(r, clientIP, site, r.URL.Query().Get("cw_altcha"))
}

func (p *Policy) validAltchaPayload(r *http.Request, clientIP, raw string) bool {
	return p.validAltchaPayloadForSite(r, clientIP, canonicalSite(r.Host), raw)
}

func (p *Policy) validAltchaPayloadForSite(r *http.Request, clientIP, site, raw string) bool {
	if len(raw) == 0 || len(raw) > 4096 {
		return false
	}
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
	want := p.signAltchaForSite(r, clientIP, site, challenge)
	if !hmac.Equal([]byte(want), []byte(payload.Signature)) {
		return false
	}
	if !hmac.Equal([]byte(altchaHash(payload.Salt, payload.Number)), []byte(payload.Challenge)) {
		return false
	}
	nonce, ok := altchaSaltNonce(payload.Salt)
	if !ok {
		return false
	}
	status, consumed := p.challengeStore.Consume("legacy-altcha:" + nonce)
	return consumed && status == ChallengeUsed
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
	if len(raw) == 0 || len(raw) > 4096 {
		return altchaPayload{}, false
	}
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
	if len(data) == 0 || len(data) > 3072 {
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
		if prefix != "" && engine.PathMatchesPrefix(path, prefix) {
			return false
		}
	}
	for _, prefix := range p.pathPrefixes {
		if prefix == "" || engine.PathMatchesPrefix(path, prefix) {
			return true
		}
	}
	return false
}

// requestPath returns the cleaned absolute request path used for bot policy,
// clearance scope, and challenge binding. ok is false when the path is invalid.
func requestPath(r *http.Request) (string, bool) {
	if r == nil || r.URL == nil {
		return "", false
	}
	return engine.NormalizeRequestPath(r.URL.Path)
}

// mustRequestPath returns a cleaned path for signing/binding. Invalid paths
// fall back to "/" so cryptographic material stays deterministic; Evaluate
// rejects invalid paths before challenge issuance when possible.
func mustRequestPath(r *http.Request) string {
	if path, ok := requestPath(r); ok {
		return path
	}
	return "/"
}

func (p *Policy) allowed(userAgent string) bool {
	ua := strings.ToLower(strings.TrimSpace(userAgent))
	if ua == "" {
		return false
	}
	for _, item := range p.allowedUserAgents {
		if item == "" {
			continue
		}
		// Exact match or whole-token match (space/paren boundaries) — avoid substring abuse
		// e.g. allowlist "googlebot" must not match "evilgooglebot".
		if ua == item || uaTokenMatch(ua, item) {
			return true
		}
	}
	return false
}

// uaTokenMatch reports whether marker appears in ua as a whole token bounded by
// start/end of string or non-alphanumeric separators (space, slash, paren, etc.).
func uaTokenMatch(ua, marker string) bool {
	if marker == "" || len(marker) > len(ua) {
		return false
	}
	start := 0
	for {
		idx := strings.Index(ua[start:], marker)
		if idx < 0 {
			return false
		}
		pos := start + idx
		leftOK := pos == 0 || !isUATokenChar(ua[pos-1])
		right := pos + len(marker)
		rightOK := right == len(ua) || !isUATokenChar(ua[right])
		if leftOK && rightOK {
			return true
		}
		start = pos + 1
	}
}

func isUATokenChar(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '_' || b == '-'
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
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "", "pow":
		return "pow"
	case "image", "graphic":
		return "image"
	case "slider", "puzzle":
		return "slider"
	default:
		return value
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

func weakNetworkClient(r *http.Request) bool {
	if r == nil {
		return false
	}
	saveData := strings.EqualFold(strings.TrimSpace(r.Header.Get("Save-Data")), "on")
	effectiveType := strings.ToLower(strings.TrimSpace(r.Header.Get("ECT")))
	return saveData || effectiveType == "slow-2g" || effectiveType == "2g"
}

type challengeData struct {
	ChallengeText
	CookieName       string
	CookieValue      string
	MaxAge           int
	ReturnURL        string
	Nonce            string
	Expires          int64
	Signature        string
	Difficulty       int
	PoWToken         string
	PoWWork          int
	UsePoW           bool
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
	SliderMinDragMS  int
	Failed           bool
}

type waitingData struct {
	Text       WaitingText
	ReturnURL  string
	Admitted   bool
	Active     int
	Capacity   int
	RetryAfter int
	Nonce      string
}

// cookieSecure reports whether cookies for this request should carry the Secure flag.
// Trusts direct TLS or X-Forwarded-Proto: https (false-positive Secure is safer than missing Secure).
func cookieSecure(r *http.Request) bool {
	if r == nil {
		return false
	}
	if r.TLS != nil {
		return true
	}
	proto := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0])
	return strings.EqualFold(proto, "https")
}

func setChallengeDocumentSecurityHeaders(w http.ResponseWriter, nonce string) {
	if w == nil {
		return
	}
	quotedNonce := "'nonce-" + nonce + "'"
	w.Header().Set("Content-Security-Policy", "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; script-src "+quotedNonce+"; style-src "+quotedNonce+"; img-src data:; media-src 'self'; connect-src 'self'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
}

type ChallengeText struct {
	Lang, Title, Heading, Protected, FailedTitle, FailedBody                             string
	ImageInstruction, ImageAlt, AudioHint, AnswerLabel, AnswerPlaceholder, Verify        string
	SliderInstruction, SliderImageAlt, Checking, SliderNoticeTitle, SecurityVerification string
	SliderLabel, SliderThumbLabel, SliderCopy, RefreshLabel                              string
	AltchaInstruction, PoWInstruction, NoScript                                          string
	ReleaseTitle, DragFirstTitle, DragFirstBody, SubmittedTitle, Elapsed                 string
}

type WaitingText struct {
	Lang, Title, Heading, Admitted, Busy, ActiveSlots string
}

func localizedChallengeText(r *http.Request) ChallengeText {
	if preferredLanguage(r) == "zh-CN" {
		return ChallengeText{Lang: "zh-CN", Title: "浏览器验证", Heading: "浏览器验证", Protected: "CheeseWAF 正在保护本次请求。", FailedTitle: "验证失败", FailedBody: "已生成新的验证，请重试。", ImageInstruction: "请输入图片中的数字；如果图片不清晰，可以使用音频验证。", ImageAlt: "包含数字的验证码图片", AudioHint: "音频由服务端根据不透明挑战令牌生成，地址中不包含答案。", AnswerLabel: "验证码答案", AnswerPlaceholder: "输入数字", Verify: "验证", SliderInstruction: "拖动滑块，使拼图片与缺口重合；松开后将立即验证。", SliderImageAlt: "滑块拼图验证码图片", Checking: "正在验证", SliderNoticeTitle: "拖动拼图片填入缺口", SecurityVerification: "安全验证", SliderLabel: "滑块拼图位置", SliderThumbLabel: "拖动滑块；也可使用方向键调整，按 Enter 提交", SliderCopy: "拖动拼图片对齐缺口", RefreshLabel: "刷新验证", AltchaInstruction: "CheeseWAF 正在浏览器本地完成后台安全校验。", PoWInstruction: "CheeseWAF 正在确认本次访问环境，完成后台安全校验后将自动刷新。", NoScript: "后台安全校验和滑块验证需要 JavaScript；如需无 JavaScript 访问，请使用图形验证码模式。", ReleaseTitle: "对齐后松开滑块", DragFirstTitle: "请先拖动滑块", DragFirstBody: "请将拼图片移动到图片缺口。", SubmittedTitle: "已提交验证", Elapsed: "耗时"}
	}
	return ChallengeText{Lang: "en", Title: "Browser verification", Heading: "Browser verification", Protected: "CheeseWAF is protecting this request.", FailedTitle: "Verification failed", FailedBody: "A new challenge has been generated. Please try again.", ImageInstruction: "Enter the digits shown in the image, or use the audio challenge if the image is unclear.", ImageAlt: "CAPTCHA image with digits", AudioHint: "Audio is generated server-side from an opaque challenge token; the URL does not contain the answer.", AnswerLabel: "CAPTCHA answer", AnswerPlaceholder: "Enter digits", Verify: "Verify", SliderInstruction: "Drag the slider so the puzzle piece fits the image gap. Verification is checked when you release it.", SliderImageAlt: "Puzzle slider CAPTCHA image", Checking: "Checking verification", SliderNoticeTitle: "Drag to fill the image gap", SecurityVerification: "Security verification", SliderLabel: "Puzzle slider position", SliderThumbLabel: "Drag slider, or use arrow keys and press Enter to submit", SliderCopy: "Drag to fit the puzzle piece", RefreshLabel: "Refresh challenge", AltchaInstruction: "CheeseWAF is completing a background security check in this browser.", PoWInstruction: "CheeseWAF is checking this browsing environment and will reload after the background security check completes.", NoScript: "JavaScript is required for the background security check and slider verification. Use image CAPTCHA mode if JavaScript-free access is required.", ReleaseTitle: "Release after aligning the piece", DragFirstTitle: "Drag the slider first", DragFirstBody: "Move the puzzle piece to the image gap.", SubmittedTitle: "Verification submitted", Elapsed: "Elapsed"}
}

func localizedWaitingText(r *http.Request) WaitingText {
	if preferredLanguage(r) == "zh-CN" {
		return WaitingText{Lang: "zh-CN", Title: "排队等待", Heading: "排队等待", Admitted: "已有可用的浏览器席位，即将自动进入。", Busy: "受保护服务当前繁忙，本页面将自动重试。", ActiveSlots: "个活动席位"}
	}
	return WaitingText{Lang: "en", Title: "Waiting room", Heading: "Waiting room", Admitted: "A browser slot is available. You will enter automatically.", Busy: "The protected service is busy. This page will retry automatically.", ActiveSlots: "active slots"}
}

func preferredLanguage(r *http.Request) string {
	if r != nil {
		for _, item := range strings.Split(strings.ToLower(r.Header.Get("Accept-Language")), ",") {
			if strings.HasPrefix(strings.TrimSpace(item), "zh") {
				return "zh-CN"
			}
		}
	}
	return "en"
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
	if max < 0 {
		return 0, fmt.Errorf("random number maximum must not be negative")
	}
	if max == 0 {
		return 0, nil
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

func altchaSaltNonce(salt string) (string, bool) {
	idx := strings.LastIndexByte(salt, ':')
	if idx <= 0 || idx > 128 {
		return "", false
	}
	return salt[:idx], true
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
	for _, key := range []string{"cw_nonce", "cw_expires", "cw_sig", "cw_pow", "cw_pow_token", "cw_pow_answer", "cw_altcha", "cw_image_token", "cw_image_answer", "cw_slider_token", "cw_slider_x", "cw_slider_drag_ms", "cw_slider_track", "cw_audio"} {
		query.Del(key)
	}
	next.RawQuery = query.Encode()
	return next.RequestURI()
}

func safeChallengeReturnURL(r *http.Request) string {
	cleaned := cleanChallengeURL(r)
	if cleaned == "" {
		return "/"
	}
	return safeRelativeRedirect(cleaned)
}

func safeRelativeRedirect(raw string) string {
	s := fsguard.SanitizeLocalRedirect(raw)
	// Mirror CodeQL go/bad-redirect-check complete form (len>1 second-char).
	if len(s) > 1 && s[0] == '/' && s[1] != '/' && s[1] != '\\' {
		return s
	}
	if s == "/" {
		return "/"
	}
	return "/"
}

func challengeRequestForReturnURL(r *http.Request, returnURL string) *http.Request {
	if r == nil || r.URL == nil {
		return r
	}
	safe := safeRelativeRedirect(returnURL)
	pathPart := safe
	rawQuery := ""
	if q := strings.IndexByte(safe, '?'); q >= 0 {
		pathPart = safe[:q]
		rawQuery = safe[q+1:]
	}
	// Full second-character check (not only leading slash / //).
	if pathPart == "" || pathPart[0] != '/' || (len(pathPart) > 1 && (pathPart[1] == '/' || pathPart[1] == '\\')) {
		pathPart = "/"
		rawQuery = ""
	}
	clone := r.Clone(r.Context())
	next := *r.URL
	next.Scheme = ""
	next.Host = ""
	next.User = nil
	next.Opaque = ""
	next.Path = pathPart
	next.RawPath = ""
	next.RawQuery = rawQuery
	next.Fragment = ""
	clone.URL = &next
	return clone
}

func imageAudioURL(r *http.Request, token string) string {
	next, err := url.Parse(safeChallengeReturnURL(r))
	if err != nil {
		return "/?cw_audio=" + url.QueryEscape(token)
	}
	query := next.Query()
	query.Set("cw_audio", token)
	next.RawQuery = query.Encode()
	return next.RequestURI()
}

var waitingTemplate = template.Must(template.New("waiting-room").Parse(`<!doctype html>
<html lang="{{.Text.Lang}}">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{.Text.Title}}</title>
  <style nonce="{{.Nonce}}">
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
    <h1>{{.Text.Heading}}</h1>
    {{if .Admitted}}
      <p>{{.Text.Admitted}}</p>
      <div class="meter"><span></span></div>
      <script nonce="{{.Nonce}}">
        window.setTimeout(function(){ window.location.replace("{{.ReturnURL}}"); }, 350);
      </script>
    {{else}}
      <p>{{.Text.Busy}}</p>
      <div class="meter"><span></span></div>
      <small>{{.Active}} / {{.Capacity}} {{.Text.ActiveSlots}}</small>
      <script nonce="{{.Nonce}}">
        window.setTimeout(function(){ window.location.reload(); }, {{.RetryAfter}} * 1000);
      </script>
    {{end}}
  </main>
</body>
</html>`))

var challengeTemplate = template.Must(template.New("bot-challenge").Parse(`<!doctype html>
<html lang="{{.Lang}}">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{.Title}}</title>
  <style nonce="{{.Nonce}}">
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
    @media(prefers-reduced-motion:reduce){*,*::before,*::after{animation-duration:.01ms!important;animation-iteration-count:1!important;scroll-behavior:auto!important;transition-duration:.01ms!important}.slider-track::after{display:none}}
    @media(max-width:460px){main{padding:14px}.captcha-row{display:grid}button{width:100%}.slider-copy{font-size:12px}}
  </style>
</head>
<body>
  <main>
    <header><div class="mark" aria-hidden="true">CW</div><h1>{{.Heading}}</h1><p>{{.Protected}}</p></header>
    {{if .Failed}}<div class="notice warning" role="alert"><strong>{{.FailedTitle}}</strong><span>{{.FailedBody}}</span></div>{{end}}
    {{if .UseImage}}
      <p>{{.ImageInstruction}}</p>
      <form class="captcha" method="post" action="{{.ReturnURL}}" autocomplete="off">
        <img class="captcha-img" src="{{.ImageData}}" width="{{.ImageWidth}}" height="{{.ImageHeight}}" alt="{{.ImageAlt}}">
        <audio controls preload="none" src="{{.AudioURL}}"></audio>
        <p class="hint">{{.AudioHint}}</p>
        <input type="hidden" name="cw_image_token" value="{{.ImageToken}}">
        <div class="captcha-row">
          <input name="cw_image_answer" inputmode="numeric" pattern="[0-9]*" maxlength="{{.ImageLength}}" aria-label="{{.AnswerLabel}}" placeholder="{{.AnswerPlaceholder}}" required>
          <button type="submit">{{.Verify}}</button>
        </div>
      </form>
    {{else if .UseSlider}}
      <p>{{.SliderInstruction}}</p>
      <form id="slider-form" class="captcha" method="post" action="{{.ReturnURL}}" autocomplete="off">
        <div class="slider-stage" style="--piece:{{.SliderPieceSize}}px;--slider-width:{{.SliderWidth}}px">
          <img src="{{.SliderImage}}" width="{{.SliderWidth}}" height="{{.SliderHeight}}" alt="{{.SliderImageAlt}}" draggable="false">
          <img id="slider-piece" class="slider-piece" src="{{.SliderPiece}}" width="{{.SliderPieceSize}}" height="{{.SliderPieceSize}}" alt="" draggable="false">
          <div id="stage-tip" class="stage-tip" role="status" aria-live="polite" hidden>{{.Checking}}</div>
        </div>
        <div id="slider-notice" class="notice" role="status" aria-live="polite" hidden><strong>{{.SliderNoticeTitle}}</strong><span>{{.SecurityVerification}}</span></div>
        <div id="slider-track" class="slider-track" role="group" aria-label="{{.SliderLabel}}" style="--piece:{{.SliderPieceSize}}px;--slider-width:{{.SliderWidth}}px">
          <span id="slider-fill" class="slider-fill"></span>
          <button id="slider-thumb" class="slider-thumb" type="button" role="slider" aria-label="{{.SliderThumbLabel}}" aria-valuemin="0" aria-valuemax="{{.SliderTrackWidth}}" aria-valuenow="0">&rarr;</button>
          <span id="slider-copy" class="slider-copy">{{.SliderCopy}}</span>
        </div>
        <input type="hidden" name="cw_slider_token" value="{{.SliderToken}}">
        <input id="slider-x" type="hidden" name="cw_slider_x" value="">
        <input id="slider-drag-ms" type="hidden" name="cw_slider_drag_ms" value="">
        <input id="slider-track-data" type="hidden" name="cw_slider_track" value="">
        <div class="captcha-foot"><span class="captcha-brand"><span class="captcha-brand-mark" aria-hidden="true">CW</span><strong>CheeseWAF</strong></span><button type="button" id="slider-refresh" aria-label="{{.RefreshLabel}}">&#8635;</button></div>
      </form>
    {{else if .UseAltcha}}
      <p>{{.AltchaInstruction}}</p>
      <div class="bar"><span></span></div>
    {{else if .UsePoW}}
      <p>{{.PoWInstruction}}</p>
      <div class="bar"><span></span></div>
    {{end}}
    <noscript>{{.NoScript}}</noscript>
  </main>
  <script nonce="{{.Nonce}}">
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
      const minDragMS = {{.SliderMinDragMS}};
      let drag = null;
      let locked = false;
      let trackPoints = [];
      function apply(x){
        const next = Math.max(0, Math.min(trackWidth, Math.round(x)));
        thumb.style.transform = "translateX(" + next + "px)";
        piece.style.transform = "translate3d(" + next + "px," + targetY + "px,0)";
        fill.style.width = (next + pieceSize / 2) + "px";
        thumb.setAttribute("aria-valuenow", String(next));
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
        drag = {id:event.pointerId, origin:event.clientX, start: Number(thumb.getAttribute("aria-valuenow") || "0"), at: performance.now()};
        trackPoints = [rel(event, drag.start, "down")];
        setNotice("", "{{.ReleaseTitle}}", "{{.SecurityVerification}}");
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
          setNotice("warning", "{{.DragFirstTitle}}", "{{.DragFirstBody}}");
          apply(0);
          return;
        }
        locked = true;
        tip.hidden = false;
        setNotice("success", "{{.SubmittedTitle}}", "{{.Elapsed}} " + (Number(inputMS.value) / 1000).toFixed(2) + "s");
        copy.textContent = "{{.SubmittedTitle}}";
        window.setTimeout(function(){ document.getElementById("slider-form").submit(); }, 120);
      }
      apply(0);
      track.addEventListener("pointerdown", start);
      track.addEventListener("pointermove", move);
      track.addEventListener("pointerup", finish);
      track.addEventListener("pointercancel", finish);
      thumb.addEventListener("keydown", function(event){
        if (locked) return;
        const current = Number(thumb.getAttribute("aria-valuenow") || "0");
        let next = current;
        if (event.key === "ArrowLeft" || event.key === "ArrowDown") next = current - (event.shiftKey ? 10 : 2);
        else if (event.key === "ArrowRight" || event.key === "ArrowUp") next = current + (event.shiftKey ? 10 : 2);
        else if (event.key === "Home") next = 0;
        else if (event.key === "End") next = trackWidth;
        else if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          const x = apply(current);
          if (x <= 0) { setNotice("warning", "{{.DragFirstTitle}}", "{{.DragFirstBody}}"); return; }
          inputX.value = String(x);
          const keyboardDragMS = Math.max(minDragMS, 500);
          const middleX = Math.max(1, Math.min(x - 1, Math.round(x / 2)));
          inputMS.value = String(keyboardDragMS);
          inputTrack.value = JSON.stringify([{x:0,y:0,t:0,type:"down"},{x:middleX,y:0,t:Math.round(keyboardDragMS / 2),type:"move"},{x:x,y:0,t:keyboardDragMS,type:"up"}]);
          locked = true;
          tip.hidden = false;
          setNotice("success", "{{.SubmittedTitle}}", "{{.Elapsed}} " + (keyboardDragMS / 1000).toFixed(2) + "s");
          copy.textContent = "{{.SubmittedTitle}}";
          window.setTimeout(function(){ document.getElementById("slider-form").submit(); }, 120);
          return;
        } else return;
        event.preventDefault();
        apply(next);
        setNotice("", "{{.ReleaseTitle}}", "{{.SecurityVerification}}");
      });
      refresh.addEventListener("click", function(){ window.location.replace("{{.ReturnURL}}"); });
    })();
    {{else if .UseAltcha}}
    const challenge = {algorithm:"{{.AltchaAlgorithm}}",challenge:"{{.AltchaChallenge}}",maxnumber:{{.AltchaMaxNumber}},salt:"{{.AltchaSalt}}",signature:"{{.AltchaSignature}}"};
    async function sha256Hex(input){const data=new TextEncoder().encode(input);const digest=await crypto.subtle.digest("SHA-256",data);return Array.from(new Uint8Array(digest)).map((b)=>b.toString(16).padStart(2,"0")).join("")}
    async function solve(){for(let i=0;i<=challenge.maxnumber;i++){const hash=await sha256Hex(challenge.salt+String(i));if(hash===challenge.challenge){const payload=btoa(JSON.stringify({algorithm:challenge.algorithm,challenge:challenge.challenge,number:i,salt:challenge.salt,signature:challenge.signature}));const target=new URL("{{.ReturnURL}}",window.location.origin);target.searchParams.set("cw_altcha",payload);window.location.replace(target.toString());return}if(i>0&&i%500===0){await new Promise((resolve)=>window.setTimeout(resolve,0))}}window.setTimeout(function(){window.location.reload()},1000)}
    if(window.crypto&&window.crypto.subtle){solve()}
    {{else if .UsePoW}}
    const token="{{.PoWToken}}";const work={{.PoWWork}};
    async function sha256Bytes(input){const data=new TextEncoder().encode(input);return new Uint8Array(await crypto.subtle.digest("SHA-256",data))}
    function hasWork(bytes,n){for(let i=0;i<n;i++){const b=bytes[Math.floor(i/2)];if(i%2===0?(b>>4)!==0:(b&15)!==0)return false}return true}
    async function solve(){for(let i=0;i<12000000;i++){if(hasWork(await sha256Bytes(token+"\u0000"+i),work)){const body=new URLSearchParams({cw_pow_token:token,cw_pow_answer:String(i)});const response=await fetch("{{.ReturnURL}}",{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},body:body,credentials:"same-origin"});window.location.replace(response.url);return}if(i>0&&i%500===0){await new Promise((resolve)=>window.setTimeout(resolve,0))}}window.setTimeout(function(){window.location.reload()},1000)}
    if(window.crypto&&window.crypto.subtle){solve()}
    {{end}}
  </script>
</body>
</html>`))
