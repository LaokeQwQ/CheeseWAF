package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/api"
	"github.com/LaokeQwQ/CheeseWAF/internal/captcha"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/protection/bot"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
	"golang.org/x/crypto/bcrypt"
)

const (
	protocolPrefix        = "CHEESEWAF_CAPTCHA_INTEGRATION "
	loginClientCookie     = "cw_captcha_client"
	behaviorVerifyPath    = "/.well-known/cheesewaf/challenge/v1/verify"
	protectedPath         = "/admin/protected"
	fixtureClientIP       = "203.0.113.41"
	fixtureSite           = "captcha.integration"
	fixtureUserAgentToken = "captcha-e2e"
	fixtureAdminUserID    = "captcha-integration-user"
)

type fixture struct {
	root      string
	secret    string
	username  string
	password  string
	config    config.Config
	store     *storage.SQLiteStore
	policy    *bot.Policy
	admin     *http.Server
	waf       *http.Server
	adminURL  string
	wafURL    string
	mu        sync.RWMutex
	latestWAF map[string]wafChallenge
	sequence  uint64
}

type wafChallenge struct {
	challenge  captcha.BehaviorChallenge
	generation uint64
}

type controlRequest struct {
	ID        uint64                    `json:"id"`
	Action    string                    `json:"action"`
	Token     string                    `json:"token,omitempty"`
	Cookie    string                    `json:"cookie,omitempty"`
	UserAgent string                    `json:"user_agent,omitempty"`
	Variant   string                    `json:"variant,omitempty"`
	X         int                       `json:"x,omitempty"`
	DragMS    int                       `json:"drag_ms,omitempty"`
	Track     string                    `json:"track,omitempty"`
	Response  captcha.BehaviorResponse  `json:"response,omitempty"`
	Challenge captcha.BehaviorChallenge `json:"challenge,omitempty"`
}

type controlReply struct {
	ID         uint64 `json:"id,omitempty"`
	OK         bool   `json:"ok"`
	Ready      bool   `json:"ready,omitempty"`
	Error      string `json:"error,omitempty"`
	AdminURL   string `json:"admin_url,omitempty"`
	WAFURL     string `json:"waf_url,omitempty"`
	Username   string `json:"username,omitempty"`
	Password   string `json:"password,omitempty"`
	X          int    `json:"x,omitempty"`
	Y          int    `json:"y,omitempty"`
	DurationMS int    `json:"duration_ms,omitempty"`
	Generation uint64 `json:"generation,omitempty"`
	Diagnosis  string `json:"diagnosis,omitempty"`
	Plan       any    `json:"plan,omitempty"`
}

type behaviorPageState struct {
	Challenge captcha.BehaviorChallenge `json:"challenge"`
}

func main() {
	if err := run(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "CAPTCHA integration fixture failed")
		os.Exit(1)
	}
}

func run() error {
	fx, err := newFixture()
	if err != nil {
		return err
	}
	defer fx.close()

	if err := writeReply(controlReply{
		OK: true, Ready: true, AdminURL: fx.adminURL, WAFURL: fx.wafURL,
		Username: fx.username, Password: fx.password,
	}); err != nil {
		return err
	}

	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 64*1024), 256*1024)
	for scanner.Scan() {
		var request controlRequest
		if err := json.Unmarshal(scanner.Bytes(), &request); err != nil {
			_ = writeReply(controlReply{OK: false, Error: "invalid_request"})
			continue
		}
		reply, stop := fx.handle(request)
		if err := writeReply(reply); err != nil {
			return err
		}
		if stop {
			return nil
		}
	}
	return scanner.Err()
}

func newFixture() (*fixture, error) {
	root, err := os.MkdirTemp("", "cheesewaf-captcha-integration-")
	if err != nil {
		return nil, err
	}
	fail := func(cause error) (*fixture, error) {
		_ = os.RemoveAll(root)
		return nil, cause
	}
	secret, err := randomText(32)
	if err != nil {
		return fail(err)
	}
	usernameSuffix, err := randomText(9)
	if err != nil {
		return fail(err)
	}
	password, err := randomText(24)
	if err != nil {
		return fail(err)
	}
	username := "captcha_" + strings.ToLower(usernameSuffix)

	cfg := config.Default()
	cfg.Setup.DataDir = filepath.Join(root, "data")
	cfg.Setup.RuntimeDir = filepath.Join(root, "run")
	cfg.CAPTCHAAssets.Backend = "local"
	cfg.CAPTCHAAssets.Local.Path = filepath.Join(root, "captcha-assets")
	cfg.Console.Login.CAPTCHA.Enabled = true
	cfg.Console.Login.CAPTCHA.Mode = "slider"
	cfg.Console.Login.CAPTCHA.TTL = 2 * time.Minute
	cfg.Console.Login.CAPTCHA.Slider.MinDrag = 450 * time.Millisecond
	cfg.Console.Login.CAPTCHA.Slider.PowEnabled = false
	cfg.APISec.Audit.Enabled = false
	cfg.APISec.Audit.Path = filepath.Join(root, "audit.log")

	store, err := storage.OpenSQLite(filepath.Join(root, "cheesewaf.db"))
	if err != nil {
		return fail(err)
	}
	if err := store.Migrate(context.Background()); err != nil {
		_ = store.Close()
		return fail(err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		_ = store.Close()
		return fail(err)
	}
	if err := store.CreateUser(context.Background(), &storage.User{
		ID: fixtureAdminUserID, Username: username, PasswordHash: string(hash), Role: "admin",
	}); err != nil {
		_ = store.Close()
		return fail(err)
	}

	adminListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = store.Close()
		return fail(err)
	}
	wafListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = adminListener.Close()
		_ = store.Close()
		return fail(err)
	}

	botConfig := cfg.Protection.Bot
	botConfig.Enabled = true
	botConfig.JSChallenge = true
	botConfig.CAPTCHA = true
	botConfig.CAPTCHAType = "shape_slider"
	botConfig.CAPTCHATypes = []string{"shape_slider"}
	botConfig.CAPTCHAEscalationTypes = []string{"shape_slider"}
	botConfig.CAPTCHAChallengeTTL = 2 * time.Minute
	botConfig.CAPTCHAFailureWindow = 5 * time.Minute
	botConfig.CAPTCHABlockDuration = 5 * time.Minute
	botConfig.CAPTCHAMaxAttempts = 5
	botConfig.CAPTCHABindingMode = "ip_prefix_ua"
	botConfig.CAPTCHAPolicyVersion = "integration-v1"
	botConfig.CAPTCHAMobileType = ""
	botConfig.ChallengeTTL = 5 * time.Minute
	botConfig.ClearanceStateCapacity = 128
	botConfig.RiskLowThreshold = 10
	botConfig.RiskMediumThreshold = 20
	botConfig.RiskHighThreshold = 30
	botConfig.RiskBlockThreshold = 95
	botConfig.RiskConfidenceMin = 0.5
	botConfig.Secret = secret
	botConfig.CookieName = "cw_integration_clearance"
	botConfig.PathPrefixes = []string{"/"}
	botConfig.ExemptPathPrefixes = nil
	botConfig.AllowedUserAgents = nil
	botConfig.SuspiciousUserAgents = []string{fixtureUserAgentToken}
	cfg.Protection.Bot = botConfig

	fx := &fixture{
		root: root, secret: secret, username: username, password: password, config: cfg, store: store,
		policy: bot.NewPolicy(botConfig), latestWAF: make(map[string]wafChallenge),
	}
	fx.admin = quietServer(api.NewRouter(api.Options{Config: &fx.config, Store: store, Secret: secret}))
	fx.waf = quietServer(http.HandlerFunc(fx.serveWAF))
	fx.adminURL = "http://" + adminListener.Addr().String()
	fx.wafURL = "http://" + wafListener.Addr().String()
	go func() { _ = fx.admin.Serve(adminListener) }()
	go func() { _ = fx.waf.Serve(wafListener) }()
	return fx, nil
}

func quietServer(handler http.Handler) *http.Server {
	return &http.Server{
		Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second,
		ErrorLog: log.New(io.Discard, "", 0),
	}
}

func (fx *fixture) close() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if fx.admin != nil {
		_ = fx.admin.Shutdown(ctx)
	}
	if fx.waf != nil {
		_ = fx.waf.Shutdown(ctx)
	}
	if fx.store != nil {
		_ = fx.store.Close()
	}
	if fx.root != "" {
		_ = os.RemoveAll(fx.root)
	}
}

func (fx *fixture) handle(request controlRequest) (controlReply, bool) {
	reply := controlReply{ID: request.ID, OK: true}
	switch request.Action {
	case "login_plan":
		x, err := fx.loginTarget(request.Token, request.Cookie, request.UserAgent)
		if err != nil {
			return controlReply{ID: request.ID, OK: false, Error: "login_plan_unavailable"}, false
		}
		if request.Variant == "wrong" {
			x = alternateLoginX(x, fx.config.Console.Login.CAPTCHA.Slider.Width-fx.config.Console.Login.CAPTCHA.Slider.PieceSize)
		} else if request.Variant != "correct" {
			return controlReply{ID: request.ID, OK: false, Error: "invalid_variant"}, false
		}
		reply.X = x
		reply.DurationMS = int(fx.config.Console.Login.CAPTCHA.Slider.MinDrag/time.Millisecond) + 180
	case "login_diagnose":
		diagnosis, err := fx.loginDiagnosis(request)
		if err != nil {
			return controlReply{ID: request.ID, OK: false, Error: "login_diagnosis_unavailable"}, false
		}
		reply.Diagnosis = diagnosis
	case "waf_plan":
		plan, ok := fx.wafTarget(request.UserAgent, request.Variant)
		if !ok {
			return controlReply{ID: request.ID, OK: false, Error: "waf_plan_unavailable"}, false
		}
		return controlReply{ID: request.ID, OK: true, X: plan.X, Y: plan.Y, DurationMS: plan.DurationMS, Generation: plan.Generation}, false
	case "waf_diagnose":
		reply.Diagnosis = fx.wafDiagnosis(request.UserAgent, request.Response)
	case "lab_plan":
		plan, err := fx.labPlan(request.Challenge, request.Variant)
		if err != nil {
			return controlReply{ID: request.ID, OK: false, Error: "lab_plan_unavailable"}, false
		}
		reply.Plan = plan
	case "shutdown":
		return reply, true
	default:
		return controlReply{ID: request.ID, OK: false, Error: "unsupported_action"}, false
	}
	return reply, false
}

func (fx *fixture) wafDiagnosis(userAgent string, response captcha.BehaviorResponse) string {
	if strings.TrimSpace(userAgent) == "" || strings.TrimSpace(response.Token) == "" {
		return "incomplete"
	}
	result := captcha.VerifyBehaviorChallenge(captcha.BehaviorOptions{
		Secret: fx.secret, Purpose: "waf-bot-behavior-v1", ClientKey: fixtureClientIP + "\n" + userAgent,
		Path: protectedPath, Site: fixtureSite, TTL: fx.config.Protection.Bot.CAPTCHAChallengeTTL,
		Type: captcha.BehaviorShapeSlider,
	}, response)
	if result.Valid {
		return "proof_state"
	}
	if result.Reason == "binding_mismatch" || result.Reason == "incorrect" || result.Reason == "expired" || result.Reason == "invalid_response" {
		return result.Reason
	}
	return "invalid_token"
}

func (fx *fixture) loginTarget(token, cookieValue, userAgent string) (int, error) {
	options, trackWidth, dragMS, err := fx.loginSliderOptions(cookieValue, userAgent)
	if err != nil || token == "" {
		return 0, errors.New("incomplete login challenge")
	}
	first := 0
	last := 0
	for x := 1; x <= trackWidth; x++ {
		if captcha.VerifySlider(options, captcha.SliderPayload{Token: token, X: x, DragMS: dragMS, Track: loginSliderTrack(x, dragMS)}) {
			if first == 0 {
				first = x
			}
			last = x
		} else if first != 0 {
			break
		}
	}
	if first != 0 {
		return first + (last-first)/2, nil
	}
	return 0, errors.New("login target not found")
}

func loginSliderTrack(finalX, dragMS int) string {
	return fmt.Sprintf(
		`[{"x":0,"y":20,"t":0,"type":"down"},{"x":%d,"y":21,"t":%d,"type":"move"},{"x":%d,"y":22,"t":%d,"type":"up"}]`,
		finalX/2,
		dragMS/2,
		finalX,
		dragMS,
	)
}

func (fx *fixture) loginDiagnosis(request controlRequest) (string, error) {
	options, _, _, err := fx.loginSliderOptions(request.Cookie, request.UserAgent)
	if err != nil || request.Token == "" || request.DragMS <= 0 {
		return "", errors.New("incomplete login submission")
	}
	target, err := fx.loginTarget(request.Token, request.Cookie, request.UserAgent)
	if err != nil {
		return "binding", nil
	}
	if request.DragMS < int(fx.config.Console.Login.CAPTCHA.Slider.MinDrag/time.Millisecond) {
		return "timing", nil
	}
	if delta := request.X - target; delta < -fx.config.Console.Login.CAPTCHA.Slider.Tolerance || delta > fx.config.Console.Login.CAPTCHA.Slider.Tolerance {
		return "target", nil
	}
	payload := captcha.SliderPayload{Token: request.Token, X: request.X, DragMS: request.DragMS}
	if !captcha.VerifySlider(options, payload) {
		return "target", nil
	}
	payload.Track = request.Track
	if !captcha.VerifySlider(options, payload) {
		return "track", nil
	}
	return "proof_state", nil
}

func (fx *fixture) loginSliderOptions(cookieValue, userAgent string) (captcha.SliderOptions, int, int, error) {
	rawID, _, ok := strings.Cut(strings.TrimSpace(cookieValue), ".")
	if !ok || rawID == "" || userAgent == "" {
		return captcha.SliderOptions{}, 0, 0, errors.New("incomplete login client")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(rawID)
	if err != nil || len(decoded) != 24 {
		return captcha.SliderOptions{}, 0, 0, errors.New("invalid login client")
	}
	owner := "client:" + fingerprint(rawID)
	clientKey := "127.0.0.1\n" + userAgent + "\n" + owner
	cfg := fx.config.Console.Login.CAPTCHA
	options := captcha.SliderOptions{
		Secret: fx.secret, Purpose: "admin-login-slider", ClientKey: clientKey, Path: "admin-login",
		TTL: cfg.TTL, Width: cfg.Slider.Width, Height: cfg.Slider.Height, PieceSize: cfg.Slider.PieceSize,
		Tolerance: cfg.Slider.Tolerance, MinDrag: cfg.Slider.MinDrag,
	}
	dragMS := int(cfg.Slider.MinDrag/time.Millisecond) + 180
	trackWidth := cfg.Slider.Width - cfg.Slider.PieceSize
	return options, trackWidth, dragMS, nil
}

func alternateLoginX(target, trackWidth int) int {
	delta := max(32, trackWidth/3)
	if target+delta <= trackWidth {
		return target + delta
	}
	return max(1, target-delta)
}

type wafPlan struct {
	X, Y, DurationMS int
	Generation       uint64
}

func (fx *fixture) wafTarget(userAgent, variant string) (wafPlan, bool) {
	fx.mu.RLock()
	latest, ok := fx.latestWAF[userAgent]
	fx.mu.RUnlock()
	if !ok || latest.challenge.Type != captcha.BehaviorShapeSlider {
		return wafPlan{}, false
	}
	presentation := latest.challenge.Presentation
	y := (presentation.PieceY + presentation.PieceSize/2) * 10000 / max(1, presentation.Height)
	options := captcha.BehaviorOptions{
		Secret: fx.secret, Purpose: "waf-bot-behavior-v1", ClientKey: fixtureClientIP + "\n" + userAgent,
		Path: protectedPath, Site: fixtureSite, TTL: fx.config.Protection.Bot.CAPTCHAChallengeTTL,
		Type: captcha.BehaviorShapeSlider,
	}
	const duration = 620
	first := 0
	last := 0
	for x := 500; x <= 10000; x += 50 {
		if captcha.VerifyBehaviorChallenge(options, behaviorShapeResponse(latest.challenge.Token, x, y, duration)).Valid {
			if first == 0 {
				first = x
			}
			last = x
		} else if first != 0 {
			break
		}
	}
	if first == 0 {
		return wafPlan{}, false
	}
	target := first + (last-first)/2
	if variant == "wrong" {
		if target <= 5000 {
			target = min(10000, target+4000)
		} else {
			target = max(500, target-4000)
		}
	} else if variant != "correct" {
		return wafPlan{}, false
	}
	return wafPlan{X: target, Y: y, DurationMS: duration, Generation: latest.generation}, true
}

func behaviorShapeResponse(token string, x, y, duration int) captcha.BehaviorResponse {
	start := 500
	return captcha.BehaviorResponse{
		Token: token, Point: &captcha.BehaviorPoint{X: x, Y: y}, DurationMS: duration,
		Track: []captcha.BehaviorTrackPoint{
			{X: start, Y: y, T: 0, Type: "down"},
			{X: (start + x) / 2, Y: y, T: duration / 2, Type: "move"},
			{X: x, Y: y, T: duration, Type: "up"},
		},
	}
}

func (fx *fixture) serveWAF(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/health" {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = io.WriteString(w, `{"status":"ok"}`)
		return
	}
	if r.URL.Path == behaviorVerifyPath && r.Method == http.MethodPost {
		fx.policy.VerifyBehaviorChallenge(w, r, fixtureClientIP, fixtureSite, false)
		return
	}
	if r.URL.Path != protectedPath || r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	if fx.policy.EvaluateForSite(r, fixtureClientIP, fixtureSite) == nil {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = io.WriteString(w, `{"protected":true,"challenge":"passed"}`)
		return
	}
	recorder := httptest.NewRecorder()
	fx.policy.ServeChallengeForSite(recorder, r, fixtureClientIP, fixtureSite)
	result := recorder.Result()
	defer result.Body.Close()
	body, err := io.ReadAll(io.LimitReader(result.Body, 2<<20))
	if err != nil {
		http.Error(w, "challenge unavailable", http.StatusServiceUnavailable)
		return
	}
	if result.StatusCode == http.StatusForbidden {
		if challenge, ok := parseBehaviorChallenge(body); ok {
			fx.mu.Lock()
			fx.sequence++
			fx.latestWAF[r.UserAgent()] = wafChallenge{challenge: challenge, generation: fx.sequence}
			fx.mu.Unlock()
		}
	}
	copyResponse(w, result, body)
}

func parseBehaviorChallenge(body []byte) (captcha.BehaviorChallenge, bool) {
	marker := []byte("const S=")
	index := bytes.Index(body, marker)
	if index < 0 {
		return captcha.BehaviorChallenge{}, false
	}
	var state behaviorPageState
	decoder := json.NewDecoder(bytes.NewReader(body[index+len(marker):]))
	if err := decoder.Decode(&state); err != nil || state.Challenge.Token == "" {
		return captcha.BehaviorChallenge{}, false
	}
	return state.Challenge, true
}

func copyResponse(w http.ResponseWriter, response *http.Response, body []byte) {
	for key, values := range response.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(response.StatusCode)
	_, _ = w.Write(body)
}

func fingerprint(parts ...string) string {
	hash := sha256.New()
	for _, part := range parts {
		_, _ = hash.Write([]byte(strings.TrimSpace(part)))
		_, _ = hash.Write([]byte{0})
	}
	return base64.RawURLEncoding.EncodeToString(hash.Sum(nil))
}

func randomText(size int) (string, error) {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func writeReply(reply controlReply) error {
	encoded, err := json.Marshal(reply)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(os.Stdout, "%s%s\n", protocolPrefix, encoded)
	return err
}
