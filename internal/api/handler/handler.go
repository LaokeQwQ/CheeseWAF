package handler

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/api/dto"
	"github.com/LaokeQwQ/CheeseWAF/internal/api/middleware"
	"github.com/LaokeQwQ/CheeseWAF/internal/captcha"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/setup"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
	"golang.org/x/crypto/bcrypt"
)

type Handler struct {
	Config              *config.Config
	ConfigPath          string
	Store               storage.Store
	Sink                storage.LogSink
	Tokens              *middleware.TokenManager
	Secret              string
	Auditor             *middleware.Auditor
	StartedAt           time.Time
	OnSitesChanged      func([]config.SiteConfig)
	OnProtectionChanged func(config.ProtectionConfig) error
	OnAPISecChanged     func(config.APISecConfig) error
}

type Options struct {
	Config              *config.Config
	ConfigPath          string
	Store               storage.Store
	Sink                storage.LogSink
	Tokens              *middleware.TokenManager
	Secret              string
	Auditor             *middleware.Auditor
	OnSitesChanged      func([]config.SiteConfig)
	OnProtectionChanged func(config.ProtectionConfig) error
	OnAPISecChanged     func(config.APISecConfig) error
}

func New(opts Options) *Handler {
	return &Handler{
		Config:              opts.Config,
		ConfigPath:          opts.ConfigPath,
		Store:               opts.Store,
		Sink:                opts.Sink,
		Tokens:              opts.Tokens,
		Secret:              opts.Secret,
		Auditor:             opts.Auditor,
		StartedAt:           time.Now().UTC(),
		OnSitesChanged:      opts.OnSitesChanged,
		OnProtectionChanged: opts.OnProtectionChanged,
		OnAPISecChanged:     opts.OnAPISecChanged,
	}
}

func (h *Handler) notifyProtectionChanged() error {
	if h == nil || h.OnProtectionChanged == nil || h.Config == nil {
		return nil
	}
	return h.OnProtectionChanged(h.Config.Protection)
}

func (h *Handler) notifyAPISecChanged() error {
	if h == nil || h.OnAPISecChanged == nil || h.Config == nil {
		return nil
	}
	return h.OnAPISecChanged(h.Config.APISec)
}

func (h *Handler) Health(w http.ResponseWriter, _ *http.Request) {
	writeData(w, map[string]any{"status": "ok", "uptime_seconds": int(time.Since(h.StartedAt).Seconds())})
}

func (h *Handler) LoginOptions(w http.ResponseWriter, _ *http.Request) {
	login := h.loginConfig()
	writeData(w, map[string]any{
		"captcha": map[string]any{
			"enabled":    login.CAPTCHA.Enabled,
			"mode":       login.CAPTCHA.Mode,
			"algorithm":  captcha.AlgorithmSHA256,
			"max_number": loginCAPTCHAPowMax(login.CAPTCHA),
			"slider": map[string]any{
				"width":          login.CAPTCHA.Slider.Width,
				"height":         login.CAPTCHA.Slider.Height,
				"piece_size":     login.CAPTCHA.Slider.PieceSize,
				"tolerance":      login.CAPTCHA.Slider.Tolerance,
				"min_drag_ms":    int(login.CAPTCHA.Slider.MinDrag / time.Millisecond),
				"pow_enabled":    login.CAPTCHA.Slider.PowEnabled,
				"pow_max_number": login.CAPTCHA.Slider.PowMaxNumber,
			},
		},
		"background": login.Background,
	})
}

func (h *Handler) LoginCAPTCHA(w http.ResponseWriter, r *http.Request) {
	login := h.loginConfig()
	if !login.CAPTCHA.Enabled {
		writeData(w, map[string]any{"enabled": false})
		return
	}
	response := map[string]any{"enabled": true, "mode": login.CAPTCHA.Mode}
	if loginCAPTCHARequiresPow(login.CAPTCHA) {
		challenge, err := captcha.NewChallenge(captcha.Options{
			Secret:    h.loginCaptchaSecret(),
			Purpose:   "admin-login",
			ClientKey: loginCaptchaClientKey(r),
			Path:      "admin-login",
			MaxNumber: loginCAPTCHAPowMax(login.CAPTCHA),
			TTL:       login.CAPTCHA.TTL,
		})
		if err != nil {
			writeError(w, http.StatusInternalServerError, "CAPTCHA_ERROR", err.Error())
			return
		}
		response["challenge"] = challenge
	}
	if loginCaptchaMode(login.CAPTCHA) == "slider" {
		slider, err := captcha.NewSliderChallenge(captcha.SliderOptions{
			Secret:    h.loginCaptchaSecret(),
			Purpose:   "admin-login-slider",
			ClientKey: loginCaptchaClientKey(r),
			Path:      "admin-login",
			TTL:       login.CAPTCHA.TTL,
			Width:     login.CAPTCHA.Slider.Width,
			Height:    login.CAPTCHA.Slider.Height,
			PieceSize: login.CAPTCHA.Slider.PieceSize,
			Tolerance: login.CAPTCHA.Slider.Tolerance,
			MinDrag:   login.CAPTCHA.Slider.MinDrag,
		})
		if err != nil {
			writeError(w, http.StatusInternalServerError, "CAPTCHA_ERROR", err.Error())
			return
		}
		response["slider"] = slider
	}
	writeData(w, response)
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var req dto.LoginRequest
	if !decode(w, r, &req) {
		return
	}
	if !h.verifyLoginCAPTCHA(r, req.CAPTCHA) {
		writeError(w, http.StatusUnauthorized, "INVALID_CAPTCHA", "captcha verification failed")
		return
	}
	h.pruneExpiredSessions(r)
	user, err := h.Store.GetUserByUsername(r.Context(), req.Username)
	if err != nil || user == nil || bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)) != nil {
		writeError(w, http.StatusUnauthorized, "INVALID_CREDENTIALS", "invalid username or password")
		return
	}
	if user.TwoFAEnabled {
		if req.TOTPCode == "" {
			writeError(w, http.StatusUnauthorized, "TWO_FA_REQUIRED", "two-factor code required")
			return
		}
		if !verifyTOTP(user.TwoFASecret, req.TOTPCode, time.Now().UTC()) {
			writeError(w, http.StatusUnauthorized, "INVALID_TWO_FA_CODE", "invalid two-factor code")
			return
		}
	}
	token, claims, err := h.Tokens.SignWithClaims(user.ID, user.Username, user.Role)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "TOKEN_ERROR", err.Error())
		return
	}
	if err := h.Store.CreateSession(r.Context(), sessionFromClaims(claims)); err != nil {
		writeError(w, http.StatusInternalServerError, "SESSION_ERROR", err.Error())
		return
	}
	writeData(w, map[string]any{"token": token, "user": user})
}

func (h *Handler) verifyLoginCAPTCHA(r *http.Request, payload *dto.CAPTCHAPayload) bool {
	login := h.loginConfig()
	if !login.CAPTCHA.Enabled {
		return true
	}
	if payload == nil {
		return false
	}
	if loginCaptchaMode(login.CAPTCHA) == "slider" {
		if payload.Slider == nil || !captcha.VerifySlider(captcha.SliderOptions{
			Secret:    h.loginCaptchaSecret(),
			Purpose:   "admin-login-slider",
			ClientKey: loginCaptchaClientKey(r),
			Path:      "admin-login",
			TTL:       login.CAPTCHA.TTL,
			Width:     login.CAPTCHA.Slider.Width,
			Height:    login.CAPTCHA.Slider.Height,
			PieceSize: login.CAPTCHA.Slider.PieceSize,
			Tolerance: login.CAPTCHA.Slider.Tolerance,
			MinDrag:   login.CAPTCHA.Slider.MinDrag,
		}, captcha.SliderPayload{
			Token:  payload.Slider.Token,
			X:      payload.Slider.X,
			DragMS: payload.Slider.DragMS,
		}) {
			return false
		}
		if !loginCAPTCHARequiresPow(login.CAPTCHA) {
			return true
		}
	}
	return captcha.Verify(captcha.Options{
		Secret:    h.loginCaptchaSecret(),
		Purpose:   "admin-login",
		ClientKey: loginCaptchaClientKey(r),
		Path:      "admin-login",
		MaxNumber: loginCAPTCHAPowMax(login.CAPTCHA),
		TTL:       login.CAPTCHA.TTL,
	}, captcha.Payload{
		Algorithm: payload.Algorithm,
		Challenge: payload.Challenge,
		Number:    payload.Number,
		Salt:      payload.Salt,
		Signature: payload.Signature,
	})
}

func (h *Handler) loginConfig() config.ConsoleLoginConfig {
	if h == nil || h.Config == nil {
		return config.Default().Console.Login
	}
	login := h.Config.Console.Login
	def := config.Default().Console.Login
	if login.CAPTCHA.MaxNumber <= 0 {
		login.CAPTCHA.MaxNumber = def.CAPTCHA.MaxNumber
	}
	if login.CAPTCHA.Mode == "" {
		login.CAPTCHA.Mode = def.CAPTCHA.Mode
	}
	if login.CAPTCHA.TTL <= 0 {
		login.CAPTCHA.TTL = def.CAPTCHA.TTL
	}
	if login.CAPTCHA.Slider.Width <= 0 {
		login.CAPTCHA.Slider.Width = def.CAPTCHA.Slider.Width
	}
	if login.CAPTCHA.Slider.Height <= 0 {
		login.CAPTCHA.Slider.Height = def.CAPTCHA.Slider.Height
	}
	if login.CAPTCHA.Slider.PieceSize <= 0 {
		login.CAPTCHA.Slider.PieceSize = def.CAPTCHA.Slider.PieceSize
	}
	if login.CAPTCHA.Slider.Tolerance <= 0 {
		login.CAPTCHA.Slider.Tolerance = def.CAPTCHA.Slider.Tolerance
	}
	if login.CAPTCHA.Slider.MinDrag <= 0 {
		login.CAPTCHA.Slider.MinDrag = def.CAPTCHA.Slider.MinDrag
	}
	if login.CAPTCHA.Slider.PowMaxNumber <= 0 {
		login.CAPTCHA.Slider.PowMaxNumber = def.CAPTCHA.Slider.PowMaxNumber
	}
	if login.SecurityEntry.Path == "" {
		login.SecurityEntry.Path = def.SecurityEntry.Path
	}
	if login.SecurityEntry.CookieName == "" {
		login.SecurityEntry.CookieName = def.SecurityEntry.CookieName
	}
	if login.Background.Type == "" {
		login.Background.Type = "auto"
	}
	return login
}

func loginCaptchaMode(cfg config.LoginCAPTCHAConfig) string {
	mode := strings.ToLower(strings.TrimSpace(cfg.Mode))
	if mode == "" {
		return "slider"
	}
	return mode
}

func loginCAPTCHAPowMax(cfg config.LoginCAPTCHAConfig) int {
	maxNumber := cfg.MaxNumber
	if loginCaptchaMode(cfg) == "slider" && cfg.Slider.PowEnabled && cfg.Slider.PowMaxNumber > 0 && cfg.Slider.PowMaxNumber < maxNumber {
		maxNumber = cfg.Slider.PowMaxNumber
	}
	if maxNumber <= 0 {
		return 75000
	}
	return maxNumber
}

func loginCAPTCHARequiresPow(cfg config.LoginCAPTCHAConfig) bool {
	if loginCaptchaMode(cfg) == "slider" {
		return cfg.Slider.PowEnabled
	}
	return true
}

func (h *Handler) loginCaptchaSecret() string {
	if h != nil && h.Secret != "" {
		return h.Secret
	}
	if h != nil && h.Config != nil && !config.IsWeakBotSecret(h.Config.Protection.Bot.Secret) {
		return h.Config.Protection.Bot.Secret
	}
	if secret, err := config.GenerateSecret(); err == nil {
		return secret
	}
	return "cheesewaf-login-captcha"
}

func loginCaptchaClientKey(r *http.Request) string {
	if r == nil {
		return ""
	}
	host := r.RemoteAddr
	if parsedHost, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		host = parsedHost
	}
	return strings.TrimSpace(host) + "\n" + r.UserAgent()
}

func (h *Handler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	claims, _ := r.Context().Value(middleware.UserContextKey).(*middleware.Claims)
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "unauthorized")
		return
	}
	user, err := h.Store.GetUserByUsername(r.Context(), claims.Username)
	if err != nil || user == nil || user.ID != claims.Subject {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "unauthorized")
		return
	}
	token, nextClaims, err := h.Tokens.SignWithClaims(user.ID, user.Username, user.Role)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "TOKEN_ERROR", err.Error())
		return
	}
	if err := h.Store.RotateSession(r.Context(), claims.ID, user.ID, sessionFromClaims(nextClaims)); err != nil {
		writeError(w, http.StatusInternalServerError, "SESSION_ERROR", err.Error())
		return
	}
	writeData(w, map[string]any{"token": token, "user": user})
}

func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	claims, _ := r.Context().Value(middleware.UserContextKey).(*middleware.Claims)
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "unauthorized")
		return
	}
	if err := h.Store.RevokeSession(r.Context(), claims.ID, claims.Subject); err != nil {
		writeError(w, http.StatusInternalServerError, "SESSION_ERROR", err.Error())
		return
	}
	writeData(w, map[string]any{"revoked": true})
}

func (h *Handler) revokeUserSessions(w http.ResponseWriter, r *http.Request, userID string, exceptID string) bool {
	if err := h.Store.RevokeUserSessions(r.Context(), userID, exceptID); err != nil {
		writeError(w, http.StatusInternalServerError, "SESSION_ERROR", err.Error())
		return false
	}
	return true
}

func (h *Handler) pruneExpiredSessions(r *http.Request) {
	if h == nil || h.Store == nil {
		return
	}
	cutoff := time.Now().UTC().Add(-24 * time.Hour)
	_, _ = h.Store.PruneSessions(r.Context(), cutoff)
}

func sessionFromClaims(claims *middleware.Claims) *storage.Session {
	if claims == nil {
		return nil
	}
	return &storage.Session{
		ID:        claims.ID,
		UserID:    claims.Subject,
		Username:  claims.Username,
		Role:      claims.Role,
		IssuedAt:  time.Unix(claims.IssuedAt, 0).UTC(),
		ExpiresAt: time.Unix(claims.Expires, 0).UTC(),
	}
}

func (h *Handler) Setup(w http.ResponseWriter, r *http.Request) {
	var req dto.SetupRequest
	if !decode(w, r, &req) {
		return
	}
	defaultAdminListen := setup.DefaultAdminListen
	if h.Config != nil && h.Config.Server.AdminListen != "" {
		defaultAdminListen = h.Config.Server.AdminListen
	}
	result, err := setup.CompleteSetup(r.Context(), setup.CompleteOptions{
		Config:             h.Config,
		ConfigPath:         h.ConfigPath,
		Store:              h.Store,
		DefaultAdminListen: defaultAdminListen,
	}, setup.SetupPayload{
		Username:      req.Username,
		Password:      req.Password,
		AdminListen:   req.AdminListen,
		AdminStrategy: req.AdminStrategy,
		AdminPublic:   req.AdminPublic,
	})
	if err != nil {
		status := setup.SetupErrorStatus(err)
		code := "SETUP_ERROR"
		if status == http.StatusBadRequest {
			code = "SETUP_VALIDATION"
		}
		if status == http.StatusConflict {
			code = "SETUP_COMPLETE"
		}
		writeError(w, status, code, err.Error())
		return
	}
	if result.Config != nil {
		h.Config = result.Config
	}
	writeData(w, map[string]any{"user": result.User, "setup_complete": true})
}

func decode(w http.ResponseWriter, r *http.Request, dest any) bool {
	if err := json.NewDecoder(r.Body).Decode(dest); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", err.Error())
		return false
	}
	return true
}

func writeData(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(dto.Response{Data: data})
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(dto.Response{Error: &dto.APIError{Code: code, Message: message}})
}
