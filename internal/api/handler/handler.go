package handler

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/acme"
	"github.com/LaokeQwQ/CheeseWAF/internal/ai"
	"github.com/LaokeQwQ/CheeseWAF/internal/api/dto"
	"github.com/LaokeQwQ/CheeseWAF/internal/api/middleware"
	"github.com/LaokeQwQ/CheeseWAF/internal/blockpage"
	"github.com/LaokeQwQ/CheeseWAF/internal/captcha"
	captchaassets "github.com/LaokeQwQ/CheeseWAF/internal/captcha/assets"
	"github.com/LaokeQwQ/CheeseWAF/internal/cluster"
	"github.com/LaokeQwQ/CheeseWAF/internal/cluster/deploy"
	"github.com/LaokeQwQ/CheeseWAF/internal/cluster/identity"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	protectionip "github.com/LaokeQwQ/CheeseWAF/internal/protection/ip"
	"github.com/LaokeQwQ/CheeseWAF/internal/setup"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
	"github.com/LaokeQwQ/CheeseWAF/internal/timekeeper"
	"golang.org/x/crypto/bcrypt"
)

type Handler struct {
	Config                       *config.Config
	ConfigPath                   string
	Store                        storage.Store
	Sink                         storage.LogSink
	Tokens                       *middleware.TokenManager
	Secret                       string
	Auditor                      *middleware.Auditor
	AssistantApprovals           *ai.ApprovalStore
	approvalStoreError           error
	TwoFAState                   *twoFAState
	ClusterIdentity              *identity.MemoryIdentityService
	ClusterDeployTasks           *deploy.TaskManager
	ClusterDeployAuth            *deploy.AuthorizationStore
	ClusterHeartbeats            *cluster.HeartbeatRegistry
	ACMEIssuer                   acme.Issuer
	TimeSync                     TimeSyncService
	LoginCAPTCHAState            *loginCAPTCHAState
	CAPTCHAAssets                captchaassets.Store
	CAPTCHAAssetReferences       *captchaassets.ReferenceManager
	CAPTCHAAssetInitError        error
	captchaAssetRuntime          atomic.Pointer[captchaAssetRuntime]
	behaviorCAPTCHAOnce          sync.Once
	behaviorCAPTCHAState         *botChallengeStore
	loginCAPTCHASecretMu         sync.Mutex
	loginCAPTCHASecret           string
	clusterIdentityMu            sync.Mutex
	clusterDeployTasksMu         sync.Mutex
	clusterDeployAuthMu          sync.Mutex
	clusterDeployPending         map[string]deploy.AuthorizationTarget
	clusterHeartbeatsMu          sync.Mutex
	configMutationMu             sync.RWMutex
	siteMutationMu               sync.Mutex
	managementTokenFlushInterval time.Duration
	configWriteFrozen            bool
	configFreezeReason           string
	userMutationMu               sync.Mutex
	now                          func() time.Time
	StartedAt                    time.Time
	geoipMu                      sync.Mutex
	geoipCacheKey                string
	geoipPolicy                  *protectionip.GeoIPPolicy
	geoipErrorKey                string
	geoipRetryAfter              time.Time
	diskUsageMu                  sync.Mutex
	diskUsageCache               map[string]cachedDirSize
	OnSitesChanged               func([]config.SiteConfig) error
	OnProtectionChanged          func(config.ProtectionConfig) error
	OnAPISecChanged              func(config.APISecConfig) error
	OnBlockPageChanged           func(config.BlockPageConfig) error
	OnTimeSyncChanged            func(config.TimeSyncConfig) error
}

type captchaAssetRuntime struct {
	store      captchaassets.Store
	references *captchaassets.ReferenceManager
	limits     config.CAPTCHAAssetLimits
	config     config.CAPTCHAAssetsConfig
	mu         sync.Mutex
	users      int
	retired    bool
	closed     bool
}

func (r *captchaAssetRuntime) acquire() bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.retired {
		return false
	}
	r.users++
	return true
}

func (r *captchaAssetRuntime) release() {
	if r == nil {
		return
	}
	r.mu.Lock()
	if r.users == 0 {
		r.mu.Unlock()
		return
	}
	r.users--
	closeStore := r.retired && r.users == 0 && !r.closed
	if closeStore {
		r.closed = true
	}
	r.mu.Unlock()
	if closeStore {
		closeCAPTCHAAssetStore(r.store)
	}
}

func (r *captchaAssetRuntime) retire() {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.retired = true
	closeStore := r.users == 0 && !r.closed
	if closeStore {
		r.closed = true
	}
	r.mu.Unlock()
	if closeStore {
		closeCAPTCHAAssetStore(r.store)
	}
}

func closeCAPTCHAAssetStore(store captchaassets.Store) {
	if closer, ok := store.(io.Closer); ok {
		_ = closer.Close()
	}
}

func (h *Handler) nowUTC() time.Time {
	if h != nil && h.now != nil {
		return h.now().UTC()
	}
	return time.Now().UTC()
}

type cachedDirSize struct {
	value     int64
	expiresAt time.Time
	loading   bool
	ready     chan struct{}
}

const (
	defaultJSONBodyLimit       = 1 << 20
	loginCAPTCHAJSONBodyLimit  = 16 << 10
	loginCAPTCHAMaxTokenLength = 8192
	loginCAPTCHAMaxTrackLength = 16384
	loginCAPTCHAMaxFieldLength = 512
	loginCAPTCHAClientCookie   = "cw_captcha_client"
	loginCAPTCHAClientIDBytes  = 24
	loginCAPTCHAClientMaxAge   = 30 * 24 * time.Hour
)

type Options struct {
	Config              *config.Config
	ConfigPath          string
	Store               storage.Store
	Sink                storage.LogSink
	Tokens              *middleware.TokenManager
	Secret              string
	Auditor             *middleware.Auditor
	AssistantApprovals  *ai.ApprovalStore
	ClusterIdentity     *identity.MemoryIdentityService
	ClusterDeployTasks  *deploy.TaskManager
	ClusterDeployAuth   *deploy.AuthorizationStore
	ClusterHeartbeats   *cluster.HeartbeatRegistry
	ACMEIssuer          acme.Issuer
	TimeSync            TimeSyncService
	OnSitesChanged      func([]config.SiteConfig) error
	OnProtectionChanged func(config.ProtectionConfig) error
	OnAPISecChanged     func(config.APISecConfig) error
	OnBlockPageChanged  func(config.BlockPageConfig) error
	OnTimeSyncChanged   func(config.TimeSyncConfig) error
	CAPTCHAAssets       captchaassets.Store
	Clock               timekeeper.Clock
}

var newPersistentApprovalStore = ai.NewPersistentApprovalStore

func New(opts Options) *Handler {
	approvals := opts.AssistantApprovals
	var approvalStoreError error
	if approvals == nil {
		approvals, approvalStoreError = newPersistentApprovalStore(defaultApprovalStorePath(opts.Config))
		if approvals == nil {
			approvals = ai.NewApprovalStore()
		}
	} else if ok, err := approvals.PersistenceHealth(); !ok {
		approvalStoreError = err
	}
	loginSecret := resolveLoginCAPTCHASecret(opts.Secret, opts.Config)
	assetStore, assetRefs, assetErr := initializeCAPTCHAAssets(opts.Config, opts.Secret, opts.CAPTCHAAssets)
	clock := opts.Clock
	if clock == nil {
		clock = timekeeper.SystemClock{}
	}
	now := clock.Now
	h := &Handler{
		Config:                       opts.Config,
		ConfigPath:                   opts.ConfigPath,
		Store:                        opts.Store,
		Sink:                         opts.Sink,
		Tokens:                       opts.Tokens,
		Secret:                       opts.Secret,
		Auditor:                      opts.Auditor,
		AssistantApprovals:           approvals,
		approvalStoreError:           approvalStoreError,
		TwoFAState:                   newTwoFAState(),
		ClusterIdentity:              opts.ClusterIdentity,
		ClusterDeployTasks:           opts.ClusterDeployTasks,
		ClusterDeployAuth:            opts.ClusterDeployAuth,
		clusterDeployPending:         map[string]deploy.AuthorizationTarget{},
		ClusterHeartbeats:            opts.ClusterHeartbeats,
		ACMEIssuer:                   opts.ACMEIssuer,
		TimeSync:                     opts.TimeSync,
		LoginCAPTCHAState:            newLoginCAPTCHAState(),
		CAPTCHAAssets:                assetStore,
		CAPTCHAAssetReferences:       assetRefs,
		CAPTCHAAssetInitError:        assetErr,
		loginCAPTCHASecret:           loginSecret,
		now:                          now,
		StartedAt:                    now().UTC(),
		managementTokenFlushInterval: time.Minute,
		diskUsageCache:               map[string]cachedDirSize{},
		OnSitesChanged:               opts.OnSitesChanged,
		OnProtectionChanged:          opts.OnProtectionChanged,
		OnAPISecChanged:              opts.OnAPISecChanged,
		OnBlockPageChanged:           opts.OnBlockPageChanged,
		OnTimeSyncChanged:            opts.OnTimeSyncChanged,
	}
	if assetStore != nil && assetRefs != nil && opts.Config != nil {
		h.captchaAssetRuntime.Store(&captchaAssetRuntime{store: assetStore, references: assetRefs, limits: opts.Config.CAPTCHAAssets.Limits, config: opts.Config.CAPTCHAAssets})
	}
	return h
}

func initializeCAPTCHAAssets(cfg *config.Config, secret string, injected captchaassets.Store) (captchaassets.Store, *captchaassets.ReferenceManager, error) {
	key := sha256.Sum256([]byte("captcha-assets:" + secret))
	refs, err := captchaassets.NewReferenceManager(key[:])
	if err != nil {
		return nil, nil, err
	}
	if injected != nil {
		return injected, refs, nil
	}
	if cfg == nil {
		return nil, refs, fmt.Errorf("captcha asset configuration is unavailable")
	}
	limits := captchaassets.Limits{MaxImageBytes: cfg.CAPTCHAAssets.Limits.MaxImageBytes, MaxFontBytes: cfg.CAPTCHAAssets.Limits.MaxFontBytes, MaxPixels: cfg.CAPTCHAAssets.Limits.MaxPixels}
	if strings.EqualFold(cfg.CAPTCHAAssets.Backend, "local") {
		store, err := captchaassets.NewLocalStore(cfg.CAPTCHAAssets.Local.Path, limits)
		return store, refs, err
	}
	if strings.EqualFold(cfg.CAPTCHAAssets.Backend, "s3") {
		metadataKey, err := os.ReadFile(strings.TrimSpace(cfg.CAPTCHAAssets.S3.MetadataKeyFile))
		if err != nil {
			return nil, refs, fmt.Errorf("read S3 metadata integrity key: %w", err)
		}
		metadataKey = bytes.TrimSpace(metadataKey)
		if len(metadataKey) < 32 || len(metadataKey) > 4096 {
			return nil, refs, fmt.Errorf("S3 metadata integrity key must contain between 32 and 4096 bytes")
		}
		s3cfg := captchaassets.S3Config{Endpoint: cfg.CAPTCHAAssets.S3.Endpoint, Region: cfg.CAPTCHAAssets.S3.Region, Bucket: cfg.CAPTCHAAssets.S3.Bucket, Prefix: cfg.CAPTCHAAssets.S3.Prefix, PathStyle: cfg.CAPTCHAAssets.S3.PathStyle, UseTLS: cfg.CAPTCHAAssets.S3.UseTLS, AllowPrivateEndpoint: cfg.CAPTCHAAssets.S3.AllowPrivateEndpoint, RequestTimeout: cfg.CAPTCHAAssets.S3.RequestTimeout, MetadataKey: metadataKey}
		client, err := captchaassets.NewHTTPObjectClient(s3cfg, cfg.CAPTCHAAssets.S3.CredentialFile)
		if err != nil {
			return nil, refs, err
		}
		store, err := captchaassets.NewS3Store(s3cfg, client, limits)
		return store, refs, err
	}
	return nil, refs, fmt.Errorf("unsupported captcha asset backend %q", cfg.CAPTCHAAssets.Backend)
}

var initializeCAPTCHAAssetStore = initializeCAPTCHAAssets

func defaultApprovalStorePath(cfg *config.Config) string {
	runtimeDir := ""
	if cfg != nil {
		runtimeDir = strings.TrimSpace(cfg.Setup.RuntimeDir)
	}
	if runtimeDir == "" {
		def := config.Default()
		runtimeDir = def.Setup.RuntimeDir
	}
	return filepath.Join(runtimeDir, "ai_approvals.json")
}

func (h *Handler) notifyProtectionChanged() error {
	if h == nil || h.OnProtectionChanged == nil || h.Config == nil {
		return nil
	}
	return h.OnProtectionChanged(h.Config.Protection)
}

func (h *Handler) notifyProtectionConfigChanged(next config.ProtectionConfig) error {
	if h == nil || h.OnProtectionChanged == nil {
		return nil
	}
	return h.OnProtectionChanged(next)
}

func (h *Handler) notifyAPISecChanged() error {
	if h == nil || h.OnAPISecChanged == nil || h.Config == nil {
		return nil
	}
	return h.OnAPISecChanged(h.Config.APISec)
}

func (h *Handler) notifyAPISecConfigChanged(next config.APISecConfig) error {
	if h == nil || h.OnAPISecChanged == nil {
		return nil
	}
	return h.OnAPISecChanged(next)
}

func (h *Handler) notifyBlockPageChanged() error {
	if h == nil || h.OnBlockPageChanged == nil || h.Config == nil {
		return nil
	}
	return h.OnBlockPageChanged(h.Config.BlockPage)
}

func (h *Handler) notifyBlockPageConfigChanged(next config.BlockPageConfig) error {
	if h == nil || h.OnBlockPageChanged == nil {
		return nil
	}
	return h.OnBlockPageChanged(next)
}

func (h *Handler) Health(w http.ResponseWriter, _ *http.Request) {
	data := map[string]any{"status": "ok", "uptime_seconds": int(time.Since(h.StartedAt).Seconds())}
	approvalHealthy, approvalErr := h.AssistantApprovals.PersistenceHealth()
	if h.approvalStoreError != nil || !approvalHealthy {
		data["status"] = "degraded"
		data["warnings"] = []string{"AI approval persistence is unavailable; modification tools are disabled"}
		data["ai_approval_persistence"] = map[string]any{"healthy": false, "error": fmt.Sprint(approvalErr)}
	} else {
		data["ai_approval_persistence"] = map[string]any{"healthy": true}
	}
	writeData(w, data)
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
	var req dto.CAPTCHAChallengeRequest
	if !decodeOptional(w, r, &req, loginCAPTCHAJSONBodyLimit, "invalid captcha request") {
		return
	}
	mode := loginCaptchaRequestedMode(login.CAPTCHA, req.Mode)
	secret := h.loginCaptchaSecret()
	if secret == "" {
		writeError(w, http.StatusInternalServerError, "CAPTCHA_SECRET_UNAVAILABLE", "captcha signing secret is unavailable")
		return
	}
	owner, peer, ok := h.loginCaptchaQuotaIdentity(w, r)
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "CAPTCHA_CAPACITY_REACHED", "captcha service is temporarily busy")
		return
	}
	clientKey := loginCaptchaClientKey(r) + "\n" + owner
	response := map[string]any{"enabled": true, "mode": mode}
	requiresPoW := loginCAPTCHARequiresPowForMode(login.CAPTCHA, mode)
	proofSlots := 0
	if requiresPoW {
		proofSlots++
	}
	if mode == "slider" {
		proofSlots++
	}
	now := h.nowUTC()
	tracker := h.loginCAPTCHATracker()
	reservation, reserved := tracker.reserveIssuance(owner, peer, proofSlots, now)
	if !reserved {
		writeError(w, http.StatusServiceUnavailable, "CAPTCHA_CAPACITY_REACHED", "captcha service is temporarily busy")
		return
	}
	committed := false
	defer func() {
		if !committed {
			tracker.rollbackIssuance(reservation)
		}
	}()

	proofKeys := make([]string, 0, proofSlots)
	if requiresPoW {
		challenge, err := captcha.NewChallenge(captcha.Options{
			Secret:    secret,
			Purpose:   "admin-login",
			ClientKey: clientKey,
			Path:      "admin-login",
			MaxNumber: loginCAPTCHAPowMaxForMode(login.CAPTCHA, mode),
			TTL:       login.CAPTCHA.TTL,
		})
		if err != nil {
			writeError(w, http.StatusInternalServerError, "CAPTCHA_ERROR", err.Error())
			return
		}
		response["challenge"] = challenge
		proofKeys = append(proofKeys, loginCAPTCHAFingerprint("pow", clientKey, challenge.Signature, challenge.Salt, challenge.Challenge))
	}
	if mode == "slider" {
		slider, err := captcha.NewSliderChallenge(captcha.SliderOptions{
			Secret:    secret,
			Purpose:   "admin-login-slider",
			ClientKey: clientKey,
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
		proofKeys = append(proofKeys, loginCAPTCHAFingerprint("slider", clientKey, slider.Token))
	}
	if err := r.Context().Err(); err != nil {
		return
	}
	now = h.nowUTC()
	if !tracker.stageIssuance(reservation, proofKeys, now.Add(login.CAPTCHA.TTL), now) {
		writeError(w, http.StatusServiceUnavailable, "CAPTCHA_CAPACITY_REACHED", "captcha service is temporarily busy")
		return
	}
	if err := writeDataResult(w, response); err != nil {
		return
	}
	if !tracker.finalizeIssuance(reservation) {
		return
	}
	committed = true
}

func (h *Handler) VerifyLoginCAPTCHA(w http.ResponseWriter, r *http.Request) {
	var payload dto.CAPTCHAPayload
	if !decodeOptional(w, r, &payload, loginCAPTCHAJSONBodyLimit, "invalid captcha payload") {
		return
	}
	if strings.TrimSpace(payload.Username) == "" {
		writeError(w, http.StatusBadRequest, "INVALID_CAPTCHA", "captcha verification failed")
		return
	}
	login := h.loginConfig()
	mode := loginCaptchaPayloadMode(login.CAPTCHA, payload.Mode)
	owner, peer, ok := h.loginCaptchaExistingQuotaIdentity(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "INVALID_CAPTCHA", "captcha verification failed")
		return
	}
	if !h.verifyLoginCAPTCHAProof(r, login, mode, &payload) {
		writeError(w, http.StatusUnauthorized, "INVALID_CAPTCHA", "captcha verification failed")
		return
	}
	clientKey, ok := h.loginCaptchaBoundClientKey(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "INVALID_CAPTCHA", "captcha verification failed")
		return
	}
	receipt, expires, err := captcha.NewReceipt(h.loginCAPTCHAReceiptOptions(clientKey, login.CAPTCHA.TTL, payload.Username), mode)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "CAPTCHA_RECEIPT_ERROR", err.Error())
		return
	}
	if !h.loginCAPTCHATracker().storeReceiptForClient(owner, peer, receipt, expires, h.nowUTC()) {
		writeError(w, http.StatusServiceUnavailable, "CAPTCHA_CAPACITY_REACHED", "captcha service is temporarily busy")
		return
	}
	writeData(w, map[string]any{"valid": true, "receipt": receipt})
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	tracker := h.loginCAPTCHATracker()
	if !tracker.acquireLoginSlot() {
		writeError(w, http.StatusTooManyRequests, "LOGIN_RATE_LIMITED", "too many login attempts")
		return
	}
	defer tracker.releaseLoginSlot()
	var req dto.LoginRequest
	if !decode(w, r, &req) {
		return
	}
	now := h.nowUTC()
	rateLimitKeys := loginRateLimitKeys(r, req.Username)
	if !tracker.loginAttemptAllowed(rateLimitKeys, now) {
		writeError(w, http.StatusTooManyRequests, "LOGIN_RATE_LIMITED", "too many failed login attempts")
		return
	}
	if req.CAPTCHA != nil {
		req.CAPTCHA.Username = req.Username
	}
	if !h.verifyLoginCAPTCHA(r, req.CAPTCHA) {
		tracker.recordLoginFailure(rateLimitKeys, now)
		writeError(w, http.StatusUnauthorized, "INVALID_CAPTCHA", "captcha verification failed")
		return
	}
	h.pruneExpiredSessions(r)
	user, err := h.Store.GetUserByUsername(r.Context(), req.Username)
	if err != nil || user == nil || bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)) != nil {
		tracker.recordLoginFailure(rateLimitKeys, now)
		writeError(w, http.StatusUnauthorized, "INVALID_CREDENTIALS", "invalid username or password")
		return
	}
	if user.TwoFAEnabled {
		if req.TOTPCode == "" {
			tracker.recordLoginFailure(rateLimitKeys, now)
			writeError(w, http.StatusUnauthorized, "TWO_FA_REQUIRED", "two-factor code required")
			return
		}
		if !verifyTOTP(user.TwoFASecret, req.TOTPCode, h.nowUTC()) {
			tracker.recordLoginFailure(rateLimitKeys, now)
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
	tracker.clearLoginFailures(rateLimitKeys, now)
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
	mode := loginCaptchaPayloadMode(login.CAPTCHA, payload.Mode)
	if payload.Receipt != "" {
		return h.consumeLoginCAPTCHAReceipt(r, login, mode, payload.Receipt, payload.Username)
	}
	if mode == "slider" {
		return false
	}
	return h.verifyLoginCAPTCHAProof(r, login, mode, payload)
}

func (h *Handler) verifyLoginCAPTCHAProof(r *http.Request, login config.ConsoleLoginConfig, mode string, payload *dto.CAPTCHAPayload) bool {
	if payload == nil {
		return false
	}
	secret := h.loginCaptchaSecret()
	if secret == "" {
		return false
	}
	if !loginCAPTCHAPayloadSizeAllowed(payload) {
		return false
	}
	clientKey, ok := h.loginCaptchaBoundClientKey(r)
	if !ok {
		return false
	}
	if mode == "slider" {
		if payload.Slider == nil {
			return false
		}
		if strings.TrimSpace(payload.Slider.Track) == "" {
			return false
		}
		now := h.nowUTC()
		proofKey := loginCAPTCHAFingerprint("slider", clientKey, payload.Slider.Token)
		tracker := h.loginCAPTCHATracker()
		proofKeys := []string{proofKey}
		if loginCAPTCHARequiresPowForMode(login.CAPTCHA, mode) {
			proofKeys = append(proofKeys, loginCAPTCHAFingerprint("pow", clientKey, payload.Signature, payload.Salt, payload.Challenge))
		}
		if !tracker.reserveProofs(proofKeys, now) {
			return false
		}
		success := false
		defer func() { tracker.finishProofs(proofKeys, success, h.nowUTC()) }()
		if !captcha.VerifySlider(captcha.SliderOptions{
			Secret:    secret,
			Purpose:   "admin-login-slider",
			ClientKey: clientKey,
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
			Track:  payload.Slider.Track,
		}) {
			return false
		}
		if !loginCAPTCHARequiresPowForMode(login.CAPTCHA, mode) {
			success = true
			return true
		}
		if !verifyLoginCAPTCHAPow(clientKey, secret, login.CAPTCHA, mode, payload) {
			return false
		}
		success = true
		return true
	}
	now := h.nowUTC()
	proofKey := loginCAPTCHAFingerprint("pow", clientKey, payload.Signature, payload.Salt, payload.Challenge)
	tracker := h.loginCAPTCHATracker()
	proofKeys := []string{proofKey}
	if !tracker.reserveProofs(proofKeys, now) {
		return false
	}
	success := false
	defer func() { tracker.finishProofs(proofKeys, success, h.nowUTC()) }()
	if !verifyLoginCAPTCHAPow(clientKey, secret, login.CAPTCHA, mode, payload) {
		return false
	}
	success = true
	return true
}

func loginCAPTCHAPayloadSizeAllowed(payload *dto.CAPTCHAPayload) bool {
	if payload == nil || len(payload.Algorithm) > loginCAPTCHAMaxFieldLength || len(payload.Challenge) > loginCAPTCHAMaxFieldLength ||
		len(payload.Salt) > loginCAPTCHAMaxFieldLength || len(payload.Signature) > loginCAPTCHAMaxFieldLength || len(payload.Receipt) > loginCAPTCHAMaxTokenLength {
		return false
	}
	if payload.Slider == nil {
		return true
	}
	return len(payload.Slider.Token) <= loginCAPTCHAMaxTokenLength && len(payload.Slider.Track) <= loginCAPTCHAMaxTrackLength
}

func verifyLoginCAPTCHAPow(clientKey, secret string, cfg config.LoginCAPTCHAConfig, mode string, payload *dto.CAPTCHAPayload) bool {
	return captcha.Verify(captcha.Options{
		Secret:    secret,
		Purpose:   "admin-login",
		ClientKey: clientKey,
		Path:      "admin-login",
		MaxNumber: loginCAPTCHAPowMaxForMode(cfg, mode),
		TTL:       cfg.TTL,
	}, captcha.Payload{
		Algorithm: payload.Algorithm,
		Challenge: payload.Challenge,
		Number:    payload.Number,
		Salt:      payload.Salt,
		Signature: payload.Signature,
	})
}

func (h *Handler) consumeLoginCAPTCHAReceipt(r *http.Request, login config.ConsoleLoginConfig, mode string, receipt, username string) bool {
	owner, peer, ok := h.loginCaptchaExistingQuotaIdentity(r)
	if !ok {
		return false
	}
	clientKey := loginCaptchaClientKey(r) + "\n" + owner
	if !captcha.VerifyReceipt(h.loginCAPTCHAReceiptOptions(clientKey, login.CAPTCHA.TTL, username), receipt, mode) {
		return false
	}
	return h.loginCAPTCHATracker().consumeReceiptForClient(owner, peer, receipt, h.nowUTC())
}

func (h *Handler) loginCAPTCHAReceiptOptions(clientKey string, ttl time.Duration, username string) captcha.ReceiptOptions {
	return captcha.ReceiptOptions{
		Secret:    h.loginCaptchaSecret(),
		Purpose:   "admin-login-receipt",
		ClientKey: clientKey,
		Path:      "admin-login",
		Subject:   username,
		TTL:       ttl,
	}
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
	return loginCAPTCHAPowMaxForMode(cfg, loginCaptchaMode(cfg))
}

func loginCAPTCHAPowMaxForMode(cfg config.LoginCAPTCHAConfig, mode string) int {
	maxNumber := cfg.MaxNumber
	if strings.ToLower(strings.TrimSpace(mode)) == "slider" && cfg.Slider.PowEnabled && cfg.Slider.PowMaxNumber > 0 && cfg.Slider.PowMaxNumber < maxNumber {
		maxNumber = cfg.Slider.PowMaxNumber
	}
	if maxNumber <= 0 {
		return 75000
	}
	return maxNumber
}

func loginCAPTCHARequiresPow(cfg config.LoginCAPTCHAConfig) bool {
	return loginCAPTCHARequiresPowForMode(cfg, loginCaptchaMode(cfg))
}

func loginCAPTCHARequiresPowForMode(cfg config.LoginCAPTCHAConfig, mode string) bool {
	if strings.ToLower(strings.TrimSpace(mode)) == "slider" {
		return cfg.Slider.PowEnabled
	}
	return true
}

func loginCaptchaRequestedMode(cfg config.LoginCAPTCHAConfig, requested string) string {
	return loginCaptchaEffectiveMode(cfg, requested)
}

func loginCaptchaPayloadMode(cfg config.LoginCAPTCHAConfig, requested string) string {
	return loginCaptchaEffectiveMode(cfg, requested)
}

func loginCaptchaEffectiveMode(cfg config.LoginCAPTCHAConfig, requested string) string {
	configured := loginCaptchaMode(cfg)
	requested = strings.ToLower(strings.TrimSpace(requested))
	// Mobile clients may select the server-supported PoW fallback when the
	// configured desktop flow is a slider. A client can never downgrade a
	// configured PoW flow to a slider or select an unknown mode.
	if configured == "slider" && requested == "pow" {
		return "pow"
	}
	return configured
}

func (h *Handler) loginCaptchaSecret() string {
	if h == nil {
		return resolveLoginCAPTCHASecret("", nil)
	}
	h.loginCAPTCHASecretMu.Lock()
	defer h.loginCAPTCHASecretMu.Unlock()
	if h.loginCAPTCHASecret == "" {
		h.loginCAPTCHASecret = resolveLoginCAPTCHASecret(h.Secret, h.Config)
	}
	return h.loginCAPTCHASecret
}

func resolveLoginCAPTCHASecret(authSecret string, cfg *config.Config) string {
	if authSecret != "" {
		return authSecret
	}
	if cfg != nil && !config.IsWeakBotSecret(cfg.Protection.Bot.Secret) {
		return cfg.Protection.Bot.Secret
	}
	if secret, err := config.GenerateSecret(); err == nil {
		return secret
	}
	return ""
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

func (h *Handler) loginCaptchaBoundClientKey(r *http.Request) (string, bool) {
	owner, _, ok := h.loginCaptchaExistingQuotaIdentity(r)
	if !ok {
		return "", false
	}
	return loginCaptchaClientKey(r) + "\n" + owner, true
}

func (h *Handler) loginCaptchaQuotaIdentity(w http.ResponseWriter, r *http.Request) (string, string, bool) {
	peer := socketPeerIP(r)
	if owner, _, ok := h.loginCaptchaExistingQuotaIdentity(r); ok {
		return owner, peer, true
	}
	id := make([]byte, loginCAPTCHAClientIDBytes)
	if _, err := rand.Read(id); err != nil {
		return "", peer, false
	}
	rawID := base64.RawURLEncoding.EncodeToString(id)
	value := h.signLoginCaptchaClientID(rawID)
	if value == "" {
		return "", peer, false
	}
	http.SetCookie(w, &http.Cookie{
		Name:     loginCAPTCHAClientCookie,
		Value:    value,
		Path:     "/",
		MaxAge:   int(loginCAPTCHAClientMaxAge / time.Second),
		Expires:  h.nowUTC().Add(loginCAPTCHAClientMaxAge),
		HttpOnly: true,
		Secure:   loginCaptchaCookieSecure(r),
		SameSite: http.SameSiteStrictMode,
	})
	return "client:" + loginCAPTCHAFingerprint(rawID), peer, true
}

// loginCaptchaCookieSecure sets Secure when the request is HTTPS or terminated TLS
// is indicated via X-Forwarded-Proto (admin console behind a reverse proxy).
func loginCaptchaCookieSecure(r *http.Request) bool {
	if r == nil {
		return false
	}
	if r.TLS != nil {
		return true
	}
	proto := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0])
	return strings.EqualFold(proto, "https")
}

func (h *Handler) loginCaptchaExistingQuotaIdentity(r *http.Request) (string, string, bool) {
	peer := socketPeerIP(r)
	if h == nil || r == nil {
		return "", peer, false
	}
	cookie, err := r.Cookie(loginCAPTCHAClientCookie)
	if err != nil {
		return "", peer, false
	}
	rawID, ok := h.verifyLoginCaptchaClientID(cookie.Value)
	if !ok {
		return "", peer, false
	}
	return "client:" + loginCAPTCHAFingerprint(rawID), peer, true
}

func (h *Handler) signLoginCaptchaClientID(rawID string) string {
	secret := h.loginCaptchaSecret()
	if secret == "" || rawID == "" {
		return ""
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte("login-captcha-client\x00" + rawID))
	return rawID + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (h *Handler) verifyLoginCaptchaClientID(value string) (string, bool) {
	rawID, signature, ok := strings.Cut(strings.TrimSpace(value), ".")
	if !ok || rawID == "" || signature == "" {
		return "", false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(rawID)
	if err != nil || len(decoded) != loginCAPTCHAClientIDBytes {
		return "", false
	}
	expected := h.signLoginCaptchaClientID(rawID)
	return rawID, hmac.Equal([]byte(expected), []byte(value))
}

func loginRateLimitKeys(r *http.Request, username string) []string {
	peer := socketPeerIP(r)
	client := trustedLoginClientIP(r, peer)
	if client == "" {
		client = peer
	}
	username = strings.ToLower(strings.TrimSpace(username))
	keys := []string{"peer:" + peer}
	if client != peer {
		keys = append(keys, "client:"+client)
	}
	if username != "" {
		keys = append(keys, "account-source:"+loginCAPTCHAFingerprint(username, client))
	}
	return keys
}

func socketPeerIP(r *http.Request) string {
	if r == nil {
		return "unknown"
	}
	host := strings.TrimSpace(r.RemoteAddr)
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		host = parsedHost
	}
	if net.ParseIP(host) == nil {
		return "unknown"
	}
	return host
}

func trustedLoginClientIP(r *http.Request, peer string) string {
	// Only honor X-Forwarded-For when the socket peer is loopback (local reverse
	// proxy on the same host). Private non-loopback peers can spoof XFF on LAN
	// or cloud VPCs, so ignore XFF and rate-limit by peer alone.
	peerIP := net.ParseIP(peer)
	if r == nil || peerIP == nil || !peerIP.IsLoopback() {
		return ""
	}
	for _, part := range strings.Split(r.Header.Get("X-Forwarded-For"), ",") {
		candidate := strings.TrimSpace(part)
		if ip := net.ParseIP(candidate); ip != nil {
			return ip.String()
		}
	}
	return ""
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
	cutoff := h.nowUTC().Add(-24 * time.Hour)
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
	r.Body = http.MaxBytesReader(w, r.Body, defaultJSONBodyLimit)
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(dest); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", err.Error())
		return false
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			err = errors.New("request body must contain exactly one JSON document")
		}
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", err.Error())
		return false
	}
	return true
}

func decodeOptional(w http.ResponseWriter, r *http.Request, dest any, limit int64, invalidMessage string) bool {
	if r.Body == nil {
		return true
	}
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(dest); err != nil {
		if err == io.EOF {
			return true
		}
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", invalidMessage)
		return false
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		message := invalidMessage
		if err == nil {
			message = "request body must contain exactly one JSON document"
		}
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", message)
		return false
	}
	return true
}

func writeData(w http.ResponseWriter, data any) {
	_ = writeDataResult(w, data)
}

func writeDataResult(w http.ResponseWriter, data any) error {
	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(dto.Response{Data: data})
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeErrorWithTraceID(w, status, code, message, blockpage.NewTraceID())
}

func writeErrorWithTraceID(w http.ResponseWriter, status int, code, message, traceID string) {
	if traceID == "" {
		traceID = blockpage.NewTraceID()
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-CheeseWAF-Trace-ID", traceID)
	w.Header().Set("X-CheeseWAF-Event-ID", traceID)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(dto.Response{Error: &dto.APIError{Code: code, Message: message, TraceID: traceID, EventID: traceID}})
}
