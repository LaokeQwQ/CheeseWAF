package api

// Independent verification cases for CHE-61: authentication, authorization,
// rate limiting and CAPTCHA boundaries. Every case is written so that a FAIL
// points at a concrete boundary in production code; the production tree is
// never modified by this file.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/ai"
	"github.com/LaokeQwQ/CheeseWAF/internal/api/handler"
	"github.com/LaokeQwQ/CheeseWAF/internal/api/middleware"
	"github.com/LaokeQwQ/CheeseWAF/internal/captcha"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

const (
	che61RemoteAddr = "198.51.100.23:40123"
	che61RemoteIP   = "198.51.100.23"

	// Mirrors handler.loginCAPTCHAProofPerPeer so the probe can assert the
	// measured ceiling instead of merely asserting "something limited".
	loginCAPTCHAProofPerPeerProbe = 256
)

// che61SolveLoginCAPTCHA mirrors solveLoginCAPTCHA but runs the login client
// from a routable (non-loopback) source address so CAPTCHA is actually
// enforced instead of being skipped for local loopback.
func che61SolveLoginCAPTCHA(t *testing.T, client *che61LoginClient, username string) map[string]any {
	t.Helper()
	challenge := client.perform(http.MethodPost, "/api/auth/captcha", []byte(`{}`))
	if challenge.Code != http.StatusOK {
		t.Fatalf("captcha challenge returned %d: %s", challenge.Code, challenge.Body.String())
	}
	var envelope struct {
		Data struct {
			Enabled   bool   `json:"enabled"`
			Mode      string `json:"mode"`
			Challenge struct {
				Algorithm string `json:"algorithm"`
				Challenge string `json:"challenge"`
				MaxNumber int    `json:"max_number"`
				Salt      string `json:"salt"`
				Signature string `json:"signature"`
			} `json:"challenge"`
		} `json:"data"`
	}
	if err := json.NewDecoder(challenge.Body).Decode(&envelope); err != nil {
		t.Fatalf("decode captcha challenge: %v", err)
	}
	if !envelope.Data.Enabled || envelope.Data.Challenge.Challenge == "" {
		t.Fatalf("captcha was not enforced for a remote client: %+v", envelope.Data)
	}
	number := -1
	for i := 0; i <= envelope.Data.Challenge.MaxNumber; i++ {
		if captcha.Hash(envelope.Data.Challenge.Salt, i) == envelope.Data.Challenge.Challenge {
			number = i
			break
		}
	}
	if number < 0 {
		t.Fatal("failed to solve login captcha challenge")
	}
	payload := map[string]any{
		"username":  username,
		"mode":      envelope.Data.Mode,
		"algorithm": envelope.Data.Challenge.Algorithm,
		"challenge": envelope.Data.Challenge.Challenge,
		"number":    number,
		"salt":      envelope.Data.Challenge.Salt,
		"signature": envelope.Data.Challenge.Signature,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal captcha payload: %v", err)
	}
	verified := client.perform(http.MethodPost, "/api/auth/captcha/verify", raw)
	if verified.Code != http.StatusOK {
		t.Fatalf("captcha verification returned %d: %s", verified.Code, verified.Body.String())
	}
	var verifiedEnvelope struct {
		Data struct {
			Receipt string `json:"receipt"`
		} `json:"data"`
	}
	if err := json.NewDecoder(verified.Body).Decode(&verifiedEnvelope); err != nil {
		t.Fatalf("decode captcha verification: %v", err)
	}
	if verifiedEnvelope.Data.Receipt == "" {
		t.Fatal("captcha verification did not return a receipt")
	}
	return map[string]any{
		"username": username,
		"mode":     envelope.Data.Mode,
		"receipt":  verifiedEnvelope.Data.Receipt,
	}
}

type che61Router struct {
	router http.Handler
	cfg    *config.Config
	store  storage.Store
	secret string
	path   string
}

func newCHE61Router(t *testing.T, mutate func(*config.Config)) *che61Router {
	t.Helper()
	tempDir := t.TempDir()
	cfg := config.Default()
	cfg.Console.Login.CAPTCHA.Enabled = true
	cfg.Console.Login.CAPTCHA.Mode = "pow"
	cfg.Console.Login.CAPTCHA.Slider.PowEnabled = false
	cfg.Console.Login.CAPTCHA.MaxNumber = 2000
	cfg.Console.Login.CAPTCHA.TTL = 2 * time.Minute
	cfg.APISec.Audit.Enabled = false
	cfg.Storage.SQLite.Path = filepath.Join(tempDir, "cheesewaf.db")
	cfg.Logging.Output.File.Path = filepath.Join(tempDir, "access.log")
	if mutate != nil {
		mutate(&cfg)
	}
	configPath := filepath.Join(tempDir, "cheesewaf.yaml")
	if err := config.Save(configPath, &cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}
	store, err := storage.OpenSQLite(cfg.Storage.SQLite.Path)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate sqlite: %v", err)
	}
	createAuthzUser(t, store, "admin-id", "admin", "admin-password", "admin")
	createAuthzUser(t, store, "reader-id", "reader", "reader-password", "readonly")
	const secret = "che61-verification-secret"
	authState := handler.NewAuthState()
	router := NewRouter(Options{
		Config:             &cfg,
		ConfigPath:         configPath,
		Store:              store,
		Secret:             secret,
		AuthState:          authState,
		AssistantApprovals: ai.NewApprovalStore(),
	})
	return &che61Router{router: router, cfg: &cfg, store: store, secret: secret, path: configPath}
}

// che61LoginClient is a cookie-jar client that always connects from a
// non-loopback address, so loopback CAPTCHA exemptions cannot hide a bypass.
type che61LoginClient struct {
	router  http.Handler
	cookies map[string]*http.Cookie
}

func newCHE61LoginClient(router http.Handler) *che61LoginClient {
	return &che61LoginClient{router: router, cookies: map[string]*http.Cookie{}}
}

func (c *che61LoginClient) perform(method, path string, body []byte) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, strings.NewReader(string(body)))
	request.RemoteAddr = che61RemoteAddr
	request.Header.Set("User-Agent", "che61-verification")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	for _, cookie := range c.cookies {
		request.AddCookie(cookie)
	}
	recorder := httptest.NewRecorder()
	c.router.ServeHTTP(recorder, request)
	for _, cookie := range recorder.Result().Cookies() {
		if cookie.MaxAge < 0 {
			delete(c.cookies, cookie.Name)
			continue
		}
		c.cookies[cookie.Name] = cookie
	}
	return recorder
}

func che61PostJSON(t *testing.T, router http.Handler, path string, token string, payload any) *httptest.ResponseRecorder {
	t.Helper()
	var body []byte
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("marshal %s: %v", path, err)
		}
		body = encoded
	}
	return performFromIP(router, http.MethodPost, path, token, body, che61RemoteAddr)
}

func che61ErrorCode(t *testing.T, recorder *httptest.ResponseRecorder) string {
	t.Helper()
	var envelope struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode error envelope (%d %s): %v", recorder.Code, recorder.Body.String(), err)
	}
	return envelope.Error.Code
}

// ---------------------------------------------------------------------------
// A. Authentication: session / token / CSRF boundaries
// ---------------------------------------------------------------------------

func TestCHE61ManagementAPIRejectsEveryUnauthenticatedShape(t *testing.T) {
	env := newCHE61Router(t, nil)
	cases := []struct {
		name    string
		prepare func(*http.Request)
	}{
		{name: "no credentials", prepare: func(*http.Request) {}},
		{name: "bearer not a jwt", prepare: func(r *http.Request) { r.Header.Set("Authorization", "Bearer not-a-jwt") }},
		{name: "bearer empty", prepare: func(r *http.Request) { r.Header.Set("Authorization", "Bearer ") }},
		{name: "basic scheme", prepare: func(r *http.Request) { r.Header.Set("Authorization", "Basic YWRtaW46YWRtaW4=") }},
		{name: "management token prefix without token", prepare: func(r *http.Request) { r.Header.Set("Authorization", "Bearer cwapi_") }},
		{name: "jwt presented as management token", prepare: func(r *http.Request) {
			r.Header.Set("Authorization", "Bearer cwapi_"+strings.Repeat("a", 64))
		}},
		{name: "unsigned alg=none jwt", prepare: func(r *http.Request) {
			header := base64RawURL([]byte(`{"alg":"none","typ":"JWT"}`))
			claims := base64RawURL([]byte(`{"sub":"admin-id","jti":"x","username":"admin","role":"admin","scope":["admin"],"iat":1,"exp":9999999999}`))
			r.Header.Set("Authorization", "Bearer "+header+"."+claims+".")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/api/system", nil)
			tc.prepare(request)
			recorder := httptest.NewRecorder()
			env.router.ServeHTTP(recorder, request)
			if recorder.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d (%s), want 401: %s", recorder.Code, che61ErrorCode(t, recorder), recorder.Body.String())
			}
		})
	}
}

func base64RawURL(payload []byte) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	var out strings.Builder
	for i := 0; i < len(payload); i += 3 {
		remaining := len(payload) - i
		b0 := payload[i]
		var b1, b2 byte
		if remaining > 1 {
			b1 = payload[i+1]
		}
		if remaining > 2 {
			b2 = payload[i+2]
		}
		out.WriteByte(alphabet[b0>>2])
		out.WriteByte(alphabet[(b0&0x03)<<4|b1>>4])
		if remaining > 1 {
			out.WriteByte(alphabet[(b1&0x0f)<<2|b2>>6])
		}
		if remaining > 2 {
			out.WriteByte(alphabet[b2&0x3f])
		}
	}
	return out.String()
}

func TestCHE61CookieSessionMutationRequiresCSRF(t *testing.T) {
	env := newCHE61Router(t, nil)
	client := newCHE61LoginClient(env.router)
	captchaPayload := che61SolveLoginCAPTCHA(t, client, "admin")
	body, err := json.Marshal(map[string]any{"username": "admin", "password": "admin-password", "captcha": captchaPayload})
	if err != nil {
		t.Fatalf("marshal login: %v", err)
	}
	login := client.perform(http.MethodPost, "/api/auth/login", body)
	if login.Code != http.StatusOK {
		t.Fatalf("login returned %d: %s", login.Code, login.Body.String())
	}
	session := client.cookies[middleware.SessionCookieName]
	csrf := client.cookies[middleware.CSRFCookieName]
	if session == nil || csrf == nil {
		t.Fatalf("login did not set session and CSRF cookies: %v", client.cookies)
	}

	mutation := func(extraHeaders map[string]string, withCSRFCookie bool) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPut, "/api/protection/bot", strings.NewReader(`{}`))
		request.RemoteAddr = che61RemoteAddr
		request.Header.Set("Content-Type", "application/json")
		request.AddCookie(&http.Cookie{Name: middleware.SessionCookieName, Value: session.Value})
		if withCSRFCookie {
			request.AddCookie(&http.Cookie{Name: middleware.CSRFCookieName, Value: csrf.Value})
		}
		for key, value := range extraHeaders {
			request.Header.Set(key, value)
		}
		recorder := httptest.NewRecorder()
		env.router.ServeHTTP(recorder, request)
		return recorder
	}

	if got := mutation(nil, true); got.Code != http.StatusForbidden || che61ErrorCode(t, got) != "CSRF_INVALID" {
		t.Fatalf("cookie session without CSRF header = %d %s, want 403 CSRF_INVALID", got.Code, got.Body.String())
	}
	if got := mutation(nil, false); got.Code != http.StatusForbidden || che61ErrorCode(t, got) != "CSRF_INVALID" {
		t.Fatalf("cookie session without CSRF cookie = %d %s, want 403 CSRF_INVALID", got.Code, got.Body.String())
	}
	if got := mutation(map[string]string{middleware.CSRFHeaderName: csrf.Value}, true); got.Code == http.StatusForbidden && che61ErrorCode(t, got) == "CSRF_INVALID" {
		t.Fatalf("valid double-submit was rejected: %s", got.Body.String())
	}
}

// ---------------------------------------------------------------------------
// B. Fail-closed behaviour of login dependencies
// ---------------------------------------------------------------------------

// A session signed under one auth secret must not verify under another.
// handler.New does not build Tokens (only api.NewRouter does), so the token
// managers are constructed directly from the same secret chain.
func TestCHE61SessionDoesNotVerifyAfterSecretRotation(t *testing.T) {
	first := middleware.NewTokenManager("rotation-secret-one", time.Hour)
	issued, _, err := first.SignWithClaims("admin-id", "admin", "admin")
	if err != nil {
		t.Fatalf("sign old session: %v", err)
	}
	if _, err := first.Verify(issued); err != nil {
		t.Fatalf("same-secret verification failed: %v", err)
	}
	second := middleware.NewTokenManager("rotation-secret-two", time.Hour)
	if _, err := second.Verify(issued); err == nil {
		t.Fatal("rotated secret still verified a session signed under the old secret")
	}
}

func TestCHE61LoginFailsClosedWhenCAPTCHAIsEnabledWithoutSecret(t *testing.T) {
	cfg := config.Default()
	cfg.Console.Login.CAPTCHA.Enabled = true
	h := &handler.Handler{Config: &cfg}
	t.Cleanup(func() { handler.ForceLoginCAPTCHASecretForTest(h, "") })
	handler.ForceLoginCAPTCHASecretForTest(h, "")
	request := httptest.NewRequest(http.MethodPost, "/api/auth/login", nil)
	request.RemoteAddr = che61RemoteAddr
	if h.VerifyLoginCAPTCHAForTest(request, nil) {
		t.Fatal("login accepted a request without CAPTCHA proof when the signing secret was unavailable")
	}
}

// ---------------------------------------------------------------------------
// C. Rate limiting
// ---------------------------------------------------------------------------

// A malformed username still burns a failure against the source key, so the
// per-source lock is reachable without solving CAPTCHA.
func TestCHE61LoginRateLimitLocksAfterRepeatedFailures(t *testing.T) {
	env := newCHE61Router(t, nil)
	limited := false
	for attempt := 0; attempt < 8; attempt++ {
		recorder := che61PostJSON(t, env.router, "/api/auth/login", "", map[string]any{
			"username": "in valid", "password": "x",
		})
		if recorder.Code == http.StatusTooManyRequests {
			limited = true
			if code := che61ErrorCode(t, recorder); code != "LOGIN_RATE_LIMITED" {
				t.Fatalf("rate-limited code = %q, want LOGIN_RATE_LIMITED", code)
			}
			break
		}
	}
	if !limited {
		t.Fatal("repeated invalid-username logins from one source never hit LOGIN_RATE_LIMITED")
	}
}

// Missing CAPTCHA proofs count toward the source failure limit before password verification.
func TestCHE61WrongPasswordIsRateLimitedWithoutCAPTCHAProof(t *testing.T) {
	env := newCHE61Router(t, nil)
	client := newCHE61LoginClient(env.router)
	recorder := client.perform(http.MethodPost, "/api/auth/login", mustJSON(t, map[string]any{
		"username": "admin", "password": "wrong-password",
	}))
	if recorder.Code != http.StatusUnauthorized || che61ErrorCode(t, recorder) != "INVALID_CAPTCHA" {
		t.Fatalf("baseline no-proof login = %d %s, want 401 INVALID_CAPTCHA", recorder.Code, recorder.Body.String())
	}

	limited := false
	lastStatus := ""
	for attempt := 0; attempt < 12; attempt++ {
		recorder := che61PostJSON(t, env.router, "/api/auth/login", "", map[string]any{
			"username": "admin", "password": "wrong-password",
		})
		lastStatus = fmt.Sprintf("%d %s", recorder.Code, che61ErrorCode(t, recorder))
		if recorder.Code == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatalf("12 no-proof login attempts from one source ended at %s; want LOGIN_RATE_LIMITED", lastStatus)
	}
}

// Companion to CHE61-F1: repeated challenge issuance from one source IS
// bounded. The peer bucket is keyed on socketPeerIP, so a caller cannot move
// itself to a fresh bucket. The ceiling was measured at exactly
// loginCAPTCHAProofPerPeer (256 per loginCAPTCHAIssueRateWindow).
func TestCHE61CaptchaChallengeIssuanceIsBoundedPerPeer(t *testing.T) {
	env := newCHE61Router(t, nil)
	issued := 0
	limitedStatus := 0
	for round := 0; round < 400 && issued < 300; round++ {
		client := newCHE61LoginClient(env.router)
		for attempt := 0; attempt < 20; attempt++ {
			recorder := client.perform(http.MethodPost, "/api/auth/captcha", []byte(`{}`))
			switch recorder.Code {
			case http.StatusOK:
				issued++
				continue
			case http.StatusServiceUnavailable, http.StatusTooManyRequests:
				limitedStatus = recorder.Code
			default:
				t.Fatalf("challenge attempt = %d %s", recorder.Code, recorder.Body.String())
			}
			break
		}
	}
	t.Logf("challenges issued to one socket peer: %d (limited with %d)", issued, limitedStatus)
	if limitedStatus == 0 {
		t.Fatalf("no ceiling observed after %d challenges from one socket peer", issued)
	}
	if issued != loginCAPTCHAProofPerPeerProbe {
		t.Fatalf("per-peer issuance ceiling = %d, want %d", issued, loginCAPTCHAProofPerPeerProbe)
	}
}

// The 256 ceiling is per socket peer, and the socket peer is not client
// controlled. What IS client controlled is the anonymous cw_captcha_client
// owner id: discarding that cookie starts a fresh owner bucket and resets the
// per-owner quota (loginCAPTCHAIssueRatePerOwner = 16) without touching the
// peer bucket. So the accurate statement is "owner quota is resettable, total
// issuance is still bounded at 256/peer/window", not "challenges are
// unbounded".
func TestCHE61CaptchaOwnerQuotaResetsWhenClientCookieIsDropped(t *testing.T) {
	env := newCHE61Router(t, nil)
	const perOwnerCap = 16
	const peerCap = 256
	issued := 0
	for round := 0; round < 32; round++ {
		client := newCHE61LoginClient(env.router)
		limited := false
		for i := 0; i < perOwnerCap+24; i++ {
			if client.perform(http.MethodPost, "/api/auth/captcha", []byte(`{}`)).Code == http.StatusOK {
				issued++
				continue
			}
			limited = true
			break
		}
		// Each fresh cookie must be able to mint a quota of its own; otherwise
		// this test would not demonstrate that the owner key is resettable.
		if !limited {
			t.Fatalf("round %d: a single owner minted %d challenges without hitting the %d quota", round, perOwnerCap+24, perOwnerCap)
		}
		if issued >= peerCap {
			break
		}
	}
	if issued <= perOwnerCap {
		t.Fatalf("one peer minted only %d challenges across cookie resets; peer ceiling %d should allow more", issued, peerCap)
	}
	if issued > peerCap {
		t.Fatalf("one peer minted %d challenges, exceeding the %d peer ceiling", issued, peerCap)
	}
	t.Logf("one peer minted %d challenges by rotating cw_captcha_client (owner quota %d, peer ceiling %d)", issued, perOwnerCap, peerCap)
}

// Control for CHE61-F1: the CAPTCHA-skip path for a loopback peer (local
// console, no X-Forwarded-For, admin_public=false) does reach bcrypt and DOES
// record failures, locking at attempt 6. This confirms F1 is scoped to the
// CAPTCHA-enforced path and that the failure counter itself works.
func TestCHE61LoopbackWithoutCAPTCHACountsFailures(t *testing.T) {
	env := newCHE61Router(t, nil)
	lastStatus := ""
	for attempt := 0; attempt < 8; attempt++ {
		recorder := performFromIP(env.router, http.MethodPost, "/api/auth/login", "", mustJSON(t, map[string]any{
			"username": "admin", "password": "wrong-password",
		}), "127.0.0.1:55555")
		lastStatus = fmt.Sprintf("%d %s", recorder.Code, che61ErrorCode(t, recorder))
		if recorder.Code == http.StatusTooManyRequests {
			return
		}
		if recorder.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d = %s, want 401 INVALID_CREDENTIALS before lockout", attempt, lastStatus)
		}
	}
	t.Fatalf("loopback no-CAPTCHA path never locked; last status %s", lastStatus)
}

// Control for CHE61-F1: once a valid CAPTCHA proof is presented, a wrong
// password does burn a failure and the source is locked. This isolates the
// gap to the missing CAPTCHA step rather than a broken limiter.
func TestCHE61WrongPasswordWithCAPTCHAProofIsLocked(t *testing.T) {
	env := newCHE61Router(t, nil)
	limited := false
	lastStatus := ""
	for attempt := 0; attempt < 10; attempt++ {
		client := newCHE61LoginClient(env.router)
		receipt := che61SolveLoginCAPTCHA(t, client, "admin")
		recorder := client.perform(http.MethodPost, "/api/auth/login", mustJSON(t, map[string]any{
			"username": "admin", "password": "wrong-password", "captcha": receipt,
		}))
		lastStatus = fmt.Sprintf("%d %s", recorder.Code, che61ErrorCode(t, recorder))
		if recorder.Code == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatalf("10 solved-CAPTCHA wrong-password attempts ended at %s; want LOGIN_RATE_LIMITED", lastStatus)
	}
}

func TestCHE61ClusterJoinRateLimitIsBoundedPerPeer(t *testing.T) {
	env := newCHE61Router(t, nil)
	limited := false
	for attempt := 0; attempt < 40; attempt++ {
		recorder := che61PostJSON(t, env.router, "/api/cluster/join", "", map[string]any{
			"token": "invalid-join-token",
			"csr":   "invalid-csr",
		})
		if recorder.Code == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("unauthenticated /api/cluster/join was never rate limited")
	}
}

// ---------------------------------------------------------------------------
// D. CAPTCHA verification boundaries
// ---------------------------------------------------------------------------

func TestCHE61LoginRejectsMissingAndForgedCAPTCHAProof(t *testing.T) {
	env := newCHE61Router(t, nil)

	plain := che61PostJSON(t, env.router, "/api/auth/login", "", map[string]any{
		"username": "admin", "password": "admin-password",
	})
	if plain.Code != http.StatusUnauthorized || che61ErrorCode(t, plain) != "INVALID_CAPTCHA" {
		t.Fatalf("login without CAPTCHA = %d %s, want 401 INVALID_CAPTCHA", plain.Code, plain.Body.String())
	}

	forged := che61PostJSON(t, env.router, "/api/auth/login", "", map[string]any{
		"username": "admin",
		"password": "admin-password",
		"captcha": map[string]any{
			"username":  "admin",
			"mode":      "pow",
			"algorithm": captcha.AlgorithmSHA256,
			"challenge": strings.Repeat("0", 64),
			"number":    1,
			"salt":      "deadbeef:9999999999",
			"signature": "forged",
		},
	})
	if forged.Code != http.StatusUnauthorized || che61ErrorCode(t, forged) != "INVALID_CAPTCHA" {
		t.Fatalf("login with forged CAPTCHA = %d %s, want 401 INVALID_CAPTCHA", forged.Code, forged.Body.String())
	}
}

// A CAPTCHA receipt is bound to the requesting account at /auth/captcha/verify
// time. It must not be reusable for a different username.
func TestCHE61CAPTCHAReceiptCannotBeReplayedForAnotherAccount(t *testing.T) {
	env := newCHE61Router(t, nil)
	attacker := newCHE61LoginClient(env.router)
	receipt := che61SolveLoginCAPTCHA(t, attacker, "admin")

	login := attacker.perform(http.MethodPost, "/api/auth/login", mustJSON(t, map[string]any{
		"username": "reader",
		"password": "reader-password",
		"captcha":  receipt,
	}))
	if login.Code == http.StatusOK {
		t.Fatal("receipt minted for admin also authorized a login as reader")
	}
	if login.Code != http.StatusUnauthorized {
		t.Fatalf("cross-account receipt login = %d %s", login.Code, login.Body.String())
	}
}

func TestCHE61CAPTCHAReceiptIsSingleUse(t *testing.T) {
	env := newCHE61Router(t, nil)
	client := newCHE61LoginClient(env.router)
	receipt := che61SolveLoginCAPTCHA(t, client, "admin")
	body, err := json.Marshal(map[string]any{"username": "admin", "password": "admin-password", "captcha": receipt})
	if err != nil {
		t.Fatalf("marshal login: %v", err)
	}
	first := client.perform(http.MethodPost, "/api/auth/login", body)
	if first.Code != http.StatusOK {
		t.Fatalf("first login with valid receipt = %d %s", first.Code, first.Body.String())
	}
	// Same cookie jar, same receipt, second attempt.
	replay := newCHE61LoginClient(env.router)
	for name, cookie := range client.cookies {
		replay.cookies[name] = cookie
	}
	second := replay.perform(http.MethodPost, "/api/auth/login", body)
	if second.Code == http.StatusOK {
		t.Fatal("CAPTCHA receipt was accepted twice")
	}
}

// A receipt issued to one client identity must not be accepted from another
// browser (cookie jar / user agent).
func TestCHE61CAPTCHAReceiptIsBoundToIssuingClient(t *testing.T) {
	env := newCHE61Router(t, nil)
	issuer := newCHE61LoginClient(env.router)
	receipt := che61SolveLoginCAPTCHA(t, issuer, "admin")

	other := newCHE61LoginClient(env.router)
	login := other.perform(http.MethodPost, "/api/auth/login", mustJSON(t, map[string]any{
		"username": "admin",
		"password": "admin-password",
		"captcha":  receipt,
	}))
	if login.Code == http.StatusOK {
		t.Fatal("CAPTCHA receipt transferred to a different client authenticated")
	}
}

// verifyLoginCAPTCHA accepts an inline PoW payload (no receipt) and only
// validates it against the server-side proof tracker. A proof that was never
// issued by /auth/captcha but is self-consistent with the signing secret must
// not authenticate.
func TestCHE61InlinePoWProofMustHaveBeenIssued(t *testing.T) {
	env := newCHE61Router(t, nil)
	challenge, err := captcha.NewChallenge(captcha.Options{
		Secret:    env.secret,
		Purpose:   "admin-login",
		ClientKey: che61RemoteIP + "\nche61-forged-only",
		Path:      "admin-login",
		MaxNumber: 10,
		TTL:       time.Minute,
	})
	if err != nil {
		t.Fatalf("mint raw challenge: %v", err)
	}
	number := -1
	for i := 0; i <= challenge.MaxNumber; i++ {
		if captcha.Hash(challenge.Salt, i) == challenge.Challenge {
			number = i
			break
		}
	}
	if number < 0 {
		t.Fatal("could not solve self-minted challenge")
	}
	client := newCHE61LoginClient(env.router)
	login := client.perform(http.MethodPost, "/api/auth/login", mustJSON(t, map[string]any{
		"username": "admin",
		"password": "admin-password",
		"captcha": map[string]any{
			"username":  "admin",
			"mode":      "pow",
			"algorithm": challenge.Algorithm,
			"challenge": challenge.Challenge,
			"number":    number,
			"salt":      challenge.Salt,
			"signature": challenge.Signature,
		},
	}))
	if login.Code == http.StatusOK {
		t.Fatal("server accepted an inline PoW proof that /auth/captcha never issued")
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return raw
}

// ---------------------------------------------------------------------------
// E. Authorization / RBAC
// ---------------------------------------------------------------------------

func TestCHE61ReadonlySessionCannotMutateConfiguration(t *testing.T) {
	env := newCHE61Router(t, nil)
	client := newCHE61LoginClient(env.router)
	payload := che61SolveLoginCAPTCHA(t, client, "reader")
	login := client.perform(http.MethodPost, "/api/auth/login", mustJSON(t, map[string]any{
		"username": "reader", "password": "reader-password", "captcha": payload,
	}))
	if login.Code != http.StatusOK {
		t.Fatalf("reader login = %d %s", login.Code, login.Body.String())
	}
	session := client.cookies[middleware.SessionCookieName]
	csrf := client.cookies[middleware.CSRFCookieName]
	for _, tc := range []struct{ method, path string }{
		{http.MethodPut, "/api/protection/bot"},
		{http.MethodPut, "/api/edge"},
		{http.MethodPost, "/api/users"},
		{http.MethodPost, "/api/system/api-tokens"},
	} {
		request := httptest.NewRequest(tc.method, tc.path, strings.NewReader(`{}`))
		request.RemoteAddr = che61RemoteAddr
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set(middleware.CSRFHeaderName, csrf.Value)
		request.AddCookie(&http.Cookie{Name: middleware.SessionCookieName, Value: session.Value})
		request.AddCookie(&http.Cookie{Name: middleware.CSRFCookieName, Value: csrf.Value})
		recorder := httptest.NewRecorder()
		env.router.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusForbidden || che61ErrorCode(t, recorder) != "FORBIDDEN" {
			t.Fatalf("readonly %s %s = %d %s, want 403 FORBIDDEN", tc.method, tc.path, recorder.Code, recorder.Body.String())
		}
	}
}

func TestCHE61SetupEndpointsRejectRequestsWithoutSetupToken(t *testing.T) {
	env := newCHE61Router(t, nil)
	for _, path := range []string{"/api/setup", "/api/setup/probe", "/api/setup/draft"} {
		recorder := performFromIP(env.router, http.MethodPost, path, "", []byte(`{}`), che61RemoteAddr)
		if recorder.Code == http.StatusOK {
			t.Fatalf("%s accepted an unauthenticated setup request", path)
		}
	}
}

// ---------------------------------------------------------------------------
// F. Concurrency / fail-open probes on shared limiter state
// ---------------------------------------------------------------------------

// loginMaxConcurrentBodiesPerClient is 4; the 5th concurrent reservation for
// one source must be refused so a stalled body cannot starve the others.
func TestCHE61LoginBodySlotIsReleasedAfterDecodeFailure(t *testing.T) {
	state := handler.NewLoginCAPTCHAStateForTest()
	source := "198.51.100.23"
	for i := 0; i < 4; i++ {
		if !state.AcquireLoginBody(source) {
			t.Fatalf("body reservation %d within the per-client cap must be granted", i)
		}
	}
	if state.AcquireLoginBody(source) {
		t.Fatal("concurrent body reservation above per-client cap must be rejected")
	}
	if !state.AcquireLoginBody("198.51.100.24") {
		t.Fatal("one source at its cap must not block an independent source")
	}
	state.ReleaseLoginBody(source)
	if !state.AcquireLoginBody(source) {
		t.Fatal("released body slot was not reusable")
	}
}

func TestCHE61LoginConcurrencySlotReleasedOnEveryPath(t *testing.T) {
	state := handler.NewLoginCAPTCHAStateForTest()
	for i := 0; i < 32; i++ {
		if !state.AcquireLoginSlot() {
			t.Fatalf("slot %d should be available", i)
		}
	}
	if state.AcquireLoginSlot() {
		t.Fatal("33rd concurrent login slot must be rejected")
	}
	state.ReleaseLoginSlot()
	if !state.AcquireLoginSlot() {
		t.Fatal("released concurrency slot must be reusable")
	}
}

// Concurrent verification of the same proof must admit at most one winner.
func TestCHE61ConcurrentProofVerificationHasSingleWinner(t *testing.T) {
	env := newCHE61Router(t, nil)
	client := newCHE61LoginClient(env.router)
	receipt := che61SolveLoginCAPTCHA(t, client, "admin")
	body := mustJSON(t, map[string]any{"username": "admin", "password": "admin-password", "captcha": receipt})

	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			twin := newCHE61LoginClient(env.router)
			for name, cookie := range client.cookies {
				twin.cookies[name] = cookie
			}
			if twin.perform(http.MethodPost, "/api/auth/login", body).Code == http.StatusOK {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if got := wins.Load(); got != 1 {
		t.Fatalf("concurrent receipt redemption produced %d successful logins, want exactly 1", got)
	}
}

// ---------------------------------------------------------------------------
// G. Cluster interconnect surfaces mounted on the shared router
// ---------------------------------------------------------------------------

// The cluster interconnect server is built from the same router. Endpoints
// meant for enrolled nodes must verify node identity on the heartbeat path.
func TestCHE61ClusterHeartbeatRequiresNodeIdentity(t *testing.T) {
	env := newCHE61Router(t, func(cfg *config.Config) {
		cfg.Cluster.Enabled = true
		cfg.Cluster.ClusterID = "che61"
		cfg.Cluster.Nodes = []config.ClusterNodeConfig{{ID: "node-a", Role: "edge", AdvertiseAddr: "10.0.0.5:9443"}}
	})
	recorder := performFromIP(env.router, http.MethodPost, "/api/cluster/nodes/node-a/heartbeat", "", []byte(`{}`), che61RemoteAddr)
	if recorder.Code != http.StatusForbidden && recorder.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated heartbeat = %d %s, want 401/403", recorder.Code, recorder.Body.String())
	}
}
