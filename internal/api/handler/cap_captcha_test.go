package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/api/dto"
	"github.com/LaokeQwQ/CheeseWAF/internal/api/middleware"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

const (
	capLoginTestSecret = "cap-login-test-secret"
	capLoginTestToken  = "cap-login-test-token"
)

func TestCapLoginCAPTCHAReceiptIsClientAndUsernameBoundAndSingleUse(t *testing.T) {
	var siteverifyRequests int
	var gotSecret, gotToken string
	capServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/siteverify" || r.Method != http.MethodPost {
			t.Errorf("siteverify request = %s %s, want POST /siteverify", r.Method, r.URL.Path)
		}
		var payload struct {
			Secret   string `json:"secret"`
			Response string `json:"response"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode siteverify payload: %v", err)
		}
		siteverifyRequests++
		gotSecret, gotToken = payload.Secret, payload.Response
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true}`))
	}))
	defer capServer.Close()

	h := newCapLoginHandler(t, capServer.URL)
	challenge, cookie := issueCapLoginChallenge(t, h, "192.0.2.40:42100", "cap-login-test-agent")
	if challenge.ChallengeID == "" || challenge.APIEndpoint != capServer.URL || challenge.WASMURL != "https://assets.example/cap.wasm" || challenge.HashWXURL != "https://assets.example/hash.wasm" {
		t.Fatalf("unexpected Cap challenge response: %+v", challenge)
	}
	challengeJSON, _ := json.Marshal(challenge)
	if strings.Contains(string(challengeJSON), capLoginTestSecret) || strings.Contains(string(challengeJSON), "secret_file") {
		t.Fatalf("challenge response leaked verifier configuration: %s", challengeJSON)
	}

	verify := verifyCapLoginChallenge(t, h, challenge.ChallengeID, capLoginTestToken, "reader", cookie, "192.0.2.40:42100", "cap-login-test-agent")
	if verify.Code != http.StatusOK {
		t.Fatalf("verify Cap token: status=%d body=%s", verify.Code, verify.Body.String())
	}
	var verified struct {
		Data struct {
			Valid   bool   `json:"valid"`
			Receipt string `json:"receipt"`
		} `json:"data"`
	}
	if err := json.Unmarshal(verify.Body.Bytes(), &verified); err != nil {
		t.Fatalf("decode receipt response: %v", err)
	}
	if !verified.Data.Valid || verified.Data.Receipt == "" {
		t.Fatalf("verify response lacks receipt: %s", verify.Body.String())
	}
	if strings.Contains(verify.Body.String(), capLoginTestToken) {
		t.Fatalf("verify response echoed Cap token: %s", verify.Body.String())
	}
	if gotSecret != capLoginTestSecret || gotToken != capLoginTestToken || siteverifyRequests != 1 {
		t.Fatalf("siteverify got secret=%q token=%q requests=%d", gotSecret, gotToken, siteverifyRequests)
	}

	// A receipt produced for one account cannot be used to log in as another,
	// and the failed username attempt must not consume the valid receipt.
	wrongUser := postCapLogin(t, h, cookie, "admin", verified.Data.Receipt, "192.0.2.40:42100", "cap-login-test-agent")
	if wrongUser.Code != http.StatusUnauthorized {
		t.Fatalf("wrong-username login status=%d body=%s, want unauthorized", wrongUser.Code, wrongUser.Body.String())
	}
	login := postCapLogin(t, h, cookie, "reader", verified.Data.Receipt, "192.0.2.40:42100", "cap-login-test-agent")
	if login.Code != http.StatusOK {
		t.Fatalf("receipt login status=%d body=%s", login.Code, login.Body.String())
	}
	if strings.Contains(login.Body.String(), capLoginTestToken) {
		t.Fatalf("login response leaked Cap token: %s", login.Body.String())
	}

	replay := postCapLogin(t, h, cookie, "reader", verified.Data.Receipt, "192.0.2.40:42100", "cap-login-test-agent")
	if replay.Code != http.StatusUnauthorized {
		t.Fatalf("receipt replay status=%d body=%s, want unauthorized", replay.Code, replay.Body.String())
	}

	// A new challenge/token pair is required: cross-client verification cannot
	// consume the original client's proof.
	challenge, cookie = issueCapLoginChallenge(t, h, "192.0.2.41:42100", "cap-login-test-agent")
	crossClient := verifyCapLoginChallenge(t, h, challenge.ChallengeID, "cross-client-token", "reader", cookie, "192.0.2.42:42100", "cap-login-test-agent")
	if crossClient.Code != http.StatusUnauthorized {
		t.Fatalf("cross-client verify status=%d body=%s, want unauthorized", crossClient.Code, crossClient.Body.String())
	}
	correctClient := verifyCapLoginChallenge(t, h, challenge.ChallengeID, "cross-client-token", "reader", cookie, "192.0.2.41:42100", "cap-login-test-agent")
	if correctClient.Code != http.StatusOK {
		t.Fatalf("cross-client attempt consumed original proof: status=%d body=%s", correctClient.Code, correctClient.Body.String())
	}
	proofReplay := verifyCapLoginChallenge(t, h, challenge.ChallengeID, "cross-client-token", "reader", cookie, "192.0.2.41:42100", "cap-login-test-agent")
	if proofReplay.Code != http.StatusUnauthorized {
		t.Fatalf("Cap proof replay status=%d body=%s, want unauthorized", proofReplay.Code, proofReplay.Body.String())
	}
	var secondVerification struct {
		Data struct {
			Receipt string `json:"receipt"`
		} `json:"data"`
	}
	if err := json.Unmarshal(correctClient.Body.Bytes(), &secondVerification); err != nil || secondVerification.Data.Receipt == "" {
		t.Fatalf("decode second local receipt: err=%v body=%s", err, correctClient.Body.String())
	}
	crossClientLogin := postCapLogin(t, h, cookie, "reader", secondVerification.Data.Receipt, "192.0.2.42:42100", "cap-login-test-agent")
	if crossClientLogin.Code != http.StatusUnauthorized {
		t.Fatalf("cross-client receipt login status=%d body=%s, want unauthorized", crossClientLogin.Code, crossClientLogin.Body.String())
	}
}

func TestCapLoginCAPTCHARejectsProviderFalseAndHidesSiteverifyErrors(t *testing.T) {
	for _, tc := range []struct {
		name       string
		status     int
		body       string
		wantStatus int
	}{
		{name: "provider false", status: http.StatusOK, body: `{"success":false}`, wantStatus: http.StatusUnauthorized},
		{name: "provider error", status: http.StatusBadGateway, body: "upstream-private-detail", wantStatus: http.StatusServiceUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			capServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer capServer.Close()

			h := newCapLoginHandler(t, capServer.URL)
			challenge, cookie := issueCapLoginChallenge(t, h, "192.0.2.50:42100", "cap-login-error-test-agent")
			response := verifyCapLoginChallenge(t, h, challenge.ChallengeID, capLoginTestToken, "reader", cookie, "192.0.2.50:42100", "cap-login-error-test-agent")
			if response.Code != tc.wantStatus {
				t.Fatalf("verification status=%d body=%s, want %d", response.Code, response.Body.String(), tc.wantStatus)
			}
			for _, private := range []string{capLoginTestToken, capLoginTestSecret, "upstream-private-detail", "siteverify"} {
				if strings.Contains(response.Body.String(), private) {
					t.Fatalf("response leaked %q: %s", private, response.Body.String())
				}
			}
		})
	}
}

func newCapLoginHandler(t *testing.T, endpoint string) *Handler {
	t.Helper()
	h, store := newUserTestHandler(t)
	createUserFixture(t, store, "cap-admin-id", "admin", "reader-password", "admin")
	secretPath := filepath.Join(t.TempDir(), "cap-siteverify-secret")
	if err := os.WriteFile(secretPath, []byte(capLoginTestSecret), 0o600); err != nil {
		t.Fatalf("write Cap secret: %v", err)
	}
	h.Secret = "cap-login-receipt-signing-secret"
	h.loginCAPTCHASecret = ""
	h.Tokens = middleware.NewTokenManager(h.Secret, time.Hour)
	h.Config.Server.AdminPublic = true
	h.Config.Console.Login.CAPTCHA.Enabled = true
	h.Config.Console.Login.CAPTCHA.Provider = "cap"
	h.Config.Console.Login.CAPTCHA.TTL = 5 * time.Minute
	h.Config.CAPTCHAProviders.Cap = config.CapStandaloneConfig{
		APIEndpoint: endpoint,
		WASMURL:     "https://assets.example/cap.wasm",
		HashWXURL:   "https://assets.example/hash.wasm",
		SecretFile:  secretPath,
		Timeout:     time.Second,
	}
	return h
}

func issueCapLoginChallenge(t *testing.T, h *Handler, remoteAddr, userAgent string) (struct {
	ChallengeID string `json:"challenge_id"`
	APIEndpoint string `json:"api_endpoint"`
	WASMURL     string `json:"wasm_url"`
	HashWXURL   string `json:"hashwx_url"`
}, *http.Cookie) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/auth/captcha", strings.NewReader(`{"mode":"cap"}`))
	req.RemoteAddr = remoteAddr
	req.Header.Set("User-Agent", userAgent)
	rec := httptest.NewRecorder()
	h.LoginCAPTCHA(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("issue Cap challenge: status=%d body=%s", rec.Code, rec.Body.String())
	}
	var result struct {
		Data struct {
			Enabled  bool   `json:"enabled"`
			Provider string `json:"provider"`
			Mode     string `json:"mode"`
			Cap      struct {
				ChallengeID string `json:"challenge_id"`
				APIEndpoint string `json:"api_endpoint"`
				WASMURL     string `json:"wasm_url"`
				HashWXURL   string `json:"hashwx_url"`
			} `json:"cap"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode Cap challenge: %v", err)
	}
	if !result.Data.Enabled || result.Data.Provider != "cap" || result.Data.Mode != "cap" {
		t.Fatalf("unexpected Cap challenge envelope: %s", rec.Body.String())
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != loginCAPTCHAClientCookie {
		t.Fatalf("challenge cookies = %#v, want signed client cookie", cookies)
	}
	return result.Data.Cap, cookies[0]
}

func verifyCapLoginChallenge(t *testing.T, h *Handler, challengeID, token, username string, cookie *http.Cookie, remoteAddr, userAgent string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(dto.CAPTCHAPayload{Provider: "cap", Mode: "cap", ChallengeID: challengeID, Token: token, Username: username})
	if err != nil {
		t.Fatalf("marshal Cap verification: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/auth/captcha/verify", bytes.NewReader(body))
	req.RemoteAddr = remoteAddr
	req.Header.Set("User-Agent", userAgent)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.VerifyLoginCAPTCHA(rec, req)
	return rec
}

func postCapLogin(t *testing.T, h *Handler, cookie *http.Cookie, username, receipt, remoteAddr, userAgent string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(dto.LoginRequest{
		Username: username,
		Password: "reader-password",
		CAPTCHA:  &dto.CAPTCHAPayload{Provider: "cap", Mode: "cap", Receipt: receipt},
	})
	if err != nil {
		t.Fatalf("marshal login request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(body))
	req.RemoteAddr = remoteAddr
	req.Header.Set("User-Agent", userAgent)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.Login(rec, req)
	return rec
}
