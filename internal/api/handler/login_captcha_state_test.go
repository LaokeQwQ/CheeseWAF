package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/api/dto"
	"github.com/LaokeQwQ/CheeseWAF/internal/captcha"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

func TestLoginAttemptConcurrencyLimit(t *testing.T) {
	state := newLoginCAPTCHAState()
	for i := 0; i < loginMaxConcurrentAttempts; i++ {
		if !state.acquireLoginSlot() {
			t.Fatalf("slot %d should be available", i)
		}
	}
	if state.acquireLoginSlot() {
		t.Fatal("attempt beyond global concurrency limit should be rejected")
	}
	state.releaseLoginSlot()
	if !state.acquireLoginSlot() {
		t.Fatal("released login slot should become available")
	}
}

func TestLoginCAPTCHAProofCanOnlyBeReservedOnceConcurrently(t *testing.T) {
	state := newLoginCAPTCHAState()
	now := time.Now().UTC()
	key := loginCAPTCHAFingerprint("pow", "client", "signature", "salt", "challenge")
	if !state.registerProofs([]string{key}, now.Add(time.Minute), now) {
		t.Fatal("register proof")
	}
	var successes atomic.Int32
	var wg sync.WaitGroup
	for range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if state.reserveProofs([]string{key}, now) {
				successes.Add(1)
				state.finishProofs([]string{key}, true, now)
			}
		}()
	}
	wg.Wait()
	if got := successes.Load(); got != 1 {
		t.Fatalf("expected exactly one proof reservation, got %d", got)
	}
}

func TestVerifyLoginCAPTCHAConcurrentProofIssuesOneReceipt(t *testing.T) {
	cfg := config.Default()
	cfg.Console.Login.CAPTCHA.Enabled = true
	cfg.Console.Login.CAPTCHA.Mode = "pow"
	cfg.Console.Login.CAPTCHA.MaxNumber = 5000
	h := &Handler{Config: &cfg, Secret: "concurrent-login-captcha-secret"}

	challengeRequest := httptest.NewRequest(http.MethodPost, "/api/auth/captcha", bytes.NewBufferString(`{}`))
	challengeRequest.RemoteAddr = "192.0.2.8:41234"
	challengeResponse := httptest.NewRecorder()
	h.LoginCAPTCHA(challengeResponse, challengeRequest)
	if challengeResponse.Code != http.StatusOK {
		t.Fatalf("issue challenge: %d %s", challengeResponse.Code, challengeResponse.Body.String())
	}
	challengeCookies := challengeResponse.Result().Cookies()
	if len(challengeCookies) != 1 {
		t.Fatalf("issue challenge returned %d cookies, want 1", len(challengeCookies))
	}
	var envelope struct {
		Data struct {
			Challenge captcha.Challenge `json:"challenge"`
		} `json:"data"`
	}
	if err := json.NewDecoder(challengeResponse.Body).Decode(&envelope); err != nil {
		t.Fatalf("decode challenge: %v", err)
	}
	challenge := envelope.Data.Challenge
	number := -1
	for i := 0; i <= challenge.MaxNumber; i++ {
		if captcha.Hash(challenge.Salt, i) == challenge.Challenge {
			number = i
			break
		}
	}
	if number < 0 {
		t.Fatal("solve challenge")
	}
	payload, err := json.Marshal(dto.CAPTCHAPayload{Username: "Cheese", Mode: "pow", Algorithm: challenge.Algorithm, Challenge: challenge.Challenge, Number: number, Salt: challenge.Salt, Signature: challenge.Signature})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	var successes atomic.Int32
	receipts := make(chan string, 100)
	var wg sync.WaitGroup
	for range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodPost, "/api/auth/captcha/verify", bytes.NewReader(payload))
			req.RemoteAddr = "192.0.2.8:41234"
			req.AddCookie(challengeCookies[0])
			rec := httptest.NewRecorder()
			h.VerifyLoginCAPTCHA(rec, req)
			if rec.Code != http.StatusOK {
				return
			}
			var response struct {
				Data struct {
					Receipt string `json:"receipt"`
				} `json:"data"`
			}
			if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
				t.Errorf("decode receipt: %v", err)
				return
			}
			if response.Data.Receipt == "" {
				t.Error("successful verification returned empty receipt")
				return
			}
			successes.Add(1)
			receipts <- response.Data.Receipt
		}()
	}
	wg.Wait()
	close(receipts)
	if got := successes.Load(); got != 1 {
		t.Fatalf("expected one successful receipt issue, got %d", got)
	}
	if got := len(receipts); got != 1 {
		t.Fatalf("expected one receipt, got %d", got)
	}
}

func TestVerifyLoginCAPTCHAPreconditionErrorsDoNotConsumeProof(t *testing.T) {
	for _, testCase := range []struct {
		name      string
		body      func([]byte) *bytes.Reader
		addCookie func(*http.Request, *http.Cookie)
		wantCode  int
	}{
		{
			name:      "missing cookie",
			body:      bytes.NewReader,
			addCookie: func(_ *http.Request, _ *http.Cookie) {},
			wantCode:  http.StatusUnauthorized,
		},
		{
			name: "tampered cookie",
			body: bytes.NewReader,
			addCookie: func(req *http.Request, cookie *http.Cookie) {
				tampered := *cookie
				tampered.Value += "x"
				req.AddCookie(&tampered)
			},
			wantCode: http.StatusUnauthorized,
		},
		{
			name: "malformed json",
			body: func(_ []byte) *bytes.Reader {
				return bytes.NewReader([]byte(`{"username":`))
			},
			addCookie: func(req *http.Request, cookie *http.Cookie) {
				req.AddCookie(cookie)
			},
			wantCode: http.StatusBadRequest,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			cfg := config.Default()
			cfg.Console.Login.CAPTCHA.Enabled = true
			cfg.Console.Login.CAPTCHA.Mode = "pow"
			cfg.Console.Login.CAPTCHA.MaxNumber = 5000
			h := &Handler{Config: &cfg, Secret: "bound-login-captcha-secret"}

			challengeRequest := httptest.NewRequest(http.MethodPost, "/api/auth/captcha", bytes.NewBufferString(`{}`))
			challengeRequest.RemoteAddr = "192.0.2.18:41234"
			challengeResponse := httptest.NewRecorder()
			h.LoginCAPTCHA(challengeResponse, challengeRequest)
			if challengeResponse.Code != http.StatusOK {
				t.Fatalf("issue challenge: %d %s", challengeResponse.Code, challengeResponse.Body.String())
			}
			cookies := challengeResponse.Result().Cookies()
			if len(cookies) != 1 {
				t.Fatalf("issue challenge returned %d cookies, want 1", len(cookies))
			}
			var envelope struct {
				Data struct {
					Challenge captcha.Challenge `json:"challenge"`
				} `json:"data"`
			}
			if err := json.NewDecoder(challengeResponse.Body).Decode(&envelope); err != nil {
				t.Fatalf("decode challenge: %v", err)
			}
			number := -1
			for i := 0; i <= envelope.Data.Challenge.MaxNumber; i++ {
				if captcha.Hash(envelope.Data.Challenge.Salt, i) == envelope.Data.Challenge.Challenge {
					number = i
					break
				}
			}
			if number < 0 {
				t.Fatal("solve challenge")
			}
			payload, err := json.Marshal(dto.CAPTCHAPayload{
				Username:  "Cheese",
				Mode:      "pow",
				Algorithm: envelope.Data.Challenge.Algorithm,
				Challenge: envelope.Data.Challenge.Challenge,
				Number:    number,
				Salt:      envelope.Data.Challenge.Salt,
				Signature: envelope.Data.Challenge.Signature,
			})
			if err != nil {
				t.Fatalf("marshal payload: %v", err)
			}

			invalidRequest := httptest.NewRequest(http.MethodPost, "/api/auth/captcha/verify", testCase.body(payload))
			invalidRequest.RemoteAddr = challengeRequest.RemoteAddr
			testCase.addCookie(invalidRequest, cookies[0])
			invalidResponse := httptest.NewRecorder()
			h.VerifyLoginCAPTCHA(invalidResponse, invalidRequest)
			if invalidResponse.Code != testCase.wantCode {
				t.Fatalf("precondition error returned %d, want %d", invalidResponse.Code, testCase.wantCode)
			}

			validRequest := httptest.NewRequest(http.MethodPost, "/api/auth/captcha/verify", bytes.NewReader(payload))
			validRequest.RemoteAddr = challengeRequest.RemoteAddr
			validRequest.AddCookie(cookies[0])
			validResponse := httptest.NewRecorder()
			h.VerifyLoginCAPTCHA(validResponse, validRequest)
			if validResponse.Code != http.StatusOK {
				t.Fatalf("original client could not consume proof after rejected request: %d %s", validResponse.Code, validResponse.Body.String())
			}
		})
	}
}

func TestLoginCAPTCHAUnknownProofFloodDoesNotCreateState(t *testing.T) {
	state := newLoginCAPTCHAState()
	now := time.Now().UTC()
	for i := 0; i < 100_000; i++ {
		key := loginCAPTCHAFingerprint("forged", fmt.Sprint(i))
		if state.reserveProofs([]string{key}, now) {
			t.Fatalf("forged proof %d was accepted", i)
		}
		state.finishProofs([]string{key}, false, now)
	}
	if got := len(state.proofs); got != 0 {
		t.Fatalf("forged proofs must not allocate state, got %d entries", got)
	}
}

func TestLoginCAPTCHAProofFailurePermanentlyConsumesProof(t *testing.T) {
	state := newLoginCAPTCHAState()
	now := time.Now().UTC()
	key := "proof"
	if !state.registerProofs([]string{key}, now.Add(time.Minute), now) {
		t.Fatal("register proof")
	}
	if !state.reserveProofs([]string{key}, now) {
		t.Fatal("first answer verification should reserve proof")
	}
	state.finishProofs([]string{key}, false, now)
	if state.reserveProofs([]string{key}, now) {
		t.Fatal("proof must remain unavailable after the first wrong answer")
	}
}

func TestVerifyLoginCAPTCHAPowWrongAnswerConsumesProof(t *testing.T) {
	cfg := config.Default()
	cfg.Console.Login.CAPTCHA.Enabled = true
	cfg.Console.Login.CAPTCHA.Mode = "pow"
	cfg.Console.Login.CAPTCHA.MaxNumber = 5000
	h := &Handler{Config: &cfg, Secret: "single-use-pow-secret"}

	challengeRequest := httptest.NewRequest(http.MethodPost, "/api/auth/captcha", bytes.NewBufferString(`{}`))
	challengeRequest.RemoteAddr = "192.0.2.40:41234"
	challengeResponse := httptest.NewRecorder()
	h.LoginCAPTCHA(challengeResponse, challengeRequest)
	if challengeResponse.Code != http.StatusOK {
		t.Fatalf("issue challenge: %d %s", challengeResponse.Code, challengeResponse.Body.String())
	}
	cookies := challengeResponse.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("issue challenge returned %d cookies, want 1", len(cookies))
	}
	var envelope struct {
		Data struct {
			Challenge captcha.Challenge `json:"challenge"`
		} `json:"data"`
	}
	if err := json.NewDecoder(challengeResponse.Body).Decode(&envelope); err != nil {
		t.Fatalf("decode challenge: %v", err)
	}
	challenge := envelope.Data.Challenge
	solution := -1
	for number := 0; number <= challenge.MaxNumber; number++ {
		if captcha.Hash(challenge.Salt, number) == challenge.Challenge {
			solution = number
			break
		}
	}
	if solution < 0 {
		t.Fatal("solve challenge")
	}
	wrong := (solution + 1) % (challenge.MaxNumber + 1)

	verify := func(number int) *httptest.ResponseRecorder {
		t.Helper()
		payload, err := json.Marshal(dto.CAPTCHAPayload{
			Username:  "Cheese",
			Mode:      "pow",
			Algorithm: challenge.Algorithm,
			Challenge: challenge.Challenge,
			Number:    number,
			Salt:      challenge.Salt,
			Signature: challenge.Signature,
		})
		if err != nil {
			t.Fatalf("marshal payload: %v", err)
		}
		req := httptest.NewRequest(http.MethodPost, "/api/auth/captcha/verify", bytes.NewReader(payload))
		req.RemoteAddr = challengeRequest.RemoteAddr
		req.AddCookie(cookies[0])
		rec := httptest.NewRecorder()
		h.VerifyLoginCAPTCHA(rec, req)
		return rec
	}

	if first := verify(wrong); first.Code != http.StatusUnauthorized {
		t.Fatalf("wrong answer returned %d, want 401: %s", first.Code, first.Body.String())
	}
	if second := verify(solution); second.Code != http.StatusUnauthorized {
		t.Fatalf("correct replay after wrong answer returned %d, want 401: %s", second.Code, second.Body.String())
	}
}

func TestVerifyLoginCAPTCHASliderWrongAnswerConsumesProof(t *testing.T) {
	cfg := config.Default()
	cfg.Console.Login.CAPTCHA.Enabled = true
	cfg.Console.Login.CAPTCHA.Mode = "slider"
	cfg.Console.Login.CAPTCHA.Slider.Tolerance = cfg.Console.Login.CAPTCHA.Slider.Width
	h := &Handler{Config: &cfg, Secret: "single-use-slider-secret"}

	challengeRequest := httptest.NewRequest(http.MethodPost, "/api/auth/captcha", bytes.NewBufferString(`{"mode":"slider"}`))
	challengeRequest.RemoteAddr = "192.0.2.41:41234"
	challengeResponse := httptest.NewRecorder()
	h.LoginCAPTCHA(challengeResponse, challengeRequest)
	if challengeResponse.Code != http.StatusOK {
		t.Fatalf("issue challenge: %d %s", challengeResponse.Code, challengeResponse.Body.String())
	}
	cookies := challengeResponse.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("issue challenge returned %d cookies, want 1", len(cookies))
	}
	var envelope struct {
		Data struct {
			Slider captcha.SliderChallenge `json:"slider"`
		} `json:"data"`
	}
	if err := json.NewDecoder(challengeResponse.Body).Decode(&envelope); err != nil {
		t.Fatalf("decode challenge: %v", err)
	}
	track := `[{"x":0,"y":20,"t":0,"type":"down"},{"x":1,"y":21,"t":180,"type":"move"},{"x":2,"y":20,"t":300,"type":"move"},{"x":0,"y":20,"t":520,"type":"up"}]`

	verify := func(dragMS int) *httptest.ResponseRecorder {
		t.Helper()
		payload, err := json.Marshal(dto.CAPTCHAPayload{
			Username: "Cheese",
			Mode:     "slider",
			Slider: &dto.SliderCAPTCHAPayload{
				Token:  envelope.Data.Slider.Token,
				X:      0,
				DragMS: dragMS,
				Track:  track,
			},
		})
		if err != nil {
			t.Fatalf("marshal payload: %v", err)
		}
		req := httptest.NewRequest(http.MethodPost, "/api/auth/captcha/verify", bytes.NewReader(payload))
		req.RemoteAddr = challengeRequest.RemoteAddr
		req.AddCookie(cookies[0])
		rec := httptest.NewRecorder()
		h.VerifyLoginCAPTCHA(rec, req)
		return rec
	}

	if first := verify(1); first.Code != http.StatusUnauthorized {
		t.Fatalf("too-fast answer returned %d, want 401: %s", first.Code, first.Body.String())
	}
	validDragMS := int(cfg.Console.Login.CAPTCHA.Slider.MinDrag/time.Millisecond) + 80
	if second := verify(validDragMS); second.Code != http.StatusUnauthorized {
		t.Fatalf("correct replay after wrong answer returned %d, want 401: %s", second.Code, second.Body.String())
	}
}

func TestVerifyLoginCAPTCHASliderMissingTrackDoesNotConsumeProof(t *testing.T) {
	cfg := config.Default()
	cfg.Console.Login.CAPTCHA.Enabled = true
	cfg.Console.Login.CAPTCHA.Mode = "slider"
	cfg.Console.Login.CAPTCHA.Slider.Tolerance = cfg.Console.Login.CAPTCHA.Slider.Width
	h := &Handler{Config: &cfg, Secret: "slider-precondition-secret"}

	challengeRequest := httptest.NewRequest(http.MethodPost, "/api/auth/captcha", bytes.NewBufferString(`{"mode":"slider"}`))
	challengeRequest.RemoteAddr = "192.0.2.42:41234"
	challengeResponse := httptest.NewRecorder()
	h.LoginCAPTCHA(challengeResponse, challengeRequest)
	if challengeResponse.Code != http.StatusOK {
		t.Fatalf("issue challenge: %d %s", challengeResponse.Code, challengeResponse.Body.String())
	}
	cookies := challengeResponse.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("issue challenge returned %d cookies, want 1", len(cookies))
	}
	var envelope struct {
		Data struct {
			Slider captcha.SliderChallenge `json:"slider"`
		} `json:"data"`
	}
	if err := json.NewDecoder(challengeResponse.Body).Decode(&envelope); err != nil {
		t.Fatalf("decode challenge: %v", err)
	}
	validTrack := `[{"x":0,"y":20,"t":0,"type":"down"},{"x":1,"y":21,"t":180,"type":"move"},{"x":2,"y":20,"t":300,"type":"move"},{"x":0,"y":20,"t":520,"type":"up"}]`

	verify := func(track string) *httptest.ResponseRecorder {
		t.Helper()
		payload, err := json.Marshal(dto.CAPTCHAPayload{
			Username: "Cheese",
			Mode:     "slider",
			Slider: &dto.SliderCAPTCHAPayload{
				Token:  envelope.Data.Slider.Token,
				X:      0,
				DragMS: int(cfg.Console.Login.CAPTCHA.Slider.MinDrag/time.Millisecond) + 80,
				Track:  track,
			},
		})
		if err != nil {
			t.Fatalf("marshal payload: %v", err)
		}
		req := httptest.NewRequest(http.MethodPost, "/api/auth/captcha/verify", bytes.NewReader(payload))
		req.RemoteAddr = challengeRequest.RemoteAddr
		req.AddCookie(cookies[0])
		rec := httptest.NewRecorder()
		h.VerifyLoginCAPTCHA(rec, req)
		return rec
	}

	if malformed := verify(""); malformed.Code != http.StatusUnauthorized {
		t.Fatalf("missing track returned %d, want 401: %s", malformed.Code, malformed.Body.String())
	}
	if valid := verify(validTrack); valid.Code != http.StatusOK {
		t.Fatalf("precondition failure consumed proof: %d %s", valid.Code, valid.Body.String())
	}
}

func TestLoginCAPTCHAExpiredProofIsRejectedAndPruned(t *testing.T) {
	state := newLoginCAPTCHAState()
	now := time.Now().UTC()
	if !state.registerProofs([]string{"expired"}, now.Add(time.Second), now) {
		t.Fatal("register proof")
	}
	later := now.Add(2 * time.Second)
	if state.reserveProofs([]string{"expired"}, later) {
		t.Fatal("expired proof was accepted")
	}
	state.mu.Lock()
	state.pruneLocked(later)
	_, exists := state.proofs["expired"]
	state.mu.Unlock()
	if exists {
		t.Fatal("expired proof was not pruned")
	}
}

func TestLoginCAPTCHAProofCapacityIsBounded(t *testing.T) {
	state := newLoginCAPTCHAState()
	now := time.Now().UTC()
	for i := 0; i < loginCAPTCHAProofCapacity; i++ {
		if !state.registerProofs([]string{fmt.Sprintf("proof-%d", i)}, now.Add(time.Minute), now) {
			t.Fatalf("register proof %d", i)
		}
	}
	if state.registerProofs([]string{"overflow"}, now.Add(time.Minute), now) {
		t.Fatal("proof capacity overflow was accepted")
	}
	if got := len(state.proofs); got != loginCAPTCHAProofCapacity {
		t.Fatalf("proof state exceeded capacity: %d", got)
	}
}

func TestLoginCAPTCHARefreshReplacesPendingProofsForClient(t *testing.T) {
	state := newLoginCAPTCHAState()
	now := time.Now().UTC()
	if !state.registerProofsForClient("client-a", "peer-a", []string{"old"}, now.Add(time.Minute), now) {
		t.Fatal("register old proof")
	}
	if !state.registerProofsForClient("client-a", "peer-a", []string{"new"}, now.Add(time.Minute), now) {
		t.Fatal("register replacement proof")
	}
	if state.reserveProofs([]string{"old"}, now) {
		t.Fatal("replaced proof remained usable")
	}
	if !state.reserveProofs([]string{"new"}, now) {
		t.Fatal("replacement proof was not usable")
	}
}

func TestLoginCAPTCHAOneClientCannotExhaustProofCapacity(t *testing.T) {
	state := newLoginCAPTCHAState()
	now := time.Now().UTC()
	for i := 0; i < loginCAPTCHAProofCapacity*2; i++ {
		if !state.registerProofsForClient("client-a", "peer-a", []string{fmt.Sprintf("proof-%d", i)}, now.Add(time.Minute), now) {
			t.Fatalf("client refresh %d was rejected", i)
		}
	}
	if got := len(state.proofs); got > loginCAPTCHAProofPerClient {
		t.Fatalf("single client retained %d proofs", got)
	}
	if !state.registerProofsForClient("client-b", "peer-b", []string{"other"}, now.Add(time.Minute), now) {
		t.Fatal("one client blocked another client")
	}
}

func TestLoginCAPTCHAReceiptQuotaIsPerClient(t *testing.T) {
	state := newLoginCAPTCHAState()
	now := time.Now().UTC()
	for i := 0; i < loginCAPTCHAReceiptCapacity*2; i++ {
		if !state.storeReceiptForClient("client-a", "peer-a", fmt.Sprintf("receipt-%d", i), now.Add(time.Minute), now) {
			t.Fatalf("store receipt %d", i)
		}
	}
	if got := len(state.receipts); got > loginCAPTCHAReceiptPerClient {
		t.Fatalf("single client retained %d receipts", got)
	}
	if !state.storeReceiptForClient("client-b", "peer-b", "other", now.Add(time.Minute), now) {
		t.Fatal("one client blocked another client receipt")
	}
}

func TestLoginCAPTCHASharedProxyClientsDoNotReplaceEachOthersProofs(t *testing.T) {
	state := newLoginCAPTCHAState()
	now := time.Now().UTC()
	if !state.registerProofsForClient("client-a", "proxy", []string{"a-old"}, now.Add(time.Minute), now) {
		t.Fatal("register client A proof")
	}
	if !state.registerProofsForClient("client-b", "proxy", []string{"b"}, now.Add(time.Minute), now) {
		t.Fatal("register client B proof")
	}
	if !state.registerProofsForClient("client-a", "proxy", []string{"a-new"}, now.Add(time.Minute), now) {
		t.Fatal("refresh client A proof")
	}
	if state.reserveProofs([]string{"a-old"}, now) {
		t.Fatal("client A old proof survived refresh")
	}
	if !state.reserveProofs([]string{"a-new"}, now) || !state.reserveProofs([]string{"b"}, now) {
		t.Fatal("one shared-proxy client invalidated another client's proof")
	}
}

func TestLoginCAPTCHASharedProxyClientsDoNotEvictEachOthersReceipts(t *testing.T) {
	state := newLoginCAPTCHAState()
	now := time.Now().UTC()
	if !state.storeReceiptForClient("client-b", "proxy", "receipt-b", now.Add(time.Minute), now) {
		t.Fatal("store client B receipt")
	}
	for i := 0; i < loginCAPTCHAReceiptPerClient*3; i++ {
		if !state.storeReceiptForClient("client-a", "proxy", fmt.Sprintf("receipt-a-%d", i), now.Add(time.Minute), now) {
			t.Fatalf("store client A receipt %d", i)
		}
	}
	if !state.consumeReceiptForClient("client-b", "proxy", "receipt-b", now) {
		t.Fatal("client A receipt rotation evicted client B receipt")
	}
}

func TestLoginCAPTCHACookieRotationCannotBypassPeerProofQuota(t *testing.T) {
	state := newLoginCAPTCHAState()
	now := time.Now().UTC()
	for i := 0; i < loginCAPTCHAProofPerPeer; i++ {
		if !state.registerProofsForClient(fmt.Sprintf("client-%d", i), "proxy", []string{fmt.Sprintf("proof-%d", i)}, now.Add(time.Minute), now) {
			t.Fatalf("peer proof %d rejected before peer quota", i)
		}
	}
	if state.registerProofsForClient("rotated-client", "proxy", []string{"overflow"}, now.Add(time.Minute), now) {
		t.Fatal("new anonymous client bypassed peer proof quota")
	}
	if !state.registerProofsForClient("other-client", "other-peer", []string{"other-proof"}, now.Add(time.Minute), now) {
		t.Fatal("one saturated peer blocked another peer")
	}
}

func TestLoginCAPTCHACookieRotationCannotBypassPeerReceiptQuota(t *testing.T) {
	state := newLoginCAPTCHAState()
	now := time.Now().UTC()
	for i := 0; i < loginCAPTCHAReceiptPerPeer; i++ {
		if !state.storeReceiptForClient(fmt.Sprintf("client-%d", i), "proxy", fmt.Sprintf("receipt-%d", i), now.Add(time.Minute), now) {
			t.Fatalf("peer receipt %d rejected before peer quota", i)
		}
	}
	if state.storeReceiptForClient("rotated-client", "proxy", "overflow", now.Add(time.Minute), now) {
		t.Fatal("new anonymous client bypassed peer receipt quota")
	}
}

func TestLoginCAPTCHAConcurrentPeerQuotaIsBounded(t *testing.T) {
	state := newLoginCAPTCHAState()
	now := time.Now().UTC()
	var accepted atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < loginCAPTCHAProofPerPeer*4; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if state.registerProofsForClient(fmt.Sprintf("client-%d", i), "proxy", []string{fmt.Sprintf("proof-%d", i)}, now.Add(time.Minute), now) {
				accepted.Add(1)
			}
		}(i)
	}
	wg.Wait()
	if got := accepted.Load(); got != loginCAPTCHAProofPerPeer {
		t.Fatalf("accepted %d proofs, want exactly peer limit %d", got, loginCAPTCHAProofPerPeer)
	}
}

func TestLoginCAPTCHAAnonymousClientCookieIsSignedAndHardened(t *testing.T) {
	h := &Handler{Secret: "test-secret", loginCAPTCHASecret: "test-secret"}
	req := httptest.NewRequest(http.MethodPost, "https://console.example/api/auth/captcha", nil)
	req.RemoteAddr = "192.0.2.40:41234"
	recorder := httptest.NewRecorder()
	owner, peer, ok := h.loginCaptchaQuotaIdentity(recorder, req)
	if !ok || owner == "" || peer != "192.0.2.40" {
		t.Fatalf("unexpected identity owner=%q peer=%q ok=%v", owner, peer, ok)
	}
	result := recorder.Result()
	cookies := result.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("got %d cookies, want 1", len(cookies))
	}
	cookie := cookies[0]
	if !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteStrictMode || cookie.Path != "/" {
		t.Fatalf("cookie flags not hardened: %#v", cookie)
	}

	next := httptest.NewRequest(http.MethodPost, "https://console.example/api/auth/captcha", nil)
	next.RemoteAddr = req.RemoteAddr
	next.AddCookie(cookie)
	nextOwner, nextPeer, ok := h.loginCaptchaExistingQuotaIdentity(next)
	if !ok || nextOwner != owner || nextPeer != peer {
		t.Fatalf("signed cookie identity changed owner=%q peer=%q ok=%v", nextOwner, nextPeer, ok)
	}

	tampered := *cookie
	tampered.Value += "x"
	next = httptest.NewRequest(http.MethodPost, "https://console.example/api/auth/captcha", nil)
	next.RemoteAddr = req.RemoteAddr
	next.AddCookie(&tampered)
	if _, _, ok := h.loginCaptchaExistingQuotaIdentity(next); ok {
		t.Fatal("tampered anonymous client cookie was accepted")
	}
}

func TestLoginCAPTCHAClientCookieSecureBehindForwardedProto(t *testing.T) {
	h := &Handler{Secret: "test-secret", loginCAPTCHASecret: "test-secret"}
	// Plain HTTP request terminated by TLS proxy: no r.TLS, but X-Forwarded-Proto: https.
	req := httptest.NewRequest(http.MethodPost, "http://console.example/api/auth/captcha", nil)
	req.RemoteAddr = "192.0.2.41:41234"
	req.Header.Set("X-Forwarded-Proto", "https")
	recorder := httptest.NewRecorder()
	if _, _, ok := h.loginCaptchaQuotaIdentity(recorder, req); !ok {
		t.Fatal("expected quota identity to issue client cookie")
	}
	cookies := recorder.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].Secure || !cookies[0].HttpOnly {
		t.Fatalf("expected Secure HttpOnly client cookie behind TLS terminator, got %#v", cookies)
	}
}

func TestLoginCAPTCHAQuotaPeerIgnoresForwardedClientHeaders(t *testing.T) {
	h := &Handler{Secret: "test-secret", loginCAPTCHASecret: "test-secret"}
	for _, forwarded := range []string{"198.51.100.1", "203.0.113.99", "forged.example"} {
		req := httptest.NewRequest(http.MethodPost, "https://console.example/api/auth/captcha", nil)
		req.RemoteAddr = "192.0.2.80:41234"
		req.Header.Set("X-Forwarded-For", forwarded)
		req.Header.Set("X-Real-IP", forwarded)
		recorder := httptest.NewRecorder()
		_, peer, ok := h.loginCaptchaQuotaIdentity(recorder, req)
		if !ok || peer != "192.0.2.80" {
			t.Fatalf("forwarded header %q changed quota peer to %q", forwarded, peer)
		}
	}
}

func TestLoginCAPTCHAClientRefreshSucceedsAtPeerCapacity(t *testing.T) {
	state := newLoginCAPTCHAState()
	now := time.Now().UTC()
	for i := 0; i < loginCAPTCHAProofPerPeer; i++ {
		if !state.registerProofsForClient(fmt.Sprintf("client-%d", i), "proxy", []string{fmt.Sprintf("proof-%d", i)}, now.Add(time.Minute), now) {
			t.Fatalf("fill peer proof %d", i)
		}
	}
	if !state.registerProofsForClient("client-0", "proxy", []string{"replacement"}, now.Add(time.Minute), now) {
		t.Fatal("existing client could not refresh at peer capacity")
	}
	if state.reserveProofs([]string{"proof-0"}, now) {
		t.Fatal("old proof survived replacement at peer capacity")
	}
	if !state.reserveProofs([]string{"replacement"}, now) {
		t.Fatal("replacement proof was not usable")
	}
}
func TestLoginCAPTCHAPayloadLengthLimits(t *testing.T) {
	valid := &dto.CAPTCHAPayload{Algorithm: "SHA-256", Challenge: "c", Salt: "s", Signature: "sig"}
	if !loginCAPTCHAPayloadSizeAllowed(valid) {
		t.Fatal("normal payload rejected")
	}
	cases := []*dto.CAPTCHAPayload{
		{Algorithm: strings.Repeat("a", loginCAPTCHAMaxFieldLength+1)},
		{Receipt: strings.Repeat("r", loginCAPTCHAMaxTokenLength+1)},
		{Slider: &dto.SliderCAPTCHAPayload{Token: strings.Repeat("t", loginCAPTCHAMaxTokenLength+1)}},
		{Slider: &dto.SliderCAPTCHAPayload{Track: strings.Repeat("x", loginCAPTCHAMaxTrackLength+1)}},
	}
	for i, payload := range cases {
		if loginCAPTCHAPayloadSizeAllowed(payload) {
			t.Fatalf("oversized payload %d was accepted", i)
		}
	}
}
func TestHandlersShareLoginCAPTCHAProofReceiptAndFailureState(t *testing.T) {
	shared := NewAuthState()
	first := &Handler{}
	second := &Handler{}
	ApplyAuthState(first, shared)
	ApplyAuthState(second, shared)
	now := time.Now().UTC()

	proof := "shared-proof"
	if !first.loginCAPTCHATracker().registerProofsForClient("owner", "peer", []string{proof}, now.Add(time.Minute), now) {
		t.Fatal("first handler failed to register proof")
	}
	if !second.loginCAPTCHATracker().reserveProofs([]string{proof}, now) {
		t.Fatal("second handler could not reserve shared proof")
	}
	first.loginCAPTCHATracker().finishProofs([]string{proof}, true, now)
	if second.loginCAPTCHATracker().reserveProofs([]string{proof}, now) {
		t.Fatal("used proof was reusable through second handler")
	}

	receipt := "shared-receipt"
	if !first.loginCAPTCHATracker().storeReceiptForClient("owner", "peer", receipt, now.Add(time.Minute), now) {
		t.Fatal("first handler failed to store receipt")
	}
	if !second.loginCAPTCHATracker().consumeReceiptForClient("owner", "peer", receipt, now) {
		t.Fatal("second handler could not consume shared receipt")
	}
	if first.loginCAPTCHATracker().consumeReceiptForClient("owner", "peer", receipt, now) {
		t.Fatal("consumed receipt was reusable through first handler")
	}

	failureKey := "ip:203.0.113.8"
	for index := 0; index < loginRateLimitMaxFailures; index++ {
		first.loginCAPTCHATracker().recordLoginFailure([]string{failureKey}, now)
	}
	if second.loginCAPTCHATracker().loginAttemptAllowed([]string{failureKey}, now) {
		t.Fatal("second handler did not observe shared login failure lock")
	}
}

func TestLoginCAPTCHAIssuanceReservationEnforcesLimitsBeforeGeneration(t *testing.T) {
	state := newLoginCAPTCHAState()
	state.issuance.limits = loginCAPTCHAIssuanceLimits{
		concurrentGlobal: 2,
		concurrentOwner:  1,
		concurrentPeer:   1,
		rateGlobal:       4,
		rateOwner:        2,
		ratePeer:         2,
		rateWindow:       time.Minute,
		reservationTTL:   10 * time.Second,
	}
	now := time.Now().UTC()

	first, ok := state.reserveIssuance("owner-a", "peer-a", 2, now)
	if !ok {
		t.Fatal("first issuance reservation was rejected")
	}
	if _, ok = state.reserveIssuance("owner-a", "peer-b", 1, now); ok {
		t.Fatal("same owner exceeded the pre-generation concurrency limit")
	}
	if _, ok = state.reserveIssuance("owner-b", "peer-a", 1, now); ok {
		t.Fatal("same peer exceeded the pre-generation concurrency limit")
	}
	second, ok := state.reserveIssuance("owner-b", "peer-b", 1, now)
	if !ok {
		t.Fatal("independent owner and peer could not reserve remaining global capacity")
	}
	if _, ok = state.reserveIssuance("owner-c", "peer-c", 1, now); ok {
		t.Fatal("global pre-generation concurrency limit was exceeded")
	}

	state.rollbackIssuance(first)
	state.rollbackIssuance(second)
	if len(state.issuance.reservations) != 0 || len(state.issuance.rates) != 0 {
		t.Fatalf("rollback leaked issuance state: reservations=%d rates=%d", len(state.issuance.reservations), len(state.issuance.rates))
	}
	if _, ok = state.reserveIssuance("owner-c", "peer-c", 1, now); !ok {
		t.Fatal("rolled-back reservation continued consuming capacity or rate quota")
	}
}

func TestLoginCAPTCHAIssuanceRollbackRestoresPreviousProof(t *testing.T) {
	state := newLoginCAPTCHAState()
	now := time.Now().UTC()
	oldKey := "old-proof"
	if !state.registerProofsForClient("owner", "peer", []string{oldKey}, now.Add(time.Minute), now) {
		t.Fatal("failed to register the existing proof")
	}
	id, ok := state.reserveIssuance("owner", "peer", 1, now)
	if !ok {
		t.Fatal("failed to reserve replacement issuance")
	}
	if !state.stageIssuance(id, []string{"new-proof"}, now.Add(time.Minute), now) {
		t.Fatal("failed to stage replacement proof")
	}
	if _, exists := state.proofs[oldKey]; exists {
		t.Fatal("old proof remained published while replacement was staged")
	}
	state.rollbackIssuance(id)
	if _, exists := state.proofs["new-proof"]; exists {
		t.Fatal("rolled-back replacement proof remained published")
	}
	if _, exists := state.proofs[oldKey]; !exists {
		t.Fatal("rollback did not restore the previous proof")
	}
}

func TestLoginCAPTCHAIssuanceFinalizeKeepsBoundedRateRecord(t *testing.T) {
	state := newLoginCAPTCHAState()
	state.issuance.limits = loginCAPTCHAIssuanceLimits{
		concurrentGlobal: 1,
		concurrentOwner:  1,
		concurrentPeer:   1,
		rateGlobal:       1,
		rateOwner:        1,
		ratePeer:         1,
		rateWindow:       time.Minute,
		reservationTTL:   10 * time.Second,
	}
	now := time.Now().UTC()
	id, ok := state.reserveIssuance("owner", "peer", 1, now)
	if !ok || !state.stageIssuance(id, []string{"proof"}, now.Add(time.Minute), now) || !state.finalizeIssuance(id) {
		t.Fatal("issuance could not be reserved, staged, and finalized")
	}
	if len(state.issuance.reservations) != 0 || len(state.issuance.rates) != 1 {
		t.Fatalf("unexpected finalized state: reservations=%d rates=%d", len(state.issuance.reservations), len(state.issuance.rates))
	}
	if _, ok = state.reserveIssuance("owner", "peer", 1, now.Add(time.Second)); ok {
		t.Fatal("finalized issuance did not consume the bounded rate window")
	}
	if _, ok = state.reserveIssuance("owner", "peer", 1, now.Add(time.Minute+time.Second)); !ok {
		t.Fatal("expired issuance rate record was not pruned")
	}
}

func TestLoginCAPTCHACanceledIssueDoesNotPublishProof(t *testing.T) {
	cfg := config.Default()
	cfg.Console.Login.CAPTCHA.Enabled = true
	cfg.Console.Login.CAPTCHA.Mode = "pow"
	h := &Handler{Config: &cfg, Secret: "canceled-issue-secret", LoginCAPTCHAState: newLoginCAPTCHAState()}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest(http.MethodPost, "/api/auth/captcha", bytes.NewBufferString(`{}`)).WithContext(ctx)
	req.RemoteAddr = "192.0.2.90:41234"
	h.LoginCAPTCHA(httptest.NewRecorder(), req)

	h.LoginCAPTCHAState.mu.Lock()
	proofCount := len(h.LoginCAPTCHAState.proofs)
	h.LoginCAPTCHAState.mu.Unlock()
	if proofCount != 0 {
		t.Fatalf("canceled issue published %d proofs", proofCount)
	}
}

func TestLoginCAPTCHAResponseWriteFailureDoesNotPublishProof(t *testing.T) {
	cfg := config.Default()
	cfg.Console.Login.CAPTCHA.Enabled = true
	cfg.Console.Login.CAPTCHA.Mode = "pow"
	h := &Handler{Config: &cfg, Secret: "write-failure-secret", LoginCAPTCHAState: newLoginCAPTCHAState()}

	req := httptest.NewRequest(http.MethodPost, "/api/auth/captcha", bytes.NewBufferString(`{}`))
	req.RemoteAddr = "192.0.2.91:41234"
	h.LoginCAPTCHA(&loginCAPTCHAFailingResponseWriter{header: make(http.Header)}, req)

	h.LoginCAPTCHAState.mu.Lock()
	proofCount := len(h.LoginCAPTCHAState.proofs)
	h.LoginCAPTCHAState.mu.Unlock()
	if proofCount != 0 {
		t.Fatalf("failed response write published %d proofs", proofCount)
	}
}

type loginCAPTCHAFailingResponseWriter struct {
	header http.Header
}

func (w *loginCAPTCHAFailingResponseWriter) Header() http.Header {
	return w.header
}

func (*loginCAPTCHAFailingResponseWriter) Write([]byte) (int, error) {
	return 0, errors.New("forced response write failure")
}

func (*loginCAPTCHAFailingResponseWriter) WriteHeader(int) {}
