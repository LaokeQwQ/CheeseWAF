package api

import (
	"fmt"
	"net/http"
	"testing"
)

func TestLoginCAPTCHAFailuresRespectSourceBoundaries(t *testing.T) {
	for _, proof := range []string{"missing", "forged"} {
		t.Run(proof, func(t *testing.T) {
			env := newCHE61Router(t, nil)
			for attempt := 0; attempt < 6; attempt++ {
				payload := map[string]any{"username": fmt.Sprintf("unknown%d", attempt), "password": "wrong"}
				if proof == "forged" {
					payload["captcha"] = map[string]any{"receipt": "forged"}
				}
				response := che61PostJSON(t, env.router, "/api/auth/login", "", payload)
				want := http.StatusUnauthorized
				if attempt == 5 {
					want = http.StatusTooManyRequests
				}
				if response.Code != want {
					t.Fatalf("attempt %d: got %d %s, want %d", attempt+1, response.Code, response.Body.String(), want)
				}
			}
			blocked := che61PostJSON(t, env.router, "/api/auth/login", "", map[string]any{"username": "admin", "password": "admin-password"})
			if blocked.Code != http.StatusTooManyRequests {
				t.Fatalf("same source changed account: got %d, want 429", blocked.Code)
			}
			otherSource := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				r.RemoteAddr = "198.51.100.24:40123"
				env.router.ServeHTTP(w, r)
			})
			client := newCHE61LoginClient(otherSource)
			receipt := che61SolveLoginCAPTCHA(t, client, "admin")
			response := client.perform(http.MethodPost, "/api/auth/login", mustJSON(t, map[string]any{"username": "admin", "password": "admin-password", "captcha": receipt}))
			if response.Code != http.StatusOK {
				t.Fatalf("other source valid login: got %d %s", response.Code, response.Body.String())
			}
		})
	}
}

func TestLoginCAPTCHAFailuresDoNotLockAccountAcrossSources(t *testing.T) {
	env := newCHE61Router(t, nil)
	for attempt := 0; attempt < 6; attempt++ {
		che61PostJSON(t, env.router, "/api/auth/login", "", map[string]any{"username": "admin", "password": "wrong"})
	}
	otherSource := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.RemoteAddr = "198.51.100.25:40123"
		env.router.ServeHTTP(w, r)
	})
	client := newCHE61LoginClient(otherSource)
	receipt := che61SolveLoginCAPTCHA(t, client, "admin")
	response := client.perform(http.MethodPost, "/api/auth/login", mustJSON(t, map[string]any{"username": "admin", "password": "admin-password", "captcha": receipt}))
	if response.Code != http.StatusOK {
		t.Fatalf("target account from other source: got %d %s", response.Code, response.Body.String())
	}
}
