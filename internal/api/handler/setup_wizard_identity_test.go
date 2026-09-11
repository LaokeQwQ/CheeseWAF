package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/setup"
)

func TestSetupDraftPatchRejectsNonCanonicalUsernameWithoutMutatingDraft(t *testing.T) {
	for _, username := range []string{" admin", "admin ", "ad\tmin", "ad\u200bmin"} {
		t.Run(username, func(t *testing.T) {
			cfg := config.Default()
			cfg.Setup.DataDir = t.TempDir()
			drafts := setup.NewDraftStore(time.Minute)
			draft, err := drafts.Create()
			if err != nil {
				t.Fatalf("create draft: %v", err)
			}
			if _, ok := drafts.Update(draft.ID, func(current *setup.SetupDraft) {
				current.Username = "admin"
				current.Profile = setup.ProfileLow
			}); !ok {
				t.Fatal("seed draft")
			}
			if !drafts.SetPassword(draft.ID, "Original-Password-9!") {
				t.Fatal("seed draft password")
			}
			h := New(Options{Config: &cfg, SetupDrafts: drafts, SetupToken: "local-setup-secret"})

			body, err := json.Marshal(map[string]any{
				"username":  username,
				"password":  "Replacement-Password-9!",
				"profile":   string(setup.ProfileHigh),
				"confirmed": true,
			})
			if err != nil {
				t.Fatalf("marshal patch: %v", err)
			}
			request := httptest.NewRequest(http.MethodPatch, "/api/setup/draft", bytes.NewReader(body))
			request.RemoteAddr = "127.0.0.1:1234"
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("X-CheeseWAF-Setup-Token", "local-setup-secret")
			request.AddCookie(&http.Cookie{Name: setup.SetupSessionCookie, Value: draft.ID})
			response := httptest.NewRecorder()

			h.SetupDraftPatch(response, request)

			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d: %s", response.Code, http.StatusBadRequest, response.Body.String())
			}
			if !strings.Contains(response.Body.String(), `"code":"USERNAME_INVALID"`) {
				t.Fatalf("response did not report USERNAME_INVALID: %s", response.Body.String())
			}
			stored, ok := drafts.Get(draft.ID)
			if !ok {
				t.Fatal("draft disappeared after rejected patch")
			}
			if stored.Username != "admin" || stored.Profile != setup.ProfileLow || stored.Confirmed {
				t.Fatalf("rejected patch mutated draft: %+v", stored)
			}
			password, ok := drafts.Password(draft.ID)
			if !ok || password != "Original-Password-9!" {
				t.Fatalf("rejected patch mutated password: password=%q set=%v", password, ok)
			}
		})
	}
}

func TestSetupDraftPatchAllowsEmptyUsernameAsNoOp(t *testing.T) {
	cfg := config.Default()
	cfg.Setup.DataDir = t.TempDir()
	drafts := setup.NewDraftStore(time.Minute)
	draft, err := drafts.Create()
	if err != nil {
		t.Fatalf("create draft: %v", err)
	}
	h := New(Options{Config: &cfg, SetupDrafts: drafts, SetupToken: "local-setup-secret"})
	request := httptest.NewRequest(http.MethodPatch, "/api/setup/draft", strings.NewReader(`{"username":"","profile":"medium"}`))
	request.RemoteAddr = "127.0.0.1:1234"
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-CheeseWAF-Setup-Token", "local-setup-secret")
	request.AddCookie(&http.Cookie{Name: setup.SetupSessionCookie, Value: draft.ID})
	response := httptest.NewRecorder()

	h.SetupDraftPatch(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", response.Code, http.StatusOK, response.Body.String())
	}
	stored, ok := drafts.Get(draft.ID)
	if !ok {
		t.Fatal("draft disappeared after patch")
	}
	if stored.Username != "" || stored.Profile != setup.ProfileMedium {
		t.Fatalf("empty username was not a no-op: %+v", stored)
	}
}
