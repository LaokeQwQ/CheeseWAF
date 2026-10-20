package bot

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

func newRewriteScopePolicy() *Policy {
	return NewPolicy(config.BotProtectionConfig{
		Enabled: true, JSChallenge: true, Secret: strings.Repeat("s", 48),
		PathPrefixes: []string{"/protected"}, ExemptPathPrefixes: []string{"/health"},
	})
}

func TestPolicyRequestPathsUseUnionOfProtectedScopes(t *testing.T) {
	for _, tc := range []struct {
		public, target string
		applies        bool
	}{
		{"/protected", "/health", true},
		{"/protected", "/outside", true},
		{"/health", "/protected", true},
		{"/outside", "/protected", true},
		{"/health", "/health/ready", false},
		{"/outside", "/health", false},
	} {
		t.Run(tc.public+" to "+tc.target, func(t *testing.T) {
			p := newRewriteScopePolicy()
			req := httptest.NewRequest(http.MethodGet, "https://example.test"+tc.public, nil)
			req.Header.Set("User-Agent", "curl/8.0")
			result := p.EvaluateForSiteWithWaitingRoomAndPaths(req, "203.0.113.10", "site", false, tc.target)
			if tc.applies && (result == nil || !result.Detected || result.Action != engine.ActionChallenge) {
				t.Fatalf("protected scope was lost: %+v", result)
			}
			if !tc.applies && result != nil {
				t.Fatalf("both unprotected identities triggered a bot result: %+v", result)
			}
		})
	}
}

func TestPolicyAdditionalPathDoesNotChangePublicClearanceBinding(t *testing.T) {
	p := newRewriteScopePolicy()
	public := httptest.NewRequest(http.MethodGet, "https://example.test/health", nil)
	public.Header.Set("User-Agent", "curl/8.0")
	clearance, _, err := p.issueClearanceForSite(public, "203.0.113.10", "site")
	if err != nil {
		t.Fatal(err)
	}
	public.AddCookie(&http.Cookie{Name: p.cookieName, Value: clearance})
	if result := p.EvaluateForSiteWithWaitingRoomAndPaths(public, "203.0.113.10", "site", false, "/protected"); result != nil {
		t.Fatalf("public clearance was evaluated against the target path: %+v", result)
	}
	target := httptest.NewRequest(http.MethodGet, "https://example.test/protected", nil)
	target.Header = public.Header.Clone()
	if result := p.EvaluateForSite(target, "203.0.113.10", "site"); result == nil {
		t.Fatal("public clearance was widened to the target path")
	}
}

func TestPolicyRequestPathsEvaluateWaitingTicketOnce(t *testing.T) {
	p := newRewriteScopePolicy()
	p.failureTracker = nil
	p.waitingRoomMaxActive = 1
	public := httptest.NewRequest(http.MethodGet, "https://example.test/protected", nil)
	public.Header.Set("User-Agent", "curl/8.0")
	ticket, _, admitted, _, _ := p.waitingTicket(public, "203.0.113.10")
	if !admitted {
		t.Fatal("initial waiting-room ticket was not admitted")
	}
	public.AddCookie(&http.Cookie{Name: p.waitingCookieName, Value: ticket})
	fixedNow := p.now()
	clockReads := 0
	p.now = func() time.Time { clockReads++; return fixedNow }
	result := p.EvaluateForSiteWithWaitingRoomAndPaths(public, "203.0.113.10", "site", true, "/protected/target", "/health", "/protected")
	if result == nil || result.Category != "bot" {
		t.Fatalf("valid waiting ticket did not proceed to the single bot evaluation: %+v", result)
	}
	if clockReads != 1 || len(p.active) != 1 {
		t.Fatalf("waiting-room ticket evaluated %d times with %d admissions, want 1 each", clockReads, len(p.active))
	}
}
