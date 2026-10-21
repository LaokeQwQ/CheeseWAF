package bot

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

func TestPolicyMatrixViewsRetainProtectedScopesAndNarrowExemptions(t *testing.T) {
	for _, tc := range []struct {
		name       string
		path       string
		protected  string
		exempt     string
		additional string
		challenge  bool
	}{
		{name: "matrix protected scope", path: "/admin;v=1/panel", protected: "/admin", exempt: "/health", challenge: true},
		{name: "matrix protected additional identity", path: "/outside", protected: "/admin", exempt: "/health", additional: "/admin;v=1/panel", challenge: true},
		{name: "matrix before dot collapse", path: "/public/.;v=1/../admin/panel", protected: "/admin", exempt: "/health", challenge: true},
		{name: "encoded matrix before dot collapse", path: "/public/.%3bv=1/../admin/panel", protected: "/admin", exempt: "/health", challenge: true},
		{name: "matrix before dot collapse in additional identity", path: "/outside", protected: "/admin", exempt: "/health", additional: "/public/.;v=1/../admin/panel", challenge: true},
		{name: "matrix before dot collapse cannot reuse old exemption", path: "/health/.;v=1/../admin/panel", protected: "/admin", exempt: "/health", challenge: true},
		{name: "old matrix deny remains", path: "/admin;v=1/panel", protected: "/admin;v=1", exempt: "/health", challenge: true},
		{name: "new matrix view cannot grant exemption", path: "/health;v=1/ready", protected: "/", exempt: "/health", challenge: true},
		{name: "old matrix exemption cannot hide another interpretation", path: "/health;v=1/ready", protected: "/", exempt: "/health;v=1", challenge: true},
		{name: "exemption requires agreement even with narrow protected scope", path: "/admin;v=1/panel", protected: "/admin;v=1", exempt: "/admin;v=1", challenge: true},
		{name: "ordinary exemption remains", path: "/health/ready", protected: "/", exempt: "/health", challenge: false},
		{name: "old cleaned exemption remains", path: "/admin/../health/ready", protected: "/", exempt: "/health", challenge: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := NewPolicy(config.BotProtectionConfig{
				Enabled: true, JSChallenge: true, Secret: "test-secret",
				PathPrefixes: []string{tc.protected}, ExemptPathPrefixes: []string{tc.exempt},
			})
			req := httptest.NewRequest(http.MethodGet, "https://example.test"+tc.path, nil)
			req.Header.Set("User-Agent", "curl/8.0")
			var additional []string
			if tc.additional != "" {
				additional = append(additional, tc.additional)
			}
			got := p.EvaluateForSiteWithWaitingRoomAndPaths(req, "203.0.113.10", "site", false, additional...)
			if tc.challenge && (got == nil || !got.Detected || got.Action != engine.ActionChallenge) {
				t.Fatalf("protected interpretation escaped bot scope: %+v", got)
			}
			if !tc.challenge && got != nil {
				t.Fatalf("unchanged exempt interpretation triggered bot detection: %+v", got)
			}
		})
	}
}

func TestPolicyMatrixViewsKeepPublicClearanceBinding(t *testing.T) {
	p := newRewriteScopePolicy()
	public := httptest.NewRequest(http.MethodGet, "https://example.test/outside;v=1", nil)
	public.Header.Set("User-Agent", "curl/8.0")
	value, _, err := p.issueClearanceForSite(public, "203.0.113.10", "site")
	if err != nil {
		t.Fatal(err)
	}
	public.AddCookie(&http.Cookie{Name: p.cookieName, Value: value})
	if got := p.EvaluateForSiteWithWaitingRoomAndPaths(public, "203.0.113.10", "site", false, "/protected;v=1"); got != nil {
		t.Fatalf("matrix scope changed original clearance binding: %+v", got)
	}
	other := httptest.NewRequest(http.MethodGet, "https://example.test/outside", nil)
	other.Header = public.Header.Clone()
	if got := p.EvaluateForSiteWithWaitingRoomAndPaths(other, "203.0.113.10", "site", false, "/protected;v=1"); got == nil {
		t.Fatal("matrix clearance widened to another original path")
	}
}

func TestPolicyMatrixViewsEvaluateWaitingTicketOnce(t *testing.T) {
	p := newRewriteScopePolicy()
	p.failureTracker = nil
	p.waitingRoomMaxActive = 1
	public := httptest.NewRequest(http.MethodGet, "https://example.test/protected;v=1", nil)
	public.Header.Set("User-Agent", "curl/8.0")
	ticket, _, admitted, _, _ := p.waitingTicket(public, "203.0.113.10")
	if !admitted {
		t.Fatal("initial waiting-room ticket was not admitted")
	}
	public.AddCookie(&http.Cookie{Name: p.waitingCookieName, Value: ticket})
	fixedNow := p.now()
	clockReads := 0
	p.now = func() time.Time { clockReads++; return fixedNow }
	got := p.EvaluateForSiteWithWaitingRoomAndPaths(public, "203.0.113.10", "site", true, "/protected;x=2", "/health")
	if got == nil || got.Category != "bot" {
		t.Fatalf("valid waiting ticket did not reach bot evaluation: %+v", got)
	}
	if clockReads != 1 || len(p.active) != 1 {
		t.Fatalf("waiting ticket evaluated %d times with %d admissions, want 1 each", clockReads, len(p.active))
	}
}
