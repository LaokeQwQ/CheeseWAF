package cli

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

func TestAdminSecurityEntryPreservesOnlyFirstSiteReturnTarget(t *testing.T) {
	cfg := config.Default()
	cfg.Console.Login.SecurityEntry.Enabled = true
	cfg.Console.Login.SecurityEntry.Path = "/AdminEntry123"
	cfg.Console.Login.SecurityEntry.CookieName = "cw_entry_return_test"
	const secret = "security-entry-return-test-secret"
	now := func() time.Time { return time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC) }

	for _, tc := range []struct {
		name     string
		query    string
		location string
	}{
		{name: "first site", query: "returnTo=%2Fsites", location: "/login?returnTo=%2Fsites"},
		{name: "literal first site", query: "returnTo=/sites", location: "/login?returnTo=%2Fsites"},
		{name: "no target", location: "/login"},
		{name: "external URL", query: "returnTo=https%3A%2F%2Fevil.example", location: "/login"},
		{name: "network path", query: "returnTo=%2F%2Fevil.example", location: "/login"},
		{name: "backslash", query: "returnTo=%2F%5Cevil.example", location: "/login"},
		{name: "double encoded target", query: "returnTo=%252Fsites", location: "/login"},
		{name: "double encoded network path", query: "returnTo=%252F%252Fevil.example", location: "/login"},
		{name: "relative target", query: "returnTo=sites", location: "/login"},
		{name: "other internal target", query: "returnTo=%2Fai", location: "/login"},
		{name: "first site with query", query: "returnTo=%2Fsites%3Fnext%3Dhttps%3A%2F%2Fevil.example", location: "/login"},
		{name: "first site with fragment", query: "returnTo=%2Fsites%23next", location: "/login"},
		{name: "traversal", query: "returnTo=%2Fother%2F..%2Fsites", location: "/login"},
		{name: "header injection", query: "returnTo=%2Fsites%0D%0ALocation%3Ahttps%3A%2F%2Fevil.example", location: "/login"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entryRequest := httptest.NewRequest(http.MethodGet, cfg.Console.Login.SecurityEntry.Path+"?"+tc.query, nil)
			entry := httptest.NewRecorder()
			if allowAdminEntranceAt(&cfg, secret, "/metrics", false, entry, entryRequest, now) {
				t.Fatal("security entry must issue a redirect instead of serving the console")
			}
			if entry.Code != http.StatusFound || entry.Header().Get("Location") != tc.location {
				t.Fatalf("entry returned %d Location %q, want %d Location %q", entry.Code, entry.Header().Get("Location"), http.StatusFound, tc.location)
			}
			cookies := entry.Result().Cookies()
			if len(cookies) != 1 || cookies[0].Name != cfg.Console.Login.SecurityEntry.CookieName || !cookies[0].HttpOnly {
				t.Fatalf("entry must mint one HttpOnly gate cookie, got %+v", cookies)
			}
			loginRequest := httptest.NewRequest(http.MethodGet, tc.location, nil)
			loginRequest.AddCookie(cookies[0])
			if !allowAdminEntranceAt(&cfg, secret, "/metrics", false, httptest.NewRecorder(), loginRequest, now) {
				t.Fatal("entry cookie did not authorize the login destination")
			}
		})
	}
}
