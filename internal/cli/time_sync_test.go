package cli

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

func TestTimekeeperConfigFromConfig(t *testing.T) {
	source := config.TimeSyncConfig{
		Enabled:            true,
		Sources:            []string{"primary.example", "backup.example"},
		SelectionInterval:  24 * time.Hour,
		SyncInterval:       30 * time.Minute,
		Timeout:            2 * time.Second,
		SamplesPerSource:   3,
		MaxAcceptedOffset:  5 * time.Minute,
		MaxRootDispersion:  2 * time.Second,
		ConsensusTolerance: 250 * time.Millisecond,
	}

	got := timekeeperConfigFromConfig(source)
	if !got.Enabled || got.ReselectInterval != source.SelectionInterval || got.SyncInterval != source.SyncInterval || got.QueryTimeout != source.Timeout || got.SamplesPerSource != source.SamplesPerSource || got.MaxAcceptedOffset != source.MaxAcceptedOffset || got.MaxRootDispersion != source.MaxRootDispersion || got.ConsistencyThreshold != source.ConsensusTolerance {
		t.Fatalf("unexpected mapped config: %#v", got)
	}
	if len(got.Sources) != 2 || got.Sources[0] != source.Sources[0] || got.Sources[1] != source.Sources[1] {
		t.Fatalf("unexpected mapped sources: %#v", got.Sources)
	}
	source.Sources[0] = "changed.example"
	if got.Sources[0] == source.Sources[0] {
		t.Fatal("mapped sources alias the mutable application config")
	}
}

func TestAdminEntryCookieUsesInjectedClock(t *testing.T) {
	fixed := time.Date(2026, time.July, 15, 12, 0, 0, 0, time.UTC)
	request := httptest.NewRequest("GET", "https://console.example/secure-entry", nil)
	request.Header.Set("User-Agent", "clock-test")
	response := httptest.NewRecorder()

	if !issueAdminEntryCookieAt(response, request, "cw_entry", "test-secret", func() time.Time { return fixed }) {
		t.Fatal("issue admin entry cookie")
	}
	result := response.Result()
	cookies := result.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected one cookie, got %d", len(cookies))
	}
	wantExpiry := fixed.Add(config.AdminSessionTTL)
	if !cookies[0].Expires.Equal(wantExpiry) {
		t.Fatalf("cookie expiry = %s, want %s", cookies[0].Expires, wantExpiry)
	}
	request.AddCookie(cookies[0])
	if !validAdminEntryCookie(request, "cw_entry", "test-secret", func() time.Time { return fixed.Add(time.Second) }) {
		t.Fatal("cookie should validate against the injected clock")
	}
}
