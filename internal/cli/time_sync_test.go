package cli

import (
	"crypto/tls"
	"net/http"
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

func TestAdminEntryCookieSecureFollowsTLSAndForwardedProto(t *testing.T) {
	now := func() time.Time { return time.Date(2026, time.August, 21, 12, 0, 0, 0, time.UTC) }

	plain := httptest.NewRecorder()
	if !issueAdminEntryCookieAt(plain, httptest.NewRequest(http.MethodGet, "http://127.0.0.1:9443/__cheesewaf-entry", nil), "cw_entry", "test-secret", now) {
		t.Fatal("issue plain HTTP entry cookie")
	}
	plainCookies := plain.Result().Cookies()
	if len(plainCookies) != 1 || plainCookies[0].Secure {
		t.Fatalf("plain HTTP entry cookie must omit Secure, got %+v", plainCookies)
	}

	httpsReq := httptest.NewRequest(http.MethodGet, "https://127.0.0.1:9443/__cheesewaf-entry", nil)
	httpsReq.TLS = &tls.ConnectionState{}
	secureRec := httptest.NewRecorder()
	if !issueAdminEntryCookieAt(secureRec, httpsReq, "cw_entry", "test-secret", now) {
		t.Fatal("issue TLS entry cookie")
	}
	secureCookies := secureRec.Result().Cookies()
	if len(secureCookies) != 1 || !secureCookies[0].Secure {
		t.Fatalf("TLS entry cookie must set Secure, got %+v", secureCookies)
	}

	proxied := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:9443/__cheesewaf-entry", nil)
	proxied.RemoteAddr = "10.0.0.5:1234" // private proxy peer; only trusted peers may flip Secure via XFP
	proxied.Header.Set("X-Forwarded-Proto", "https")
	proxyRec := httptest.NewRecorder()
	if !issueAdminEntryCookieAt(proxyRec, proxied, "cw_entry", "test-secret", now) {
		t.Fatal("issue proxied HTTPS entry cookie")
	}
	proxyCookies := proxyRec.Result().Cookies()
	if len(proxyCookies) != 1 || !proxyCookies[0].Secure {
		t.Fatalf("X-Forwarded-Proto=https from a private peer must set Secure, got %+v", proxyCookies)
	}

	publicProxied := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:9443/__cheesewaf-entry", nil)
	publicProxied.RemoteAddr = "203.0.113.7:1234" // public peer must not flip Secure
	publicProxied.Header.Set("X-Forwarded-Proto", "https")
	publicRec := httptest.NewRecorder()
	if !issueAdminEntryCookieAt(publicRec, publicProxied, "cw_entry", "test-secret", now) {
		t.Fatal("issue public proxied entry cookie")
	}
	publicCookies := publicRec.Result().Cookies()
	if len(publicCookies) != 1 || publicCookies[0].Secure {
		t.Fatalf("public peer X-Forwarded-Proto=https must not set Secure, got %+v", publicCookies)
	}
}
