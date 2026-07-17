package proxy

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
	"golang.org/x/net/html"
)

const (
	bug067068Host                 = "localhost"
	bug067068UserAgent            = "curl/8.12.1"
	bug067068CookieName           = "cw_bug067068_clearance"
	bug067068BehaviorOwnerQuota   = 8
	bug067068PoWSolutionSearchMax = 1 << 20
)

var (
	bug067068PoWHeaderPattern = regexp.MustCompile(`(?:^|,\s*)CheeseWAF-Compute\s+challenge="([^"]+)",\s*target=([0-9]+)`)
	bug067068BehaviorState    = regexp.MustCompile(`const S=(\{.*\});\s*\n`)
)

type bug067068ProxyFixture struct {
	handler      http.Handler
	upstream     *httptest.Server
	upstreamHits atomic.Int64
}

type bug067068PoWChallenge struct {
	token string
	work  int
}

type bug067068BehaviorPageState struct {
	Challenge struct {
		Type  string `json:"type"`
		Token string `json:"token"`
	} `json:"challenge"`
	ReturnURL string `json:"returnURL"`
}

func TestBUG067JSOnlyPoWProxyClearanceFlow(t *testing.T) {
	fixture := newBUG067068ProxyFixture(t, func(cfg *config.Config) {
		cfg.Sites[0].ID = bug067068Host
		cfg.Protection.Bot.JSChallenge = true
		cfg.Protection.Bot.CAPTCHA = false
	})

	assertBUG067068PoWClearanceFlow(t, fixture, "/js-only", "198.51.100.10")
}

func TestBUG067SiteIDBindingProxyClearanceFlow(t *testing.T) {
	fixture := newBUG067068ProxyFixture(t, func(cfg *config.Config) {
		cfg.Sites[0].ID = "site-uuid"
		cfg.Protection.Bot.JSChallenge = true
		cfg.Protection.Bot.CAPTCHA = false
	})

	assertBUG067068PoWClearanceFlow(t, fixture, "/site-bound", "198.51.100.11")
}

func TestBUG067ChallengeReturnPathsStaySiteRelative(t *testing.T) {
	targets := []struct {
		name   string
		target string
	}{
		{name: "scheme_relative", target: "//evil.example/path"},
		{name: "encoded_backslashes", target: "/%5C%5Cevil.example/path"},
	}

	for _, tc := range targets {
		t.Run(tc.name, func(t *testing.T) {
			t.Run("ordinary_form", func(t *testing.T) {
				fixture := newBUG067068ProxyFixture(t, func(cfg *config.Config) {
					cfg.Sites[0].ID = bug067068Host
					cfg.Protection.Bot.JSChallenge = false
					cfg.Protection.Bot.CAPTCHA = true
					cfg.Protection.Bot.CAPTCHAType = "image"
					cfg.Protection.Bot.CAPTCHATypes = nil
					cfg.Protection.Bot.CAPTCHAEscalationTypes = nil
					cfg.Protection.Bot.ImageCAPTCHALength = 4
					cfg.Protection.Bot.ImageCAPTCHAWidth = 120
					cfg.Protection.Bot.ImageCAPTCHAHeight = 48
				})

				rec := fixture.request(http.MethodGet, tc.target, "198.51.100.20", bug067068UserAgent, nil)
				if rec.Code != http.StatusForbidden {
					t.Fatalf("challenge status=%d body=%q", rec.Code, rec.Body.String())
				}
				action, err := bug067068FirstFormAction(rec.Body.String())
				if err != nil {
					t.Fatal(err)
				}
				if action != "/" {
					t.Fatalf("form action=%q, want normalized site path /", action)
				}
			})

			t.Run("behavior_state", func(t *testing.T) {
				fixture := newBUG067068ProxyFixture(t, configureBUG067068Behavior)
				rec := fixture.request(http.MethodGet, tc.target, "198.51.100.21", bug067068UserAgent, nil)
				if rec.Code != http.StatusForbidden {
					t.Fatalf("challenge status=%d body=%q", rec.Code, rec.Body.String())
				}
				state, err := bug067068ParseBehaviorState(rec.Body.String())
				if err != nil {
					t.Fatal(err)
				}
				if state.ReturnURL != "/" {
					t.Fatalf("behavior returnURL=%q, want normalized site path /", state.ReturnURL)
				}
				if state.Challenge.Token == "" {
					t.Fatal("behavior challenge token is empty")
				}
			})

			t.Run("pow_post_redirect", func(t *testing.T) {
				fixture := newBUG067068ProxyFixture(t, func(cfg *config.Config) {
					cfg.Sites[0].ID = bug067068Host
					cfg.Protection.Bot.JSChallenge = false
					cfg.Protection.Bot.CAPTCHA = true
					cfg.Protection.Bot.CAPTCHAType = "pow"
					cfg.Protection.Bot.CAPTCHATypes = nil
					cfg.Protection.Bot.CAPTCHAEscalationTypes = nil
				})
				issued := fixture.request(http.MethodGet, tc.target, "198.51.100.22", bug067068UserAgent, nil)
				challenge := requireBUG067068PoWChallenge(t, issued)
				answer := solveBUG067068PoW(t, challenge)

				form := url.Values{"cw_pow_token": {challenge.token}, "cw_pow_answer": {answer}}
				verified := fixture.request(http.MethodPost, "/", "198.51.100.22", bug067068UserAgent, form)
				if verified.Code != http.StatusSeeOther {
					t.Fatalf("normalized-path verification status=%d location=%q, want 303 redirect to /", verified.Code, verified.Header().Get("Location"))
				}
				if location := verified.Header().Get("Location"); location != "/" {
					t.Fatalf("redirect location=%q, want normalized site path /", location)
				}
				if cookie := bug067068ResponseCookie(verified, bug067068CookieName); cookie == nil || cookie.Value == "" {
					t.Fatal("successful normalized-path verification did not issue clearance")
				}
			})
		})
	}
}

func TestBUG068ConsumedPoWOwnerCannotExhaustOtherOwner(t *testing.T) {
	const capacity = 3
	fixture := newBUG067068ProxyFixture(t, func(cfg *config.Config) {
		cfg.Sites[0].ID = bug067068Host
		cfg.Protection.Bot.JSChallenge = false
		cfg.Protection.Bot.CAPTCHA = true
		cfg.Protection.Bot.CAPTCHAType = "pow"
		cfg.Protection.Bot.CAPTCHATypes = nil
		cfg.Protection.Bot.CAPTCHAEscalationTypes = nil
		cfg.Protection.Bot.ClearanceStateCapacity = capacity
	})

	for i := 0; i < capacity; i++ {
		issued := fixture.request(http.MethodGet, "/capacity", "198.51.100.30", bug067068UserAgent, nil)
		challenge := requireBUG067068PoWChallenge(t, issued)
		answer := solveBUG067068PoW(t, challenge)
		form := url.Values{"cw_pow_token": {challenge.token}, "cw_pow_answer": {answer}}
		verified := fixture.request(http.MethodPost, "/capacity", "198.51.100.30", bug067068UserAgent, form)
		if verified.Code != http.StatusSeeOther {
			t.Fatalf("owner A cycle %d status=%d body=%q", i+1, verified.Code, verified.Body.String())
		}
	}

	other := fixture.request(http.MethodGet, "/capacity", "198.51.100.31", bug067068UserAgent, nil)
	challenge := requireBUG067068PoWChallenge(t, other)
	if challenge.token == "" || challenge.work != 1 {
		t.Fatalf("owner B challenge=%+v, want non-empty work-1 challenge", challenge)
	}
	if hits := fixture.upstreamHits.Load(); hits != 0 {
		t.Fatalf("challenge flow reached upstream %d times", hits)
	}
}

func TestBUG068ConcurrentBehaviorRefreshHonorsOwnerQuota(t *testing.T) {
	fixture := newBUG067068ProxyFixture(t, configureBUG067068Behavior)
	prime := fixture.request(http.MethodGet, "/behavior", "198.51.100.40", bug067068UserAgent, nil)
	if prime.Code != http.StatusForbidden {
		t.Fatalf("prime challenge status=%d body=%q", prime.Code, prime.Body.String())
	}
	if _, err := bug067068ParseBehaviorState(prime.Body.String()); err != nil {
		t.Fatal(err)
	}
	ownerCookie := bug067068OnlyResponseCookie(t, prime)

	const concurrentRefreshes = bug067068BehaviorOwnerQuota * 2
	type result struct {
		status int
		body   string
	}
	start := make(chan struct{})
	results := make(chan result, concurrentRefreshes)
	var wg sync.WaitGroup
	for i := 0; i < concurrentRefreshes; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			rec := fixture.request(http.MethodGet, "/behavior", "198.51.100.40", bug067068UserAgent, nil, ownerCookie)
			results <- result{status: rec.Code, body: rec.Body.String()}
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	successes, rejected := 1, 0 // The prime request owns the first pending slot.
	for result := range results {
		switch result.status {
		case http.StatusForbidden:
			state, err := bug067068ParseBehaviorState(result.body)
			if err != nil {
				t.Errorf("successful issuance has no Behavior state: %v", err)
				continue
			}
			if state.Challenge.Token == "" {
				t.Error("successful issuance has an empty Behavior token")
				continue
			}
			successes++
		case http.StatusServiceUnavailable:
			if strings.Contains(result.body, "const S=") {
				t.Error("quota rejection exposed a usable Behavior state")
			}
			rejected++
		default:
			t.Errorf("unexpected refresh status=%d body=%q", result.status, result.body)
		}
	}
	if successes < 2 || successes > bug067068BehaviorOwnerQuota {
		t.Errorf("owner received %d challenges, want between 2 and pending quota %d", successes, bug067068BehaviorOwnerQuota)
	}
	if want := 1 + concurrentRefreshes - successes; rejected != want {
		t.Errorf("quota rejected %d refreshes, want %d for %d successful issues", rejected, want, successes)
	}
	if hits := fixture.upstreamHits.Load(); hits != 0 {
		t.Fatalf("Behavior refresh reached upstream %d times", hits)
	}

	other := fixture.request(http.MethodGet, "/behavior", "198.51.100.41", "curl/8.12.1 owner-b", nil)
	if other.Code != http.StatusForbidden {
		t.Fatalf("owner B status=%d body=%q", other.Code, other.Body.String())
	}
	state, err := bug067068ParseBehaviorState(other.Body.String())
	if err != nil {
		t.Fatal(err)
	}
	if state.Challenge.Token == "" {
		t.Fatal("owner B received an empty Behavior token")
	}
}

func newBUG067068ProxyFixture(t *testing.T, mutate func(*config.Config)) *bug067068ProxyFixture {
	t.Helper()
	fixture := &bug067068ProxyFixture{}
	fixture.upstream = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fixture.upstreamHits.Add(1)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = fmt.Fprintf(w, "upstream:%s", r.URL.RequestURI())
	}))
	t.Cleanup(fixture.upstream.Close)

	cfg := config.Default()
	cfg.Sites[0].ID = bug067068Host
	cfg.Sites[0].Domains = []string{bug067068Host}
	cfg.Sites[0].Upstreams = []config.UpstreamConfig{{Address: fixture.upstream.URL, Weight: 1}}
	cfg.Sites[0].WAF.Response.Enabled = false
	cfg.Protection.Policy = config.ProtectionPolicyConfig{
		WebAttack:   config.ProtectionLevelOff,
		APISecurity: config.ProtectionLevelOff,
		BotCC:       config.ProtectionLevelStrict,
		ThreatIntel: config.ProtectionLevelOff,
	}
	cfg.Protection.IP.Blacklist = nil
	cfg.Protection.IP.Whitelist = nil
	cfg.Protection.IP.AccessRules = nil
	cfg.Protection.IP.ThreatIntel = nil
	cfg.Protection.IP.Providers = nil
	cfg.Protection.RateLimit.Enabled = false
	cfg.Protection.ACL.Enabled = false
	cfg.APISec.Enabled = false

	bot := &cfg.Protection.Bot
	bot.Enabled = true
	bot.Secret = strings.Repeat("s", 48)
	bot.CookieName = bug067068CookieName
	bot.JSChallenge = true
	bot.CAPTCHA = false
	bot.WaitingRoom = false
	bot.ChallengeDifficulty = 1
	bot.PoWMaxDifficulty = 1
	bot.ClearanceStateCapacity = 64
	bot.ChallengeTTL = time.Minute
	bot.CAPTCHAChallengeTTL = time.Minute
	bot.PoWAcceptLegacy = false
	bot.ClearanceAcceptLegacy = false
	bot.RiskLowThreshold = 1
	bot.RiskMediumThreshold = 2
	bot.RiskHighThreshold = 3
	bot.RiskBlockThreshold = 1000
	bot.RiskConfidenceMin = 0.01
	bot.AllowedUserAgents = nil
	bot.SuspiciousUserAgents = []string{"curl"}
	if mutate != nil {
		mutate(&cfg)
	}

	server, err := NewServer(&cfg, engine.NewPipeline(), noopSink{})
	if err != nil {
		t.Fatal(err)
	}
	fixture.handler = server.Handler()
	return fixture
}

func configureBUG067068Behavior(cfg *config.Config) {
	cfg.Sites[0].ID = bug067068Host
	cfg.Protection.Bot.JSChallenge = false
	cfg.Protection.Bot.CAPTCHA = true
	cfg.Protection.Bot.CAPTCHAType = "random"
	cfg.Protection.Bot.CAPTCHATypes = []string{"pow"}
	cfg.Protection.Bot.CAPTCHAEscalationTypes = nil
}

func (f *bug067068ProxyFixture) request(method, target, clientIP, userAgent string, form url.Values, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	var body *strings.Reader
	if form == nil {
		body = strings.NewReader("")
	} else {
		body = strings.NewReader(form.Encode())
	}
	req := httptest.NewRequest(method, "http://"+bug067068Host+target, body)
	req.Host = bug067068Host
	req.RemoteAddr = net.JoinHostPort(clientIP, "43210")
	req.Header.Set("User-Agent", userAgent)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	return rec
}

func assertBUG067068PoWClearanceFlow(t *testing.T, fixture *bug067068ProxyFixture, path, clientIP string) {
	t.Helper()
	issued := fixture.request(http.MethodGet, path, clientIP, bug067068UserAgent, nil)
	challenge := requireBUG067068PoWChallenge(t, issued)
	answer := solveBUG067068PoW(t, challenge)

	form := url.Values{"cw_pow_token": {challenge.token}, "cw_pow_answer": {answer}}
	verified := fixture.request(http.MethodPost, path, clientIP, bug067068UserAgent, form)
	if verified.Code != http.StatusSeeOther {
		t.Fatalf("verification status=%d location=%q body=%q", verified.Code, verified.Header().Get("Location"), verified.Body.String())
	}
	if location := verified.Header().Get("Location"); location != path {
		t.Fatalf("verification redirect=%q, want %q", location, path)
	}
	clearance := bug067068ResponseCookie(verified, bug067068CookieName)
	if clearance == nil || clearance.Value == "" {
		t.Fatal("verification did not issue a non-empty clearance cookie")
	}

	allowed := fixture.request(http.MethodGet, path, clientIP, bug067068UserAgent, nil, clearance)
	if allowed.Code != http.StatusOK {
		t.Fatalf("clearance GET status=%d body=%q", allowed.Code, allowed.Body.String())
	}
	if got, want := allowed.Body.String(), "upstream:"+path; got != want {
		t.Fatalf("upstream response=%q, want %q", got, want)
	}
	if hits := fixture.upstreamHits.Load(); hits != 1 {
		t.Fatalf("upstream hits=%d, want 1", hits)
	}
}

func requireBUG067068PoWChallenge(t *testing.T, rec *httptest.ResponseRecorder) bug067068PoWChallenge {
	t.Helper()
	if rec.Code != http.StatusForbidden {
		t.Fatalf("challenge status=%d body=%q", rec.Code, rec.Body.String())
	}
	challenge, err := parseBUG067068PoWChallenge(rec.Header().Values("WWW-Authenticate"))
	if err != nil {
		t.Fatalf("parse CheeseWAF PoW challenge: %v; headers=%v body=%q", err, rec.Header(), rec.Body.String())
	}
	if challenge.token == "" || challenge.work != 1 {
		t.Fatalf("invalid PoW challenge: %+v", challenge)
	}
	return challenge
}

func parseBUG067068PoWChallenge(headers []string) (bug067068PoWChallenge, error) {
	for _, header := range headers {
		match := bug067068PoWHeaderPattern.FindStringSubmatch(header)
		if len(match) != 3 {
			continue
		}
		work, err := strconv.Atoi(match[2])
		if err != nil {
			return bug067068PoWChallenge{}, fmt.Errorf("invalid target %q: %w", match[2], err)
		}
		return bug067068PoWChallenge{token: match[1], work: work}, nil
	}
	return bug067068PoWChallenge{}, fmt.Errorf("CheeseWAF-Compute challenge is missing")
}

func solveBUG067068PoW(t *testing.T, challenge bug067068PoWChallenge) string {
	t.Helper()
	for i := 0; i < bug067068PoWSolutionSearchMax; i++ {
		answer := strconv.Itoa(i)
		sum := sha256.Sum256([]byte(challenge.token + "\x00" + answer))
		if bug067068HasLeadingZeroNibbles(sum[:], challenge.work) {
			return answer
		}
	}
	t.Fatalf("no PoW solution found within %d attempts for work=%d", bug067068PoWSolutionSearchMax, challenge.work)
	return ""
}

func bug067068HasLeadingZeroNibbles(sum []byte, n int) bool {
	if n < 1 || n > len(sum)*2 {
		return false
	}
	for i := 0; i < n; i++ {
		value := sum[i/2]
		if i%2 == 0 {
			if value>>4 != 0 {
				return false
			}
		} else if value&0x0f != 0 {
			return false
		}
	}
	return true
}

func bug067068ParseBehaviorState(page string) (bug067068BehaviorPageState, error) {
	match := bug067068BehaviorState.FindStringSubmatch(page)
	if len(match) != 2 {
		return bug067068BehaviorPageState{}, fmt.Errorf("Behavior const S state is missing")
	}
	var state bug067068BehaviorPageState
	if err := json.Unmarshal([]byte(match[1]), &state); err != nil {
		return bug067068BehaviorPageState{}, fmt.Errorf("decode Behavior const S state: %w", err)
	}
	return state, nil
}

func bug067068FirstFormAction(page string) (string, error) {
	tokenizer := html.NewTokenizer(strings.NewReader(page))
	for {
		switch tokenizer.Next() {
		case html.ErrorToken:
			return "", fmt.Errorf("challenge form action is missing: %w", tokenizer.Err())
		case html.StartTagToken, html.SelfClosingTagToken:
			token := tokenizer.Token()
			if token.Data != "form" {
				continue
			}
			for _, attr := range token.Attr {
				if attr.Key == "action" {
					return attr.Val, nil
				}
			}
			return "", fmt.Errorf("challenge form has no action attribute")
		}
	}
}

func bug067068ResponseCookie(rec *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}

func bug067068OnlyResponseCookie(t *testing.T, rec *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Value == "" {
		t.Fatalf("expected one non-empty owner cookie, got %v", cookies)
	}
	return cookies[0]
}
