package intelapi_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/intel"
	"github.com/LaokeQwQ/CheeseWAF/internal/intel/impact"
	"github.com/LaokeQwQ/CheeseWAF/internal/intelapi"
	"github.com/LaokeQwQ/CheeseWAF/internal/intelstore"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

const advisoryHTML = `<!doctype html>
<html>
<head><title>CVE-2025-1234 PHP2Shell advisory</title></head>
<body>
<h1>PHP2Shell</h1>
<p>Exploit request: POST /uploads/index.php with multipart/form-data.</p>
<p>Set the multipart field PHP_SESSION_UPLOAD_PROGRESS and a PHPSESSID cookie.</p>
<p>Nested array parameter: a[b][c][d]=1 is accepted by the parser.</p>
<pre>&lt;?php system($_GET["cmd"]); ?&gt;</pre>
<p>Response evidence: Set-Cookie: PHPSESSID=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ</p>
<p>HTTP/1.1 200 OK</p>
</body>
</html>`

const benignHTML = `<html><head><title>Weekly newsletter</title></head><body><p>Nothing to see here. Hello world.</p></body></html>`

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func newTestClock() *testClock {
	return &testClock{now: time.Date(2026, 10, 22, 10, 0, 0, 0, time.UTC)}
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

type stubFetcher struct {
	mu       sync.Mutex
	body     []byte
	called   bool
	lastURL  string
	fetchErr error
}

func (f *stubFetcher) Fetch(_ context.Context, request intel.FetchRequest) (intel.FetchResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.called = true
	f.lastURL = request.URL
	if f.fetchErr != nil {
		return intel.FetchResult{}, f.fetchErr
	}
	sum := sha256.Sum256(f.body)
	return intel.FetchResult{
		URL:         request.URL,
		StatusCode:  http.StatusOK,
		ContentType: "text/html",
		Body:        f.body,
		FetchedAt:   time.Now().UTC(),
		SHA256:      hex.EncodeToString(sum[:]),
	}, nil
}

func (f *stubFetcher) wasCalled() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.called
}

func (f *stubFetcher) url() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastURL
}

type testEnv struct {
	handler http.Handler
	store   intelstore.Store
	fetcher *stubFetcher
	clock   *testClock
}

type importResult struct {
	JobID      string `json:"job_id"`
	Item       intel.Item
	Candidate  intel.Candidate
	Impact     impact.Assessment
	Candidates []struct {
		Candidate intel.Candidate   `json:"candidate"`
		Impact    impact.Assessment `json:"impact"`
	} `json:"candidates"`
	ItemCreated      bool `json:"item_created"`
	CandidateCreated bool `json:"candidate_created"`
}

func setupEnv(t *testing.T, configure func(*intelapi.HandlerOptions)) *testEnv {
	t.Helper()
	ctx := context.Background()
	db, err := storage.OpenSQLite(filepath.Join(t.TempDir(), "intelapi.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	store, err := db.IntelStore()
	if err != nil {
		t.Fatalf("intel store: %v", err)
	}
	if err := store.UpsertSource(ctx, intel.Source{
		ID:      "src-test",
		Type:    "url",
		URL:     "https://advisory.example.test/feed.xml",
		Trust:   intel.TrustVendor,
		Enabled: true,
	}); err != nil {
		t.Fatalf("upsert source: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, advisoryHTML)
	}))
	t.Cleanup(server.Close)
	response, err := http.Get(server.URL)
	if err != nil {
		t.Fatalf("fetch test html: %v", err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil {
		t.Fatalf("read test html: %v", err)
	}

	clock := newTestClock()
	fetcher := &stubFetcher{body: body}
	options := intelapi.HandlerOptions{
		Store:   store,
		Fetcher: fetcher,
		Now:     clock.Now,
		Actor:   func(*http.Request) (string, error) { return "alice", nil },
	}
	if configure != nil {
		configure(&options)
	}
	return &testEnv{handler: intelapi.NewHandler(options), store: store, fetcher: fetcher, clock: clock}
}

func (e *testEnv) doJSON(t *testing.T, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("encode request: %v", err)
		}
		reader = bytes.NewReader(encoded)
	}
	request := httptest.NewRequest(method, path, reader)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	recorder := httptest.NewRecorder()
	e.handler.ServeHTTP(recorder, request)
	return recorder
}

func (e *testEnv) doRaw(t *testing.T, method, path, contentType, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	recorder := httptest.NewRecorder()
	e.handler.ServeHTTP(recorder, request)
	return recorder
}

func decodeResponse[T any](t *testing.T, recorder *httptest.ResponseRecorder) T {
	t.Helper()
	var value T
	if err := json.Unmarshal(recorder.Body.Bytes(), &value); err != nil {
		t.Fatalf("decode response %q: %v", recorder.Body.String(), err)
	}
	return value
}

func (e *testEnv) importAdvisory(t *testing.T, url string) importResult {
	t.Helper()
	recorder := e.doJSON(t, http.MethodPost, "/import-url", map[string]any{
		"url":     url,
		"site_id": "site-a",
	})
	if recorder.Code != http.StatusCreated && recorder.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	return decodeResponse[importResult](t, recorder)
}

func TestImportURLCreatesDisabledLogCandidate(t *testing.T) {
	env := setupEnv(t, nil)
	result := env.importAdvisory(t, "https://advisory.example.test/advisory/1")

	if env.fetcher.url() != "https://advisory.example.test/advisory/1" {
		t.Fatalf("fetcher received %q", env.fetcher.url())
	}
	if result.Candidate.State != intel.CandidateDraft {
		t.Fatalf("candidate state=%q", result.Candidate.State)
	}
	if result.Candidate.Action != intel.ActionLog {
		t.Fatalf("candidate action=%q", result.Candidate.Action)
	}
	if !result.CandidateCreated || !result.ItemCreated {
		t.Fatalf("expected created flags, got candidate=%v item=%v", result.CandidateCreated, result.ItemCreated)
	}
	compiled, err := intel.DecodeCompiledRule([]byte(result.Candidate.RuleJSON))
	if err != nil {
		t.Fatalf("decode compiled rule: %v", err)
	}
	if compiled.Rule.Enabled {
		t.Fatal("imported rule must remain disabled")
	}
	if compiled.Rule.Action != intel.ActionLog {
		t.Fatalf("rule action=%q", compiled.Rule.Action)
	}
	if result.Impact.Verdict != impact.VerdictNeedsReview {
		t.Fatalf("impact verdict=%q reasons=%v", result.Impact.Verdict, result.Impact.Reasons)
	}
	if result.Impact.RequiresApprovalForBlock {
		t.Fatal("log-only candidate must not require block approval")
	}
	if len(result.Candidates) != 1 {
		t.Fatalf("candidate previews=%d", len(result.Candidates))
	}

	if _, err := env.store.GetItem(context.Background(), result.Item.ID); err != nil {
		t.Fatalf("persisted item: %v", err)
	}
	stored, err := env.store.GetCandidate(context.Background(), result.Candidate.ID)
	if err != nil {
		t.Fatalf("persisted candidate: %v", err)
	}
	if stored.State != intel.CandidateDraft || stored.Action != intel.ActionLog {
		t.Fatalf("stored candidate=%+v", stored)
	}
	job, err := env.store.GetImportJob(context.Background(), result.JobID)
	if err != nil {
		t.Fatalf("import job: %v", err)
	}
	if job.Status != intelstore.ImportStatusCompleted {
		t.Fatalf("job status=%q error=%q", job.Status, job.Error)
	}

	again := env.importAdvisory(t, "https://advisory.example.test/advisory/1")
	if again.CandidateCreated || again.ItemCreated {
		t.Fatalf("second import must deduplicate: candidate=%v item=%v", again.CandidateCreated, again.ItemCreated)
	}
}

func TestImportURLUsesRequestedScope(t *testing.T) {
	env := setupEnv(t, nil)
	recorder := env.doJSON(t, http.MethodPost, "/import-url", map[string]any{
		"url":         "https://advisory.example.test/advisory/1",
		"site_id":     "site-a",
		"path_prefix": "/uploads",
		"methods":     []string{"post"},
	})
	if recorder.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	result := decodeResponse[importResult](t, recorder)
	compiled, err := intel.DecodeCompiledRule([]byte(result.Candidate.RuleJSON))
	if err != nil {
		t.Fatalf("decode rule: %v", err)
	}
	if compiled.Scope.SiteID != "site-a" || compiled.Scope.PathPrefix != "/uploads" {
		t.Fatalf("scope=%+v", compiled.Scope)
	}
	if len(compiled.Scope.Methods) != 1 || compiled.Scope.Methods[0] != "POST" {
		t.Fatalf("methods=%v", compiled.Scope.Methods)
	}
}

func TestImportURLRejectsSSRFAndMetadataTargets(t *testing.T) {
	env := setupEnv(t, nil)
	for _, rawURL := range []string{
		"http://127.0.0.1:8080/admin",
		"http://169.254.169.254/latest/meta-data/",
		"http://[::1]/",
		"file:///etc/passwd",
	} {
		recorder := env.doJSON(t, http.MethodPost, "/import-url", map[string]any{
			"url":     rawURL,
			"site_id": "site-a",
		})
		if recorder.Code != http.StatusUnprocessableEntity {
			t.Fatalf("%s status=%d body=%s", rawURL, recorder.Code, recorder.Body.String())
		}
		envelope := decodeResponse[struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}](t, recorder)
		if envelope.Error.Code != "unsafe_url" {
			t.Fatalf("%s code=%q", rawURL, envelope.Error.Code)
		}
	}
	if env.fetcher.wasCalled() {
		t.Fatal("fetcher must not be called for an unsafe URL")
	}
}

func TestImportURLRejectsUnregisteredSource(t *testing.T) {
	env := setupEnv(t, nil)
	recorder := env.doJSON(t, http.MethodPost, "/import-url", map[string]any{
		"url":     "https://unknown.example.test/advisory",
		"site_id": "site-a",
	})
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	envelope := decodeResponse[struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}](t, recorder)
	if envelope.Error.Code != "source_unregistered" {
		t.Fatalf("code=%q", envelope.Error.Code)
	}
	if env.fetcher.wasCalled() {
		t.Fatal("fetcher must not be called for an unregistered source")
	}
}

func TestImportURLStrictJSONAndLimits(t *testing.T) {
	env := setupEnv(t, nil)

	recorder := env.doRaw(t, http.MethodPost, "/import-url", "text/plain", `{"url":"https://advisory.example.test/a","site_id":"site-a"}`)
	if recorder.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("content type status=%d", recorder.Code)
	}
	recorder = env.doRaw(t, http.MethodPost, "/import-url", "application/json", `{"url":"https://advisory.example.test/a","site_id":"site-a","trust":"official"}`)
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("unknown field status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	recorder = env.doRaw(t, http.MethodPost, "/import-url", "application/json", `{"url":"https://advisory.example.test/a","site_id":"site-a"} trailing`)
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("trailing json status=%d", recorder.Code)
	}
	oversized := `{"url":"https://advisory.example.test/a","site_id":"site-a","path_prefix":"/` + strings.Repeat("a", 20000) + `"}`
	recorder = env.doRaw(t, http.MethodPost, "/import-url", "application/json", oversized)
	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestImportURLNoSafeShape(t *testing.T) {
	env := setupEnv(t, nil)
	env.fetcher.body = []byte(benignHTML)
	recorder := env.doJSON(t, http.MethodPost, "/import-url", map[string]any{
		"url":     "https://advisory.example.test/newsletter",
		"site_id": "site-a",
	})
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	envelope := decodeResponse[struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}](t, recorder)
	if envelope.Error.Code != "no_safe_rule" {
		t.Fatalf("code=%q", envelope.Error.Code)
	}
}

func TestApproveRequiresConfirmationAndApprover(t *testing.T) {
	env := setupEnv(t, nil)
	result := env.importAdvisory(t, "https://advisory.example.test/advisory/1")
	path := "/candidates/" + result.Candidate.ID + "/approve"

	recorder := env.doJSON(t, http.MethodPost, path, map[string]any{"approved_by": "alice", "confirm": false})
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("confirm status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	// The reviewer identity is derived from the authenticated actor, not the
	// body; an empty body field is ignored.
	recorder = env.doJSON(t, http.MethodPost, path, map[string]any{"approved_by": "", "confirm": true})
	if recorder.Code != http.StatusOK {
		t.Fatalf("actor approval status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	recorder = env.doJSON(t, http.MethodPost, "/candidates/missing/approve", map[string]any{"approved_by": "alice", "confirm": true})
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("missing status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestApproveIgnoresForgedBodyIdentity(t *testing.T) {
	env := setupEnv(t, nil)
	result := env.importAdvisory(t, "https://advisory.example.test/advisory/1")
	recorder := env.doJSON(t, http.MethodPost, "/candidates/"+result.Candidate.ID+"/approve", map[string]any{
		"approved_by": "mallory",
		"confirm":     true,
	})
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	response := decodeResponse[struct {
		Candidate intel.Candidate `json:"candidate"`
	}](t, recorder)
	if response.Candidate.Provenance.ApprovedBy != "alice" {
		t.Fatalf("forged approver persisted: %+v", response.Candidate.Provenance)
	}
}

func TestApproveLogMovesToShadow(t *testing.T) {
	env := setupEnv(t, nil)
	result := env.importAdvisory(t, "https://advisory.example.test/advisory/1")
	recorder := env.doJSON(t, http.MethodPost, "/candidates/"+result.Candidate.ID+"/approve", map[string]any{
		"approved_by": "alice",
		"confirm":     true,
	})
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	response := decodeResponse[struct {
		Candidate intel.Candidate `json:"candidate"`
	}](t, recorder)
	if response.Candidate.State != intel.CandidateShadow {
		t.Fatalf("state=%q", response.Candidate.State)
	}
	if response.Candidate.Action != intel.ActionLog {
		t.Fatalf("action=%q", response.Candidate.Action)
	}
	if !response.Candidate.Provenance.Approved || response.Candidate.Provenance.ApprovedBy != "alice" {
		t.Fatalf("provenance=%+v", response.Candidate.Provenance)
	}
}

func TestApproveBlockRequiresImpactEvidence(t *testing.T) {
	env := setupEnv(t, nil)
	result := env.importAdvisory(t, "https://advisory.example.test/advisory/1")
	recorder := env.doJSON(t, http.MethodPost, "/candidates/"+result.Candidate.ID+"/approve", map[string]any{
		"approved_by": "alice",
		"action":      "block",
		"confirm":     true,
	})
	if recorder.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	envelope := decodeResponse[struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}](t, recorder)
	if envelope.Error.Code != "impact_insufficient" {
		t.Fatalf("code=%q", envelope.Error.Code)
	}
	stored, err := env.store.GetCandidate(context.Background(), result.Candidate.ID)
	if err != nil {
		t.Fatalf("get candidate: %v", err)
	}
	if stored.State != intel.CandidateDraft || stored.Action != intel.ActionLog {
		t.Fatalf("block rejection changed candidate: %+v", stored)
	}
}

func TestApproveBlockWithShadowEvidencePromotesToCanary(t *testing.T) {
	env := setupEnv(t, func(options *intelapi.HandlerOptions) {
		options.Profiles = func(_ context.Context, candidate impact.Candidate) ([]impact.Profile, error) {
			return []impact.Profile{{
				SiteID:   candidate.SiteID,
				Path:     "/uploads/index.php",
				Method:   "POST",
				Requests: 1000,
				Statuses: impact.StatusCounts{200: 1000},
				Matches: impact.MatchCounts{
					candidate.ID: impact.MatchObservation{Count: 5},
				},
			}}, nil
		}
	})
	result := env.importAdvisory(t, "https://advisory.example.test/advisory/1")
	candidateID := result.Candidate.ID
	if result.Impact.Verdict != impact.VerdictAllowShadow {
		t.Fatalf("import verdict=%q reasons=%v", result.Impact.Verdict, result.Impact.Reasons)
	}

	recorder := env.doJSON(t, http.MethodPost, "/candidates/"+candidateID+"/approve", map[string]any{
		"approved_by": "alice",
		"confirm":     true,
	})
	if recorder.Code != http.StatusOK {
		t.Fatalf("shadow status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	env.clock.Advance(2 * time.Hour)
	recorder = env.doJSON(t, http.MethodPost, "/candidates/"+candidateID+"/approve", map[string]any{
		"approved_by": "alice",
		"action":      "block",
		"confirm":     true,
	})
	if recorder.Code != http.StatusOK {
		t.Fatalf("block status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	response := decodeResponse[struct {
		Candidate intel.Candidate `json:"candidate"`
	}](t, recorder)
	if response.Candidate.State != intel.CandidateCanary {
		t.Fatalf("state=%q", response.Candidate.State)
	}
	if response.Candidate.Action != intel.ActionBlock {
		t.Fatalf("action=%q", response.Candidate.Action)
	}
	compiled, err := intel.DecodeCompiledRule([]byte(response.Candidate.RuleJSON))
	if err != nil {
		t.Fatalf("decode rule: %v", err)
	}
	if compiled.Rule.Enabled || compiled.Rule.Action != intel.ActionBlock {
		t.Fatalf("compiled rule enabled=%v action=%q", compiled.Rule.Enabled, compiled.Rule.Action)
	}
}

func TestRejectCandidate(t *testing.T) {
	env := setupEnv(t, nil)
	result := env.importAdvisory(t, "https://advisory.example.test/advisory/1")

	request := httptest.NewRequest(http.MethodPost, "/candidates/"+result.Candidate.ID+"/reject", nil)
	recorder := httptest.NewRecorder()
	env.handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("reject status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	response := decodeResponse[struct {
		Candidate intel.Candidate `json:"candidate"`
	}](t, recorder)
	if response.Candidate.State != intel.CandidateRejected || response.Candidate.Action != intel.ActionLog {
		t.Fatalf("candidate=%+v", response.Candidate)
	}

	recorder = env.doJSON(t, http.MethodPost, "/candidates/"+result.Candidate.ID+"/reject", map[string]any{})
	if recorder.Code != http.StatusConflict {
		t.Fatalf("second reject status=%d", recorder.Code)
	}
	recorder = env.doJSON(t, http.MethodPost, "/candidates/"+result.Candidate.ID+"/approve", map[string]any{
		"approved_by": "alice",
		"confirm":     true,
	})
	if recorder.Code != http.StatusConflict {
		t.Fatalf("approve rejected status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestListItemsCandidatesAndImpact(t *testing.T) {
	env := setupEnv(t, nil)
	result := env.importAdvisory(t, "https://advisory.example.test/advisory/1")

	recorder := env.doJSON(t, http.MethodGet, "/items?limit=10&state=draft", nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("items status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var items struct {
		Items []intel.Item `json:"items"`
		Count int          `json:"count"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &items); err != nil {
		t.Fatalf("decode items: %v", err)
	}
	if items.Count != 1 || items.Items[0].ID != result.Item.ID {
		t.Fatalf("items=%+v", items)
	}

	recorder = env.doJSON(t, http.MethodGet, "/candidates?site_id=site-a&state=draft", nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("candidates status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var candidates struct {
		Candidates []intel.Candidate `json:"candidates"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &candidates); err != nil {
		t.Fatalf("decode candidates: %v", err)
	}
	if len(candidates.Candidates) != 1 || candidates.Candidates[0].ID != result.Candidate.ID {
		t.Fatalf("candidates=%+v", candidates)
	}

	recorder = env.doJSON(t, http.MethodGet, "/impact?site_id=site-a", nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("impact status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var assessments struct {
		Assessments []impact.Assessment `json:"assessments"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &assessments); err != nil {
		t.Fatalf("decode impact: %v", err)
	}
	if len(assessments.Assessments) != 1 || assessments.Assessments[0].Verdict != impact.VerdictNeedsReview {
		t.Fatalf("assessments=%+v", assessments)
	}

	recorder = env.doJSON(t, http.MethodGet, "/items?state=bogus", nil)
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("invalid state status=%d", recorder.Code)
	}
	recorder = env.doJSON(t, http.MethodGet, "/impact", nil)
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("missing site status=%d", recorder.Code)
	}
}

func TestAuthorizerIsEnforced(t *testing.T) {
	env := setupEnv(t, func(options *intelapi.HandlerOptions) {
		options.Authorizer = func(*http.Request) error { return intelapi.ErrUnauthorized }
	})
	recorder := env.doJSON(t, http.MethodGet, "/items", nil)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}

	env = setupEnv(t, func(options *intelapi.HandlerOptions) {
		options.Authorizer = func(*http.Request) error { return context.Canceled }
	})
	recorder = env.doJSON(t, http.MethodGet, "/items", nil)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestNotFoundEndpoint(t *testing.T) {
	env := setupEnv(t, nil)
	recorder := env.doJSON(t, http.MethodGet, "/nope", nil)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status=%d", recorder.Code)
	}
}

func TestURLImportCanBeDisabled(t *testing.T) {
	env := setupEnv(t, func(options *intelapi.HandlerOptions) {
		options.DisableURLImport = true
	})
	recorder := env.doJSON(t, http.MethodPost, "/import-url", map[string]any{"url": "https://advisory.example.test/advisory/1", "site_id": "site-a"})
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}
