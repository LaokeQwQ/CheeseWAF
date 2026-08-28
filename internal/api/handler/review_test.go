package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/api/middleware"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
	"github.com/go-chi/chi/v5"
)

func TestReviewListAndAllowDecision(t *testing.T) {
	handler, store, site := newSiteTestHandler(t)
	ctx := context.Background()
	item := &storage.ReviewItem{
		SiteID:   site.ID,
		URI:      "/search?q=eval",
		Category: "webshell",
		Payload:  "eval($_GET[cmd])",
		Shape:    "embedded",
		Status:   "pending",
	}
	if err := store.CreateReviewItem(ctx, item); err != nil {
		t.Fatal(err)
	}

	router := chi.NewRouter()
	router.Get("/review", handler.ListReviewItems)
	router.Post("/review/{id}/decide", handler.DecideReviewItem)

	list := httptest.NewRecorder()
	router.ServeHTTP(list, httptest.NewRequest(http.MethodGet, "/review?status=pending&site_id="+site.ID, nil))
	if list.Code != http.StatusOK {
		t.Fatalf("list: %d %s", list.Code, list.Body.String())
	}

	decide := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/review/"+item.ID+"/decide", bytes.NewReader([]byte(`{"decision":"allow"}`)))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.UserContextKey, &middleware.Claims{
		Subject: "u1", Username: "admin", Role: "admin",
	}))
	router.ServeHTTP(decide, req)
	if decide.Code != http.StatusOK {
		t.Fatalf("decide: %d %s", decide.Code, decide.Body.String())
	}
	var envelope struct {
		Data storage.ReviewItem `json:"data"`
	}
	if err := json.Unmarshal(decide.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Data.Status != "allowed" || envelope.Data.DecidedByName != "admin" {
		t.Fatalf("unexpected decide result: %+v", envelope.Data)
	}
}

func TestReviewBlockPayloadAddsLiveCustomRule(t *testing.T) {
	handler, store, site := newSiteTestHandler(t)
	ctx := context.Background()
	item := &storage.ReviewItem{
		SiteID:    site.ID,
		URI:       "/search?s=eval",
		Category:  "webshell",
		Payload:   "eval($_GET[cmd])",
		Source:    "query",
		ParamName: "s",
		Shape:     "embedded",
		Status:    "pending",
	}
	if err := store.CreateReviewItem(ctx, item); err != nil {
		t.Fatal(err)
	}

	router := chi.NewRouter()
	router.Post("/review/{id}/decide", handler.DecideReviewItem)
	decide := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/review/"+item.ID+"/decide", bytes.NewReader([]byte(`{"decision":"block_payload"}`)))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.UserContextKey, &middleware.Claims{
		Subject: "u1", Username: "admin", Role: "admin",
	}))
	router.ServeHTTP(decide, req)
	if decide.Code != http.StatusOK {
		t.Fatalf("decide: %d %s", decide.Code, decide.Body.String())
	}
	updated, err := store.GetSite(ctx, site.ID)
	if err != nil || updated == nil || len(updated.Advanced.CustomRules) != 1 {
		t.Fatalf("expected one live custom rule, site=%+v err=%v", updated, err)
	}
	if updated.Advanced.CustomRules[0].Action != "block" || updated.Advanced.CustomRules[0].Pattern == "" {
		t.Fatalf("unexpected rule: %+v", updated.Advanced.CustomRules[0])
	}
}

func TestReviewRejectsUnknownDecision(t *testing.T) {
	handler, store, site := newSiteTestHandler(t)
	item := &storage.ReviewItem{SiteID: site.ID, Status: "pending", URI: "/"}
	if err := store.CreateReviewItem(context.Background(), item); err != nil {
		t.Fatal(err)
	}
	router := chi.NewRouter()
	router.Post("/review/{id}/decide", handler.DecideReviewItem)
	decide := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/review/"+item.ID+"/decide", bytes.NewReader([]byte(`{"decision":"delete_cms"}`)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(decide, req)
	if decide.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d %s", decide.Code, decide.Body.String())
	}
}

func TestReviewAllowWhitelistAddsParam(t *testing.T) {
	handler, store, site := newSiteTestHandler(t)
	item := &storage.ReviewItem{
		SiteID:    site.ID,
		URI:       "/editor",
		ParamName: "content",
		Status:    "pending",
		Category:  "xss",
	}
	if err := store.CreateReviewItem(context.Background(), item); err != nil {
		t.Fatal(err)
	}
	router := chi.NewRouter()
	router.Post("/review/{id}/decide", handler.DecideReviewItem)
	decide := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/review/"+item.ID+"/decide", bytes.NewReader([]byte(`{"decision":"allow_whitelist"}`)))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.UserContextKey, &middleware.Claims{Username: "admin", Role: "admin"}))
	router.ServeHTTP(decide, req)
	if decide.Code != http.StatusOK {
		t.Fatalf("decide: %d %s", decide.Code, decide.Body.String())
	}
	updated, err := store.GetSite(context.Background(), site.ID)
	if err != nil || updated == nil {
		t.Fatal(err)
	}
	if len(updated.Advanced.SemanticPolicy.ParamAllowlist) != 1 || updated.Advanced.SemanticPolicy.ParamAllowlist[0] != "content" {
		t.Fatalf("expected param allowlist, got %+v", updated.Advanced.SemanticPolicy)
	}
}

func TestReviewBlockFingerprintAddsDeny(t *testing.T) {
	handler, store, site := newSiteTestHandler(t)
	item := &storage.ReviewItem{
		SiteID:      site.ID,
		URI:         "/search",
		Category:    "webshell",
		Payload:     "eval($_GET[cmd])",
		Fingerprint: "aabbccddeeff0011",
		Status:      "pending",
	}
	if err := store.CreateReviewItem(context.Background(), item); err != nil {
		t.Fatal(err)
	}
	router := chi.NewRouter()
	router.Post("/review/{id}/decide", handler.DecideReviewItem)
	decide := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/review/"+item.ID+"/decide", bytes.NewReader([]byte(`{"decision":"block_fingerprint"}`)))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.UserContextKey, &middleware.Claims{Username: "admin", Role: "admin"}))
	router.ServeHTTP(decide, req)
	if decide.Code != http.StatusOK {
		t.Fatalf("decide: %d %s", decide.Code, decide.Body.String())
	}
	updated, err := store.GetSite(context.Background(), site.ID)
	if err != nil || updated == nil {
		t.Fatal(err)
	}
	if len(updated.Advanced.SemanticPolicy.FingerprintDeny) != 1 || updated.Advanced.SemanticPolicy.FingerprintDeny[0] != "aabbccddeeff0011" {
		t.Fatalf("expected fingerprint deny, got %+v", updated.Advanced.SemanticPolicy)
	}
}

func TestReviewBlockedItemStillAcceptsLastingIntercept(t *testing.T) {
	handler, store, site := newSiteTestHandler(t)
	item := &storage.ReviewItem{
		SiteID:          site.ID,
		URI:             "/search",
		Category:        "webshell",
		Payload:         "eval($_GET[cmd])",
		Fingerprint:     "aabbccddeeff0011",
		ProtectionLevel: 5,
		Status:          "blocked",
		Decision:        "block_now",
	}
	if err := store.CreateReviewItem(context.Background(), item); err != nil {
		t.Fatal(err)
	}
	router := chi.NewRouter()
	router.Post("/review/{id}/decide", handler.DecideReviewItem)
	decide := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/review/"+item.ID+"/decide", bytes.NewReader([]byte(`{"decision":"block_fingerprint"}`)))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.UserContextKey, &middleware.Claims{Username: "admin", Role: "admin"}))
	router.ServeHTTP(decide, req)
	if decide.Code != http.StatusOK {
		t.Fatalf("blocked item must still accept fingerprint intercept: %d %s", decide.Code, decide.Body.String())
	}
	updated, err := store.GetSite(context.Background(), site.ID)
	if err != nil || updated == nil {
		t.Fatal(err)
	}
	if len(updated.Advanced.SemanticPolicy.FingerprintDeny) != 1 || updated.Advanced.SemanticPolicy.FingerprintDeny[0] != "aabbccddeeff0011" {
		t.Fatalf("expected fingerprint deny, got %+v", updated.Advanced.SemanticPolicy)
	}
}

func TestReviewBlockedItemRejectsAllow(t *testing.T) {
	handler, store, site := newSiteTestHandler(t)
	item := &storage.ReviewItem{
		SiteID:   site.ID,
		URI:      "/search",
		Category: "webshell",
		Status:   "blocked",
		Decision: "block_now",
	}
	if err := store.CreateReviewItem(context.Background(), item); err != nil {
		t.Fatal(err)
	}
	router := chi.NewRouter()
	router.Post("/review/{id}/decide", handler.DecideReviewItem)
	decide := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/review/"+item.ID+"/decide", bytes.NewReader([]byte(`{"decision":"allow"}`)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(decide, req)
	if decide.Code != http.StatusConflict {
		t.Fatalf("blocked item must not accept allow, got %d %s", decide.Code, decide.Body.String())
	}
}

func TestReviewDecisionReleasesClaimWhenRuleApplicationFails(t *testing.T) {
	handler, store, site := newSiteTestHandler(t)
	item := &storage.ReviewItem{SiteID: site.ID, Status: "pending", URI: "/search", Payload: ""}
	if err := store.CreateReviewItem(context.Background(), item); err != nil {
		t.Fatal(err)
	}
	router := chi.NewRouter()
	router.Post("/review/{id}/decide", handler.DecideReviewItem)
	req := httptest.NewRequest(http.MethodPost, "/review/"+item.ID+"/decide", bytes.NewReader([]byte(`{"decision":"block_payload"}`)))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected apply failure, got %d %s", recorder.Code, recorder.Body.String())
	}
	claim, err := store.ClaimReviewItem(context.Background(), item.ID, "allow")
	if err != nil || claim == nil {
		t.Fatalf("failed apply must release claim: claim=%+v err=%v", claim, err)
	}
	if err := store.ReleaseReviewItem(context.Background(), item.ID, claim.Token); err != nil {
		t.Fatal(err)
	}
}

func TestReviewDecisionClaimAllowsOnlyOneConcurrentRuleApplication(t *testing.T) {
	handler, store, site := newSiteTestHandler(t)
	item := &storage.ReviewItem{
		SiteID:  site.ID,
		Status:  "pending",
		URI:     "/search",
		Payload: "eval($_GET[cmd])",
		Source:  "query",
	}
	if err := store.CreateReviewItem(context.Background(), item); err != nil {
		t.Fatal(err)
	}
	router := chi.NewRouter()
	router.Post("/review/{id}/decide", handler.DecideReviewItem)

	const attempts = 8
	codes := make(chan int, attempts)
	var wg sync.WaitGroup
	for range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodPost, "/review/"+item.ID+"/decide", bytes.NewReader([]byte(`{"decision":"block_payload"}`)))
			req.Header.Set("Content-Type", "application/json")
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, req)
			codes <- recorder.Code
		}()
	}
	wg.Wait()
	close(codes)
	oks := 0
	for code := range codes {
		if code == http.StatusOK {
			oks++
		}
		if code != http.StatusOK && code != http.StatusConflict {
			t.Fatalf("unexpected concurrent decision status: %d", code)
		}
	}
	if oks != 1 {
		t.Fatalf("expected exactly one successful decision, got %d", oks)
	}
	updated, err := store.GetSite(context.Background(), site.ID)
	if err != nil || updated == nil || len(updated.Advanced.CustomRules) != 1 {
		t.Fatalf("expected exactly one applied rule: site=%+v err=%v", updated, err)
	}
}
