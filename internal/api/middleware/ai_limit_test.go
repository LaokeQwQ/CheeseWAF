package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAIRequestLimiterSeparatesSubjectsAndBoundsConcurrencyAndRate(t *testing.T) {
	now := time.Date(2026, time.August, 10, 0, 0, 0, 0, time.UTC)
	limiter := NewAIRequestLimiter(AIRequestLimitOptions{
		MaxRequests: 2,
		MaxInFlight: 1,
		MaxSubjects: 4,
		Window:      time.Minute,
		SubjectTTL:  2 * time.Minute,
		Now:         func() time.Time { return now },
	})

	releaseA, _, _ := limiter.acquire("admin:user-a")
	if releaseA == nil {
		t.Fatal("first request should be admitted")
	}
	if release, code, _ := limiter.acquire("admin:user-a"); release != nil || code != "AI_CONCURRENCY_LIMITED" {
		t.Fatalf("same-subject concurrent request = release %v code %q", release != nil, code)
	}
	releaseB, _, _ := limiter.acquire("admin:user-b")
	if releaseB == nil {
		t.Fatal("different subject should have an independent budget")
	}
	releaseA()
	releaseB()

	releaseA, _, _ = limiter.acquire("admin:user-a")
	if releaseA == nil {
		t.Fatal("second sequential request should be admitted")
	}
	releaseA()
	if release, code, _ := limiter.acquire("admin:user-a"); release != nil || code != "AI_RATE_LIMITED" {
		t.Fatalf("third request in the window = release %v code %q", release != nil, code)
	}

	now = now.Add(time.Minute)
	if release, _, _ := limiter.acquire("admin:user-a"); release == nil {
		t.Fatal("request budget should recover after the window")
	} else {
		release()
	}
}

func TestAIRequestLimiterPrunesIdleSubjects(t *testing.T) {
	now := time.Date(2026, time.August, 10, 0, 0, 0, 0, time.UTC)
	limiter := NewAIRequestLimiter(AIRequestLimitOptions{
		MaxRequests: 1,
		MaxInFlight: 1,
		MaxSubjects: 1,
		Window:      time.Minute,
		SubjectTTL:  time.Minute,
		Now:         func() time.Time { return now },
	})
	release, _, _ := limiter.acquire("admin:old")
	release()
	now = now.Add(time.Minute)
	release, _, _ = limiter.acquire("admin:new")
	if release == nil {
		t.Fatal("expired subject should not consume map capacity")
	}
	release()
	if len(limiter.states) != 1 || limiter.states["admin:new"] == nil {
		t.Fatalf("unexpected limiter states: %#v", limiter.states)
	}
}

func TestAIRequestLimiterMiddlewareRequiresCanonicalSubject(t *testing.T) {
	limiter := NewAIRequestLimiter(AIRequestLimitOptions{})
	called := false
	handler := limiter.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))

	missing := httptest.NewRecorder()
	handler.ServeHTTP(missing, httptest.NewRequest(http.MethodPost, "/api/ai/analyze", nil))
	if missing.Code != http.StatusUnauthorized || called {
		t.Fatalf("missing subject status=%d called=%v", missing.Code, called)
	}

	request := httptest.NewRequest(http.MethodPost, "/api/ai/analyze", nil)
	request = request.WithContext(context.WithValue(request.Context(), UserContextKey, &Claims{Subject: "user-1", Role: "admin"}))
	handler.ServeHTTP(httptest.NewRecorder(), request)
	if !called {
		t.Fatal("authenticated subject should reach the next handler")
	}
}
