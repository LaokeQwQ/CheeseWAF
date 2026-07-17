package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/api/middleware"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
	"github.com/go-chi/chi/v5"
)

func TestNotificationHandlersPersistUserScopedMutations(t *testing.T) {
	h, store := newNotificationTestHandler(t)
	ctx := context.Background()
	now := time.Now().UTC()
	for _, item := range []*storage.Notification{
		{ID: "a-unread", UserID: "user-a", Type: "warning", Title: "A unread", Read: false, CreatedAt: now.Add(-time.Minute), UpdatedAt: now.Add(-time.Minute)},
		{ID: "a-pinned", UserID: "user-a", Type: "info", Title: "A pinned", Read: true, Pinned: true, CreatedAt: now, UpdatedAt: now},
		{ID: "b-only", UserID: "user-b", Type: "critical", Title: "B only", Read: false, CreatedAt: now, UpdatedAt: now},
	} {
		if err := store.CreateNotification(ctx, item); err != nil {
			t.Fatalf("create notification: %v", err)
		}
	}
	router := notificationTestRouter(h, "user-a")

	recorder := performNotificationRequest(t, router, http.MethodGet, "/notifications?filter=unread&page=1&limit=10", nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("list unread status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var listed struct {
		Data struct {
			Items         []storage.Notification `json:"items"`
			Total         int64                  `json:"total"`
			FilteredTotal int64                  `json:"filtered_total"`
			Unread        int64                  `json:"unread"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &listed); err != nil {
		t.Fatalf("decode list response: %v", err)
	}
	if listed.Data.Total != 2 || len(listed.Data.Items) != 1 || listed.Data.Items[0].ID != "a-unread" {
		t.Fatalf("unexpected scoped list: %+v", listed.Data)
	}

	recorder = performNotificationRequest(t, router, http.MethodPatch, "/notifications/a-unread", map[string]any{"read": true, "pinned": true})
	if recorder.Code != http.StatusOK {
		t.Fatalf("update status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	items, _, _, unread, err := store.ListNotifications(ctx, "user-a", storage.NotificationFilter{State: "pinned", Limit: 10})
	if err != nil || len(items) != 2 || unread != 0 {
		t.Fatalf("mutation did not persist items=%+v unread=%d err=%v", items, unread, err)
	}

	recorder = performNotificationRequest(t, router, http.MethodPost, "/notifications/read-all", map[string]any{})
	if recorder.Code != http.StatusOK || !bytes.Contains(recorder.Body.Bytes(), []byte(`"updated":0`)) {
		t.Fatalf("read-all status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	recorder = performNotificationRequest(t, router, http.MethodDelete, "/notifications", nil)
	if recorder.Code != http.StatusOK || !bytes.Contains(recorder.Body.Bytes(), []byte(`"deleted":2`)) {
		t.Fatalf("clear status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	remaining, total, _, _, err := store.ListNotifications(ctx, "user-b", storage.NotificationFilter{State: "all", Limit: 10})
	if err != nil || total != 1 || len(remaining) != 1 || remaining[0].ID != "b-only" {
		t.Fatalf("clear crossed user boundary: items=%+v total=%d err=%v", remaining, total, err)
	}
}

func TestNotificationHandlersRejectInvalidAndCrossUserRequests(t *testing.T) {
	h, store := newNotificationTestHandler(t)
	if err := store.CreateNotification(context.Background(), &storage.Notification{ID: "b-only", UserID: "user-b", Type: "info", Title: "B"}); err != nil {
		t.Fatalf("create notification: %v", err)
	}
	router := notificationTestRouter(h, "user-a")
	tests := []struct {
		method, path string
		body         any
		status       int
	}{
		{http.MethodGet, "/notifications?filter=other", nil, http.StatusBadRequest},
		{http.MethodGet, "/notifications?limit=101", nil, http.StatusBadRequest},
		{http.MethodPatch, "/notifications/b-only", map[string]any{"read": true}, http.StatusNotFound},
		{http.MethodPatch, "/notifications/missing", map[string]any{}, http.StatusBadRequest},
	}
	for _, test := range tests {
		recorder := performNotificationRequest(t, router, test.method, test.path, test.body)
		if recorder.Code != test.status {
			t.Errorf("%s %s status=%d want=%d body=%s", test.method, test.path, recorder.Code, test.status, recorder.Body.String())
		}
	}

	unauthenticated := chi.NewRouter()
	unauthenticated.Get("/notifications", h.ListNotifications)
	recorder := httptest.NewRecorder()
	unauthenticated.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/notifications", nil))
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func newNotificationTestHandler(t *testing.T) (*Handler, *storage.SQLiteStore) {
	t.Helper()
	store, err := storage.OpenSQLite(filepath.Join(t.TempDir(), "notifications.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate sqlite: %v", err)
	}
	for _, user := range []*storage.User{
		{ID: "user-a", Username: "user-a", PasswordHash: "test-only", Role: "admin"},
		{ID: "user-b", Username: "user-b", PasswordHash: "test-only", Role: "admin"},
	} {
		if err := store.CreateUser(context.Background(), user); err != nil {
			t.Fatalf("create notification user: %v", err)
		}
	}
	cfg := config.Default()
	return New(Options{Config: &cfg, Store: store}), store
}

func notificationTestRouter(h *Handler, userID string) http.Handler {
	router := chi.NewRouter()
	router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := &middleware.Claims{Subject: userID, Username: userID, Role: "admin"}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), middleware.UserContextKey, claims)))
		})
	})
	router.Get("/notifications", h.ListNotifications)
	router.Patch("/notifications/{id}", h.UpdateNotification)
	router.Post("/notifications/read-all", h.MarkAllNotificationsRead)
	router.Delete("/notifications", h.ClearNotifications)
	return router
}

func performNotificationRequest(t *testing.T, router http.Handler, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var payload bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&payload).Encode(body); err != nil {
			t.Fatalf("encode body: %v", err)
		}
	}
	request := httptest.NewRequest(method, path, &payload)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	return recorder
}
