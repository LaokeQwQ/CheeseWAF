package middleware

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

type auditFakeClock struct {
	now time.Time
}

func (c *auditFakeClock) Now() time.Time {
	return c.now
}

type deadlineResponseWriter struct {
	header   http.Header
	deadline time.Time
	called   bool
}

func (w *deadlineResponseWriter) Header() http.Header {
	if w.header == nil {
		w.header = http.Header{}
	}
	return w.header
}

func (w *deadlineResponseWriter) Write(data []byte) (int, error) {
	return len(data), nil
}

func (w *deadlineResponseWriter) WriteHeader(int) {}

func (w *deadlineResponseWriter) SetWriteDeadline(deadline time.Time) error {
	w.deadline = deadline
	w.called = true
	return nil
}

func TestStatusRecorderUnwrapAllowsResponseControllerWriteDeadline(t *testing.T) {
	base := &deadlineResponseWriter{}
	recorder := &statusRecorder{ResponseWriter: base, status: http.StatusOK}

	if err := http.NewResponseController(recorder).SetWriteDeadline(time.Time{}); err != nil {
		t.Fatalf("set write deadline through statusRecorder: %v", err)
	}
	if !base.called {
		t.Fatal("expected underlying response writer SetWriteDeadline to be called")
	}
	if !base.deadline.IsZero() {
		t.Fatalf("expected zero write deadline, got %s", base.deadline)
	}
}

func TestStatusRecorderAllowsStreamingPastServerWriteTimeout(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		recorder.Header().Set("Content-Type", "text/event-stream")
		if err := http.NewResponseController(recorder).SetWriteDeadline(time.Time{}); err != nil {
			t.Errorf("set write deadline through statusRecorder: %v", err)
			return
		}
		_, _ = recorder.Write([]byte("event: trace\ndata: {}\n\n"))
		recorder.Flush()
		time.Sleep(250 * time.Millisecond)
		_, _ = recorder.Write([]byte("event: done\ndata: {}\n\n"))
		recorder.Flush()
	})
	server := httptest.NewUnstartedServer(handler)
	server.Config.WriteTimeout = 80 * time.Millisecond
	server.Start()
	defer server.Close()

	client := server.Client()
	client.Timeout = 2 * time.Second
	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("get streaming response: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read streaming response: %v", err)
	}
	if got := string(body); !strings.Contains(got, "event: done") {
		t.Fatalf("stream ended before delayed event, body:\n%s", got)
	}
}

func TestAuditorWithClockUsesControlledUTCTimestamp(t *testing.T) {
	now := time.Date(2024, time.November, 5, 13, 14, 15, 0, time.FixedZone("test", 7*60*60))
	clock := &auditFakeClock{now: now}
	auditor := NewAuditorWithClock(filepath.Join(t.TempDir(), "audit.jsonl"), clock)
	handler := auditor.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/test", nil))

	entries, err := auditor.Query(1)
	if err != nil {
		t.Fatalf("query audit entries: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("entry count = %d, want 1", len(entries))
	}
	if !entries[0].Timestamp.Equal(now.UTC()) || entries[0].Timestamp.Location() != time.UTC {
		t.Fatalf("timestamp = %s (%s), want %s (UTC)", entries[0].Timestamp, entries[0].Timestamp.Location(), now.UTC())
	}
}

func TestAuditorClockOffsetDoesNotAffectLatency(t *testing.T) {
	startWall := time.Date(2024, time.January, 1, 0, 0, 0, 0, time.UTC)
	clock := &auditFakeClock{now: startWall}
	auditor := NewAuditorWithClock(filepath.Join(t.TempDir(), "audit.jsonl"), clock)
	handler := auditor.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(20 * time.Millisecond)
		clock.now = clock.now.Add(50 * 365 * 24 * time.Hour)
		w.WriteHeader(http.StatusNoContent)
	}))

	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/test", nil))

	entries, err := auditor.Query(1)
	if err != nil {
		t.Fatalf("query audit entries: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("entry count = %d, want 1", len(entries))
	}
	if entries[0].LatencyMS < 15 || entries[0].LatencyMS > 5_000 {
		t.Fatalf("latency = %dms, want monotonic request duration independent of wall-clock offset", entries[0].LatencyMS)
	}
	wantTimestamp := startWall.Add(50 * 365 * 24 * time.Hour)
	if !entries[0].Timestamp.Equal(wantTimestamp) {
		t.Fatalf("timestamp = %s, want shifted wall time %s", entries[0].Timestamp, wantTimestamp)
	}
}

func TestAuditorBoundsFieldsAndSerializedEntry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	auditor := NewAuditor(path)
	hostile := strings.Repeat("\x00<", maxAuditPathBytes*4) + "\xff"
	if err := auditor.Write(context.Background(), AuditEntry{
		Timestamp: time.Now(),
		Subject:   hostile,
		User:      hostile,
		Role:      hostile,
		Method:    hostile,
		Path:      hostile,
		RemoteIP:  hostile,
		Target:    hostile,
		Message:   hostile,
	}); err != nil {
		t.Fatalf("write bounded audit entry: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read audit file: %v", err)
	}
	if len(raw) > maxAuditLineBytes+1 {
		t.Fatalf("serialized entry = %d bytes, maximum = %d", len(raw), maxAuditLineBytes+1)
	}
	entries, err := auditor.Query(1)
	if err != nil || len(entries) != 1 {
		t.Fatalf("query bounded entry: entries=%d err=%v", len(entries), err)
	}
	fields := []struct {
		name string
		got  string
		max  int
	}{
		{name: "subject", got: entries[0].Subject, max: maxAuditSubjectBytes},
		{name: "user", got: entries[0].User, max: maxAuditUserBytes},
		{name: "role", got: entries[0].Role, max: maxAuditRoleBytes},
		{name: "method", got: entries[0].Method, max: maxAuditMethodBytes},
		{name: "path", got: entries[0].Path, max: maxAuditPathBytes},
		{name: "remote_ip", got: entries[0].RemoteIP, max: maxAuditRemoteIPBytes},
		{name: "target", got: entries[0].Target, max: maxAuditTargetBytes},
		{name: "message", got: entries[0].Message, max: maxAuditMessageBytes},
	}
	for _, field := range fields {
		if len(field.got) > field.max {
			t.Errorf("%s = %d bytes, maximum = %d", field.name, len(field.got), field.max)
		}
		if !utf8.ValidString(field.got) {
			t.Errorf("%s is not valid UTF-8", field.name)
		}
	}
}

func TestAuditorRotationEnforcesTotalBudgetAndRetainsNewest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	auditor := NewAuditor(path)
	auditor.maxFileBytes = 1024
	auditor.maxBackups = 2

	if err := os.WriteFile(path, []byte(strings.Repeat("x", 2048)), 0o640); err != nil {
		t.Fatalf("seed oversized active file: %v", err)
	}
	if err := os.WriteFile(path+".9", []byte(strings.Repeat("x", 2048)), 0o640); err != nil {
		t.Fatalf("seed stale backup: %v", err)
	}
	for index := 0; index < 30; index++ {
		if err := auditor.Write(context.Background(), AuditEntry{
			Timestamp: time.Unix(int64(index), 0).UTC(),
			Method:    http.MethodPost,
			Path:      "/api/system",
			Target:    strconv.Itoa(index),
			Message:   strings.Repeat("m", 80),
		}); err != nil {
			t.Fatalf("write entry %d: %v", index, err)
		}
	}

	var total int64
	for _, candidate := range []string{path, path + ".1", path + ".2"} {
		info, err := os.Stat(candidate)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatalf("stat %s: %v", candidate, err)
		}
		if info.Size() > auditor.maxFileBytes {
			t.Errorf("%s = %d bytes, budget = %d", candidate, info.Size(), auditor.maxFileBytes)
		}
		total += info.Size()
	}
	if total > auditor.maxFileBytes*int64(auditor.maxBackups+1) {
		t.Fatalf("total audit bytes = %d, budget = %d", total, auditor.maxFileBytes*int64(auditor.maxBackups+1))
	}
	for _, stale := range []string{path + ".3", path + ".9"} {
		if _, err := os.Stat(stale); !os.IsNotExist(err) {
			t.Fatalf("stale backup %s was not removed: %v", stale, err)
		}
	}

	entries, err := auditor.Query(5)
	if err != nil {
		t.Fatalf("query rotated entries: %v", err)
	}
	if len(entries) != 5 {
		t.Fatalf("entry count = %d, want 5", len(entries))
	}
	for index, entry := range entries {
		want := strconv.Itoa(25 + index)
		if entry.Target != want {
			t.Fatalf("entry %d target = %q, want %q; entries=%+v", index, entry.Target, want, entries)
		}
	}
}

func TestAuditorQuerySkipsOversizedLegacyLineAndContinues(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	encode := func(target string) []byte {
		data, err := json.Marshal(AuditEntry{Timestamp: time.Now().UTC(), Method: http.MethodGet, Path: "/api/test", Target: target})
		if err != nil {
			t.Fatalf("marshal fixture: %v", err)
		}
		return append(data, '\n')
	}
	content := append([]byte{}, encode("before")...)
	content = append(content, []byte(`{"path":"`)...)
	content = append(content, []byte(strings.Repeat("x", maxAuditLineBytes*4))...)
	content = append(content, []byte(`"}`+"\n")...)
	content = append(content, encode("after")...)
	if err := os.WriteFile(path, content, 0o640); err != nil {
		t.Fatalf("write legacy audit fixture: %v", err)
	}

	entries, err := NewAuditor(path).Query(2)
	if err != nil {
		t.Fatalf("query after oversized line: %v", err)
	}
	if len(entries) != 2 || entries[0].Target != "before" || entries[1].Target != "after" {
		t.Fatalf("query did not resume after oversized line: %+v", entries)
	}
}

func TestAuditorMiddlewareWritesDeniedRequests(t *testing.T) {
	auditor := NewAuditor(filepath.Join(t.TempDir(), "audit.jsonl"))
	handler := auditor.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/system", nil))

	entries, err := auditor.Query(10)
	if err != nil {
		t.Fatalf("query audit entries: %v", err)
	}
	if len(entries) != 1 || entries[0].Status != http.StatusForbidden {
		t.Fatalf("denied request missing from audit log: %+v", entries)
	}
}

func TestAuditorMiddlewareRetainsAllDeniedRequests(t *testing.T) {
	auditor := NewAuditor(filepath.Join(t.TempDir(), "audit.jsonl"))
	handler := auditor.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	for index := 0; index < 3; index++ {
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/system", nil))
	}

	entries, err := auditor.Query(10)
	if err != nil {
		t.Fatalf("query audit entries: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("denied audit entries = %d, want 3", len(entries))
	}
}

func TestAuditorMiddlewareWritesAfterRequestCancellation(t *testing.T) {
	auditor := NewAuditor(filepath.Join(t.TempDir(), "audit.jsonl"))
	requestContext, cancel := context.WithCancel(context.Background())
	handler := auditor.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		cancel()
		w.WriteHeader(http.StatusNoContent)
	}))
	request := httptest.NewRequest(http.MethodPost, "/api/system", nil).WithContext(requestContext)
	handler.ServeHTTP(httptest.NewRecorder(), request)

	entries, err := auditor.Query(1)
	if err != nil {
		t.Fatalf("query audit entries: %v", err)
	}
	if len(entries) != 1 || entries[0].Status != http.StatusNoContent {
		t.Fatalf("completed request disappeared after cancellation: %+v", entries)
	}
}
