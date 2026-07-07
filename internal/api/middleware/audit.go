package middleware

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type AuditEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Subject   string    `json:"subject,omitempty"`
	User      string    `json:"user"`
	Role      string    `json:"role"`
	Method    string    `json:"method"`
	Path      string    `json:"path"`
	Status    int       `json:"status"`
	RemoteIP  string    `json:"remote_ip"`
	LatencyMS int64     `json:"latency_ms"`
}

type Auditor struct {
	path string
	mu   sync.Mutex
}

func NewAuditor(path string) *Auditor {
	return &Auditor{path: path}
}

func (a *Auditor) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		start := time.Now()
		next.ServeHTTP(recorder, r)
		claims, _ := r.Context().Value(UserContextKey).(*Claims)
		entry := AuditEntry{
			Timestamp: time.Now().UTC(),
			Method:    r.Method,
			Path:      r.URL.Path,
			Status:    recorder.status,
			RemoteIP:  r.RemoteAddr,
			LatencyMS: time.Since(start).Milliseconds(),
		}
		if claims != nil {
			entry.Subject = claims.Subject
			entry.User = claims.Username
			entry.Role = claims.Role
		}
		_ = a.Write(r.Context(), entry)
	})
}

func (a *Auditor) Write(ctx context.Context, entry AuditEntry) error {
	if a == nil || a.path == "" {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(a.path), 0o750); err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	file, err := os.OpenFile(a.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	defer file.Close()
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	_, err = file.Write(append(data, '\n'))
	return err
}

func (a *Auditor) Query(limit int) ([]AuditEntry, error) {
	if a == nil || a.path == "" {
		return nil, nil
	}
	if limit <= 0 {
		limit = 100
	}
	file, err := os.Open(a.path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	var entries []AuditEntry
	for scanner.Scan() {
		var entry AuditEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err == nil {
			entries = append(entries, entry)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(entries) > limit {
		entries = entries[len(entries)-limit:]
	}
	return entries, nil
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func (r *statusRecorder) Flush() {
	if flusher, ok := r.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (r *statusRecorder) Unwrap() http.ResponseWriter {
	return r.ResponseWriter
}
