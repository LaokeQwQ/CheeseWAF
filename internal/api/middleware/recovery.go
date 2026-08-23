package middleware

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/blockpage"
)

// Recovery converts handler panics into a stable API error and correlates them with audit logs.
func Recovery(auditor *Auditor) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if recovered := recover(); recovered != nil {
					traceID := blockpage.NewTraceID()
					log.Printf("api panic trace_id=%s method=%s path=%s panic=%v\n%s", traceID, r.Method, r.URL.Path, recovered, debug.Stack())
					w.Header().Set("Content-Type", "application/json")
					w.Header().Set("X-CheeseWAF-Trace-ID", traceID)
					w.Header().Set("X-CheeseWAF-Event-ID", traceID)
					w.WriteHeader(http.StatusInternalServerError)
					_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{
						"code": "INTERNAL_ERROR", "message": "internal server error", "trace_id": traceID, "event_id": traceID,
					}})
					if auditor != nil {
						entry := AuditEntry{Timestamp: time.Now().UTC(), Method: r.Method, Path: r.URL.Path, Status: http.StatusInternalServerError, RemoteIP: r.RemoteAddr, Target: "panic", Message: "trace_id=" + traceID}
						if err := auditor.Write(context.WithoutCancel(r.Context()), entry); err != nil {
							log.Printf("audit panic trace_id=%s: %v", traceID, err)
						}
					}
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}
