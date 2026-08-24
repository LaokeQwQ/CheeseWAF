package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
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
					log.Printf("api panic trace_id=%s method=%s path=%s panic=%s", traceID, quoteRecoveryLogValue(r.Method), quoteRecoveryLogValue(r.URL.Path), recoveryPanicValue(recovered))
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
							log.Printf("audit panic trace_id=%s error=%s", traceID, quoteRecoveryLogValue(err.Error()))
						}
					}
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

const maxRecoveryLogValueBytes = 2048

func quoteRecoveryLogValue(value string) string {
	if len(value) > maxRecoveryLogValueBytes {
		value = value[:maxRecoveryLogValueBytes] + "...(truncated)"
	}
	return strconv.QuoteToASCII(value)
}

func recoveryPanicValue(value any) string {
	switch typed := value.(type) {
	case string:
		return quoteRecoveryLogValue(typed)
	case error:
		return quoteRecoveryLogValue(safeRecoveryErrorText(typed))
	default:
		return quoteRecoveryLogValue(fmt.Sprintf("<%T>", value))
	}
}

func safeRecoveryErrorText(err error) (text string) {
	text = fmt.Sprintf("<%T>", err)
	defer func() {
		_ = recover()
	}()
	return err.Error()
}
