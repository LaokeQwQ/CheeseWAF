package proxy

import (
	"bufio"
	"net"
	"net/http"
	"time"
)

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

func withIdleWriteTimeout(next http.Handler, timeout time.Duration) http.Handler {
	if timeout <= 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writer := &idleWriteTimeoutWriter{ResponseWriter: w, timeout: timeout}
		writer.refreshDeadline()
		next.ServeHTTP(writer, r)
	})
}

type idleWriteTimeoutWriter struct {
	http.ResponseWriter
	timeout time.Duration
}

func (w *idleWriteTimeoutWriter) refreshDeadline() {
	_ = http.NewResponseController(w.ResponseWriter).SetWriteDeadline(time.Now().Add(w.timeout))
}

func (w *idleWriteTimeoutWriter) WriteHeader(status int) {
	w.refreshDeadline()
	w.ResponseWriter.WriteHeader(status)
}

func (w *idleWriteTimeoutWriter) Write(p []byte) (int, error) {
	w.refreshDeadline()
	return w.ResponseWriter.Write(p)
}

func (w *idleWriteTimeoutWriter) Flush() {
	w.refreshDeadline()
	_ = http.NewResponseController(w.ResponseWriter).Flush()
}

func (w *idleWriteTimeoutWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return http.NewResponseController(w.ResponseWriter).Hijack()
}

func (w *idleWriteTimeoutWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}
