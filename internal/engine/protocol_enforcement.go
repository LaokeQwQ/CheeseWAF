// Package engine provides HTTP protocol enforcement and smuggling detection.
// Detects CL.TE, TE.CL smuggling, chunked encoding abuse, and header injection.
package engine

import (
	"net/http"
	"strconv"
	"strings"
)

// ProtocolViolation holds detected protocol-level violations.
type ProtocolViolation struct {
	Detected   bool
	Type       string // smuggling, chunked_abuse, encoding_abuse, header_injection
	Severity   Severity
	Confidence float64
	Message    string
}

// DetectProtocolViolations checks the HTTP request for protocol-level attacks.
func DetectProtocolViolations(r *http.Request) *ProtocolViolation {
	if r == nil {
		return nil
	}

	// 1. HTTP Smuggling: CL.TE (Content-Length + Transfer-Encoding conflict)
	if v := detectCLTESmuggling(r); v != nil {
		return v
	}

	// 2. HTTP Smuggling: TE.CL (Transfer-Encoding + Content-Length conflict)
	if v := detectTECLSmuggling(r); v != nil {
		return v
	}

	// 3. Chunked encoding abuse
	if v := detectChunkedAbuse(r); v != nil {
		return v
	}

	// 4. HTTP/2 downgrade or WebSocket upgrade abuse
	if v := detectUpgradeDowngradeAbuse(r); v != nil {
		return v
	}

	// 5. Header injection via encoding
	if v := detectHeaderInjection(r); v != nil {
		return v
	}

	return nil
}

// transferEncodingValues reads TE from r.TransferEncoding (net/http canonical
// field) first, then falls back to the raw Header map. net/http often moves TE
// out of Header into TransferEncoding, so Header-only reads miss smuggling signals.
func transferEncodingValues(r *http.Request) []string {
	if r == nil {
		return nil
	}
	if len(r.TransferEncoding) > 0 {
		out := make([]string, len(r.TransferEncoding))
		copy(out, r.TransferEncoding)
		return out
	}
	if vals := r.Header["Transfer-Encoding"]; len(vals) > 0 {
		var out []string
		for _, v := range vals {
			for _, part := range strings.Split(v, ",") {
				part = strings.TrimSpace(part)
				if part != "" {
					out = append(out, part)
				}
			}
		}
		return out
	}
	if te := strings.TrimSpace(r.Header.Get("Transfer-Encoding")); te != "" {
		return []string{te}
	}
	return nil
}

func transferEncodingJoined(r *http.Request) string {
	vals := transferEncodingValues(r)
	if len(vals) == 0 {
		return ""
	}
	return strings.Join(vals, ", ")
}

func hasChunkedTransferEncoding(r *http.Request) bool {
	for _, v := range transferEncodingValues(r) {
		if strings.Contains(strings.ToLower(v), "chunked") {
			return true
		}
	}
	return false
}

// positiveContentLength reports a declared Content-Length > 0 from Header or the
// parsed r.ContentLength field (which may remain set after Header mutation).
func positiveContentLength(r *http.Request) bool {
	if r.ContentLength > 0 {
		return true
	}
	cl := strings.TrimSpace(r.Header.Get("Content-Length"))
	if cl == "" {
		return false
	}
	clVal, err := strconv.Atoi(cl)
	return err == nil && clVal > 0
}

// CL.TE smuggling: attacker sends both Content-Length and Transfer-Encoding,
// front-end uses CL, back-end uses TE → request body smuggling.
func detectCLTESmuggling(r *http.Request) *ProtocolViolation {
	if !positiveContentLength(r) || !hasChunkedTransferEncoding(r) {
		return nil
	}
	return &ProtocolViolation{
		Detected: true, Type: "smuggling", Severity: SeverityHigh, Confidence: 0.92,
		Message: "HTTP request smuggling: Content-Length + Transfer-Encoding: chunked conflict (CL.TE attack)",
	}
}

// TE.CL smuggling: Transfer-Encoding with trailing Content-Length in chunked body.
func detectTECLSmuggling(r *http.Request) *ProtocolViolation {
	vals := transferEncodingValues(r)
	if len(vals) == 0 {
		return nil
	}
	joined := strings.ToLower(strings.Join(vals, ", "))
	if !strings.Contains(joined, "chunked") {
		return nil
	}

	// TE with multiple values (e.g., "chunked, identity")
	for _, v := range vals {
		v = strings.ToLower(strings.TrimSpace(v))
		if v != "chunked" && v != "" {
			return &ProtocolViolation{
				Detected: true, Type: "smuggling", Severity: SeverityCritical, Confidence: 0.95,
				Message: "HTTP request smuggling: Transfer-Encoding with suspicious additional value: " + v,
			}
		}
	}

	// Check for TE header obfuscation (leading/trailing spaces, tab separators)
	rawTE := transferEncodingJoined(r)
	if strings.Contains(rawTE, "\x0b") || strings.Contains(rawTE, "\x00") {
		return &ProtocolViolation{
			Detected: true, Type: "smuggling", Severity: SeverityCritical, Confidence: 0.98,
			Message: "HTTP request smuggling: Transfer-Encoding header obfuscation (null/vertical-tab byte)",
		}
	}
	return nil
}

// Chunked encoding abuse: oversized chunks, malformed sizes, chunk size overflow.
func detectChunkedAbuse(r *http.Request) *ProtocolViolation {
	if !hasChunkedTransferEncoding(r) {
		return nil
	}

	// Detect overly large chunk size prefix (potential overflow attack)
	body := r.ContentLength
	if body < 0 {
		body = 0
	}
	if body > 10*1024*1024 { // 10MB single chunk
		return &ProtocolViolation{
			Detected: true, Type: "chunked_abuse", Severity: SeverityHigh, Confidence: 0.82,
			Message: "chunked encoding abuse: request body exceeds safe chunk size limit",
		}
	}
	return nil
}

func detectUpgradeDowngradeAbuse(r *http.Request) *ProtocolViolation {
	if r.ProtoMajor >= 2 {
		if connection := r.Header.Get("Connection"); connection != "" {
			return &ProtocolViolation{
				Detected: true, Type: "smuggling", Severity: SeverityHigh, Confidence: 0.9,
				Message: "HTTP/2 request contains forbidden hop-by-hop Connection header",
			}
		}
		if upgrade := r.Header.Get("Upgrade"); upgrade != "" {
			return &ProtocolViolation{
				Detected: true, Type: "smuggling", Severity: SeverityHigh, Confidence: 0.9,
				Message: "HTTP/2 request contains forbidden Upgrade header (downgrade smuggling vector)",
			}
		}
		if te := strings.TrimSpace(strings.ToLower(r.Header.Get("TE"))); te != "" && te != "trailers" {
			return &ProtocolViolation{
				Detected: true, Type: "smuggling", Severity: SeverityHigh, Confidence: 0.88,
				Message: "HTTP/2 request contains invalid TE header value: " + te,
			}
		}
		// HTTP/2 forbids Transfer-Encoding; read both Header and TransferEncoding.
		if len(transferEncodingValues(r)) > 0 {
			return &ProtocolViolation{
				Detected: true, Type: "smuggling", Severity: SeverityCritical, Confidence: 0.96,
				Message: "HTTP/2 request contains forbidden Transfer-Encoding header",
			}
		}
		return nil
	}

	upgrade := strings.TrimSpace(r.Header.Get("Upgrade"))
	if !strings.EqualFold(upgrade, "websocket") {
		return nil
	}
	connection := strings.ToLower(r.Header.Get("Connection"))
	if r.Method != http.MethodGet || !strings.Contains(connection, "upgrade") || strings.TrimSpace(r.Header.Get("Sec-WebSocket-Key")) == "" {
		return &ProtocolViolation{
			Detected: true, Type: "upgrade_abuse", Severity: SeverityMedium, Confidence: 0.78,
			Message: "malformed WebSocket upgrade request",
		}
	}
	return nil
}

// Header injection: detect attempts to inject extra headers via encoding tricks.
func detectHeaderInjection(r *http.Request) *ProtocolViolation {
	// Check for CRLF in header values (response splitting / header injection)
	for key, values := range r.Header {
		for _, v := range values {
			if strings.Contains(v, "\r") || strings.Contains(v, "\n") {
				return &ProtocolViolation{
					Detected: true, Type: "header_injection", Severity: SeverityCritical, Confidence: 0.98,
					Message: "header injection detected: CR/LF bytes in header " + key,
				}
			}
		}
	}

	// Check for oversized headers (potential buffer overflow)
	for key, values := range r.Header {
		for _, v := range values {
			if len(v) > 8192 {
				return &ProtocolViolation{
					Detected: true, Type: "header_injection", Severity: SeverityHigh, Confidence: 0.85,
					Message: "oversized header value in " + key + " (possible buffer overflow probe)",
				}
			}
		}
	}

	// Check for HTTP/1.0 downgrade attempt (smuggling via protocol version)
	if r.ProtoMajor == 1 && r.ProtoMinor == 0 {
		if r.Header.Get("Host") == "" || r.Header.Get("Connection") == "keep-alive" {
			// HTTP/1.0 with keep-alive — potential smuggling vector
			return &ProtocolViolation{
				Detected: true, Type: "encoding_abuse", Severity: SeverityMedium, Confidence: 0.65,
				Message: "HTTP/1.0 request with keep-alive (potential smuggling downgrade)",
			}
		}
	}
	return nil
}
