package engine

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/blockpage"
)

func NewRequestContext(r *http.Request, siteID string) (*RequestContext, error) {
	reqCtx := &RequestContext{
		Request:  r,
		ClientIP: ClientIP(r),
		TraceID:  blockpage.NewTraceID(),
		SiteID:   siteID,
		Metadata: map[string]any{},
	}
	reqCtx.DecodedURI = r.URL.RequestURI()
	if r.Body != nil {
		body, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
		if err != nil {
			return nil, err
		}
		reqCtx.DecodedBody = body
		r.Body = io.NopCloser(bytes.NewReader(body))
	}
	return reqCtx, nil
}

func ClientIP(r *http.Request) string {
	for _, header := range []string{"CF-Connecting-IP", "X-Real-IP", "X-Forwarded-For"} {
		value := strings.TrimSpace(r.Header.Get(header))
		if value == "" {
			continue
		}
		if header == "X-Forwarded-For" {
			value = strings.TrimSpace(strings.Split(value, ",")[0])
		}
		if ip := net.ParseIP(value); ip != nil {
			return ip.String()
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (a Action) String() string {
	switch a {
	case ActionBlock:
		return "block"
	case ActionChallenge:
		return "challenge"
	case ActionLog:
		return "log"
	default:
		return "pass"
	}
}

func (s Severity) String() string {
	switch s {
	case SeverityCritical:
		return "critical"
	case SeverityHigh:
		return "high"
	case SeverityMedium:
		return "medium"
	case SeverityLow:
		return "low"
	default:
		return "info"
	}
}
