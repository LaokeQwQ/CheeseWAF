package engine

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/blockpage"
)

func NewRequestContext(r *http.Request, siteID string) (*RequestContext, error) {
	return newRequestContext(r, siteID, ClientIP(r))
}

func NewRequestContextWithTrustedProxies(r *http.Request, siteID string, trustedCIDRs []string) (*RequestContext, error) {
	return newRequestContext(r, siteID, ClientIPWithTrustedProxies(r, trustedCIDRs))
}

func newRequestContext(r *http.Request, siteID, clientIP string) (*RequestContext, error) {
	reqCtx := &RequestContext{
		Request:  r,
		ClientIP: clientIP,
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

func ClientIPWithTrustedProxies(r *http.Request, trustedCIDRs []string) string {
	remote := remoteAddrIP(r)
	if !isTrustedProxy(remote, trustedCIDRs) {
		return remote
	}
	for _, header := range []string{
		"CF-Connecting-IP",
		"True-Client-IP",
		"Fastly-Client-IP",
		"Fly-Client-IP",
		"DO-Connecting-IP",
		"Ali-CDN-Real-IP",
		"CDN-Src-IP",
		"X-CDN-Src-IP",
		"X-Azure-ClientIP",
		"X-Vercel-Forwarded-For",
		"X-Original-Forwarded-For",
		"X-Real-IP",
		"X-Client-IP",
		"X-Cluster-Client-IP",
		"X-Appengine-User-IP",
	} {
		if ip := firstHeaderIP(r.Header.Get(header)); ip != "" {
			return ip
		}
	}
	if ip := forwardedForIP(r.Header.Get("X-Forwarded-For"), trustedCIDRs); ip != "" {
		return ip
	}
	if ip := forwardedForIP(strings.Join(forwardedHeaderValues(r.Header.Get("Forwarded")), ","), trustedCIDRs); ip != "" {
		return ip
	}
	return remote
}

func remoteAddrIP(r *http.Request) string {
	if r == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		return ip.String()
	}
	return strings.TrimSpace(r.RemoteAddr)
}

func isTrustedProxy(remote string, trustedCIDRs []string) bool {
	ip, err := netip.ParseAddr(remote)
	if err != nil {
		return false
	}
	for _, raw := range trustedCIDRs {
		prefix, ok := parseTrustedPrefix(raw)
		if ok && prefix.Contains(ip) {
			return true
		}
	}
	return false
}

func parseTrustedPrefix(raw string) (netip.Prefix, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return netip.Prefix{}, false
	}
	if strings.Contains(raw, "/") {
		prefix, err := netip.ParsePrefix(raw)
		return prefix, err == nil
	}
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return netip.Prefix{}, false
	}
	if addr.Is4() {
		return netip.PrefixFrom(addr, 32), true
	}
	return netip.PrefixFrom(addr, 128), true
}

func firstHeaderIP(value string) string {
	for _, part := range strings.Split(value, ",") {
		if ip := parseHeaderIP(part); ip != "" {
			return ip
		}
	}
	return ""
}

func forwardedForIP(value string, trustedCIDRs []string) string {
	parts := strings.Split(value, ",")
	var first string
	for i := len(parts) - 1; i >= 0; i-- {
		ip := parseHeaderIP(parts[i])
		if ip == "" {
			continue
		}
		first = ip
		if !isTrustedProxy(ip, trustedCIDRs) {
			return ip
		}
	}
	return first
}

func forwardedHeaderValues(raw string) []string {
	values := make([]string, 0)
	for _, item := range strings.Split(raw, ",") {
		for _, part := range strings.Split(item, ";") {
			key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
			if !ok || !strings.EqualFold(strings.TrimSpace(key), "for") {
				continue
			}
			values = append(values, value)
		}
	}
	return values
}

func parseHeaderIP(raw string) string {
	raw = strings.TrimSpace(strings.Trim(raw, `"`))
	if raw == "" || strings.EqualFold(raw, "unknown") {
		return ""
	}
	if strings.HasPrefix(raw, "[") {
		if end := strings.Index(raw, "]"); end > 0 {
			raw = raw[1:end]
		}
	}
	if host, _, err := net.SplitHostPort(raw); err == nil {
		raw = host
	}
	raw = strings.Trim(raw, "[]")
	if ip := net.ParseIP(raw); ip != nil {
		return ip.String()
	}
	return ""
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
