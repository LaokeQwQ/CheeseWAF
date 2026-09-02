package semantic

import (
	"context"
	"math/bits"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine/decoder"
)

var (
	urlLikePattern           = regexp.MustCompile(`(?i)(?:https?|gopher|dict|ftp|file)://[^\s'"<>]+`)
	schemeRelativeURLPattern = regexp.MustCompile(`(?i)(?:^|[\s"'(])//[^\s'"<>]+`)
	ssrfRedirectFieldTokens  = [...]string{"redirect", "return", "next", "continue", "fallback"}
	ssrfTelemetryFieldTokens = [...]string{"url", "link", "referrer", "referer", "fullref", "redirect", "href", "src", "origin"}
	ssrfFetchPathMarkers     = [...]string{"fetch", "proxy", "import", "include", "require", "remote", "webhook", "callback", "ssrf"}
	ssrfFetchQueryMarkers    = [...]string{"fetch", "proxy", "remote", "webhook", "callback", "endpoint", "destination", "dest"}
	ssrfTelemetryKeyCleaner  = strings.NewReplacer("_", "", "-", "")
)

type SSRFDetector struct {
	mode string
}

// ssrfCacheScope captures every request property consulted by the same-origin
// suppression gate. Raw strings are retained instead of parsed maps so adding
// the scope to a cache key stays allocation-free on the analyzer hot path.
type ssrfCacheScope struct {
	hostValidated bool
	tls           bool
	scheme        string
	requestHost   string
	urlHost       string
	path          string
	rawQuery      string
}

func NewSSRFDetector(mode string) *SSRFDetector {
	if mode == "" {
		mode = "block"
	}
	return &SSRFDetector{mode: mode}
}

func (d *SSRFDetector) ID() string    { return "semantic.ssrf" }
func (d *SSRFDetector) Name() string  { return "SSRF Semantic Detector" }
func (d *SSRFDetector) Priority() int { return 350 }

func (d *SSRFDetector) Detect(ctx context.Context, reqCtx *engine.RequestContext) (*engine.DetectionResult, error) {
	for _, candidate := range extractCandidates(reqCtx) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !ssrfFetchSink(candidate) {
			continue
		}
		// Browser telemetry often echoes the site's own absolute URL through a
		// tracking endpoint. A same-origin reference is transport metadata, not
		// an SSRF pivot, but only suppress it when the request has several
		// independent tracking fields; explicit fetch/proxy routes stay eligible.
		if ssrfSameOriginTelemetryReference(candidate, reqCtx.Request) {
			continue
		}
		payload := decoder.Decode(candidate.text).Text
		target, reason, ok := ssrfDangerousTarget(payload)
		if ok {
			return &engine.DetectionResult{
				Detected:   true,
				DetectorID: d.ID(),
				Category:   "ssrf",
				Severity:   engine.SeverityHigh,
				Action:     actionForMode(d.mode),
				Message:    reason,
				Confidence: 0.84,
				Payload:    target,
			}, nil
		}
	}
	return nil, nil
}

// ssrfSameOriginTelemetryReference keeps the SSRF detector precise for
// browser-side tracking requests that carry absolute links back to the same
// origin. It is deliberately conservative: only query candidates, a known
// URL-like telemetry field, an HTTP(S) URL whose host equals the request
// authority, and a multi-field tracking shape qualify. Bare hosts, different
// internal hosts, non-HTTP schemes, and explicit server-fetch routes remain
// blockable.
func ssrfSameOriginTelemetryReference(candidate semanticCandidate, req *http.Request) bool {
	if !candidate.hostValidated || req == nil || req.URL == nil {
		return false
	}
	if candidate.input.Source == "query" && ssrfTelemetryField(candidate.input.Name) && ssrfTelemetryShape(req) && !ssrfExplicitFetchRoute(req) {
		if ssrfSameOriginHTTPURL(candidate, req) {
			return true
		}
	}
	return ssrfSameOriginRedirectReference(candidate, req)
}

// ssrfSameOriginRedirectReference handles login/OAuth redirect parameters that
// point back to the already-routed site. These are client navigation targets,
// not server-side fetch sinks. Keep the route and field gates narrow so generic
// URL/endpoint parameters and explicit fetch handlers remain blockable.
func ssrfSameOriginRedirectReference(candidate semanticCandidate, req *http.Request) bool {
	if !candidate.hostValidated || req == nil || req.URL == nil {
		return false
	}
	if candidate.input.Source == "body.raw" {
		if !ssrfRedirectRoute(req.URL.Path) || ssrfExplicitFetchRoute(req) || !ssrfRawRedirectForm(candidate.text) {
			return false
		}
		return ssrfSameOriginHTTPURL(candidate, req)
	}
	if !ssrfRedirectField(candidate.input.Name) {
		return false
	}
	switch strings.ToLower(candidate.input.Source) {
	case "query", "body.form", "body.json":
	default:
		return false
	}
	if ssrfExplicitFetchRoute(req) || !ssrfRedirectRoute(req.URL.Path) {
		return false
	}
	return ssrfSameOriginHTTPURL(candidate, req)
}

func ssrfRawRedirectForm(text string) bool {
	values, err := url.ParseQuery(text)
	if err != nil {
		return false
	}
	for key, list := range values {
		if !ssrfRedirectField(key) || len(list) != 1 || strings.TrimSpace(list[0]) == "" {
			continue
		}
		decoded := strings.TrimSpace(decoder.Decode(list[0]).Text)
		if strings.Contains(decoded, "://") || strings.HasPrefix(decoded, "//") {
			return true
		}
	}
	return false
}

func ssrfSameOriginHTTPURL(candidate semanticCandidate, req *http.Request) bool {
	requestScheme := ssrfRequestScheme(req)
	authority := req.Host
	if strings.TrimSpace(authority) == "" {
		authority = req.URL.Host
	}
	authority = canonicalSSRFAuthority(authority, requestScheme)
	if authority == "" {
		return false
	}
	payload := strings.TrimSpace(decoder.Decode(candidate.text).Text)
	urls := ssrfURLCandidates(payload)
	if len(urls) != 1 {
		return false
	}
	parsed, err := url.Parse(strings.TrimSpace(strings.Trim(urls[0], `"'(),;`)))
	if err != nil || parsed.Hostname() == "" {
		return false
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return false
	}
	if requestScheme != "" && scheme != requestScheme {
		return false
	}
	return canonicalSSRFAuthority(parsed.Host, scheme) == authority
}

func ssrfRequestScheme(req *http.Request) string {
	if req == nil {
		return ""
	}
	if req.URL != nil && strings.TrimSpace(req.URL.Scheme) != "" {
		return strings.ToLower(strings.TrimSpace(req.URL.Scheme))
	}
	if req.TLS != nil {
		return "https"
	}
	return "http"
}

// ssrfRequestContextSensitive identifies candidates whose SSRF result can vary
// with the surrounding request. The same candidate text may be same-origin
// telemetry on one request but a cross-origin private target on another, so it
// must not be shared through the process-wide candidate cache. Keep this check
// cheaper and broader than the suppression gate: false positives only cost a
// small recomputation, while a false negative could reuse a request-specific
// decision incorrectly.
func ssrfRequestContextSensitive(candidate semanticCandidate) bool {
	if candidate.request == nil {
		return false
	}
	if candidate.input.Source == "body.raw" {
		// Avoid parsing every raw body as a query string. Most body candidates
		// are JSON, multipart, or opaque bytes and cannot be redirect forms.
		return ssrfPossibleRedirectForm(candidate.text)
	}
	return ssrfRequestContextField(candidate.input.Source, candidate.input.Name)
}

func ssrfRequestCacheScope(candidate semanticCandidate) (ssrfCacheScope, bool) {
	if !ssrfRequestContextSensitive(candidate) || candidate.request == nil || candidate.request.URL == nil {
		return ssrfCacheScope{}, false
	}
	req := candidate.request
	return ssrfCacheScope{
		hostValidated: candidate.hostValidated,
		tls:           req.TLS != nil,
		scheme:        req.URL.Scheme,
		requestHost:   req.Host,
		urlHost:       req.URL.Host,
		path:          req.URL.Path,
		rawQuery:      req.URL.RawQuery,
	}, true
}

func ssrfPossibleRedirectForm(text string) bool {
	lower := strings.ToLower(text)
	for _, marker := range ssrfRedirectFieldTokens {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func ssrfRequestContextField(source, name string) bool {
	switch {
	case strings.EqualFold(strings.TrimSpace(source), "query"):
		return ssrfTelemetryField(name) || ssrfRedirectField(name)
	case strings.EqualFold(strings.TrimSpace(source), "body.form"), strings.EqualFold(strings.TrimSpace(source), "body.json"):
		return ssrfRedirectField(name)
	default:
		return false
	}
}

func ssrfRedirectField(name string) bool {
	for _, token := range ssrfRedirectFieldTokens {
		if ssrfFieldToken(name, token) {
			return true
		}
	}
	return false
}

func ssrfRedirectRoute(path string) bool {
	path = strings.ToLower(strings.TrimSpace(path))
	if path == "" {
		return false
	}
	segments := strings.FieldsFunc(path, func(r rune) bool {
		return r == '/' || r == '?' || r == '#'
	})
	for _, segment := range segments {
		for _, token := range strings.FieldsFunc(segment, func(r rune) bool {
			return r == '-' || r == '_' || r == '.'
		}) {
			switch token {
			case "login", "logout", "oauth", "auth", "callback", "redirect", "return", "go":
				return true
			}
		}
	}
	return false
}

func ssrfTelemetryField(name string) bool {
	for _, token := range ssrfTelemetryFieldTokens {
		if ssrfFieldToken(name, token) {
			return true
		}
	}
	return false
}

func ssrfFieldToken(name, wanted string) bool {
	name = strings.TrimSpace(name)
	start := 0
	for i := 0; i <= len(name); i++ {
		if i != len(name) && name[i] != '.' && name[i] != '_' && name[i] != '-' {
			continue
		}
		if i > start && strings.EqualFold(name[start:i], wanted) {
			return true
		}
		start = i + 1
	}
	return false
}

// ssrfTelemetryShape requires several independent browser-tracking keys. A
// single "url" parameter is intentionally insufficient, so ordinary fetch
// endpoints and redirect handlers keep their existing SSRF coverage.
func ssrfTelemetryShape(req *http.Request) bool {
	if req == nil || req.URL == nil || req.URL.RawQuery == "" {
		return false
	}
	seen := uint64(0)
	for key := range req.URL.Query() {
		key = strings.ToLower(strings.TrimSpace(key))
		key = ssrfTelemetryKeyCleaner.Replace(key)
		if bit, ok := ssrfTelemetryTrackingFields[key]; ok {
			seen |= bit
		}
	}
	return bits.OnesCount64(seen) >= 3
}

var ssrfTelemetryTrackingFields = map[string]uint64{
	"actionname": 1 << 0, "browser": 1 << 1, "device": 1 << 2, "fullref": 1 << 3, "fvts": 1 << 4,
	"lvts": 1 << 5, "pvid": 1 << 6, "rand": 1 << 7, "refts": 1 << 8, "sendimage": 1 << 9,
	"siteid": 1 << 10, "visitorid": 1 << 11, "wmcaction": 1 << 12,
}

func ssrfExplicitFetchRoute(req *http.Request) bool {
	if req == nil || req.URL == nil {
		return false
	}
	path := strings.ToLower(req.URL.Path)
	for _, marker := range ssrfFetchPathMarkers {
		if strings.Contains(path, marker) {
			return true
		}
	}
	for key := range req.URL.Query() {
		key = strings.ToLower(strings.TrimSpace(key))
		for _, marker := range ssrfFetchQueryMarkers {
			if key == marker {
				return true
			}
		}
	}
	return false
}

func canonicalSSRFAuthority(host, scheme string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	parsed, err := url.Parse("//" + host)
	if err != nil || parsed.Hostname() == "" {
		return ""
	}
	hostname := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(parsed.Hostname())), ".")
	if hostname == "" {
		return ""
	}
	port := strings.TrimSpace(parsed.Port())
	if port == "" {
		switch strings.ToLower(strings.TrimSpace(scheme)) {
		case "http":
			port = "80"
		case "https":
			port = "443"
		}
	}
	if port == "" {
		return hostname
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return ""
	}
	port = strconv.Itoa(portNumber)
	// Use a canonical bracketed form for IPv6 while keeping ordinary hostnames
	// readable. The port remains part of the origin identity; LoadBalancer host
	// matching may ignore it, but SSRF same-origin comparison must not.
	if strings.Contains(hostname, ":") {
		return net.JoinHostPort(hostname, port)
	}
	return hostname + ":" + port
}

func ssrfDangerousTarget(payload string) (string, string, bool) {
	payload = strings.TrimSpace(payload)
	if payload == "" {
		return "", "", false
	}
	if strings.Contains(strings.ToLower(payload), "file://") {
		return payload, "SSRF target points to local file scheme", true
	}
	for _, rawURL := range ssrfURLCandidates(payload) {
		parsed, err := url.Parse(rawURL)
		if err != nil || parsed.Hostname() == "" {
			continue
		}
		host := parsed.Hostname()
		if isInternalHost(host) {
			return rawURL, "SSRF target points to local or private network", true
		}
		// DNS rebinding helpers / explicit rebind labels on a fetch sink.
		// FP-first: only hostname-shape evidence, never block arbitrary public domains.
		if isDNSRebindHost(host) {
			return rawURL, "SSRF target uses DNS-rebind helper host or rebind label", true
		}
	}
	for _, host := range ssrfHostCandidates(payload) {
		if isInternalHost(host) {
			return host, "SSRF target host points to local or private network", true
		}
		if isDNSRebindHost(host) {
			return host, "SSRF target host uses DNS-rebind helper or rebind label", true
		}
	}
	return "", "", false
}

// isDNSRebindHost matches known rebind services and explicit "rebind" DNS labels.
// Does NOT match ordinary public sites; requires multi-label host with rebind marker.
func isDNSRebindHost(host string) bool {
	host = strings.TrimSuffix(strings.Trim(strings.ToLower(host), "[]"), ".")
	if host == "" || !strings.Contains(host, ".") {
		return false
	}
	for _, suf := range []string{
		".rbndr.us", ".1u.ms", ".rebind.network", ".localtest.me",
		".vcap.me", ".lacolhost.com", ".localho.st",
	} {
		if strings.HasSuffix(host, suf) {
			return true
		}
	}
	// Labels used by rebind tooling (rebind.attacker.example.com, dnsrebind.x.y).
	for _, label := range strings.Split(host, ".") {
		switch label {
		case "rebind", "dnsrebind", "rbndr", "dns-rebind":
			return true
		}
	}
	return false
}

func looksLikeSSRFTarget(payload string) bool {
	for _, host := range ssrfHostCandidates(payload) {
		if isInternalHost(host) || isDNSRebindHost(host) {
			return true
		}
	}
	for _, rawURL := range ssrfURLCandidates(payload) {
		if parsed, err := url.Parse(rawURL); err == nil {
			if h := parsed.Hostname(); isInternalHost(h) || isDNSRebindHost(h) {
				return true
			}
		}
	}
	return false
}

func ssrfURLCandidates(payload string) []string {
	candidates := urlLikePattern.FindAllString(payload, -1)
	for _, match := range schemeRelativeURLPattern.FindAllString(payload, -1) {
		match = strings.TrimSpace(strings.Trim(match, `"'()`))
		if strings.HasPrefix(match, "//") {
			candidates = append(candidates, match)
		}
	}
	return candidates
}

func ssrfHostCandidates(payload string) []string {
	fields := strings.FieldsFunc(payload, func(r rune) bool {
		switch r {
		case ' ', '\t', '\r', '\n', '"', '\'', '<', '>', '(', ')', ',', ';':
			return true
		default:
			return false
		}
	})
	fields = append(fields, payload)
	hosts := make([]string, 0, len(fields))
	for _, field := range fields {
		if host := ssrfHostFromField(field); host != "" {
			hosts = append(hosts, host)
		}
	}
	return hosts
}

func ssrfHostFromField(field string) string {
	field = strings.TrimSpace(strings.Trim(field, `"'<>(),;`))
	if field == "" || strings.Contains(field, "://") {
		return ""
	}
	field = strings.TrimPrefix(field, "//")
	if at := strings.LastIndex(field, "@"); at >= 0 {
		field = field[at+1:]
	}
	if strings.HasPrefix(field, "[") {
		if end := strings.Index(field, "]"); end > 0 {
			return field[1:end]
		}
	}
	for _, sep := range []string{"/", "?", "#"} {
		if idx := strings.Index(field, sep); idx >= 0 {
			field = field[:idx]
		}
	}
	if host, _, err := net.SplitHostPort(field); err == nil {
		return strings.Trim(host, "[]")
	}
	if strings.Count(field, ":") > 1 {
		if ip := net.ParseIP(strings.Trim(field, "[]")); ip != nil {
			return strings.Trim(field, "[]")
		}
		return ""
	}
	if host, _, ok := strings.Cut(field, ":"); ok {
		return strings.Trim(host, "[]")
	}
	return strings.Trim(field, "[]")
}

func isInternalHost(host string) bool {
	host = strings.TrimSuffix(strings.Trim(strings.ToLower(host), "[]"), ".")
	if host == "" {
		return false
	}
	if host == "localhost" || strings.HasSuffix(host, ".localhost") ||
		host == "metadata" || host == "metadata.google.internal" || host == "metadata.google.internal." ||
		host == "0.0.0.0" || host == "0" {
		return true
	}
	if dynamicDNSHostResolvesInternal(host) {
		return true
	}
	// Handle IPv4-mapped IPv6 addresses like ::ffff:127.0.0.1
	if ipv4, ok := extractIPv4FromMappedIPv6(host); ok {
		return internalIP(ipv4)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		ip = parseNumericIPv4(host)
	}
	if ip == nil {
		return false
	}
	return internalIP(ip)
}

func extractIPv4FromMappedIPv6(host string) (net.IP, bool) {
	if !strings.HasPrefix(host, "::ffff:") {
		return nil, false
	}
	ipv4 := net.ParseIP(strings.TrimPrefix(host, "::ffff:"))
	if ipv4 != nil && ipv4.To4() != nil {
		return ipv4, true
	}
	return nil, false
}

func dynamicDNSHostResolvesInternal(host string) bool {
	for _, suffix := range []string{".nip.io", ".sslip.io", ".xip.io"} {
		if !strings.HasSuffix(host, suffix) {
			continue
		}
		encoded := strings.TrimSuffix(host, suffix)
		if encoded == "" {
			continue
		}
		candidates := []string{encoded}
		if strings.Contains(encoded, "-") {
			candidates = append(candidates, strings.ReplaceAll(encoded, "-", "."))
		}
		for _, candidate := range candidates {
			if internalIP(parseNumericIPv4(candidate)) {
				return true
			}
			if len(candidate) == 8 && isHex(candidate) {
				value, err := strconv.ParseUint(candidate, 16, 32)
				if err == nil && internalIP(net.IPv4(byte(value>>24), byte(value>>16), byte(value>>8), byte(value))) {
					return true
				}
			}
		}
	}
	return false
}

func internalIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() ||
		ip.Equal(net.ParseIP("169.254.169.254")) || ip.Equal(net.ParseIP("169.254.170.2")) || ip.Equal(net.ParseIP("100.100.100.200"))
}

func isHex(value string) bool {
	for _, ch := range value {
		if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f')) {
			return false
		}
	}
	return value != ""
}

func parseNumericIPv4(host string) net.IP {
	host = strings.TrimSuffix(host, ".")
	if strings.Contains(host, ".") {
		return parseDottedNumericIPv4(host)
	}
	if strings.Contains(host, ":") {
		return nil
	}
	value, err := strconv.ParseUint(host, 0, 32)
	if err != nil {
		return nil
	}
	return ipv4FromUint32(value)
}

func parseDottedNumericIPv4(host string) net.IP {
	parts := strings.Split(host, ".")
	if len(parts) < 2 || len(parts) > 4 {
		return nil
	}
	values := make([]uint64, len(parts))
	for i, part := range parts {
		if part == "" {
			return nil
		}
		value, err := strconv.ParseUint(part, 0, 32)
		if err != nil {
			return nil
		}
		values[i] = value
	}
	for i := 0; i < len(values)-1; i++ {
		if values[i] > 0xff {
			return nil
		}
	}
	switch len(values) {
	case 2:
		if values[1] > 0xffffff {
			return nil
		}
		return ipv4FromOctets(values[0], values[1]>>16, values[1]>>8, values[1])
	case 3:
		if values[2] > 0xffff {
			return nil
		}
		return ipv4FromOctets(values[0], values[1], values[2]>>8, values[2])
	case 4:
		if values[3] > 0xff {
			return nil
		}
		return ipv4FromOctets(values[0], values[1], values[2], values[3])
	default:
		return nil
	}
}

func ipv4FromUint32(value uint64) net.IP {
	if value > 0xffffffff {
		return nil
	}
	return ipv4FromOctets((value>>24)&0xff, (value>>16)&0xff, (value>>8)&0xff, value&0xff)
}

func ipv4FromOctets(parts ...uint64) net.IP {
	if len(parts) != 4 {
		return nil
	}
	octets := [4]byte{}
	for i, part := range parts {
		octet, ok := ipv4Octet(part)
		if !ok {
			return nil
		}
		octets[i] = octet
	}
	return net.IPv4(octets[0], octets[1], octets[2], octets[3])
}

func ipv4Octet(value uint64) (byte, bool) {
	if value > 0xff {
		return 0, false
	}
	return byte(value), true
}
