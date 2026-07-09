package semantic

import (
	"context"
	"net"
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
)

type SSRFDetector struct {
	mode string
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

func (d *SSRFDetector) Detect(_ context.Context, reqCtx *engine.RequestContext) (*engine.DetectionResult, error) {
	for _, candidate := range extractCandidates(reqCtx) {
		if !ssrfFetchSink(candidate) {
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
		if isInternalHost(parsed.Hostname()) {
			return rawURL, "SSRF target points to local or private network", true
		}
	}
	for _, host := range ssrfHostCandidates(payload) {
		if isInternalHost(host) {
			return host, "SSRF target host points to local or private network", true
		}
	}
	return "", "", false
}

func looksLikeSSRFTarget(payload string) bool {
	for _, host := range ssrfHostCandidates(payload) {
		if isInternalHost(host) {
			return true
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
