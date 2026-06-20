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

var urlLikePattern = regexp.MustCompile(`(?i)(?:https?|gopher|dict|ftp|file)://[^\s'"<>]+`)

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
		if strings.Contains(strings.ToLower(payload), "file://") {
			return &engine.DetectionResult{
				Detected:   true,
				DetectorID: d.ID(),
				Category:   "ssrf",
				Severity:   engine.SeverityHigh,
				Action:     actionForMode(d.mode),
				Message:    "SSRF target points to local file scheme",
				Confidence: 0.88,
				Payload:    strings.TrimSpace(payload),
			}, nil
		}
		for _, rawURL := range urlLikePattern.FindAllString(payload, -1) {
			parsed, err := url.Parse(rawURL)
			if err != nil || parsed.Hostname() == "" {
				continue
			}
			if isInternalHost(parsed.Hostname()) {
				return &engine.DetectionResult{
					Detected:   true,
					DetectorID: d.ID(),
					Category:   "ssrf",
					Severity:   engine.SeverityHigh,
					Action:     actionForMode(d.mode),
					Message:    "SSRF target points to local or private network",
					Confidence: 0.82,
					Payload:    rawURL,
				}, nil
			}
		}
	}
	return nil, nil
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
	return net.IPv4(byte(value>>24), byte(value>>16), byte(value>>8), byte(value))
}

func parseDottedNumericIPv4(host string) net.IP {
	parts := strings.Split(host, ".")
	if len(parts) != 4 {
		return nil
	}
	var octets [4]byte
	for i, part := range parts {
		if part == "" {
			return nil
		}
		value, err := strconv.ParseUint(part, 0, 8)
		if err != nil {
			return nil
		}
		octets[i] = byte(value)
	}
	return net.IPv4(octets[0], octets[1], octets[2], octets[3])
}
