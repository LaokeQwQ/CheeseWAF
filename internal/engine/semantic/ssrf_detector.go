package semantic

import (
	"context"
	"net"
	"net/url"
	"regexp"
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
	payload := decoder.Decode(requestText(reqCtx)).Text
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
	return nil, nil
}

func isInternalHost(host string) bool {
	host = strings.Trim(strings.ToLower(host), "[]")
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return host == "metadata.google.internal"
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return true
	}
	return ip.Equal(net.ParseIP("169.254.169.254"))
}
