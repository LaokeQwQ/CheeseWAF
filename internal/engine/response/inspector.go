// Package response detects sensitive data in upstream responses.
package response

import (
	"fmt"
	"io"
	"net/http"
	"regexp"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

type Finding struct {
	Pattern string `json:"pattern"`
	Message string `json:"message"`
}

type Inspector struct {
	enabled bool
	maxBody int64
	rules   []*regexp.Regexp
}

func New(cfg config.ResponseInspectionConfig) (*Inspector, error) {
	if !cfg.Enabled {
		return &Inspector{}, nil
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = 1 << 20
	}
	patterns := cfg.SensitivePatterns
	if len(patterns) == 0 {
		patterns = []string{
			`AKIA[0-9A-Z]{16}`,
			`(?i)password\s*[=:]\s*['"]?[^'"\s]+`,
			`(?i)secret[_-]?key\s*[=:]\s*['"]?[^'"\s]+`,
			`(?i)BEGIN\s+(?:RSA|EC|OPENSSH)\s+PRIVATE\s+KEY`,
		}
	}
	inspector := &Inspector{enabled: true, maxBody: cfg.MaxBodyBytes}
	for _, pattern := range patterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("compile response pattern %q: %w", pattern, err)
		}
		inspector.rules = append(inspector.rules, re)
	}
	return inspector, nil
}

func (i *Inspector) Enabled() bool {
	return i != nil && i.enabled
}

func (i *Inspector) Inspect(body []byte) *Finding {
	if !i.Enabled() {
		return nil
	}
	for _, rule := range i.rules {
		if rule.Match(body) {
			return &Finding{Pattern: rule.String(), Message: "sensitive response data matched"}
		}
	}
	return nil
}

func (i *Inspector) InspectHTTP(resp *http.Response) (*Finding, error) {
	if !i.Enabled() || resp == nil || resp.Body == nil {
		return nil, nil
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()
	resp.Body = io.NopCloser(newReplayReader(body))
	resp.ContentLength = int64(len(body))
	resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))
	if int64(len(body)) > i.maxBody {
		return nil, nil
	}
	return i.Inspect(body), nil
}
