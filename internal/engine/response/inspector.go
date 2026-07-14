// Package response detects sensitive data in upstream responses.
package response

import (
	"bytes"
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
	limit := i.maxBody
	if limit <= 0 {
		limit = 1 << 20
	}
	originalBody := resp.Body
	body, err := io.ReadAll(io.LimitReader(originalBody, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		resp.Body = replayThenClose(body, originalBody)
		return i.Inspect(body[:limit]), nil
	}
	originalBody.Close()
	resp.Body = io.NopCloser(newReplayReader(body))
	resp.ContentLength = int64(len(body))
	resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))
	return i.Inspect(body), nil
}

type replayReadCloser struct {
	io.Reader
	closer io.Closer
}

func (r replayReadCloser) Close() error {
	return r.closer.Close()
}

func replayThenClose(prefix []byte, rest io.ReadCloser) io.ReadCloser {
	return replayReadCloser{
		Reader: io.MultiReader(bytes.NewReader(prefix), rest),
		closer: rest,
	}
}
