// Package response detects sensitive data in upstream responses.
package response

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

const maxDecompressionRatio = 20

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
	// Read transfer-encoded bytes; keep them for the client.
	raw, err := io.ReadAll(io.LimitReader(originalBody, limit*maxDecompressionRatio+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit*maxDecompressionRatio {
		resp.Body = replayThenClose(raw, originalBody)
		return nil, nil
	}
	originalBody.Close()
	resp.Body = io.NopCloser(newReplayReader(raw))
	resp.ContentLength = int64(len(raw))
	resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(raw)))

	inspectBody := raw
	encoding := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Encoding")))
	if encoding != "" && encoding != "identity" {
		if plain, derr := decodeResponseContent(raw, encoding, limit); derr == nil {
			inspectBody = plain
		}
		// Unsupported encodings: skip inspection rather than false-negative on ciphertext.
	}
	if int64(len(inspectBody)) > limit {
		inspectBody = inspectBody[:limit]
	}
	return i.Inspect(inspectBody), nil
}

func decodeResponseContent(raw []byte, encoding string, maxPlain int64) ([]byte, error) {
	if strings.Contains(encoding, ",") {
		return nil, fmt.Errorf("multi-layer content-encoding")
	}
	var reader io.Reader
	switch encoding {
	case "gzip", "x-gzip":
		gr, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			return nil, err
		}
		defer gr.Close()
		reader = gr
	case "deflate":
		reader = flate.NewReader(bytes.NewReader(raw))
	default:
		return nil, fmt.Errorf("unsupported content-encoding %q", encoding)
	}
	limit := maxPlain
	if ratioCap := int64(len(raw)) * maxDecompressionRatio; ratioCap > 0 && ratioCap < limit {
		limit = ratioCap
	}
	plain, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(plain)) > limit {
		return plain[:limit], nil
	}
	return plain, nil
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
