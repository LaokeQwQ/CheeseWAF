// Package response detects sensitive data in upstream responses.
package response

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"fmt"
	"io"
	"mime"
	"net/http"
	"regexp"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/protection/tamper"
)

const maxDecompressionRatio = 20

type Finding struct {
	Pattern    string `json:"pattern,omitempty"`
	Message    string `json:"message"`
	DetectorID string `json:"detector_id"`
	Category   string `json:"category"`
	Severity   string `json:"severity"`
	Reason     string `json:"reason,omitempty"`
}

type Inspector struct {
	enabled  bool
	maxBody  int64
	rules    []*regexp.Regexp
	verifier *tamper.Verifier
}

func New(cfg config.ResponseInspectionConfig) (*Inspector, error) {
	if len(cfg.TamperSnapshots) > 0 && !cfg.Enabled {
		return nil, fmt.Errorf("response inspection must be enabled when tamper snapshots are configured")
	}
	if !cfg.Enabled {
		return &Inspector{}, nil
	}
	if cfg.MaxBodyBytes < 0 || cfg.MaxBodyBytes > 1<<30 {
		return nil, fmt.Errorf("response inspection max body must be between 0 and 1 GiB")
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
	if len(cfg.TamperSnapshots) > 0 {
		snapshots := make([]tamper.Snapshot, 0, len(cfg.TamperSnapshots))
		for _, snapshot := range cfg.TamperSnapshots {
			if int64(snapshot.Size) > cfg.MaxBodyBytes {
				return nil, fmt.Errorf("tamper snapshot %q exceeds response inspection limit", snapshot.URL)
			}
			snapshots = append(snapshots, tamper.Snapshot{
				URL: snapshot.URL, MAC: snapshot.MAC, Size: snapshot.Size, CapturedAt: snapshot.CapturedAt,
			})
		}
		verifier, err := tamper.NewVerifier([]byte(cfg.TamperKey), snapshots)
		if err != nil {
			return nil, fmt.Errorf("configure response tamper verifier: %w", err)
		}
		inspector.verifier = verifier
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
			return &Finding{
				Pattern: rule.String(), Message: "sensitive response data matched",
				DetectorID: "response.inspector", Category: "response", Severity: "high",
			}
		}
	}
	return nil
}

func (i *Inspector) InspectHTTP(resp *http.Response) (*Finding, error) {
	var request *http.Request
	if resp != nil {
		request = resp.Request
	}
	return i.InspectHTTPForRequest(resp, request)
}

// InspectHTTPForRequest inspects an upstream response once and replays its
// original transfer bytes. Authenticated snapshots use the public request URL,
// not the rewritten upstream URL.
func (i *Inspector) InspectHTTPForRequest(resp *http.Response, request *http.Request) (*Finding, error) {
	if !i.Enabled() || resp == nil || resp.Body == nil {
		return nil, nil
	}
	resourceURL, tamperTarget := i.tamperResourceURL(request)
	if IsStreamingContentType(resp.Header.Get("Content-Type")) {
		if tamperTarget {
			return tamperUnavailableFinding(resourceURL, "streaming_response"), nil
		}
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
		if tamperTarget {
			return tamperUnavailableFinding(resourceURL, "size_limit"), nil
		}
		return nil, nil
	}
	originalBody.Close()
	resp.Body = io.NopCloser(newReplayReader(raw))
	resp.ContentLength = int64(len(raw))
	resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(raw)))

	inspectBody := raw
	complete := true
	encoding := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Encoding")))
	if encoding != "" && encoding != "identity" {
		plain, decodedComplete, derr := decodeResponseContent(raw, encoding, limit)
		if derr != nil {
			if tamperTarget {
				return tamperUnavailableFinding(resourceURL, "unsupported_encoding"), nil
			}
			return nil, nil
		}
		inspectBody = plain
		complete = decodedComplete
	}
	if int64(len(inspectBody)) > limit {
		inspectBody = inspectBody[:limit]
		complete = false
	}
	if tamperTarget {
		if !complete {
			return tamperUnavailableFinding(resourceURL, "size_limit"), nil
		}
		drift, err := i.verifier.Compare(resourceURL, inspectBody)
		if err != nil {
			return nil, err
		}
		if drift.Changed {
			return &Finding{
				Pattern: resourceURL, Message: "response differs from authenticated tamper snapshot",
				DetectorID: "protection.tamper", Category: "tamper", Severity: "critical", Reason: drift.Reason,
			}, nil
		}
	}
	return i.Inspect(inspectBody), nil
}

// InspectCaptured applies the same inline checks to an in-memory cache hit.
func (i *Inspector) InspectCaptured(request *http.Request, header http.Header, body []byte) (*Finding, error) {
	resp := &http.Response{
		Header: header.Clone(), Body: io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)), Request: request,
	}
	return i.InspectHTTPForRequest(resp, request)
}

// HasTamperSnapshot reports whether this public request maps to an exact
// response baseline. Callers use it to keep buffering enabled until inspection
// has completed.
func (i *Inspector) HasTamperSnapshot(request *http.Request) bool {
	_, ok := i.tamperResourceURL(request)
	return ok
}

func (i *Inspector) tamperResourceURL(request *http.Request) (string, bool) {
	if i == nil || i.verifier == nil || !i.verifier.Enabled() || request == nil || request.URL == nil || request.Method != http.MethodGet {
		return "", false
	}
	relative := request.URL.RequestURI()
	if i.verifier.HasSnapshot(relative) {
		return relative, true
	}
	scheme := request.URL.Scheme
	if scheme == "" {
		scheme = "http"
		if request.TLS != nil {
			scheme = "https"
		}
	}
	host := request.Host
	if host == "" {
		host = request.URL.Host
	}
	if host != "" {
		absolute := scheme + "://" + host + relative
		if i.verifier.HasSnapshot(absolute) {
			return absolute, true
		}
	}
	return "", false
}

func tamperUnavailableFinding(resourceURL, reason string) *Finding {
	return &Finding{
		Pattern: resourceURL, Message: "authenticated tamper snapshot could not be verified",
		DetectorID: "protection.tamper", Category: "tamper", Severity: "high", Reason: reason,
	}
}

// IsStreamingContentType identifies responses that must not be fully buffered.
func IsStreamingContentType(contentType string) bool {
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		mediaType = strings.TrimSpace(strings.Split(contentType, ";")[0])
	}
	mediaType = strings.ToLower(mediaType)
	return mediaType == "text/event-stream" ||
		mediaType == "multipart/x-mixed-replace" ||
		strings.HasPrefix(mediaType, "application/grpc") ||
		strings.HasPrefix(mediaType, "audio/") ||
		strings.HasPrefix(mediaType, "video/")
}

func decodeResponseContent(raw []byte, encoding string, maxPlain int64) ([]byte, bool, error) {
	if strings.Contains(encoding, ",") {
		return nil, false, fmt.Errorf("multi-layer content-encoding")
	}
	var reader io.Reader
	switch encoding {
	case "gzip", "x-gzip":
		gr, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			return nil, false, err
		}
		defer gr.Close()
		reader = gr
	case "deflate":
		reader = flate.NewReader(bytes.NewReader(raw))
	default:
		return nil, false, fmt.Errorf("unsupported content-encoding %q", encoding)
	}
	limit := maxPlain
	if ratioCap := int64(len(raw)) * maxDecompressionRatio; ratioCap > 0 && ratioCap < limit {
		limit = ratioCap
	}
	plain, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(plain)) > limit {
		return plain[:limit], false, nil
	}
	return plain, true, nil
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
