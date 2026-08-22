package webshell

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

const (
	defaultDetectorTimeout       = 25 * time.Millisecond
	defaultDetectorConcurrency   = 32
	defaultDetectorCandidateSize = 1 << 20
)

type DetectorConfig struct {
	Mode              string
	MaxCandidateBytes int
	MaxConcurrent     int
	Timeout           time.Duration
}

type Detector struct {
	mode         string
	maxCandidate int
	timeout      time.Duration
	slots        chan struct{}
	scanner      *Scanner
}

func NewDetector(cfg DetectorConfig) *Detector {
	if cfg.MaxCandidateBytes <= 0 {
		cfg.MaxCandidateBytes = defaultDetectorCandidateSize
	}
	if cfg.MaxConcurrent <= 0 {
		cfg.MaxConcurrent = defaultDetectorConcurrency
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultDetectorTimeout
	}
	return &Detector{
		mode:         strings.ToLower(strings.TrimSpace(cfg.Mode)),
		maxCandidate: cfg.MaxCandidateBytes,
		timeout:      cfg.Timeout,
		slots:        make(chan struct{}, cfg.MaxConcurrent),
		scanner:      NewScanner(),
	}
}

func (d *Detector) ID() string   { return "protection.webshell" }
func (d *Detector) Name() string { return "Bounded Webshell Upload Scanner" }

// Run immediately before the concurrent semantic group. This keeps lazy body
// loading single-threaded and lets a high-confidence webshell block short-circuit.
func (d *Detector) Priority() int { return 289 }

func (d *Detector) Detect(ctx context.Context, reqCtx *engine.RequestContext) (*engine.DetectionResult, error) {
	if d == nil || reqCtx == nil || reqCtx.Request == nil || d.mode == "off" {
		return nil, nil
	}
	select {
	case d.slots <- struct{}{}:
		defer func() { <-d.slots }()
	default:
		return nil, engine.ErrDetectionOverload
	}
	if err := reqCtx.EnsureBody(); err != nil {
		return nil, err
	}
	scanCtx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()

	name := requestName(reqCtx.Request)
	uri := ""
	if reqCtx.Request.URL != nil {
		uri = reqCtx.Request.URL.RequestURI()
	}
	surfaces := [][]byte{[]byte(uri)}
	if len(reqCtx.DecodedBody) > 0 {
		body := reqCtx.DecodedBody
		if len(body) > d.maxCandidate {
			if executableCandidate(reqCtx.Request, body) {
				return d.result(Finding{Rule: "scan-limit", Severity: "high", Message: "webshell scan limit exceeded for executable candidate"}, body[:d.maxCandidate]), nil
			}
			body = body[:d.maxCandidate]
		}
		surfaces = append(surfaces, body)
	}
	for _, surface := range surfaces {
		if err := scanCtx.Err(); err != nil {
			if ctx.Err() == nil && errors.Is(err, context.DeadlineExceeded) {
				return d.result(Finding{
					Rule: "scan-timeout", Severity: "high", Message: "webshell scan deadline exceeded",
				}, surface), nil
			}
			return nil, err
		}
		findings, err := d.scanner.ScanContext(scanCtx, name, surface)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if errors.Is(err, context.DeadlineExceeded) {
				return d.result(Finding{
					Rule: "scan-timeout", Severity: "high", Message: "webshell scan deadline exceeded",
				}, surface), nil
			}
			return nil, err
		}
		if len(findings) > 0 {
			return d.result(findings[0], surface), nil
		}
	}
	return nil, nil
}

func executableCandidate(req *http.Request, body []byte) bool {
	name := strings.ToLower(requestName(req))
	if hasSuffixFold(name, ".php", ".php3", ".php4", ".php5", ".phtml", ".phar", ".jsp", ".jspx", ".asp", ".aspx") {
		return true
	}
	if req != nil {
		contentType := strings.ToLower(req.Header.Get("Content-Type"))
		if strings.Contains(contentType, "php") || strings.Contains(contentType, "java-server-page") || strings.Contains(contentType, "asp") {
			return true
		}
	}
	lowerBody := bytes.ToLower(body)
	if bytes.Contains(lowerBody, []byte("<?php")) || bytes.Contains(lowerBody, []byte("<jsp:")) || bytes.Contains(lowerBody, []byte("runat=\"server\"")) {
		return true
	}
	for _, marker := range [][]byte{[]byte(`filename="`), []byte(`filename='`)} {
		if index := bytes.Index(lowerBody, marker); index >= 0 {
			name := lowerBody[index:min(len(lowerBody), index+256)]
			if bytes.Contains(name, []byte(".php")) || bytes.Contains(name, []byte(".jsp")) || bytes.Contains(name, []byte(".aspx")) {
				return true
			}
		}
	}
	return false
}

func requestName(req *http.Request) string {
	if req == nil || req.URL == nil {
		return "request"
	}
	name := req.URL.Path
	if name == "" {
		return "request"
	}
	return name
}

func (d *Detector) result(finding Finding, payload []byte) *engine.DetectionResult {
	action := engine.ActionLog
	if d.mode == "block" {
		action = engine.ActionBlock
	}
	severity := engine.SeverityMedium
	switch finding.Severity {
	case "critical":
		severity = engine.SeverityCritical
	case "high":
		severity = engine.SeverityHigh
	}
	if len(payload) > 256 {
		payload = payload[:256]
	}
	return &engine.DetectionResult{
		Detected:   true,
		DetectorID: d.ID(),
		Category:   "webshell",
		Severity:   severity,
		Action:     action,
		Message:    finding.Message,
		Confidence: 0.94,
		Payload:    string(payload),
	}
}

var _ engine.Detector = (*Detector)(nil)
